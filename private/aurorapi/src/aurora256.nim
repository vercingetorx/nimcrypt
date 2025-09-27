# ========================================
# File: src/aurora256_ct.nim
# AURORA-Π (Pi) — Constant-time engine variant
# - Same external API types as src/aurora256.nim: expandKey, encryptBlock, decryptBlock
# - Uses SHAKE256 as a KDF/PRF to derive whitening and program
# - Executes all op candidates each step and selects via masks (no key-dependent branches)
# ========================================
when isMainModule: discard

import ./common
import ../private/sha3/shake256

# ------- Parameters -------

const
  PI_BLOCK_BYTES* = AURORA_BLOCK_BYTES # 32
  PI_KEY_BYTES*   = AURORA_KEY_BYTES   # 32
  PI_TWEAK_BYTES* = AURORA_TWEAK_BYTES # 16

# Compile-time profile (override with: -d:piProfile=balanced or test)
const piProfile {.strdefine.}: string = "max"

when piProfile == "balanced":
  const PI_STEPS = 48
elif piProfile == "test":
  const PI_STEPS = 32
else: # max (default)
  const PI_STEPS = 64

# ------- State helpers -------

type State256 = array[4, uint64] # little-endian lanes

proc loadState(b: openArray[byte]): State256 =
  result[0] = load64(b,  0)
  result[1] = load64(b,  8)
  result[2] = load64(b, 16)
  result[3] = load64(b, 24)

proc storeState(b: var openArray[byte], s: State256) =
  store64(b,  0, s[0])
  store64(b,  8, s[1])
  store64(b, 16, s[2])
  store64(b, 24, s[3])

proc asBytes(s: State256): array[32, byte] =
  var output: array[32, byte]
  storeState(output, s)
  output

proc fromBytes(b: openArray[byte]): State256 =
  loadState(b)

proc toHex64(x: uint64): string =
  var s = newString(16)
  var t = x
  for i in countdown(15, 0):
    let nib = int(t and 0xFu64)
    s[i] = char((if nib < 10: ord('0') + nib else: ord('a') + (nib-10)))
    t = t shr 4
  result = s

# ------- Constant-time helpers -------

proc ctMask32Eq(a, b: uint32): uint32 {.inline.} =
  ## 0xFFFFFFFF when a == b else 0x00000000
  let x = a xor b
  let m = (x - 1) shr 31
  0'u32 - m

proc ctMask64Eq(a, b: uint32): uint64 {.inline.} =
  let m32 = ctMask32Eq(a, b)
  (uint64(m32) shl 32) or uint64(m32)

proc ctBlend64(a, b, m: uint64): uint64 {.inline.} =
  ## return (a & ~m) | (b & m)
  (a and (not m)) or (b and m)

# ------- PRF via SHAKE256 (domain-separated) -------

type PRFCtx = object
  ctx: Shake256Ctx

proc initPRF(key: openArray[byte], tweak: openArray[byte], dom: string, subTag: string = ""): PRFCtx =
  ## Initialize domain-separated SHAKE256 XOF: DS || dom || subTag || 0x00 || key || 0x00 || tweak
  var c = newShake256Ctx()
  c.update("AURORA-PI-CT")
  c.update(dom)
  if subTag.len > 0: c.update(subTag)
  c.update("\x00")
  if key.len > 0: c.update(key)
  c.update("\x00")
  if tweak.len > 0: c.update(tweak) else: discard
  result.ctx = c

proc next64(pr: var PRFCtx): uint64 {.inline.} =
  var tmp = pr.ctx.read(8)
  load64(tmp, 0)

proc sampleRange(pr: var PRFCtx, n: int): int {.inline.} =
  ## Uniform sample in [0, n-1] using rejection to avoid modulo bias
  let m = uint64(n)
  let maxu = 0xFFFFFFFFFFFFFFFF'u64
  let limit = (maxu div m) * m - 1'u64
  var x: uint64
  while true:
    x = pr.next64()
    if x <= limit:
      return int(x mod m)

# ------- Byte permutation (constant-time) -------

proc genPerm32(pr: var PRFCtx): array[32, byte] =
  var p: array[32, byte]
  for i in 0..31: p[i] = byte(i)
  var i = 31
  while i > 0:
    let j = pr.sampleRange(i+1)  # unbiased in [0..i]
    let tmp = p[i]
    p[i] = p[j]
    p[j] = tmp
    dec i
  return p

proc permInverse(p: array[32, byte]): array[32, byte] =
  var inv: array[32, byte]
  for i in 0..31:
    inv[p[i]] = byte(i)
  return inv

proc eqMask8(a, b: uint8): uint8 {.inline.} =
  ## Branchless equality mask: 0xFF when a == b else 0x00
  let x = uint32(a xor b)
  let m = (x - 1) shr 31        # 1 if x==0 else 0
  let mask32 = 0'u32 - m        # 0xFFFFFFFF if equal else 0x0
  uint8(mask32 and 0xFF'u32)

proc applyPerm(s: State256, p: array[32, byte]): State256 =
  ## Constant-time permutation application without secret-dependent indexing
  var inb = s.asBytes
  var outb: array[32, byte]
  for j in 0..31: outb[j] = 0'u8
  for k in 0..31:
    let v = inb[k]
    let vk = uint32(v)
    for j in 0..31:
      let m = uint32(eqMask8(p[j], uint8(k)))
      let contrib = (vk and m) and 0xFF'u32
      outb[j] = byte(uint32(outb[j]) or contrib)
  fromBytes(outb)

# ------- Instruction set -------

type
  OpKind = enum
    OP_XOR, OP_ADD, OP_ROTL, OP_MUL, OP_PERM, OP_CROSS

  Instr = object
    op: OpKind
    lane: int8            # 0..3 or -1 for non-lane ops
    rot: uint8            # for ROTL
    r2, r3, r4: uint8     # for CROSS
    imm: uint64           # for XOR/ADD/MUL
    perm: array[32, byte] # for PERM only

  KeySchedule* = object
    enc*: seq[Instr]
    dec*: seq[Instr]
    wIn*: State256
    wOut*: State256

proc describeFirstInstrs*(ks: KeySchedule, n: int): string =
  var desc = ""
  let m = min(n, ks.enc.len)
  for i in 0 ..< m:
    let ins = ks.enc[i]
    case ins.op
    of OP_XOR:
      desc.add("XOR lane="); desc.add($int(ins.lane)); desc.add(" c=0x"); desc.add(toHex64(ins.imm)); desc.add("\n")
    of OP_ADD:
      desc.add("ADD lane="); desc.add($int(ins.lane)); desc.add(" c=0x"); desc.add(toHex64(ins.imm)); desc.add("\n")
    of OP_ROTL:
      desc.add("ROTL lane="); desc.add($int(ins.lane)); desc.add(" r="); desc.add($int(ins.rot)); desc.add("\n")
    of OP_MUL:
      desc.add("MUL lane="); desc.add($int(ins.lane)); desc.add(" c=0x"); desc.add(toHex64(ins.imm)); desc.add("\n")
    of OP_PERM:
      desc.add("PERM first8=[")
      for j in 0..7:
        if j>0: desc.add(",")
        desc.add($int(ins.perm[j]))
      desc.add("]\n")
    of OP_CROSS:
      desc.add("CROSS r1="); desc.add($int(ins.rot));
      desc.add(" r2="); desc.add($int(ins.r2));
      desc.add(" r3="); desc.add($int(ins.r3));
      desc.add(" r4="); desc.add($int(ins.r4)); desc.add("\n")
  result = desc

# ------- Ops (per-lane primitives) -------

proc doRotl64(x: uint64, r: int): uint64 {.inline.} = rotl(x, r)
proc doRotr64(x: uint64, r: int): uint64 {.inline.} = rotr(x, r)

proc invOdd64(c: uint64): uint64 =
  ## multiplicative inverse of odd 64-bit modulo 2^64 (Newton iteration)
  var x: uint64 = 1'u64
  for _ in 0..5:
    x = x * (2'u64 - c * x)
  x

# ------- Constant-time engine -------

proc runProgCT(x: var State256, prog: seq[Instr], decrypt = false) =
  let decMask = if decrypt: 0xFFFFFFFFFFFFFFFF'u64 else: 0'u64
  for ins in prog:
    # Build op masks (64-bit all-ones if match else zero)
    let mXor   = ctMask64Eq(uint32(ins.op.ord), uint32(OP_XOR.ord))
    let mAdd   = ctMask64Eq(uint32(ins.op.ord), uint32(OP_ADD.ord))
    let mRotl  = ctMask64Eq(uint32(ins.op.ord), uint32(OP_ROTL.ord))
    let mMul   = ctMask64Eq(uint32(ins.op.ord), uint32(OP_MUL.ord))
    let mPerm  = ctMask64Eq(uint32(ins.op.ord), uint32(OP_PERM.ord))
    let mCross = ctMask64Eq(uint32(ins.op.ord), uint32(OP_CROSS.ord))

    # Lane masks for lane-local ops
    var lm: array[4, uint64]
    for i in 0..3:
      lm[i] = ctMask64Eq(uint32(i), uint32(int(ins.lane)))

    var candXor, candAdd, candRotl, candMul, candPerm, candCrossF, candCrossI: State256
    # start all candidates as identity (pass-through)
    for i in 0..3:
      candXor[i] = x[i]
      candAdd[i] = x[i]
      candRotl[i] = x[i]
      candMul[i] = x[i]
      candPerm[i] = x[i]
      candCrossF[i] = x[i]
      candCrossI[i] = x[i]

    # XOR candidate (lane-local)
    for i in 0..3:
      let xi = x[i] xor ins.imm
      candXor[i] = ctBlend64(x[i], xi, lm[i])

    # ADD/SUB candidate (lane-local, controlled by decrypt flag)
    for i in 0..3:
      let addv = x[i] + ins.imm
      let subv = x[i] - ins.imm
      let sel  = ctBlend64(addv, subv, decMask)  # decrypt? pick SUB
      candAdd[i] = ctBlend64(x[i], sel, lm[i])

    # ROTL/ROTR candidate (lane-local, controlled by decrypt flag)
    let r = int(ins.rot)
    for i in 0..3:
      let rvL = doRotl64(x[i], r)
      let rvR = doRotr64(x[i], r)
      let sel = ctBlend64(rvL, rvR, decMask)     # decrypt? pick ROTR
      candRotl[i] = ctBlend64(x[i], sel, lm[i])

    # MUL candidate (lane-local). For decrypt path, imm is already inverted in dec program
    for i in 0..3:
      let mv = x[i] * ins.imm
      candMul[i] = ctBlend64(x[i], mv, lm[i])

    # PERM candidate (full-state)
    candPerm = applyPerm(x, ins.perm)

    # CROSS forward and inverse candidates (full-state)
    block:
      var t: State256
      t = x
      t[0] = t[0] + doRotl64(t[1], int(ins.rot))
      t[2] = t[2] + doRotl64(t[3], int(ins.r2))
      t[1] = t[1] xor doRotl64(t[2], int(ins.r3))
      t[3] = t[3] xor doRotl64(t[0], int(ins.r4))
      candCrossF = t
    block:
      var t: State256
      t = x
      t[3] = t[3] xor doRotl64(t[0], int(ins.r4))
      t[1] = t[1] xor doRotl64(t[2], int(ins.r3))
      t[2] = t[2] - doRotl64(t[3], int(ins.r2))
      t[0] = t[0] - doRotl64(t[1], int(ins.rot))
      candCrossI = t

    # Select CROSS variant based on decrypt flag
    var candCross: State256
    for i in 0..3:
      candCross[i] = ctBlend64(candCrossF[i], candCrossI[i], decMask)

    # Merge all candidates according to op mask
    var newX: State256
    for i in 0..3:
      var acc: uint64 = 0
      acc = acc or (candXor[i]  and mXor)
      acc = acc or (candAdd[i]  and mAdd)
      acc = acc or (candRotl[i] and mRotl)
      acc = acc or (candMul[i]  and mMul)
      acc = acc or (candPerm[i] and mPerm)
      acc = acc or (candCross[i] and mCross)
      newX[i] = acc
    x = newX

# ------- Program generation (via SHAKE-derived PRF) -------

proc expandKey*(key: openArray[byte], tweak: openArray[byte] = @[]): KeySchedule =
  doAssert key.len == PI_KEY_BYTES
  doAssert tweak.len == 0 or tweak.len == PI_TWEAK_BYTES

  # Domain-separated PRFs
  var prWin  = initPRF(key, tweak, "WIN_PI")
  var prWout = initPRF(key, tweak, "WOUT_PI")
  var prProgA = initPRF(key, tweak, "PROG_PI", "A")
  var prProgB = initPRF(key, tweak, "PROG_PI", "B")

  # Whitening in/out (256 bits each)
  var buf: array[32, byte]
  for i in 0..3: result.wIn[i]  = prWin.next64()
  for i in 0..3: result.wOut[i] = prWout.next64()

  # Program synthesis with strengthened quotas
  var prog: seq[Instr]  = @[]
  var step: int         = 0
  var winRemaining: int = 8
  var permCount: int    = 0
  var crossCount: int   = 0
  var crossFirst: bool  = false  # at least one CROSS in first 4 steps of window
  var crossSecond: bool = false  # at least one CROSS in last 4 steps of window
  var haveMul: bool     = false
  var laneHit: array[4, bool]
  # Super-window (16-step) per-lane MUL coverage
  var superRemaining: int = 16
  var mulLaneSeen: array[4, bool]

  while step < PI_STEPS:
    let firstHalf = step < (PI_STEPS div 2)
    var forceKind = -1
    var forcedLane = -1

    # Window diffusion quotas (per 8 steps):
    # - at least one PERM and one CROSS
    # - at least 3 total among {PERM,CROSS}
    let havePerm = permCount > 0
    let haveCross = crossCount > 0
    let totalPC = permCount + crossCount

    # Super-window per-lane MUL coverage (per 16 steps): ensure each lane gets a MUL at least once
    var missingMulCount = 0
    var firstMissingLane = -1
    for ln in 0..3:
      if not mulLaneSeen[ln]:
        inc missingMulCount
        if firstMissingLane < 0: firstMissingLane = ln

    # End of first half (before taking step 4 of window): ensure at least one CROSS in first half
    if forceKind < 0 and winRemaining == 5 and not crossFirst:
      forceKind = 6  # CROSS

    # If super-window is tight, force MUL early (avoid using the very last step of a window)
    if forceKind < 0 and missingMulCount > 0 and superRemaining <= (missingMulCount + 1) and winRemaining > 1:
      forceKind = 4
      forcedLane = firstMissingLane

    # On the last step of the 8-step window, satisfy window quotas and lane coverage
    if forceKind < 0 and winRemaining == 1:
      # Ensure at least one CROSS in second half of the window
      if not crossSecond:
        forceKind = 6
      elif not havePerm:
        forceKind = 5   # PERM
      elif not haveCross:
        forceKind = 6   # CROSS
      elif totalPC < 3:
        # Add an extra diffusion op to reach >=3 among {PERM,CROSS}
        forceKind = 6   # choose CROSS deterministically
      elif not haveMul:
        forceKind = 4   # MUL (some nonlinearity each window)
      else:
        # Enforce per-window lane coverage for lane-local ops
        for ln in 0..3:
          if not laneHit[ln]:
            forceKind = 0   # choose a lane-op (XOR)
            forcedLane = ln
            break

    let pick =
      if forceKind >= 0:
        forceKind
      else:
        if firstHalf: int(prProgA.next64() mod 8'u64) else: int(prProgB.next64() mod 8'u64)
    case pick
    of 0,1: # XOR
      let ln =
        if forcedLane >= 0: forcedLane
        else: (if firstHalf: int(prProgA.next64() and 3'u64) else: int(prProgB.next64() and 3'u64))
      var c = if firstHalf: prProgA.next64() else: prProgB.next64()
      while c == 0'u64:
        c = if firstHalf: prProgA.next64() else: prProgB.next64()  # reject true no-op
      prog.add Instr(op: OP_XOR, lane: int8(ln), imm: c)
      laneHit[ln] = true
    of 2:   # ADD (odd)
      let ln = if firstHalf: int(prProgA.next64() and 3'u64) else: int(prProgB.next64() and 3'u64)
      let c = (if firstHalf: prProgA.next64() else: prProgB.next64()) or 1'u64
      prog.add Instr(op: OP_ADD, lane: int8(ln), imm: c)
      laneHit[ln] = true
    of 3:   # ROTL
      let ln = if firstHalf: int(prProgA.next64() and 3'u64) else: int(prProgB.next64() and 3'u64)
      let r = 1 + int((if firstHalf: prProgA.next64() else: prProgB.next64()) mod 63'u64)
      prog.add Instr(op: OP_ROTL, lane: int8(ln), rot: uint8(r))
      laneHit[ln] = true
    of 4:   # MUL (odd, not 1)
      let ln = if forcedLane >= 0: forcedLane else: (if firstHalf: int(prProgA.next64() and 3'u64) else: int(prProgB.next64() and 3'u64))
      var c = (if firstHalf: prProgA.next64() else: prProgB.next64()) or 1'u64
      while c == 1'u64:
        c = (if firstHalf: prProgA.next64() else: prProgB.next64()) or 1'u64  # reject identity multiplier
      prog.add Instr(op: OP_MUL, lane: int8(ln), imm: c)
      haveMul = true
      laneHit[ln] = true
      mulLaneSeen[ln] = true
    of 5:   # PERM
      let permVal = if firstHalf: genPerm32(prProgA) else: genPerm32(prProgB)
      prog.add Instr(op: OP_PERM, lane: -1'i8, perm: permVal)
      inc permCount
    else:   # CROSS
      let r1 = 1 + int((if firstHalf: prProgA.next64() else: prProgB.next64()) mod 63'u64)
      let r2 = 1 + int((if firstHalf: prProgA.next64() else: prProgB.next64()) mod 63'u64)
      let r3 = 1 + int((if firstHalf: prProgA.next64() else: prProgB.next64()) mod 63'u64)
      let r4 = 1 + int((if firstHalf: prProgA.next64() else: prProgB.next64()) mod 63'u64)
      prog.add Instr(op: OP_CROSS, lane: -1'i8, rot: uint8(r1), r2: uint8(r2), r3: uint8(r3), r4: uint8(r4))
      inc crossCount
      if winRemaining >= 5: crossFirst = true else: crossSecond = true

    inc step
    dec winRemaining
    if winRemaining == 0:
      winRemaining = 8
      permCount = 0
      crossCount = 0
      crossFirst = false
      crossSecond = false
      haveMul = false
      for i in 0..3: laneHit[i] = false

    dec superRemaining
    if superRemaining == 0:
      superRemaining = 16
      for i in 0..3: mulLaneSeen[i] = false

  result.enc = prog

  # Build dec program as inverse in reverse order
  result.dec = @[]
  for i in countdown(prog.high, 0):
    let ins = prog[i]
    case ins.op
    of OP_XOR:
      result.dec.add ins # self-inverse
    of OP_ADD:
      # inverse handled in runProgCT via decrypt flag (SUB)
      result.dec.add Instr(op: OP_ADD, lane: ins.lane, imm: ins.imm)
    of OP_ROTL:
      # inverse handled in runProgCT via decrypt flag (ROTR)
      result.dec.add Instr(op: OP_ROTL, lane: ins.lane, rot: ins.rot)
    of OP_MUL:
      let invc = invOdd64(ins.imm)
      result.dec.add Instr(op: OP_MUL, lane: ins.lane, imm: invc)
    of OP_PERM:
      let invp = permInverse(ins.perm)
      result.dec.add Instr(op: OP_PERM, lane: -1'i8, perm: invp)
    of OP_CROSS:
      result.dec.add ins # handled by inverse routine in engine

# ------- Block encryption/decryption -------

proc encryptBlock*(ks: KeySchedule, buf: openArray[byte]): array[PI_BLOCK_BYTES, byte] =
  doAssert buf.len == PI_BLOCK_BYTES
  var st = loadState(buf)
  for i in 0..3: st[i] = st[i] xor ks.wIn[i]
  runProgCT(st, ks.enc, false)
  for i in 0..3: st[i] = st[i] xor ks.wOut[i]
  var outb: array[PI_BLOCK_BYTES, byte]
  storeState(outb, st)
  outb

proc decryptBlock*(ks: KeySchedule, buf: openArray[byte]): array[PI_BLOCK_BYTES, byte] =
  doAssert buf.len == PI_BLOCK_BYTES
  var st = loadState(buf)
  for i in 0..3: st[i] = st[i] xor ks.wOut[i]
  runProgCT(st, ks.dec, true)
  for i in 0..3: st[i] = st[i] xor ks.wIn[i]
  var outb: array[PI_BLOCK_BYTES, byte]
  storeState(outb, st)
  outb
