# NOTE: Nim 2.0 might need std imports because of changes to standard library

# ========================================
# File: src/aurora256.nim
# ========================================
when isMainModule: discard

import ./common

# AURORA-Π (RMC): Reversible Microcoded Cipher over 256-bit blocks
# Implements a key/tweak-programmed instruction stream. Constant-time ops only.

const
  PI_BLOCK_BYTES* = AURORA_BLOCK_BYTES # 32
  PI_KEY_BYTES*   = AURORA_KEY_BYTES   # 32
  PI_TWEAK_BYTES* = AURORA_TWEAK_BYTES # 16

# Compile-time profile (override with: -d:piProfile=balanced or test)
const piProfile {.strdefine.}: string = "max"

when piProfile == "balanced":
  const AURX_ROUNDS = 20
  const AURX_WARMUP = 10
  const PI_STEPS    = 48
elif piProfile == "test":
  const AURX_ROUNDS = 16
  const AURX_WARMUP =  8
  const PI_STEPS    = 32
else: # max (default)
  const AURX_ROUNDS = 28
  const AURX_WARMUP = 12
  const PI_STEPS    = 64 # micro-ops count (heuristic)

# ------- basic helpers -------

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

# ------- PRF (key/tweak to stream) — AURX512 ARX-MUL permutation -------

type PRF* = object
  s: array[8, uint64]      # 512-bit state
  ctr: uint64
  outbuf: array[2, uint64] # squeeze 2 words (capacity bump)
  idx: int                 # 0..2
  mulSched: array[AURX_ROUNDS, uint64]  # per-round odd multipliers (key/tweak-derived)

var RC_Ag: array[12, uint64]
var RC_Mg: array[12, uint64]
var rcInitDone = false

proc mix(a: var uint64, b: var uint64, r: int, m: uint64, c: uint64) {.inline.} =
  a = a + (b xor c)
  b = rotr(b xor a, r)
  a = a * m

proc mix2(a: var uint64, b: var uint64, r: int, m: uint64, c: uint64) {.inline.} =
  a = a xor (b + c)
  b = rotl(b, r) xor a
  a = a * m # odd multiplier => invertible mod 2^64

proc splitmix64(state: var uint64): uint64 {.inline.} =
  state = state + 0x9e3779b97f4a7c15'u64
  var z = state
  z = (z xor (z shr 30)) * 0xbf58476d1ce4e5b9'u64
  z = (z xor (z shr 27)) * 0x94d049bb133111eb'u64
  z = z xor (z shr 31)
  return z

proc fnv64(data: string): uint64 =
  var h: uint64 = 1469598103934665603'u64
  for ch in data:
    h = h xor uint64(ord(ch))
    h = h * 1099511628211'u64
  return h

proc initRCsOnce() =
  if rcInitDone: return
  var sa = fnv64("AURORA-PI-RC_A-v1")
  var sm = fnv64("AURORA-PI-RC_M-v1")
  # Always populate full families of 12 constants regardless of warmup/profile
  for i in 0..<12:
    RC_Ag[i] = splitmix64(sa)
    RC_Mg[i] = splitmix64(sm) or 1'u64  # force odd multipliers
  rcInitDone = true

proc aurxPerm(pr: var PRF) {.inline.} =
  var s = pr.s
  const R0a = [13, 17, 43, 29]
  const R0b = [11, 19, 37, 31]
  const R1  = [31, 27, 46, 33]
  for r in 0..<AURX_ROUNDS:
    let m0 = pr.mulSched[r]
    let m1 = pr.mulSched[(r+7 ) mod AURX_ROUNDS]
    let m2 = pr.mulSched[(r+13) mod AURX_ROUNDS]
    let m3 = pr.mulSched[(r+19) mod AURX_ROUNDS]

    if (r and 1) == 0:
      mix( s[0], s[1], R0a[0], m0, RC_Ag[(r)    mod 12])
      mix( s[2], s[3], R0a[1], m1, RC_Ag[(r+5)  mod 12])
      mix( s[4], s[5], R0a[2], m2, RC_Ag[(r+7)  mod 12])
      mix( s[6], s[7], R0a[3], m3, RC_Ag[(r+2)  mod 12])
    else:
      mix2(s[0], s[1], R0b[0], m0, RC_Ag[(r+1)  mod 12])
      mix2(s[2], s[3], R0b[1], m1, RC_Ag[(r+6)  mod 12])
      mix2(s[4], s[5], R0b[2], m2, RC_Ag[(r+8)  mod 12])
      mix2(s[6], s[7], R0b[3], m3, RC_Ag[(r+3)  mod 12])

    # cross-lane coupling
    s[1] = s[1] + rotl(s[0], R1[0])
    s[3] = s[3] xor rotl(s[2], R1[1])
    s[5] = s[5] + rotl(s[4], R1[2])
    s[7] = s[7] xor rotl(s[6], R1[3])

    # lane shuffle
    let t = s
    s[0] = t[0]; s[1] = t[3]; s[2] = t[5]; s[3] = t[7]
    s[4] = t[2]; s[5] = t[4]; s[6] = t[6]; s[7] = t[1]

    # constant coverage across lanes
    for i in 0..7:
      s[i] = s[i] xor rotl(RC_Ag[((r + i) mod 12)], ((i*9 + r) and 63))
  pr.s = s

proc initPRF(key: openArray[byte], tweak: openArray[byte]): PRF =
  initRCsOnce()
  doAssert key.len == PI_KEY_BYTES
  doAssert tweak.len == 0 or tweak.len == PI_TWEAK_BYTES

  # Seed state from key/tweak (same semantics as before)
  result.s[0] = load64(key, 0)
  result.s[1] = load64(key, 8)
  result.s[2] = load64(key, 16)
  result.s[3] = load64(key, 24)
  if tweak.len == 0:
    result.s[4] = 0x746f702d74776561'u64    # "top-twea"
    result.s[5] = 0x6b2d6e756c6c2d30'u64    # "k-null-0"
  else:
    result.s[4] = load64(tweak, 0)
    result.s[5] = load64(tweak, 8)
  result.s[6] = 0x243f6a8885a308d3'u64
  result.s[7] = 0x13198a2e03707344'u64

  result.ctr = 0
  result.idx = 2            # force a refill on first next32/next64

  # --- NEW: derive per-round odd multipliers from (key,tweak) transparently ---
  var seed = result.s[0] xor result.s[2] xor (result.s[1] shl 1) xor (result.s[3] shr 1) xor 0x414152'u64
  for r in 0..<AURX_ROUNDS:
    var x = splitmix64(seed)      # documented stream generator
    result.mulSched[r] = (x or 1'u64)  # force odd (invertible mod 2^64)

  # Warm-up permutations using the new mul schedule
  for _ in 0..<AURX_WARMUP:
    aurxPerm(result)

  # Ready to squeeze
  result.idx = 2

proc refill(pr: var PRF) {.inline.} =
  # Nonlinear, keyed counter absorption + capacity-friendly squeeze
  let idx = int(pr.ctr mod 12)
  let lane = int(((pr.s[0] xor pr.s[5] xor pr.ctr) and 7'u64))
  let lane2 = (lane + 3) and 7
  let prod = pr.ctr * RC_Mg[idx]
  pr.s[lane]  = pr.s[lane]  + prod
  pr.s[lane2] = pr.s[lane2] xor rotl(prod, int((pr.ctr shr 5) and 63'u64))
  pr.s[6] = pr.s[6] + 0x9e3779b97f4a7c15'u64
  aurxPerm(pr)
  pr.outbuf[0] = pr.s[0] xor pr.s[4]
  pr.outbuf[1] = pr.s[2] xor pr.s[6]
  pr.idx = 0
  pr.ctr = pr.ctr + 1'u64

proc absorb(pr: var PRF, t0, t1: uint64) {.inline.} =
  pr.s[4] = pr.s[4] xor t0
  pr.s[5] = pr.s[5] + t1
  pr.refill()  # permute and refresh buffer

proc next64(pr: var PRF): uint64 {.inline.} =
  if pr.idx >= 2: pr.refill()
  let w = pr.outbuf[pr.idx]
  pr.idx += 1
  return w

# ------- Byte permutation (invertible) -------

proc genPerm32(pr: var PRF): array[32, byte] =
  var p: array[32, byte]
  for i in 0..31: p[i] = byte(i)
  var i = 31
  while i > 0:
    let j = int(next64(pr) mod uint64(i+1))
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
  result = uint8(mask32 and 0xFF'u32)

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
  return fromBytes(outb)

# ------- Instruction set -------

type
  OpKind = enum
    OP_XOR, OP_ADD, OP_ROTL, OP_MUL, OP_PERM, OP_CROSS

  Instr = object
    op: OpKind
    lane: int8            # 0..3 or -1 for non-lane ops
    rot: uint8            # for ROTL or GFSHIFT (1..63)
    r2, r3, r4: uint8     # for CROSS
    imm: uint64           # for XOR/ADD
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

# ------- Ops -------

proc doXor( x: var State256, lane: int, c: uint64) {.inline.} = x[lane] = x[lane] xor c
proc doAdd( x: var State256, lane: int, c: uint64) {.inline.} = x[lane] = x[lane] + c
proc doSub( x: var State256, lane: int, c: uint64) {.inline.} = x[lane] = x[lane] - c
proc doRotl(x: var State256, lane: int, r: int)    {.inline.} = x[lane] = rotl(x[lane], r)
proc doRotr(x: var State256, lane: int, r: int)    {.inline.} = x[lane] = rotr(x[lane], r)
proc doMul( x: var State256, lane: int, c: uint64) {.inline.} = x[lane] = x[lane] * c

# multiplicative inverse of odd 64-bit modulo 2^64
proc invOdd64(c: uint64): uint64 =
  var x: uint64 = 1'u64
  for _ in 0..5:
    x = x * (2'u64 - c * x)
  return x

proc doPerm(x: var State256, p: array[32, byte]) {.inline.} =
  x = applyPerm(x, p)

proc doCross(x: var State256, r1, r2, r3, r4: int) =
  # forward
  x[0] = x[0] +   rotl(x[1], r1)
  x[2] = x[2] +   rotl(x[3], r2)
  x[1] = x[1] xor rotl(x[2], r3)
  x[3] = x[3] xor rotl(x[0], r4)

proc doCrossInv(x: var State256, r1, r2, r3, r4: int) =
  # inverse order
  x[3] = x[3] xor rotl(x[0], r4)
  x[1] = x[1] xor rotl(x[2], r3)
  x[2] = x[2] -   rotl(x[3], r2)
  x[0] = x[0] -   rotl(x[1], r1)

# ------- Program generation -------

proc expandKey*(key: openArray[byte], tweak: openArray[byte] = @[]): KeySchedule =
  doAssert key.len == PI_KEY_BYTES
  doAssert tweak.len == 0 or tweak.len == PI_TWEAK_BYTES
  var pr = initPRF(key, tweak)

  # Domain-separated draws from PRF
  const DOM_WIN  = 0x57494e5f5049'u64   # "WIN_PI"
  const DOM_WOUT = 0x574f55545f5049'u64 # "WOUT_PI"
  const DOM_PROG = 0x50524f475f5049'u64 # "PROG_PI"

  # Whitening in/out
  pr.absorb(DOM_WIN, 0x01'u64)
  for i in 0..3: result.wIn[i] = pr.next64()
  pr.absorb(DOM_WOUT, 0x02'u64)
  for i in 0..3: result.wOut[i] = pr.next64()
  # Program synthesis
  pr.absorb(DOM_PROG, 0x03'u64)

  # Build enc program
  var prog: seq[Instr]  = @[]
  var step: int         = 0
  var winRemaining: int = 8
  var havePerm: bool    = false
  var haveCross: bool   = false
  var haveMul: bool     = false
  var laneHit: array[4, bool]

  while step < PI_STEPS:
    if step == PI_STEPS div 2:
      pr.absorb(DOM_PROG, 0x04'u64)
    var forceKind = -1
    var forcedLane = -1
    if winRemaining == 1:
      if not havePerm:
        forceKind = 5   # PERM
      elif not haveCross:
        forceKind = 6   # CROSS
      elif not haveMul:
        forceKind = 4   # MUL
      else:
        # Enforce per-window lane coverage for lane-local ops
        for ln in 0..3:
          if not laneHit[ln]:
            forceKind = 0   # choose a lane-op (XOR)
            forcedLane = ln
            break

    let pick = if forceKind >= 0: forceKind else: int(pr.next64() mod 8)
    case pick
    of 0,1: # XOR
      let ln = if forcedLane >= 0: forcedLane else: int(pr.next64() and 3'u64)
      var c = pr.next64()
      while c == 0'u64: c = pr.next64()          # reject true no-op
      prog.add Instr(op: OP_XOR, lane: int8(ln), imm: c)
      laneHit[ln] = true
    of 2:   # ADD (odd)
      let ln = int(pr.next64() and 3'u64)
      let c = pr.next64() or 1'u64
      prog.add Instr(op: OP_ADD, lane: int8(ln), imm: c)
      laneHit[ln] = true
    of 3:   # ROTL
      let ln = int(pr.next64() and 3'u64)
      let r = 1 + int(pr.next64() mod 63'u64)
      prog.add Instr(op: OP_ROTL, lane: int8(ln), rot: uint8(r))
      laneHit[ln] = true
    of 4:   # MUL (odd)
      let ln = int(pr.next64() and 3'u64)
      var c = pr.next64() or 1'u64
      while c == 1'u64: c = pr.next64() or 1'u64  # reject identity multiplier
      prog.add Instr(op: OP_MUL, lane: int8(ln), imm: c)
      haveMul = true
      laneHit[ln] = true
    of 5:   # PERM
      let permVal = genPerm32(pr)
      prog.add Instr(op: OP_PERM, lane: -1'i8, perm: permVal)
      havePerm = true
    else:   # CROSS
      let r1 = 1 + int(pr.next64() mod 63'u64)
      let r2 = 1 + int(pr.next64() mod 63'u64)
      let r3 = 1 + int(pr.next64() mod 63'u64)
      let r4 = 1 + int(pr.next64() mod 63'u64)
      prog.add Instr(op: OP_CROSS, lane: -1'i8, rot: uint8(r1), r2: uint8(r2), r3: uint8(r3), r4: uint8(r4))
      haveCross = true

    inc step
    dec winRemaining
    if winRemaining == 0:
      winRemaining = 8
      havePerm = false
      haveCross = false
      haveMul = false
      for i in 0..3: laneHit[i] = false
  result.enc = prog

  # Build dec program as inverse in reverse order
  result.dec = @[]
  for i in countdown(prog.high, 0):
    let ins = prog[i]
    case ins.op
    of OP_XOR:
      result.dec.add ins # self-inverse
    of OP_ADD:
      # inverse is subtraction, handled in runProg via decrypt flag
      result.dec.add Instr(op: OP_ADD, lane: ins.lane, imm: ins.imm)
    of OP_ROTL:
      # inverse handled as ROTR in runProg
      result.dec.add Instr(op: OP_ROTL, lane: ins.lane, rot: ins.rot)
    of OP_MUL:
      let invc = invOdd64(ins.imm)
      result.dec.add Instr(op: OP_MUL, lane: ins.lane, imm: invc)
    of OP_PERM:
      let invp = permInverse(ins.perm)
      result.dec.add Instr(op: OP_PERM, lane: -1'i8, perm: invp)
    of OP_CROSS:
      result.dec.add ins # handled by inverse routine

# ------- Execute -------

proc runProg(x: var State256, prog: seq[Instr], decrypt = false) =
  for ins in prog:
    case ins.op
    of OP_XOR:
      doXor(x, int(ins.lane), ins.imm)
    of OP_ADD:
      if decrypt: doSub(x, int(ins.lane), ins.imm) else: doAdd(x, int(ins.lane), ins.imm)
    of OP_ROTL:
      if decrypt: doRotr(x, int(ins.lane), int(ins.rot)) else: doRotl(x, int(ins.lane), int(ins.rot))
    of OP_MUL:
      doMul(x, int(ins.lane), ins.imm)
    of OP_PERM:
      doPerm(x, ins.perm)
    of OP_CROSS:
      if decrypt: doCrossInv(x, int(ins.rot), int(ins.r2), int(ins.r3), int(ins.r4))
      else:       doCross(x,    int(ins.rot), int(ins.r2), int(ins.r3), int(ins.r4))

# Encrypt a single 256-bit block (tweakable via expandKey)
proc encryptBlock*(ks: KeySchedule, buf: openArray[byte]): array[PI_BLOCK_BYTES, byte] =
  doAssert buf.len == PI_BLOCK_BYTES
  var st = loadState(buf)
  for i in 0..3: st[i] = st[i] xor ks.wIn[i]
  runProg(st, ks.enc, false)
  for i in 0..3: st[i] = st[i] xor ks.wOut[i]
  var outb: array[PI_BLOCK_BYTES, byte]
  storeState(outb, st)
  return outb

# Decrypt a single 256-bit block (same tweak used at expandKey)
proc decryptBlock*(ks: KeySchedule, buf: openArray[byte]): array[PI_BLOCK_BYTES, byte] =
  doAssert buf.len == PI_BLOCK_BYTES
  var st = loadState(buf)
  for i in 0..3: st[i] = st[i] xor ks.wOut[i]
  runProg(st, ks.dec, true)
  for i in 0..3: st[i] = st[i] xor ks.wIn[i]
  var outb: array[PI_BLOCK_BYTES, byte]
  storeState(outb, st)
  return outb
