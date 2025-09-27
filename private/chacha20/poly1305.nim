import std/[parseutils, strutils, sysrand]
import ./blake2/blake2s

from chacha20 import derivePoly1305KeyPair

# NOTE: ported from https://github.com/Legrandin/pycryptodome/blob/master/src/poly1305.c
# NOTE: https://datatracker.ietf.org/doc/html/rfc8439

type
  MacState = object
    r, rr: array[4, uint32]    # First key - variable in polynomial
    s, h: array[5, uint32]     # Second key and state, respectively
    buffer: array[16, uint8]
    bufferUsed: uint           # Track how much of the buffer is used

const
  ErrNull = 1
  ErrKeySize = 2
  ErrMemory = 3
  ErrDigestSize = 4
  Ok = 0

######################################################################################

proc stringToArray(s: string): array[16, uint8] =
  if s.len != 16:
    raise newException(ValueError, "String must be exactly 16 characters long")
  for i in 0 ..< s.len:
    result[i] = s[i].ord.uint8


proc encodeBytes(s: string): seq[byte] =
  ## encode ascii string to bytes
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)
  
  return result


proc decodeBytes(bs: openArray[byte]): string =
  ## decode bytes to ascii string
  result = newStringOfCap(bs.len)
  for i, b in bs:
    result.add(char(b))
  
  return result


proc unhexlify(hexStr: string): seq[byte] =
  ## Converts a hexadecimal string to its actual byte representation.
  if hexStr.len mod 2 != 0:
    raise newException(ValueError, "Hexadecimal string must have an even length.")
  result = newSeq[byte](hexStr.len div 2)
  for i in 0 ..< result.len:
    discard parseHex[byte](hexStr.substr(i * 2, i * 2 + 1), result[i])

######################################################################################

proc poly1305LoadR(r: var array[4, uint32], rr: var array[4, uint32], secret: openArray[uint8]) =
  for i in 0 ..< 4:
    let mask = if i == 0: 0x0FFFFFF'u32 else: 0x0FFFFFFC'u32
    r[i] = (uint32(secret[i*4]) or
            uint32(secret[i*4 + 1]) shl 8 or
            uint32(secret[i*4 + 2]) shl 16 or
            uint32(secret[i*4 + 3]) shl 24) and mask
    rr[i] = (r[i] shr 2) * 5


proc poly1305LoadM(m: var array[5, uint32], data: openArray[uint8], len: Natural) =
  if len > 16:
    raise newException(ValueError, "poly1305_load_m: length must be <= 16")

  var copy: array[20, uint8]  # 5 * 4 bytes = 20 bytes
  for i in 0 ..< len:
    copy[i] = data[i]
  if len < copy.len:
    copy[len] = 1'u8  # 2^128 or 2^{8*(l mod 16)}

  for i in 0 ..< 5:
    let offset = i * 4
    # Assuming little-endian format
    m[i] = uint32(copy[offset]) or
           uint32(copy[offset+1]) shl 8 or
           uint32(copy[offset+2]) shl 16 or
           uint32(copy[offset+3]) shl 24
    if i == 4:  # Correct handling for the fifth element
      if len < 16:
        m[i] = 0'u32


proc poly1305LoadS(m: var array[5, uint32], s: openArray[uint8]) =
  for i in 0 ..< 4:
    let offset = i * 4
    m[i] = uint32(s[offset]) or
           uint32(s[offset+1]) shl 8 or
           uint32(s[offset+2]) shl 16 or
           uint32(s[offset+3]) shl 24
  m[4] = 0'u32  # Explicitly set the fifth element to 0


proc poly1305Multiply(h: var array[5, uint32], r: openArray[uint32], rr: openArray[uint32]) =
  var
    a0,  a1,  a2,  a3:      uint64
    aa0, aa1, aa2, aa3:     uint64
    x0,  x1,  x2,  x3,  x4: uint64
    carry:                  uint64

  # Assigning values from r and rr to variables for easier manipulation
  a0 =  r[0].uint64
  a1 =  r[1].uint64
  a2 =  r[2].uint64
  a3 =  r[3].uint64
  aa0 = rr[0].uint64
  aa1 = rr[1].uint64
  aa2 = rr[2].uint64
  aa3 = rr[3].uint64

  # Schoolbook multiplication
  x0 = a0 * h[0].uint64 + aa0 * h[4].uint64 + aa1 * h[3].uint64 + aa2 * h[2].uint64 + aa3 * h[1].uint64
  x1 = a0 * h[1].uint64 +  a1 * h[0].uint64 + aa1 * h[4].uint64 + aa2 * h[3].uint64 + aa3 * h[2].uint64
  x2 = a0 * h[2].uint64 +  a1 * h[1].uint64 +  a2 * h[0].uint64 + aa2 * h[4].uint64 + aa3 * h[3].uint64
  x3 = a0 * h[3].uint64 +  a1 * h[2].uint64 +  a2 * h[1].uint64 +  a3 * h[0].uint64 + aa3 * h[4].uint64
  x4 = (a0 and 3) * h[4].uint64

  # Adjusting and carrying as necessary
  x4 += x3 shr 32
  x3 = x3 and 0xFFFFFFFF'u64

  carry = (x4 shr 2) * 5
  x4 = x4 and 3

  # Reducing and storing back into h
  x0 += carry
  h[0] = uint32(x0 and 0xFFFFFFFF'u64)
  carry = x0 shr 32

  x1 += carry
  h[1] = uint32(x1 and 0xFFFFFFFF'u64)
  carry = x1 shr 32

  x2 += carry
  h[2] = uint32(x2 and 0xFFFFFFFF'u64)
  carry = x2 shr 32

  x3 += carry
  h[3] = uint32(x3 and 0xFFFFFFFF'u64)
  carry = x3 shr 32

  x4 += carry
  assert(x4 < 8'u64)
  h[4] = uint32(x4)


proc poly1305Reduce(h: var array[5, uint32]) =
  if h[4] >= 8'u32:
    raise newException(ValueError, "poly1305_reduce: invariant violated (h[4] >= 8)")

  for i in 0..<2:
    var
      mask, carry: uint32
      g: array[5, uint32]

    # Compute h + (-p) by adding and removing 2^130
    g[0] = h[0] + 5
    carry = if g[0] < h[0]: 1'u32 else: 0'u32

    g[1] = h[1] + carry
    carry = if g[1] < h[1]: 1'u32 else: 0'u32

    g[2] = h[2] + carry
    carry = if g[2] < h[2]: 1'u32 else: 0'u32

    g[3] = h[3] + carry
    carry = if g[3] < h[3]: 1'u32 else: 0'u32

    g[4] = h[4] + carry - 4'u32

    mask = ((g[4] shr 31) - 1'u32).uint32  # All 1s if g[] is a valid reduction

    # Conditional application of g[] to h[] based on mask
    for j in 0..<5:
      h[j] = (h[j] and not mask) xor (g[j] and mask)


proc poly1305Accumulate(h: var array[5, uint32], m: openArray[uint32]) =
  var
    carry: uint8
    tmp: uint64

  # Addition with carry handling for the first 32-bit chunk
  h[0] += m[0]
  carry = if h[0] < m[0]: 1 else: 0

  # Process each subsequent chunk, taking into account the carry from the previous operation
  for i in 1 ..< 5:
    tmp   = uint64(h[i]) + m[i] + carry
    h[i]  = uint32(tmp)
    carry = uint8( tmp shr 32) # Extract new carry

  if carry != 0:
    raise newException(ValueError, "poly1305Accumulate: final carry must be 0")


proc poly1305Process(h: var array[5, uint32], r: openArray[uint32], rr: openArray[uint32], msg: openArray[uint8], len: Natural) =
  if len == 0:
    return

  var m: array[5, uint32]
  poly1305LoadM(m, msg, len)
  poly1305Accumulate(h, m)
  poly1305Multiply(h, r, rr)


proc poly1305Finalize(h: var array[5, uint32], s: openArray[uint32]) =
  poly1305Reduce(h)          # Reduce modulo 2^130 - 5
  poly1305Accumulate(h, s)   # Add the fixed part of the key
  h[4] = 0'u32               # Ensure the result is within 128 bits

######################################################################################

proc poly1305Init(state: var MacState, r: openArray[uint8], s: openArray[uint8]): int =
  if r.len == 0 or s.len == 0:
    return ErrNull

  if r.len != 16 or s.len != 16:
    return ErrKeySize

  poly1305LoadR(state.r, state.rr, r)
  poly1305LoadS(state.s, s)

  return Ok


proc poly1305Update(state: var MacState, input: openArray[uint8], len: Natural): int =
  if len == 0:
    return ErrNull

  var pos = 0  # Current position in the input data
  var vLen = len
  while vLen > 0:
    let btc = min(vLen, 16 - state.bufferUsed)  # Bytes to copy
    for i in 0 ..< btc:
      state.buffer[state.bufferUsed + i.uint] = input[pos + i]
    inc(state.bufferUsed, btc)
    inc(pos, btc)
    dec(vLen, btc)

    if state.bufferUsed == 16:
      poly1305Process(state.h, state.r, state.rr, state.buffer, 16)
      state.bufferUsed = 0

  return Ok


proc poly1305Digest(state: var MacState, digest: var openArray[uint8], len: Natural): int =
  if digest.len == 0:
    return ErrNull

  if len != 16:
    return ErrDigestSize

  # Create a temporary copy of the state to avoid mutating the original state
  var temp = state

  # Process any remaining bytes in the buffer
  if temp.bufferUsed > 0:
    poly1305Process(temp.h, temp.r, temp.rr, temp.buffer, temp.bufferUsed)
    temp.bufferUsed = 0  # Reset buffer used after processing

  # Finalize the computation
  poly1305Finalize(temp.h, temp.s)

  # Store the result in the digest array
  for i in 0 ..< 4:
    let value = temp.h[i]
    digest[i * 4    ] = uint8( value         and 0xFF)
    digest[i * 4 + 1] = uint8((value shr  8) and 0xFF)
    digest[i * 4 + 2] = uint8((value shr 16) and 0xFF)
    digest[i * 4 + 3] = uint8((value shr 24) and 0xFF)

  return Ok

# --- in private/poly1305.nim (or wherever your module lives) ---

# Add this near your other exported constructors:

proc newPoly1305FromRS*(r: openArray[byte], s: openArray[byte],
                        data: openArray[byte] = @[]): MacState =
  ## Initialize Poly1305 directly from 16-byte r and 16-byte s.
  if r.len != 16 or s.len != 16:
    raise newException(ValueError, "Poly1305 (r,s) must be 16 bytes each")
  let rc = poly1305Init(result, r, s)   # uses your existing internal proc
  if rc != Ok:
    raise newException(ValueError, "poly1305Init failed")
  if data.len > 0:
    discard result.poly1305Update(data, data.len)
  return result

######################################################################################

proc newPoly1305Ctx*(key, nonce: openArray[byte], data: openArray[byte] = @[]): MacState =
  let (r, s, nonce) = derivePoly1305KeyPair(key, nonce)
  
  let initResult = poly1305Init(result, r, s)
  if initResult != Ok:
    # QUESTION: raise exception here?
    return
  
  if data.len > 0:
    discard result.poly1305Update(data, data.len)
  
  return result


proc newPoly1305Ctx*(key, nonce: string, data: openArray[byte] = @[]): MacState =
  return newPoly1305Ctx(encodeBytes(key), encodeBytes(nonce), data)


proc update*(state: var MacState, input: openArray[uint8]) =
  ## wrapper
  discard state.poly1305Update(input, input.len)


proc update*(state: var MacState, input: string) =
  ## wrapper
  discard state.poly1305Update(encodeBytes(input), input.len)


proc digest*(state: var MacState): array[16, uint8] =
  ## produces a binary mac tag
  ## does not alter mac state
  discard state.poly1305Digest(result, 16)
  return result


proc hexDigest*(state: var MacState): string =
  ## produces a hex string mac tag of length 32
  ## does not alter mac state
  var digest: array[16, uint8]
  discard state.poly1305Digest(digest, 16)
  
  result = newStringOfCap(32)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc verify*(ctx: var MacState, macTag: openArray[uint8]): bool =
  let secret = urandom(16)
  var mac1 = newBlake2sCtx(key=secret, msg=macTag,       digestSize=20)
  var mac2 = newBlake2sCtx(key=secret, msg=ctx.digest(), digestSize=20)

  return mac1.digest() == mac2.digest()


proc hexVerify*(ctx: var MacState, hexMacTag: string): bool =
  return ctx.verify(unhexlify(hexMacTag))

######################################################################################

when isMainModule:
  let secret = "Thirtytwo very very secret bytes"
  let nonce = "0123456789AB"

  var state = newPoly1305Ctx(secret, nonce)
  state.update("Hello")

  let mac = state.hexDigest()
  echo mac
  echo state.hexVerify(mac)
