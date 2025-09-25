import std/[sequtils, strutils, base64]
import ./galois

# Usage notes
# - Contexts are stateful across calls:
#   - CBC: Keeps the previous ciphertext block. If you call encrypt/decrypt
#     multiple times on the same TwofishCbcCtx, blocks chain across calls.
#     To process independent messages, create a fresh ctx with newTwofishCbcCtx.
#   - CTR: Maintains a 128-bit counter (nonce[0..7] || state[0..7]) and
#     increments the low 8 bytes for each block. The counter continues across
#     calls. To process an independent message with the same ctx, either
#     call initCounter() to reset it to nonce||initState or create a new ctx
#     with newTwofishCtrCtx.

# Twofish core expects the cipher state type to be declared before inclusion.
type
  TwoFishCtx = object
    s: array[4, array[256, uint32]]
    k: array[40, uint32]


include twofish_core

const twofishSbox* = sbox
#[
  key sizes (int bytes -> bits):
    16 -> 128bit
    24 -> 192bit
    32 -> 256bit
]#

const blocksize = 16

type
  TwofishEcbCtx* = object # Electronic CodeBook
    key:            seq[byte]
    state:          TwoFishCtx
  TwofishCbcCtx* = object # Ciphertext Block Chaining
    key:            seq[byte]
    iv:             seq[byte]
    state:          TwoFishCtx
    previousBlock:  array[blocksize, byte]
    isEncryptState: bool
  TwofishCtrCtx* = object # Counter
    key:            seq[byte]
    nonce:          seq[byte]
    state:          TwoFishCtx
    initState:      array[8, byte]
    counter:        array[blocksize, byte]
    isEncryptState: bool
  TwofishGcmCtx* = object # Galois/Counter Mode (AEAD)
    key:   seq[byte]
    iv:    seq[byte]
    state: TwoFishCtx
    H:     Block128           # E_K(0^128)
    J0:    Block128           # pre-counter block
  TwofishGcmSivCtx* = object # GCM-SIV (AEAD, per-nonce key derivation)
    key:   seq[byte]          # key-generating key (16 or 32 bytes)
    nonce: seq[byte]          # 12 bytes
  TwofishXtsCtx* = object # XTS mode (IEEE P1619)
    key1:  seq[byte]          # 16 or 32 bytes
    key2:  seq[byte]          # 16 or 32 bytes
    st1:   TwoFishCtx         # data encryption key
    st2:   TwoFishCtx         # tweak encryption key


#################################################################################

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

proc fromHex*(h: string): seq[byte] =
  ## parse lowercase/uppercase hex string to bytes
  if h.len mod 2 != 0:
    raise newException(ValueError, "hex string must have even length")
  result = newSeq[byte](h.len div 2)
  for i in 0 ..< result.len:
    let a = h[2*i]
    let b = h[2*i+1]
    proc val(c: char): int =
      if c >= '0' and c <= '9': int(c) - int('0')
      elif c >= 'a' and c <= 'f': 10 + int(c) - int('a')
      elif c >= 'A' and c <= 'F': 10 + int(c) - int('A')
      else: raise newException(ValueError, "invalid hex char: " & $c)
    result[i] = byte((val(a) shl 4) or val(b))


proc padPKCS7*(data: openArray[byte]): seq[byte] =
  let paddingLen = 16 - (len(data) mod 16)
  let paddingByte = paddingLen.byte
  result = newSeqOfCap[byte](len(data) + paddingLen)
  result.add(data)
  for _ in 1 .. paddingLen:
    result.add(paddingByte)


proc unpadPKCS7*(data: openArray[byte]): seq[byte] =
  if data.len == 0 or data.len mod 16 != 0:
    raise newException(ValueError, "Invalid padded data length")
  
  let paddingLen = data[^1].int
  if paddingLen < 1 or paddingLen > 16:
    raise newException(ValueError, "Invalid padding length")
  
  for i in 1 .. paddingLen:
    if data[data.len - i] != paddingLen.byte:
      raise newException(ValueError, "Invalid padding")
  result = data[0 ..< data.len - paddingLen]


proc xorBlocks(this: var openArray[byte], that: openArray[byte]) =
  for i in 0 ..< this.len:
    this[i] = this[i] xor that[i]


proc xorBlocks(this: openArray[byte], that: openArray[byte]): array[blocksize, byte] =
  for i in 0 ..< this.len:
    result[i] = this[i] xor that[i]


proc xorBlocksSeq(this: openArray[byte], that: openArray[byte]): seq[byte] =
  result = newSeq[byte](this.len)
  for i in 0 ..< this.len:
    result[i] = this[i] xor that[i]


proc initPreviousBlock(ctx: var TwofishCbcCtx) =
  ## initialize previous block with IV
  for i, b in ctx.iv:
    ctx.previousBlock[i] = b


proc initCounter*(ctx: var TwofishCtrCtx) =
  ## initialize counter with IV
  for i, b in ctx.nonce:
    ctx.counter[i] = b
  for i, b in ctx.initState:
    ctx.counter[8 + i] = b


proc incrementCounter(ctx: var TwofishCtrCtx) =
  for i in countdown(15, 8):
    ctx.counter[i] = ctx.counter[i] + 1
    if ctx.counter[i] != 0:  # No overflow for this byte
      return
  raise newException(OverflowDefect, "counter overflow")


proc intToBytesBE(n: uint64): array[8, byte] =
  ## big endian
  for i in 0 ..< 8:
    result[7 - i] = byte((n shr (8 * i)) and 0xFF'u64)


proc hexDigest*(data: openArray[byte]): string =
  ## produces a hex string of length data.len * 2
  result = newStringOfCap(data.len + data.len)
  for b in data:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc `$`*(data: seq[byte]): string =
  return decodeBytes(data)

#################################################################################
# ECB
#################################################################################

proc encrypt*(ctx: TwofishEcbCtx, input: openArray[byte], output: var openArray[byte]) =
  ## ECB Mode
  ## encrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.len - 1, step=blocksize):
    twofishEncrypt(ctx.state, input[i ..< i + blocksize], blk)
    for j, b in blk:
      output[i + j] = b


proc encrypt*(ctx: TwofishEcbCtx, input: openArray[byte]): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.len - 1, step=blocksize):
    twofishEncrypt(ctx.state, input[i ..< i + blocksize], blk)
    for j, b in blk:
      result[i + j] = b

  return result


proc encrypt*(ctx: TwofishEcbCtx, input: string, output: var openArray[byte]) =
  ## ECB Mode
  ## encrypt in place
  encrypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: TwofishEcbCtx, input: string): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  return encrypt(ctx, input.toOpenArrayByte(0, input.len.pred))


proc decrypt*(ctx: TwofishEcbCtx, input: openArray[byte], output: var openArray[byte]) =
  ## ECB Mode
  ## decrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.len.pred, step=blocksize):
    twofishDecrypt(ctx.state, input[i ..< i + blocksize], blk)
    for j, b in blk:
      output[i + j] = b


proc decrypt*(ctx: TwofishEcbCtx, input: openArray[byte]): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.len.pred, step=blocksize):
    twofishDecrypt(ctx.state, input[i ..< i + blocksize], blk)
    for j, b in blk:
      result[i + j] = b

  return result


proc decrypt*(ctx: TwofishEcbCtx, input: string, output: var openArray[byte]) =
  ## ECB Mode
  ## decrypt in place
  decrypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: TwofishEcbCtx, input: string): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  return decrypt(ctx, input.encodeBytes())

#################################################################################
# CBC
#################################################################################

proc encrypt*(ctx: var TwofishCbcCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CBC Mode
  ## encrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  if not ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = true


  for i in countup(0, input.high, step=blocksize):
    # XOR with previous ciphertext block (or IV)
    twofishEncrypt(ctx.state, xorBlocks(input[i ..< i + blocksize], ctx.previousBlock), blk)
    for j, b in blk:
      output[i + j] = b
    ctx.previousBlock = blk


proc encrypt*(ctx: var TwofishCbcCtx, input: openArray[byte]): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  if not ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = true

  for i in countup(0, input.high, step=blocksize):
    # XOR with previous ciphertext block (or IV)
    twofishEncrypt(ctx.state, xorBlocks(input[i ..< i + blocksize], ctx.previousBlock), blk)
    for j, b in blk:
      result[i + j] = b
    ctx.previousBlock = blk

  return result


proc encrypt*(ctx: var TwofishCbcCtx, input: string, output: var openArray[byte]) =
  ## CBC Mode
  ## encrypt in place
  encrypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: var TwofishCbcCtx, input: string): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  return encrypt(ctx, input.encodeBytes())


proc decrypt*(ctx: var TwofishCbcCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CBC Mode
  ## decrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var ptBlk: array[blocksize, byte]
  var ctBlk: array[blocksize, byte]

  if ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = false

  for i in countup(0, input.high, step=blocksize):
    for i, b in input[i ..< i + blocksize]:
      ptBlk[i] = b
    twofishDecrypt(ctx.state, ptBlk, ctBlk)
    # XOR with previous ciphertext block (or IV for the first block)
    xorBlocks(ctBlk, ctx.previousBlock)
    for j, b in ctBlk:
      output[i + j] = b
    
    ctx.previousBlock = ptBlk


proc decrypt*(ctx: var TwofishCbcCtx, input: openArray[byte]): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var ptBlk: array[blocksize, byte]
  var ctBlk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  if ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = false

  for i in countup(0, input.high, step=blocksize):
    for i, b in input[i ..< i + blocksize]:
      ptBlk[i] = b
    twofishDecrypt(ctx.state, ptBlk, ctBlk)
    # XOR with previous ciphertext block (or IV for the first block)
    xorBlocks(ctBlk, ctx.previousBlock)
    for j, b in ctBlk:
      result[i + j] = b
    ctx.previousBlock = ptBlk

  return result


proc decrypt*(ctx: var TwofishCbcCtx, input: string, output: var openArray[byte]) =
  ## CBC Mode
  ## decrypt in place
  decrypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: var TwofishCbcCtx, input: string): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  return decrypt(ctx, input.encodeBytes())

#################################################################################
# CTR
#################################################################################

proc crypt*(ctx: var TwofishCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## crypt in place
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.high, step=blocksize):
    # Encrypt the counter
    twofishEncrypt(ctx.state, ctx.counter, blk)
    ctx.incrementCounter()
    # XOR the encrypted counter with the block
    for j, b in xorBlocksSeq(input[i ..< min(i + blocksize, input.len)], blk):
      output[i + j] = b


proc crypt*(ctx: var TwofishCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns result as new sequence
  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.high, step=blocksize):
    # Encrypt the counter
    twofishEncrypt(ctx.state, ctx.counter, blk)
    ctx.incrementCounter()
    # XOR the encrypted counter with the block
    for j, b in xorBlocksSeq(input[i ..< min(i + blocksize, input.len)], blk):
      result[i + j] = b

  return result


proc encrypt*(ctx: var TwofishCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## encrypt in place
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  crypt(ctx, input, output)


proc encrypt*(ctx: var TwofishCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  return crypt(ctx, input)


proc encrypt*(ctx: var TwofishCtrCtx, input: string, output: var openArray[byte]) =
  ## CTR Mode
  ## encrypt in place
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  crypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: var TwofishCtrCtx, input: string): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  return crypt(ctx, input.encodeBytes())


proc decrypt*(ctx: var TwofishCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## decrypt in place
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  crypt(ctx, input, output)


proc decrypt*(ctx: var TwofishCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  return crypt(ctx, input)


proc decrypt*(ctx: var TwofishCtrCtx, input: string, output: var openArray[byte]) =
  ## CTR Mode
  ## decrypt in place
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  crypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: var TwofishCtrCtx, input: string): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  return crypt(ctx, input.encodeBytes())

#################################################################################
# GCM
#################################################################################

proc inc32(ctr: var Block128) {.inline.} =
  ## increment low 32 bits of counter (big-endian)
  var i = blocksize - 1
  var carry = 1'u16
  # bytes 12..15
  while i >= blocksize - 4:
    let sum = uint16(ctr[i]) + carry
    ctr[i] = byte(sum and 0xFF)
    carry = sum shr 8
    if i == blocksize - 4: break
    dec(i)


proc gcmCalcH(state: TwoFishCtx): Block128 =
  var zero: Block128
  var outBlk: Block128
  twofishEncrypt(state, zero, outBlk)
  for i in 0 ..< blocksize: result[i] = outBlk[i]


proc deriveJ0(H: Block128, iv: openArray[byte]): Block128 =
  if iv.len == 12:
    # IV || 0x00000001
    for i in 0 ..< 12: result[i] = iv[i]
    result[12] = 0x00
    result[13] = 0x00
    result[14] = 0x00
    result[15] = 0x01
  else:
    # J0 = GHASH(H, empty, IV)
    result = ghash(H, newSeq[byte](0), iv)


proc gctr(state: TwoFishCtx, icb: Block128, input: openArray[byte], output: var openArray[byte]) =
  var counter: Block128 = icb
  var stream: Block128
  var i = 0
  while i < input.len:
    inc32(counter)
    twofishEncrypt(state, counter, stream)
    let take = min(blocksize, input.len - i)
    for j in 0 ..< take:
      output[i + j] = input[i + j] xor stream[j]
    i.inc(take)


proc encrypt*(ctx: var TwofishGcmCtx, aad: openArray[byte], plaintext: openArray[byte], ciphertext: var openArray[byte], tag: var openArray[byte]) =
  if plaintext.len > ciphertext.len:
    raise newException(ValueError, "output length must be >= input length")
  if tag.len != blocksize:
    raise newException(ValueError, "tag must be 16 bytes long")
  # C = GCTR(K, inc32(J0), P)
  gctr(ctx.state, ctx.J0, plaintext, ciphertext)
  # S = GHASH(H, A, C)
  let S = ghash(ctx.H, aad, ciphertext)
  # T = E(K, J0) xor S
  var ekJ0: Block128
  twofishEncrypt(ctx.state, ctx.J0, ekJ0)
  for i in 0 ..< blocksize:
    tag[i] = ekJ0[i] xor S[i]


proc encrypt*(ctx: var TwofishGcmCtx, aad: openArray[byte], plaintext: openArray[byte]): (seq[byte], array[blocksize, byte]) =
  var ct = newSeq[byte](plaintext.len)
  var tag: array[blocksize, byte]
  var tagBuf = newSeq[byte](blocksize)
  encrypt(ctx, aad, plaintext, ct, tagBuf)
  for i in 0 ..< blocksize: tag[i] = tagBuf[i]
  return (ct, tag)


proc decrypt*(ctx: var TwofishGcmCtx, aad: openArray[byte], ciphertext: openArray[byte], plaintext: var openArray[byte], tag: openArray[byte]) =
  if ciphertext.len > plaintext.len:
    raise newException(ValueError, "output length must be >= input length")
  if tag.len != blocksize:
    raise newException(ValueError, "tag must be 16 bytes long")
  # Compute expected tag from ciphertext
  let S = ghash(ctx.H, aad, ciphertext)
  var ekJ0: Block128
  twofishEncrypt(ctx.state, ctx.J0, ekJ0)
  var expected = newSeq[byte](blocksize)
  for i in 0 ..< blocksize:
    expected[i] = ekJ0[i] xor S[i]
  if not ctEq(expected, tag):
    raise newException(ValueError, "GCM tag mismatch")
  # P = GCTR(K, inc32(J0), C)
  gctr(ctx.state, ctx.J0, ciphertext, plaintext)


proc decrypt*(ctx: var TwofishGcmCtx, aad: openArray[byte], ciphertext: openArray[byte], tag: openArray[byte]): seq[byte] =
  var pt = newSeq[byte](ciphertext.len)
  decrypt(ctx, aad, ciphertext, pt, tag)
  return pt

#################################################################################
# GCM-SIV
#################################################################################

proc deriveGcmSivKeys*(kgen: openArray[byte], nonce: openArray[byte]): (seq[byte], Block128) =
  ## Returns (message_encryption_key, message_authentication_key)
  if nonce.len != 12:
    raise newException(ValueError, "Nonce must be 12 bytes long")
  var st: TwoFishCtx
  init(kgen, st.s, st.k)
  var blk: array[blocksize, byte]
  var blkOut: array[blocksize, byte]
  var authKey: Block128
  var encKey = newSeq[byte](if kgen.len == 32: 32 else: 16)

  # Authentication key (16 bytes): counters 0,1
  # counter 0
  blk[0] = 0x00; blk[1] = 0x00; blk[2] = 0x00; blk[3] = 0x00
  for i in 0 ..< 12: blk[4 + i] = nonce[i]
  twofishEncrypt(st, blk, blkOut)
  for i in 0 ..< 8: authKey[i] = blkOut[i]
  # counter 1
  blk[0] = 0x01; blk[1] = 0x00; blk[2] = 0x00; blk[3] = 0x00
  for i in 0 ..< 12: blk[4 + i] = nonce[i]
  twofishEncrypt(st, blk, blkOut)
  for i in 0 ..< 8: authKey[8 + i] = blkOut[i]

  # Encryption key: counters 2,3,(4,5)
  blk[0] = 0x02; blk[1] = 0x00; blk[2] = 0x00; blk[3] = 0x00
  for i in 0 ..< 12: blk[4 + i] = nonce[i]
  twofishEncrypt(st, blk, blkOut)
  for i in 0 ..< 8: encKey[i] = blkOut[i]
  blk[0] = 0x03; blk[1] = 0x00; blk[2] = 0x00; blk[3] = 0x00
  for i in 0 ..< 12: blk[4 + i] = nonce[i]
  twofishEncrypt(st, blk, blkOut)
  for i in 0 ..< 8: encKey[8 + i] = blkOut[i]
  if kgen.len == 32:
    blk[0] = 0x04; blk[1] = 0x00; blk[2] = 0x00; blk[3] = 0x00
    for i in 0 ..< 12: blk[4 + i] = nonce[i]
    twofishEncrypt(st, blk, blkOut)
    for i in 0 ..< 8: encKey[16 + i] = blkOut[i]
    blk[0] = 0x05; blk[1] = 0x00; blk[2] = 0x00; blk[3] = 0x00
    for i in 0 ..< 12: blk[4 + i] = nonce[i]
    twofishEncrypt(st, blk, blkOut)
    for i in 0 ..< 8: encKey[24 + i] = blkOut[i]

  return (encKey, authKey)


proc inc32Le(ctr: var array[blocksize, byte]) {.inline.} =
  var carry: uint16 = 1
  for i in 0 ..< 4:
    let s = uint16(ctr[i]) + carry
    ctr[i] = byte(s and 0xFF)
    carry = s shr 8


proc gcmSivCtr(encState: TwoFishCtx, initial: array[blocksize, byte], input: openArray[byte], output: var openArray[byte]) =
  var counter = initial
  var stream: array[blocksize, byte]
  var i = 0
  while i < input.len:
    # keystream = Twofish_K(counter)
    twofishEncrypt(encState, counter, stream)
    let take = min(blocksize, input.len - i)
    for j in 0 ..< take:
      output[i + j] = input[i + j] xor stream[j]
    inc32Le(counter)
    i.inc(take)


proc encrypt*(ctx: TwofishGcmSivCtx, aad: openArray[byte], plaintext: openArray[byte], ciphertext: var openArray[byte], tag: var openArray[byte]) =
  if plaintext.len > ciphertext.len:
    raise newException(ValueError, "output length must be >= input length")
  if tag.len != blocksize:
    raise newException(ValueError, "tag must be 16 bytes long")
  let (encKey, authKey) = deriveGcmSivKeys(ctx.key, ctx.nonce)
  # Compute S_s via POLYVAL over padded AD || padded PT || lenblock(le)
  let S = polyval(authKey, aad, plaintext)
  var tagBlock: array[blocksize, byte]
  for i in 0 ..< blocksize: tagBlock[i] = S[i]
  for i in 0 ..< 12: tagBlock[i] = tagBlock[i] xor ctx.nonce[i]
  tagBlock[15] = tagBlock[15] and 0x7F'u8
  # Encrypt with encKey to get tag
  var encState: TwoFishCtx
  init(encKey, encState.s, encState.k)
  var tagOut: array[blocksize, byte]
  twofishEncrypt(encState, tagBlock, tagOut)
  for i in 0 ..< blocksize: tag[i] = tagOut[i]
  # CTR mode with initial counter = tag with MSB set
  var ctr0 = tagOut
  ctr0[15] = ctr0[15] or 0x80'u8
  gcmSivCtr(encState, ctr0, plaintext, ciphertext)


proc encrypt*(ctx: TwofishGcmSivCtx, aad: openArray[byte], plaintext: openArray[byte]): (seq[byte], array[blocksize, byte]) =
  var ct = newSeq[byte](plaintext.len)
  var tag: array[blocksize, byte]
  var tagBuf = newSeq[byte](blocksize)
  ctx.encrypt(aad, plaintext, ct, tagBuf)
  for i in 0 ..< blocksize: tag[i] = tagBuf[i]
  return (ct, tag)


proc decrypt*(ctx: TwofishGcmSivCtx, aad: openArray[byte], ciphertext: openArray[byte], plaintext: var openArray[byte], tag: openArray[byte]) =
  if ciphertext.len > plaintext.len:
    raise newException(ValueError, "output length must be >= input length")
  if tag.len != blocksize:
    raise newException(ValueError, "tag must be 16 bytes long")
  let (encKey, authKey) = deriveGcmSivKeys(ctx.key, ctx.nonce)
  var encState: TwoFishCtx
  init(encKey, encState.s, encState.k)
  var ctr0: array[blocksize, byte]
  for i in 0 ..< blocksize: ctr0[i] = tag[i]
  ctr0[15] = ctr0[15] or 0x80'u8
  gcmSivCtr(encState, ctr0, ciphertext, plaintext)
  # Compute expected tag from AAD and plaintext
  let S = polyval(authKey, aad, plaintext)
  var tagBlock: array[blocksize, byte]
  for i in 0 ..< blocksize: tagBlock[i] = S[i]
  for i in 0 ..< 12: tagBlock[i] = tagBlock[i] xor ctx.nonce[i]
  tagBlock[15] = tagBlock[15] and 0x7F'u8
  var expected: array[blocksize, byte]
  twofishEncrypt(encState, tagBlock, expected)
  var expectedSeq = newSeq[byte](blocksize)
  for i in 0 ..< blocksize: expectedSeq[i] = expected[i]
  if not ctEq(expectedSeq, tag):
    raise newException(ValueError, "GCM-SIV tag mismatch")


proc decrypt*(ctx: TwofishGcmSivCtx, aad: openArray[byte], ciphertext: openArray[byte], tag: openArray[byte]): seq[byte] =
  var pt = newSeq[byte](ciphertext.len)
  ctx.decrypt(aad, ciphertext, pt, tag)
  return pt

#################################################################################
# AEAD Convenience Wrappers (ct || tag)
#################################################################################

# GCM: returns ciphertext concatenated with 16-byte tag
proc encryptAead*(ctx: var TwofishGcmCtx, aad: openArray[byte], plaintext: openArray[byte]): seq[byte] =
  var ct = newSeq[byte](plaintext.len)
  var tagBuf = newSeq[byte](blocksize)
  ctx.encrypt(aad, plaintext, ct, tagBuf)
  result = newSeq[byte](ct.len + blocksize)
  for i in 0 ..< ct.len: result[i] = ct[i]
  for j in 0 ..< blocksize: result[ct.len + j] = tagBuf[j]


proc decryptAead*(ctx: var TwofishGcmCtx, aad: openArray[byte], data: openArray[byte]): seq[byte] =
  if data.len < blocksize:
    raise newException(ValueError, "aead input too short (no tag)")
  let ctLen = data.len - blocksize
  var pt = newSeq[byte](ctLen)
  ctx.decrypt(aad, data[0 ..< ctLen], pt, data[ctLen ..< data.len])
  return pt


# GCM: string helpers (hex/base64)
proc encryptAeadHex*(ctx: var TwofishGcmCtx, aad, plaintext: string): string =
  let outBuf = ctx.encryptAead(aad.encodeBytes(), plaintext.encodeBytes())
  return hexDigest(outBuf)


proc decryptAeadHex*(ctx: var TwofishGcmCtx, aad: string, dataHex: string): string =
  let data = fromHex(dataHex)
  let pt = ctx.decryptAead(aad.encodeBytes(), data)
  return decodeBytes(pt)


proc encryptAeadB64*(ctx: var TwofishGcmCtx, aad, plaintext: string): string =
  let outBuf = ctx.encryptAead(aad.encodeBytes(), plaintext.encodeBytes())
  return encode(outBuf)


proc decryptAeadB64*(ctx: var TwofishGcmCtx, aad: string, dataB64: string): string =
  let raw = decode(dataB64)
  let data = encodeBytes(raw)
  let pt = ctx.decryptAead(aad.encodeBytes(), data)
  return decodeBytes(pt)


# GCM-SIV: returns ciphertext concatenated with 16-byte tag
proc encryptAead*(ctx: TwofishGcmSivCtx, aad: openArray[byte], plaintext: openArray[byte]): seq[byte] =
  var ct = newSeq[byte](plaintext.len)
  var tagBuf = newSeq[byte](blocksize)
  ctx.encrypt(aad, plaintext, ct, tagBuf)
  result = newSeq[byte](ct.len + blocksize)
  for i in 0 ..< ct.len: result[i] = ct[i]
  for j in 0 ..< blocksize: result[ct.len + j] = tagBuf[j]


proc decryptAead*(ctx: TwofishGcmSivCtx, aad: openArray[byte], data: openArray[byte]): seq[byte] =
  if data.len < blocksize:
    raise newException(ValueError, "aead input too short (no tag)")
  let ctLen = data.len - blocksize
  var pt = newSeq[byte](ctLen)
  ctx.decrypt(aad, data[0 ..< ctLen], pt, data[ctLen ..< data.len])
  return pt


# GCM-SIV: string helpers (hex/base64)
proc encryptAeadHex*(ctx: TwofishGcmSivCtx, aad, plaintext: string): string =
  let outBuf = ctx.encryptAead(aad.encodeBytes(), plaintext.encodeBytes())
  return hexDigest(outBuf)


proc decryptAeadHex*(ctx: TwofishGcmSivCtx, aad: string, dataHex: string): string =
  let data = fromHex(dataHex)
  let pt = ctx.decryptAead(aad.encodeBytes(), data)
  return decodeBytes(pt)

#################################################################################
# XTS
#################################################################################

proc xtsMulAlpha(t: var array[blocksize, byte]) {.inline.} =
  ## Multiply tweak by alpha in GF(2^128) (little-endian byte order)
  var carry: uint8 = 0
  for i in 0 ..< blocksize:
    let b = t[i]
    let newCarry = (b shr 7) and 1
    t[i] = ((b shl 1) and 0xFF) or carry
    carry = newCarry
  if carry == 1:
    t[0] = t[0] xor 0x87'u8


proc encrypt*(ctx: TwofishXtsCtx, tweak: openArray[byte], input: openArray[byte], output: var openArray[byte]) =
  ## XTS encryption with ciphertext stealing for final partial block
  if tweak.len != blocksize:
    raise newException(ValueError, "XTS tweak must be 16 bytes")
  if input.len < blocksize:
    raise newException(ValueError, "XTS requires input length >= 16")
  if output.len < input.len:
    raise newException(ValueError, "output length must be >= input length")

  var t: array[blocksize, byte]
  for i in 0 ..< blocksize: t[i] = tweak[i]
  twofishEncrypt(ctx.st2, t, t)
  var t0: array[blocksize, byte]
  for i in 0 ..< blocksize: t0[i] = t[i]

  var off = 0
  let nFull = input.len div blocksize
  let r = input.len mod blocksize
  var fullLen = if r == 0: nFull * blocksize else: (if nFull > 0: (nFull - 1) * blocksize else: 0)

  var scratch: array[blocksize, byte]

  while off < fullLen:
    for i in 0 ..< blocksize: scratch[i] = input[off + i] xor t[i]
    twofishEncrypt(ctx.st1, scratch, scratch)
    for i in 0 ..< blocksize: output[off + i] = scratch[i] xor t[i]
    xtsMulAlpha(t)
    off += blocksize

  if r == 0:
    return

  # Compute T_prev for last full block
  let lastOff = (nFull - 1) * blocksize
  let partOff = lastOff + blocksize
  var tPrev: array[blocksize, byte]
  for i in 0 ..< blocksize: tPrev[i] = t0[i]
  for _ in 1 ..< nFull:
    xtsMulAlpha(tPrev)
  # Compute C* for last full block
  for i in 0 ..< blocksize: scratch[i] = input[lastOff + i] xor tPrev[i]
  twofishEncrypt(ctx.st1, scratch, scratch)
  for i in 0 ..< blocksize: scratch[i] = scratch[i] xor tPrev[i]

  # Write partial and replace head with P_partial
  for i in 0 ..< r:
    output[partOff + i] = scratch[i]
    scratch[i] = input[partOff + i]

  var tdash = t
  xtsMulAlpha(tdash)
  for i in 0 ..< blocksize: scratch[i] = scratch[i] xor tdash[i]
  twofishEncrypt(ctx.st1, scratch, scratch)
  for i in 0 ..< blocksize: output[lastOff + i] = scratch[i] xor tdash[i]


proc decrypt*(ctx: TwofishXtsCtx, tweak: openArray[byte], input: openArray[byte], output: var openArray[byte]) =
  ## XTS decryption with ciphertext stealing for final partial block
  if tweak.len != blocksize:
    raise newException(ValueError, "XTS tweak must be 16 bytes")
  if input.len < blocksize:
    raise newException(ValueError, "XTS requires input length >= 16")
  if output.len < input.len:
    raise newException(ValueError, "output length must be >= input length")

  var t: array[blocksize, byte]
  for i in 0 ..< blocksize: t[i] = tweak[i]
  twofishEncrypt(ctx.st2, t, t)

  let nFull = input.len div blocksize
  let r = input.len mod blocksize
  var fullLen = if r == 0: nFull * blocksize else: (if nFull > 0: (nFull - 1) * blocksize else: 0)

  var off = 0
  var scratch: array[blocksize, byte]

  while off < fullLen:
    for i in 0 ..< blocksize: scratch[i] = input[off + i] xor t[i]
    twofishDecrypt(ctx.st1, scratch, scratch)
    for i in 0 ..< blocksize: output[off + i] = scratch[i] xor t[i]
    xtsMulAlpha(t)
    off += blocksize

  if r == 0:
    return

  let lastOffD = off
  let partOffD = off + blocksize
  var tdash = t
  xtsMulAlpha(tdash)

  # Pdash from C_{n-1} with tweak1
  for i in 0 ..< blocksize: scratch[i] = input[lastOffD + i] xor tdash[i]
  twofishDecrypt(ctx.st1, scratch, scratch)
  for i in 0 ..< blocksize: scratch[i] = scratch[i] xor tdash[i]

  # Write p_partial and set head to c_partial
  for i in 0 ..< r:
    output[partOffD + i] = scratch[i]
    scratch[i] = input[partOffD + i]

  for i in 0 ..< blocksize: scratch[i] = scratch[i] xor t[i]
  twofishDecrypt(ctx.st1, scratch, scratch)
  for i in 0 ..< blocksize: output[lastOffD + i] = scratch[i] xor t[i]


proc encrypt*(ctx: TwofishXtsCtx, tweak: openArray[byte], input: openArray[byte]): seq[byte] =
  result = newSeq[byte](input.len)
  encrypt(ctx, tweak, input, result)


proc decrypt*(ctx: TwofishXtsCtx, tweak: openArray[byte], input: openArray[byte]): seq[byte] =
  result = newSeq[byte](input.len)
  decrypt(ctx, tweak, input, result)


proc encrypt*(ctx: TwofishXtsCtx, tweak, input: string): seq[byte] =
  return encrypt(ctx, tweak.encodeBytes(), input.encodeBytes())


proc decrypt*(ctx: TwofishXtsCtx, tweak, input: string): seq[byte] =
  return decrypt(ctx, tweak.encodeBytes(), input.encodeBytes())


# XTS: string helpers (hex/base64)
proc encryptXtsHex*(ctx: TwofishXtsCtx, tweakHex, plaintextHex: string): string =
  let tweak = fromHex(tweakHex)
  let pt = fromHex(plaintextHex)
  let ct = ctx.encrypt(tweak, pt)
  return hexDigest(ct)


proc decryptXtsHex*(ctx: TwofishXtsCtx, tweakHex, dataHex: string): string =
  let tweak = fromHex(tweakHex)
  let ct = fromHex(dataHex)
  let pt = ctx.decrypt(tweak, ct)
  return hexDigest(pt)


proc encryptXtsB64*(ctx: TwofishXtsCtx, tweakB64, plaintextB64: string): string =
  let tweakRaw = decode(tweakB64)
  let dataRaw = decode(plaintextB64)
  let ct = ctx.encrypt(encodeBytes(tweakRaw), encodeBytes(dataRaw))
  return encode(ct)


proc decryptXtsB64*(ctx: TwofishXtsCtx, tweakB64, dataB64: string): string =
  let tweakRaw = decode(tweakB64)
  let dataRaw = decode(dataB64)
  let pt = ctx.decrypt(encodeBytes(tweakRaw), encodeBytes(dataRaw))
  return encode(pt)


proc encryptAeadB64*(ctx: TwofishGcmSivCtx, aad, plaintext: string): string =
  let outBuf = ctx.encryptAead(aad.encodeBytes(), plaintext.encodeBytes())
  return encode(outBuf)


proc decryptAeadB64*(ctx: TwofishGcmSivCtx, aad: string, dataB64: string): string =
  let raw = decode(dataB64)
  let data = encodeBytes(raw)
  let pt = ctx.decryptAead(aad.encodeBytes(), data)
  return decodeBytes(pt)

#################################################################################
# initializers
#################################################################################

proc newTwofishEcbCtx*(key: openArray[byte]): TwofishEcbCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  result.key = toSeq(key)
  init(result.key, result.state.s, result.state.k)


proc newTwofishEcbCtx*(key: string): TwofishEcbCtx =
  return newTwofishEcbCtx(key.encodeBytes())


proc newTwofishCbcCtx*(key, iv: openArray[byte]): TwofishCbcCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if iv.len != 16:
    raise newException(ValueError, "Initialization vector (IV) must be 16 bytes long")
  result.key = toSeq(key)
  result.iv = toSeq(iv)
  result.initPreviousBlock()

  init(result.key, result.state.s, result.state.k)


proc newTwofishCbcCtx*(key, iv: string): TwofishCbcCtx =
  return newTwofishCbcCtx(key.encodeBytes(), iv.encodeBytes())


proc newTwofishCtrCtx*(key, nonce: openArray[byte], initState: openArray[byte]=newSeq[byte](8)): TwofishCtrCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if nonce.len != 8:
    raise newException(ValueError, "Nonce must be 8 bytes long")
  if initState.len != 8:
    raise newException(ValueError, "Initial state must be 8 bytes long")
  
  result.key = toSeq(key)
  result.nonce = toSeq(nonce)
  for i, b in initState:
    result.initState[i] = b
  result.initCounter()

  init(result.key, result.state.s, result.state.k)


proc newTwofishCtrCtx*(key, nonce: string, initState: int = 0): TwofishCtrCtx =
  return newTwofishCtrCtx(key.encodeBytes(), nonce.encodeBytes(), intToBytesBE(uint64(initState)))


proc newTwofishGcmCtx*(key, iv: openArray[byte]): TwofishGcmCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if iv.len == 0:
    raise newException(ValueError, "IV must be non-empty")
  result.key = toSeq(key)
  result.iv = toSeq(iv)
  init(result.key, result.state.s, result.state.k)
  result.H = gcmCalcH(result.state)
  result.J0 = deriveJ0(result.H, result.iv)


proc newTwofishGcmCtx*(key, iv: string): TwofishGcmCtx =
  return newTwofishGcmCtx(key.encodeBytes(), iv.encodeBytes())


proc newTwofishGcmSivCtx*(key, nonce: openArray[byte]): TwofishGcmSivCtx =
  if not key.len in {16, 32}:
    raise newException(ValueError, "Key must be 16 or 32 bytes long for GCM-SIV")
  if nonce.len != 12:
    raise newException(ValueError, "Nonce must be 12 bytes long")
  result.key = toSeq(key)
  result.nonce = toSeq(nonce)


proc newTwofishGcmSivCtx*(key, nonce: string): TwofishGcmSivCtx =
  return newTwofishGcmSivCtx(key.encodeBytes(), nonce.encodeBytes())


proc newTwofishXtsCtx*(key1, key2: openArray[byte]): TwofishXtsCtx =
  if not (key1.len == 16 or key1.len == 32) or key2.len != key1.len:
    raise newException(ValueError, "XTS keys must be 16/16 or 32/32 bytes long")
  result.key1 = toSeq(key1)
  result.key2 = toSeq(key2)
  init(result.key1, result.st1.s, result.st1.k)
  init(result.key2, result.st2.s, result.st2.k)


proc newTwofishXtsCtx*(combined: openArray[byte]): TwofishXtsCtx =
  if not (combined.len == 32 or combined.len == 64):
    raise newException(ValueError, "XTS combined key must be 32 or 64 bytes")
  let half = combined.len div 2
  return newTwofishXtsCtx(combined[0 ..< half], combined[half ..< combined.len])


proc newTwofishXtsCtx*(key1, key2: string): TwofishXtsCtx =
  return newTwofishXtsCtx(key1.encodeBytes(), key2.encodeBytes())


proc newTwofishXtsCtx*(combined: string): TwofishXtsCtx =
  return newTwofishXtsCtx(combined.encodeBytes())

#################################################################################

when isMainModule:
  let
    message = "This is a message of length 32!!" # 32
    key = "0123456789ABCDEFGHIJKLMNOPQRSTUV" # 32
    iv = "0000000000000000" # 16

  var ctx = newTwofishCbcCtx(key, iv)
  let ciphertext = ctx.encrypt(message)
  echo encode(ciphertext)
  let plaintext = ctx.decrypt(ciphertext)
  echo plaintext
  doAssert $plaintext == message
