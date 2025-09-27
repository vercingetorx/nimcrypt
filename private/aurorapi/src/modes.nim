# ========================================
# File: src/modes.nim
# ========================================
when isMainModule: discard

import ./common
import ./aurora256

# CTR mode — nonce+counter (128b nonce + 128b counter)
# NOTE: CTR requires unique nonces under the same key; caller must ensure.

type CtrState* = object
  ks*: KeySchedule
  nonce*: array[16, byte]
  counter*: U128

proc initCtr*(ks: KeySchedule, nonce: openArray[byte]): CtrState =
  doAssert nonce.len == 16
  result.ks = ks
  for i in 0..15: result.nonce[i] = nonce[i]
  # counter starts at 0
  result.counter = (a: 0'u64, b: 0'u64)

proc incCounter(cs: var CtrState) {.inline.} =
  cs.counter.a = cs.counter.a + 1'u64
  if cs.counter.a == 0: cs.counter.b = cs.counter.b + 1'u64

proc keystreamBlock(cs: var CtrState): array[32, byte] =
  var blk: array[32, byte]
  # construct input block = nonce || counter
  for i in 0..15: blk[i] = cs.nonce[i]
  putU128(blk, 16, cs.counter)
  let outb = cs.ks.encryptBlock(blk)
  cs.incCounter()
  return outb

proc xorInplace(dst: var openArray[byte], src: openArray[byte]) {.inline.} =
  for i in 0 ..< dst.len:
    dst[i] = dst[i] xor src[i]

proc ctrXor*(cs: var CtrState, data: var openArray[byte]) =
  var off = 0
  while off < data.len:
    let ksblk = cs.keystreamBlock()
    let n = min(ksblk.len, data.len - off)
    for i in 0 ..< n:
      data[off+i] = data[off+i] xor ksblk[i]
    off += n

# XEX (XE) tweakable mode for sector-like tweaks (e.g., disk sector numbers)
# Here tweak is 128-bit; multiply-by-x over GF(2^128) based on primitive poly

proc gf128MulX(T: var array[16, byte]) =
  let carry = (T[15] and 0x80'u8) != 0
  var i = 15
  while i > 0:
    let hi = (T[i-1] shr 7) and 1'u8
    T[i] = byte((T[i] shl 1) or hi)
    dec i
  T[0] = byte(T[0] shl 1)
  if carry:
    T[15] = T[15] xor 0x87'u8  # Rijndael poly; fine for XEX doubling

proc xexEncrypt*(ks: KeySchedule, tweak128: openArray[byte], pt: openArray[byte]): seq[byte] =
  ## XEX with 128-bit tweak, ciphertext same length as pt (multiple of 32)
  doAssert tweak128.len == 16
  doAssert pt.len mod 32 == 0
  var T: array[16, byte]
  for i in 0..15: T[i] = tweak128[i]

  result = newSeq[byte](pt.len)
  var i = 0
  while i < pt.len:
    var mask: array[32, byte]
    # Build mask = T || (T*2) (simple derivation)
    var T2 = T
    gf128MulX(T2)
    for j in 0..15: mask[j] = T[j]
    for j in 0..15: mask[16+j] = T2[j]

    var blk: array[32, byte]
    for j in 0..31: blk[j] = pt[i+j] xor mask[j]
    let enc = ks.encryptBlock(blk)
    for j in 0..31: result[i+j] = enc[j] xor mask[j]

    gf128MulX(T)   # advance tweak for next block
    i += 32

proc xexDecrypt*(ks: KeySchedule, tweak128: openArray[byte], ct: openArray[byte]): seq[byte] =
  doAssert tweak128.len == 16
  doAssert ct.len mod 32 == 0
  var T: array[16, byte]
  for i in 0..15: T[i] = tweak128[i]

  result = newSeq[byte](ct.len)
  var i = 0
  while i < ct.len:
    var mask: array[32, byte]
    var T2 = T
    gf128MulX(T2)
    for j in 0..15: mask[j] = T[j]
    for j in 0..15: mask[16+j] = T2[j]

    var blk: array[32, byte]
    for j in 0..31: blk[j] = ct[i+j] xor mask[j]
    let dec = ks.decryptBlock(blk)
    for j in 0..31: result[i+j] = dec[j] xor mask[j]

    gf128MulX(T)
    i += 32
