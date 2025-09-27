# ========================================
# File: src/aead.nim
# Authenticated modes for Aurora-Π
#  - π-XEX-AE: keyed-delta XEX with integrated tag (MP compression)
#  - π-SIV: deterministic AEAD via PRF-based SIV + CTR
# ========================================
when isMainModule: discard

import std/strformat
import ./aurora256
import ./modes
import ../private/sha3/sha3_256
## Note: This module is parameterized by KeySchedule inputs; the public API module
## (aurora.nim) derives appropriate schedules and calls into these functions.

type AuroraAuthError* = object of CatchableError

# ---- Helpers ----

proc putBe64(b: var openArray[byte], off: int, x: uint64) {.inline.} =
  var t = x
  for i in 0..7:
    b[off + (7 - i)] = byte(t and 0xff'u64)
    t = t shr 8

proc putLe64(b: var openArray[byte], off: int, x: uint64) {.inline.} =
  var t = x
  for i in 0..7:
    b[off + i] = byte(t and 0xff'u64)
    t = t shr 8

proc xorBlock(a: var array[PI_BLOCK_BYTES, byte], b: openArray[byte]) {.inline.} =
  for i in 0 ..< PI_BLOCK_BYTES: a[i] = a[i] xor b[i]

proc mpCompress(state: var array[PI_BLOCK_BYTES, byte], ks: KeySchedule, blkIn: openArray[byte]) {.inline.} =
  ## Miyaguchi–Preneel-style compression using Aurora-Π as PRP
  var x = state
  xorBlock(x, blkIn)
  let y = ks.encryptBlock(x)
  var outb: array[PI_BLOCK_BYTES, byte]
  for i in 0 ..< PI_BLOCK_BYTES:
    outb[i] = byte(uint8(y[i]) xor uint8(blkIn[i]) xor uint8(state[i]))
  state = outb

proc mpAbsorbBytes(state: var array[PI_BLOCK_BYTES, byte], ks: KeySchedule, data: openArray[byte]) =
  var off = 0
  while off + PI_BLOCK_BYTES <= data.len:
    mpCompress(state, ks, data.toOpenArray(off, off + PI_BLOCK_BYTES - 1))
    off += PI_BLOCK_BYTES
  # pad tail with 0x80 then zeros
  var blk: array[PI_BLOCK_BYTES, byte]
  let remain = data.len - off
  if remain > 0:
    for i in 0 ..< remain: blk[i] = data[off + i]
  blk[remain] = 0x80'u8
  for i in remain+1 ..< PI_BLOCK_BYTES:
    blk[i] = 0
  mpCompress(state, ks, blk)

proc deriveDelta(ksMask: KeySchedule, sectorTweak: openArray[byte], blockIndex: uint64): array[PI_BLOCK_BYTES, byte] =
  ## Δ_i = E_{Kmask}( encode( T || be128(i) ) ) ; here be128(i) packs i into last 16 bytes
  doAssert sectorTweak.len == 16
  var inb: array[PI_BLOCK_BYTES, byte]
  for i in 0..15: inb[i] = sectorTweak[i]
  # high 64 bits zero, low 64 bits = i in big-endian
  for i in 0..7: inb[16+i] = 0
  putBe64(inb, 24, blockIndex)
  result = ksMask.encryptBlock(inb)

# ---- π-XEX-AE (keyed delta + MP tag) ----

proc calcXexTag(ksTag: KeySchedule, sectorTweak: openArray[byte], ad: openArray[byte], ciphertext: openArray[byte], ptLen: int): array[PI_BLOCK_BYTES, byte] =
  ## Compute MP tag over header, sectorTweak, AD, and ciphertext.
  var st: array[PI_BLOCK_BYTES, byte]
  for j in 0 ..< PI_BLOCK_BYTES: st[j] = 0
  var hdr: array[PI_BLOCK_BYTES, byte]
  putLe64(hdr, 0,  uint64(ad.len))
  putLe64(hdr, 8,  uint64(ptLen))
  let modeId = "pi-XEX-AE-v1"
  for k in 0 ..< modeId.len: hdr[16+k] = byte(modeId[k])
  mpCompress(st, ksTag, hdr)
  var twblk: array[PI_BLOCK_BYTES, byte]
  for t in 0..15: twblk[t] = sectorTweak[t]
  twblk[16] = 0x80'u8
  for t in 17 ..< PI_BLOCK_BYTES: twblk[t] = 0
  mpCompress(st, ksTag, twblk)
  if ad.len > 0: mpAbsorbBytes(st, ksTag, ad)
  if ciphertext.len > 0: mpAbsorbBytes(st, ksTag, ciphertext)
  return st

proc xexSealAE*(ksEnc: KeySchedule, ksMask: KeySchedule, ksTag: KeySchedule,
                sectorTweak: openArray[byte], ad: openArray[byte], plaintext: openArray[byte]): (seq[byte], array[32,byte]) =
  ## Encrypt and authenticate using keyed-delta XEX and MP tag. Plaintext must be multiple of 32 bytes.
  if sectorTweak.len != 16:
    raise newException(AuroraAuthError, &"XEX-AE sector tweak must be 16 bytes, got {sectorTweak.len}")
  if plaintext.len mod PI_BLOCK_BYTES != 0:
    raise newException(AuroraAuthError, &"XEX-AE plaintext must be multiple of {PI_BLOCK_BYTES} bytes, got {plaintext.len}")

  # Encrypt
  var ct = newSeq[byte](plaintext.len)
  var i = 0
  var blkIdx: uint64 = 0
  while i < plaintext.len:
    var pblk: array[PI_BLOCK_BYTES, byte]
    for j in 0 ..< PI_BLOCK_BYTES: pblk[j] = plaintext[i+j]
    let delta = deriveDelta(ksMask, sectorTweak, blkIdx)
    var x = pblk
    xorBlock(x, delta)
    let y = ksEnc.encryptBlock(x)
    var cblk = y
    xorBlock(cblk, delta)
    for j in 0 ..< PI_BLOCK_BYTES: ct[i+j] = cblk[j]
    inc i, PI_BLOCK_BYTES
    inc blkIdx
  # Tag over (ad, ct) with header binding pt length and tweak
  let tag = calcXexTag(ksTag, sectorTweak, ad, ct, plaintext.len)
  return (ct, tag)

proc xexOpenAE*(ksEnc: KeySchedule, ksMask: KeySchedule, ksTag: KeySchedule,
                sectorTweak: openArray[byte], ad: openArray[byte], ciphertext: openArray[byte], tag: openArray[byte]): seq[byte] =
  ## Verify tag and decrypt. Returns plaintext or raises on failure.
  if sectorTweak.len != 16:
    raise newException(AuroraAuthError, &"XEX-AE sector tweak must be 16 bytes, got {sectorTweak.len}")
  if ciphertext.len mod PI_BLOCK_BYTES != 0:
    raise newException(AuroraAuthError, &"XEX-AE ciphertext must be multiple of {PI_BLOCK_BYTES} bytes, got {ciphertext.len}")
  if tag.len != PI_BLOCK_BYTES:
    raise newException(AuroraAuthError, &"XEX-AE tag must be {PI_BLOCK_BYTES} bytes, got {tag.len}")

  # compute tag over provided ciphertext
  let tagCalc = calcXexTag(ksTag, sectorTweak, ad, ciphertext, ciphertext.len)
  # constant-time compare
  var diff: uint8 = 0
  for i in 0 ..< PI_BLOCK_BYTES:
    diff = diff or (uint8(tag[i]) xor uint8(tagCalc[i]))
  if diff != 0'u8: raise newException(AuroraAuthError, "XEX-AE tag mismatch")

  # decrypt
  result = newSeq[byte](ciphertext.len)
  var i = 0
  var blkIdx: uint64 = 0
  while i < ciphertext.len:
    var cblk: array[PI_BLOCK_BYTES, byte]
    for j in 0 ..< PI_BLOCK_BYTES: cblk[j] = ciphertext[i+j]
    let delta = deriveDelta(ksMask, sectorTweak, blkIdx)
    var y = cblk
    xorBlock(y, delta)
    let x = ksEnc.decryptBlock(y)
    var pblk = x
    xorBlock(pblk, delta)
    for j in 0 ..< PI_BLOCK_BYTES: result[i+j] = pblk[j]
    inc i, PI_BLOCK_BYTES
    inc blkIdx

# ---- π-SIV (deterministic AEAD) ----

proc ctrEncWithNonce(ks: KeySchedule, nonce: array[16, byte], data: openArray[byte]): seq[byte] =
  var st = initCtr(ks, nonce)
  result = newSeq[byte](data.len)
  if data.len > 0:
    for i in 0 ..< data.len: result[i] = data[i]
    st.ctrXor(result)

## HMAC-SHA3-256 (PRF for S2V)
proc hmacSha3_256(key: openArray[byte], msg: openArray[byte]): array[32, byte]
proc hmacSha3_256_trunc16(key: openArray[byte], msg: openArray[byte]): array[16, byte]
proc dbl128(b: var array[16, byte])
proc s2v(macKey: openArray[byte], ad: openArray[byte], plaintext: openArray[byte]): array[16, byte]

proc sivSealWithMacKey*(ksEnc: KeySchedule, macKey: openArray[byte], ad: openArray[byte], plaintext: openArray[byte]): (array[16,byte], seq[byte]) =
  ## S2V using externally provided MAC key (e.g., from SHAKE256 KDF)
  let siv = s2v(macKey, ad, plaintext)
  let ct = ctrEncWithNonce(ksEnc, siv, plaintext)
  return (siv, ct)

proc sivOpenWithMacKey*(ksEnc: KeySchedule, macKey: openArray[byte], ad: openArray[byte], siv: openArray[byte], ciphertext: openArray[byte]): seq[byte] =
  ## Verify and decrypt using externally provided MAC key.
  if siv.len != 16:
    raise newException(AuroraAuthError, &"SIV must be 16 bytes, got {siv.len}")
  var nonce: array[16, byte]
  for i in 0..15: nonce[i] = siv[i]
  # Decrypt first
  result = ctrEncWithNonce(ksEnc, nonce, ciphertext)
  # Recompute SIV over (AD, PT)
  let siv2 = s2v(macKey, ad, result)
  var diff: uint8 = 0
  for i in 0..15: diff = diff or (uint8(siv[i]) xor uint8(siv2[i]))
  if diff != 0'u8:
    result.setLen(0)
    raise newException(AuroraAuthError, "SIV verification failed")
## ---- HMAC-SHA3-256 (PRF for S2V) ----

proc hmacSha3_256(key: openArray[byte], msg: openArray[byte]): array[32, byte] =
  const B = 136  # SHA3-256 block size (rate)
  # key normalization
  var k0: array[B, byte]
  if key.len > B:
    var c = newSha3_256Ctx()
    c.update(key)
    let kh = c.digest()
    for i in 0 ..< 32: k0[i] = kh[i]
    for i in 32 ..< B: k0[i] = 0
  else:
    for i in 0 ..< key.len: k0[i] = key[i]
    for i in key.len ..< B: k0[i] = 0
  var ipad: array[B, byte]
  var opad: array[B, byte]
  for i in 0 ..< B:
    ipad[i] = k0[i] xor 0x36'u8
    opad[i] = k0[i] xor 0x5c'u8
  var inner = newSha3_256Ctx()
  inner.update(ipad)
  if msg.len > 0: inner.update(msg)
  let innerDigest = inner.digest()
  var outer = newSha3_256Ctx()
  outer.update(opad)
  outer.update(innerDigest)
  return outer.digest()

proc hmacSha3_256_trunc16(key: openArray[byte], msg: openArray[byte]): array[16, byte] =
  let full = hmacSha3_256(key, msg)
  for i in 0 ..< 16: result[i] = full[i]

## ---- S2V components ----

proc dbl128(b: var array[16, byte]) =
  ## GF(2^128) doubling with Rijndael polynomial (0x87 in low byte)
  let carry = (b[0] and 0x80'u8) != 0
  var i = 15
  while i > 0:
    let hi = (b[i-1] shr 7) and 1'u8
    b[i] = byte((b[i] shl 1) or hi)
    dec i
  b[0] = byte(b[0] shl 1)
  if carry:
    b[15] = b[15] xor 0x87'u8

proc s2v(macKey: openArray[byte], ad: openArray[byte], plaintext: openArray[byte]): array[16, byte] =
  ## RFC 5297 S2V-style synthetic IV using HMAC-SHA3-256 as PRF (truncated to 128 bits)
  var D = hmacSha3_256_trunc16(macKey, @[])  # PRF of empty string
  if ad.len > 0:
    dbl128(D)
    let macAd = hmacSha3_256_trunc16(macKey, ad)
    for i in 0 ..< 16: D[i] = D[i] xor macAd[i]
  if plaintext.len >= 16:
    # T = P with last 16 bytes XOR D
    var tmp = newSeq[byte](plaintext.len)
    for i in 0 ..< plaintext.len: tmp[i] = plaintext[i]
    let off = plaintext.len - 16
    for i in 0 ..< 16: tmp[off + i] = tmp[off + i] xor D[i]
    let mac = hmacSha3_256_trunc16(macKey, tmp)
    return mac
  else:
    # T = pad(P) XOR dbl(D)
    var t: array[16, byte]
    for i in 0 ..< plaintext.len: t[i] = plaintext[i]
    t[plaintext.len] = 0x80'u8
    for i in plaintext.len + 1 ..< 16: t[i] = 0
    dbl128(D)
    for i in 0 ..< 16: t[i] = t[i] xor D[i]
    let mac = hmacSha3_256_trunc16(macKey, t)
    return mac

## Removed PRP-derived S2V MAC key; SHAKE256-based keying lives in aurora.nim
