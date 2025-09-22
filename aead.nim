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

proc sivSeal*(ksEnc: KeySchedule, ksMac: KeySchedule, ad: openArray[byte], plaintext: openArray[byte]): (array[16,byte], seq[byte]) =
  ## Deterministic AEAD (misuse-resistant). Returns (SIV16, ciphertext).
  let ksMac = ksMac
  # Aggregate SIV via MP over AD and PT with a header
  var st: array[PI_BLOCK_BYTES, byte]
  for j in 0 ..< PI_BLOCK_BYTES: st[j] = 0
  var hdr: array[PI_BLOCK_BYTES, byte]
  putLe64(hdr, 0,  uint64(ad.len))
  putLe64(hdr, 8,  uint64(plaintext.len))
  let modeId = "pi-SIV-v1"
  for k in 0 ..< modeId.len: hdr[16+k] = byte(modeId[k])
  mpCompress(st, ksMac, hdr)
  if ad.len > 0: mpAbsorbBytes(st, ksMac, ad)
  if plaintext.len > 0: mpAbsorbBytes(st, ksMac, plaintext)
  # Use first 16 bytes of state as nonce for CTR
  var nonce: array[16, byte]
  for i in 0..15: nonce[i] = st[i]
  let ct = ctrEncWithNonce(ksEnc, nonce, plaintext)
  return (nonce, ct)

proc sivOpen*(ksEnc: KeySchedule, ksMac: KeySchedule, ad: openArray[byte], siv: openArray[byte], ciphertext: openArray[byte]): seq[byte] =
  ## Verify and decrypt a SIV-sealed message. Raises on failure.
  if siv.len != 16:
    raise newException(AuroraAuthError, &"SIV must be 16 bytes, got {siv.len}")
  var nonce: array[16, byte]
  for i in 0..15: nonce[i] = siv[i]
  # Decrypt
  result = ctrEncWithNonce(ksEnc, nonce, ciphertext)
  # Recompute SIV over (AD, PT)
  let (siv2, _) = sivSeal(ksEnc, ksMac, ad, result)
  var diff: uint8 = 0
  for i in 0..15: diff = diff or (uint8(siv[i]) xor uint8(siv2[i]))
  if diff != 0'u8:
    # Zero plaintext on auth failure to avoid oracle leakage
    result.setLen(0)
    raise newException(AuroraAuthError, "SIV verification failed")
