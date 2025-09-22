# ========================================
# File: aurora.nim
# Public, user-friendly API for Aurora-Π
# ========================================
when isMainModule: discard

import std/[strformat, sysrand]
import src/aead
import src/aurora256
import src/common
import src/hexutil
import src/modes

type
  AuroraError* = object of CatchableError

  AuroraPiCipher* = object
    ## A configured Aurora-Π cipher instance for a given key/tweak
    keySchedule*: KeySchedule
    rootKey*: array[PI_KEY_BYTES, byte]
    hasTweak*: bool
    rootTweak*: array[PI_TWEAK_BYTES, byte]

proc newAuroraPiContext*(key: openArray[byte], tweak: openArray[byte] = @[]): AuroraPiCipher =
  ## Create a cipher instance. Key must be 32 bytes. Tweak is empty or 16 bytes.
  if key.len != PI_KEY_BYTES:
    raise newException(AuroraError, &"Key must be {PI_KEY_BYTES} bytes, got {key.len}")
  if not (tweak.len == 0 or tweak.len == PI_TWEAK_BYTES):
    raise newException(AuroraError, &"Tweak must be empty or {PI_TWEAK_BYTES} bytes, got {tweak.len}")
  result.keySchedule = expandKey(key, tweak)
  for i in 0 ..< PI_KEY_BYTES: result.rootKey[i] = key[i]
  if tweak.len == 0:
    result.hasTweak = false
    for i in 0 ..< PI_TWEAK_BYTES: result.rootTweak[i] = 0
  else:
    result.hasTweak = true
    for i in 0 ..< PI_TWEAK_BYTES: result.rootTweak[i] = tweak[i]

proc deriveKeySchedule*(c: AuroraPiCipher, dom: array[PI_TWEAK_BYTES, byte]): KeySchedule =
  ## Derive an internal KeySchedule by domain-separating the tweak (T xor dom)
  var tw: array[PI_TWEAK_BYTES, byte]
  for i in 0 ..< PI_TWEAK_BYTES:
    tw[i] = byte(uint8(c.rootTweak[i]) xor uint8(dom[i]))
  let tweakSeq = if c.hasTweak: (block:
      var s: seq[byte] = @[]; s.setLen(PI_TWEAK_BYTES); for i in 0..<PI_TWEAK_BYTES: s[i] = tw[i]; s)
    else: (block:
      var s: seq[byte] = @[]; s.setLen(PI_TWEAK_BYTES); for i in 0..<PI_TWEAK_BYTES: s[i] = dom[i]; s)
  var keySeq: seq[byte] = @[]; keySeq.setLen(PI_KEY_BYTES)
  for i in 0..<PI_KEY_BYTES: keySeq[i] = c.rootKey[i]
  result = expandKey(keySeq, tweakSeq)

const
  DOM_MASK*: array[PI_TWEAK_BYTES, byte] = [
    byte 0x4d,0x41,0x53,0x4b,0x5f,0x50,0x49,0x5f,0x44,0x4f,0x4d,0x76,0x31,0x21,0x21,0x21 # "MASK_PI_DOMv1!!!"
  ]
  DOM_TAG*: array[PI_TWEAK_BYTES, byte] = [
    byte 0x54,0x41,0x47,0x5f,0x50,0x49,0x5f,0x44,0x4f,0x4d,0x76,0x31,0x21,0x21,0x21,0x21 # "TAG_PI_DOMv1!!!!"
  ]

# ---------------- Block API ----------------

proc encryptBlock*(c: AuroraPiCipher, plaintext: openArray[byte]): array[PI_BLOCK_BYTES, byte] =
  ## Encrypt a single 256-bit block. Input must be 32 bytes.
  if plaintext.len != PI_BLOCK_BYTES:
    raise newException(AuroraError, &"Plaintext block must be {PI_BLOCK_BYTES} bytes, got {plaintext.len}")
  c.keySchedule.encryptBlock(plaintext)

proc decryptBlock*(c: AuroraPiCipher, ciphertext: openArray[byte]): array[PI_BLOCK_BYTES, byte] =
  ## Decrypt a single 256-bit block. Input must be 32 bytes.
  if ciphertext.len != PI_BLOCK_BYTES:
    raise newException(AuroraError, &"Ciphertext block must be {PI_BLOCK_BYTES} bytes, got {ciphertext.len}")
  c.keySchedule.decryptBlock(ciphertext)

# ---------------- CTR mode (stream) ----------------

proc ctrEncrypt*(c: AuroraPiCipher, nonce: openArray[byte], plaintext: openArray[byte]): seq[byte] =
  ## CTR mode encryption. Nonce must be 16 bytes, unique per key.
  if nonce.len != 16:
    raise newException(AuroraError, &"CTR nonce must be 16 bytes, got {nonce.len}")
  var n: array[16, byte]
  for i in 0..15: n[i] = nonce[i]
  var st = initCtr(c.keySchedule, n)
  result = newSeq[byte](plaintext.len)
  if plaintext.len > 0:
    for i in 0 ..< plaintext.len: result[i] = plaintext[i]
    st.ctrXor(result)

proc ctrDecrypt*(c: AuroraPiCipher, nonce: openArray[byte], ciphertext: openArray[byte]): seq[byte] =
  ## CTR mode decryption. Nonce must match the one used for encryption.
  if nonce.len != 16:
    raise newException(AuroraError, &"CTR nonce must be 16 bytes, got {nonce.len}")
  var n: array[16, byte]
  for i in 0..15: n[i] = nonce[i]
  var st = initCtr(c.keySchedule, n)
  result = newSeq[byte](ciphertext.len)
  if ciphertext.len > 0:
    for i in 0 ..< ciphertext.len: result[i] = ciphertext[i]
    st.ctrXor(result)

# ---------------- XEX mode (tweakable) ----------------

proc xexEncrypt*(c: AuroraPiCipher, sectorTweak: openArray[byte], plaintext: openArray[byte]): seq[byte] =
  ## XEX-like tweakable encryption. sectorTweak must be 16 bytes; plaintext length must be a multiple of 32.
  if sectorTweak.len != 16:
    raise newException(AuroraError, &"XEX tweak must be 16 bytes, got {sectorTweak.len}")
  if plaintext.len mod PI_BLOCK_BYTES != 0:
    raise newException(AuroraError, &"XEX data length must be multiple of {PI_BLOCK_BYTES} bytes, got {plaintext.len}")
  result = xexEncrypt(c.keySchedule, sectorTweak, plaintext)

proc xexDecrypt*(c: AuroraPiCipher, sectorTweak: openArray[byte], ciphertext: openArray[byte]): seq[byte] =
  ## XEX-like tweakable decryption. sectorTweak must match the one used for encryption.
  if sectorTweak.len != 16:
    raise newException(AuroraError, &"XEX tweak must be 16 bytes, got {sectorTweak.len}")
  if ciphertext.len mod PI_BLOCK_BYTES != 0:
    raise newException(AuroraError, &"XEX data length must be multiple of {PI_BLOCK_BYTES} bytes, got {ciphertext.len}")
  result = xexDecrypt(c.keySchedule, sectorTweak, ciphertext)

# ---------------- Utilities ----------------

proc randomNonce16*(): array[16, byte] =
  ## system random bytes
  if not urandom(result):
    raise newException(OSError, "Could not obtain secure random bytes")

# ---------------- Authenticated APIs ----------------

proc xexSeal*(c: AuroraPiCipher, sectorTweak: openArray[byte], ad: openArray[byte], plaintext: openArray[byte]): (seq[byte], array[32,byte]) =
  ## π-XEX-AE: keyed-delta XEX with integrated tag. Plaintext must be block-aligned (32B).
  let ksEnc = c.keySchedule
  let ksMask = c.deriveKeySchedule(DOM_MASK)
  let ksTag  = c.deriveKeySchedule(DOM_TAG)
  aead.xexSealAE(ksEnc, ksMask, ksTag, sectorTweak, ad, plaintext)

proc xexOpen*(c: AuroraPiCipher, sectorTweak: openArray[byte], ad: openArray[byte], ciphertext: openArray[byte], tag: openArray[byte]): seq[byte] =
  ## Verify tag and decrypt (π-XEX-AE). Raises AuroraAuthError on failure.
  let ksEnc = c.keySchedule
  let ksMask = c.deriveKeySchedule(DOM_MASK)
  let ksTag  = c.deriveKeySchedule(DOM_TAG)
  aead.xexOpenAE(ksEnc, ksMask, ksTag, sectorTweak, ad, ciphertext, tag)

proc sivSeal*(c: AuroraPiCipher, ad: openArray[byte], plaintext: openArray[byte]): (array[16,byte], seq[byte]) =
  ## π-SIV: deterministic AEAD. Returns (SIV16, ciphertext). Safe default for general use.
  let ksEnc = c.keySchedule
  let ksMac  = c.deriveKeySchedule(DOM_TAG)
  aead.sivSeal(ksEnc, ksMac, ad, plaintext)

proc sivOpen*(c: AuroraPiCipher, ad: openArray[byte], siv: openArray[byte], ciphertext: openArray[byte]): seq[byte] =
  ## Verify and decrypt a π-SIV ciphertext. Raises AuroraAuthError on failure.
  let ksEnc = c.keySchedule
  let ksMac  = c.deriveKeySchedule(DOM_TAG)
  aead.sivOpen(ksEnc, ksMac, ad, siv, ciphertext)


when isMainModule:
  let key = incBytes(32)
  let tweak = incBytes(16)
  let cipher = newAuroraPiContext(key, tweak)

  # Block KAT
  let ptBlk = incBytes(32)
  let ctBlk = cipher.encryptBlock(ptBlk)
  let dtBlk = cipher.decryptBlock(ctBlk)
  printKV("BLK_KEY", toHex(key))
  printKV("BLK_TWEAK", toHex(tweak))
  printKV("BLK_PT", toHex(ptBlk))
  printKV("BLK_CT", toHex(ctBlk))
  printKV("BLK_DT", toHex(dtBlk))
  assert ptBlk == dtBlk

  printLine()
  # CTR KAT
  let nonce = incBytes(16)
  let msg = toBytes("The quick brown fox jumps over 13 lazy dogs.")
  let ctStream = cipher.ctrEncrypt(nonce, msg)
  let dtStream = cipher.ctrDecrypt(nonce, ctStream)
  printKV("CTR_NONCE", toHex(nonce))
  printKV("CTR_PT", toHex(msg))
  printKV("CTR_CT", toHex(ctStream))
  printKV("CTR_DT", toHex(dtStream))
  assert msg == dtStream


  printLine()
  # XEX KAT (conf-only)
  let sectorTweak = bytesSeq([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff])
  var sector = incBytes(64)
  let xct = cipher.xexEncrypt(sectorTweak, sector)
  let xdt = cipher.xexDecrypt(sectorTweak, xct)
  printKV("XEX_TWEAK", toHex(sectorTweak))
  printKV("XEX_PT", toHex(sector))
  printKV("XEX_CT", toHex(xct))
  printKV("XEX_DT", toHex(xdt))
  assert sector == xdt


  printLine()
  # π-XEX-AE KAT
  let ad = toBytes("AD")
  let (ct2, ctTag) = cipher.xexSeal(sectorTweak, ad, sector)
  let dt2 = cipher.xexOpen(sectorTweak, ad, ct2, ctTag)
  printKV("XEXAE_AD", toHex(ad))
  printKV("XEXAE_PT", toHex(sector))
  printKV("XEXAE_CT", toHex(ct2))
  printKV("XEXAE_CT_TAG", toHex(ctTag))
  printKV("XEXAE_DT", toHex(dt2))
  assert sector == dt2


  printLine()
  # π-SIV KAT (deterministic AEAD)
  let msg2 = toBytes("secret message")
  let (siv, ct3) = cipher.sivSeal(ad, msg2)
  let dt3 = cipher.sivOpen(ad, siv, ct3)
  printKV("SIV_AD", toHex(ad))
  printKV("SIV_IV", toHex(siv))
  printKV("SIV_PT", toHex(msg2))
  printKV("SIV_CT", toHex(ct3))
  printKV("SIV_DT", toHex(dt3))
  printLine()
  assert msg2 == dt3