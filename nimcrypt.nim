# NimCrypt-AEF — Authenticated Encrypted File format (chunked, multi-cipher)
# Ciphers: XChaCha20, AES-GCM-SIV, Twofish-CTR, Aurora-CTR
# Notes: AEAD per-record with AD binding header, filename, metadata, and chunk index/length.
#
# CLI:
#   -e/--encrypt (default) | -d/--decrypt
#   -r/--recursive         : recurse into directories
#   -q/--quiet             : reduce output
#   -v/--version           : print version
#   --chunk <MiB>          : chunk size in MiB (default 1)
#   --m <KiB> --t <iters> --p <lanes> : Argon2id (defaults m=65536,t=3,p=1)
#   --cipher <name>        : xchacha20 (default) | aes-gcm-siv | twofish-gcm-siv | serpent-gcm-siv | camellia-gcm-siv | aurora-siv
#
# Header v3 (authenticated as AD):
#   magic[4] = "AEF1"
#   version[1] = 3
#   suite[1]   : 0=xchacha20, 1=aes-gcm-siv, 2=twofish-gcm-siv, 3=serpent-gcm-siv, 4=camellia-gcm-siv, 50=aurora-siv
#   flags[1]   (bit0: has filename, bit1: has metadata)
#   mKiB[u32], t[u32], p[u32]
#   salt[32]
#   nonceBase[24]
#   chunkSize[u32]
#   fnLen[u16]
#   fnCT[fnLen] + fnTag[tagLen]                       (AEAD idx=0)
#   metaLen[u32] + metaCT[metaLen] + metaTag[tagLen]  (AEAD idx=UINT64_MAX, if FlagHasMeta)
#
# Chunks i = 1..:
#   len[u32] || ct[len] || tag[tagLen]
#   AD = headerFixed || fnCT || fnTag || [metaCT||metaTag] || i[u64] || len[u32]

import std/[os, strutils, streams, parseopt, sysrand, terminal, times]

# primitives
import private/argon2/argon2
import private/blake2/blake2s
import private/chacha20/poly1305

# block ciphers
import private/aes/aes
import private/twofish/twofish
import private/aurorapi/aurora
import private/serpent/serpent
import private/camellia/camellia
import private/chacha20/chacha20

# -------------------- Constants & Types --------------------
const
  MAGIC        = "AEF1"
  MAGIC4: array[4, char] = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3]]
  VERSION      = 3'u8
  TagLen       = 16
  SaltLen      = 32
  NonceBaseLen = 24
  DefaultChunkMiB = 1
  DefaultChunk    = DefaultChunkMiB * 1024 * 1024

  DefaultArgonM = 65536    # 64 MiB
  DefaultArgonT = 3
  DefaultArgonP = 1

  FlagHasName = 0x01'u8
  FlagHasMeta = 0x02'u8

  IdxFilename = 0'u64
  IdxMeta     = 0xFFFF_FFFF_FFFF_FFFF'u64

type
  CipherSuite* = enum
    csXChaCha20  = 0'u8
    csAesGCM     = 1'u8
    csTwofishGCM = 2'u8
    csSerpentGCM = 3'u8
    csCamelliaGCM= 4'u8
    # test ciphers 50+
    csAuroraCtr  = 50'u8

  Header* = object
    magic:       array[4, char]
    version:     uint8
    suite:       uint8
    flags:       uint8      # bit0: has filename, bit1: has metadata
    mKiB:        uint32
    t:           uint32
    p:           uint32
    salt:        array[SaltLen, byte]
    nonceBase:   array[NonceBaseLen, byte]
    chunkSize:   uint32
    fnLen:       uint16

# -------------------- helpers --------------------

proc bytesToString(bs: openArray[byte]): string =
  result = newStringOfCap(bs.len)
  for b in bs: result.add(char(b))


proc putU32(buf: var seq[byte], x: uint32) =
  buf.add(byte x); buf.add(byte (x shr 8)); buf.add(byte (x shr 16)); buf.add(byte (x shr 24))


proc putU64(buf: var seq[byte], x: uint64) =
  buf.add(byte x); buf.add(byte (x shr 8)); buf.add(byte (x shr 16)); buf.add(byte (x shr 24))
  buf.add(byte (x shr 32)); buf.add(byte (x shr 40)); buf.add(byte (x shr 48)); buf.add(byte (x shr 56))


proc putU16(buf: var seq[byte], x: uint16) =
  buf.add(byte x); buf.add(byte (x shr 8))


proc getU32(s: Stream): uint32 =
  var b: array[4, byte]
  if s.readData(addr b[0], 4) != 4: raise newException(IOError, "unexpected EOF (u32)")
  uint32(b[0]) or (uint32(b[1]) shl 8) or (uint32(b[2]) shl 16) or (uint32(b[3]) shl 24)


proc getU64(s: Stream): uint64 =
  var b: array[8, byte]
  if s.readData(addr b[0], 8) != 8: raise newException(IOError, "unexpected EOF (u64)")
  uint64(b[0]) or (uint64(b[1]) shl 8) or (uint64(b[2]) shl 16) or (uint64(b[3]) shl 24) or
  (uint64(b[4]) shl 32) or (uint64(b[5]) shl 40) or (uint64(b[6]) shl 48) or (uint64(b[7]) shl 56)


proc getU16(s: Stream): uint16 =
  var b: array[2, byte]
  if s.readData(addr b[0], 2) != 2: raise newException(IOError, "unexpected EOF (u16)")
  uint16(b[0]) or (uint16(b[1]) shl 8)

# -------------------- KDF & labels --------------------

proc kdfMaster*(password: string, salt: openArray[byte], mKiB: int = 32, t: int = 32, p: int = 32, outLen: int = 32): seq[byte] =
  return argon2Hash(password.toOpenArrayByte(0, password.len - 1), salt, timeCost=t, memoryCost=mKiB, parallelism=p, digestSize=outLen)


proc kdfLabel(master: openArray[byte], label: string): array[32, byte] =
  let d = newBlake2sCtx(msg=label.toOpenArrayByte(0, label.len-1), key=master, digestSize=32).digest()
  for i in 0..<32: result[i] = d[i]


proc suiteName(s: CipherSuite): string =
  case s
  of csXChaCha20:   "xchacha20"
  of csAesGCM:      "aes-gcm-siv"
  of csTwofishGCM:  "twofish-gcm-siv"
  of csSerpentGCM:  "serpent-gcm-siv"
  of csCamelliaGCM: "camellia-gcm-siv"
  of csAuroraCtr:   "aurora-ctr"


proc tagLenForSuite(s: CipherSuite): int =
  ## Per-suite authentication tag length for AEF.
  # case s
  # of csLightseal: 32
  # else:           TagLen
  return TagLen


proc deriveSubkeys(master: openArray[byte], suite: CipherSuite): (array[32,byte], array[32,byte]) =
  return (kdfLabel(master, "file-meta:" & suiteName(suite)),
          kdfLabel(master, "file-data:" & suiteName(suite)))

# -------------------- Nonces / IVs --------------------

proc nonce24WithIdx(base: array[NonceBaseLen, byte], idx: uint64): array[NonceBaseLen, byte] =
  result = base
  result[16] = byte idx;       result[17] = byte (idx shr 8)
  result[18] = byte (idx shr 16); result[19] = byte (idx shr 24)
  result[20] = byte (idx shr 32); result[21] = byte (idx shr 40)
  result[22] = byte (idx shr 48); result[23] = byte (idx shr 56)
  return result


# Unused
proc nonce8ForIdx(base: array[NonceBaseLen, byte], idx: uint64): array[8, byte] =
  for i in 0..<8:
    result[i] = base[i] xor byte(idx shr (8*i))
  return result


# For AES/Twofish/Serpent/Camellia
proc nonce12ForIdx(base: array[NonceBaseLen, byte], idx: uint64): array[12, byte] =
  ## AES 12-byte nonce derivation using 8-bit steps across lower 6 bytes (48-bit space)
  for i in 0..<6:
    result[i] = base[i]
    result[6+i] = base[6+i] xor byte(idx shr (8*i))
  return result


# For ChaCha20
proc nonce12From24(n24: array[NonceBaseLen, byte]): array[12, byte] =
  return [byte 0,0,0,0, n24[16],n24[17],n24[18],n24[19],n24[20],n24[21],n24[22],n24[23]]


# For Aurora (16-byte nonce)
proc nonce16ForIdx(base: array[NonceBaseLen, byte], idx: uint64): array[16, byte] =
  for i in 0..<8:
    result[i] = base[i]
    result[8+i] = base[8+i] xor byte(idx shr (8*i))

# -------------------- AEAD per suite --------------------

# XChaCha20-Poly1305 — standard: block 0 -> Poly key; data from counter 1
proc aeadXC20P1305Encrypt(key: openArray[byte], nonce24: array[NonceBaseLen, byte],
                          ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  let sub = hChaCha20(key, nonce24[0 ..< 16])
  let n12 = nonce12From24(nonce24)
  var mac = newPoly1305Ctx(sub, n12, ad)
  var ch  = newChaCha20Ctx(sub, n12); ch.seek(1'u64, 0'u64, 0'u)
  let ct  = ch.encrypt(pt)
  mac.update(ct)
  let t = mac.digest()
  var tag: array[TagLen, byte]
  for i in 0..<TagLen: tag[i] = t[i]
  return (ct, tag)


proc aeadXC20P1305Decrypt(key: openArray[byte], nonce24: array[NonceBaseLen, byte],
                          ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  let sub = hChaCha20(key, nonce24[0 ..< 16])
  let n12 = nonce12From24(nonce24)
  var mac = newPoly1305Ctx(sub, n12, ad)
  mac.update(ct)
  if not mac.verify(tag): return (false, @[])
  var ch = newChaCha20Ctx(sub, n12); ch.seek(1'u64, 0'u64, 0'u)
  return (true, ch.encrypt(ct))


# AES-GCM-SIV
proc aeadAesGcmSivEncrypt(key: openArray[byte], nonce12: array[12,byte],
                          ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  ## Encrypt using AES-GCM-SIV, returning (ct, tag)
  var ctx = newAesGcmSivCtx(key, nonce12)
  let (ctOnly, tagBlock) = ctx.encrypt(ad, pt)
  var tag: array[TagLen, byte]
  for j in 0 ..< TagLen:
    tag[j] = tagBlock[j]
  return (ctOnly, tag)


proc aeadAesGcmSivDecrypt(key: openArray[byte], nonce12: array[12,byte],
                          ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  ## Verify tag and decrypt using AES-GCM-SIV. Returns (ok, pt).
  var ctx = newAesGcmSivCtx(key, nonce12)
  let pt = ctx.decrypt(ad, ct, tag)
  return (true, pt)


# Twofish-GCM-SIV
proc aeadTwofishGcmSivEncrypt(key: openArray[byte], nonce12: array[12,byte],
                              ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  ## Encrypt using TWOFISH-GCM-SIV, returning (ct, tag)
  var ctx = newTwofishGcmSivCtx(key, nonce12)
  let (ctOnly, tagBlock) = ctx.encrypt(ad, pt)
  var tag: array[TagLen, byte]
  for j in 0 ..< TagLen:
    tag[j] = tagBlock[j]
  return (ctOnly, tag)


proc aeadTwofishGcmSivDecrypt(key: openArray[byte], nonce12: array[12,byte],
                              ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  ## Verify tag and decrypt using TWOFISH-GCM-SIV. Returns (ok, pt).
  var ctx = newTwofishGcmSivCtx(key, nonce12)
  let pt = ctx.decrypt(ad, ct, tag)
  return (true, pt)


# Serpent-GCM-SIV
proc aeadSerpentGcmSivEncrypt(key: openArray[byte], nonce12: array[12,byte],
                              ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  ## Encrypt using AES-GCM-SIV, returning (ct, tag)
  var ctx = newSerpentGcmSivCtx(key, nonce12)
  let (ctOnly, tagBlock) = ctx.encrypt(ad, pt)
  var tag: array[TagLen, byte]
  for j in 0 ..< TagLen:
    tag[j] = tagBlock[j]
  return (ctOnly, tag)


proc aeadSerpentGcmSivDecrypt(key: openArray[byte], nonce12: array[12,byte],
                          ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  ## Verify tag and decrypt using AES-GCM-SIV. Returns (ok, pt).
  var ctx = newSerpentGcmSivCtx(key, nonce12)
  let pt = ctx.decrypt(ad, ct, tag)
  return (true, pt)


# Camellia-GCM-SIV
proc aeadCamelliaGcmSivEncrypt(key: openArray[byte], nonce12: array[12,byte],
                          ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  ## Encrypt using AES-GCM-SIV, returning (ct, tag)
  var ctx = newCamelliaGcmSivCtx(key, nonce12)
  let (ctOnly, tagBlock) = ctx.encrypt(ad, pt)
  var tag: array[TagLen, byte]
  for j in 0 ..< TagLen:
    tag[j] = tagBlock[j]
  return (ctOnly, tag)


proc aeadCamelliaGcmSivDecrypt(key: openArray[byte], nonce12: array[12,byte],
                          ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  ## Verify tag and decrypt using AES-GCM-SIV. Returns (ok, pt).
  var ctx = newCamelliaGcmSivCtx(key, nonce12)
  let pt = ctx.decrypt(ad, ct, tag)
  return (true, pt)


# Aurora-SIV
proc aeadAuroraCtrP1305Encrypt(key: openArray[byte], nonce16: array[16,byte],
                               ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  let ctx = newAuroraPiContext(key, nonce16)
  let (tag, ct) = ctx.sivSeal(ad, pt)
  return (ct, tag)


proc aeadAuroraCtrP1305Decrypt(key: openArray[byte], nonce16: array[16,byte],
                               ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  let ctx = newAuroraPiContext(key, nonce16)
  var pt = ctx.sivOpen(ad, tag, ct)
  return (true, pt)

# ---- Suite router helpers ----

proc aeadEncryptAt(s: CipherSuite, key: openArray[byte], base: array[NonceBaseLen, byte],
                   idx: uint64, ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  case s
  of csXChaCha20:   aeadXC20P1305Encrypt(key, nonce24WithIdx(base, idx), ad, pt)
  of csAesGCM:      aeadAesGcmSivEncrypt(key, nonce12ForIdx(base, idx), ad, pt)
  of csTwofishGCM:  aeadTwofishGcmSivEncrypt(key, nonce12ForIdx(base, idx), ad, pt)
  of csSerpentGCM:  aeadSerpentGcmSivEncrypt(key, nonce12ForIdx(base, idx), ad, pt)
  of csCamelliaGCM: aeadCamelliaGcmSivEncrypt(key, nonce12ForIdx(base, idx), ad, pt)
  of csAuroraCtr:   aeadAuroraCtrP1305Encrypt(key, nonce16ForIdx(base, idx), ad, pt)


proc aeadDecryptAt(s: CipherSuite, key: openArray[byte], base: array[NonceBaseLen, byte],
                   idx: uint64, ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  case s
  of csXChaCha20:   aeadXC20P1305Decrypt(key, nonce24WithIdx(base, idx), ad, ct, tag)
  of csAesGCM:      aeadAesGcmSivDecrypt(key, nonce12ForIdx(base, idx), ad, ct, tag)
  of csTwofishGCM:  aeadTwofishGcmSivDecrypt(key, nonce12ForIdx(base, idx), ad, ct, tag)
  of csSerpentGCM:  aeadSerpentGcmSivDecrypt(key, nonce12ForIdx(base, idx), ad, ct, tag)
  of csCamelliaGCM: aeadCamelliaGcmSivDecrypt(key, nonce12ForIdx(base, idx), ad, ct, tag)
  of csAuroraCtr:   aeadAuroraCtrP1305Decrypt(key, nonce16ForIdx(base, idx), ad, ct, tag)


# Keep the old meta/filename/chunk helpers for clarity
proc aeadMetaEncrypt(s: CipherSuite, key: openArray[byte], base: array[NonceBaseLen, byte],
                     ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  aeadEncryptAt(s, key, base, IdxFilename, ad, pt)


proc aeadMetaDecrypt(s: CipherSuite, key: openArray[byte], base: array[NonceBaseLen, byte],
                     ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  aeadDecryptAt(s, key, base, IdxFilename, ad, ct, tag)


proc aeadChunkEncrypt(s: CipherSuite, key: openArray[byte], base: array[NonceBaseLen, byte],
                      idx: uint64, ad, pt: openArray[byte]): (seq[byte], array[TagLen, byte]) =
  aeadEncryptAt(s, key, base, idx, ad, pt)


proc aeadChunkDecrypt(s: CipherSuite, key: openArray[byte], base: array[NonceBaseLen, byte],
                      idx: uint64, ad, ct: openArray[byte], tag: openArray[byte]): (bool, seq[byte]) =
  aeadDecryptAt(s, key, base, idx, ad, ct, tag)

# -------------------- Metadata pack/unpack --------------------

proc permSetToBits(p: set[FilePermission]): uint16 =
  var b: uint16 = 0
  template setbit(bit: int) = (b = b or (1'u16 shl bit))
  if fpUserRead   in p: setbit 0
  if fpUserWrite  in p: setbit 1
  if fpUserExec   in p: setbit 2
  if fpGroupRead  in p: setbit 3
  if fpGroupWrite in p: setbit 4
  if fpGroupExec  in p: setbit 5
  if fpOthersRead in p: setbit 6
  if fpOthersWrite in p: setbit 7
  if fpOthersExec in p: setbit 8
  return b


proc bitsToPermSet(b: uint16): set[FilePermission] =
  result = {}
  template has(bit: int): bool = (b and (1'u16 shl bit)) != 0
  if has 0: result.incl fpUserRead
  if has 1: result.incl fpUserWrite
  if has 2: result.incl fpUserExec
  if has 3: result.incl fpGroupRead
  if has 4: result.incl fpGroupWrite
  if has 5: result.incl fpGroupExec
  if has 6: result.incl fpOthersRead
  if has 7: result.incl fpOthersWrite
  if has 8: result.incl fpOthersExec


proc packMeta(path: string): seq[byte] =
  ## mtime (unix seconds) || permsBits (u16)
  let msec  = os.getLastModificationTime(path).toUnix
  let perms = getFilePermissions(path)
  let bits  = permSetToBits(perms)
  result = @[]
  putU64(result, uint64(msec))
  putU16(result, bits)


proc unpackMeta(buf: openArray[byte]): (uint64, set[FilePermission]) =
  if buf.len < 10: raise newException(IOError, "bad meta")
  let msec =
    uint64(buf[0]) or (uint64(buf[1]) shl 8) or (uint64(buf[2]) shl 16) or (uint64(buf[3]) shl 24) or
    (uint64(buf[4]) shl 32) or (uint64(buf[5]) shl 40) or (uint64(buf[6]) shl 48) or (uint64(buf[7]) shl 56)
  let bits = uint16(buf[8]) or (uint16(buf[9]) shl 8)
  return (msec, bitsToPermSet(bits))


proc applyMeta(path: string, msec: uint64, perms: set[FilePermission]) =
  setLastModificationTime(path, fromUnix(int64(msec)))
  try:
    setFilePermissions(path, perms)
  except OSError:
    discard

# -------------------- Header bytes (for AD) --------------------

proc buildHeaderFixed(h: Header): seq[byte] =
  var output: seq[byte]
  for i in 0..<4: output.add(byte h.magic[i])
  output.add(h.version)
  output.add(h.suite)
  output.add(h.flags)
  putU32(output, h.mKiB); putU32(output, h.t); putU32(output, h.p)
  for b in h.salt: output.add(b)
  for b in h.nonceBase: output.add(b)
  putU32(output, h.chunkSize)
  putU16(output, h.fnLen)
  return output


proc writeHeader*(s: Stream, h: Header, headerFixedOut: var seq[byte]) =
  headerFixedOut = buildHeaderFixed(h)
  s.writeData(unsafeAddr headerFixedOut[0], headerFixedOut.len)


proc readHeader*(s: Stream): (Header, seq[byte]) =
  var h: Header
  var fixed: seq[byte]
  # magic
  var mag: array[4, char]
  if s.readData(addr mag[0], 4) != 4: raise newException(IOError, "EOF reading magic")
  if mag != MAGIC4: raise newException(IOError, "bad magic")
  for i in 0..<4: h.magic[i] = mag[i]
  fixed.add(byte mag[0]); fixed.add(byte mag[1]); fixed.add(byte mag[2]); fixed.add(byte mag[3])
  # v3 fields
  var v, su, f: uint8
  if s.readData(addr v, 1)  != 1: raise newException(IOError, "EOF version")
  if v != VERSION: raise newException(IOError, "unsupported version")
  if s.readData(addr su, 1) != 1: raise newException(IOError, "EOF suite")
  if s.readData(addr f, 1)  != 1: raise newException(IOError, "EOF flags")
  h.version = v; h.suite = su; h.flags = f
  fixed.add(v); fixed.add(su); fixed.add(f)
  # params
  h.mKiB = s.getU32(); putU32(fixed, h.mKiB)
  h.t    = s.getU32(); putU32(fixed, h.t)
  h.p    = s.getU32(); putU32(fixed, h.p)
  if s.readData(addr h.salt[0], SaltLen) != SaltLen: raise newException(IOError, "EOF salt")
  for b in h.salt: fixed.add(b)
  if s.readData(addr h.nonceBase[0], NonceBaseLen) != NonceBaseLen: raise newException(IOError, "EOF nonce")
  for b in h.nonceBase: fixed.add(b)
  h.chunkSize = s.getU32(); putU32(fixed, h.chunkSize)
  h.fnLen     = s.getU16(); putU16(fixed, h.fnLen)
  return (h, fixed)

# -------------------- Encrypt / Decrypt core --------------------

proc encFile*(srcPath: string, password: string, chunkSize = DefaultChunk,
              mKiB = DefaultArgonM, t = DefaultArgonT, p = DefaultArgonP,
              quiet=false, suite: CipherSuite = csXChaCha20) =
  if not fileExists(srcPath):
    if not quiet: echo "file not found: ", srcPath
    return

  var h: Header
  h.magic = [MAGIC[0],MAGIC[1],MAGIC[2],MAGIC[3]]
  h.version = VERSION
  h.suite   = uint8(suite)
  h.flags   = FlagHasName or FlagHasMeta      # metadata ON by default
  h.mKiB    = uint32(mKiB)
  h.t       = uint32(t)
  h.p       = uint32(p)
  discard urandom(h.salt)
  discard urandom(h.nonceBase)
  h.chunkSize = uint32(chunkSize)

  let (dir, fname) = splitPath(srcPath)
  if fname.len > high(uint16).int: raise newException(ValueError, "filename too long")
  h.fnLen = uint16(fname.len)

  let master = kdfMaster(password, h.salt, mKiB, t, p, 32)
  let (kMeta, kData) = deriveSubkeys(master, suite)

  let inS  = newFileStream(srcPath, fmRead)
  if inS.isNil: raise newException(IOError, "unable to open input")

  var ok = false
  try:
    # Build header bytes (used as AD)
    let headerFixed = buildHeaderFixed(h)

    # Encrypt filename at idx=0
    let tagLen = tagLenForSuite(suite)
    let (fnCT, fnTagDyn) = aeadMetaEncrypt(suite, kMeta, h.nonceBase, headerFixed,
                                      fname.toOpenArrayByte(0, fname.len-1))

    # -------- FILENAME HASHING (on-disk ciphertext name) --------
    var fnHasher = newBlake2sCtx(key=master, salt=h.nonceBase.toOpenArray(0, 7), digestSize=32)
    fnHasher.update(fnCT)
    let outName = fnHasher.hexDigest() & ".crypt"
    let outPath = dir / outName
    # ------------------------------------------------------------

    let outS = newFileStream(outPath, fmWrite)
    if outS.isNil: (inS.close(); raise newException(IOError, "unable to open output"))
    try:
      # Write header
      outS.writeData(unsafeAddr headerFixed[0], headerFixed.len)

      # Write encrypted filename + tag
      outS.writeData(unsafeAddr fnCT[0], fnCT.len)
      outS.writeData(unsafeAddr fnTagDyn[0], tagLen)

      # Encrypt metadata block (mtime + mode), at distinct nonce idx
      var adDataPrefix = headerFixed
      adDataPrefix.add(fnCT)
      for i in 0..<tagLen: adDataPrefix.add(fnTagDyn[i])

      if (h.flags and FlagHasMeta) != 0'u8:
        let metaPlain = packMeta(srcPath)
        var metaCT: seq[byte]
        var metaTagDyn: seq[byte]
        let (ctm, tagm) = aeadEncryptAt(suite, kMeta, h.nonceBase, IdxMeta, headerFixed, metaPlain)
        metaCT = ctm; metaTagDyn = @tagm
        # write metaLen, metaCT, metaTag
        var ml = uint32(metaCT.len)
        var lenbuf: array[4, byte]
        lenbuf[0] = byte ml
        lenbuf[1] = byte (ml shr 8)
        lenbuf[2] = byte (ml shr 16)
        lenbuf[3] = byte (ml shr 24)
        outS.writeData(addr lenbuf[0], 4)
        outS.writeData(unsafeAddr metaCT[0], metaCT.len)
        outS.writeData(unsafeAddr metaTagDyn[0], tagLen)

        # bind chunks to metadata as well
        adDataPrefix.add(metaCT)
        for i in 0..<tagLen: adDataPrefix.add(metaTagDyn[i])

      # Stream data in chunks
      var chunkIdx: uint64 = 1
      var buf = newSeq[byte](chunkSize)

      while true:
        let r = inS.readData(addr buf[0], buf.len)
        if r <= 0: break

        var ad = adDataPrefix
        putU64(ad, chunkIdx)
        putU32(ad, uint32(r))

        let (ct, tagDyn) = aeadChunkEncrypt(suite, kData, h.nonceBase, chunkIdx, ad, buf.toOpenArray(0, r-1))
      
        var u32len: array[4, byte]
        u32len[0] = byte  r
        u32len[1] = byte (r shr 8)
        u32len[2] = byte (r shr 16)
        u32len[3] = byte (r shr 24)
        outS.writeData(addr u32len[0], 4)
        outS.writeData(unsafeAddr ct[0], ct.len)
        outS.writeData(unsafeAddr tagDyn[0], tagLen)

        inc chunkIdx

      outS.flush()
      ok = true
    finally:
      outS.close()
  finally:
    inS.close()

  if ok:
    discard tryRemoveFile(srcPath)
    if not quiet: stdout.styledWriteLine(fgDefault, "[", fgGreen, "encrypted", fgDefault, "] ", fname)
  else:
    if not quiet: stdout.styledWriteLine(fgDefault, "<", fgRed, "error", fgDefault, "> ", fname)


proc decFile*(encPath: string, password: string, quiet=false) =
  if not fileExists(encPath):
    if not quiet: echo "file not found: ", encPath
    return

  let inS = newFileStream(encPath, fmRead)
  if inS.isNil: raise newException(IOError, "unable to open input")

  var ok = false
  var outPath = ""
  try:
    let (h, headerFixed) = inS.readHeader()
    let suite = CipherSuite(h.suite)
    let master = kdfMaster(password, h.salt, int(h.mKiB), int(h.t), int(h.p), 32)
    let (kMeta, kData) = deriveSubkeys(master, suite)

    # Filename
    if h.fnLen == 0: raise newException(IOError, "missing filename")
    var fnCT = newSeq[byte](int(h.fnLen))
    if inS.readData(addr fnCT[0], fnCT.len) != fnCT.len: raise newException(IOError, "EOF filename CT")
    let tagLen = tagLenForSuite(suite)
    var tagFn = newSeq[byte](tagLen)
    if inS.readData(addr tagFn[0], tagLen) != tagLen: raise newException(IOError, "EOF filename tag")

    let (metaOk, fnPlain) = aeadMetaDecrypt(suite, kMeta, h.nonceBase, headerFixed, fnCT, tagFn)
    if not metaOk: raise newException(IOError, "bad filename tag")

    let dir = splitPath(encPath).head
    outPath = dir / bytesToString(fnPlain)

    let outS = newFileStream(outPath, fmWrite)
    if outS.isNil: raise newException(IOError, "unable to open output")

    # AD prefix for chunks
    var adDataPrefix = headerFixed
    adDataPrefix.add(fnCT)
    for i in 0..<tagLen: adDataPrefix.add(tagFn[i])

    # Encrypted metadata (if present)
    var restoreMsec: uint64 = 0
    var restorePerms: set[FilePermission] = {}
    if (h.flags and FlagHasMeta) != 0'u8:
      var lenBuf: array[4, byte]
      if inS.readData(addr lenBuf[0], 4) != 4: raise newException(IOError, "EOF meta len")
      let metaLen = uint32(lenBuf[0]) or (uint32(lenBuf[1]) shl 8) or (uint32(lenBuf[2]) shl 16) or (uint32(lenBuf[3]) shl 24)
      if metaLen > 0'u32:
        var metaCT = newSeq[byte](int(metaLen))
        if inS.readData(addr metaCT[0], metaCT.len) != metaCT.len: raise newException(IOError, "EOF meta CT")
        let tagLen = tagLenForSuite(suite)
        var tagM = newSeq[byte](tagLen)
        if inS.readData(addr tagM[0], tagLen) != tagLen: raise newException(IOError, "EOF meta tag")

        let (okM, metaPlain) = aeadDecryptAt(suite, kMeta, h.nonceBase, IdxMeta, headerFixed, metaCT, tagM)
        if not okM: raise newException(IOError, "bad metadata tag")

        # metaPlain = u64 mtime || u16 permBits (LE)
        if metaPlain.len < 10:
          raise newException(IOError, "bad metadata blob")
        let msec =
          uint64(metaPlain[0]) or (uint64(metaPlain[1]) shl 8) or (uint64(metaPlain[2]) shl 16) or (uint64(metaPlain[3]) shl 24) or
          (uint64(metaPlain[4]) shl 32) or (uint64(metaPlain[5]) shl 40) or (uint64(metaPlain[6]) shl 48) or (uint64(metaPlain[7]) shl 56)
        let bits = uint16(metaPlain[8]) or (uint16(metaPlain[9]) shl 8)
        restoreMsec = msec
        restorePerms = bitsToPermSet(bits)

        # bind chunks to metadata too
        adDataPrefix.add(metaCT)
        for i in 0..<tagLen: adDataPrefix.add(tagM[i])

    # Chunks
    var chunkIdx: uint64 = 1
    var len: uint32
    var lenBuf: array[4, byte]

    while true:
      let got = inS.readData(addr lenBuf[0], 4)
      if got == 0: break
      if got != 4: raise newException(IOError, "EOF chunk len")
      len = uint32(lenBuf[0]) or (uint32(lenBuf[1]) shl 8) or (uint32(lenBuf[2]) shl 16) or (uint32(lenBuf[3]) shl 24)

      var ct = newSeq[byte](len.int)
      if inS.readData(addr ct[0], ct.len) != ct.len: raise newException(IOError, "EOF chunk CT")
      let tagLen = tagLenForSuite(suite)
      var tagC = newSeq[byte](tagLen)
      if inS.readData(addr tagC[0], tagLen) != tagLen: raise newException(IOError, "EOF chunk tag")

      var ad = adDataPrefix
      putU64(ad, chunkIdx)
      putU32(ad, len)

      let (okC, pt) = aeadChunkDecrypt(suite, kData, h.nonceBase, chunkIdx, ad, ct, tagC)
      if not okC: raise newException(IOError, "authentication failed (chunk)")

      outS.writeData(unsafeAddr pt[0], pt.len)
      inc chunkIdx

    outS.flush()
    outS.close()

    # Restore metadata (best-effort)
    if (h.flags and FlagHasMeta) != 0'u8 and restoreMsec != 0'u64:
      applyMeta(outPath, restoreMsec, restorePerms)

    ok = true
  finally:
    inS.close()

  if ok:
    discard tryRemoveFile(encPath)
    if not quiet: stdout.styledWriteLine(fgDefault, "[", fgGreen, "decrypted", fgDefault, "] ", outPath.splitPath.tail)
  else:
    if not quiet: stdout.styledWriteLine(fgDefault, "<", fgRed, "error", fgDefault, "> ", encPath)

# -------------------- Dir helpers & CLI --------------------

proc encDir*(dirPath: string, password: string, recursive=false, quiet=false, chunkSize=DefaultChunk,
             mKiB=DefaultArgonM, t=DefaultArgonT, p=DefaultArgonP, suite: CipherSuite = csXChaCha20) =
  if not dirExists(dirPath):
    if not quiet: echo "directory not found: ", dirPath
    return
  if recursive:
    for fp in walkDirRec(dirPath):
      if fileExists(fp) and not fp.endsWith(".crypt") and not isHidden(fp):
        encFile(fp, password, chunkSize, mKiB, t, p, quiet, suite)
  else:
    for kind, fp in walkDir(dirPath):
      if kind == pcFile and not fp.endsWith(".crypt") and not isHidden(fp):
        encFile(fp, password, chunkSize, mKiB, t, p, quiet, suite)


proc decDir*(dirPath: string, password: string, recursive=false, quiet=false) =
  if not dirExists(dirPath):
    if not quiet: echo "directory not found: ", dirPath
    return
  if recursive:
    for fp in walkDirRec(dirPath):
      if fileExists(fp) and fp.endsWith(".crypt"):
        decFile(fp, password, quiet)
  else:
    for kind, fp in walkDir(dirPath):
      if kind == pcFile and fp.endsWith(".crypt"):
        decFile(fp, password, quiet)


proc readPw(prompt: string): string =
  when declared(readPasswordFromStdin):
    result = readPasswordFromStdin(prompt)
  else:
    stdout.write(prompt); stdout.flushFile(); result = stdin.readLine()


proc parseSuite(s: string): CipherSuite =
  let v = s.toLowerAscii()
  if v in ["chacha", "xchacha20", "xc20", "xchacha20-poly1305"]: return csXChaCha20
  if v in ["aes", "aes-gcm-siv", "aes-gcm", "aesgcm"]: return csAesGCM
  if v in ["twofish", "twofish-gcm-siv", "twofish-gcm", "twofishgcm"]: return csTwofishGCM
  if v in ["serpent", "serpent-gcm-siv", "serpent-gcm", "serpentgcm"]: return csSerpentGCM
  if v in ["camellia", "camellia-gcm-siv", "camellia-gcm", "camelliagcm"]: return csCamelliaGCM
  if v in ["aurora", "aurora-siv", "aurorasiv"]: return csAuroraCtr
  raise newException(ValueError, "unknown cipher: " & s)

proc usage() =
  echo "NimCrypt-AEF — multi-cipher (xchacha20/aes-gcm-siv/twofish-gcm-siv/serpent-gcm-siv/camellia-gcm-siv/aurora-siv)"
  echo "usage:"
  echo "  nimcrypt -e/encrypt/-d/decrypt [flags] file"
  echo "  nimcrypt -v/--version"
  echo "  nimcrypt <subcommand> -q/--quiet"
  echo "  nimcrypt <subcommand> -r/--recursive"
  echo "  nimcrypt <subcommand> -c/--cipher"
  echo "  nimcrypt <subcommand> -m<N> -t<N> -p<N>"
  echo ""
  echo "Use 'nimcrypt --help' to see all options."

proc main() =
  const
    sNoVal  = {'e','d','h','q','r','v'}
    lNoVal  = @["encrypt","decrypt","help","quiet","recursive","version"]
  var
    paths: seq[string]
    mode = -1
    recursive = false
    quiet = false
    chunkMiB = DefaultChunkMiB
    mKiB     = DefaultArgonM
    t        = DefaultArgonT
    p        = DefaultArgonP
    suite    = csXChaCha20

  for kind, key, val in getopt(shortNoVal=sNoVal, longNoVal=lNoVal):
    case kind
    of cmdEnd: break
    of cmdArgument:
      if key.len > 0: paths.add(key)
    of cmdShortOption, cmdLongOption:
      case key
      of "e","encrypt": mode = 0
      of "d","decrypt": mode = 1
      of "h","help":
        usage()
        return
      of "q","quiet": quiet = true
      of "r","recursive": recursive = true
      of "v","version": echo "3"; return
      of "chunk": chunkMiB = parseInt(val)
      of "m": mKiB = parseInt(val)
      of "t": t = parseInt(val)
      of "p": p = parseInt(val)
      of "cipher", "c": suite = parseSuite(val)
      else:
        echo "invalid option: ", key; return

  if paths.len == 0: echo "no path(s)"; return

  let pw1 = readPw("password: ")
  let pw2 = readPw("verify password: ")
  if pw1 != pw2: echo "passwords do not match"; return

  let chunkSize = max(1, chunkMiB) * 1024 * 1024

  for fp in paths:
    var m = mode
    if m == -1: m = if fp.endsWith(".crypt"): 1 else: 0
    if m == 0:
      if dirExists(fp): encDir(fp, pw1, recursive, quiet, chunkSize, mKiB, t, p, suite)
      else: encFile(fp, pw1, chunkSize, mKiB, t, p, quiet, suite)
    else:
      if dirExists(fp): decDir(fp, pw1, recursive, quiet)
      else: decFile(fp, pw1, quiet)


when isMainModule:
  main()
