const gBlocksize = 16

type Block128* = array[gBlocksize, byte]

proc xorBlock*(a: var Block128, b: Block128) {.inline.} =
  for i in 0 ..< gBlocksize:
    a[i] = a[i] xor b[i]

proc xorInto*(dst: var openArray[byte], src: openArray[byte]) {.inline.} =
  for i in 0 ..< src.len:
    dst[i] = dst[i] xor src[i]

proc shiftRight1(b: var Block128) {.inline.} =
  var carry: byte = 0
  for i in 0 ..< gBlocksize:
    let cur = b[i]
    let newCarry = cur and 0x01
    b[i] = (cur shr 1) or (carry shl 7)
    carry = newCarry

proc gf128Mul*(x, y: Block128): Block128 =
  # GHASH multiplication in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1
  # Implements NIST SP 800-38D, Appendix B (bit-by-bit right shift method)
  var Z: Block128 # zero
  var V: Block128 = y

  for byteIdx in 0 ..< gBlocksize:
    var mask: byte = 0x80
    while mask != 0:
      if (x[byteIdx] and mask) != 0:
        xorBlock(Z, V)

      let lsb = (V[gBlocksize - 1] and 0x01) != 0
      shiftRight1(V)
      if lsb:
        V[0] = V[0] xor 0xE1'u8
      mask = mask shr 1

  return Z

proc beLen64(n: uint64): array[8, byte] {.inline.} =
  var r: array[8, byte]
  for i in 0 ..< 8:
    r[7 - i] = byte((n shr (8 * i)) and 0xFF'u64)
  return r

proc ghashBlocks*(H: Block128, blocks: openArray[byte]): Block128 =
  var Y: Block128
  var i = 0
  while i < blocks.len:
    var blk: Block128
    for j in 0 ..< gBlocksize:
      blk[j] = blocks[i + j]
    xorBlock(Y, blk)
    Y = gf128Mul(Y, H)
    i.inc(gBlocksize)
  return Y

proc ghash*(H: Block128, aad, data: openArray[byte]): Block128 =
  var Y: Block128 # all zeros

  # AAD blocks
  var i = 0
  while i < aad.len:
    var blk: Block128
    let take = min(gBlocksize, aad.len - i)
    for j in 0 ..< take: blk[j] = aad[i + j]
    # remaining bytes are already zero-padded
    xorBlock(Y, blk)
    Y = gf128Mul(Y, H)
    i.inc(take)

  # Data blocks
  i = 0
  while i < data.len:
    var blk: Block128
    let take = min(gBlocksize, data.len - i)
    for j in 0 ..< take: blk[j] = data[i + j]
    xorBlock(Y, blk)
    Y = gf128Mul(Y, H)
    i.inc(take)

  # Lengths block: [len(AAD) in bits | len(DATA) in bits]
  var lenBlk: Block128
  let aBits = beLen64(uint64(aad.len) * 8'u64)
  let dBits = beLen64(uint64(data.len) * 8'u64)
  for j in 0 ..< 8: lenBlk[j] = aBits[j]
  for j in 0 ..< 8: lenBlk[8 + j] = dBits[j]
  xorBlock(Y, lenBlk)
  Y = gf128Mul(Y, H)

  return Y

proc ctEq*(a, b: openArray[byte]): bool {.inline.} =
  if a.len != b.len: return false
  var acc: uint8 = 0
  for i in 0 ..< a.len:
    acc = acc xor (a[i] xor b[i])
  return acc == 0

proc byteReverse*(b: Block128): Block128 {.inline.} =
  for i in 0 ..< gBlocksize:
    result[i] = b[gBlocksize - 1 - i]

proc reverseBlocks*(data: openArray[byte]): seq[byte] =
  assert data.len mod gBlocksize == 0
  result = newSeq[byte](data.len)
  var i = 0
  while i < data.len:
    for j in 0 ..< gBlocksize:
      result[i + j] = data[i + (gBlocksize - 1 - j)]
    i.inc(gBlocksize)

proc mulX_GHASH*(b: Block128): Block128 =
  var v = b
  let lsb = (v[gBlocksize - 1] and 0x01) != 0
  # Right shift by 1 (GHASH convention)
  var carry: byte = 0
  for i in 0 ..< gBlocksize:
    let cur = v[i]
    let newCarry = cur and 0x01
    v[i] = (cur shr 1) or (carry shl 7)
    carry = newCarry
  if lsb:
    v[0] = v[0] xor 0xE1'u8
  return v

proc leLen64(n: uint64): array[8, byte] {.inline.} =
  var r: array[8, byte]
  for i in 0 ..< 8:
    r[i] = byte((n shr (8 * i)) and 0xFF'u64)
  return r

proc padToBlocks*(data: openArray[byte]): seq[byte] =
  let rem = data.len mod gBlocksize
  if rem == 0:
    result = @data
  else:
    result = newSeq[byte](data.len + (gBlocksize - rem))
    for i in 0 ..< data.len: result[i] = data[i]


proc polyval*(H: Block128, aad, data: openArray[byte]): Block128 =
  let padA = padToBlocks(aad)
  let padD = padToBlocks(data)
  var lenBlk: Block128
  let aBits = leLen64(uint64(aad.len) * 8'u64)
  let dBits = leLen64(uint64(data.len) * 8'u64)
  for j in 0 ..< 8: lenBlk[j] = aBits[j]
  for j in 0 ..< 8: lenBlk[8 + j] = dBits[j]
  var buf = newSeq[byte](padA.len + padD.len + gBlocksize)
  var off = 0
  for i in 0 ..< padA.len: (buf[off] = padA[i]; inc(off))
  for i in 0 ..< padD.len: (buf[off] = padD[i]; inc(off))
  for j in 0 ..< gBlocksize: (buf[off] = lenBlk[j]; inc(off))
  let Hb = byteReverse(H)
  let Hx = mulX_GHASH(Hb)
  let blocksRev = reverseBlocks(buf)
  let Yb = ghashBlocks(Hx, blocksRev)
  return byteReverse(Yb)
