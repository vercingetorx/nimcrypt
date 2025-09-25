import std/bitops

# NOTE: ported to Nim from https://cs.opensource.google/go/x/crypto/+/master:twofish/twofish.go
# with unrolled rounds and inline helpers.

const
  mdsPolynomial: uint32 = 0x169'u32  # x^8 + x^6 + x^5 + x^3 + 1, see [TWOFISH] 4.2
  rsPolynomial:  uint32 = 0x14d'u32  # x^8 + x^6 + x^3 + x^2 + 1, see [TWOFISH] 4.3

type
  KeySizeError = object of ValueError

# NOTE: the RS matrix. See [TWOFISH] 4.3
const rs: array[4, array[8, byte]] = [
  [0x01'u8, 0xA4'u8, 0x55'u8, 0x87'u8, 0x5A'u8, 0x58'u8, 0xDB'u8, 0x9E'u8],
  [0xA4'u8, 0x56'u8, 0x82'u8, 0xF3'u8, 0x1E'u8, 0xC6'u8, 0x68'u8, 0xE5'u8],
  [0x02'u8, 0xA1'u8, 0xFC'u8, 0xC1'u8, 0x47'u8, 0xAE'u8, 0x3D'u8, 0x19'u8],
  [0xA4'u8, 0x55'u8, 0x87'u8, 0x5A'u8, 0x58'u8, 0xDB'u8, 0x9E'u8, 0x03'u8]
]

# NOTE: sbox tables
const sbox: array[2, array[256, byte]] = [
  [
    0xa9'u8, 0x67'u8, 0xb3'u8, 0xe8'u8, 0x04'u8, 0xfd'u8, 0xa3'u8, 0x76'u8,
    0x9a'u8, 0x92'u8, 0x80'u8, 0x78'u8, 0xe4'u8, 0xdd'u8, 0xd1'u8, 0x38'u8,
    0x0d'u8, 0xc6'u8, 0x35'u8, 0x98'u8, 0x18'u8, 0xf7'u8, 0xec'u8, 0x6c'u8,
    0x43'u8, 0x75'u8, 0x37'u8, 0x26'u8, 0xfa'u8, 0x13'u8, 0x94'u8, 0x48'u8,
    0xf2'u8, 0xd0'u8, 0x8b'u8, 0x30'u8, 0x84'u8, 0x54'u8, 0xdf'u8, 0x23'u8,
    0x19'u8, 0x5b'u8, 0x3d'u8, 0x59'u8, 0xf3'u8, 0xae'u8, 0xa2'u8, 0x82'u8,
    0x63'u8, 0x01'u8, 0x83'u8, 0x2e'u8, 0xd9'u8, 0x51'u8, 0x9b'u8, 0x7c'u8,
    0xa6'u8, 0xeb'u8, 0xa5'u8, 0xbe'u8, 0x16'u8, 0x0c'u8, 0xe3'u8, 0x61'u8,
    0xc0'u8, 0x8c'u8, 0x3a'u8, 0xf5'u8, 0x73'u8, 0x2c'u8, 0x25'u8, 0x0b'u8,
    0xbb'u8, 0x4e'u8, 0x89'u8, 0x6b'u8, 0x53'u8, 0x6a'u8, 0xb4'u8, 0xf1'u8,
    0xe1'u8, 0xe6'u8, 0xbd'u8, 0x45'u8, 0xe2'u8, 0xf4'u8, 0xb6'u8, 0x66'u8,
    0xcc'u8, 0x95'u8, 0x03'u8, 0x56'u8, 0xd4'u8, 0x1c'u8, 0x1e'u8, 0xd7'u8,
    0xfb'u8, 0xc3'u8, 0x8e'u8, 0xb5'u8, 0xe9'u8, 0xcf'u8, 0xbf'u8, 0xba'u8,
    0xea'u8, 0x77'u8, 0x39'u8, 0xaf'u8, 0x33'u8, 0xc9'u8, 0x62'u8, 0x71'u8,
    0x81'u8, 0x79'u8, 0x09'u8, 0xad'u8, 0x24'u8, 0xcd'u8, 0xf9'u8, 0xd8'u8,
    0xe5'u8, 0xc5'u8, 0xb9'u8, 0x4d'u8, 0x44'u8, 0x08'u8, 0x86'u8, 0xe7'u8,
    0xa1'u8, 0x1d'u8, 0xaa'u8, 0xed'u8, 0x06'u8, 0x70'u8, 0xb2'u8, 0xd2'u8,
    0x41'u8, 0x7b'u8, 0xa0'u8, 0x11'u8, 0x31'u8, 0xc2'u8, 0x27'u8, 0x90'u8,
    0x20'u8, 0xf6'u8, 0x60'u8, 0xff'u8, 0x96'u8, 0x5c'u8, 0xb1'u8, 0xab'u8,
    0x9e'u8, 0x9c'u8, 0x52'u8, 0x1b'u8, 0x5f'u8, 0x93'u8, 0x0a'u8, 0xef'u8,
    0x91'u8, 0x85'u8, 0x49'u8, 0xee'u8, 0x2d'u8, 0x4f'u8, 0x8f'u8, 0x3b'u8,
    0x47'u8, 0x87'u8, 0x6d'u8, 0x46'u8, 0xd6'u8, 0x3e'u8, 0x69'u8, 0x64'u8,
    0x2a'u8, 0xce'u8, 0xcb'u8, 0x2f'u8, 0xfc'u8, 0x97'u8, 0x05'u8, 0x7a'u8,
    0xac'u8, 0x7f'u8, 0xd5'u8, 0x1a'u8, 0x4b'u8, 0x0e'u8, 0xa7'u8, 0x5a'u8,
    0x28'u8, 0x14'u8, 0x3f'u8, 0x29'u8, 0x88'u8, 0x3c'u8, 0x4c'u8, 0x02'u8,
    0xb8'u8, 0xda'u8, 0xb0'u8, 0x17'u8, 0x55'u8, 0x1f'u8, 0x8a'u8, 0x7d'u8,
    0x57'u8, 0xc7'u8, 0x8d'u8, 0x74'u8, 0xb7'u8, 0xc4'u8, 0x9f'u8, 0x72'u8,
    0x7e'u8, 0x15'u8, 0x22'u8, 0x12'u8, 0x58'u8, 0x07'u8, 0x99'u8, 0x34'u8,
    0x6e'u8, 0x50'u8, 0xde'u8, 0x68'u8, 0x65'u8, 0xbc'u8, 0xdb'u8, 0xf8'u8,
    0xc8'u8, 0xa8'u8, 0x2b'u8, 0x40'u8, 0xdc'u8, 0xfe'u8, 0x32'u8, 0xa4'u8,
    0xca'u8, 0x10'u8, 0x21'u8, 0xf0'u8, 0xd3'u8, 0x5d'u8, 0x0f'u8, 0x00'u8,
    0x6f'u8, 0x9d'u8, 0x36'u8, 0x42'u8, 0x4a'u8, 0x5e'u8, 0xc1'u8, 0xe0'u8
  ],
  [
    0x75'u8, 0xf3'u8, 0xc6'u8, 0xf4'u8, 0xdb'u8, 0x7b'u8, 0xfb'u8, 0xc8'u8,
    0x4a'u8, 0xd3'u8, 0xe6'u8, 0x6b'u8, 0x45'u8, 0x7d'u8, 0xe8'u8, 0x4b'u8,
    0xd6'u8, 0x32'u8, 0xd8'u8, 0xfd'u8, 0x37'u8, 0x71'u8, 0xf1'u8, 0xe1'u8,
    0x30'u8, 0x0f'u8, 0xf8'u8, 0x1b'u8, 0x87'u8, 0xfa'u8, 0x06'u8, 0x3f'u8,
    0x5e'u8, 0xba'u8, 0xae'u8, 0x5b'u8, 0x8a'u8, 0x00'u8, 0xbc'u8, 0x9d'u8,
    0x6d'u8, 0xc1'u8, 0xb1'u8, 0x0e'u8, 0x80'u8, 0x5d'u8, 0xd2'u8, 0xd5'u8,
    0xa0'u8, 0x84'u8, 0x07'u8, 0x14'u8, 0xb5'u8, 0x90'u8, 0x2c'u8, 0xa3'u8,
    0xb2'u8, 0x73'u8, 0x4c'u8, 0x54'u8, 0x92'u8, 0x74'u8, 0x36'u8, 0x51'u8,
    0x38'u8, 0xb0'u8, 0xbd'u8, 0x5a'u8, 0xfc'u8, 0x60'u8, 0x62'u8, 0x96'u8,
    0x6c'u8, 0x42'u8, 0xf7'u8, 0x10'u8, 0x7c'u8, 0x28'u8, 0x27'u8, 0x8c'u8,
    0x13'u8, 0x95'u8, 0x9c'u8, 0xc7'u8, 0x24'u8, 0x46'u8, 0x3b'u8, 0x70'u8,
    0xca'u8, 0xe3'u8, 0x85'u8, 0xcb'u8, 0x11'u8, 0xd0'u8, 0x93'u8, 0xb8'u8,
    0xa6'u8, 0x83'u8, 0x20'u8, 0xff'u8, 0x9f'u8, 0x77'u8, 0xc3'u8, 0xcc'u8,
    0x03'u8, 0x6f'u8, 0x08'u8, 0xbf'u8, 0x40'u8, 0xe7'u8, 0x2b'u8, 0xe2'u8,
    0x79'u8, 0x0c'u8, 0xaa'u8, 0x82'u8, 0x41'u8, 0x3a'u8, 0xea'u8, 0xb9'u8,
    0xe4'u8, 0x9a'u8, 0xa4'u8, 0x97'u8, 0x7e'u8, 0xda'u8, 0x7a'u8, 0x17'u8,
    0x66'u8, 0x94'u8, 0xa1'u8, 0x1d'u8, 0x3d'u8, 0xf0'u8, 0xde'u8, 0xb3'u8,
    0x0b'u8, 0x72'u8, 0xa7'u8, 0x1c'u8, 0xef'u8, 0xd1'u8, 0x53'u8, 0x3e'u8,
    0x8f'u8, 0x33'u8, 0x26'u8, 0x5f'u8, 0xec'u8, 0x76'u8, 0x2a'u8, 0x49'u8,
    0x81'u8, 0x88'u8, 0xee'u8, 0x21'u8, 0xc4'u8, 0x1a'u8, 0xeb'u8, 0xd9'u8,
    0xc5'u8, 0x39'u8, 0x99'u8, 0xcd'u8, 0xad'u8, 0x31'u8, 0x8b'u8, 0x01'u8,
    0x18'u8, 0x23'u8, 0xdd'u8, 0x1f'u8, 0x4e'u8, 0x2d'u8, 0xf9'u8, 0x48'u8,
    0x4f'u8, 0xf2'u8, 0x65'u8, 0x8e'u8, 0x78'u8, 0x5c'u8, 0x58'u8, 0x19'u8,
    0x8d'u8, 0xe5'u8, 0x98'u8, 0x57'u8, 0x67'u8, 0x7f'u8, 0x05'u8, 0x64'u8,
    0xaf'u8, 0x63'u8, 0xb6'u8, 0xfe'u8, 0xf5'u8, 0xb7'u8, 0x3c'u8, 0xa5'u8,
    0xce'u8, 0xe9'u8, 0x68'u8, 0x44'u8, 0xe0'u8, 0x4d'u8, 0x43'u8, 0x69'u8,
    0x29'u8, 0x2e'u8, 0xac'u8, 0x15'u8, 0x59'u8, 0xa8'u8, 0x0a'u8, 0x9e'u8,
    0x6e'u8, 0x47'u8, 0xdf'u8, 0x34'u8, 0x35'u8, 0x6a'u8, 0xcf'u8, 0xdc'u8,
    0x22'u8, 0xc9'u8, 0xc0'u8, 0x9b'u8, 0x89'u8, 0xd4'u8, 0xed'u8, 0xab'u8,
    0x12'u8, 0xa2'u8, 0x0d'u8, 0x52'u8, 0xbb'u8, 0x02'u8, 0x2f'u8, 0xa9'u8,
    0xd7'u8, 0x61'u8, 0x1e'u8, 0xb4'u8, 0x50'u8, 0x04'u8, 0xf6'u8, 0xc2'u8,
    0x16'u8, 0x25'u8, 0x86'u8, 0x56'u8, 0x55'u8, 0x09'u8, 0xbe'u8, 0x91'u8
  ]
]

# -----------------------------------------------------------------------------
# Basic helpers

proc store32lAt(dst: var openArray[byte], off: int, src: uint32) {.inline.} =
  dst[off + 0] = byte(src)
  dst[off + 1] = byte(src shr  8)
  dst[off + 2] = byte(src shr 16)
  dst[off + 3] = byte(src shr 24)

proc load32lAt(src: openArray[byte], off: int): uint32 {.inline.} =
  uint32(src[off + 0])        or
  (uint32(src[off + 1]) shl  8) or
  (uint32(src[off + 2]) shl 16) or
  (uint32(src[off + 3]) shl 24)

# -----------------------------------------------------------------------------
# Field arithmetic

proc gfMult(a, b: byte, p: uint32): byte =
  ## returns a·b in GF(2^8)/p
  var B: array[2, uint32] = [0'u32, uint32(b)]
  let P: array[2, uint32] = [0'u32, p]

  var temp: uint32
  var aa = a
  for _ in 0 ..< 7:
    temp = temp xor B[aa and 1]
    aa = aa shr 1
    B[1] = P[B[1] shr 7] xor (B[1] shl 1)

  temp = temp xor B[aa and 1]
  return byte(temp)

proc mdsColumnMult(input: byte, col: int): uint32 {.inline.} =
  ## calculates y[col] where [y0 y1 y2 y3] = MDS · [x0]
  let
    mul01 = input
    mul5B = gfMult(input, 0x5B'u8, mdsPolynomial)
    mulEF = gfMult(input, 0xEF'u8, mdsPolynomial)

  case col
  of 0:
    uint32(mul01) or (uint32(mul5B) shl 8) or (uint32(mulEF) shl 16) or (uint32(mulEF) shl 24)
  of 1:
    uint32(mulEF) or (uint32(mulEF) shl 8) or (uint32(mul5B) shl 16) or (uint32(mul01) shl 24)
  of 2:
    uint32(mul5B) or (uint32(mulEF) shl 8) or (uint32(mul01) shl 16) or (uint32(mulEF) shl 24)
  of 3:
    uint32(mul5B) or (uint32(mul01) shl 8) or (uint32(mulEF) shl 16) or (uint32(mul5B) shl 24)
  else:
    raise newException(ValueError, "Invalid column index")

# -----------------------------------------------------------------------------
# Key-dependent functions

template F1(x: untyped): untyped =
  (c.s[0][byte(x)] xor c.s[1][byte(x shr 8)] xor c.s[2][byte(x shr 16)] xor c.s[3][byte(x shr 24)])

template F2(x: untyped): untyped =
  (c.s[1][byte(x)] xor c.s[2][byte(x shr 8)] xor c.s[3][byte(x shr 16)] xor c.s[0][byte(x shr 24)])

proc h(input, key: openArray[byte], offset: int): uint32 =
  ## implements the S-box generation function. See [TWOFISH] 4.3.5
  var y0 = input[0]
  var y1 = input[1]
  var y2 = input[2]
  var y3 = input[3]

  let keyLenDiv8 = key.len div 8
  if keyLenDiv8 == 4:
    y0 = sbox[1][y0] xor key[4*(6+offset)+0]
    y1 = sbox[0][y1] xor key[4*(6+offset)+1]
    y2 = sbox[0][y2] xor key[4*(6+offset)+2]
    y3 = sbox[1][y3] xor key[4*(6+offset)+3]
  if keyLenDiv8 >= 3:
    y0 = sbox[1][y0] xor key[4*(4+offset)+0]
    y1 = sbox[1][y1] xor key[4*(4+offset)+1]
    y2 = sbox[0][y2] xor key[4*(4+offset)+2]
    y3 = sbox[0][y3] xor key[4*(4+offset)+3]
  if keyLenDiv8 >= 2:
    y0 = sbox[1][sbox[0][sbox[0][y0] xor key[4*(2+offset)+0]] xor key[4*(0+offset)+0]]
    y1 = sbox[0][sbox[0][sbox[1][y1] xor key[4*(2+offset)+1]] xor key[4*(0+offset)+1]]
    y2 = sbox[1][sbox[1][sbox[0][y2] xor key[4*(2+offset)+2]] xor key[4*(0+offset)+2]]
    y3 = sbox[0][sbox[1][sbox[1][y3] xor key[4*(2+offset)+3]] xor key[4*(0+offset)+3]]

  mdsColumnMult(y0, 0) xor mdsColumnMult(y1, 1) xor mdsColumnMult(y2, 2) xor mdsColumnMult(y3, 3)

# -----------------------------------------------------------------------------
# Round templates (fully unrolled at compile-time)

template ENC_ROUND(idx: static[int]; ia, ib, ic, id: untyped) =
  block:
    const base = 8 + idx * 4
    var t1, t2: uint32
    t2 = F2(ib)
    t1 = F1(ia) + t2
    ic = rotateRightBits(ic xor (t1 + c.k[base + 0]), 1)
    id = rotateLeftBits(id, 1) xor (t2 + t1 + c.k[base + 1])
    t2 = F2(id)
    t1 = F1(ic) + t2
    ia = rotateRightBits(ia xor (t1 + c.k[base + 2]), 1)
    ib = rotateLeftBits(ib, 1) xor (t2 + t1 + c.k[base + 3])

template DEC_ROUND(idx: static[int]; ia, ib, ic, id: untyped) =
  block:
    const base = 4 + idx * 4
    var t1, t2: uint32
    t2 = F2(id)
    t1 = F1(ic) + t2
    ia = rotateLeftBits(ia, 1) xor (t1 + c.k[base + 2])
    ib = rotateRightBits(ib xor (t2 + t1 + c.k[base + 3]), 1)
    t2 = F2(ib)
    t1 = F1(ia) + t2
    ic = rotateLeftBits(ic, 1) xor (t1 + c.k[base + 0])
    id = rotateRightBits(id xor (t2 + t1 + c.k[base + 1]), 1)

# -----------------------------------------------------------------------------
# Core cipher operations

proc twofishEncrypt*(c: TwoFishCtx, src: openArray[byte], dst: var openArray[byte]) =
  var ia = load32lAt(src,  0) xor c.k[0]
  var ib = load32lAt(src,  4) xor c.k[1]
  var ic = load32lAt(src,  8) xor c.k[2]
  var id = load32lAt(src, 12) xor c.k[3]

  ENC_ROUND(0, ia, ib, ic, id)
  ENC_ROUND(1, ia, ib, ic, id)
  ENC_ROUND(2, ia, ib, ic, id)
  ENC_ROUND(3, ia, ib, ic, id)
  ENC_ROUND(4, ia, ib, ic, id)
  ENC_ROUND(5, ia, ib, ic, id)
  ENC_ROUND(6, ia, ib, ic, id)
  ENC_ROUND(7, ia, ib, ic, id)

  store32lAt(dst,  0, ic xor c.k[4])
  store32lAt(dst,  4, id xor c.k[5])
  store32lAt(dst,  8, ia xor c.k[6])
  store32lAt(dst, 12, ib xor c.k[7])

proc twofishDecrypt*(c: TwoFishCtx, src: openArray[byte], dst: var openArray[byte]) =
  let ta = load32lAt(src,  0)
  let tb = load32lAt(src,  4)
  let tc = load32lAt(src,  8)
  let td = load32lAt(src, 12)

  var ia = tc xor c.k[6]
  var ib = td xor c.k[7]
  var ic = ta xor c.k[4]
  var id = tb xor c.k[5]

  DEC_ROUND(8, ia, ib, ic, id)
  DEC_ROUND(7, ia, ib, ic, id)
  DEC_ROUND(6, ia, ib, ic, id)
  DEC_ROUND(5, ia, ib, ic, id)
  DEC_ROUND(4, ia, ib, ic, id)
  DEC_ROUND(3, ia, ib, ic, id)
  DEC_ROUND(2, ia, ib, ic, id)
  DEC_ROUND(1, ia, ib, ic, id)

  store32lAt(dst,  0, ia xor c.k[0])
  store32lAt(dst,  4, ib xor c.k[1])
  store32lAt(dst,  8, ic xor c.k[2])
  store32lAt(dst, 12, id xor c.k[3])

# -----------------------------------------------------------------------------
# Key schedule setup

proc init*(key: openArray[byte], s: var array[4, array[256, uint32]],
           k: var array[40, uint32]) =
  ## initialize key and sboxes
  let keylen = len(key)

  if keylen != 16 and keylen != 24 and keylen != 32:
    raise newException(KeySizeError, "Invalid key length")

  let kBits = keylen div 8

  # NOTE: create the S[..] words
  var Sbytes: array[16, byte]
  for i in 0 ..< kBits:
    for j, rsRow in rs:
      for z, rsVal in rsRow:
        Sbytes[4*i+j] = Sbytes[4*i+j] xor gfMult(key[8*i+z], rsVal, rsPolynomial)

  # NOTE: calculate subkeys
  var tmp: array[4, byte]
  for i in 0 ..< 20:
    tmp[0] = byte(2 * i)
    tmp[1] = tmp[0]
    tmp[2] = tmp[0]
    tmp[3] = tmp[0]
    let A = h(tmp, key, 0)

    tmp[0] = byte(2 * i + 1)
    tmp[1] = tmp[0]
    tmp[2] = tmp[0]
    tmp[3] = tmp[0]
    let B = rotateLeftBits(h(tmp, key, 1), 8)

    k[2*i] = A + B
    k[2*i+1] = rotateLeftBits(2*B + A, 9)

  # NOTE: calculate sboxes
  case kBits
  of 2:
    for i in 0 ..< 256:
      s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][i] xor Sbytes[0]] xor Sbytes[4]], 0)
      s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][i] xor Sbytes[1]] xor Sbytes[5]], 1)
      s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][i] xor Sbytes[2]] xor Sbytes[6]], 2)
      s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][i] xor Sbytes[3]] xor Sbytes[7]], 3)
  of 3:
    for i in 0 ..< 256:
      s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][sbox[1][i] xor Sbytes[0]] xor Sbytes[4]] xor Sbytes[ 8]], 0)
      s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][sbox[1][i] xor Sbytes[1]] xor Sbytes[5]] xor Sbytes[ 9]], 1)
      s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][sbox[0][i] xor Sbytes[2]] xor Sbytes[6]] xor Sbytes[10]], 2)
      s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][sbox[0][i] xor Sbytes[3]] xor Sbytes[7]] xor Sbytes[11]], 3)
  else:
    for i in 0 ..< 256:
      s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][sbox[1][sbox[1][i] xor Sbytes[0]] xor Sbytes[4]] xor Sbytes[ 8]] xor Sbytes[12]], 0)
      s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][sbox[1][sbox[0][i] xor Sbytes[1]] xor Sbytes[5]] xor Sbytes[ 9]] xor Sbytes[13]], 1)
      s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][sbox[0][sbox[0][i] xor Sbytes[2]] xor Sbytes[6]] xor Sbytes[10]] xor Sbytes[14]], 2)
      s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][sbox[0][sbox[1][i] xor Sbytes[3]] xor Sbytes[7]] xor Sbytes[11]] xor Sbytes[15]], 3)
