import std/bitops

# NOTE: ported to Nim from https://cs.opensource.google/go/x/crypto/+/master:twofish/twofish.go

const BlockSize = 16
const mdsPolynomial: uint32 = 0x169'u32  # x^8 + x^6 + x^5 + x^3 + 1, see [TWOFISH] 4.2
const rsPolynomial:  uint32 = 0x14d'u32  # x^8 + x^6 + x^3 + x^2 + 1, see [TWOFISH] 4.3

type KeySizeError = object of ValueError

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

###################################################################################

proc store32l(dst: var openArray[byte], index: int, src: uint32) =
  dst[index + 0] = byte(src)
  dst[index + 1] = byte(src shr  8)
  dst[index + 2] = byte(src shr 16)
  dst[index + 3] = byte(src shr 24)


proc load32l(src: openArray[byte]): uint32 =
  result = uint32(src[0])        or
           uint32(src[1]) shl  8 or
           uint32(src[2]) shl 16 or
           uint32(src[3]) shl 24

###################################################################################

proc gfMult(a, b: byte, p: uint32): byte =
  ## returns a·b in GF(2^8)/p
  var B: array[2, uint32] = [0'u32, uint32(b)]
  let P: array[2, uint32] = [0'u32, p]
  
  var temp: uint32
  var aa = a

  # NOTE: branchless GF multiplier
  for i in 0 ..< 7:
    temp = temp xor B[aa and 1]
    aa = aa shr 1
    B[1] = P[B[1] shr 7] xor (B[1] shl 1)

  temp = temp xor B[aa and 1]
  return byte(temp)


proc mdsColumnMult(input: byte, col: int): uint32 =
  ## calculates y[col] where [y0 y1 y2 y3] = MDS · [x0]
  let
    mul01 = input
    mul5B = gfMult(input, 0x5B'u8, mdsPolynomial)
    mulEF = gfMult(input, 0xEF'u8, mdsPolynomial)

  case col
  of 0:
    return uint32(mul01) or (uint32(mul5B) shl 8) or (uint32(mulEF) shl 16) or (uint32(mulEF) shl 24)
  of 1:
    return uint32(mulEF) or (uint32(mulEF) shl 8) or (uint32(mul5B) shl 16) or (uint32(mul01) shl 24)
  of 2:
    return uint32(mul5B) or (uint32(mulEF) shl 8) or (uint32(mul01) shl 16) or (uint32(mulEF) shl 24)
  of 3:
    return uint32(mul5B) or (uint32(mul01) shl 8) or (uint32(mulEF) shl 16) or (uint32(mul5B) shl 24)
  else:
    raise newException(ValueError, "Invalid column index")


proc h(input, key: openArray[byte], offset: int): uint32 =
  ## implements the S-box generation function. See [TWOFISH] 4.3.5
  var y: array[4, byte]
  for x in 0 ..< y.len:
    y[x] = input[x]

  let keyLenDiv8 = key.len div 8
  if keyLenDiv8 == 4:
    y[0] = sbox[1][y[0]] xor key[4*(6+offset)+0]
    y[1] = sbox[0][y[1]] xor key[4*(6+offset)+1]
    y[2] = sbox[0][y[2]] xor key[4*(6+offset)+2]
    y[3] = sbox[1][y[3]] xor key[4*(6+offset)+3]
  if keyLenDiv8 >= 3:
    y[0] = sbox[1][y[0]] xor key[4*(4+offset)+0]
    y[1] = sbox[1][y[1]] xor key[4*(4+offset)+1]
    y[2] = sbox[0][y[2]] xor key[4*(4+offset)+2]
    y[3] = sbox[0][y[3]] xor key[4*(4+offset)+3]
  if keyLenDiv8 >= 2:
    y[0] = sbox[1][sbox[0][sbox[0][y[0]] xor key[4*(2+offset)+0]] xor key[4*(0+offset)+0]]
    y[1] = sbox[0][sbox[0][sbox[1][y[1]] xor key[4*(2+offset)+1]] xor key[4*(0+offset)+1]]
    y[2] = sbox[1][sbox[1][sbox[0][y[2]] xor key[4*(2+offset)+2]] xor key[4*(0+offset)+2]]
    y[3] = sbox[0][sbox[1][sbox[1][y[3]] xor key[4*(2+offset)+3]] xor key[4*(0+offset)+3]]
  
  # NOTE: [y0 y1 y2 y3] = MDS . [x0 x1 x2 x3]
  var mdsMult: uint32
  for i in 0 ..< y.len:
    mdsMult = mdsMult xor mdsColumnMult(y[i], i)
  return mdsMult


proc twofishEncrypt*(c: TwoFishCtx, src: openArray[byte], dst: var openArray[byte]) =
  let
    S1 = c.s[0]
    S2 = c.s[1]
    S3 = c.s[2]
    S4 = c.s[3]

  # NOTE: load input
  var
    ia = load32l(src[ 0 ..<  4])
    ib = load32l(src[ 4 ..<  8])
    ic = load32l(src[ 8 ..< 12])
    id = load32l(src[12 ..< 16])

  # NOTE: pre-whitening
  ia = ia xor c.k[0]
  ib = ib xor c.k[1]
  ic = ic xor c.k[2]
  id = id xor c.k[3]

  var t1, t2: uint32
  for i in 0 ..< 8:
    let k = c.k[8+i*4 ..< 12+i*4]
    t2 =  S2[byte(ib)] xor S3[byte(ib shr 8)] xor S4[byte(ib shr 16)] xor S1[byte(ib shr 24)]
    t1 = (S1[byte(ia)] xor S2[byte(ia shr 8)] xor S3[byte(ia shr 16)] xor S4[byte(ia shr 24)]) + t2
    ic = rotateRightBits(ic xor (t1 + k[0]), 1)
    id = rotateLeftBits(id, 1) xor (t2 + t1 + k[1])

    t2 =  S2[byte(id)] xor S3[byte(id shr 8)] xor S4[byte(id shr 16)] xor S1[byte(id shr 24)]
    t1 = (S1[byte(ic)] xor S2[byte(ic shr 8)] xor S3[byte(ic shr 16)] xor S4[byte(ic shr 24)]) + t2
    ia = rotateRightBits(ia xor (t1 + k[2]), 1)
    ib = rotateLeftBits(ib, 1) xor (t2 + t1 + k[3])

  # NOTE: output with "undo last swap"
  let
    ta = ic xor c.k[4]
    tb = id xor c.k[5]
    tc = ia xor c.k[6]
    td = ib xor c.k[7]

  store32l(dst,  0, ta)
  store32l(dst,  4, tb)
  store32l(dst,  8, tc)
  store32l(dst, 12, td)


proc twofishDecrypt*(c: TwoFishCtx, src: openArray[byte], dst: var openArray[byte]) =
  let
    S1 = c.s[0]
    S2 = c.s[1]
    S3 = c.s[2]
    S4 = c.s[3]

  # NOTE: load input
  var
    ta = load32l(src[ 0 ..<  4])
    tb = load32l(src[ 4 ..<  8])
    tc = load32l(src[ 8 ..< 12])
    td = load32l(src[12 ..< 16])

  # NOTE: undo final swap
  var
    ia = tc xor c.k[6]
    ib = td xor c.k[7]
    ic = ta xor c.k[4]
    id = tb xor c.k[5]

  var t1, t2: uint32
  for i in countdown(8, 1, 1):
    let k = c.k[4+i*4 ..< 8+i*4]
    t2 =  S2[byte(id)] xor S3[byte(id shr 8)] xor S4[byte(id shr 16)] xor S1[byte(id shr 24)]
    t1 = (S1[byte(ic)] xor S2[byte(ic shr 8)] xor S3[byte(ic shr 16)] xor S4[byte(ic shr 24)]) + t2
    ia = rotateLeftBits(ia, 1) xor (t1 + k[2])
    ib = rotateRightBits(ib xor (t2 + t1 + k[3]), 1)

    t2 =  S2[byte(ib)] xor S3[byte(ib shr 8)] xor S4[byte(ib shr 16)] xor S1[byte(ib shr 24)]
    t1 = (S1[byte(ia)] xor S2[byte(ia shr 8)] xor S3[byte(ia shr 16)] xor S4[byte(ia shr 24)]) + t2
    ic = rotateLeftBits(ic, 1) xor (t1 + k[0])
    id = rotateRightBits(id xor (t2 + t1 + k[1]), 1)

  # NOTE: undo pre-whitening
  ia = ia xor c.k[0]
  ib = ib xor c.k[1]
  ic = ic xor c.k[2]
  id = id xor c.k[3]

  store32l(dst,  0, ia)
  store32l(dst,  4, ib)
  store32l(dst,  8, ic)
  store32l(dst, 12, id)

###################################################################################

proc init*(key: openArray[byte], s: var array[4,  array[256, uint32]], k: var array[40, uint32]) =
  ## initialize key and sboxes
  let keylen = len(key)

  if keylen != 16 and keylen != 24 and keylen != 32:
    raise newException(KeySizeError, "Invalid key length")

  let kBits = keylen div 8

  # NOTE: create the S[..] words
  var S: array[4 * 4, byte]
  for i in 0 ..< kBits:
    for j, rsRow in rs:
      for k, rsVal in rsRow:
        S[4*i+j] = S[4*i+j] xor gfMult(key[8*i+k], rsVal, rsPolynomial)
  
  # NOTE: calculate subkeys
  var A, B: uint32
  var tmp: array[4, byte]
  for i in 0 ..< 20:
    for j in 0 ..< tmp.len:
      tmp[j] = byte(2 * i)
    A = h(tmp, key, 0)

    for j in 0 ..< tmp.len:
      tmp[j] = byte(2*i + 1)
    B = rotateLeftBits(h(tmp, key, 1), 8)

    k[2*i] = A + B
    k[2*i+1] = rotateLeftBits(2*B+A, 9)
  
  # NOTE: calculate sboxes
  case kBits:
  of 2:
    for i in 0 ..< 256:
      s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][i] xor S[0]] xor S[4]], 0)
      s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][i] xor S[1]] xor S[5]], 1)
      s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][i] xor S[2]] xor S[6]], 2)
      s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][i] xor S[3]] xor S[7]], 3)
  of 3:
    for i in 0 ..< 256:
      s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][sbox[1][i] xor S[0]] xor S[4]] xor S[ 8]], 0)
      s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][sbox[1][i] xor S[1]] xor S[5]] xor S[ 9]], 1)
      s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][sbox[0][i] xor S[2]] xor S[6]] xor S[10]], 2)
      s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][sbox[0][i] xor S[3]] xor S[7]] xor S[11]], 3)
  else:
    for i in 0 ..< 256:
      s[0][i] = mdsColumnMult(sbox[1][sbox[0][sbox[0][sbox[1][sbox[1][i] xor S[0]] xor S[4]] xor S[ 8]] xor S[12]], 0)
      s[1][i] = mdsColumnMult(sbox[0][sbox[0][sbox[1][sbox[1][sbox[0][i] xor S[1]] xor S[5]] xor S[ 9]] xor S[13]], 1)
      s[2][i] = mdsColumnMult(sbox[1][sbox[1][sbox[0][sbox[0][sbox[0][i] xor S[2]] xor S[6]] xor S[10]] xor S[14]], 2)
      s[3][i] = mdsColumnMult(sbox[0][sbox[1][sbox[1][sbox[0][sbox[1][i] xor S[3]] xor S[7]] xor S[11]] xor S[15]], 3)
