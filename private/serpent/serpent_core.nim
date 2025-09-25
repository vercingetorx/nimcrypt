const
  serpentBlockSize* = 16
  serpentRounds* = 32
  phi = 0x9E3779B9'u32

type
  SerpentSchedule* = object
    subkeys*: array[serpentRounds + 1, array[4, uint32]]

# ---------------------------------------------------------------------------
# Basic bit operations

proc rol(x: uint32; n: int): uint32 {.inline.} =
  let s = n and 31
  if s == 0:
    result = x
  else:
    result = (x shl s) or (x shr (32 - s))

proc ror(x: uint32; n: int): uint32 {.inline.} =
  let s = n and 31
  if s == 0:
    result = x
  else:
    result = (x shr s) or (x shl (32 - s))

# ---------------------------------------------------------------------------
# S-box and inverse S-box round templates (direct translation of macros)

template RND00(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t05, t06, t07, t08, t09, t11, t12, t13, t14, t15, t17: uint32
    t01 = b xor c
    t02 = a or d
    t03 = a xor b
    z = t02 xor t01
    t05 = c or z
    t06 = a xor d
    t07 = b or c
    t08 = d and t05
    t09 = t03 and t07
    y = t09 xor t08
    t11 = t09 and y
    t12 = c xor d
    t13 = t07 xor t11
    t14 = b and t06
    t15 = t06 xor t13
    w = not t15
    t17 = w xor t14
    x = t12 xor t17

template InvRND00(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t08, t09, t10, t12, t13, t14, t15, t17, t18: uint32
    t01 = c xor d
    t02 = a or b
    t03 = b or c
    t04 = c and t01
    t05 = t02 xor t01
    t06 = a or t04
    y = not t05
    t08 = b xor d
    t09 = t03 and t08
    t10 = d or y
    x = t09 xor t06
    t12 = a or t05
    t13 = x xor t12
    t14 = t03 xor t10
    t15 = a xor c
    z = t14 xor t13
    t17 = t05 and t13
    t18 = t14 or t17
    w = t15 xor t18

template RND01(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t07, t08, t10, t11, t12, t13, t16, t17: uint32
    t01 = a or d
    t02 = c xor d
    t03 = not b
    t04 = a xor c
    t05 = a or t03
    t06 = d and t04
    t07 = t01 and t02
    t08 = b or t06
    y = t02 xor t05
    t10 = t07 xor t08
    t11 = t01 xor t10
    t12 = y xor t11
    t13 = b and d
    z = not t10
    x = t13 xor t12
    t16 = t10 or x
    t17 = t05 and t16
    w = c xor t17

template InvRND01(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t14, t15, t17: uint32
    t01 = a xor b
    t02 = b or d
    t03 = a and c
    t04 = c xor t02
    t05 = a or t04
    t06 = t01 and t05
    t07 = d or t03
    t08 = b xor t06
    t09 = t07 xor t06
    t10 = t04 or t03
    t11 = d and t08
    y = not t09
    x = t10 xor t11
    t14 = a or y
    t15 = t06 xor x
    z = t01 xor t04
    t17 = c xor t15
    w = t14 xor t17

template RND02(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t05, t06, t07, t08, t09, t10, t12, t13, t14: uint32
    t01 = a or c
    t02 = a xor b
    t03 = d xor t01
    w = t02 xor t03
    t05 = c xor w
    t06 = b xor t05
    t07 = b or t05
    t08 = t01 and t06
    t09 = t03 xor t07
    t10 = t02 or t09
    x = t10 xor t08
    t12 = a or d
    t13 = t09 xor x
    t14 = b xor t13
    z = not t09
    y = t12 xor t14

template InvRND02(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t06, t07, t08, t09, t10, t11, t12, t15, t16, t17: uint32
    t01 = a xor d
    t02 = c xor d
    t03 = a and c
    t04 = b or t02
    w = t01 xor t04
    t06 = a or c
    t07 = d or w
    t08 = not d
    t09 = b and t06
    t10 = t08 or t03
    t11 = b and t07
    t12 = t06 and t02
    z = t09 xor t10
    x = t12 xor t11
    t15 = c and z
    t16 = w xor x
    t17 = t10 xor t15
    y = t16 xor t17

template RND03(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t13, t14, t15: uint32
    t01 = a xor c
    t02 = a or d
    t03 = a and d
    t04 = t01 and t02
    t05 = b or t03
    t06 = a and b
    t07 = d xor t04
    t08 = c or t06
    t09 = b xor t07
    t10 = d and t05
    t11 = t02 xor t10
    z = t08 xor t09
    t13 = d or z
    t14 = a or t07
    t15 = b and t13
    y = t08 xor t11
    w = t14 xor t15
    x = t05 xor t04

template InvRND03(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t07, t09, t11, t12, t13, t14, t16: uint32
    t01 = c or d
    t02 = a or d
    t03 = c xor t02
    t04 = b xor t02
    t05 = a xor d
    t06 = t04 and t03
    t07 = b and t01
    y = t05 xor t06
    t09 = a xor t03
    w = t07 xor t03
    t11 = w or t05
    t12 = t09 and t11
    t13 = a and y
    t14 = t01 xor t05
    x = b xor t12
    t16 = b or t13
    z = t14 xor t16

template RND04(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t08, t09, t10, t11, t12, t13, t14, t15, t16: uint32
    t01 = a or b
    t02 = b or c
    t03 = a xor t02
    t04 = b xor d
    t05 = d or t03
    t06 = d and t01
    z = t03 xor t06
    t08 = z and t04
    t09 = t04 and t05
    t10 = c xor t06
    t11 = b and c
    t12 = t04 xor t08
    t13 = t11 or t03
    t14 = t10 xor t09
    t15 = a and t05
    t16 = t11 or t12
    y = t13 xor t08
    x = t15 xor t16
    w = not t14

template InvRND04(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t07, t09, t10, t11, t12, t13, t15: uint32
    t01 = b or d
    t02 = c or d
    t03 = a and t01
    t04 = b xor t02
    t05 = c xor d
    t06 = not t03
    t07 = a and t04
    x = t05 xor t07
    t09 = x or t06
    t10 = a xor t07
    t11 = t01 xor t09
    t12 = d xor t04
    t13 = c or t10
    z = t03 xor t12
    t15 = a xor t04
    y = t11 xor t13
    w = t15 xor t09

template RND05(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t07, t08, t09, t10, t11, t12, t13, t14: uint32
    t01 = b xor d
    t02 = b or d
    t03 = a and t01
    t04 = c xor t02
    t05 = t03 xor t04
    w = not t05
    t07 = a xor t01
    t08 = d or w
    t09 = b or t05
    t10 = d xor t08
    t11 = b or t07
    t12 = t03 or w
    t13 = t07 or t10
    t14 = t01 xor t11
    y = t09 xor t13
    x = t07 xor t08
    z = t12 xor t14

template InvRND05(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t07, t08, t09, t10, t12, t13, t15, t16: uint32
    t01 = a and d
    t02 = c xor t01
    t03 = a xor d
    t04 = b and t02
    t05 = a and c
    w = t03 xor t04
    t07 = a and w
    t08 = t01 xor w
    t09 = b or t05
    t10 = not b
    x = t08 xor t09
    t12 = t10 or t07
    t13 = w or x
    z = t02 xor t12
    t15 = t02 xor t13
    t16 = b xor d
    y = t16 xor t15

template RND06(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t07, t08, t09, t10, t11, t12, t13, t15, t17, t18: uint32
    t01 = a and d
    t02 = b xor c
    t03 = a xor d
    t04 = t01 xor t02
    t05 = b or c
    x = not t04
    t07 = t03 and t05
    t08 = b and x
    t09 = a or c
    t10 = t07 xor t08
    t11 = b or d
    t12 = c xor t11
    t13 = t09 xor t10
    y = not t13
    t15 = x and t03
    z = t12 xor t07
    t17 = a xor b
    t18 = y xor t15
    w = t17 xor t18

template InvRND06(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t07, t08, t09, t12, t13, t14, t15, t16, t17: uint32
    t01 = a xor c
    t02 = not c
    t03 = b and t01
    t04 = b or t02
    t05 = d or t03
    t06 = b xor d
    t07 = a and t04
    t08 = a or t02
    t09 = t07 xor t05
    x = t06 xor t08
    w = not t09
    t12 = b and w
    t13 = t01 and t05
    t14 = t01 xor t12
    t15 = t07 xor t13
    t16 = d or t02
    t17 = a xor x
    z = t17 xor t15
    y = t16 xor t14

template RND07(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t05, t06, t08, t09, t10, t11, t13, t14, t15, t16, t17: uint32
    t01 = a and c
    t02 = not d
    t03 = a and t02
    t04 = b or t01
    t05 = a and b
    t06 = c xor t04
    z = t03 xor t06
    t08 = c or z
    t09 = d or t05
    t10 = a xor t08
    t11 = t04 and z
    x = t09 xor t10
    t13 = b xor x
    t14 = t01 xor x
    t15 = c xor t05
    t16 = t11 or t13
    t17 = t02 or t14
    w = t15 xor t17
    y = a xor t16

template InvRND07(a, b, c, d, w, x, y, z: untyped) =
  block:
    var t01, t02, t03, t04, t06, t07, t08, t09, t10, t11, t13, t14, t15, t16: uint32
    t01 = a and b
    t02 = a or b
    t03 = c or t01
    t04 = d and t02
    z = t03 xor t04
    t06 = b xor t04
    t07 = d xor z
    t08 = not t07
    t09 = t06 or t08
    t10 = b xor d
    t11 = a or d
    x = a xor t09
    t13 = c xor t06
    t14 = c and t11
    t15 = d or x
    t16 = t01 or t10
    w = t13 xor t15
    y = t14 xor t16

template RND08(a, b, c, d, e, f, g, h: untyped) =
  RND00(a, b, c, d, e, f, g, h)

template RND09(a, b, c, d, e, f, g, h: untyped) =
  RND01(a, b, c, d, e, f, g, h)

template RND10(a, b, c, d, e, f, g, h: untyped) =
  RND02(a, b, c, d, e, f, g, h)

template RND11(a, b, c, d, e, f, g, h: untyped) =
  RND03(a, b, c, d, e, f, g, h)

template RND12(a, b, c, d, e, f, g, h: untyped) =
  RND04(a, b, c, d, e, f, g, h)

template RND13(a, b, c, d, e, f, g, h: untyped) =
  RND05(a, b, c, d, e, f, g, h)

template RND14(a, b, c, d, e, f, g, h: untyped) =
  RND06(a, b, c, d, e, f, g, h)

template RND15(a, b, c, d, e, f, g, h: untyped) =
  RND07(a, b, c, d, e, f, g, h)

template RND16(a, b, c, d, e, f, g, h: untyped) =
  RND00(a, b, c, d, e, f, g, h)

template RND17(a, b, c, d, e, f, g, h: untyped) =
  RND01(a, b, c, d, e, f, g, h)

template RND18(a, b, c, d, e, f, g, h: untyped) =
  RND02(a, b, c, d, e, f, g, h)

template RND19(a, b, c, d, e, f, g, h: untyped) =
  RND03(a, b, c, d, e, f, g, h)

template RND20(a, b, c, d, e, f, g, h: untyped) =
  RND04(a, b, c, d, e, f, g, h)

template RND21(a, b, c, d, e, f, g, h: untyped) =
  RND05(a, b, c, d, e, f, g, h)

template RND22(a, b, c, d, e, f, g, h: untyped) =
  RND06(a, b, c, d, e, f, g, h)

template RND23(a, b, c, d, e, f, g, h: untyped) =
  RND07(a, b, c, d, e, f, g, h)

template RND24(a, b, c, d, e, f, g, h: untyped) =
  RND00(a, b, c, d, e, f, g, h)

template RND25(a, b, c, d, e, f, g, h: untyped) =
  RND01(a, b, c, d, e, f, g, h)

template RND26(a, b, c, d, e, f, g, h: untyped) =
  RND02(a, b, c, d, e, f, g, h)

template RND27(a, b, c, d, e, f, g, h: untyped) =
  RND03(a, b, c, d, e, f, g, h)

template RND28(a, b, c, d, e, f, g, h: untyped) =
  RND04(a, b, c, d, e, f, g, h)

template RND29(a, b, c, d, e, f, g, h: untyped) =
  RND05(a, b, c, d, e, f, g, h)

template RND30(a, b, c, d, e, f, g, h: untyped) =
  RND06(a, b, c, d, e, f, g, h)

template RND31(a, b, c, d, e, f, g, h: untyped) =
  RND07(a, b, c, d, e, f, g, h)

# Inverse round aliases

template InvRND08(a, b, c, d, e, f, g, h: untyped) =
  InvRND00(a, b, c, d, e, f, g, h)

template InvRND09(a, b, c, d, e, f, g, h: untyped) =
  InvRND01(a, b, c, d, e, f, g, h)

template InvRND10(a, b, c, d, e, f, g, h: untyped) =
  InvRND02(a, b, c, d, e, f, g, h)

template InvRND11(a, b, c, d, e, f, g, h: untyped) =
  InvRND03(a, b, c, d, e, f, g, h)

template InvRND12(a, b, c, d, e, f, g, h: untyped) =
  InvRND04(a, b, c, d, e, f, g, h)

template InvRND13(a, b, c, d, e, f, g, h: untyped) =
  InvRND05(a, b, c, d, e, f, g, h)

template InvRND14(a, b, c, d, e, f, g, h: untyped) =
  InvRND06(a, b, c, d, e, f, g, h)

template InvRND15(a, b, c, d, e, f, g, h: untyped) =
  InvRND07(a, b, c, d, e, f, g, h)

template InvRND16(a, b, c, d, e, f, g, h: untyped) =
  InvRND00(a, b, c, d, e, f, g, h)

template InvRND17(a, b, c, d, e, f, g, h: untyped) =
  InvRND01(a, b, c, d, e, f, g, h)

template InvRND18(a, b, c, d, e, f, g, h: untyped) =
  InvRND02(a, b, c, d, e, f, g, h)

template InvRND19(a, b, c, d, e, f, g, h: untyped) =
  InvRND03(a, b, c, d, e, f, g, h)

template InvRND20(a, b, c, d, e, f, g, h: untyped) =
  InvRND04(a, b, c, d, e, f, g, h)

template InvRND21(a, b, c, d, e, f, g, h: untyped) =
  InvRND05(a, b, c, d, e, f, g, h)

template InvRND22(a, b, c, d, e, f, g, h: untyped) =
  InvRND06(a, b, c, d, e, f, g, h)

template InvRND23(a, b, c, d, e, f, g, h: untyped) =
  InvRND07(a, b, c, d, e, f, g, h)

template InvRND24(a, b, c, d, e, f, g, h: untyped) =
  InvRND00(a, b, c, d, e, f, g, h)

template InvRND25(a, b, c, d, e, f, g, h: untyped) =
  InvRND01(a, b, c, d, e, f, g, h)

template InvRND26(a, b, c, d, e, f, g, h: untyped) =
  InvRND02(a, b, c, d, e, f, g, h)

template InvRND27(a, b, c, d, e, f, g, h: untyped) =
  InvRND03(a, b, c, d, e, f, g, h)

template InvRND28(a, b, c, d, e, f, g, h: untyped) =
  InvRND04(a, b, c, d, e, f, g, h)

template InvRND29(a, b, c, d, e, f, g, h: untyped) =
  InvRND05(a, b, c, d, e, f, g, h)

template InvRND30(a, b, c, d, e, f, g, h: untyped) =
  InvRND06(a, b, c, d, e, f, g, h)

template InvRND31(a, b, c, d, e, f, g, h: untyped) =
  InvRND07(a, b, c, d, e, f, g, h)

# ---------------------------------------------------------------------------
# Linear transforms and key mixing

template transform(x0, x1, x2, x3, y0, y1, y2, y3: untyped) =
  block:
    y0 = rol(x0, 13)
    y2 = rol(x2, 3)
    y1 = x1 xor y0 xor y2
    y3 = x3 xor y2 xor (y0 shl 3)
    y1 = rol(y1, 1)
    y3 = rol(y3, 7)
    y0 = y0 xor y1 xor y3
    y2 = y2 xor y3 xor (y1 shl 7)
    y0 = rol(y0, 5)
    y2 = rol(y2, 22)


template inv_transform(x0, x1, x2, x3, y0, y1, y2, y3: untyped) =
  block:
    y2 = ror(x2, 22)
    y0 = ror(x0, 5)
    y2 = y2 xor x3 xor (x1 shl 7)
    y0 = y0 xor x1 xor x3
    y3 = ror(x3, 7)
    y1 = ror(x1, 1)
    y3 = y3 xor y2 xor (y0 shl 3)
    y1 = y1 xor y0 xor y2
    y2 = ror(y2, 3)
    y0 = ror(y0, 13)


template keying(x0, x1, x2, x3, subkey: untyped) =
  block:
    x0 = x0 xor subkey[0]
    x1 = x1 xor subkey[1]
    x2 = x2 xor subkey[2]
    x3 = x3 xor subkey[3]

# ---------------------------------------------------------------------------
# Block load/store helpers (match reference ordering)

proc loadBlock*(data: openArray[byte]): array[4, uint32] {.inline.} =
  assert data.len >= serpentBlockSize
  result[0] = (uint32(data[12]) shl 24) or (uint32(data[13]) shl 16) or (uint32(data[14]) shl 8) or uint32(data[15])
  result[1] = (uint32(data[8]) shl 24) or (uint32(data[9]) shl 16) or (uint32(data[10]) shl 8) or uint32(data[11])
  result[2] = (uint32(data[4]) shl 24) or (uint32(data[5]) shl 16) or (uint32(data[6]) shl 8) or uint32(data[7])
  result[3] = (uint32(data[0]) shl 24) or (uint32(data[1]) shl 16) or (uint32(data[2]) shl 8) or uint32(data[3])

proc storeBlock*(words: array[4, uint32]): array[16, byte] {.inline.} =
  result[0] = byte((words[3] shr 24) and 0xFF'u32)
  result[1] = byte((words[3] shr 16) and 0xFF'u32)
  result[2] = byte((words[3] shr 8) and 0xFF'u32)
  result[3] = byte(words[3] and 0xFF'u32)
  result[4] = byte((words[2] shr 24) and 0xFF'u32)
  result[5] = byte((words[2] shr 16) and 0xFF'u32)
  result[6] = byte((words[2] shr 8) and 0xFF'u32)
  result[7] = byte(words[2] and 0xFF'u32)
  result[8] = byte((words[1] shr 24) and 0xFF'u32)
  result[9] = byte((words[1] shr 16) and 0xFF'u32)
  result[10] = byte((words[1] shr 8) and 0xFF'u32)
  result[11] = byte(words[1] and 0xFF'u32)
  result[12] = byte((words[0] shr 24) and 0xFF'u32)
  result[13] = byte((words[0] shr 16) and 0xFF'u32)
  result[14] = byte((words[0] shr 8) and 0xFF'u32)
  result[15] = byte(words[0] and 0xFF'u32)

# ---------------------------------------------------------------------------
# Key schedule (faithful port of makeKey)

proc initSerpentSchedule*(key: openArray[byte]): SerpentSchedule =
  if key.len == 0 or key.len > 32:
    raise newException(ValueError, "Serpent key must be 1..32 bytes")

  var keyWords: array[8, uint32]
  var idx = key.len
  var wordIdx = 0
  while idx > 0 and wordIdx < keyWords.len:
    let chunk = min(4, idx)
    var value: uint32 = 0
    let base = idx - chunk
    for j in 0 ..< chunk:
      value = (value shl 8) or uint32(key[base + j])
    keyWords[wordIdx] = value
    idx -= chunk
    inc wordIdx
  while wordIdx < keyWords.len:
    keyWords[wordIdx] = 0
    inc wordIdx

  var w: array[132, uint32]
  var k: array[132, uint32]

  let keyBits = key.len * 8
  let fullWords = keyBits div 32
  for i in 0 ..< fullWords:
    w[i] = keyWords[i]
  if keyBits < 256:
    let bitIndex = keyBits mod 32
    let wordIndex = fullWords
    let baseWord = if wordIndex < keyWords.len: keyWords[wordIndex] else: 0'u32
    let mask = if bitIndex == 0: 0'u32 else: (1'u32 shl bitIndex) - 1'u32
    w[wordIndex] = (baseWord and mask) or (1'u32 shl bitIndex)
    for i in wordIndex + 1 ..< 8:
      w[i] = 0
  else:
    for i in fullWords ..< 8:
      w[i] = keyWords[i]

  for i in 8 ..< 16:
    let t = w[i - 8] xor w[i - 5] xor w[i - 3] xor w[i - 1] xor phi xor uint32(i - 8)
    w[i] = rol(t, 11)

  for i in 0 ..< 8:
    w[i] = w[i + 8]

  for i in 8 ..< 132:
    let t = w[i - 8] xor w[i - 5] xor w[i - 3] xor w[i - 1] xor phi xor uint32(i)
    w[i] = rol(t, 11)

  RND03(w[0], w[1], w[2], w[3], k[0], k[1], k[2], k[3])
  RND02(w[4], w[5], w[6], w[7], k[4], k[5], k[6], k[7])
  RND01(w[8], w[9], w[10], w[11], k[8], k[9], k[10], k[11])
  RND00(w[12], w[13], w[14], w[15], k[12], k[13], k[14], k[15])
  RND31(w[16], w[17], w[18], w[19], k[16], k[17], k[18], k[19])
  RND30(w[20], w[21], w[22], w[23], k[20], k[21], k[22], k[23])
  RND29(w[24], w[25], w[26], w[27], k[24], k[25], k[26], k[27])
  RND28(w[28], w[29], w[30], w[31], k[28], k[29], k[30], k[31])
  RND27(w[32], w[33], w[34], w[35], k[32], k[33], k[34], k[35])
  RND26(w[36], w[37], w[38], w[39], k[36], k[37], k[38], k[39])
  RND25(w[40], w[41], w[42], w[43], k[40], k[41], k[42], k[43])
  RND24(w[44], w[45], w[46], w[47], k[44], k[45], k[46], k[47])
  RND23(w[48], w[49], w[50], w[51], k[48], k[49], k[50], k[51])
  RND22(w[52], w[53], w[54], w[55], k[52], k[53], k[54], k[55])
  RND21(w[56], w[57], w[58], w[59], k[56], k[57], k[58], k[59])
  RND20(w[60], w[61], w[62], w[63], k[60], k[61], k[62], k[63])
  RND19(w[64], w[65], w[66], w[67], k[64], k[65], k[66], k[67])
  RND18(w[68], w[69], w[70], w[71], k[68], k[69], k[70], k[71])
  RND17(w[72], w[73], w[74], w[75], k[72], k[73], k[74], k[75])
  RND16(w[76], w[77], w[78], w[79], k[76], k[77], k[78], k[79])
  RND15(w[80], w[81], w[82], w[83], k[80], k[81], k[82], k[83])
  RND14(w[84], w[85], w[86], w[87], k[84], k[85], k[86], k[87])
  RND13(w[88], w[89], w[90], w[91], k[88], k[89], k[90], k[91])
  RND12(w[92], w[93], w[94], w[95], k[92], k[93], k[94], k[95])
  RND11(w[96], w[97], w[98], w[99], k[96], k[97], k[98], k[99])
  RND10(w[100], w[101], w[102], w[103], k[100], k[101], k[102], k[103])
  RND09(w[104], w[105], w[106], w[107], k[104], k[105], k[106], k[107])
  RND08(w[108], w[109], w[110], w[111], k[108], k[109], k[110], k[111])
  RND07(w[112], w[113], w[114], w[115], k[112], k[113], k[114], k[115])
  RND06(w[116], w[117], w[118], w[119], k[116], k[117], k[118], k[119])
  RND05(w[120], w[121], w[122], w[123], k[120], k[121], k[122], k[123])
  RND04(w[124], w[125], w[126], w[127], k[124], k[125], k[126], k[127])
  RND03(w[128], w[129], w[130], w[131], k[128], k[129], k[130], k[131])

  for i in 0 .. serpentRounds:
    for j in 0 .. 3:
      result.subkeys[i][j] = k[4 * i + j]

# ---------------------------------------------------------------------------
# Block cipher core (no structural changes from C reference)

proc encryptBlockWords*(ctx: SerpentSchedule; state: var array[4, uint32]) =
  var x0 = state[0]
  var x1 = state[1]
  var x2 = state[2]
  var x3 = state[3]
  var y0, y1, y2, y3: uint32

  keying(x0, x1, x2, x3, ctx.subkeys[0])
  RND00(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[1])
  RND01(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[2])
  RND02(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[3])
  RND03(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[4])
  RND04(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[5])
  RND05(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[6])
  RND06(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[7])
  RND07(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[8])
  RND08(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[9])
  RND09(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[10])
  RND10(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[11])
  RND11(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[12])
  RND12(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[13])
  RND13(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[14])
  RND14(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[15])
  RND15(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[16])
  RND16(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[17])
  RND17(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[18])
  RND18(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[19])
  RND19(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[20])
  RND20(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[21])
  RND21(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[22])
  RND22(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[23])
  RND23(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[24])
  RND24(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[25])
  RND25(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[26])
  RND26(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[27])
  RND27(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[28])
  RND28(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[29])
  RND29(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[30])
  RND30(x0, x1, x2, x3, y0, y1, y2, y3)
  transform(y0, y1, y2, y3, x0, x1, x2, x3)
  keying(x0, x1, x2, x3, ctx.subkeys[31])
  RND31(x0, x1, x2, x3, y0, y1, y2, y3)
  x0 = y0
  x1 = y1
  x2 = y2
  x3 = y3
  keying(x0, x1, x2, x3, ctx.subkeys[32])

  state[0] = x0
  state[1] = x1
  state[2] = x2
  state[3] = x3

proc decryptBlockWords*(ctx: SerpentSchedule; state: var array[4, uint32]) =
  var x0 = state[0]
  var x1 = state[1]
  var x2 = state[2]
  var x3 = state[3]
  var y0, y1, y2, y3: uint32

  keying(x0, x1, x2, x3, ctx.subkeys[32])
  InvRND31(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[31])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND30(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[30])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND29(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[29])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND28(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[28])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND27(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[27])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND26(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[26])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND25(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[25])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND24(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[24])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND23(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[23])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND22(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[22])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND21(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[21])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND20(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[20])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND19(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[19])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND18(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[18])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND17(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[17])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND16(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[16])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND15(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[15])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND14(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[14])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND13(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[13])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND12(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[12])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND11(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[11])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND10(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[10])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND09(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[9])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND08(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[8])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND07(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[7])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND06(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[6])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND05(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[5])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND04(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[4])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND03(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[3])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND02(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[2])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND01(x0, x1, x2, x3, y0, y1, y2, y3)
  keying(y0, y1, y2, y3, ctx.subkeys[1])
  inv_transform(y0, y1, y2, y3, x0, x1, x2, x3)
  InvRND00(x0, x1, x2, x3, y0, y1, y2, y3)
  x0 = y0
  x1 = y1
  x2 = y2
  x3 = y3
  keying(x0, x1, x2, x3, ctx.subkeys[0])

  state[0] = x0
  state[1] = x1
  state[2] = x2
  state[3] = x3

# ---------------------------------------------------------------------------
# Byte-level wrappers

proc serpentEncrypt*(ctx: SerpentSchedule; data: var array[16, byte]) =
  var state = loadBlock(data)
  ctx.encryptBlockWords(state)
  data = storeBlock(state)

proc serpentDecrypt*(ctx: SerpentSchedule; data: var array[16, byte]) =
  var state = loadBlock(data)
  ctx.decryptBlockWords(state)
  data = storeBlock(state)
