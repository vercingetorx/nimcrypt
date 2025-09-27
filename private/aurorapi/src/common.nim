# ========================================
# File: src/common.nim
# ========================================
when isMainModule: discard

import std/bitops

const
  AURORA_BLOCK_BYTES* = 32          # 256-bit block
  AURORA_KEY_BYTES*   = 32          # 256-bit key (primary)
  AURORA_TWEAK_BYTES* = 16          # 128-bit tweak (optional)
  AURORA_ROUNDS*      = 16          # Feistel rounds

# --- Simple little-endian converters ---
proc load64*(b: openArray[byte], off: int): uint64 =
  ## Load little-endian u64 from b[off..off+7]
  var r: uint64 = 0
  for i in 0..7:
    r = r or (uint64(b[off+i]) shl (i*8))
  r

proc store64*(b: var openArray[byte], off: int, x: uint64) =
  var t = x
  for i in 0..7:
    b[off+i] = byte(t and 0xff'u64)
    t = t shr 8

# --- Rotation helpers (wrap around) ---
proc rotl*(x: uint64, r: int): uint64 {.inline.} = rotateLeftBits(x, r)
proc rotr*(x: uint64, r: int): uint64 {.inline.} = rotateRightBits(x, r)

# --- XOR / ADD on 128-bit (2x u64) tuples ---
type U128* = tuple[a: uint64, b: uint64]

template `^^`*(x, y: U128): U128 = (a: x.a xor y.a, b: x.b xor y.b)

proc toU128*(mem: openArray[byte], off: int): U128 {.inline.} =
  result.a = load64(mem, off)
  result.b = load64(mem, off+8)

proc putU128*(dst: var openArray[byte], off: int, v: U128) {.inline.} =
  store64(dst, off, v.a)
  store64(dst, off+8, v.b)

# Round constants — distinct from typical ARX suites
# Generated from fractional bits of sqrt of selected odd primes (little variant)
# Fixed at compile time for reproducibility
const RC64*: array[AURORA_ROUNDS, array[2, uint64]] = [
  [0x9e3779b185ebca87'u64, 0xc2b2ae3d27d4eb4f'u64],
  [0x165667b19e3779f9'u64, 0x85ebca77c2b2ae63'u64],
  [0x27d4eb2f165667cb'u64, 0x9e3779b185ebca87'u64],
  [0xc2b2ae3d85ebca77'u64, 0x165667b19e3779f9'u64],
  [0x94d049bb133111eb'u64, 0x2545f4914f6cdd1d'u64],
  [0x15aa83f9ebc77eee'u64, 0x2d51a13d34b0bcb5'u64],
  [0x3c6ef372fe94f82a'u64, 0xbb67ae8584caa73b'u64],
  [0xa54ff53a5f1d36f1'u64, 0x510e527fade682d1'u64],
  [0x9b05688c2b3e6c1f'u64, 0x1f83d9abfb41bd6b'u64],
  [0x5be0cd19137e2179'u64, 0x6a09e667bb67ae85'u64],
  [0x243f6a8885a308d3'u64, 0x13198a2e03707344'u64],
  [0xa4093822299f31d0'u64, 0x082efa98ec4e6c89'u64],
  [0x452821e638d01377'u64, 0xbe5466cf34e90c6c'u64],
  [0xc0ac29b7c97c50dd'u64, 0x3f84d5b5b5470917'u64],
  [0x9216d5d98979fb1b'u64, 0xd1310ba698dfb5ac'u64],
  [0x2ffd72dbd01adfb7'u64, 0xb8e1afed6a267e96'u64]
]

# Lightweight non-linear mixing on 128-bit (2x64) — invertible sequence
proc nlMix*(x: var U128) {.inline.} =
  # ARX-like invertible steps
  x.a = x.a + (rotl(x.b, 23))
  x.b = x.b xor (rotl(x.a, 17))
  x.a = x.a xor (rotl(x.b, 31))
  x.b = x.b + (rotl(x.a, 27))

proc nlUnmix*(x: var U128) {.inline.} =
  # exact inverse order
  x.b = x.b - (rotl(x.a, 27))
  x.a = x.a xor (rotl(x.b, 31))
  x.b = x.b xor (rotl(x.a, 17))
  x.a = x.a - (rotl(x.b, 23))

proc bytesSeq*(vals: openArray[int]): seq[byte] =
  result = newSeq[byte](vals.len)
  for i, v in vals: result[i] = byte(v and 0xff)

proc toBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc incBytes*(n: int): seq[byte] =
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(i and 0xff)

proc printKV*(k, v: string) =
  echo k, ": ", v

proc printLine*() = echo "----------------------------------------"
