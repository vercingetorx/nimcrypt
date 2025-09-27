# NOTE: ported to Nim from https://github.com/Legrandin/pycryptodome/blob/master/src/keccak.c
import std/bitops


const
  KECCAK_F1600_STATE = 200
  ERR_NULL = -1
  ERR_UNKNOWN = -5
  SUCCESS = 0

type
  KeccakState* = object
    state: array[25, uint64]
    buf: array[KECCAK_F1600_STATE, uint8]
    validBytes: uint32
    capacity: uint32
    rate: uint32
    squeezing: uint8
    rounds: uint8


proc keccakFunction*(state: var array[25, uint64], rounds: byte)

###########################################################################################

proc storeU64LE(dst: ptr array[KECCAK_F1600_STATE, uint8], src: uint64, index: int) =
  dst[][index + 0] = byte(src)
  dst[][index + 1] = byte(src shr  8)
  dst[][index + 2] = byte(src shr 16)
  dst[][index + 3] = byte(src shr 24)
  dst[][index + 4] = byte(src shr 32)
  dst[][index + 5] = byte(src shr 40)
  dst[][index + 6] = byte(src shr 48)
  dst[][index + 7] = byte(src shr 56)


proc loadU64LE(src: ptr array[KECCAK_F1600_STATE, uint8], index: int): uint64 =
  result = uint64(src[][index + 0])        or
           uint64(src[][index + 1]) shl  8 or
           uint64(src[][index + 2]) shl 16 or
           uint64(src[][index + 3]) shl 24 or
           uint64(src[][index + 4]) shl 32 or
           uint64(src[][index + 5]) shl 40 or
           uint64(src[][index + 6]) shl 48 or
           uint64(src[][index + 7]) shl 56

###########################################################################################

proc keccakAbsorbInternal(self: var KeccakState) =
  var i: int
  for j in countup(0, int(self.rate) - 1, 8):
    self.state[i] = self.state[i] xor loadU64LE(addr self.buf, j)
    inc i


proc keccakSqueezeInternal(self: var KeccakState) =
  var i: int
  for j in countup(0, int(self.rate) - 1, 8):
    storeU64LE(addr self.buf, self.state[i], j)
    inc i


proc keccakInit*(capacityBytes: int, rounds: uint8): KeccakState =
  if capacityBytes >= KECCAK_F1600_STATE or not (rounds in [12'u8, 24'u8]):
    raise newException(ValueError, "Invalid capacity bytes or round number")

  result = KeccakState(
    capacity: uint32(capacityBytes),
    rate: KECCAK_F1600_STATE - uint32(capacityBytes),
    rounds: rounds
  )


proc keccakAbsorb*(self: var KeccakState, input: openArray[byte]): int =
  if input.len == 0:
    return ERR_NULL

  if self.squeezing != 0'u8:
    return ERR_UNKNOWN

  var length = input.len
  var inIdx = 0

  while length > 0:
    let left = int(self.rate) - int(self.validBytes)
    let tc = min(length, left)
    copyMem(addr self.buf[self.validBytes], unsafeAddr input[inIdx], tc)

    self.validBytes += uint32(tc)
    inIdx += tc
    length -= tc

    if self.validBytes == self.rate:
      keccakAbsorbInternal(self)
      keccakFunction(self.state, self.rounds)
      self.validBytes = 0

  return SUCCESS


proc keccakFinish*(self: var KeccakState, padding: uint8) =
  assert(self.squeezing == 0)
  assert(self.validBytes < uint32(self.rate))

  # NOTE: padding
  for i in int(self.validBytes) ..< int(self.rate):
    self.buf[i] = 0
  self.buf[self.validBytes] = padding
  self.buf[self.rate - 1] = self.buf[self.rate - 1] or 0x80'u8

  # NOTE: final absorb
  keccakAbsorbInternal(self)
  keccakFunction(self.state, self.rounds)

  # NOTE: first squeeze
  self.squeezing = 1
  keccakSqueezeInternal(self)
  self.validBytes = uint32(self.rate)


proc keccakSqueeze*(self: var KeccakState, output: var openArray[byte], length: int, padding: uint8): int =
  if output.len == 0:
    return ERR_NULL

  if self.squeezing == 0:
    self.keccakFinish(padding)

  assert(self.squeezing == 1)
  assert(self.validBytes > 0)
  assert(self.validBytes <= uint32(self.rate))

  var outPos = 0
  var lengthInner = length

  while lengthInner > 0:
    let tc = min(int(self.validBytes), lengthInner)
    for i in 0 ..< tc:
      output[outPos + i] = self.buf[int(self.rate) - int(self.validBytes) + i]

    self.validBytes -= uint32(tc)
    outPos += tc
    lengthInner -= tc

    if self.validBytes == 0:
      keccakFunction(self.state, self.rounds)
      keccakSqueezeInternal(self)
      self.validBytes = self.rate

  return SUCCESS


proc keccakDigest*(state: var KeccakState, digest: var openArray[byte], len: int, padding: uint8): int =
  if digest.len == 0:
    return ERR_NULL

  if 2 * len != int(state.capacity):
    return ERR_UNKNOWN

  var tmp: KeccakState = state
  return tmp.keccakSqueeze(digest, len, padding)

###########################################################################################

const KECCAK_ROUNDS = 24

const ROT_01 = 36
const ROT_02 = 3
const ROT_03 = 41
const ROT_04 = 18
const ROT_05 = 1
const ROT_06 = 44
const ROT_07 = 10
const ROT_08 = 45
const ROT_09 = 2
const ROT_10 = 62
const ROT_11 = 6
const ROT_12 = 43
const ROT_13 = 15
const ROT_14 = 61
const ROT_15 = 28
const ROT_16 = 55
const ROT_17 = 25
const ROT_18 = 21
const ROT_19 = 56
const ROT_20 = 27
const ROT_21 = 20
const ROT_22 = 39
const ROT_23 = 8
const ROT_24 = 14

const roundConstants: array[24, uint64] = [
  0x0000000000000001'u64, 0x0000000000008082'u64, 0x800000000000808A'u64,
  0x8000000080008000'u64, 0x000000000000808B'u64, 0x0000000080000001'u64,
  0x8000000080008081'u64, 0x8000000000008009'u64, 0x000000000000008A'u64,
  0x0000000000000088'u64, 0x0000000080008009'u64, 0x000000008000000A'u64,
  0x000000008000808B'u64, 0x800000000000008B'u64, 0x8000000000008089'u64,
  0x8000000000008003'u64, 0x8000000000008002'u64, 0x8000000000000080'u64,
  0x000000000000800A'u64, 0x800000008000000A'u64, 0x8000000080008081'u64,
  0x8000000000008080'u64, 0x0000000080000001'u64, 0x8000000080008008'u64
]

proc keccakFunction*(state: var array[25, uint64], rounds: byte) =
  # Validate the state pointer.
  # assert(state != nil, "State cannot be nil.")

  # NOTE: temporary variables to avoid indexing overhead.
  var
    a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12: uint64
    a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24: uint64

  var
    b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12: uint64
    b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24: uint64

  var
    c0, c1, c2, c3, c4, d: uint64

  # NOTE: load state into local variables.
  a0 = state[0]
  a1 = state[1]
  a2 = state[2]
  a3 = state[3]
  a4 = state[4]
  a5 = state[5]
  a6 = state[6]
  a7 = state[7]
  a8 = state[8]
  a9 = state[9]
  a10 = state[10]
  a11 = state[11]
  a12 = state[12]
  a13 = state[13]
  a14 = state[14]
  a15 = state[15]
  a16 = state[16]
  a17 = state[17]
  a18 = state[18]
  a19 = state[19]
  a20 = state[20]
  a21 = state[21]
  a22 = state[22]
  a23 = state[23]
  a24 = state[24]

  let startRound = if rounds == 24: 0 else: 12

  for i in startRound ..<  KECCAK_ROUNDS:
    #[ NOTE:
        Uses temporary variables and loop unrolling to
        avoid array indexing and inner loops overhead
    ]#

    # NOTE: prepare column parity for Theta step
    c0 = a0 xor a5 xor a10 xor a15 xor a20
    c1 = a1 xor a6 xor a11 xor a16 xor a21
    c2 = a2 xor a7 xor a12 xor a17 xor a22
    c3 = a3 xor a8 xor a13 xor a18 xor a23
    c4 = a4 xor a9 xor a14 xor a19 xor a24

    # NOTE: Theta + Rho + Pi steps
    d   = c4 xor rotateLeftBits(c1, 1)
    b0  = d xor a0
    b16 = rotateLeftBits(d xor a5,  ROT_01)
    b7  = rotateLeftBits(d xor a10, ROT_02)
    b23 = rotateLeftBits(d xor a15, ROT_03)
    b14 = rotateLeftBits(d xor a20, ROT_04)

    d   = c0 xor rotateLeftBits(c2, 1)
    b10 = rotateLeftBits(d xor a1,  ROT_05)
    b1  = rotateLeftBits(d xor a6,  ROT_06)
    b17 = rotateLeftBits(d xor a11, ROT_07)
    b8  = rotateLeftBits(d xor a16, ROT_08)
    b24 = rotateLeftBits(d xor a21, ROT_09)

    d   = c1 xor rotateLeftBits(c3, 1)
    b20 = rotateLeftBits(d xor a2,  ROT_10)
    b11 = rotateLeftBits(d xor a7,  ROT_11)
    b2  = rotateLeftBits(d xor a12, ROT_12)
    b18 = rotateLeftBits(d xor a17, ROT_13)
    b9  = rotateLeftBits(d xor a22, ROT_14)

    d   = c2 xor rotateLeftBits(c4, 1)
    b5  = rotateLeftBits(d xor a3,  ROT_15)
    b21 = rotateLeftBits(d xor a8,  ROT_16)
    b12 = rotateLeftBits(d xor a13, ROT_17)
    b3  = rotateLeftBits(d xor a18, ROT_18)
    b19 = rotateLeftBits(d xor a23, ROT_19)

    d   = c3 xor rotateLeftBits(c0, 1)
    b15 = rotateLeftBits(d xor a4,  ROT_20)
    b6  = rotateLeftBits(d xor a9,  ROT_21)
    b22 = rotateLeftBits(d xor a14, ROT_22)
    b13 = rotateLeftBits(d xor a19, ROT_23)
    b4  = rotateLeftBits(d xor a24, ROT_24)

    # NOTE: Chi + Iota steps
    a0  = b0  xor (not b1 and b2) xor roundConstants[i]
    a1  = b1  xor (not b2 and b3)
    a2  = b2  xor (not b3 and b4)
    a3  = b3  xor (not b4 and b0)
    a4  = b4  xor (not b0 and b1)

    a5  = b5  xor (not b6 and b7)
    a6  = b6  xor (not b7 and b8)
    a7  = b7  xor (not b8 and b9)
    a8  = b8  xor (not b9 and b5)
    a9  = b9  xor (not b5 and b6)

    a10 = b10 xor (not b11 and b12)
    a11 = b11 xor (not b12 and b13)
    a12 = b12 xor (not b13 and b14)
    a13 = b13 xor (not b14 and b10)
    a14 = b14 xor (not b10 and b11)

    a15 = b15 xor (not b16 and b17)
    a16 = b16 xor (not b17 and b18)
    a17 = b17 xor (not b18 and b19)
    a18 = b18 xor (not b19 and b15)
    a19 = b19 xor (not b15 and b16)

    a20 = b20 xor (not b21 and b22)
    a21 = b21 xor (not b22 and b23)
    a22 = b22 xor (not b23 and b24)
    a23 = b23 xor (not b24 and b20)
    a24 = b24 xor (not b20 and b21)

  state[0]  = a0
  state[1]  = a1
  state[2]  = a2
  state[3]  = a3
  state[4]  = a4
  state[5]  = a5
  state[6]  = a6
  state[7]  = a7
  state[8]  = a8
  state[9]  = a9
  state[10] = a10
  state[11] = a11
  state[12] = a12
  state[13] = a13
  state[14] = a14
  state[15] = a15
  state[16] = a16
  state[17] = a17
  state[18] = a18
  state[19] = a19
  state[20] = a20
  state[21] = a21
  state[22] = a22
  state[23] = a23
  state[24] = a24
