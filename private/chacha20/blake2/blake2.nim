import std/[bitops]


# NOTE: https://www.rfc-editor.org/rfc/rfc7693


const
  wordsInBlock = 16
  wordsInState = 8


func G(v: var array[16, uint32], a, b, c, d: int, x, y: uint32) =
  ## blake2s
  v[a] = v[a] + v[b] + x
  v[d] = rotateRightBits(v[d] xor v[a], R1)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], R2)
  v[a] = v[a] + v[b] + y
  v[d] = rotateRightBits(v[d] xor v[a], R3)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], R4)


func G(v: var array[16, uint64], a, b, c, d: int, x, y: uint64) =
  ## blake2b
  v[a] = v[a] + v[b] + x
  v[d] = rotateRightBits(v[d] xor v[a], R1)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], R2)
  v[a] = v[a] + v[b] + y
  v[d] = rotateRightBits(v[d] xor v[a], R3)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], R4)
