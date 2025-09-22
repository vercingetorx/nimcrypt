import std/sequtils

# NOTE: based on https://github.com/Legrandin/pycryptodome/blob/master/src/chacha20.c

type
  ChaCha20Ctx* = object
    h: array[16, uint32]
    nonce: seq[byte]
    usedKeyStream: uint
    keyStream: array[16 * sizeof(uint32), uint8]

const ChaChaKeySize = 32

#######################################################################

proc encodeBytes(s: string): seq[byte] =
  ## encode ascii string to bytes
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)
  
  return result


proc decodeBytes(bs: openArray[byte]): string =
  ## decode bytes to ascii string
  result = newStringOfCap(bs.len)
  for i, b in bs:
    result.add(char(b))
  
  return result


proc loadU32LittleEndian(arr: openArray[uint8], index: int): uint32 =
  if not (index + 4 <= arr.len):
    raise newException(IndexError, "index error")
  result = uint32(arr[index + 0])         or
          (uint32(arr[index + 1]) shl 8 ) or
          (uint32(arr[index + 2]) shl 16) or
          (uint32(arr[index + 3]) shl 24)


proc storeU32LittleEndian(arr: var openArray[uint8], index: int, value: uint32) =
  if not (index + 4 <= arr.len):
    raise newException(IndexError, "index error")
  arr[index + 0] = uint8( value         and 0xFF)
  arr[index + 1] = uint8((value shr 8 ) and 0xFF)
  arr[index + 2] = uint8((value shr 16) and 0xFF)
  arr[index + 3] = uint8((value shr 24) and 0xFF)

#######################################################################

proc rotateLeft(q: var uint32, n: int) =
  q = (q shl n) or (q shr (32 - n))


proc quarterRound(a, b, c, d: var uint32) =
  a += b
  d = d xor a
  rotateLeft(d, 16)
  c += d
  b = b xor c
  rotateLeft(b, 12)
  a += b
  d = d xor a
  rotateLeft(d, 8)
  c += d
  b = b xor c
  rotateLeft(b, 7)

#######################################################################

proc init(ctx: var ChaCha20Ctx, key: openArray[uint8],
          keySize: int, nonce: openArray[uint8], nonceSize: int) =
  if keySize != ChaChaKeySize:
    raise newException(ValueError, "key must be 32 bytes")
  if nonceSize notin [8, 12, 16]:
    raise newException(ValueError, "nonce must be 8/12/24 bytes")

  ctx.h[0] = 0x61707865'u32
  ctx.h[1] = 0x3320646e'u32
  ctx.h[2] = 0x79622d32'u32
  ctx.h[3] = 0x6b206574'u32

  # NOTE: move 256-bit/32-byte key into h[4..11]
  for i in 0 ..< 32 div 4:
    ctx.h[4 + i] = loadU32LittleEndian(key, 4 * i)

  case nonceSize
  of 8:
    # h[12] and h[13] remain 0 (offset)
    ctx.h[14] = loadU32LittleEndian(nonce,  0)
    ctx.h[15] = loadU32LittleEndian(nonce,  4)
  of 12:
    # h[12] remains 0 (offset)
    ctx.h[13] = loadU32LittleEndian(nonce,  0)
    ctx.h[14] = loadU32LittleEndian(nonce,  4)
    ctx.h[15] = loadU32LittleEndian(nonce,  8)
  of 16:
    ctx.h[12] = loadU32LittleEndian(nonce,  0)
    ctx.h[13] = loadU32LittleEndian(nonce,  4)
    ctx.h[14] = loadU32LittleEndian(nonce,  8)
    ctx.h[15] = loadU32LittleEndian(nonce, 12)
  else:
    discard

  ctx.nonce = toSeq(nonce)
  ctx.usedKeyStream = sizeof(ctx.keyStream).uint


proc generateBlock(ctx: var ChaCha20Ctx, h: var array[16, uint32]) =
  #[
    Purpose:
      This function is responsible for generating a single block of the ChaCha20 key stream.
      It plays a crucial role in the ChaCha20 encryption process by producing the keystream
      used to encrypt or decrypt data.
    
    Functionality:
      - Initializes the block (`h`) with the current state (`state->h`).
      - Performs 20 rounds of the ChaCha20 quarter round operation, alternating between
        column and diagonal rounds, to mix the input state.
      - After the rounds, it adds the original input state to the mixed state, which forms
        one block of the key stream.
      - Stores the generated key stream block into `state->keyStream`.
      - Manages the counter incrementation based on the nonce size, ensuring proper handling
        of the keystream generation for different nonce sizes, including special handling
        for HChaCha20.
    
    Parameters:
      - state: A pointer to the `stream_state` structure, which holds the current state of
              the ChaCha20 encryption, including the key, nonce, and block counter.
      - h: An array of 16 `uint32_t` elements, which will be used to hold the generated
          keystream block.
    
    Return Value:
      - Returns 0 on successful generation of the key stream block.
      - Returns `ERR_MAX_DATA` if the counter overflows, indicating that the maximum amount
        of data that can be safely encrypted with the current key-nonce combination has been reached.
    
    Notes:
      - This function is an internal part of the ChaCha20 encryption mechanism and is typically
        not called directly by users of the ChaCha20 encryption algorithm.
      - Proper management of the `stream_state` structure is crucial for the correct operation
        of this function.
  ]#
  # NOTE: copy state.h to h
  for i in 0 ..< h.len:
    h[i] = ctx.h[i]

  # NOTE: core loop
  for i in 0 ..< 10:
    # NOTE: column round
    quarterRound(h[0], h[4], h[8],  h[12])
    quarterRound(h[1], h[5], h[9],  h[13])
    quarterRound(h[2], h[6], h[10], h[14])
    quarterRound(h[3], h[7], h[11], h[15])
    # NOTE: diagonal round
    quarterRound(h[0], h[5], h[10], h[15])
    quarterRound(h[1], h[6], h[11], h[12])
    quarterRound(h[2], h[7], h[8],  h[13])
    quarterRound(h[3], h[4], h[9],  h[14])

  # NOTE: add and store results
  for i in 0 ..< 16:
    let sum = h[i] + ctx.h[i]
    storeU32LittleEndian(ctx.keyStream, 4 * i, uint32(sum))

  ctx.usedKeyStream = 0

  # NONCE: handle nonce size
  case ctx.nonce.len
  of 8:
    # NOTE: nonce is 64 bits, counter is two words
    ctx.h[12].inc
    if ctx.h[12] == 0:
      ctx.h[13].inc
      if ctx.h[13] == 0:
        # TEMP: implement correct exception type and message
        raise newException(IndexError, "error max data")
  of 12:
    # NOTE: nonce is 96 bits, counter is one word
    ctx.h[12].inc
    if ctx.h[12] == 0:
      # TEMP: implement correct exception type and message
      raise newException(IndexError, "error max data")
  of 16:
    # Note: nonce is 192 bits, no counter (HChaCha20)
    discard
  else:
    discard


proc crypt*(ctx: var ChaCha20Ctx, input: openArray[uint8]): seq[byte] =
  ## return new sequence of encrypted/decrypted data
  if ctx.nonce.len notin [8, 12]:
    raise newException(ValueError, "nonce must be 8/12/24 bytes")
  
  result = newSeq[byte](input.len)

  var remainingLen = input.len
  var indexOffset = 0

  while remainingLen > 0:
    var h: array[16, uint32]
    var keyStreamToUse: int

    if ctx.usedKeyStream == sizeof(ctx.keyStream).uint:
      ctx.generateBlock(h)

    keyStreamToUse = min(remainingLen, sizeof(ctx.keyStream) - int(ctx.usedKeyStream))
    for i in 0 ..< keyStreamToUse:
      result[indexOffset + i] = input[indexOffset + i] xor ctx.keyStream[i + int(ctx.usedKeyStream)]

    indexOffset += keyStreamToUse
    remainingLen -= keyStreamToUse
    ctx.usedKeyStream += uint(keyStreamToUse)

  return result


proc crypt*(ctx: var ChaCha20Ctx, input: openArray[uint8], output: var openArray[uint8]) =
  ## encrypt/decrypt data in place
  if ctx.nonce.len notin [8, 12]:
    raise newException(ValueError, "nonce must be 8/12/24 bytes")

  var remainingLen = input.len
  var indexOffset = 0

  while remainingLen > 0:
    var h: array[16, uint32]
    var keyStreamToUse: int

    if ctx.usedKeyStream == sizeof(ctx.keyStream).uint:
      ctx.generateBlock(h)

    keyStreamToUse = min(remainingLen, sizeof(ctx.keyStream) - int(ctx.usedKeyStream))
    for i in 0 ..< keyStreamToUse:
      output[indexOffset + i] = input[indexOffset + i] xor ctx.keyStream[i + int(ctx.usedKeyStream)]

    indexOffset += keyStreamToUse
    remainingLen -= keyStreamToUse
    ctx.usedKeyStream += uint(keyStreamToUse)


proc crypt*(ctx: var ChaCha20Ctx, input, output: ptr byte, length: int) =
  ## encrypt/decrypt data in place using pointers
  if ctx.nonce.len notin [8, 12]:
    raise newException(ValueError, "nonce must be 8/12/24 bytes")
  
  var inputPtr = input
  var outputPtr = output
  var remainingLen = length

  while remainingLen > 0:
    var h: array[16, uint32]
    var keyStreamToUse: int

    if ctx.usedKeyStream == sizeof(ctx.keyStream).uint:
      ctx.generateBlock(h)

    keyStreamToUse = min(remainingLen, sizeof(ctx.keyStream) - int(ctx.usedKeyStream))
    for i in 0 ..< keyStreamToUse:
      outputPtr[] = inputPtr[] xor ctx.keyStream[i + int(ctx.usedKeyStream)]
      inputPtr = cast[ptr byte](cast[uint](inputPtr) + 1)
      outputPtr = cast[ptr byte](cast[uint](outputPtr) + 1)

    remainingLen -= keyStreamToUse
    ctx.usedKeyStream += uint(keyStreamToUse)


proc encrypt*(state: var ChaCha20Ctx, input: openArray[uint8]): seq[uint8] =
  ## new sequence (wrapper)
  return crypt(state, input)


proc encrypt*(state: var ChaCha20Ctx, input: string): seq[uint8] =
  ## new sequence (wrapper)
  return crypt(state, input.encodeBytes())


proc encrypt*(state: var ChaCha20Ctx, input: openArray[uint8], output: var openArray[uint8]) =
  ## in place (wrapper)
  crypt(state, input, output)


proc encrypt*(state: var ChaCha20Ctx, input, output: ptr uint8, length: int) =
  ## in place pointer (wrapper)
  crypt(state, input, output, length)


proc encrypt*(state: var ChaCha20Ctx, input: string, output: var openArray[uint8]) =
  ## in place (wrapper)
  crypt(state, input.encodeBytes(), output)


proc decrypt*(state: var ChaCha20Ctx, input: openArray[uint8]): seq[uint8] =
  ## new sequence (wrapper)
  return crypt(state, input)


proc decrypt*(state: var ChaCha20Ctx, input: string): seq[uint8] =
  ## new sequence (wrapper)
  return crypt(state, input.encodeBytes())


proc decrypt*(state: var ChaCha20Ctx, input: openArray[uint8], output: var openArray[uint8]) =
  ## in place (wrapper)
  crypt(state, input, output)


proc decrypt*(state: var ChaCha20Ctx, input, output: ptr uint8, length: int) =
  ## in place pointer (wrapper)
  crypt(state, input, output, length)


proc decrypt*(state: var ChaCha20Ctx, input: string, output: var openArray[uint8]) =
  ## in place (wrapper)
  crypt(state, input.encodeBytes(), output)


proc seek*(ctx: var ChaCha20Ctx, blockLow, blockHigh: uint64, offset: uint) =
  #[
    Purpose:
      The chacha20_seek function is designed to set the internal state of the ChaCha20
      stream cipher to a specific block and offset. This is particularly useful for
      random access within a large stream of data encrypted with ChaCha20, allowing
      efficient decryption of arbitrary portions of the data without needing to process
      the entire stream from the beginning.
    
    Functionality:
      - Validates the input parameters and the state of the ChaCha20 cipher.
      - Sets the block counter in the state based on the provided `block_high` and `block_low`
        values, allowing the cipher to jump to a specific point in the key stream.
      - The `offset` parameter specifies a byte offset within the block, enabling fine-tuned
        positioning within the key stream.
      - Generates the key stream for the specified block by calling `chacha20_core`.
      - Adjusts the `usedKeyStream` field of the state to reflect the offset within the current block.
    
    Parameters:
      - state: A pointer to the `stream_state` structure, which holds the current state of
              the ChaCha20 encryption, including the key, nonce, and block counter.
      - block_high: The high part of the block counter, used for large data sizes.
      - block_low: The low part of the block counter, typically used for standard block addressing.
      - offset: The byte offset within the block where the key stream generation should begin.
    
    Return Value:
      - Returns 0 on successful setting of the state.
      - Returns error codes for various failure scenarios such as null state pointer,
        incorrect nonce size, or exceeding the maximum offset.
    
    Notes:
      - This function is essential for scenarios where only a specific segment of the encrypted
        data needs to be processed, avoiding the need to decrypt data from the beginning of the stream.
      - Proper management and understanding of block counters and offsets are critical for the
        correct and secure operation of this function.
  ]#

  if ctx.nonce.len notin [8, 12]:
    raise newException(ValueError, "nonce must be 8/12/24 bytes")

  if offset >= sizeof(ctx.keyStream).uint:
    raise newException(ValueError, "offset not in keyStream")

  if ctx.nonce.len == 8:
    # NOTE: nonce is 64 bits, counter is two words
    ctx.h[12] = uint32(blockLow)
    ctx.h[13] = uint32(blockHigh)
  else:
    # NOTE: nonce is 96 bits, counter is one word
    if blockHigh > 0:
      raise newException(ValueError, "block high index not in keyStream")
    ctx.h[12] = uint32(blockLow)

  ctx.generateBlock(ctx.h)
  ctx.usedKeyStream = offset


proc hChaCha20*(key, nonce16: openArray[uint8]): seq[byte] =
  #[
    hchacha20 Function (xchacha20)

    Purpose:
      The hchacha20 function is a variant of the ChaCha20 stream cipher, specifically designed
      for deriving a new 256-bit subkey from an existing key and a 16-byte nonce. This function
      is particularly useful in cryptographic protocols where different subkeys are required
      for different contexts or sessions, based on a single master key.

    Functionality:
      - Takes an initial 256-bit key and a 16-byte nonce as input.
      - Performs the ChaCha20 core operation, but unlike standard ChaCha20, it extracts a 256-bit
        subkey based on a subset of the ChaCha20 state (specifically, the first and last rows).
      - The derived subkey can be used in subsequent cryptographic operations, ensuring that
        each operation uses a unique key, even if the master key remains the same.

    Typical Use Cases:
      - Key Derivation: Generating unique subkeys for different encryption sessions or contexts
        to enhance security by avoiding key reuse.
      - XChaCha20 Algorithm: Integral in extending the nonce size in the XChaCha20 algorithm,
        allowing the encryption of a larger volume of data with the same key without nonce reuse.
      - Modular Cryptographic Schemes: Serving as a building block in more complex cryptographic
        protocols that require key derivation or management.

    Parameters:
      - key: The initial 256-bit key.
      - nonce16: The 16-byte nonce used for subkey derivation.
      - subkey: The output buffer where the derived 256-bit subkey is stored.

    Notes:
      - This function does not perform encryption/decryption itself but is used to enhance the
        flexibility and security of the encryption process by facilitating dynamic key management.
  ]#
  var ctx: ChaCha20Ctx
  ctx.init(key, key.len, nonce16, 16)

  var h: array[16, uint32]
  ctx.generateBlock(h)
  
  result = newSeq[byte](32)
  # NOTE: only keep the first and last row from the new state
  storeU32LittleEndian(result,  0, h[ 0])
  storeU32LittleEndian(result,  4, h[ 1])
  storeU32LittleEndian(result,  8, h[ 2])
  storeU32LittleEndian(result, 12, h[ 3])
  storeU32LittleEndian(result, 16, h[12])
  storeU32LittleEndian(result, 20, h[13])
  storeU32LittleEndian(result, 24, h[14])
  storeU32LittleEndian(result, 28, h[15])

  return result

#######################################################################

proc newChaCha20Ctx*(key, nonce: openArray[byte]): ChaCha20Ctx =
  # NOTE: xchacha20
  if nonce.len == 24:
    let subKey = hChaCha20(key, nonce[0 ..< 16])
    result.init(subKey, subKey.len, nonce[16 ..< 24], 8)
  else:
    result.init(key, key.len, nonce, nonce.len)


proc newChaCha20Ctx*(key, nonce: string): ChaCha20Ctx =
  return newChaCha20Ctx(key.encodeBytes(), nonce.encodeBytes())


proc derivePoly1305KeyPair*(key: openArray[byte], nonce: openArray[byte]): (seq[byte], seq[byte], seq[byte]) =
  if key.len != ChaChaKeySize:
    raise newException(ValueError, "Poly1305 with ChaCha20 requires a 32-byte key")
  
  const emptyData: array[32, uint8] = [
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
  ]
  var
    paddedNonce: seq[byte]
    derivedKey: seq[byte]

  if nonce.len == 8:
    paddedNonce = @[0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8] & toSeq(nonce)
  elif nonce.len == 12:
    paddedNonce = toSeq(nonce)
  else:
    raise newException(ValueError, "Poly1305 with ChaCha20 requires an 8 or 12-byte nonce")

  var chacha20Cipher = newChaCha20Ctx(key, paddedNonce)
  derivedKey = chacha20Cipher.encrypt(emptyData)

  let r = derivedKey[ 0 .. 15]  # First 16 bytes
  let s = derivedKey[16 .. 31]  # Next 16 bytes

  return (r, s, paddedNonce)

#######################################################################

when isMainModule:
  import base64

  let plaintext = "Attack at dawn"
  let key       = "12345678901234561234567890123456"
  let nonce8    = "01234567"
  let nonce12   = "0123456789AB"
  let nonce24   = "0123456789ABCDEFGHIJKLMN"
  
  var ctx = newChaCha20Ctx(key, nonce24)
  
  # NOTE: encrypt in place
  # var ciphertext: array[14, byte]
  # ctx.encrypt(plaintext, ciphertext)
  # NOTE: return ciphertext
  let ciphertext = ctx.encrypt(plaintext)
  # doAssert ciphertext.encode() == "jRN9sVx/2cHOPcit7Fo=" # 8
  # doAssert ciphertext.encode() == "wt86LJl5CUx5lCeTBh0=" # 12
  doAssert ciphertext.encode() == "E3plHVm5ulH2EXX9en0=" # 24
