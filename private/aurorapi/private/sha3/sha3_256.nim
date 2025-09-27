import std/strutils

include keccak


type Sha3_256Ctx = object
  state: KeccakState
  blockSize: int
  digestSize: int
  padding: byte


const
  DigestSize = 32
  BlockSize = 136
  Padding = 0x06'u8
  Rounds = 24'u8


proc update*(ctx: var Sha3_256Ctx, data: openArray[byte]) =
  discard ctx.state.keccakAbsorb(data)


proc update*(ctx: var Sha3_256Ctx, data: string) =
  discard ctx.state.keccakAbsorb(data.toOpenArrayByte(0, data.len.pred))


proc digest*(ctx: var Sha3_256Ctx): array[DigestSize, byte] =
  discard keccakDigest(ctx.state, result, ctx.digestSize, ctx.padding)


proc hexDigest*(ctx: var Sha3_256Ctx): string =
  ## produces a hex string of length ctx.digestSize * 2
  result = newStringOfCap(ctx.digestSize + ctx.digestSize)
  let digest = ctx.digest()
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc newSha3_256Ctx*(data: openArray[byte] = @[]): Sha3_256Ctx =
  result.blockSize = BlockSize
  result.digestSize = DigestSize
  result.padding = Padding
  
  result.state = keccakInit(DigestSize + DigestSize, Rounds)

  if data.len > 0:
    result.update(data)


proc newSha3_256Ctx*(data: string): Sha3_256Ctx =
  return newSha3_256Ctx(data.toOpenArrayByte(0, data.len.pred))


when isMainModule:
  let message = "hello world"

  var ctx = newSha3_256Ctx(message)
  doAssert ctx.hexDigest() == "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
