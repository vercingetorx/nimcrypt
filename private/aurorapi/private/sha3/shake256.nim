import std/strutils

include keccak


type Shake256Ctx* = object
  state: KeccakState
  digestSize: int
  padding: byte


const
  DigestSize = 64
  Padding = 0x1F'u8
  Rounds = 24'u8


proc read*(ctx: var Shake256Ctx, length: int = DigestSize): seq[byte] =
  result = newSeq[byte](length)
  discard keccakSqueeze(ctx.state, result, length, ctx.padding)


proc read*(ctx: var Shake256Ctx, dst: var openArray[byte]) =
  discard keccakSqueeze(ctx.state, dst, dst.len, ctx.padding)


proc write*(ctx: var Shake256Ctx, data: openArray[byte]) =
  discard keccakAbsorb(ctx.state, data)


proc update*(ctx: var Shake256Ctx, data: openArray[byte]) =
  ctx.write(data)


proc update*(ctx: var Shake256Ctx, data: string) =
  ctx.write(data.toOpenArrayByte(0, data.len.pred))


proc digest*(ctx: var Shake256Ctx, length: int = DigestSize): seq[byte] =
  return ctx.read(length)


proc hexDigest*(ctx: var Shake256Ctx, length: int = DigestSize): string =
  ## produces a hex string of length length * 2
  result = newStringOfCap(length + length)
  let digest = ctx.read(length)
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc newShake256Ctx*(data: openArray[byte] = @[]): Shake256Ctx =
  ## Shake256 XOF
  result.digestSize = DigestSize
  result.padding = Padding
  
  result.state = keccakInit(DigestSize, Rounds)

  if data.len > 0:
    result.update(data)


proc newShake256Ctx*(data: string): Shake256Ctx =
  return newShake256Ctx(data.toOpenArrayByte(0, data.len.pred))


when isMainModule:
  let message = "hello world"

  var ctx = newShake256Ctx(message)
  doAssert ctx.hexDigest() == "369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527f4f3c2d55c2d46a29f2e945d469c3df27853a8735271f5cc2d9e889544357116"
