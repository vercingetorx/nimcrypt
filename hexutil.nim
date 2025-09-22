# ========================================
# File: src/hexutil.nim
# ========================================
when isMainModule: discard

import std/strutils

proc toHex*(b: openArray[byte]): string =
  result = newStringOfCap(b.len*2)
  for v in b:
    result.add toHex(int(v), 2)

proc parseHex*(s: string): seq[byte] =
  ## Parse hex (len must be even)
  let t = s.strip
  doAssert t.len mod 2 == 0, "hex length must be even"
  result = newSeq[byte](t.len div 2)
  var i = 0
  while i < t.len:
    result[i div 2] = byte(parseHexInt(t.substr(i, i+1)))
    i += 2