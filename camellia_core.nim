# NOTE: ported to Nim from https://github.com/openssl/openssl/blob/master/crypto/camellia/camellia.c

import std/bitops

const
  BlockSize* = 16
  KeyTableSize* = 68

type
  KeyTable* = array[KeyTableSize, uint32]
  CamelliaKey* = object
    rounds*: int
    rk*: KeyTable

const
  CamelliaSBox*: array[4, array[256, uint32]] = [
    [0x70707000u32, 0x82828200u32, 0x2c2c2c00u32, 0xececec00u32, 0xb3b3b300u32, 0x27272700u32, 0xc0c0c000u32, 0xe5e5e500u32, 0xe4e4e400u32, 0x85858500u32, 0x57575700u32, 0x35353500u32, 0xeaeaea00u32, 0x0c0c0c00u32, 0xaeaeae00u32, 0x41414100u32, 0x23232300u32, 0xefefef00u32, 0x6b6b6b00u32, 0x93939300u32, 0x45454500u32, 0x19191900u32, 0xa5a5a500u32, 0x21212100u32, 0xededed00u32, 0x0e0e0e00u32, 0x4f4f4f00u32, 0x4e4e4e00u32, 0x1d1d1d00u32, 0x65656500u32, 0x92929200u32, 0xbdbdbd00u32, 0x86868600u32, 0xb8b8b800u32, 0xafafaf00u32, 0x8f8f8f00u32, 0x7c7c7c00u32, 0xebebeb00u32, 0x1f1f1f00u32, 0xcecece00u32, 0x3e3e3e00u32, 0x30303000u32, 0xdcdcdc00u32, 0x5f5f5f00u32, 0x5e5e5e00u32, 0xc5c5c500u32, 0x0b0b0b00u32, 0x1a1a1a00u32, 0xa6a6a600u32, 0xe1e1e100u32, 0x39393900u32, 0xcacaca00u32, 0xd5d5d500u32, 0x47474700u32, 0x5d5d5d00u32, 0x3d3d3d00u32, 0xd9d9d900u32, 0x01010100u32, 0x5a5a5a00u32, 0xd6d6d600u32, 0x51515100u32, 0x56565600u32, 0x6c6c6c00u32, 0x4d4d4d00u32, 0x8b8b8b00u32, 0x0d0d0d00u32, 0x9a9a9a00u32, 0x66666600u32, 0xfbfbfb00u32, 0xcccccc00u32, 0xb0b0b000u32, 0x2d2d2d00u32, 0x74747400u32, 0x12121200u32, 0x2b2b2b00u32, 0x20202000u32, 0xf0f0f000u32, 0xb1b1b100u32, 0x84848400u32, 0x99999900u32, 0xdfdfdf00u32, 0x4c4c4c00u32, 0xcbcbcb00u32, 0xc2c2c200u32, 0x34343400u32, 0x7e7e7e00u32, 0x76767600u32, 0x05050500u32, 0x6d6d6d00u32, 0xb7b7b700u32, 0xa9a9a900u32, 0x31313100u32, 0xd1d1d100u32, 0x17171700u32, 0x04040400u32, 0xd7d7d700u32, 0x14141400u32, 0x58585800u32, 0x3a3a3a00u32, 0x61616100u32, 0xdedede00u32, 0x1b1b1b00u32, 0x11111100u32, 0x1c1c1c00u32, 0x32323200u32, 0x0f0f0f00u32, 0x9c9c9c00u32, 0x16161600u32, 0x53535300u32, 0x18181800u32, 0xf2f2f200u32, 0x22222200u32, 0xfefefe00u32, 0x44444400u32, 0xcfcfcf00u32, 0xb2b2b200u32, 0xc3c3c300u32, 0xb5b5b500u32, 0x7a7a7a00u32, 0x91919100u32, 0x24242400u32, 0x08080800u32, 0xe8e8e800u32, 0xa8a8a800u32, 0x60606000u32, 0xfcfcfc00u32, 0x69696900u32, 0x50505000u32, 0xaaaaaa00u32, 0xd0d0d000u32, 0xa0a0a000u32, 0x7d7d7d00u32, 0xa1a1a100u32, 0x89898900u32, 0x62626200u32, 0x97979700u32, 0x54545400u32, 0x5b5b5b00u32, 0x1e1e1e00u32, 0x95959500u32, 0xe0e0e000u32, 0xffffff00u32, 0x64646400u32, 0xd2d2d200u32, 0x10101000u32, 0xc4c4c400u32, 0x00000000u32, 0x48484800u32, 0xa3a3a300u32, 0xf7f7f700u32, 0x75757500u32, 0xdbdbdb00u32, 0x8a8a8a00u32, 0x03030300u32, 0xe6e6e600u32, 0xdadada00u32, 0x09090900u32, 0x3f3f3f00u32, 0xdddddd00u32, 0x94949400u32, 0x87878700u32, 0x5c5c5c00u32, 0x83838300u32, 0x02020200u32, 0xcdcdcd00u32, 0x4a4a4a00u32, 0x90909000u32, 0x33333300u32, 0x73737300u32, 0x67676700u32, 0xf6f6f600u32, 0xf3f3f300u32, 0x9d9d9d00u32, 0x7f7f7f00u32, 0xbfbfbf00u32, 0xe2e2e200u32, 0x52525200u32, 0x9b9b9b00u32, 0xd8d8d800u32, 0x26262600u32, 0xc8c8c800u32, 0x37373700u32, 0xc6c6c600u32, 0x3b3b3b00u32, 0x81818100u32, 0x96969600u32, 0x6f6f6f00u32, 0x4b4b4b00u32, 0x13131300u32, 0xbebebe00u32, 0x63636300u32, 0x2e2e2e00u32, 0xe9e9e900u32, 0x79797900u32, 0xa7a7a700u32, 0x8c8c8c00u32, 0x9f9f9f00u32, 0x6e6e6e00u32, 0xbcbcbc00u32, 0x8e8e8e00u32, 0x29292900u32, 0xf5f5f500u32, 0xf9f9f900u32, 0xb6b6b600u32, 0x2f2f2f00u32, 0xfdfdfd00u32, 0xb4b4b400u32, 0x59595900u32, 0x78787800u32, 0x98989800u32, 0x06060600u32, 0x6a6a6a00u32, 0xe7e7e700u32, 0x46464600u32, 0x71717100u32, 0xbababa00u32, 0xd4d4d400u32, 0x25252500u32, 0xababab00u32, 0x42424200u32, 0x88888800u32, 0xa2a2a200u32, 0x8d8d8d00u32, 0xfafafa00u32, 0x72727200u32, 0x07070700u32, 0xb9b9b900u32, 0x55555500u32, 0xf8f8f800u32, 0xeeeeee00u32, 0xacacac00u32, 0x0a0a0a00u32, 0x36363600u32, 0x49494900u32, 0x2a2a2a00u32, 0x68686800u32, 0x3c3c3c00u32, 0x38383800u32, 0xf1f1f100u32, 0xa4a4a400u32, 0x40404000u32, 0x28282800u32, 0xd3d3d300u32, 0x7b7b7b00u32, 0xbbbbbb00u32, 0xc9c9c900u32, 0x43434300u32, 0xc1c1c100u32, 0x15151500u32, 0xe3e3e300u32, 0xadadad00u32, 0xf4f4f400u32, 0x77777700u32, 0xc7c7c700u32, 0x80808000u32, 0x9e9e9e00u32],
    [0x70700070u32, 0x2c2c002cu32, 0xb3b300b3u32, 0xc0c000c0u32, 0xe4e400e4u32, 0x57570057u32, 0xeaea00eau32, 0xaeae00aeu32, 0x23230023u32, 0x6b6b006bu32, 0x45450045u32, 0xa5a500a5u32, 0xeded00edu32, 0x4f4f004fu32, 0x1d1d001du32, 0x92920092u32, 0x86860086u32, 0xafaf00afu32, 0x7c7c007cu32, 0x1f1f001fu32, 0x3e3e003eu32, 0xdcdc00dcu32, 0x5e5e005eu32, 0x0b0b000bu32, 0xa6a600a6u32, 0x39390039u32, 0xd5d500d5u32, 0x5d5d005du32, 0xd9d900d9u32, 0x5a5a005au32, 0x51510051u32, 0x6c6c006cu32, 0x8b8b008bu32, 0x9a9a009au32, 0xfbfb00fbu32, 0xb0b000b0u32, 0x74740074u32, 0x2b2b002bu32, 0xf0f000f0u32, 0x84840084u32, 0xdfdf00dfu32, 0xcbcb00cbu32, 0x34340034u32, 0x76760076u32, 0x6d6d006du32, 0xa9a900a9u32, 0xd1d100d1u32, 0x04040004u32, 0x14140014u32, 0x3a3a003au32, 0xdede00deu32, 0x11110011u32, 0x32320032u32, 0x9c9c009cu32, 0x53530053u32, 0xf2f200f2u32, 0xfefe00feu32, 0xcfcf00cfu32, 0xc3c300c3u32, 0x7a7a007au32, 0x24240024u32, 0xe8e800e8u32, 0x60600060u32, 0x69690069u32, 0xaaaa00aau32, 0xa0a000a0u32, 0xa1a100a1u32, 0x62620062u32, 0x54540054u32, 0x1e1e001eu32, 0xe0e000e0u32, 0x64640064u32, 0x10100010u32, 0x00000000u32, 0xa3a300a3u32, 0x75750075u32, 0x8a8a008au32, 0xe6e600e6u32, 0x09090009u32, 0xdddd00ddu32, 0x87870087u32, 0x83830083u32, 0xcdcd00cdu32, 0x90900090u32, 0x73730073u32, 0xf6f600f6u32, 0x9d9d009du32, 0xbfbf00bfu32, 0x52520052u32, 0xd8d800d8u32, 0xc8c800c8u32, 0xc6c600c6u32, 0x81810081u32, 0x6f6f006fu32, 0x13130013u32, 0x63630063u32, 0xe9e900e9u32, 0xa7a700a7u32, 0x9f9f009fu32, 0xbcbc00bcu32, 0x29290029u32, 0xf9f900f9u32, 0x2f2f002fu32, 0xb4b400b4u32, 0x78780078u32, 0x06060006u32, 0xe7e700e7u32, 0x71710071u32, 0xd4d400d4u32, 0xabab00abu32, 0x88880088u32, 0x8d8d008du32, 0x72720072u32, 0xb9b900b9u32, 0xf8f800f8u32, 0xacac00acu32, 0x36360036u32, 0x2a2a002au32, 0x3c3c003cu32, 0xf1f100f1u32, 0x40400040u32, 0xd3d300d3u32, 0xbbbb00bbu32, 0x43430043u32, 0x15150015u32, 0xadad00adu32, 0x77770077u32, 0x80800080u32, 0x82820082u32, 0xecec00ecu32, 0x27270027u32, 0xe5e500e5u32, 0x85850085u32, 0x35350035u32, 0x0c0c000cu32, 0x41410041u32, 0xefef00efu32, 0x93930093u32, 0x19190019u32, 0x21210021u32, 0x0e0e000eu32, 0x4e4e004eu32, 0x65650065u32, 0xbdbd00bdu32, 0xb8b800b8u32, 0x8f8f008fu32, 0xebeb00ebu32, 0xcece00ceu32, 0x30300030u32, 0x5f5f005fu32, 0xc5c500c5u32, 0x1a1a001au32, 0xe1e100e1u32, 0xcaca00cau32, 0x47470047u32, 0x3d3d003du32, 0x01010001u32, 0xd6d600d6u32, 0x56560056u32, 0x4d4d004du32, 0x0d0d000du32, 0x66660066u32, 0xcccc00ccu32, 0x2d2d002du32, 0x12120012u32, 0x20200020u32, 0xb1b100b1u32, 0x99990099u32, 0x4c4c004cu32, 0xc2c200c2u32, 0x7e7e007eu32, 0x05050005u32, 0xb7b700b7u32, 0x31310031u32, 0x17170017u32, 0xd7d700d7u32, 0x58580058u32, 0x61610061u32, 0x1b1b001bu32, 0x1c1c001cu32, 0x0f0f000fu32, 0x16160016u32, 0x18180018u32, 0x22220022u32, 0x44440044u32, 0xb2b200b2u32, 0xb5b500b5u32, 0x91910091u32, 0x08080008u32, 0xa8a800a8u32, 0xfcfc00fcu32, 0x50500050u32, 0xd0d000d0u32, 0x7d7d007du32, 0x89890089u32, 0x97970097u32, 0x5b5b005bu32, 0x95950095u32, 0xffff00ffu32, 0xd2d200d2u32, 0xc4c400c4u32, 0x48480048u32, 0xf7f700f7u32, 0xdbdb00dbu32, 0x03030003u32, 0xdada00dau32, 0x3f3f003fu32, 0x94940094u32, 0x5c5c005cu32, 0x02020002u32, 0x4a4a004au32, 0x33330033u32, 0x67670067u32, 0xf3f300f3u32, 0x7f7f007fu32, 0xe2e200e2u32, 0x9b9b009bu32, 0x26260026u32, 0x37370037u32, 0x3b3b003bu32, 0x96960096u32, 0x4b4b004bu32, 0xbebe00beu32, 0x2e2e002eu32, 0x79790079u32, 0x8c8c008cu32, 0x6e6e006eu32, 0x8e8e008eu32, 0xf5f500f5u32, 0xb6b600b6u32, 0xfdfd00fdu32, 0x59590059u32, 0x98980098u32, 0x6a6a006au32, 0x46460046u32, 0xbaba00bau32, 0x25250025u32, 0x42420042u32, 0xa2a200a2u32, 0xfafa00fau32, 0x07070007u32, 0x55550055u32, 0xeeee00eeu32, 0x0a0a000au32, 0x49490049u32, 0x68680068u32, 0x38380038u32, 0xa4a400a4u32, 0x28280028u32, 0x7b7b007bu32, 0xc9c900c9u32, 0xc1c100c1u32, 0xe3e300e3u32, 0xf4f400f4u32, 0xc7c700c7u32, 0x9e9e009eu32],
    [0x00e0e0e0u32, 0x00050505u32, 0x00585858u32, 0x00d9d9d9u32, 0x00676767u32, 0x004e4e4eu32, 0x00818181u32, 0x00cbcbcbu32, 0x00c9c9c9u32, 0x000b0b0bu32, 0x00aeaeaeu32, 0x006a6a6au32, 0x00d5d5d5u32, 0x00181818u32, 0x005d5d5du32, 0x00828282u32, 0x00464646u32, 0x00dfdfdfu32, 0x00d6d6d6u32, 0x00272727u32, 0x008a8a8au32, 0x00323232u32, 0x004b4b4bu32, 0x00424242u32, 0x00dbdbdbu32, 0x001c1c1cu32, 0x009e9e9eu32, 0x009c9c9cu32, 0x003a3a3au32, 0x00cacacau32, 0x00252525u32, 0x007b7b7bu32, 0x000d0d0du32, 0x00717171u32, 0x005f5f5fu32, 0x001f1f1fu32, 0x00f8f8f8u32, 0x00d7d7d7u32, 0x003e3e3eu32, 0x009d9d9du32, 0x007c7c7cu32, 0x00606060u32, 0x00b9b9b9u32, 0x00bebebeu32, 0x00bcbcbcu32, 0x008b8b8bu32, 0x00161616u32, 0x00343434u32, 0x004d4d4du32, 0x00c3c3c3u32, 0x00727272u32, 0x00959595u32, 0x00abababu32, 0x008e8e8eu32, 0x00bababau32, 0x007a7a7au32, 0x00b3b3b3u32, 0x00020202u32, 0x00b4b4b4u32, 0x00adadadu32, 0x00a2a2a2u32, 0x00acacacu32, 0x00d8d8d8u32, 0x009a9a9au32, 0x00171717u32, 0x001a1a1au32, 0x00353535u32, 0x00ccccccu32, 0x00f7f7f7u32, 0x00999999u32, 0x00616161u32, 0x005a5a5au32, 0x00e8e8e8u32, 0x00242424u32, 0x00565656u32, 0x00404040u32, 0x00e1e1e1u32, 0x00636363u32, 0x00090909u32, 0x00333333u32, 0x00bfbfbfu32, 0x00989898u32, 0x00979797u32, 0x00858585u32, 0x00686868u32, 0x00fcfcfcu32, 0x00ecececu32, 0x000a0a0au32, 0x00dadadau32, 0x006f6f6fu32, 0x00535353u32, 0x00626262u32, 0x00a3a3a3u32, 0x002e2e2eu32, 0x00080808u32, 0x00afafafu32, 0x00282828u32, 0x00b0b0b0u32, 0x00747474u32, 0x00c2c2c2u32, 0x00bdbdbdu32, 0x00363636u32, 0x00222222u32, 0x00383838u32, 0x00646464u32, 0x001e1e1eu32, 0x00393939u32, 0x002c2c2cu32, 0x00a6a6a6u32, 0x00303030u32, 0x00e5e5e5u32, 0x00444444u32, 0x00fdfdfdu32, 0x00888888u32, 0x009f9f9fu32, 0x00656565u32, 0x00878787u32, 0x006b6b6bu32, 0x00f4f4f4u32, 0x00232323u32, 0x00484848u32, 0x00101010u32, 0x00d1d1d1u32, 0x00515151u32, 0x00c0c0c0u32, 0x00f9f9f9u32, 0x00d2d2d2u32, 0x00a0a0a0u32, 0x00555555u32, 0x00a1a1a1u32, 0x00414141u32, 0x00fafafau32, 0x00434343u32, 0x00131313u32, 0x00c4c4c4u32, 0x002f2f2fu32, 0x00a8a8a8u32, 0x00b6b6b6u32, 0x003c3c3cu32, 0x002b2b2bu32, 0x00c1c1c1u32, 0x00ffffffu32, 0x00c8c8c8u32, 0x00a5a5a5u32, 0x00202020u32, 0x00898989u32, 0x00000000u32, 0x00909090u32, 0x00474747u32, 0x00efefefu32, 0x00eaeaeau32, 0x00b7b7b7u32, 0x00151515u32, 0x00060606u32, 0x00cdcdcdu32, 0x00b5b5b5u32, 0x00121212u32, 0x007e7e7eu32, 0x00bbbbbbu32, 0x00292929u32, 0x000f0f0fu32, 0x00b8b8b8u32, 0x00070707u32, 0x00040404u32, 0x009b9b9bu32, 0x00949494u32, 0x00212121u32, 0x00666666u32, 0x00e6e6e6u32, 0x00cececeu32, 0x00edededu32, 0x00e7e7e7u32, 0x003b3b3bu32, 0x00fefefeu32, 0x007f7f7fu32, 0x00c5c5c5u32, 0x00a4a4a4u32, 0x00373737u32, 0x00b1b1b1u32, 0x004c4c4cu32, 0x00919191u32, 0x006e6e6eu32, 0x008d8d8du32, 0x00767676u32, 0x00030303u32, 0x002d2d2du32, 0x00dededeu32, 0x00969696u32, 0x00262626u32, 0x007d7d7du32, 0x00c6c6c6u32, 0x005c5c5cu32, 0x00d3d3d3u32, 0x00f2f2f2u32, 0x004f4f4fu32, 0x00191919u32, 0x003f3f3fu32, 0x00dcdcdcu32, 0x00797979u32, 0x001d1d1du32, 0x00525252u32, 0x00ebebebu32, 0x00f3f3f3u32, 0x006d6d6du32, 0x005e5e5eu32, 0x00fbfbfbu32, 0x00696969u32, 0x00b2b2b2u32, 0x00f0f0f0u32, 0x00313131u32, 0x000c0c0cu32, 0x00d4d4d4u32, 0x00cfcfcfu32, 0x008c8c8cu32, 0x00e2e2e2u32, 0x00757575u32, 0x00a9a9a9u32, 0x004a4a4au32, 0x00575757u32, 0x00848484u32, 0x00111111u32, 0x00454545u32, 0x001b1b1bu32, 0x00f5f5f5u32, 0x00e4e4e4u32, 0x000e0e0eu32, 0x00737373u32, 0x00aaaaaau32, 0x00f1f1f1u32, 0x00ddddddu32, 0x00595959u32, 0x00141414u32, 0x006c6c6cu32, 0x00929292u32, 0x00545454u32, 0x00d0d0d0u32, 0x00787878u32, 0x00707070u32, 0x00e3e3e3u32, 0x00494949u32, 0x00808080u32, 0x00505050u32, 0x00a7a7a7u32, 0x00f6f6f6u32, 0x00777777u32, 0x00939393u32, 0x00868686u32, 0x00838383u32, 0x002a2a2au32, 0x00c7c7c7u32, 0x005b5b5bu32, 0x00e9e9e9u32, 0x00eeeeeeu32, 0x008f8f8fu32, 0x00010101u32, 0x003d3d3du32],
    [0x38003838u32, 0x41004141u32, 0x16001616u32, 0x76007676u32, 0xd900d9d9u32, 0x93009393u32, 0x60006060u32, 0xf200f2f2u32, 0x72007272u32, 0xc200c2c2u32, 0xab00ababu32, 0x9a009a9au32, 0x75007575u32, 0x06000606u32, 0x57005757u32, 0xa000a0a0u32, 0x91009191u32, 0xf700f7f7u32, 0xb500b5b5u32, 0xc900c9c9u32, 0xa200a2a2u32, 0x8c008c8cu32, 0xd200d2d2u32, 0x90009090u32, 0xf600f6f6u32, 0x07000707u32, 0xa700a7a7u32, 0x27002727u32, 0x8e008e8eu32, 0xb200b2b2u32, 0x49004949u32, 0xde00dedeu32, 0x43004343u32, 0x5c005c5cu32, 0xd700d7d7u32, 0xc700c7c7u32, 0x3e003e3eu32, 0xf500f5f5u32, 0x8f008f8fu32, 0x67006767u32, 0x1f001f1fu32, 0x18001818u32, 0x6e006e6eu32, 0xaf00afafu32, 0x2f002f2fu32, 0xe200e2e2u32, 0x85008585u32, 0x0d000d0du32, 0x53005353u32, 0xf000f0f0u32, 0x9c009c9cu32, 0x65006565u32, 0xea00eaeau32, 0xa300a3a3u32, 0xae00aeaeu32, 0x9e009e9eu32, 0xec00ececu32, 0x80008080u32, 0x2d002d2du32, 0x6b006b6bu32, 0xa800a8a8u32, 0x2b002b2bu32, 0x36003636u32, 0xa600a6a6u32, 0xc500c5c5u32, 0x86008686u32, 0x4d004d4du32, 0x33003333u32, 0xfd00fdfdu32, 0x66006666u32, 0x58005858u32, 0x96009696u32, 0x3a003a3au32, 0x09000909u32, 0x95009595u32, 0x10001010u32, 0x78007878u32, 0xd800d8d8u32, 0x42004242u32, 0xcc00ccccu32, 0xef00efefu32, 0x26002626u32, 0xe500e5e5u32, 0x61006161u32, 0x1a001a1au32, 0x3f003f3fu32, 0x3b003b3bu32, 0x82008282u32, 0xb600b6b6u32, 0xdb00dbdbu32, 0xd400d4d4u32, 0x98009898u32, 0xe800e8e8u32, 0x8b008b8bu32, 0x02000202u32, 0xeb00ebebu32, 0x0a000a0au32, 0x2c002c2cu32, 0x1d001d1du32, 0xb000b0b0u32, 0x6f006f6fu32, 0x8d008d8du32, 0x88008888u32, 0x0e000e0eu32, 0x19001919u32, 0x87008787u32, 0x4e004e4eu32, 0x0b000b0bu32, 0xa900a9a9u32, 0x0c000c0cu32, 0x79007979u32, 0x11001111u32, 0x7f007f7fu32, 0x22002222u32, 0xe700e7e7u32, 0x59005959u32, 0xe100e1e1u32, 0xda00dadau32, 0x3d003d3du32, 0xc800c8c8u32, 0x12001212u32, 0x04000404u32, 0x74007474u32, 0x54005454u32, 0x30003030u32, 0x7e007e7eu32, 0xb400b4b4u32, 0x28002828u32, 0x55005555u32, 0x68006868u32, 0x50005050u32, 0xbe00bebeu32, 0xd000d0d0u32, 0xc400c4c4u32, 0x31003131u32, 0xcb00cbcbu32, 0x2a002a2au32, 0xad00adadu32, 0x0f000f0fu32, 0xca00cacau32, 0x70007070u32, 0xff00ffffu32, 0x32003232u32, 0x69006969u32, 0x08000808u32, 0x62006262u32, 0x00000000u32, 0x24002424u32, 0xd100d1d1u32, 0xfb00fbfbu32, 0xba00babau32, 0xed00ededu32, 0x45004545u32, 0x81008181u32, 0x73007373u32, 0x6d006d6du32, 0x84008484u32, 0x9f009f9fu32, 0xee00eeeeu32, 0x4a004a4au32, 0xc300c3c3u32, 0x2e002e2eu32, 0xc100c1c1u32, 0x01000101u32, 0xe600e6e6u32, 0x25002525u32, 0x48004848u32, 0x99009999u32, 0xb900b9b9u32, 0xb300b3b3u32, 0x7b007b7bu32, 0xf900f9f9u32, 0xce00ceceu32, 0xbf00bfbfu32, 0xdf00dfdfu32, 0x71007171u32, 0x29002929u32, 0xcd00cdcdu32, 0x6c006c6cu32, 0x13001313u32, 0x64006464u32, 0x9b009b9bu32, 0x63006363u32, 0x9d009d9du32, 0xc000c0c0u32, 0x4b004b4bu32, 0xb700b7b7u32, 0xa500a5a5u32, 0x89008989u32, 0x5f005f5fu32, 0xb100b1b1u32, 0x17001717u32, 0xf400f4f4u32, 0xbc00bcbcu32, 0xd300d3d3u32, 0x46004646u32, 0xcf00cfcfu32, 0x37003737u32, 0x5e005e5eu32, 0x47004747u32, 0x94009494u32, 0xfa00fafau32, 0xfc00fcfcu32, 0x5b005b5bu32, 0x97009797u32, 0xfe00fefeu32, 0x5a005a5au32, 0xac00acacu32, 0x3c003c3cu32, 0x4c004c4cu32, 0x03000303u32, 0x35003535u32, 0xf300f3f3u32, 0x23002323u32, 0xb800b8b8u32, 0x5d005d5du32, 0x6a006a6au32, 0x92009292u32, 0xd500d5d5u32, 0x21002121u32, 0x44004444u32, 0x51005151u32, 0xc600c6c6u32, 0x7d007d7du32, 0x39003939u32, 0x83008383u32, 0xdc00dcdcu32, 0xaa00aaaau32, 0x7c007c7cu32, 0x77007777u32, 0x56005656u32, 0x05000505u32, 0x1b001b1bu32, 0xa400a4a4u32, 0x15001515u32, 0x34003434u32, 0x1e001e1eu32, 0x1c001c1cu32, 0xf800f8f8u32, 0x52005252u32, 0x20002020u32, 0x14001414u32, 0xe900e9e9u32, 0xbd00bdbdu32, 0xdd00ddddu32, 0xe400e4e4u32, 0xa100a1a1u32, 0xe000e0e0u32, 0x8a008a8au32, 0xf100f1f1u32, 0xd600d6d6u32, 0x7a007a7au32, 0xbb00bbbbu32, 0xe300e3e3u32, 0x40004040u32, 0x4f004f4fu32]
  ]
  Sigma*: array[12, uint32] = [0xa09e667fu32, 0x3bcc908bu32, 0xb67ae858u32, 0x4caa73b2u32, 0xc6ef372fu32, 0xe94f82beu32, 0x54ff53a5u32, 0xf1d36f1cu32, 0x10e527fau32, 0xde682d1du32, 0xb05688c2u32, 0xb3e6c1fdu32]

func rol32(x: uint32; n: int): uint32 {.inline.} =
  rotateLeftBits(x, n and 31)

func ror32(x: uint32; n: int): uint32 {.inline.} =
  rotateRightBits(x, n and 31)

template rotLeft128(s0, s1, s2, s3: var uint32; n: int) =
  let r = 32 - n
  let t0 = s0 shr r
  s0 = (s0 shl n) or (s1 shr r)
  s1 = (s1 shl n) or (s2 shr r)
  s2 = (s2 shl n) or (s3 shr r)
  s3 = (s3 shl n) or t0

template feistel(s0, s1, s2, s3: var uint32; table: untyped; offset: int) =
  var t0 = s0 xor table[offset]
  var t3 = CamelliaSBox[1][int(t0 and 0xff'u32)]
  var t1 = s1 xor table[offset + 1]
  t3 = t3 xor CamelliaSBox[3][int((t0 shr 8) and 0xff'u32)]
  var t2 = CamelliaSBox[0][int(t1 and 0xff'u32)]
  t3 = t3 xor CamelliaSBox[2][int((t0 shr 16) and 0xff'u32)]
  t2 = t2 xor CamelliaSBox[1][int((t1 shr 8) and 0xff'u32)]
  t3 = t3 xor CamelliaSBox[0][int(t0 shr 24)]
  t2 = t2 xor t3
  t3 = ror32(t3, 8)
  t2 = t2 xor CamelliaSBox[3][int((t1 shr 16) and 0xff'u32)]
  s3 = s3 xor t3
  t2 = t2 xor CamelliaSBox[2][int(t1 shr 24)]
  s2 = s2 xor t2
  s3 = s3 xor t2

func loadU32BE(data: openArray[byte]; offset: int): uint32 {.inline.} =
  doAssert offset + 4 <= data.len
  (uint32(data[offset]) shl 24) xor
    (uint32(data[offset + 1]) shl 16) xor
    (uint32(data[offset + 2]) shl 8) xor
    uint32(data[offset + 3])

proc storeU32BE(data: var openArray[byte]; offset: int; value: uint32) {.inline.} =
  doAssert offset + 4 <= data.len
  data[offset] = byte(value shr 24)
  data[offset + 1] = byte((value shr 16) and 0xff'u32)
  data[offset + 2] = byte((value shr 8) and 0xff'u32)
  data[offset + 3] = byte(value and 0xff'u32)

proc camelliaEKeygen*(bits: int; rawKey: openArray[byte]; k: var KeyTable): int =
  doAssert rawKey.len >= 16
  var s0 = loadU32BE(rawKey, 0)
  var s1 = loadU32BE(rawKey, 4)
  var s2 = loadU32BE(rawKey, 8)
  var s3 = loadU32BE(rawKey, 12)

  k[0] = s0
  k[1] = s1
  k[2] = s2
  k[3] = s3

  if bits != 128:
    doAssert rawKey.len >= 24
    var r0 = loadU32BE(rawKey, 16)
    var r1 = loadU32BE(rawKey, 20)
    s0 = r0
    s1 = r1
    k[8] = r0
    k[9] = r1

    var r2, r3: uint32
    if bits == 192:
      r2 = not r0
      r3 = not r1
    else:
      doAssert rawKey.len >= 32
      r2 = loadU32BE(rawKey, 24)
      r3 = loadU32BE(rawKey, 28)
    s2 = r2
    s3 = r3
    k[10] = r2
    k[11] = r3

    s0 = s0 xor k[0]
    s1 = s1 xor k[1]
    s2 = s2 xor k[2]
    s3 = s3 xor k[3]

  feistel(s0, s1, s2, s3, Sigma, 0)
  feistel(s2, s3, s0, s1, Sigma, 2)

  s0 = s0 xor k[0]
  s1 = s1 xor k[1]
  s2 = s2 xor k[2]
  s3 = s3 xor k[3]

  feistel(s0, s1, s2, s3, Sigma, 4)
  feistel(s2, s3, s0, s1, Sigma, 6)

  if bits == 128:
    k[4] = s0
    k[5] = s1
    k[6] = s2
    k[7] = s3
    rotLeft128(s0, s1, s2, s3, 15)
    k[12] = s0
    k[13] = s1
    k[14] = s2
    k[15] = s3
    rotLeft128(s0, s1, s2, s3, 15)
    k[16] = s0
    k[17] = s1
    k[18] = s2
    k[19] = s3
    rotLeft128(s0, s1, s2, s3, 15)
    k[24] = s0
    k[25] = s1
    rotLeft128(s0, s1, s2, s3, 15)
    k[28] = s0
    k[29] = s1
    k[30] = s2
    k[31] = s3
    rotLeft128(s1, s2, s3, s0, 2)
    k[40] = s1
    k[41] = s2
    k[42] = s3
    k[43] = s0
    rotLeft128(s1, s2, s3, s0, 17)
    k[48] = s1
    k[49] = s2
    k[50] = s3
    k[51] = s0

    s0 = k[0]
    s1 = k[1]
    s2 = k[2]
    s3 = k[3]
    rotLeft128(s0, s1, s2, s3, 15)
    k[8] = s0
    k[9] = s1
    k[10] = s2
    k[11] = s3
    rotLeft128(s0, s1, s2, s3, 30)
    k[20] = s0
    k[21] = s1
    k[22] = s2
    k[23] = s3
    rotLeft128(s0, s1, s2, s3, 15)
    k[26] = s2
    k[27] = s3
    rotLeft128(s0, s1, s2, s3, 17)
    k[32] = s0
    k[33] = s1
    k[34] = s2
    k[35] = s3
    rotLeft128(s0, s1, s2, s3, 17)
    k[36] = s0
    k[37] = s1
    k[38] = s2
    k[39] = s3
    rotLeft128(s0, s1, s2, s3, 17)
    k[44] = s0
    k[45] = s1
    k[46] = s2
    k[47] = s3

    return 3

  k[12] = s0
  k[13] = s1
  k[14] = s2
  k[15] = s3
  s0 = s0 xor k[8]
  s1 = s1 xor k[9]
  s2 = s2 xor k[10]
  s3 = s3 xor k[11]
  feistel(s0, s1, s2, s3, Sigma, 8)
  feistel(s2, s3, s0, s1, Sigma, 10)

  k[4] = s0
  k[5] = s1
  k[6] = s2
  k[7] = s3
  rotLeft128(s0, s1, s2, s3, 30)
  k[20] = s0
  k[21] = s1
  k[22] = s2
  k[23] = s3
  rotLeft128(s0, s1, s2, s3, 30)
  k[40] = s0
  k[41] = s1
  k[42] = s2
  k[43] = s3
  rotLeft128(s1, s2, s3, s0, 19)
  k[64] = s1
  k[65] = s2
  k[66] = s3
  k[67] = s0

  s0 = k[8]
  s1 = k[9]
  s2 = k[10]
  s3 = k[11]
  rotLeft128(s0, s1, s2, s3, 15)
  k[8] = s0
  k[9] = s1
  k[10] = s2
  k[11] = s3
  rotLeft128(s0, s1, s2, s3, 15)
  k[16] = s0
  k[17] = s1
  k[18] = s2
  k[19] = s3
  rotLeft128(s0, s1, s2, s3, 30)
  k[36] = s0
  k[37] = s1
  k[38] = s2
  k[39] = s3
  rotLeft128(s1, s2, s3, s0, 2)
  k[52] = s1
  k[53] = s2
  k[54] = s3
  k[55] = s0

  s0 = k[12]
  s1 = k[13]
  s2 = k[14]
  s3 = k[15]
  rotLeft128(s0, s1, s2, s3, 15)
  k[12] = s0
  k[13] = s1
  k[14] = s2
  k[15] = s3
  rotLeft128(s0, s1, s2, s3, 30)
  k[28] = s0
  k[29] = s1
  k[30] = s2
  k[31] = s3
  k[48] = s1
  k[49] = s2
  k[50] = s3
  k[51] = s0
  rotLeft128(s1, s2, s3, s0, 17)
  k[56] = s1
  k[57] = s2
  k[58] = s3
  k[59] = s0

  s0 = k[0]
  s1 = k[1]
  s2 = k[2]
  s3 = k[3]
  rotLeft128(s1, s2, s3, s0, 13)
  k[24] = s1
  k[25] = s2
  k[26] = s3
  k[27] = s0
  rotLeft128(s1, s2, s3, s0, 15)
  k[32] = s1
  k[33] = s2
  k[34] = s3
  k[35] = s0
  rotLeft128(s1, s2, s3, s0, 17)
  k[44] = s1
  k[45] = s2
  k[46] = s3
  k[47] = s0
  rotLeft128(s2, s3, s0, s1, 2)
  k[60] = s2
  k[61] = s3
  k[62] = s0
  k[63] = s1

  4

proc camelliaEncryptBlock*(grandRounds: int; plaintext: openArray[byte];
                          keyTable: openArray[uint32]; ciphertext: var openArray[byte]) =
  doAssert plaintext.len >= BlockSize
  doAssert ciphertext.len >= BlockSize
  var s0 = loadU32BE(plaintext, 0) xor keyTable[0]
  var s1 = loadU32BE(plaintext, 4) xor keyTable[1]
  var s2 = loadU32BE(plaintext, 8) xor keyTable[2]
  var s3 = loadU32BE(plaintext, 12) xor keyTable[3]
  var offset = 4
  let endOffset = grandRounds * 16

  while true:
    feistel(s0, s1, s2, s3, keyTable, offset)
    feistel(s2, s3, s0, s1, keyTable, offset + 2)
    feistel(s0, s1, s2, s3, keyTable, offset + 4)
    feistel(s2, s3, s0, s1, keyTable, offset + 6)
    feistel(s0, s1, s2, s3, keyTable, offset + 8)
    feistel(s2, s3, s0, s1, keyTable, offset + 10)
    offset += 12
    if offset == endOffset:
      break
    s1 = s1 xor rol32(s0 and keyTable[offset], 1)
    s2 = s2 xor (s3 or keyTable[offset + 3])
    s0 = s0 xor (s1 or keyTable[offset + 1])
    s3 = s3 xor rol32(s2 and keyTable[offset + 2], 1)
    offset += 4

  let finalOff = offset
  s2 = s2 xor keyTable[finalOff]
  s3 = s3 xor keyTable[finalOff + 1]
  s0 = s0 xor keyTable[finalOff + 2]
  s1 = s1 xor keyTable[finalOff + 3]

  storeU32BE(ciphertext, 0, s2)
  storeU32BE(ciphertext, 4, s3)
  storeU32BE(ciphertext, 8, s0)
  storeU32BE(ciphertext, 12, s1)

proc camelliaDecryptBlock*(grandRounds: int; ciphertext: openArray[byte];
                          keyTable: openArray[uint32]; plaintext: var openArray[byte]) =
  doAssert ciphertext.len >= BlockSize
  doAssert plaintext.len >= BlockSize
  var offset = grandRounds * 16
  var s0 = loadU32BE(ciphertext, 0) xor keyTable[offset]
  var s1 = loadU32BE(ciphertext, 4) xor keyTable[offset + 1]
  var s2 = loadU32BE(ciphertext, 8) xor keyTable[offset + 2]
  var s3 = loadU32BE(ciphertext, 12) xor keyTable[offset + 3]
  let endOffset = 4

  while true:
    offset -= 12
    feistel(s0, s1, s2, s3, keyTable, offset + 10)
    feistel(s2, s3, s0, s1, keyTable, offset + 8)
    feistel(s0, s1, s2, s3, keyTable, offset + 6)
    feistel(s2, s3, s0, s1, keyTable, offset + 4)
    feistel(s0, s1, s2, s3, keyTable, offset + 2)
    feistel(s2, s3, s0, s1, keyTable, offset)
    if offset == endOffset:
      break
    offset -= 4
    s1 = s1 xor rol32(s0 and keyTable[offset + 2], 1)
    s2 = s2 xor (s3 or keyTable[offset + 1])
    s0 = s0 xor (s1 or keyTable[offset + 3])
    s3 = s3 xor rol32(s2 and keyTable[offset], 1)

  offset -= 4
  s2 = s2 xor keyTable[offset]
  s3 = s3 xor keyTable[offset + 1]
  s0 = s0 xor keyTable[offset + 2]
  s1 = s1 xor keyTable[offset + 3]

  storeU32BE(plaintext, 0, s2)
  storeU32BE(plaintext, 4, s3)
  storeU32BE(plaintext, 8, s0)
  storeU32BE(plaintext, 12, s1)
