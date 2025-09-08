import 'dart:typed_data';
import 'dart:math';
import 'package:hex/hex.dart';

// Assuming these are in your project structure
// import '../frames/quic_frame.dart';
import '../payload_parser9.dart';
import '../protocol.dart';
import '../initial_aead.dart';

void unprotectAndParseInitialPacket(Uint8List packetBytes) {
  print('\n--- Parsing the QUIC Initial Packet ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version

  final dcidLen = mutablePacket[offset];
  offset += 1;
  final dcid = Uint8List.view(buffer, offset, dcidLen);
  offset += dcidLen;
  print("Connection id: ${HEX.encode(dcid)}");

  offset += 1 + mutablePacket[offset]; // Skip SCID
  offset += 1; // Skip Token Len

  // 1. Correctly parse the length field from the header.
  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;

  final (_, opener) = newInitialAEAD(
    dcid,
    Perspective.server,
    Version.version1,
  );

  final sample = Uint8List.view(buffer, pnOffset + 4, 16);

  // 2. Decrypt ONLY the first byte
  final firstByteView = Uint8List.view(buffer, 0, 1);
  firstByteView[0] ^= opener.mask[0] & 0x0f;
  // final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 1);

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  print("Decoded Packet Number: $wirePn");

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final associatedData = Uint8List.view(buffer, 0, payloadOffset);

  // 2. THE FIX: Use the `lengthField` to get the exact ciphertext length.
  final ciphertext = Uint8List.view(
    buffer,
    payloadOffset,
    lengthField - pnLength,
  );

  final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
  print('✅ **Payload decrypted successfully!**');
  print(
    '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...**',
  );
  // print(plaintext);
  parsePayload(plaintext);
}

void main() {
  unprotectAndParseInitialPacket(quicIntialPacket);
}

final expectedPacket = splitHexString(
  "c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11 d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399 1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c 8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212 30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5 457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208 4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec 4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3 485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db 059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c 7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8 9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556 be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74 68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00 f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632 291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964 25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd 14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198 e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73 203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047 90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2 162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4 40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0 6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e 8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0 be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400 54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab 760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9 f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4 056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064 7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241 e221af44860018ab0856972e194cd934",
);

final quicIntialPacket = Uint8List.fromList([
  0xcd,
  0x00,
  0x00,
  0x00,
  0x01,
  0x08,
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x05,
  0x63,
  0x5f,
  0x63,
  0x69,
  0x64,
  0x00,
  0x41,
  0x03,
  0x98,
  0x1c,
  0x36,
  0xa7,
  0xed,
  0x78,
  0x71,
  0x6b,
  0xe9,
  0x71,
  0x1b,
  0xa4,
  0x98,
  0xb7,
  0xed,
  0x86,
  0x84,
  0x43,
  0xbb,
  0x2e,
  0x0c,
  0x51,
  0x4d,
  0x4d,
  0x84,
  0x8e,
  0xad,
  0xcc,
  0x7a,
  0x00,
  0xd2,
  0x5c,
  0xe9,
  0xf9,
  0xaf,
  0xa4,
  0x83,
  0x97,
  0x80,
  0x88,
  0xde,
  0x83,
  0x6b,
  0xe6,
  0x8c,
  0x0b,
  0x32,
  0xa2,
  0x45,
  0x95,
  0xd7,
  0x81,
  0x3e,
  0xa5,
  0x41,
  0x4a,
  0x91,
  0x99,
  0x32,
  0x9a,
  0x6d,
  0x9f,
  0x7f,
  0x76,
  0x0d,
  0xd8,
  0xbb,
  0x24,
  0x9b,
  0xf3,
  0xf5,
  0x3d,
  0x9a,
  0x77,
  0xfb,
  0xb7,
  0xb3,
  0x95,
  0xb8,
  0xd6,
  0x6d,
  0x78,
  0x79,
  0xa5,
  0x1f,
  0xe5,
  0x9e,
  0xf9,
  0x60,
  0x1f,
  0x79,
  0x99,
  0x8e,
  0xb3,
  0x56,
  0x8e,
  0x1f,
  0xdc,
  0x78,
  0x9f,
  0x64,
  0x0a,
  0xca,
  0xb3,
  0x85,
  0x8a,
  0x82,
  0xef,
  0x29,
  0x30,
  0xfa,
  0x5c,
  0xe1,
  0x4b,
  0x5b,
  0x9e,
  0xa0,
  0xbd,
  0xb2,
  0x9f,
  0x45,
  0x72,
  0xda,
  0x85,
  0xaa,
  0x3d,
  0xef,
  0x39,
  0xb7,
  0xef,
  0xaf,
  0xff,
  0xa0,
  0x74,
  0xb9,
  0x26,
  0x70,
  0x70,
  0xd5,
  0x0b,
  0x5d,
  0x07,
  0x84,
  0x2e,
  0x49,
  0xbb,
  0xa3,
  0xbc,
  0x78,
  0x7f,
  0xf2,
  0x95,
  0xd6,
  0xae,
  0x3b,
  0x51,
  0x43,
  0x05,
  0xf1,
  0x02,
  0xaf,
  0xe5,
  0xa0,
  0x47,
  0xb3,
  0xfb,
  0x4c,
  0x99,
  0xeb,
  0x92,
  0xa2,
  0x74,
  0xd2,
  0x44,
  0xd6,
  0x04,
  0x92,
  0xc0,
  0xe2,
  0xe6,
  0xe2,
  0x12,
  0xce,
  0xf0,
  0xf9,
  0xe3,
  0xf6,
  0x2e,
  0xfd,
  0x09,
  0x55,
  0xe7,
  0x1c,
  0x76,
  0x8a,
  0xa6,
  0xbb,
  0x3c,
  0xd8,
  0x0b,
  0xbb,
  0x37,
  0x55,
  0xc8,
  0xb7,
  0xeb,
  0xee,
  0x32,
  0x71,
  0x2f,
  0x40,
  0xf2,
  0x24,
  0x51,
  0x19,
  0x48,
  0x70,
  0x21,
  0xb4,
  0xb8,
  0x4e,
  0x15,
  0x65,
  0xe3,
  0xca,
  0x31,
  0x96,
  0x7a,
  0xc8,
  0x60,
  0x4d,
  0x40,
  0x32,
  0x17,
  0x0d,
  0xec,
  0x28,
  0x0a,
  0xee,
  0xfa,
  0x09,
  0x5d,
  0x08,
  0xb3,
  0xb7,
  0x24,
  0x1e,
  0xf6,
  0x64,
  0x6a,
  0x6c,
  0x86,
  0xe5,
  0xc6,
  0x2c,
  0xe0,
  0x8b,
  0xe0,
  0x99,
]);
