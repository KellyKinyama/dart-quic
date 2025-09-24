import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:collection/collection.dart'; // Add this to your pubspec.yaml if not present
import 'package:hex/hex.dart';

import '../payload_parser_final.dart';
import '../protocol.dart';
import '../initial_aead.dart';

/// Verifies the entire client-side sealing and protection process against a known packet vector.
Uint8List testClientInitialProtection() {
  print('\n--- Running Test: Client Initial Packet Protection Vector ---');
  final connID = splitHexString('0x8394c8f03e515708');
  final version = Version.version1;
  final header = splitHexString("c300000001088394c8f03e5157080000449e00000002");
  final data = splitHexString(
    "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868 04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578 616d706c652e636f6dff01000100000a 00080006001d00170018001000070005 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400 0d0010000e0403050306030203080408 050806002d00020101001c0002400100 3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000 75300901100f088394c8f03e51570806 048000ffff",
  );
  final expectedSample = splitHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
  final expectedHdrFirstByte = 0xc0;
  final expectedHdrPnBytes = splitHexString("7b9aec34");
  final expectedPacket = splitHexString(
    "c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11 d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399 1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c 8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212 30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5 457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208 4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec 4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3 485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db 059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c 7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8 9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556 be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74 68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00 f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632 291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964 25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd 14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198 e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73 203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047 90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2 162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4 40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0 6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e 8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0 be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400 54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab 760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9 f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4 056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064 7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241 e221af44860018ab0856972e194cd934",
  );

  // 1. Create client sealer
  final (sealer, opener) = newInitialAEAD(connID, Perspective.client, version);

  // 2. Pad data to the required minimum length for an Initial packet
  final paddedDataBuilder = BytesBuilder()..add(data);
  if (paddedDataBuilder.length < 1162) {
    paddedDataBuilder.add(Uint8List(1162 - paddedDataBuilder.length));
  }
  final paddedData = paddedDataBuilder.toBytes();

  // 3. Seal the payload
  final sealed = sealer.seal(paddedData, 2, header);

  // 4. Extract and verify the sample used for header protection
  // Note: this test vector uses a simplified sample location (first 16 bytes).
  final sample = sealed.sublist(0, 16);
  // _expectEquals(sample, expectedSample, 'Client Packet Sample');

  print('Client Packet Sample');
  print("Got:      $sample");
  print("Expected: $expectedSample");
  print("");

  // 5. Encrypt the header and verify its protected parts
  final protectedHeader = Uint8List.fromList(header);
  final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
  final pnView = Uint8List.view(
    protectedHeader.buffer,
    protectedHeader.length - 4,
    4,
  );
  sealer.encryptHeader(sample, firstByteView, pnView);

  print('Protected First Byte');
  print("Got:      ${protectedHeader[0]}");
  print("Expected: $expectedHdrFirstByte");
  print("");

  print('Protected Packet Number');
  print("Got:      $pnView");
  print("Expected: $expectedHdrPnBytes");
  print("");

  // 6. Assemble and verify the final, full packet
  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealed);

  // _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
  // print('Final Client Packet');
  // print("Got:      ${finalPacket.toBytes()}");
  print("Expected: $expectedPacket");
  print("");

  return finalPacket.toBytes();
}

Uint8List testServersInitial() {
  final connID = splitHexString("8394c8f03e515708");

  // name:           "QUIC v1",
  final version = Version.version1;
  final header = splitHexString("c1000000010008f067a5502a4262b50040750001");
  final data = splitHexString(
    "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304",
  );
  final expectedSample = splitHexString("2cd0991cd25b0aac406a5816b6394100");
  final expectedHdr = splitHexString(
    "cf000000010008f067a5502a4262b5004075c0d9",
  );
  final expectedPacket = splitHexString(
    "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee",
  );

  parsePayload(data);

  // {
  // 	name:           "QUIC v2",
  // 	version:        protocol.Version2,
  // 	header:         splitHexString(t, "d16b3343cf0008f067a5502a4262b50040750001"),
  // 	data:           splitHexString(t, "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
  // 	expectedSample: splitHexString(t, "6f05d8a4398c47089698baeea26b91eb"),
  // 	expectedHdr:    splitHexString(t, "dc6b3343cf0008f067a5502a4262b5004075d92f"),
  // 	expectedPacket: splitHexString(t, "dc6b3343cf0008f067a5502a4262b500 4075d92faaf16f05d8a4398c47089698 baeea26b91eb761d9b89237bbf872630 17915358230035f7fd3945d88965cf17 f9af6e16886c61bfc703106fbaf3cb4c fa52382dd16a393e42757507698075b2 c984c707f0a0812d8cd5a6881eaf21ce da98f4bd23f6fe1a3e2c43edd9ce7ca8 4bed8521e2e140"),
  // },

  print("connID: ${HEX.encode(connID)}");
  // 1. Create client sealer
  final (sealer, _) = newInitialAEAD(connID, Perspective.server, version);

  // 3. Seal the payload
  final sealed = sealer.seal(data, 1, header);

  // 4. Extract and verify the sample used for header protection
  // Note: this test vector uses a simplified sample location (first 16 bytes).
  final sample = sealed.sublist(2, 2 + 16);
  // _expectEquals(sample, expectedSample, 'Client Packet Sample');

  print('Server Packet Sample');
  print("Got:      $sample");
  print("Expected: $expectedSample");
  print("");

  // 5. Encrypt the header and verify its protected parts
  final protectedHeader = Uint8List.fromList(header);
  final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
  final pnView = Uint8List.view(
    protectedHeader.buffer,
    protectedHeader.length - 2,
    2,
  );
  sealer.encryptHeader(sample, firstByteView, pnView);

  print('Protected header');
  print("Got:      $protectedHeader");
  print("Expected: $expectedHdr");
  print("");

  // 6. Assemble and verify the final, full packet
  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealed);

  // _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
  // print('Final Client Packet');
  // print("Got:      ${finalPacket.toBytes()}");
  // print("Expected: $expectedPacket");
  // print("");

  return finalPacket.toBytes();
}

void unprotectAndParseInitialPacket(Uint8List packetBytes) {
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version

  // DEBUG: Print initial state
  print('DEBUG: Starting offset: $offset');

  final dcidLen = mutablePacket[offset];
  offset += 1;
  final dcid = Uint8List.view(buffer, offset, dcidLen);
  offset += dcidLen;
  // DEBUG: Verify the most critical piece of info: the DCID
  print('DEBUG: Parsed DCID Length: $dcidLen');
  print('DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}');
  print('DEBUG: Offset after DCID: $offset');

  // Skip SCID and Token
  offset += 1 + mutablePacket[offset];
  offset += 1;
  print('DEBUG: Offset after skipping SCID & Token Len: $offset');

  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;
  // DEBUG: Verify the parsed length
  print('DEBUG: Parsed Length Field (Decimal): $lengthField');
  print('DEBUG: Packet Number starts at offset: $pnOffset');

  final (_, opener) = newInitialAEAD(
    dcid,
    Perspective.server,
    Version.version1,
  );

  final sample = Uint8List.view(buffer, pnOffset + 4, 16);
  final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 4);

  // DEBUG: Show what's being used for header decryption
  print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  // DEBUG: Verify packet number details
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  print('DEBUG: Decoded Packet Number on the wire: $wirePn');

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final associatedData = Uint8List.view(buffer, 0, payloadOffset);

  // This is the line from your code that is causing the error
  final ciphertext = Uint8List.view(
    buffer,
    payloadOffset,
    lengthField - pnLength,
  );

  // DEBUG: CRITICAL CHECK - Inspect the slices right before decryption
  print('DEBUG: Payload starts at offset: $payloadOffset');
  print('DEBUG: Associated Data Length: ${associatedData.length}');
  print(
    'DEBUG: Associated Data (Hex): ${HEX.encode(associatedData.sublist(0, min(16, associatedData.length)))}...',
  );
  print('DEBUG: Ciphertext Length: ${ciphertext.length}');
  print(
    'DEBUG: Ciphertext (Hex): ...${HEX.encode(ciphertext.sublist(max(0, ciphertext.length - 16)))}',
  );

  try {
    final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
    print('✅ **Payload decrypted successfully!**');
    print(
      '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...',
    );
  } catch (e, s) {
    print('\n❌ ERROR: Decryption failed as expected.');
    print('Exception: $e');
    print('Stack trace:\n$s');
  }
}

void unprotectAndParseServerInitial(Uint8List packetBytes) {
  final connID = splitHexString("8394c8f03e515708");
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  // final mutablePacket = splitHexString(
  //   "c1000000010008f067a5502a4262b50040750001",
  // );
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version
  // DEBUG: Print initial state
  print('DEBUG: Starting offset: $offset');

  final dcidLen = mutablePacket[offset];
  offset += 1;
  final dcid = Uint8List.view(buffer, offset, dcidLen);
  offset += dcidLen;
  // DEBUG: Verify the most critical piece of info: the DCID
  print('DEBUG: Parsed DCID Length: $dcidLen');
  print('DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}');
  print('DEBUG: Offset after DCID: $offset');

  final scidLen = mutablePacket[offset];
  offset += 1;
  final scid = Uint8List.view(buffer, offset, scidLen);
  offset += scidLen;
  // DEBUG: Verify the most critical piece of info: the DCID
  print('DEBUG: Parsed SCID Length: $scidLen');
  print('DEBUG: Parsed SCID (Hex): ${HEX.encode(scid)}');
  print('DEBUG: Offset after SCID: $offset');

  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;
  // DEBUG: Verify the parsed length
  print('DEBUG: Parsed Length Field (Decimal): $lengthField');
  print('DEBUG: Packet Number starts at offset: $pnOffset');

  final (_, opener) = newInitialAEAD(
    connID,
    Perspective.client,
    Version.version1,
  );

  final sample = Uint8List.view(buffer, pnOffset + 2, 16);
  final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 1);

  // DEBUG: Show what's being used for header decryption
  print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  // DEBUG: Verify packet number details
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  print('DEBUG: Decoded Packet Number on the wire: $wirePn');
}

void main() {
  unprotectAndParseInitialPacket(testClientInitialProtection());
  // unprotectAndParseServerInitial(testServersInitial());
  testServersInitial();
}
