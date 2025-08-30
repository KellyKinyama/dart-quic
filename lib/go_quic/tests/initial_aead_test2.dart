import 'dart:typed_data';
import 'dart:math';
import 'package:collection/collection.dart'; // Add this to your pubspec.yaml if not present
import 'package:hex/hex.dart';

import '../protocol.dart';
import '../initial_aead.dart';
import '../aead.dart';

// Helper to compare lists, needed for assertions
final _listEquals = const ListEquality().equals;

// Helper for simple assertions since we're not using the `test` package
void _expectEquals(dynamic got, dynamic expected, String message) {
  bool equal = false;
  if (got is List && expected is List) {
    equal = _listEquals(got, expected);
  } else {
    equal = (got == expected);
  }

  if (!equal) {
    print('❌ TEST FAILED: $message');
    print('  Expected: $expected');
    print('  Got:      $got');
    throw Exception('Test failed: $message');
  }
  print('✅ PASSED: $message');
}

/// Verifies the key derivation schedule against RFC test vectors.
void testKeyAndIvDerivation() {
  print('\n--- Running Test: Key and IV Derivation ---');
  final connID = splitHexString('0x8394c8f03e515708');

  // Client Secrets
  final (clientSecretV1, _) = computeSecrets(connID, Version.version1);
  final expectedClientSecretV1 = splitHexString(
    'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea',
  );
  _expectEquals(clientSecretV1, expectedClientSecretV1, 'Client Secret v1');

  final (keyV1, ivV1) = computeInitialKeyAndIV(
    clientSecretV1,
    Version.version1,
  );
  _expectEquals(
    keyV1,
    splitHexString('1f369613dd76d5467730efcbe3b1a22d'),
    'Client Key v1',
  );
  _expectEquals(
    ivV1,
    splitHexString('fa044b2f42a3fd3b46fb255c'),
    'Client IV v1',
  );

  // Server Secrets
  final (_, serverSecretV1) = computeSecrets(connID, Version.version1);
  final expectedServerSecretV1 = splitHexString(
    '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b',
  );
  _expectEquals(serverSecretV1, expectedServerSecretV1, 'Server Secret v1');

  final (sKeyV1, sIvV1) = computeInitialKeyAndIV(
    serverSecretV1,
    Version.version1,
  );
  _expectEquals(
    sKeyV1,
    splitHexString('cf3a5331653c364c88f0f379b6067e37'),
    'Server Key v1',
  );
  _expectEquals(
    sIvV1,
    splitHexString('0ac1493ca1905853b0bba03e'),
    'Server IV v1',
  );
}

/// Verifies the entire client-side sealing and protection process against a known packet vector.
void testClientInitialProtection() {
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
  final (sealer, _) = newInitialAEAD(connID, Perspective.client, version);

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
  _expectEquals(sample, expectedSample, 'Client Packet Sample');

  // 5. Encrypt the header and verify its protected parts
  final protectedHeader = Uint8List.fromList(header);
  final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
  final pnView = Uint8List.view(
    protectedHeader.buffer,
    protectedHeader.length - 4,
    4,
  );
  sealer.encryptHeader(sample, firstByteView, pnView);

  _expectEquals(
    protectedHeader[0],
    expectedHdrFirstByte,
    'Protected First Byte',
  );
  _expectEquals(pnView, expectedHdrPnBytes, 'Protected Packet Number');

  // 6. Assemble and verify the final, full packet
  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealed);
  _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
}

/// Verifies that a simple seal/open round trip works correctly.
void testSealsAndOpens() {
  print('\n--- Running Test: Seal/Open Round Trip ---');
  final cid = splitHexString('1234567890abcdef');
  final version = Version.version1;

  final (clientSealer, clientOpener) = newInitialAEAD(
    cid,
    Perspective.client,
    version,
  );
  final (serverSealer, serverOpener) = newInitialAEAD(
    cid,
    Perspective.server,
    version,
  );

  final clientMessage = clientSealer.seal(
    Uint8List.fromList('foobar'.codeUnits),
    42,
    Uint8List.fromList('aad'.codeUnits),
  );
  final openedClientMessage = serverOpener.open(
    clientMessage,
    42,
    Uint8List.fromList('aad'.codeUnits),
  );
  _expectEquals(
    openedClientMessage,
    Uint8List.fromList('foobar'.codeUnits),
    'Client->Server message',
  );

  final serverMessage = serverSealer.seal(
    Uint8List.fromList('raboof'.codeUnits),
    99,
    Uint8List.fromList('daa'.codeUnits),
  );
  final openedServerMessage = clientOpener.open(
    serverMessage,
    99,
    Uint8List.fromList('daa'.codeUnits),
  );
  _expectEquals(
    openedServerMessage,
    Uint8List.fromList('raboof'.codeUnits),
    'Server->Client message',
  );
}

/// Verifies that decryption fails when different Connection IDs are used.
void testFailsWithDifferentConnectionIDs() {
  print('\n--- Running Test: Fails with Different CIDs ---');
  final c1 = splitHexString('0000000000000001');
  final c2 = splitHexString('0000000000000002');
  final version = Version.version1;

  final (clientSealer, _) = newInitialAEAD(c1, Perspective.client, version);
  final (_, serverOpener) = newInitialAEAD(c2, Perspective.server, version);

  final clientMessage = clientSealer.seal(
    Uint8List.fromList('foobar'.codeUnits),
    42,
    Uint8List.fromList('aad'.codeUnits),
  );

  try {
    serverOpener.open(clientMessage, 42, Uint8List.fromList('aad'.codeUnits));
    // If we reach here, the test failed because it didn't throw.
    throw Exception('Decryption succeeded unexpectedly');
  } catch (e) {
    _expectEquals(
      e.toString(),
      'Exception: decryption failed',
      'Decryption failure with different CIDs',
    );
  }
}

/// Verifies that header protection can be applied and removed correctly.
// void testEncryptsAndDecryptsHeader() {
//   print('\n--- Running Test: Header Protection Round Trip ---');
//   final connID = splitHexString('decafbad');
//   final version = Version.version1;
//   final (sealer, opener) = newInitialAEAD(connID, Perspective.client, version);

//   final header = Uint8List.fromList([
//     0xc3,
//     0,
//     1,
//     2,
//     3,
//     4,
//     0xde,
//     0xad,
//     0xbe,
//     0xef,
//   ]);
//   final originalHeader = Uint8List.fromList(header);

//   final sample = Uint8List.fromList(
//     List.generate(16, (_) => Random.secure().nextInt(256)),
//   );
//   // Random.secure().nextInt(sample);

//   final firstByte = Uint8List.view(header.buffer, 0, 1);
//   final pnBytes = Uint8List.view(header.buffer, 6, 4);

//   // Encrypt
//   sealer.encryptHeader(sample, firstByte, pnBytes);
//   if (_listEquals(header, originalHeader)) {
//     throw Exception('Header did not change after encryption');
//   }
//   print('✅ PASSED: Header changed after encryption');

//   // Decrypt
//   opener.decryptHeader(sample, firstByte, pnBytes);
//   _expectEquals(header, originalHeader, 'Header restored after decryption');
// }

/// Verifies that header protection can be applied and removed correctly.
void testEncryptsAndDecryptsHeader() {
  print('\n--- Running Test: Header Protection Round Trip ---');
  final connID = splitHexString('decafbad');
  final version = Version.version1;

  // Create BOTH a client and a server context
  final (clientSealer, clientOpener) = newInitialAEAD(
    connID,
    Perspective.client,
    version,
  );
  final (serverSealer, serverOpener) = newInitialAEAD(
    connID,
    Perspective.server,
    version,
  );

  final header = Uint8List.fromList([
    0xc3,
    0,
    1,
    2,
    3,
    4,
    0xde,
    0xad,
    0xbe,
    0xef,
  ]);
  final originalHeader = Uint8List.fromList(header);

  final sample = Uint8List.fromList(
    List.generate(16, (_) => Random.secure().nextInt(256)),
  );

  final firstByte = Uint8List.view(header.buffer, 0, 1);
  final pnBytes = Uint8List.view(header.buffer, 6, 4);

  // Test Client -> Server
  clientSealer.encryptHeader(sample, firstByte, pnBytes);
  if (_listEquals(header, originalHeader)) {
    throw Exception('Client header did not change after encryption');
  }
  print('✅ PASSED: Client header changed after encryption');

  // Decrypt with the SERVER's opener
  serverOpener.decryptHeader(sample, firstByte, pnBytes);
  _expectEquals(
    header,
    originalHeader,
    'Client header restored after decryption by server',
  );

  // Test Server -> Client
  serverSealer.encryptHeader(sample, firstByte, pnBytes);
  if (_listEquals(header, originalHeader)) {
    throw Exception('Server header did not change after encryption');
  }
  print('✅ PASSED: Server header changed after encryption');

  // Decrypt with the CLIENT's opener
  clientOpener.decryptHeader(sample, firstByte, pnBytes);
  _expectEquals(
    header,
    originalHeader,
    'Server header restored after decryption by client',
  );
}

void main() {
  try {
    testKeyAndIvDerivation();
    testClientInitialProtection();
    testSealsAndOpens();
    testFailsWithDifferentConnectionIDs();
    testEncryptsAndDecryptsHeader();
    print('\n🎉 All tests passed successfully!');
  } catch (e, st) {
    print('\n🔥 One or more tests failed.');
    print("Trace: $st");
  }
}
