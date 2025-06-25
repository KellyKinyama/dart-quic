// bin/appendix_a_verifier.dart
import 'dart:typed_data';
import 'package:collection/collection.dart'; // For listEquals

import 'enums.dart';
import 'key_manager.dart';
import 'packet_protector.dart';
import 'types.dart';
import 'utils.dart'; // For hexToBytes, bytesToHex, listEquals, createHkdfLabelInfo

final QuicKeyManager _keyManager = QuicKeyManager();
final QuicPacketProtector _packetProtector = QuicPacketProtector();

// Helper to print and assert for verification
void _verify(String name, Uint8List actual, String expectedHex) {
  final expected = hexToBytes(expectedHex);
  print('$name (Actual):   ${bytesToHex(actual)}');
  print('$name (Expected): ${bytesToHex(expected)}');
  if (!listEquals(actual, expected)) {
    throw Exception('Verification Failed: $name mismatch!');
  }
  print('$name Verified.\n');
}

void _verifyInt(String name, int actual, int expected) {
  print('$name (Actual):   $actual');
  print('$name (Expected): $expected');
  if (actual != expected) {
    throw Exception('Verification Failed: $name mismatch!');
  }
  print('$name Verified.\n');
}

void _runTest(String testName, Function testFunction) {
  print('===================================================');
  print('Running Test: $testName');
  print('===================================================\n');
  try {
    testFunction();
    print('Test PASSED: $testName\n');
  } catch (e) {
    print('Test FAILED: $testName - $e\n');
  }
}

// --- Appendix A.1. Keys ---
void verifyAppendixA1Keys() {
  final Uint8List clientDstConnectionId = hexToBytes(
    '8394c8f03e515708',
  ); // DCID from A.2

  // Manual HKDF-Extract for initial_secret (for verification, not part of live key manager)
  final Hkdf initialHkdfExtract = Hkdf(quicKdfSHA256._digest);
  initialHkdfExtract.init(
    HkdfParameters(
      clientDstConnectionId,
      Uint8List.fromList(QuicConstants.initialSalt),
      Uint8List(0),
    ),
  );
  final Uint8List calculatedInitialSecret = initialHkdfExtract.extractKey();
  _verify(
    'initial_secret',
    calculatedInitialSecret,
    '7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44',
  );

  // Derive client_initial_secret
  final Uint8List clientInitialSecret = quicKdfSHA256.hkdfExpandLabel(
    calculatedInitialSecret,
    "client in",
    Uint8List(0),
    quicKdfSHA256.hashLength,
  );
  _verify(
    'client_initial_secret',
    clientInitialSecret,
    'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea',
  );

  // Derive client keys
  final Uint8List clientKey = quicKdfSHA256.hkdfExpandLabel(
    clientInitialSecret,
    "quic key",
    Uint8List(0),
    aes128Gcm.keyLength,
  );
  final Uint8List clientIv = quicKdfSHA256.hkdfExpandLabel(
    clientInitialSecret,
    "quic iv",
    Uint8List(0),
    aes128Gcm.ivLength,
  );
  final Uint8List clientHp = quicKdfSHA256.hkdfExpandLabel(
    clientInitialSecret,
    "quic hp",
    Uint8List(0),
    aes128Gcm.keyLength,
  );
  _verify('client key', clientKey, '1f369613dd76d5467730efcbe3b1a22d');
  _verify('client iv', clientIv, 'fa044b2f42a3fd3b46fb255c');
  _verify('client hp', clientHp, '9f50449e04a0e810283a1e9933adedd2');

  // Derive server_initial_secret
  final Uint8List serverInitialSecret = quicKdfSHA256.hkdfExpandLabel(
    calculatedInitialSecret,
    "server in",
    Uint8List(0),
    quicKdfSHA256.hashLength,
  );
  _verify(
    'server_initial_secret',
    serverInitialSecret,
    '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b',
  );

  // Derive server keys
  final Uint8List serverKey = quicKdfSHA256.hkdfExpandLabel(
    serverInitialSecret,
    "quic key",
    Uint8List(0),
    aes128Gcm.keyLength,
  );
  final Uint8List serverIv = quicKdfSHA256.hkdfExpandLabel(
    serverInitialSecret,
    "quic iv",
    Uint8List(0),
    aes128Gcm.ivLength,
  );
  final Uint8List serverHp = quicKdfSHA256.hkdfExpandLabel(
    serverInitialSecret,
    "quic hp",
    Uint8List(0),
    aes128Gcm.keyLength,
  );
  _verify('server key', serverKey, 'cf3a5331653c364c88f0f379b6067e37');
  _verify('server iv', serverIv, '0ac1493ca1905853b0bba03e');
  _verify('server hp', serverHp, 'c206b8d9b9f0f37644430b490eeaa314');

  // Populate QuicKeyManager for subsequent packet protection tests
  _keyManager.setSendKeys(
    EncryptionLevel.initial,
    QuicPacketProtectionKeys(
      key: clientKey,
      iv: clientIv,
      hpKey: clientHp,
      aead: aes128Gcm,
      kdf: quicKdfSHA256,
    ),
  );
  _keyManager.setReceiveKeys(
    EncryptionLevel.initial,
    QuicPacketProtectionKeys(
      key: serverKey,
      iv: serverIv,
      hpKey: serverHp,
      aead: aes128Gcm,
      kdf: quicKdfSHA256,
    ),
  );
}

// --- Appendix A.2. Client Initial Packet ---
void verifyAppendixA2ClientInitial() {
  final Uint8List unprotectedPayload = hexToBytes(
    '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
            '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
            '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
            '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
            'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
            '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
            '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
            '75300901100f088394c8f03e51570806048000ffff'
            // Padding to make 1162 bytes (total payload including CRYPTO frame)
            '00' *
        (1162 - 400), // The provided hex is 400 bytes, fill with 0x00
  );
  _verifyInt('Unprotected Payload Length', unprotectedPayload.length, 1162);

  final Uint8List unprotectedHeader = hexToBytes(
    'c300000001088394c8f03e5157080000449e00000002',
  );
  final int packetNumber = 2;
  final bool isLongHeader = true;
  final int pnOffset = 22; // Offset of Packet Number field in unprotectedHeader
  final int pnLength = 4; // Encoded length of Packet Number

  final QuicPacketProtectionKeys clientKeys = _keyManager.getSendKeys(
    EncryptionLevel.initial,
  )!;

  // Manually encrypt payload for verification of ciphertext and sample
  final Uint8List nonce = _packetProtector._createAeadNonce(
    clientKeys.iv,
    packetNumber,
  );
  final Uint8List associatedData = unprotectedHeader;
  final Uint8List calculatedCiphertextWithTag = clientKeys.aead.encrypt(
    clientKeys.key,
    nonce,
    associatedData,
    unprotectedPayload,
  );
  _verifyInt(
    'Ciphertext+Tag Length',
    calculatedCiphertextWithTag.length,
    unprotectedPayload.length + clientKeys.aead.tagLength,
  );

  // Take sample from the encrypted payload
  final Uint8List sample = calculatedCiphertextWithTag.sublist(
    0,
    QuicConstants.headerProtectionSampleLength,
  );
  _verify('Sample', sample, 'd1b1c98dd7689fb8ec11d242b123dc9b');

  // Calculate mask
  final Uint8List fullMask = aesEcbEncrypt(clientKeys.hpKey, sample);
  final Uint8List mask = fullMask.sublist(0, 5); // Only first 5 bytes are used
  _verify('Mask', mask, '437b9aec36');

  // Apply mask to header
  final Uint8List maskedHeader = Uint8List.fromList(unprotectedHeader);
  maskedHeader[0] ^= (mask[0] & 0x0F); // Long header: 4 bits masked
  maskedHeader[pnOffset] ^= mask[1];
  maskedHeader[pnOffset + 1] ^= mask[2];
  maskedHeader[pnOffset + 2] ^= mask[3];
  maskedHeader[pnOffset + 3] ^= mask[4];
  _verify(
    'Masked Header',
    maskedHeader,
    'c000000001088394c8f03e5157080000449e7b9aec34',
  );

  final Uint8List finalProtectedPacket = Uint8List.fromList([
    ...maskedHeader,
    ...calculatedCiphertextWithTag,
  ]);
  _verify(
    'Final Protected Packet',
    finalProtectedPacket,
    'c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11'
        'd242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399'
        '1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c'
        '8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212'
        '30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5'
        '457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208'
        '4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec'
        '4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3'
        '485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db'
        '059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c'
        '7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8'
        '9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556'
        'be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74'
        '68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a'
        'c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00'
        'f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632'
        '291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964'
        '25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd'
        '14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff'
        'ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198'
        'e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd'
        'c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73'
        '203a4a13e96f5432ec0fd4a1ee65acddd5e3904df54c1da510b0ff20dcc0c77f'
        'cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e'
        'fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade'
        'a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047'
        '90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2'
        '162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4'
        '40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0'
        '6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e'
        '8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0'
        'be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400'
        '54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab'
        '760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9'
        'f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4'
        '056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064'
        '7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241'
        'e221af44860018ab0856972e194cd934',
  );
}

// --- Appendix A.3. Server Initial Packet ---
void verifyAppendixA3ServerInitial() {
  final Uint8List unprotectedPayload = hexToBytes(
    '02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739'
    '88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94'
    '0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00'
    '020304',
  );
  _verifyInt(
    'Unprotected Payload Length (Server)',
    unprotectedPayload.length,
    126,
  );

  final Uint8List unprotectedHeader = hexToBytes(
    'c1000000010008f067a5502a4262b50040750001',
  );
  final int packetNumber = 1; // Server uses PN 1
  final bool isLongHeader = true;
  final int pnOffset = 22; // Offset of Packet Number field in unprotectedHeader
  final int pnLength = 2; // Encoded length of Packet Number

  final QuicPacketProtectionKeys serverKeys = _keyManager.getReceiveKeys(
    EncryptionLevel.initial,
  )!; // Server's send keys are client's receive keys

  // Manually encrypt payload for verification of ciphertext and sample
  final Uint8List nonce = _packetProtector._createAeadNonce(
    serverKeys.iv,
    packetNumber,
  );
  final Uint8List associatedData = unprotectedHeader;
  final Uint8List calculatedCiphertextWithTag = serverKeys.aead.encrypt(
    serverKeys.key,
    nonce,
    associatedData,
    unprotectedPayload,
  );
  _verifyInt(
    'Ciphertext+Tag Length (Server)',
    calculatedCiphertextWithTag.length,
    unprotectedPayload.length + serverKeys.aead.tagLength,
  );

  // Take sample from the encrypted payload
  final Uint8List sample = calculatedCiphertextWithTag.sublist(
    0,
    QuicConstants.headerProtectionSampleLength,
  );
  _verify('Sample (Server)', sample, '2cd0991cd25b0aac406a5816b6394100');

  // Calculate mask
  final Uint8List fullMask = aesEcbEncrypt(serverKeys.hpKey, sample);
  final Uint8List mask = fullMask.sublist(0, 5); // Only first 5 bytes are used
  _verify('Mask (Server)', mask, '2ec0d8356a');

  // Apply mask to header
  final Uint8List maskedHeader = Uint8List.fromList(unprotectedHeader);
  maskedHeader[0] ^= (mask[0] & 0x0F); // Long header: 4 bits masked
  maskedHeader[pnOffset] ^= mask[1];
  maskedHeader[pnOffset + 1] ^= mask[2];
  // No mask[3], mask[4] as pnLength is 2
  _verify(
    'Masked Header (Server)',
    maskedHeader,
    'cf000000010008f067a5502a4262b5004075c0d9',
  );

  final Uint8List finalProtectedPacket = Uint8List.fromList([
    ...maskedHeader,
    ...calculatedCiphertextWithTag,
  ]);
  _verify(
    'Final Protected Packet (Server)',
    finalProtectedPacket,
    'cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a'
        '5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3'
        'dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84'
        '022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4'
        '2158407dd074ee',
  );
}

// --- Appendix A.4. Retry Packet ---
void verifyAppendixA4Retry() {
  final Uint8List retryPacket = hexToBytes(
    'ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f'
    '0f2496ba',
  );
  final Uint8List originalDcId = hexToBytes(
    '8394c8f03e515708',
  ); // Client's initial DCID

  final bool isValid = _packetProtector.validateRetryIntegrity(
    retryPacket,
    originalDcId,
  );
  print('Retry Integrity Valid (Actual): $isValid');
  print('Retry Integrity Valid (Expected): true');
  if (!isValid) {
    throw Exception('Verification Failed: Retry Integrity Check failed!');
  }
  print('Retry Integrity Verified.\n');
}

// --- Appendix A.5. ChaCha20-Poly1305 Short Header Packet ---
void verifyAppendixA5ChaCha20ShortHeaderPacket() {
  final Uint8List secret = hexToBytes(
    '9ac312a7f877468ebe69422748ad00a1'
    '5443f18203a07d6060f688f30f21632b',
  );

  // Derive keys for ChaCha20-Poly1305
  final Uint8List key = quicKdfSHA256.hkdfExpandLabel(
    secret,
    "quic key",
    Uint8List(0),
    chacha20Poly1305.keyLength,
  );
  final Uint8List iv = quicKdfSHA256.hkdfExpandLabel(
    secret,
    "quic iv",
    Uint8List(0),
    chacha20Poly1305.ivLength,
  );
  final Uint8List hp = quicKdfSHA256.hkdfExpandLabel(
    secret,
    "quic hp",
    Uint8List(0),
    chacha20Poly1305.keyLength,
  );
  final Uint8List ku = quicKdfSHA256.hkdfExpandLabel(
    secret,
    "quic ku",
    Uint8List(0),
    chacha20Poly1305.keyLength,
  ); // Not used in packet protection

  _verify(
    'ChaCha20 key',
    key,
    'c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8',
  );
  _verify('ChaCha20 iv', iv, 'e0459b3474bdd0e44a41c144');
  _verify(
    'ChaCha20 hp',
    hp,
    '25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4',
  );
  _verify(
    'ChaCha20 ku',
    ku,
    '1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9',
  );

  final QuicPacketProtectionKeys chachaKeys = QuicPacketProtectionKeys(
    key: key,
    iv: iv,
    hpKey: hp,
    aead: chacha20Poly1305,
    kdf: quicKdfSHA256,
  ); // Assuming SHA256 KDF for this example

  final int packetNumber = 654360564;
  final Uint8List unprotectedHeader = hexToBytes(
    '4200bff4',
  ); // Short header with 3-byte PN, Key Phase 0
  final Uint8List payloadPlaintext = hexToBytes('01'); // PING frame

  // Verify nonce construction
  final Uint8List actualNonce = _packetProtector._createAeadNonce(
    chachaKeys.iv,
    packetNumber,
  );
  _verify('Nonce (ChaCha20)', actualNonce, 'e0459b3474bdd0e46d417eb0');

  // Manually encrypt payload to verify ciphertext
  final Uint8List associatedData = unprotectedHeader;
  final Uint8List calculatedCiphertextWithTag = chachaKeys.aead.encrypt(
    chachaKeys.key,
    actualNonce,
    associatedData,
    payloadPlaintext,
  );
  _verify(
    'Payload Ciphertext+Tag (ChaCha20)',
    calculatedCiphertextWithTag,
    '655e5cd55c41f69080575d7999c25a5bfb',
  );

  // Verify sample and mask
  final Uint8List sample = calculatedCiphertextWithTag.sublist(
    1,
    QuicConstants.headerProtectionSampleLength + 1,
  ); // Sample starts from 2nd byte
  _verify('Sample (ChaCha20)', sample, '5e5cd55c41f69080575d7999c25a5bfb');

  final Uint8List fullMask = chacha20Encrypt(
    chachaKeys.hpKey,
    sample.sublist(0, 4),
    sample.sublist(4, 16),
    Uint8List(5),
  ); // Simulate ChaCha20 encryption of 5 zero bytes
  final Uint8List mask = fullMask.sublist(0, 5); // Take first 5 bytes
  _verify('Mask (ChaCha20)', mask, 'aefefe7d03');

  // Apply mask to header
  final Uint8List maskedHeader = Uint8List.fromList(unprotectedHeader);
  maskedHeader[0] ^=
      (mask[0] & 0x1F); // Short header: 5 bits masked (key phase + PN length)
  maskedHeader[1] ^= mask[1];
  maskedHeader[2] ^= mask[2];
  maskedHeader[3] ^= mask[3]; // PN is 3 bytes, so mask[1..3]
  // In the RFC, the packet number is encoded as 0xbff4 (2 bytes). The example says PN length 3.
  // This implies the 3-byte PN is 0x00bff4.
  // The header 4200bff4 has a 2-byte PN 0xbff4, and the example says "packet number of length 3 (that is, 49140 is encoded)".
  // This is contradictory in the RFC. The encoded value 0xbff4 implies a 2-byte PN length.
  // Let's assume the provided unprotected header `4200bff4` represents a 2-byte PN (0xbff4) for consistency with the byte array.
  // If the PN length from the header (bits 0,1) is '10' (3 bytes), then it would be `4a00bff4`.
  // RFC A.5 states "packet number of length 3 (that is, 49140 is encoded)"
  // The given header `4200bff4` implies a `pn_length` of 2 (`0b00` from `42`'s last two bits).
  // This means the RFC example might have a slight inconsistency between text and hex.
  // We will assume `pnLength` based on the encoded packet number in the header for consistency with `unprotect` logic.
  // If PN is 2 bytes long, only mask[1] and mask[2] are applied to PN, and mask[3] is unused for PN.
  // However, the example shows mask[3] and mask[4] being used on the header.
  // Let's assume the example is correct about the mask application for 3-byte PN: mask[1..3] for PN, and header[0] for 5 bits.
  // The provided masked header shows header[1], header[2], header[3] are masked.
  // So, using 3-byte PN (mask[1..3]) is correct for the example output.
  // This means the initial header (4200bff4) has its PN (00bff4) encoded with length 3.
  // This makes the header byte `4A` (01001010) not `42` (01000010).
  // This implies RFC example has an error in its stated "unprotected header".
  // Let's use the given `mask` on the provided `unprotected header` and see if it yields the RFC's `header = 4cfe4189`.
  // header = 42 00 bf f4
  // mask =   ae fe fe 7d 03
  // header[0] ^ (mask[0] & 0x1f) = 0x42 ^ (0xae & 0x1f) = 0x42 ^ 0x0e = 0x4c (Matches RFC!)
  // header[1] ^ mask[1] = 0x00 ^ 0xfe = 0xfe (Matches RFC!)
  // header[2] ^ mask[2] = 0xbf ^ 0xfe = 0x41 (Matches RFC!)
  // header[3] ^ mask[3] = 0xf4 ^ 0x7d = 0x89 (Matches RFC!)
  // So, the mask application (first 5 bytes of mask) matches the example output, but the PN length deduction from `42` is inconsistent.
  // For the purpose of this verification, we apply the mask directly as shown.
  // Header: 42 00 bf f4 (input)
  // Mask:   ae fe fe 7d 03
  // Result: 4C fe 41 89 (expected)

  // This means we need to adjust `pnLength` to be 3 for the masking part.
  final int actualPnLengthForMasking =
      3; // From RFC explanation, not header bits.

  maskedHeader[pnOffset] ^= mask[1]; // Correct for 00bff4
  maskedHeader[pnOffset + 1] ^= mask[2];
  maskedHeader[pnOffset + 2] ^= mask[3]; // Applying mask[3] because PN length 3
  _verify('Masked Header (ChaCha20)', maskedHeader, '4cfe4189');

  final Uint8List finalProtectedPacket = Uint8List.fromList([
    ...maskedHeader,
    ...calculatedCiphertextWithTag,
  ]);
  _verify(
    'Final Protected Packet (ChaCha20)',
    finalProtectedPacket,
    '4cfe4189655e5cd55c41f69080575d7999c25a5bfb',
  );

  // Verify decryption as well
  final Map<String, dynamic>? unprotectedResult = _packetProtector.unprotect(
    packetData: finalProtectedPacket,
    keys: chachaKeys,
    isLongHeader: false,
    headerLength: maskedHeader.length,
    pnOffset: pnOffset,
  );
  if (unprotectedResult == null) {
    throw Exception('ChaCha20 Decryption Failed!');
  }
  _verify(
    'Decrypted Payload (ChaCha20)',
    unprotectedResult['payload']!,
    bytesToHex(payloadPlaintext),
  );
  _verifyInt(
    'Decrypted PN (ChaCha20)',
    unprotectedResult['packet_number']!,
    packetNumber,
  );
}

void main() {
  _runTest('Appendix A.1. Key Derivation', verifyAppendixA1Keys);
  _runTest(
    'Appendix A.2. Client Initial Packet Protection',
    verifyAppendixA2ClientInitial,
  );
  _runTest(
    'Appendix A.3. Server Initial Packet Protection',
    verifyAppendixA3ServerInitial,
  );
  _runTest('Appendix A.4. Retry Packet Integrity', verifyAppendixA4Retry);
  _runTest(
    'Appendix A.5. ChaCha20-Poly1305 Short Header Packet Protection',
    verifyAppendixA5ChaCha20ShortHeaderPacket,
  );

  print(
    '\nAll Appendix A verifications attempted. Check console for "Verified" messages.',
  );
}
