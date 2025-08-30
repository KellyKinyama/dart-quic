// Filename: crypto.dart
import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'cipher_suite.dart';
import 'header_protector2.dart';
import 'hkdf2.dart';
// import 'interface.dart';
// import 'packet.dart';
// import 'prf.dart';

// (Uint8List, Uint8List, Uint8List) deriveKeyIvHp(
//   int cipherSuite,
//   Uint8List secret,
//   int version,
// ) {
//   final algorithm = CipherSuite.getById(cipherSuite);

//   if (version == QuicProtocolVersion.version2) {
//     return (
//       hkdfExpandLabel(secret, utf8.encode("quicv2 key"), "", algorithm.keyLen),
//       hkdfExpandLabel(secret, utf8.encode("quicv2 iv"), "", 12),
//       hkdfExpandLabel(secret, utf8.encode("quicv2 hp"), "", algorithm.keyLen),
//     );
//   } else {
//     return (
//       hkdfExpandLabel(secret, utf8.encode("quic key"), "", algorithm.keyLen),
//       hkdfExpandLabel(secret, utf8.encode("quic iv"), "", 12),
//       hkdfExpandLabel(secret, utf8.encode("quic hp"), "", algorithm.keyLen),
//     );
//   }
// }

class CryptoContext {
  XorNonceAead? aead;
  HeaderProtector? hp;

  Future<void> setup({
    required CipherSuite suite,
    required List<int> secret,
    required bool isLongHeader,
  }) async {
    final key = hkdf_expand_label(
      Uint8List.fromList(secret),
      utf8.encode('quic key'),
      Uint8List(0),
      suite.keyLen,
    );
    final iv = hkdf_expand_label(
      Uint8List.fromList(secret),
      utf8.encode('quic iv'),
      Uint8List(0),
      suite.ivLen,
    );
    final hpKey = hkdf_expand_label(
      Uint8List.fromList(secret),
      utf8.encode('quic hp'),
      Uint8List(0),
      suite.keyLen,
    );

    final secretKey = SecretKeyData(key);
    final aeadCipher = suite.aeadFactory();
    this.aead = XorNonceAead(aeadCipher, secretKey, iv);
    this.hp = await AesHeaderProtector.create(suite, hpKey, isLongHeader);
  }

  Future<Uint8List> encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) async {
    final protectedPayload = await aead!.seal(
      plainPayload,
      _packetNumberToNonce(packetNumber),
      plainHeader,
    );

    final pnLength = (plainHeader[0] & 0x03) + 1;
    final sampleOffset = 4 - pnLength;
    final sample = protectedPayload.sublist(sampleOffset, sampleOffset + 16);

    final protectedHeader = Uint8List.fromList(plainHeader);
    hp!.encryptHeader(
      sample,
      ByteData.sublistView(protectedHeader),
      protectedHeader.sublist(protectedHeader.length - pnLength),
    );

    return Uint8List.fromList([...protectedHeader, ...protectedPayload]);
  }

  Future<(Uint8List, Uint8List, int)> decryptPacket(
    Uint8List packet,
    int pnOffset,
    int expectedPn,
  ) async {
    // ** THIS IS THE FINAL FIX **

    // 1. Get the sample from the correct fixed offset in the original packet.
    final sample = packet.sublist(pnOffset + 4, pnOffset + 20);

    // 2. Create distinct, mutable copies of the header parts to be deprotected.
    final firstByteProtected = ByteData(1)..setUint8(0, packet[0]);
    final pnProtected = packet.sublist(pnOffset, pnOffset + 4);

    // 3. Deprotect the copies. The changes are contained in these local variables.
    hp!.decryptHeader(sample, firstByteProtected, pnProtected);

    // 4. Decode the packet number length from the now-decrypted first byte.
    final firstBytePlain = firstByteProtected.getUint8(0);
    final pnLength = (firstBytePlain & 0x03) + 1;

    // 5. Explicitly build the plain header from the deprotected parts and original packet data.
    final plainHeaderBuilder = BytesBuilder();
    plainHeaderBuilder.addByte(
      firstBytePlain,
    ); // Add the deprotected first byte
    plainHeaderBuilder.add(
      packet.sublist(1, pnOffset),
    ); // Add the untouched middle part of the header
    plainHeaderBuilder.add(
      pnProtected.sublist(0, pnLength),
    ); // Add the deprotected packet number bytes
    final plainHeader = plainHeaderBuilder.toBytes();

    final protectedPayload = packet.sublist(pnOffset + pnLength);

    // 6. Decode the full packet number from the deprotected bytes.
    int truncatedPn = 0;
    for (int i = 0; i < pnLength; i++) {
      truncatedPn = (truncatedPn << 8) | pnProtected[i];
    }
    final packetNumber = _decodePacketNumber(
      truncatedPn,
      pnLength * 8,
      expectedPn,
    );

    // 7. Decrypt the payload using the correctly reconstructed plainHeader as AAD.
    final plainPayload = await aead!.open(
      protectedPayload,
      _packetNumberToNonce(packetNumber),
      plainHeader,
    );

    return (plainHeader, plainPayload, packetNumber);
  }

  Uint8List _packetNumberToNonce(int n) {
    final byteData = ByteData(8)..setUint64(0, n, Endian.big);
    return byteData.buffer.asUint8List();
  }

  int _decodePacketNumber(int truncated, int numBits, int expected) {
    final window = 1 << numBits;
    final halfWindow = window ~/ 2;
    final candidate = (expected & ~(window - 1)) | truncated;
    if (candidate <= expected - halfWindow) return candidate + window;
    if (candidate > expected + halfWindow) return candidate - window;
    return candidate;
  }
}

class CryptoPair {
  final send = CryptoContext();
  final recv = CryptoContext();

  Future<void> setupInitial({
    required Uint8List cid,
    required bool isClient,
  }) async {
    final salt = Uint8List.fromList([
      0x38,
      0x76,
      0x2c,
      0xf7,
      0xf5,
      0x59,
      0x34,
      0xb3,
      0x4d,
      0x17,
      0x9a,
      0xe6,
      0xa4,
      0xc8,
      0x0c,
      0xad,
      0xcc,
      0xbb,
      0x7f,
      0x0a,
    ]);

    final initialSecretBytes = hkdfExtract(cid, salt: salt);

    final clientSecret = hkdf_expand_label(
      initialSecretBytes,
      utf8.encode('client in'),
      Uint8List(0),
      32,
    );
    final serverSecret = hkdf_expand_label(
      initialSecretBytes,
      utf8.encode('server in'),
      Uint8List(0),
      32,
    );

    final sendSecret = isClient ? clientSecret : serverSecret;
    final recvSecret = isClient ? serverSecret : clientSecret;

    await send.setup(
      suite: CipherSuite.getById(0x1301),
      secret: sendSecret,
      isLongHeader: true,
    );
    await recv.setup(
      suite: CipherSuite.getById(0x1301),
      secret: recvSecret,
      isLongHeader: true,
    );
  }
}
