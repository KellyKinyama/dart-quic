import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dart_quic/aioquic/quic/crypto/chacha3.dart';
import '../enums.dart';
import '../packet2.dart';
// import 'crypto_logic.dart';
import 'crypto_logic2.dart';
import 'hkdf.dart';

// Helper for HKDF-Expand-Label
// Future<SecretKey> hkdfExpandLabel(
//   Hkdf hkdf,
//   SecretKey secret,
//   List<int> label,
//   List<int> context,
//   int length,
// ) async {
//   final labelBytes = Uint8List.fromList([
//     (length >> 8) & 0xFF, length & 0xFF, // length
//     'quic '.length + label.length, ...'quic '.codeUnits, ...label, // label
//     context.length, ...context, // context
//   ]);
//   return await hkdf.deriveKey(
//     secretKey: secret,
//     info: labelBytes,
//     // outputLength: length,
//   );
// }

// Helper for HKDF-Extract
// Future<SecretKey> hkdfExtract(Hkdf hkdf, List<int> salt, SecretKey ikm) async {
//   return await hkdf.extract(secretKey: ikm, nonce: salt);
// }

class KeyUnavailableError extends CryptoError {
  KeyUnavailableError(String message) : super(message);
}

class CryptoContext {
  ChachaCipher? aead;
  HeaderProtection? hp;
  CipherSuite? cipherSuite;
  SecretKey? secret;
  int? version;
  int keyPhase = 0;
  Uint8List iv;

  CryptoContext(this.iv);

  bool get isValid => aead != null;

  Future<void> setup({
    required CipherSuite suite,
    required SecretKey secret,
    required int version,
  }) async {
    this.cipherSuite = suite;
    this.secret = secret;
    this.version = version;

    final (hpCipherName, aeadCipherName) = cipherSuites[suite]!;
    final (key, iv, hpKey) = await deriveKeyIvHp(
      suite: suite,
      secret: secret,
      version: version,
    );

    aead = ChachaCipher(secretKey: SecretKey(key), iv: iv);
    hp = HeaderProtection(hpCipherName, hpKey);
  }

  void teardown() {
    aead = null;
    hp = null;
    cipherSuite = null;
    secret = null;
    version = null;
  }

  Future<Uint8List> encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) async {
    if (!isValid) throw KeyUnavailableError('Encryption key is not available');
    final protectedPayload = await aead!.encrypt(
      plainPayload,
      plainHeader,
      _createNonce(packetNumber),
    );
    return await hp!.apply(plainHeader, protectedPayload);
  }

  Future<(Uint8List, Uint8List, int, bool)> decryptPacket(
    Uint8List packet,
    int encryptedOffset,
    int expectedPacketNumber,
  ) async {
    if (hp == null || aead == null) {
      throw KeyUnavailableError('Decryption key is not available');
    }

    final (plainHeader, truncatedPn) = await hp!.remove(
      packet,
      encryptedOffset,
    );
    final packetNumber = decodePacketNumber(
      truncatedPn,
      (plainHeader[0] & 0x03) + 1,
      expectedPacketNumber,
    );

    var keyPhaseBit = 0;
    var isShortHeader = !isLongHeader(plainHeader[0]);
    if (isShortHeader) {
      keyPhaseBit = (plainHeader[0] & 0x04) >> 2;
    }

    // This is a simplification. In a real implementation, you would have separate
    // crypto contexts for the next key phase and switch to it.
    // Here we just note that a phase change happened.
    final keyPhaseChanged = isShortHeader && keyPhaseBit != keyPhase;

    final payload = await aead!.decrypt(
      packet.sublist(plainHeader.length),
      plainHeader,
      _createNonce(packetNumber),
    );

    return (plainHeader, payload, packetNumber, keyPhaseChanged);
  }

  // Uint8List _createNonce(int packetNumber) {
  //   final nonce = Uint8List.fromList(iv);
  //   final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);
  //   for (var i = 0; i < 8; i++) {
  //     nonce[nonce.length - 8 + i] ^= pnBytes.getUint8(i);
  //   }
  //   return nonce;
  // }

  // ✅ CORRECT
  // Uint8List _createNonce(int packetNumber) {
  //   if (iv == null) {
  //     throw Exception('IV is not available');
  //   }
  //   // Create a mutable copy of the IV.
  //   final nonce = Uint8List.fromList(iv!);

  //   // The packet number is a 64-bit integer in big-endian format.
  //   final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);

  //   // XOR the packet number into the nonce as per RFC 9001 Section 5.3.
  //   // The packet number is left-padded with zeros to the size of the IV.
  //   for (var i = 0; i < 8; i++) {
  //     nonce[nonce.length - 8 + i] ^= pnBytes.getUint8(i);
  //   }
  //   return nonce;
  // }

  // The correct implementation for _createNonce should be:
  // Uint8List _createNonce(int packetNumber) {
  //   final nonce = Uint8List.fromList(iv!);
  //   final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);
  //   for (var i = 0; i < 8; i++) {
  //     nonce[nonce.length - 8 + i] ^= pnBytes.getUint8(i);
  //   }
  //   return nonce.sublist(nonce.length - 12);
  // }
  Uint8List _createNonce(int packetNumber) {
    final nonce = Uint8List.fromList(iv!);
    final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);
    for (var i = 0; i < 8; i++) {
      nonce[nonce.length - 8 + i] ^= pnBytes.getUint8(i);
    }
    return nonce.sublist(0, 12); // Truncate to 12 bytes
  }
}

Future<(Uint8List, Uint8List, Uint8List)> deriveKeyIvHp({
  required CipherSuite suite,
  required SecretKey secret,
  required int version,
}) async {
  final keySize =
      (suite == CipherSuite.AES_256_GCM_SHA384 ||
          suite == CipherSuite.CHACHA20_POLY1305_SHA256)
      ? 32
      : 16;
  final ivSize = 12;
  final hash = cipherSuiteHash[suite]!;
  final hkdf = Hkdf(hmac: hash, outputLength: keySize);

  final keyLabel = version == QuicProtocolVersion.VERSION_2.value
      ? 'quicv2 key'.codeUnits
      : 'quic key'.codeUnits;
  final ivLabel = version == QuicProtocolVersion.VERSION_2.value
      ? 'quicv2 iv'.codeUnits
      : 'quic iv'.codeUnits;
  final hpLabel = version == QuicProtocolVersion.VERSION_2.value
      ? 'quicv2 hp'.codeUnits
      : 'quic hp'.codeUnits;

  // final key = await hkdf_expand_label(hkdf, secret, keyLabel, [], keySize);
  // final iv = await hkdfExpandLabel(hkdf, secret, ivLabel, [], ivSize);
  // final hp = await hkdfExpandLabel(hkdf, secret, hpLabel, [], keySize);
  final secretBytes = Uint8List.fromList(await secret.extractBytes());
  final key = hkdf_expand_label(
    secretBytes,
    Uint8List.fromList(keyLabel),
    Uint8List(0),
    keySize,
  );
  final iv = hkdf_expand_label(
    secretBytes,
    Uint8List.fromList(ivLabel),
    Uint8List(0),
    ivSize,
  );
  final hp = hkdf_expand_label(
    secretBytes,
    Uint8List.fromList(hpLabel),
    Uint8List(0),
    keySize,
  );

  return (key, iv, hp);
}
