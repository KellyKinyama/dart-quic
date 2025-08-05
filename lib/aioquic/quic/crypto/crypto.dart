import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import '../enums.dart';
import '../packet2.dart';
import 'crypto_logic.dart';
import 'crypto_logic2.dart';

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
  Aead? aead;
  HeaderProtection? hp;
  CipherSuite? cipherSuite;
  SecretKey? secret;
  int? version;
  int keyPhase = 0;

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

    aead = Aead(
      aeadCipherName,
      Uint8List.fromList(await key.extractBytes()),
      Uint8List.fromList(await iv.extractBytes()),
    );
    hp = HeaderProtection(
      hpCipherName,
      Uint8List.fromList(await hpKey.extractBytes()),
    );
  }

  void teardown() {
    aead = null;
    hp = null;
    cipherSuite = null;
    secret = null;
    version = null;
  }

  Uint8List encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) {
    if (!isValid) throw KeyUnavailableError('Encryption key is not available');
    final protectedPayload = aead!.encrypt(
      plainPayload,
      plainHeader,
      packetNumber,
    );
    return hp!.apply(plainHeader, protectedPayload);
  }

  (Uint8List, Uint8List, int, bool) decryptPacket(
    Uint8List packet,
    int encryptedOffset,
    int expectedPacketNumber,
  ) {
    if (hp == null || aead == null) {
      throw KeyUnavailableError('Decryption key is not available');
    }

    final (plainHeader, truncatedPn) = hp!.remove(packet, encryptedOffset);
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

    final payload = aead!.decrypt(
      packet.sublist(plainHeader.length),
      plainHeader,
      packetNumber,
    );

    return (plainHeader, payload, packetNumber, keyPhaseChanged);
  }
}

Future<(SecretKey, SecretKey, SecretKey)> deriveKeyIvHp({
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

  final key = await hkdfExpandLabel(hkdf, secret, keyLabel, [], keySize);
  final iv = await hkdfExpandLabel(hkdf, secret, ivLabel, [], ivSize);
  final hp = await hkdfExpandLabel(hkdf, secret, hpLabel, [], keySize);

  return (key, iv, hp);
}
