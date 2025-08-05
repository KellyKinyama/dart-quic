//
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'chacha2.dart';
import 'hkdf.dart';
import '../packet.dart';

abstract class AEAD {
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  );
  Future<Uint8List> decrypt(
    Uint8List encrypted,
    Uint8List associatedData,
    Uint8List nonce,
  );
}

class CryptoPair {
  final AEAD aead;
  final HeaderProtection hp;

  CryptoPair(this.aead, this.hp);
}

abstract class HeaderProtection {
  Future<Uint8List> apply(Uint8List header, Uint8List encryptedPayload);
  Future<Uint8List> unapply(Uint8List header, Uint8List encryptedPayload);
}

class HeaderProtectionChaCha20 extends HeaderProtection {
  final ChachaCipher _cipher;

  HeaderProtectionChaCha20(Uint8List key)
    : _cipher = ChachaCipher("chacha20", secret: key);

  @override
  Future<Uint8List> apply(Uint8List header, Uint8List encryptedPayload) async {
    return await _maskHeader(header, encryptedPayload, apply: true);
  }

  @override
  Future<Uint8List> unapply(
    Uint8List header,
    Uint8List encryptedPayload,
  ) async {
    return await _maskHeader(header, encryptedPayload, apply: false);
  }

  Future<Uint8List> _maskHeader(
    Uint8List header,
    Uint8List encryptedPayload, {
    required bool apply,
  }) async {
    // According to RFC 9001, the sample is from the encrypted payload.
    // The size of the sample is 16 bytes.
    if (encryptedPayload.length < 16) {
      throw Exception('Payload must be at least 16 bytes');
    }
    final sample = encryptedPayload.sublist(0, 16);

    // The nonce must be 12 bytes.
    // The Python implementation uses the sample as the nonce, which is a 16-byte value.
    // RFC 9001, section 5.4 specifies how to derive the nonce, and in the case of ChaCha20, it's 12 bytes.
    // The Python code uses a 12-byte IV (equivalent to nonce) for header protection.
    // The aioquic library's _crypto.py actually handles this by taking a 16-byte sample and using the last 12 bytes for the nonce.
    // Let's replicate that logic.
    final nonce = Uint8List.fromList(sample.sublist(4, 16));

    final mask = await _cipher.encrypt(Uint8List(5), Uint8List(0), nonce);

    // Apply or unapply the mask to the header.
    // The mask is XORed with the first byte of the header, and the packet number.
    header[0] ^= mask[0];

    final packetNumber = header.sublist(header.length - 4, header.length);
    for (var i = 0; i < 4; i++) {
      packetNumber[i] ^= mask[i + 1];
    }
    return header;
  }
}
