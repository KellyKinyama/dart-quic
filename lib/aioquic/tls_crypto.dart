// The following code is a Dart translation of the `crypto.c` C module.
// This translation re-implements the cryptographic logic using high-level
// Dart classes and types, as a direct translation of the C code with
// OpenSSL bindings would require `dart:ffi`. This version assumes the
// existence of a suitable cryptographic library in Dart, such as `Pointy Castle`,
// and provides a conceptual implementation based on the C logic.
// Error handling is done with a custom exception class, `CryptoError`, and
// idiomatic Dart `throw` statements instead of C macros.

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

// Constants from the C code
const int aeadKeyLengthMax = 32;
const int aeadNonceLength = 12;
const int aeadTagLength = 16;
const int packetLengthMax = 1500;
const int packetNumberLengthMax = 4;
const int sampleLength = 16;

/// Custom exception for cryptographic errors.
class CryptoError implements Exception {
  final String message;
  CryptoError(this.message);

  @override
  String toString() => 'CryptoError: $message';
}

/// A conceptual implementation of the AEAD cryptographic object.
class AEAD {
  final Uint8List _key;
  final Uint8List _iv;
  final String _cipherName;
  late final GcmCodec _codec;

  AEAD({
    required String cipherName,
    required Uint8List key,
    required Uint8List iv,
  }) : _cipherName = cipherName,
       _key = key,
       _iv = iv {
    if (key.length > aeadKeyLengthMax) {
      throw CryptoError('Invalid key length');
    }
    if (iv.length > aeadNonceLength) {
      throw CryptoError('Invalid iv length');
    }

    // This is a conceptual implementation. In a real-world scenario,
    // you would use a library like Pointy Castle to handle the actual
    // encryption and decryption.
    // For example, you would initialize an AEAD algorithm here.
    switch (cipherName) {
      case 'aes-128-gcm':
      case 'aes-256-gcm':
        _codec = GcmCodec();
        break;
      default:
        throw CryptoError('Invalid cipher name: $cipherName');
    }
  }

  Uint8List decrypt({
    required Uint8List data,
    required Uint8List associated,
    required int pn,
  }) {
    if (data.length < aeadTagLength || data.length > packetLengthMax) {
      throw CryptoError('Invalid payload length');
    }

    final nonce = Uint8List.fromList(_iv);
    for (var i = 0; i < 8; ++i) {
      nonce[aeadNonceLength - 1 - i] ^= (pn >> (8 * i));
    }

    // A real implementation would use a cryptographic library.
    // This is a placeholder to show the logic.
    final cipher = BlockCipher('AES/GCM')
      ..init(key: _key, nonce: nonce, associatedData: associated);
    final tag = data.sublist(data.length - aeadTagLength);
    final ciphertext = data.sublist(0, data.length - aeadTagLength);

    try {
      final plaintext = cipher.decrypt(ciphertext, tag: tag);
      return plaintext;
    } on Exception {
      throw CryptoError('Payload decryption failed');
    }
  }

  Uint8List encrypt({
    required Uint8List data,
    required Uint8List associated,
    required int pn,
  }) {
    if (data.length > packetLengthMax) {
      throw CryptoError('Invalid payload length');
    }

    final nonce = Uint8List.fromList(_iv);
    for (var i = 0; i < 8; ++i) {
      nonce[aeadNonceLength - 1 - i] ^= (pn >> (8 * i));
    }

    // A real implementation would use a cryptographic library.
    // This is a placeholder to show the logic.
    final cipher = BlockCipher('AES/GCM')
      ..init(key: _key, nonce: nonce, associatedData: associated);
    final result = cipher.encrypt(data);

    final output = Uint8List(data.length + aeadTagLength);
    output.setAll(0, result.ciphertext);
    output.setAll(data.length, result.tag);
    return output;
  }
}

/// A conceptual implementation of the HeaderProtection cryptographic object.
class HeaderProtection {
  final String _cipherName;
  final Uint8List _key;
  final bool _isChacha20;
  final Uint8List _mask = Uint8List(31);
  final Uint8List _zero = Uint8List(5);

  HeaderProtection({required String cipherName, required Uint8List key})
    : _cipherName = cipherName,
      _key = key,
      _isChacha20 = cipherName == 'chacha20' {
    // In a real-world scenario, we would initialize the cipher here.
  }

  Uint8List _maskHeader({required Uint8List sample}) {
    // Conceptual implementation of `HeaderProtection_mask`
    // In a real implementation, this would use a cryptographic library.
    Uint8List mask;
    if (_isChacha20) {
      // This is a simplification; ChaCha20 uses a different key stream generation.
      final cipher = Cipher('ChaCha20')..init(key: _key, nonce: sample);
      mask = cipher.process(_zero);
    } else {
      final cipher = Cipher('AES/ECB')..init(key: _key);
      mask = cipher.process(sample.sublist(0, sampleLength));
    }
    return mask;
  }

  Uint8List apply({required Uint8List header, required Uint8List payload}) {
    final pnLength = (header[0] & 0x03) + 1;
    final pnOffset = header.length - pnLength;
    final sample = payload.sublist(packetNumberLengthMax - pnLength);

    final mask = _maskHeader(sample: sample);

    final buffer = Uint8List(header.length + payload.length);
    buffer.setAll(0, header);
    buffer.setAll(header.length, payload);

    if ((buffer[0] & 0x80) != 0) {
      buffer[0] ^= mask[0] & 0x0F;
    } else {
      buffer[0] ^= mask[0] & 0x1F;
    }

    for (var i = 0; i < pnLength; ++i) {
      buffer[pnOffset + i] ^= mask[1 + i];
    }
    return buffer;
  }

  Tuple<Uint8List, int, int> remove({
    required Uint8List packet,
    required int pnOffset,
  }) {
    final sample = packet.sublist(pnOffset + packetNumberLengthMax);

    final mask = _maskHeader(sample: sample);

    final buffer = Uint8List(pnOffset + packetNumberLengthMax);
    buffer.setAll(0, packet.sublist(0, pnOffset + packetNumberLengthMax));

    if ((buffer[0] & 0x80) != 0) {
      buffer[0] ^= mask[0] & 0x0F;
    } else {
      buffer[0] ^= mask[0] & 0x1F;
    }

    final pnLength = (buffer[0] & 0x03) + 1;
    var pnTruncated = 0;
    for (var i = 0; i < pnLength; ++i) {
      buffer[pnOffset + i] ^= mask[1 + i];
      pnTruncated |= buffer[pnOffset + i] << (8 * (pnLength - 1 - i));
    }

    return Tuple(buffer.sublist(0, pnOffset + pnLength), pnLength, pnTruncated);
  }
}

// A simple utility class to represent a tuple, as Dart does not have a native one.
class Tuple<T1, T2, T3> {
  final T1 first;
  final T2 second;
  final T3 third;
  Tuple(this.first, this.second, this.third);
}

// Dummy classes for the sake of a complete example.
class Cipher {
  Cipher(String name);
  void init({
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? associatedData,
  }) {}
  Uint8List process(Uint8List data) => Uint8List(0);
  (Uint8List, Uint8List) encrypt(Uint8List data) =>
      (Uint8List(0), Uint8List(0));
  Uint8List decrypt(Uint8List data, {required Uint8List tag}) => Uint8List(0);
}

class BlockCipher {
  BlockCipher(String name);
  void init({
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? associatedData,
  }) {}
  (Uint8List, Uint8List) encrypt(Uint8List data) =>
      (Uint8List(0), Uint8List(0));
  Uint8List decrypt(Uint8List data, {required Uint8List tag}) => Uint8List(0);
}

class GcmCodec {}

extension on List<int> {
  String encode(List<int> data) {
    return hex.encode(data);
  }
}
