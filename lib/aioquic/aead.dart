import 'dart:typed_data';

// Custom exception for cryptographic errors, matching the Python `CryptoError(ValueError)`.
class CryptoError implements Exception {
  final String message;
  CryptoError(this.message);

  @override
  String toString() => 'CryptoError: $message';
}

class AEAD {
  AEAD({
    required Uint8List cipherName,
    required Uint8List key,
    required Uint8List iv,
  }) {
    // Implementation not provided in the original Python snippet.
  }

  Uint8List decrypt({
    required Uint8List data,
    required Uint8List associatedData,
    required int packetNumber,
  }) {
    // Implementation not provided in the original Python snippet.
    throw UnimplementedError();
  }

  Uint8List encrypt({
    required Uint8List data,
    required Uint8List associatedData,
    required int packetNumber,
  }) {
    // Implementation not provided in the original Python snippet.
    throw UnimplementedError();
  }
}

class HeaderProtection {
  HeaderProtection({required Uint8List cipherName, required Uint8List key}) {
    // Implementation not provided in the original Python snippet.
  }

  Uint8List apply({
    required Uint8List plainHeader,
    required Uint8List protectedPayload,
  }) {
    // Implementation not provided in the original Python snippet.
    throw UnimplementedError();
  }

  (Uint8List, int) remove({
    required Uint8List packet,
    required int encryptedOffset,
  }) {
    // Implementation not provided in the original Python snippet.
    throw UnimplementedError();
  }
}
