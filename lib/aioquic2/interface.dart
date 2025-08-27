// Filename: interface.dart
import 'dart:async';
import 'dart:typed_data';

/// Thrown when AEAD decryption fails, typically due to an invalid authentication tag.
class DecryptionFailedException implements Exception {
  final String message = "AEAD decryption failed";
  @override
  String toString() => message;
}

/// Thrown when cryptographic keys for a specific encryption level are not yet available.
class KeyUnavailableError implements Exception {
  final String message = "Cryptographic keys are not yet available for this epoch";
  @override
  String toString() => message;
}