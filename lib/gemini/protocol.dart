import 'dart:typed_data';

/// Defines the QUIC protocol version.
enum Version { version1, version2 }

/// A helper class to hold byte lengths for packet numbers.
class PacketNumberLen {
  static const int len1 = 1;
  static const int len2 = 2;
  static const int len3 = 3;
  static const int len4 = 4;
}

/// A custom exception for decryption failures.
class DecryptionFailedException implements Exception {
  final String message;
  DecryptionFailedException(this.message);
  @override
  String toString() => 'DecryptionFailedException: $message';
}
