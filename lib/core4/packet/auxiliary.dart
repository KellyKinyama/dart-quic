// auxiliary.dart (UPDATED)
import 'dart:typed_data';
import 'dart:math';
import 'dart:convert'; // For utf8 encoding for "QUIC" string in RetryPacket

// Import cryptographic libraries
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/chacha20.dart';
import 'package:pointycastle/macs/poly1305.dart';
import 'package:pointycastle/modes/gcm.dart';
import 'package:pointycastle/key_derivators/hkdf.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';

// Placeholder for external dependencies. In a full implementation, these would be detailed.
enum EncryptionLevel { initial, handshake, zeroRtt, oneRtt }

enum PnSpace {
  initial,
  handshake,
  application,
} // Corresponds to the array in PacketParser

enum Role { client, server }

// Moved from Aead.java
abstract class Aead {
  Uint8List createHeaderProtectionMask(Uint8List sample);
  Uint8List encrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext,
    Uint8List? additionalData,
  );
  Uint8List decrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
    Uint8List? additionalData,
  );
  int getKeySize();
  int getNonceSize(); // Equivalent to IV size
}

class Version {
  final int value;
  const Version(this.value);

  static const Version QUIC_VERSION_1 = Version(0x00000001);
  static const Version QUIC_VERSION_2 = Version(
    0x00000002,
  ); // Example if V2 exists
  static const Version QUIC_RESERVED_VERSION = Version(
    0x00000000,
  ); // For Version Negotiation

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Version &&
          runtimeType == other.runtimeType &&
          value == other.value;

  @override
  int get hashCode => value.hashCode;

  static Version fromBytes(ByteBuffer buffer) {
    // Reads a 4-byte version from the current buffer position
    if (buffer.remaining < 4) {
      throw InvalidPacketException("Buffer too short for Version field");
    }
    // Need to use ByteData for reading int from ByteBuffer
    final ByteData byteData = buffer.asByteData(buffer.position, 4);
    final versionValue = byteData.getUint32(0);
    buffer.position += 4; // Advance buffer position
    return Version(versionValue);
  }
}

class VersionHolder {
  Version? version; // Holds the negotiated QUIC version for the connection
  VersionHolder([this.version]);
}

abstract class QuicFrame {} // Base class for all QUIC Frames

class PaddingFrame extends QuicFrame {} // Example of a simple frame type

abstract class PacketFilter {
  // Interface for processing a parsed QUIC packet
  void process(QuicPacket packet, PacketMetaData metaData);
}

// ConnectionSecrets placeholder moved to its own file.
// abstract class ConnectionSecrets {}

abstract class Logger {
  // Basic logging interface
  void debug(String message, [Object? error, StackTrace? stackTrace]);
  void info(String message, [Object? error, StackTrace? stackTrace]);
  void warn(String message, [Object? error, StackTrace? stackTrace]);
  void error(String message, [Object? error, StackTrace? stackTrace]);
}

// Custom exception classes for QUIC-specific errors
class InvalidPacketException implements Exception {
  final String message;
  InvalidPacketException([this.message = 'Invalid QUIC Packet']);
  @override
  String toString() => 'InvalidPacketException: $message';
}

class DecryptionException implements Exception {
  final String message;
  DecryptionException([this.message = 'Decryption failed']);
  @override
  String toString() => 'DecryptionException: $message';
}

class TransportError implements Exception {
  final String message;
  final int errorCode;
  TransportError(this.message, this.errorCode);
  @override
  String toString() => 'TransportError: $message (Code: $errorCode)';
}

class NotYetImplementedException implements Exception {
  final String message;
  NotYetImplementedException([this.message = 'Not yet implemented']);
  @override
  String toString() => 'NotYetImplementedException: $message';
}

class IntegerTooLargeException implements Exception {
  final String message;
  IntegerTooLargeException([this.message = 'Integer too large']);
  @override
  String toString() => 'IntegerTooLargeException: $message';
}

class InvalidIntegerEncodingException implements Exception {
  final String message;
  InvalidIntegerEncodingException([this.message = 'Invalid integer encoding']);
  @override
  String toString() => 'InvalidIntegerEncodingException: $message';
}

class QuicRuntimeException implements Exception {
  final String message;
  QuicRuntimeException(this.message);
  @override
  String toString() => 'QuicRuntimeException: $message';
}

// Helper for VariableLengthInteger based on RFC 9000 Section 16
// This decodes a variable-length integer from a ByteBuffer and advances its position.
class VariableLengthInteger {
  static int decode(ByteBuffer buffer) {
    if (buffer.remaining < 1) {
      throw InvalidIntegerEncodingException("Buffer too short for VLI prefix");
    }
    final ByteData byteData = buffer.asByteData(
      buffer.position,
      8,
    ); // Read up to 8 bytes for VLI
    int firstByte = byteData.getUint8(0);
    int length = 1 << ((firstByte >> 6) & 0x03);

    if (buffer.remaining < length) {
      throw InvalidIntegerEncodingException(
        "Buffer too short for VLI of length $length",
      );
    }

    int value;
    switch (length) {
      case 1:
        value = firstByte & 0x3F;
        break;
      case 2:
        value = (firstByte & 0x3F) << 8 | byteData.getUint8(1);
        break;
      case 4:
        value =
            (firstByte & 0x3F) << 24 |
            byteData.getUint8(1) << 16 |
            byteData.getUint8(2) << 8 |
            byteData.getUint8(3);
        break;
      case 8:
        // Use getUint64 for 8-byte VLI
        // Note: Dart's `int` can handle 64-bit integers.
        value =
            (firstByte & 0x3F) << 56 |
            byteData.getUint64(1); // Read remaining 7 bytes as Uint64
        break;
      default:
        throw InvalidIntegerEncodingException("Invalid VLI length prefix");
    }
    buffer.position += length; // Advance buffer position
    return value;
  }
}

class PacketMetaData {
  // Placeholder for metadata about the received packet (e.g., receive time, source address)
}

// Extension to provide `forEachIndexed` similar to some Java stream functionalities.
extension IterableByteBuffer on ByteBuffer {
  Uint8List asUint8List() {
    return Uint8List.view(this);
  }

  int get remaining => lengthInBytes - position;
  set position(int newPosition) {
    // This is a common pattern to manage position in a ByteBuffer
    // by creating sub-views or managing offset manually.
    // For simplicity, let's assume a custom class wrapper around ByteBuffer
    // that manages `position`. For direct `ByteBuffer`, `Uint8List.view` and
    // `sublist` are the ways to "advance".

    // For now, let's use a class with a `_position` member.
    // If this is a direct `ByteBuffer`, this `set position` won't work as expected.
    // The previous implementation used `buffer.asByteData().buffer.asByteBuffer(offset, length)`
    // which effectively creates a new buffer view. I will adjust the Parser and Packet
    // classes to explicitly pass sub-buffers or offsets.
    throw UnimplementedError(
      "ByteBuffer extension `position` is for conceptual clarity. "
      "Actual use requires creating sub-buffers or managing offsets.",
    );
  }

  int get position => throw UnimplementedError(
    "ByteBuffer extension `position` is for conceptual clarity. "
    "Actual use requires creating sub-buffers or managing offsets.",
  );
}

// Simple utility to compare Uint8Lists
bool listEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Hkdf implementation using pointycastle
class Hkdf {
  static Uint8List deriveKey(
    Digest digest,
    Uint8List secret,
    int length, {
    Uint8List? salt,
    Uint8List? info,
  }) {
    final hkdf = HKDF(digest);
    hkdf.init(
      HKDFParameters(secret, salt ?? Uint8List(0), info ?? Uint8List(0)),
    );
    return hkdf.process(length);
  }
}
