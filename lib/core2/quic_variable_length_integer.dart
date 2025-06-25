import 'dart:typed_data';

/// Utility class for encoding and decoding QUIC variable-length integers.
///
/// See RFC 9000, Section 16.
class QuicVariableLengthInteger {
  /// Encodes a non-negative integer into a variable-length QUIC integer.
  ///
  /// Throws [ArgumentError] if the value is negative or exceeds 62 bits.
  static Uint8List encode(int value) {
    if (value < 0) {
      throw ArgumentError('Value must be non-negative.');
    }
    if (value > (1 << 62) - 1) {
      // Max 62-bit value
      throw ArgumentError(
        'Value exceeds maximum 62-bit integer supported by QUIC VLQ.',
      );
    }

    if (value < (1 << 6)) {
      // 1-byte encoding (00xxxxxxxx)
      final buffer = Uint8List(1);
      buffer[0] = value & 0x3F; // Mask out the 2 MSBs, set 00
      return buffer;
    } else if (value < (1 << 14)) {
      // 2-byte encoding (01xxxxxxxx xxxxxxxx)
      final buffer = Uint8List(2);
      final byteData = ByteData.view(buffer.buffer);
      byteData.setUint16(
        0,
        (0x4000 | value) & 0x7FFF,
        Endian.big,
      ); // Set 01 prefix
      return buffer;
    } else if (value < (1 << 30)) {
      // 4-byte encoding (10xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx)
      final buffer = Uint8List(4);
      final byteData = ByteData.view(buffer.buffer);
      byteData.setUint32(
        0,
        (0x80000000 | value) & 0xBFFFFFFF,
        Endian.big,
      ); // Set 10 prefix
      return buffer;
    } else {
      // 8-byte encoding (11xxxxxxxx ...)
      final buffer = Uint8List(8);
      final byteData = ByteData.view(buffer.buffer);
      // Dart's setUint64 handles up to 64 bits. For QUIC VLQ, it's 62 bits, so direct set works.
      byteData.setUint64(
        0,
        (0xC000000000000000 | value),
        Endian.big,
      ); // Set 11 prefix
      return buffer;
    }
  }

  /// Decodes a variable-length QUIC integer from a [Uint8List].
  ///
  /// Returns a [MapEntry] where the key is the decoded integer value
  /// and the value is the number of bytes consumed.
  /// Throws [ArgumentError] if the buffer is too short.
  static MapEntry<int, int> decode(Uint8List buffer, [int offset = 0]) {
    if (offset >= buffer.length) {
      throw ArgumentError('Buffer is too short to read VLQ header.');
    }

    final ByteData byteData = ByteData.view(
      buffer.buffer,
      buffer.offsetInBytes + offset,
    );
    final int firstByte = byteData.getUint8(0);
    final int prefix =
        (firstByte & 0xC0) >> 6; // Extract the two most significant bits

    switch (prefix) {
      case 0x00: // 1-byte encoding
        return MapEntry(firstByte & 0x3F, 1);
      case 0x01: // 2-byte encoding
        if (buffer.length - offset < 2) {
          throw ArgumentError('Buffer too short for 2-byte VLQ.');
        }
        return MapEntry(byteData.getUint16(0, Endian.big) & 0x3FFF, 2);
      case 0x02: // 4-byte encoding
        if (buffer.length - offset < 4) {
          throw ArgumentError('Buffer too short for 4-byte VLQ.');
        }
        return MapEntry(byteData.getUint32(0, Endian.big) & 0x3FFFFFFF, 4);
      case 0x03: // 8-byte encoding
        if (buffer.length - offset < 8) {
          throw ArgumentError('Buffer too short for 8-byte VLQ.');
        }
        return MapEntry(
          byteData.getUint64(0, Endian.big) & 0x3FFFFFFFFFFFFFFF,
          8,
        );
      default:
        // This case should theoretically not be reachable due to `prefix` definition
        throw StateError('Invalid VLQ prefix encountered.');
    }
  }

  /// Returns the number of bytes required to encode an integer as a variable-length integer.
  static int getEncodedLength(int value) {
    if (value < 0) {
      throw ArgumentError('Variable-length integers cannot be negative.');
    }
    if (value <= 63) {
      // 0x3f
      return 1;
    } else if (value <= 16383) {
      // 0x3fff
      return 2;
    } else if (value <= 1073741823) {
      // 0x3fffffff
      return 4;
    } else if (value <= 4611686018427387903) {
      // 0x3fffffffffffffff (2^62 - 1)
      return 8;
    } else {
      throw ArgumentError(
        'Value $value is too large for a variable-length integer (max 2^62-1).',
      );
    }
  }
}
