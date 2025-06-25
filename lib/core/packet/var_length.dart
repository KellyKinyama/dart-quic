// Example of a conceptual readVarInt function
// This would be much more complex to handle all cases correctly.
// import 'dart:typed_data';

// int readVarInt(Uint8List data, int offset) {
//   final firstByte = data[offset];
//   final prefix = (firstByte >> 6) & 0x03;
//   if (prefix == 0x00) {
//     return firstByte & 0x3F; // 6 bits
//   } else if (prefix == 0x01) {
//     return ByteData.view(data.buffer).getUint16(offset) & 0x3FFF; // 14 bits
//   } else if (prefix == 0x10) { // This prefix is 2 in binary, which is 0x2. The text states 0x11, which would be 3.
//                              // There seems to be a slight discrepancy between the text and standard varint notation.
//                              // QUIC varints are 00, 01, 10, 11 for 1, 2, 4, 8 bytes respectively.
//                              // If it's 0x10 (binary 10), then it's 4 bytes, 30 bits.
//     return ByteData.view(data.buffer).getUint32(offset) & 0x3FFFFFFF; // 30 bits
//   } else if (prefix == 0x11) { // Binary 11
//     // For 8 bytes (62 bits)
//     return ByteData.view(data.buffer).getUint64(offset) & 0x3FFFFFFFFFFFFFFF; // 62 bits
//   }
//   throw Exception('Invalid varint prefix');
// }

import 'dart:typed_data';

// Helper for reading/writing QUIC variable-length integers (varints)
class VarInt {
  /// Reads a variable-length integer from a [Uint8List] at a given [offset].
  ///
  /// The length of the varint is encoded in the first two bits of the first byte.
  ///
  /// Returns a Map containing 'value' and 'bytesRead'.
  static Map<String, int> read(Uint8List data, int offset) {
    if (offset >= data.length) {
      throw FormatException('Attempted to read varint beyond data bounds.');
    }
    final firstByte = data[offset];
    final prefix =
        (firstByte >> 6) & 0x03; // Extract the two most significant bits

    int value;
    int bytesRead;

    if (prefix == 0x00) {
      // 1-byte varint (00xxxxxx)
      value = firstByte & 0x3F; // Mask out the prefix bits
      bytesRead = 1;
    } else if (prefix == 0x01) {
      // 2-byte varint (01xxxxxx xxxxxxxx)
      if (offset + 1 >= data.length) {
        throw FormatException('Incomplete 2-byte varint.');
      }
      value =
          data.buffer.asByteData().getUint16(offset) &
          0x3FFF; // Mask out prefix
      bytesRead = 2;
    } else if (prefix == 0x02) {
      // 4-byte varint (10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx)
      if (offset + 3 >= data.length) {
        throw FormatException('Incomplete 4-byte varint.');
      }
      value =
          data.buffer.asByteData().getUint32(offset) &
          0x3FFFFFFF; // Mask out prefix
      bytesRead = 4;
    } else if (prefix == 0x03) {
      // 8-byte varint (11xxxxxx ... 8 bytes total)
      if (offset + 7 >= data.length) {
        throw FormatException('Incomplete 8-byte varint.');
      }
      value =
          data.buffer.asByteData().getUint64(offset) &
          0x3FFFFFFFFFFFFFFF; // Mask out prefix
      bytesRead = 8;
    } else {
      // This case should ideally not be reachable with (val >> 6) & 0x03
      // but included for robustness.
      throw FormatException('Invalid varint prefix: $prefix');
    }

    return {'value': value, 'bytesRead': bytesRead};
  }

  /// Writes an integer [value] as a variable-length integer.
  ///
  /// This method ensures the shortest possible encoding is used, as required
  /// by the RFC for Frame Type fields, and generally recommended for efficiency.
  static Uint8List write(int value) {
    if (value < 0) {
      throw ArgumentError('Variable-length integer must be non-negative.');
    }

    final BytesBuilder builder = BytesBuilder();

    if (value <= 0x3F) {
      // 1-byte encoding (6 bits)
      builder.addByte(value & 0x3F); // Prefix 00
    } else if (value <= 0x3FFF) {
      // 2-byte encoding (14 bits)
      final int encodedValue = (0x01 << 14) | (value & 0x3FFF); // Prefix 01
      builder.add(Uint8List(2)..buffer.asByteData().setUint16(0, encodedValue));
    } else if (value <= 0x3FFFFFFF) {
      // 4-byte encoding (30 bits)
      final int encodedValue = (0x02 << 30) | (value & 0x3FFFFFFF); // Prefix 10
      builder.add(Uint8List(4)..buffer.asByteData().setUint32(0, encodedValue));
    } else if (value <= 0x3FFFFFFFFFFFFFFF) {
      // 8-byte encoding (62 bits)
      final int encodedValue =
          (0x03 << 62) | (value & 0x3FFFFFFFFFFFFFFF); // Prefix 11
      builder.add(Uint8List(8)..buffer.asByteData().setUint64(0, encodedValue));
    } else {
      throw ArgumentError(
        'Value $value is too large to be encoded as a 62-bit varint.',
      );
    }
    return builder.toBytes();
  }

  //   // Determine the number of bytes a varint will occupy when written.
  // static int getLength(int value) {
  //   if (value < (1 << 6)) return 1;
  //   if (value < (1 << 14)) return 2;
  //   if (value < (1 << 30)) return 4;
  //   if (value < (1 << 62)) return 8;
  //   throw ArgumentError(
  //     'Value $value is too large for a QUIC varint (max 2^62 - 1).',
  //   );
  // }
}
