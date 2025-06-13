// Example of a conceptual readVarInt function
// This would be much more complex to handle all cases correctly.
import 'dart:typed_data';

int readVarInt(Uint8List data, int offset) {
  final firstByte = data[offset];
  final prefix = (firstByte >> 6) & 0x03;
  if (prefix == 0x00) {
    return firstByte & 0x3F; // 6 bits
  } else if (prefix == 0x01) {
    return ByteData.view(data.buffer).getUint16(offset) & 0x3FFF; // 14 bits
  } else if (prefix == 0x10) { // This prefix is 2 in binary, which is 0x2. The text states 0x11, which would be 3.
                             // There seems to be a slight discrepancy between the text and standard varint notation.
                             // QUIC varints are 00, 01, 10, 11 for 1, 2, 4, 8 bytes respectively.
                             // If it's 0x10 (binary 10), then it's 4 bytes, 30 bits.
    return ByteData.view(data.buffer).getUint32(offset) & 0x3FFFFFFF; // 30 bits
  } else if (prefix == 0x11) { // Binary 11
    // For 8 bytes (62 bits)
    return ByteData.view(data.buffer).getUint64(offset) & 0x3FFFFFFFFFFFFFFF; // 62 bits
  }
  throw Exception('Invalid varint prefix');
}

// Similar `writeVarInt` function would be needed.