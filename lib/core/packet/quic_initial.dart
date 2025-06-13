import 'dart:typed_data';

import 'quic_long_header.dart';

// Helper for reading/writing QUIC variable-length integers (varints)
// This is a simplified implementation for illustration.
// A robust version would handle all 4 varint lengths and potential errors.
class VarInt {
  static int read(Uint8List data, int offset) {
    if (offset >= data.length) {
      throw FormatException('Attempted to read varint beyond data bounds.');
    }
    final firstByte = data[offset];
    final prefix = (firstByte >> 6) & 0x03;
    int value;
    int bytesRead;

    if (prefix == 0x00) {
      // 1-byte varint
      value = firstByte & 0x3F;
      bytesRead = 1;
    } else if (prefix == 0x01) {
      // 2-byte varint
      if (offset + 1 >= data.length)
        throw FormatException('Incomplete 2-byte varint.');
      value = data.buffer.asByteData().getUint16(offset) & 0x3FFF;
      bytesRead = 2;
    } else if (prefix == 0x02) {
      // 4-byte varint
      if (offset + 3 >= data.length)
        throw FormatException('Incomplete 4-byte varint.');
      value = data.buffer.asByteData().getUint32(offset) & 0x3FFFFFFF;
      bytesRead = 4;
    } else if (prefix == 0x03) {
      // 8-byte varint
      if (offset + 7 >= data.length)
        throw FormatException('Incomplete 8-byte varint.');
      // Dart's int can handle up to 63 bits, so Uint64 works for 62-bit varint
      value = data.buffer.asByteData().getUint64(offset) & 0x3FFFFFFFFFFFFFFF;
      bytesRead = 8;
    } else {
      throw FormatException('Invalid varint prefix: $prefix');
    }
    return value;
  }

  static Uint8List write(int value) {
    final builder = BytesBuilder();
    if (value < (1 << 6)) {
      // 1-byte
      builder.addByte(value & 0x3F);
    } else if (value < (1 << 14)) {
      // 2-byte
      builder.add(
        Uint8List(2)..buffer.asByteData().setUint16(0, value | 0x4000),
      );
    } else if (value < (1 << 30)) {
      // 4-byte
      builder.add(
        Uint8List(4)..buffer.asByteData().setUint32(0, value | 0x80000000),
      );
    } else if (value < (1 << 62)) {
      // 8-byte
      builder.add(
        Uint8List(8)
          ..buffer.asByteData().setUint64(0, value | 0xC000000000000000),
      );
    } else {
      throw ArgumentError(
        'Value $value is too large for a QUIC varint (max 2^62 - 1).',
      );
    }
    return builder.toBytes();
  }

  // Determine the number of bytes a varint will occupy when written.
  static int getLength(int value) {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    if (value < (1 << 62)) return 8;
    throw ArgumentError(
      'Value $value is too large for a QUIC varint (max 2^62 - 1).',
    );
  }
}

class QuicInitialPacketHeader extends QuicLongHeader {
  final int reservedBits;
  final int
  packetNumberLengthBits; // The 'Packet Number Length' in the first byte
  final int tokenLength; // This is a varint
  final Uint8List? token;
  final int
  length; // This is a varint, the total length of the packet number + payload
  final int
  packetNumber; // This is a varint, actual length determined by packetNumberLengthBits
  final Uint8List packetPayload;

  QuicInitialPacketHeader({
    required int headerForm,
    required int fixedBit,
    required int longPacketType,
    required this.reservedBits,
    required this.packetNumberLengthBits, // Using 'Bits' to distinguish from byte length
    required int version,
    required int destConnectionIdLength,
    Uint8List? destConnectionId,
    required int sourceConnectionIdLength,
    Uint8List? sourceConnectionId,
    required this.tokenLength,
    this.token,
    required this.length,
    required this.packetNumber,
    required this.packetPayload,
  }) : super(
         headerForm: headerForm,
         fixedBit: fixedBit,
         longPacketType: longPacketType,
         // For Initial Packet, Type-Specific Bits are 2 Reserved + 2 Packet Number Length
         typeSpecificBits: (reservedBits << 2) | packetNumberLengthBits,
         version: version,
         destConnectionIdLength: destConnectionIdLength,
         destConnectionId: destConnectionId,
         sourceConnectionIdLength: sourceConnectionIdLength,
         sourceConnectionId: sourceConnectionId,
       );

  factory QuicInitialPacketHeader.parse(Uint8List data) {
    int offset = 0;
    final firstByte = data[offset++];

    final headerForm = (firstByte >> 7) & 0x01;
    final fixedBit = (firstByte >> 6) & 0x01;
    final longPacketType =
        (firstByte >> 4) & 0x03; // Should be 0 for Initial Packet Type
    final reservedBits = (firstByte >> 2) & 0x03;
    final packetNumberLengthBits =
        firstByte & 0x03; // Low order 2 bits, indicates byte length

    final version = data.buffer.asByteData().getUint32(offset);
    offset += 4;

    final destConnectionIdLength = data[offset++];
    Uint8List? destConnectionId;
    if (destConnectionIdLength > 0) {
      destConnectionId = data.sublist(offset, offset + destConnectionIdLength);
      offset += destConnectionIdLength;
    }

    final sourceConnectionIdLength = data[offset++];
    Uint8List? sourceConnectionId;
    if (sourceConnectionIdLength > 0) {
      sourceConnectionId = data.sublist(
        offset,
        offset + sourceConnectionIdLength,
      );
      offset += sourceConnectionIdLength;
    }

    // Parse Token Length (varint)
    final tokenLength = VarInt.read(data, offset);
    offset += VarInt.getLength(tokenLength); // Advance by actual varint length

    Uint8List? token;
    if (tokenLength > 0) {
      token = data.sublist(offset, offset + tokenLength);
      offset += tokenLength;
    }

    // Parse Length (varint) - this is the total length of the Packet Number and Packet Payload
    final length = VarInt.read(data, offset);
    offset += VarInt.getLength(length);

    // Parse Packet Number (length determined by packetNumberLengthBits)
    final packetNumberByteLength =
        1 << packetNumberLengthBits; // 0->1, 1->2, 2->4, 3->8 bytes
    int packetNumber;
    switch (packetNumberByteLength) {
      case 1:
        packetNumber = data[offset];
        break;
      case 2:
        packetNumber = data.buffer.asByteData().getUint16(offset);
        break;
      case 4:
        packetNumber = data.buffer.asByteData().getUint32(offset);
        break;
      case 8:
        packetNumber = data.buffer.asByteData().getUint64(offset);
        break;
      default:
        throw FormatException(
          'Invalid packet number byte length derived from bits: $packetNumberByteLength',
        );
    }
    offset += packetNumberByteLength;

    final packetPayload = data.sublist(offset);

    return QuicInitialPacketHeader(
      headerForm: headerForm,
      fixedBit: fixedBit,
      longPacketType: longPacketType,
      reservedBits: reservedBits,
      packetNumberLengthBits: packetNumberLengthBits,
      version: version,
      destConnectionIdLength: destConnectionIdLength,
      destConnectionId: destConnectionId,
      sourceConnectionIdLength: sourceConnectionIdLength,
      sourceConnectionId: sourceConnectionId,
      tokenLength: tokenLength,
      token: token,
      length: length,
      packetNumber: packetNumber,
      packetPayload: packetPayload,
    );
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    int firstByte =
        (headerForm << 7) |
        (fixedBit << 6) |
        (longPacketType << 4) |
        (reservedBits << 2) |
        packetNumberLengthBits;
    builder.addByte(firstByte);
    builder.add(Uint8List(4)..buffer.asByteData().setUint32(0, version));
    builder.addByte(destConnectionIdLength);
    if (destConnectionId != null) {
      builder.add(destConnectionId!);
    }
    builder.addByte(sourceConnectionIdLength);
    if (sourceConnectionId != null) {
      builder.add(sourceConnectionId!);
    }

    // Add Token Length (varint) and Token
    builder.add(VarInt.write(tokenLength));
    if (token != null) {
      builder.add(token!);
    }

    // Add Length (varint)
    builder.add(VarInt.write(length));

    // Add Packet Number (based on packetNumberLengthBits)
    final packetNumberByteLength = 1 << packetNumberLengthBits;
    switch (packetNumberByteLength) {
      case 1:
        builder.addByte(packetNumber);
        break;
      case 2:
        builder.add(
          Uint8List(2)..buffer.asByteData().setUint16(0, packetNumber),
        );
        break;
      case 4:
        builder.add(
          Uint8List(4)..buffer.asByteData().setUint32(0, packetNumber),
        );
        break;
      case 8:
        builder.add(
          Uint8List(8)..buffer.asByteData().setUint64(0, packetNumber),
        );
        break;
    }

    builder.add(packetPayload);
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'QuicInitialPacketHeader(headerForm: $headerForm, fixedBit: $fixedBit, longPacketType: $longPacketType, reservedBits: $reservedBits, packetNumberLengthBits: $packetNumberLengthBits, version: 0x${version.toRadixString(16)}, destConnectionIdLength: $destConnectionIdLength, destConnectionId: ${destConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, sourceConnectionIdLength: $sourceConnectionIdLength, sourceConnectionId: ${sourceConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, tokenLength: $tokenLength, token: ${token?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, length: $length, packetNumber: $packetNumber, packetPayloadLength: ${packetPayload.length})';
  }
}
