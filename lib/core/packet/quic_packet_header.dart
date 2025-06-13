import 'dart:typed_data';

import 'quic_initial.dart';
import 'quic_long_header.dart';
import 'quic_short_header.dart';
import 'quic_zero_rtt_packet_header.dart';

// Helper for reading/writing QUIC variable-length integers (varints)
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

abstract class QuicPacketHeader {
  final int headerForm;
  final int fixedBit;

  QuicPacketHeader({required this.headerForm, required this.fixedBit});

  factory QuicPacketHeader.parse(
    Uint8List data, {
    int? shortHeaderDestConnectionIdLength,
  }) {
    if (data.isEmpty) {
      throw ArgumentError('Packet data cannot be empty.');
    }
    final firstByte = data[0];
    final headerForm = (firstByte >> 7) & 0x01;

    if (headerForm == 1) {
      final longPacketType = (firstByte >> 4) & 0x03;
      switch (longPacketType) {
        case 0: // Initial Packet Type
          return QuicInitialPacketHeader.parse(data);
        case 1: // 0-RTT Packet Type
          return QuicZeroRTTPacketHeader.parse(data);
        // Add cases for Handshake and Retry packets if needed
        default:
          throw FormatException('Unknown Long Packet Type: $longPacketType');
      }
    } else {
      if (shortHeaderDestConnectionIdLength == null) {
        throw ArgumentError(
          'Destination Connection ID Length must be provided for Short Headers.',
        );
      }
      return QuicShortHeader.parse(
        data,
        destConnectionIdLength: shortHeaderDestConnectionIdLength,
      );
    }
  }

  bool get isAckEliciting {
    // List of non-ack-eliciting frame types
    const Set<int> nonAckElicitingTypes = {
      0x02, // ACK
      0x03, // ACK with ECN
      0x01, // PADDING (usually) - check QUIC spec for exact rules
      0x1C, // CONNECTION_CLOSE (with Error Code) - This frame can be ack-eliciting depending on context,
      // but the text specifically states if a packet *only* contains CC, it's non-eliciting.
      // For simplicity here, we'll follow the text's direct example.
    };
    return !nonAckElicitingTypes.contains(this);
  }

  Uint8List toBytes();
}

// Modify QuicPacketHeader (already defined in previous response)
// Add a method to check if a frame type is ack-eliciting
extension QuicFrameTypeExtension on int {
  bool get isAckEliciting {
    // List of non-ack-eliciting frame types
    const Set<int> nonAckElicitingTypes = {
      0x02, // ACK
      0x03, // ACK with ECN
      0x01, // PADDING (usually) - check QUIC spec for exact rules
      0x1C, // CONNECTION_CLOSE (with Error Code) - This frame can be ack-eliciting depending on context,
            // but the text specifically states if a packet *only* contains CC, it's non-eliciting.
            // For simplicity here, we'll follow the text's direct example.
    };
    return !nonAckElicitingTypes.contains(this);
  }
}