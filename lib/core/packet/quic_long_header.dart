import 'dart:typed_data';
import 'package:collection/collection.dart';

import 'quic_packet_header.dart'; // For deep equality checks if needed

class QuicLongHeader extends QuicPacketHeader {
  final int longPacketType;
  final int typeSpecificBits;
  final int version;
  final int destConnectionIdLength;
  final Uint8List? destConnectionId;
  final int sourceConnectionIdLength;
  final Uint8List? sourceConnectionId;
  // Note: The text also mentions a 'Length (i)' field in the Initial packet's long header.
  // This is a crucial field for packet coalescing, but it's part of the Type-Specific Payload
  // for the Initial Packet type, so we'll handle it there. The general Long Header
  // itself doesn't explicitly list 'Length' as a top-level field outside of its
  // specific packet types.

  QuicLongHeader({
    required int headerForm,
    required int fixedBit,
    required this.longPacketType,
    required this.typeSpecificBits,
    required this.version,
    required this.destConnectionIdLength,
    this.destConnectionId,
    required this.sourceConnectionIdLength,
    this.sourceConnectionId,
  }) : super(headerForm: headerForm, fixedBit: fixedBit);

  /// Parses a byte array into a QuicLongHeader object.
  factory QuicLongHeader.parse(Uint8List data) {
    if (data.length < 9) {
      // Minimum size: 1 byte for first byte + 4 for version + 2 for conn ID lengths + 2 for 0-length CIDs
      throw FormatException('Insufficient data for a complete Long Header.');
    }

    int offset = 0;
    final firstByte = data[offset++];

    final headerForm = (firstByte >> 7) & 0x01;
    final fixedBit = (firstByte >> 6) & 0x01;
    final longPacketType = (firstByte >> 4) & 0x03;
    final typeSpecificBits =
        firstByte &
        0x0F; // For Initial packet, this would be Reserved + Packet Number Length

    // Read 32-bit version
    final version = data.buffer.asByteData().getUint32(offset);
    offset += 4;

    final destConnectionIdLength = data[offset++];
    Uint8List? destConnectionId;
    if (destConnectionIdLength > 0) {
      if (offset + destConnectionIdLength > data.length) {
        throw FormatException(
          'Malformed Long Header: Destination Connection ID length extends beyond data.',
        );
      }
      destConnectionId = data.sublist(offset, offset + destConnectionIdLength);
      offset += destConnectionIdLength;
    }

    final sourceConnectionIdLength = data[offset++];
    Uint8List? sourceConnectionId;
    if (sourceConnectionIdLength > 0) {
      if (offset + sourceConnectionIdLength > data.length) {
        throw FormatException(
          'Malformed Long Header: Source Connection ID length extends beyond data.',
        );
      }
      sourceConnectionId = data.sublist(
        offset,
        offset + sourceConnectionIdLength,
      );
      offset += sourceConnectionIdLength;
    }

    // The remainder of the data is the Type-Specific Payload.
    // For a generic Long Header, we don't parse it here, but it would be passed
    // to a more specific packet type parser (e.g., InitialPacketHeader).
    // The text implies 'Type-Specific Payload' is the part after connection IDs.

    return QuicLongHeader(
      headerForm: headerForm,
      fixedBit: fixedBit,
      longPacketType: longPacketType,
      typeSpecificBits: typeSpecificBits,
      version: version,
      destConnectionIdLength: destConnectionIdLength,
      destConnectionId: destConnectionId,
      sourceConnectionIdLength: sourceConnectionIdLength,
      sourceConnectionId: sourceConnectionId,
    );
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    int firstByte =
        (headerForm << 7) |
        (fixedBit << 6) |
        (longPacketType << 4) |
        typeSpecificBits;
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
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'QuicLongHeader(headerForm: $headerForm, fixedBit: $fixedBit, longPacketType: $longPacketType, typeSpecificBits: $typeSpecificBits, version: 0x${version.toRadixString(16)}, destConnectionIdLength: $destConnectionIdLength, destConnectionId: ${destConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, sourceConnectionIdLength: $sourceConnectionIdLength, sourceConnectionId: ${sourceConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()})';
  }
}
