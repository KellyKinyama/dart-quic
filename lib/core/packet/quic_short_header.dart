import 'dart:typed_data';

import 'quic_packet_header.dart';

class QuicShortHeader extends QuicPacketHeader {
  final int spinBit;
  final int reservedBits;
  final int keyPhase;
  final int
  packetNumberLengthBits; // The 'Packet Number Length' in the first byte
  final Uint8List?
  destConnectionId; // Length not explicitly in header, known by receiver
  final int packetNumber; // Variable-length integer
  final Uint8List packetPayload;

  QuicShortHeader({
    required int headerForm,
    required int fixedBit,
    required this.spinBit,
    required this.reservedBits,
    required this.keyPhase,
    required this.packetNumberLengthBits,
    this.destConnectionId,
    required this.packetNumber,
    required this.packetPayload,
  }) : super(headerForm: headerForm, fixedBit: fixedBit);

  /// Parses a byte array into a QuicShortHeader object.
  /// Requires `destConnectionIdLength` to be known by the receiver.
  factory QuicShortHeader.parse(
    Uint8List data, {
    required int destConnectionIdLength,
  }) {
    int offset = 0;
    final firstByte = data[offset++];

    final headerForm = (firstByte >> 7) & 0x01; // Should be 0 for Short Header
    final fixedBit = (firstByte >> 6) & 0x01;
    final spinBit = (firstByte >> 5) & 0x01;
    final reservedBits = (firstByte >> 3) & 0x03;
    final keyPhase = (firstByte >> 2) & 0x01;
    final packetNumberLengthBits = firstByte & 0x03; // Low order 2 bits

    Uint8List? destConnectionId;
    if (destConnectionIdLength > 0) {
      if (offset + destConnectionIdLength > data.length) {
        throw FormatException(
          'Malformed Short Header: Destination Connection ID length extends beyond data.',
        );
      }
      destConnectionId = data.sublist(offset, offset + destConnectionIdLength);
      offset += destConnectionIdLength;
    }

    // Parse Packet Number (length determined by packetNumberLengthBits)
    final packetNumberByteLength = 1 << packetNumberLengthBits;
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

    return QuicShortHeader(
      headerForm: headerForm,
      fixedBit: fixedBit,
      spinBit: spinBit,
      reservedBits: reservedBits,
      keyPhase: keyPhase,
      packetNumberLengthBits: packetNumberLengthBits,
      destConnectionId: destConnectionId,
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
        (spinBit << 5) |
        (reservedBits << 3) |
        (keyPhase << 2) |
        packetNumberLengthBits;
    builder.addByte(firstByte);
    if (destConnectionId != null) {
      builder.add(destConnectionId!);
    }

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
    return 'QuicShortHeader(headerForm: $headerForm, fixedBit: $fixedBit, spinBit: $spinBit, reservedBits: $reservedBits, keyPhase: $keyPhase, packetNumberLengthBits: $packetNumberLengthBits, destConnectionId: ${destConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, packetNumber: $packetNumber, packetPayloadLength: ${packetPayload.length})';
  }
}
