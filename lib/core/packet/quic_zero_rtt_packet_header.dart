import 'dart:typed_data';

import 'quic_long_header.dart';
import 'quic_packet_header.dart';

class QuicZeroRTTPacketHeader extends QuicLongHeader {
  final int reservedBits;
  final int packetNumberLengthBits;
  final int length; // Total length of the packet number + payload (varint)
  final int packetNumber;
  final Uint8List packetPayload;

  QuicZeroRTTPacketHeader({
    required int headerForm,
    required int fixedBit,
    required int longPacketType, // Should be 1 for 0-RTT
    required this.reservedBits,
    required this.packetNumberLengthBits,
    required int version,
    required int destConnectionIdLength,
    Uint8List? destConnectionId,
    required int sourceConnectionIdLength,
    Uint8List? sourceConnectionId,
    required this.length,
    required this.packetNumber,
    required this.packetPayload,
  }) : super(
          headerForm: headerForm,
          fixedBit: fixedBit,
          longPacketType: longPacketType,
          // For 0-RTT Packet, Type-Specific Bits are 2 Reserved + 2 Packet Number Length
          typeSpecificBits: (reservedBits << 2) | packetNumberLengthBits,
          version: version,
          destConnectionIdLength: destConnectionIdLength,
          destConnectionId: destConnectionId,
          sourceConnectionIdLength: sourceConnectionIdLength,
          sourceConnectionId: sourceConnectionId,
        );

  factory QuicZeroRTTPacketHeader.parse(Uint8List data) {
    int offset = 0;
    final firstByte = data[offset++];

    final headerForm = (firstByte >> 7) & 0x01; // Should be 1
    final fixedBit = (firstByte >> 6) & 0x01;   // Should be 1
    final longPacketType = (firstByte >> 4) & 0x03; // Should be 1 for 0-RTT
    final reservedBits = (firstByte >> 2) & 0x03;
    final packetNumberLengthBits = firstByte & 0x03;

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
      sourceConnectionId = data.sublist(offset, offset + sourceConnectionIdLength);
      offset += sourceConnectionIdLength;
    }

    // Parse Length (varint) - this is the total length of the Packet Number and Packet Payload
    final length = VarInt.read(data, offset);
    offset += VarInt.getLength(length);

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
        throw FormatException('Invalid packet number byte length derived from bits: $packetNumberByteLength');
    }
    offset += packetNumberByteLength;

    final packetPayload = data.sublist(offset);

    return QuicZeroRTTPacketHeader(
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
      length: length,
      packetNumber: packetNumber,
      packetPayload: packetPayload,
    );
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    int firstByte = (headerForm << 7) | (fixedBit << 6) | (longPacketType << 4) | (reservedBits << 2) | packetNumberLengthBits;
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

    builder.add(VarInt.write(length));

    final packetNumberByteLength = 1 << packetNumberLengthBits;
    switch (packetNumberByteLength) {
      case 1:
        builder.addByte(packetNumber);
        break;
      case 2:
        builder.add(Uint8List(2)..buffer.asByteData().setUint16(0, packetNumber));
        break;
      case 4:
        builder.add(Uint8List(4)..buffer.asByteData().setUint32(0, packetNumber));
        break;
      case 8:
        builder.add(Uint8List(8)..buffer.asByteData().setUint64(0, packetNumber));
        break;
    }

    builder.add(packetPayload);
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'QuicZeroRTTPacketHeader(headerForm: $headerForm, fixedBit: $fixedBit, longPacketType: $longPacketType, reservedBits: $reservedBits, packetNumberLengthBits: $packetNumberLengthBits, version: 0x${version.toRadixString(16)}, destConnectionIdLength: $destConnectionIdLength, destConnectionId: ${destConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, sourceConnectionIdLength: $sourceConnectionIdLength, sourceConnectionId: ${sourceConnectionId?.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, length: $length, packetNumber: $packetNumber, packetPayloadLength: ${packetPayload.length})';
  }
}