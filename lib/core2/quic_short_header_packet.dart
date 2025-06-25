import 'dart:typed_data';
import 'quic_packet.dart';
import 'quic_packet_number.dart'; // For decoding packet numbers

/// Represents a QUIC Short Header (1-RTT) Packet (RFC 9000, Section 17.3.1).
///
/// This class handles parsing and serialization of the short header structure.
/// It explicitly notes fields that are header-protected, but for simplicity
/// in this structural parsing, it assumes their raw values are readable on the wire.
/// A full QUIC implementation would require header protection removal before
/// interpreting these fields.
class ShortHeaderPacket extends QuicPacket {
  @override
  final bool isLongHeader = false; // Header Form (1) = 0
  final bool fixedBit; // Fixed Bit (1) = 1
  final bool spinBit; // Spin Bit (1) - header protected
  final int reservedBits; // Reserved Bits (2) - header protected, MUST be 0
  final bool keyPhase; // Key Phase (1) - header protected
  final int
  packetNumberLengthBits; // Packet Number Length (2) - header protected, length-1

  @override
  final Uint8List destinationConnectionId; // Destination Connection ID (0..160)
  final Uint8List packetNumberRaw; // Raw bytes of Packet Number (1-4 bytes)
  final int decodedPacketNumber; // Decoded full packet number
  final Uint8List packetPayload; // Packet Payload (8..), 1-RTT protected

  ShortHeaderPacket({
    required this.fixedBit,
    required this.spinBit,
    required this.reservedBits,
    required this.keyPhase,
    required this.packetNumberLengthBits,
    required this.destinationConnectionId,
    required this.packetNumberRaw,
    required this.decodedPacketNumber,
    required this.packetPayload,
  }) : assert(fixedBit, 'Fixed Bit MUST be 1 for Short Header Packets.'),
       assert(
         reservedBits == 0,
         'Reserved Bits MUST be 0 for Short Header Packets (after protection).',
       ),
       assert(
         packetNumberLengthBits >= 0 && packetNumberLengthBits <= 3,
         'Packet Number Length must be 0-3',
       );

  /// Factory constructor to parse a Short Header Packet from raw bytes.
  ///
  /// `expectedDestinationConnectionIdLength` is crucial as the CID length
  /// is NOT encoded in the short header. This must be known from connection context.
  /// `largestReceivedPn` is used for packet number decoding.
  ///
  /// This parser focuses on the header structure defined in Section 17.3.1.
  /// It does NOT perform header protection removal or full packet number recovery
  /// in a cryptographically secure way. The `decodedPacketNumber` will be based
  /// on `largestReceivedPn` provided. Fields like `spinBit`, `reservedBits`,
  /// `keyPhase`, `packetNumberLengthBits`, and `packetNumberRaw` are read directly
  /// from the wire bytes, assuming header protection has been applied or for testing purposes.
  factory ShortHeaderPacket.parse(
    Uint8List datagramBytes, {
    required int expectedDestinationConnectionIdLength,
    int largestReceivedPn = 0,
  }) {
    final ByteData byteData = ByteData.view(datagramBytes.buffer);
    int offset = 0;

    if (datagramBytes.isEmpty) {
      throw FormatException('Empty datagram, cannot parse QUIC packet.');
    }

    final int firstByte = byteData.getUint8(offset++);

    // Header Form (1 bit) - MSB
    final bool headerForm = (firstByte & 0x80) != 0;
    if (headerForm) {
      throw FormatException('Not a Short Header Packet: Header Form bit is 1.');
    }

    // Fixed Bit (1 bit) - 0x40
    final bool fixedBit = (firstByte & 0x40) != 0;
    if (!fixedBit) {
      throw FormatException(
        'Malformed Short Header Packet: Fixed Bit MUST be 1 (0x40 bit unset).',
      );
    }

    // Spin Bit (1 bit) - 0x20
    final bool spinBit = (firstByte & 0x20) != 0;

    // Reserved Bits (2 bits) - 0x18
    final int reservedBits = (firstByte & 0x18) >> 3;
    // In a real implementation, after header protection, this MUST be 0.
    // For now, we capture its value.
    // if (reservedBits != 0) {
    //   print('Warning: Short Header Packet has non-zero Reserved Bits (0x${reservedBits.toRadixString(16)}) after assuming no header protection applied.');
    // }

    // Key Phase (1 bit) - 0x04
    final bool keyPhase = (firstByte & 0x04) != 0;

    // Packet Number Length (2 bits) - 0x03, encoded as length - 1
    final int packetNumberLengthBits = firstByte & 0x03;

    // Destination Connection ID
    if (datagramBytes.length < offset + expectedDestinationConnectionIdLength) {
      throw FormatException(
        'Datagram too short to read Destination Connection ID ($expectedDestinationConnectionIdLength bytes).',
      );
    }
    final Uint8List destinationConnectionId = Uint8List.fromList(
      datagramBytes.sublist(
        offset,
        offset + expectedDestinationConnectionIdLength,
      ),
    );
    offset += expectedDestinationConnectionIdLength;

    // Packet Number
    final int pnBytes = packetNumberLengthBits + 1;
    if (datagramBytes.lengthInBytes - offset < pnBytes) {
      throw FormatException(
        'Packet number length ($pnBytes bytes) exceeds remaining packet data for Short Header packet. Remaining: ${datagramBytes.lengthInBytes - offset}',
      );
    }
    final Uint8List packetNumberRaw = Uint8List.fromList(
      datagramBytes.sublist(offset, offset + pnBytes),
    );
    offset += pnBytes;

    final int decodedPacketNumber = QuicPacketNumber.decode(
      packetNumberRaw,
      packetNumberLengthBits,
      largestReceivedPn,
    );

    // Packet Payload
    final Uint8List packetPayload = Uint8List.fromList(
      datagramBytes.sublist(offset),
    );

    return ShortHeaderPacket(
      fixedBit: fixedBit,
      spinBit: spinBit,
      reservedBits: reservedBits,
      keyPhase: keyPhase,
      packetNumberLengthBits: packetNumberLengthBits,
      destinationConnectionId: destinationConnectionId,
      packetNumberRaw: packetNumberRaw,
      decodedPacketNumber: decodedPacketNumber,
      packetPayload: packetPayload,
    );
  }

  /// Serializes the Short Header Packet into bytes.
  ///
  /// This method constructs the raw bytes of the header and payload.
  /// It does NOT apply header protection or packet protection (encryption).
  /// For `reservedBits`, `keyPhase`, and `packetNumberLengthBits`,
  /// it serializes the values provided in the constructor (expected to be 0 for reserved, etc.).
  Uint8List toBytes() {
    final List<int> bytes = [];

    // Byte 0: Header Form, Fixed Bit, Spin Bit, Reserved Bits, Key Phase, Packet Number Length
    int firstByte = 0x00; // Header Form (1) = 0 (MSB is 0)
    firstByte |= 0x40; // Fixed Bit (1) = 1

    if (spinBit) {
      firstByte |= 0x20; // Spin Bit (1)
    }

    firstByte |=
        (reservedBits << 3) &
        0x18; // Reserved Bits (2) - MUST be 0 after protection
    if (reservedBits != 0) {
      throw StateError(
        'Attempting to serialize Short Header with non-zero Reserved Bits. They MUST be 0 before protection.',
      );
    }

    if (keyPhase) {
      firstByte |= 0x04; // Key Phase (1)
    }

    firstByte |= (packetNumberLengthBits & 0x03); // Packet Number Length (2)

    bytes.add(firstByte);

    // Destination Connection ID
    bytes.addAll(destinationConnectionId);

    // Packet Number
    bytes.addAll(packetNumberRaw);

    // Packet Payload
    bytes.addAll(packetPayload);

    return Uint8List.fromList(bytes);
  }

  @override
  String toString() {
    return 'ShortHeaderPacket{\n'
        '  Header Form: $isLongHeader,\n'
        '  Fixed Bit: $fixedBit,\n'
        '  Spin Bit: $spinBit,\n'
        '  Reserved Bits: 0x${reservedBits.toRadixString(16)},\n'
        '  Key Phase: $keyPhase,\n'
        '  PN Length Bits: $packetNumberLengthBits,\n'
        '  Dest CID Length: ${destinationConnectionId.length},\n'
        '  Dest CID: ${destinationConnectionId.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')},\n'
        '  Raw PN: ${packetNumberRaw.map((e) => e.toRadixString(16).padLeft(2, '0')).join(' ')}, Decoded PN: $decodedPacketNumber,\n'
        '  Packet Payload Size: ${packetPayload.length} bytes,\n'
        '}';
  }
}
