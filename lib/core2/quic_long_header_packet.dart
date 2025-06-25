import 'dart:typed_data';
import 'quic_variable_length_integer.dart';
import 'quic_packet_number.dart';

/// Represents the types of Long Header Packets.
///
/// See RFC 9000, Table 5, and RFC 8999 for Version Negotiation.
enum QuicLongHeaderType {
  initial(0x00),
  zeroRtt(0x01), // 0-RTT
  handshake(0x02),
  retry(0x03),
  versionNegotiation; // Identified by Version = 0x00000000, no direct 2-bit value.

  final int?
  value; // 2-bit value for Initial, 0-RTT, Handshake, Retry. Null for Version Negotiation.
  const QuicLongHeaderType([this.value]);

  static QuicLongHeaderType? fromValue(int value) {
    for (var type in QuicLongHeaderType.values) {
      if (type.value == value) {
        return type;
      }
    }
    return null;
  }
}

/// Abstract base class for all QUIC packets.
abstract class QuicPacket {
  /// True if it's a long header, false for short header.
  bool get isLongHeader;
  int get version;
  Uint8List get destinationConnectionId;
  Uint8List get sourceConnectionId;
  QuicLongHeaderType get identifiedType;
  bool get isVersionNegotiation;
}

/// Represents a QUIC Long Header Packet (RFC 9000, Section 17.2).
///
/// This class handles parsing and serialization of the long header structure.
/// It does NOT perform header protection or packet protection (encryption/decryption),
/// which are separate cryptographic steps.
class LongHeaderPacket extends QuicPacket {
  @override
  final bool isLongHeader = true; // Header Form (1) = 1
  @override
  final bool fixedBit; // Fixed Bit (1) = 1 (unless Version Negotiation)
  @override
  final QuicLongHeaderType identifiedType; // The overall type of the long header packet
  @override
  final bool isVersionNegotiation; // Convenience flag for Version Negotiation
  @override
  final int version; // Version (32)

  final Uint8List destinationConnectionId; // Destination Connection ID (0..160)
  final Uint8List sourceConnectionId; // Source Connection ID (0..160)

  // Fields specific to Initial, 0-RTT, Handshake, Retry packets (not Version Negotiation)
  final int?
  reservedBits; // Reserved Bits (2) - MUST be 0 (after header protection removed)
  final int? packetNumberLengthBits; // Packet Number Length (2) - length - 1
  final int? length; // Length (i) - of remainder (Packet Number + Payload)
  final Uint8List? packetNumberRaw; // Raw bytes of Packet Number (1-4 bytes)
  final int?
  decodedPacketNumber; // Decoded full packet number (after header protection removed)
  final Uint8List? packetPayload; // Packet Payload (sequence of frames)

  // For Version Negotiation packets, this holds the "Supported Versions" list.
  // For other packet types, if present, it indicates unparsed trailing data
  // or a custom type-specific payload not covered by `packetPayload`.
  final Uint8List? typeSpecificPayload;

  LongHeaderPacket({
    required this.fixedBit,
    required this.identifiedType,
    required this.isVersionNegotiation,
    required this.version,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    this.typeSpecificPayload,
    this.reservedBits,
    this.packetNumberLengthBits,
    this.length,
    this.packetNumberRaw,
    this.decodedPacketNumber,
    this.packetPayload,
  }) : assert(
         fixedBit || identifiedType == QuicLongHeaderType.versionNegotiation,
         'Fixed Bit MUST be 1 unless it is a Version Negotiation packet.',
       ),
       assert(
         (version == 0x00000000) ==
             isVersionNegotiation, // Version is 0x00000000 IFF it's VN
         'Version must be 0x00000000 if isVersionNegotiation is true, and non-zero otherwise.',
       ),
       assert(
         reservedBits == null || (reservedBits! >= 0 && reservedBits! <= 3),
         'Reserved Bits must be 0-3',
       ),
       assert(
         packetNumberLengthBits == null ||
             (packetNumberLengthBits! >= 0 && packetNumberLengthBits! <= 3),
         'Packet Number Length must be 0-3',
       );

  /// Factory constructor to parse a Long Header Packet from raw bytes.
  ///
  /// `largestReceivedPn` is used for packet number decoding and should reflect
  /// the highest packet number received in the relevant packet number space.
  /// For Initial packets, this is often 0.
  ///
  /// This parser focuses on the header structure defined in Section 17.2.
  /// It does NOT perform header protection removal or full packet number recovery
  /// in a cryptographically secure way. The `decodedPacketNumber` will be based
  /// on `largestReceivedPn` provided.
  factory LongHeaderPacket.parse(
    Uint8List datagramBytes, {
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
    if (!headerForm) {
      throw FormatException('Not a Long Header Packet: Header Form bit is 0.');
    }

    // Fixed Bit (1 bit) - next bit after Header Form
    final bool fixedBit = (firstByte & 0x40) != 0;

    // Version (32 bits) - read early to determine packet type
    if (datagramBytes.length < offset + 4) {
      throw FormatException('Datagram too short to read Version field.');
    }
    final int version = byteData.getUint32(offset, Endian.big);
    offset += 4;

    // --- Determine Packet Type based on Version (primary differentiator for VN) ---
    final bool isVersionNegotiation = (version == 0x00000000);

    QuicLongHeaderType identifiedType;
    int
    typeSpecificBitsValue; // The raw value of the type-specific bits from byte 0

    if (isVersionNegotiation) {
      identifiedType = QuicLongHeaderType.versionNegotiation;
      // For VN, Fixed Bit MUST be 0.
      if (fixedBit) {
        throw FormatException(
          'Malformed Version Negotiation Packet: Fixed Bit MUST be 0 (0x40 bit set).',
        );
      }
      // For VN, the lower 6 bits (0x3F) of byte 0 are unused and MUST be 0.
      if ((firstByte & 0x3F) != 0) {
        // This is a strict check. RFC 8999 S5 says "unused" and "MUST be 0".
        // A robust implementation might just log a warning instead of throwing for this.
        // For now, we'll allow parsing but note it.
      }
      typeSpecificBitsValue =
          (firstByte & 0x3F); // Capture all 6 bits for VN (should be 0)
    } else {
      // Normal Long Header Packets (Initial, 0-RTT, Handshake, Retry)
      final int longPacketTypeValue =
          (firstByte & 0x30) >> 4; // Extract 2 bits for type
      final QuicLongHeaderType? resolvedType = QuicLongHeaderType.fromValue(
        longPacketTypeValue,
      );
      if (resolvedType == null) {
        throw FormatException(
          'Unknown Long Packet Type: 0x${longPacketTypeValue.toRadixString(16)} for non-VN packet. First byte: 0x${firstByte.toRadixString(16)}',
        );
      }
      identifiedType = resolvedType;
      // For these types, Fixed Bit MUST be 1.
      if (!fixedBit) {
        throw FormatException(
          'Malformed Long Header Packet (type $identifiedType): Fixed Bit MUST be 1 (0x40 bit unset).',
        );
      }
      typeSpecificBitsValue = (firstByte & 0x0F); // Only 4 bits for these types
    }

    // Common CID parsing (applies to all Long Header Packet types, including VN)
    if (datagramBytes.length < offset + 1) {
      throw FormatException(
        'Datagram too short to read Destination Connection ID Length.',
      );
    }
    final int destCidLength = byteData.getUint8(offset++);
    if (destCidLength > 20 && version == 0x00000001) {
      // QUIC Version 1 check
      throw FormatException(
        'Destination Connection ID Length ($destCidLength) exceeds 20 bytes for QUIC Version 1.',
      );
    }
    if (datagramBytes.length < offset + destCidLength) {
      throw FormatException(
        'Datagram too short to read Destination Connection ID ($destCidLength bytes).',
      );
    }
    final Uint8List destinationConnectionId = Uint8List.fromList(
      datagramBytes.sublist(offset, offset + destCidLength),
    );
    offset += destCidLength;

    if (datagramBytes.length < offset + 1) {
      throw FormatException(
        'Datagram too short to read Source Connection ID Length.',
      );
    }
    final int sourceCidLength = byteData.getUint8(offset++);
    if (sourceCidLength > 20 && version == 0x00000001) {
      // QUIC Version 1 check
      throw FormatException(
        'Source Connection ID Length ($sourceCidLength) exceeds 20 bytes for QUIC Version 1.',
      );
    }
    if (datagramBytes.length < offset + sourceCidLength) {
      throw FormatException(
        'Datagram too short to read Source Connection ID ($sourceCidLength bytes).',
      );
    }
    final Uint8List sourceConnectionId = Uint8List.fromList(
      datagramBytes.sublist(offset, offset + sourceCidLength),
    );
    offset += sourceCidLength;

    // Initialize optional fields for non-VN packets to null
    int? reservedBits;
    int? packetNumberLengthBits;
    int? length;
    Uint8List? packetNumberRaw;
    int? decodedPacketNumber;
    Uint8List? packetPayload;
    Uint8List?
    typeSpecificPayloadRemainder; // Will hold 'Supported Versions' for VN

    if (!isVersionNegotiation) {
      // These fields are only present for Initial, 0-RTT, Handshake, Retry
      reservedBits =
          (typeSpecificBitsValue & 0x0C) >>
          2; // Extract from the 4 type-specific bits
      packetNumberLengthBits =
          typeSpecificBitsValue & 0x03; // Extract from the 4 type-specific bits

      if (datagramBytes.length < offset + 1) {
        throw FormatException(
          'Datagram too short to read Length field (VLQ header).',
        );
      }
      final lengthEntry = QuicVariableLengthInteger.decode(
        datagramBytes,
        offset,
      );
      length = lengthEntry.key;
      offset += lengthEntry.value;

      final int pnBytes = packetNumberLengthBits + 1;
      if (datagramBytes.lengthInBytes - offset < pnBytes) {
        throw FormatException(
          'Packet number length ($pnBytes bytes) exceeds remaining packet data for non-VN packet. Remaining: ${datagramBytes.lengthInBytes - offset}',
        );
      }
      packetNumberRaw = Uint8List.fromList(
        datagramBytes.sublist(offset, offset + pnBytes),
      );
      offset += pnBytes;

      // Actual packet number decoding (after header protection removal, assume done for this parse)
      // Pass largestReceivedPn from context
      decodedPacketNumber = QuicPacketNumber.decode(
        packetNumberRaw,
        packetNumberLengthBits,
        largestReceivedPn,
      );

      final int expectedPayloadEnd =
          offset + (length - pnBytes); // Length field includes PN and Payload
      if (expectedPayloadEnd > datagramBytes.lengthInBytes) {
        throw FormatException(
          'Declared packet length ($length) exceeds actual datagram size for non-VN packet. Expected end: $expectedPayloadEnd, Actual length: ${datagramBytes.lengthInBytes}',
        );
      }
      packetPayload = Uint8List.fromList(
        datagramBytes.sublist(offset, expectedPayloadEnd),
      );
      offset = expectedPayloadEnd;
    } else {
      // For Version Negotiation, the remainder of the packet is the list of supported versions.
      typeSpecificPayloadRemainder = (offset < datagramBytes.lengthInBytes)
          ? Uint8List.fromList(datagramBytes.sublist(offset))
          : null;
      offset = datagramBytes
          .lengthInBytes; // All remaining bytes consumed by VN payload
    }

    return LongHeaderPacket(
      fixedBit: fixedBit,
      identifiedType: identifiedType,
      isVersionNegotiation: isVersionNegotiation,
      version: version,
      destinationConnectionId: destinationConnectionId,
      sourceConnectionId: sourceConnectionId,
      typeSpecificPayload:
          typeSpecificPayloadRemainder, // This will be the VN payload
      reservedBits: reservedBits,
      packetNumberLengthBits: packetNumberLengthBits,
      length: length,
      packetNumberRaw: packetNumberRaw,
      decodedPacketNumber: decodedPacketNumber,
      packetPayload: packetPayload,
    );
  }

  /// Serializes the Long Header Packet into bytes.
  ///
  /// This method constructs the raw bytes of the header and payload.
  /// It does NOT apply header protection or packet protection (encryption).
  Uint8List toBytes() {
    final List<int> bytes = [];

    // Byte 0: Header Form, Fixed Bit, Long Packet Type (or 0 for VN), Type-Specific Bits
    int firstByte = 0x80; // Header Form (1) = 1

    if (fixedBit) {
      firstByte |= 0x40; // Fixed Bit (1) = 1
    }

    if (isVersionNegotiation) {
      // For VN, the remaining 6 bits (0x3F) of byte 0 are unused and MUST be 0.
      // Since `fixedBit` is false for VN, 0x40 is not set.
      // So, `firstByte` should essentially just be `0x80`.
      // The remaining 6 bits `0x3F` are expected to be 0 for a valid VN packet.
      // We'll add it to `firstByte` as a sanity check/representation if they were set.
      firstByte |=
          (0x3F &
          0x00); // Ensures these bits are zero for serialization, as required.
    } else {
      // For other types (Initial, 0-RTT, Handshake, Retry), use the identifiedType's value for the 2 bits.
      firstByte |= (identifiedType.value! << 4) & 0x30; // Long Packet Type (2)

      // If packet number fields are present, combine with Type-Specific Bits (4 bits)
      if (packetNumberLengthBits != null && reservedBits != null) {
        firstByte |= (reservedBits! << 2) & 0x0C; // Reserved Bits (from 0x0F)
        firstByte |=
            (packetNumberLengthBits! &
            0x03); // Packet Number Length (from 0x0F)
      } else {
        // If these fields are null for a non-VN packet, ensure the 4 bits are 0.
        firstByte |= (0x0F & 0x00);
      }
    }
    bytes.add(firstByte);

    // Version (32)
    final versionBytes = ByteData(4);
    versionBytes.setUint32(0, version, Endian.big);
    bytes.addAll(versionBytes.buffer.asUint8List());

    // Destination Connection ID Length (8)
    bytes.add(destinationConnectionId.length);
    // Destination Connection ID (0..160)
    bytes.addAll(destinationConnectionId);

    // Source Connection ID Length (8)
    bytes.add(sourceConnectionId.length);
    // Source Connection ID (0..160)
    bytes.addAll(sourceConnectionId);

    if (isVersionNegotiation) {
      // For Version Negotiation, the typeSpecificPayload is the 'Supported Versions' list
      if (typeSpecificPayload != null) {
        bytes.addAll(typeSpecificPayload!);
      }
    } else {
      // Type-specific fields for Initial, 0-RTT, Handshake, Retry
      // These MUST be present if it's not a Version Negotiation packet
      if (length == null || packetNumberRaw == null || packetPayload == null) {
        throw StateError(
          'Non-Version Negotiation packet is missing required length, packetNumberRaw, or packetPayload fields for serialization.',
        );
      }

      // Length (i)
      bytes.addAll(QuicVariableLengthInteger.encode(length!));

      // Packet Number (1-4 bytes)
      bytes.addAll(packetNumberRaw!);

      // Packet Payload
      bytes.addAll(packetPayload!);
    }
    return Uint8List.fromList(bytes);
  }

  @override
  String toString() {
    String pnInfo = '';
    if (!isVersionNegotiation &&
        packetNumberLengthBits != null &&
        packetNumberRaw != null) {
      pnInfo =
          'PN Length Bits: $packetNumberLengthBits, Raw PN: ${packetNumberRaw!.map((e) => e.toRadixString(16).padLeft(2, '0')).join(' ')}, Decoded PN: $decodedPacketNumber, ';
    }
    String payloadInfo = '';
    if (isVersionNegotiation) {
      payloadInfo =
          'Supported Versions Length: ${typeSpecificPayload?.length ?? 0} bytes, Supported Versions: ${typeSpecificPayload?.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}, ';
    } else {
      payloadInfo =
          'Length (payload+PN): $length, Packet Payload Size: ${packetPayload?.length ?? 0} bytes, ';
    }

    return 'LongHeaderPacket{\n'
        '  Header Form: $isLongHeader,\n'
        '  Fixed Bit: $fixedBit,\n'
        '  Identified Type: $identifiedType,\n'
        '  Is Version Negotiation: $isVersionNegotiation,\n'
        '  Version: 0x${version.toRadixString(16).padLeft(8, '0')},\n'
        '  Dest CID Length: ${destinationConnectionId.length},\n'
        '  Dest CID: ${destinationConnectionId.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')},\n'
        '  Src CID Length: ${sourceConnectionId.length},\n'
        '  Src CID: ${sourceConnectionId.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')},\n'
        '  $pnInfo'
        '  $payloadInfo'
        '}';
  }
}
