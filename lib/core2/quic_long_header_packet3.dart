// Previous content of quic_variable_length_integer.dart, quic_packet_number.dart
// should be imported or placed in respective files as before.
import 'dart:typed_data';
import 'quic_variable_length_integer.dart';
import 'quic_packet_number.dart';
import 'quic_packet.dart'; // Import the new base class

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

/// Represents a QUIC Long Header Packet (RFC 9000, Section 17.2).
///
/// This class handles parsing and serialization of the long header structure.
/// It does NOT perform header protection or packet protection (encryption/decryption),
/// which are separate cryptographic steps.
class LongHeaderPacket extends QuicPacket {
  // Now extends the new base class
  @override
  final bool isLongHeader = true; // Header Form (1) = 1
  final bool fixedBit; // Fixed Bit (1) = 1 (unless Version Negotiation)
  final QuicLongHeaderType
  identifiedType; // The overall type of the long header packet
  final bool isVersionNegotiation; // Convenience flag for Version Negotiation
  final int version; // Version (32)

  @override
  final Uint8List destinationConnectionId; // Destination Connection ID (0..2040 for VN, 0..160 for others)
  final Uint8List
  sourceConnectionId; // Source Connection ID (0..2040 for VN, 0..160 for others)

  // Fields specific to Initial packets
  final int? tokenLength; // Token Length (i) - for Initial Packet
  final Uint8List? token; // Token (..) - for Initial Packet

  // Fields specific to Retry packets
  final Uint8List? retryToken; // Retry Token (..) - for Retry Packet
  final Uint8List?
  retryIntegrityTag; // Retry Integrity Tag (128) - for Retry Packet (16 bytes)

  // Fields specific to Initial, 0-RTT, Handshake packets (and part of first byte for Retry)
  final int?
  reservedBits; // Reserved Bits (2) - MUST be 0 (after header protection removed)
  final int? packetNumberLengthBits; // Packet Number Length (2) - length - 1

  // Fields specific to Initial, 0-RTT, Handshake packets
  final int? length; // Length (i) - of remainder (Packet Number + Payload)
  final Uint8List? packetNumberRaw; // Raw bytes of Packet Number (1-4 bytes)
  final int?
  decodedPacketNumber; // Decoded full packet number (after header protection removed)
  final Uint8List? packetPayload; // Packet Payload (sequence of frames)

  // For Version Negotiation packets, this holds the "Supported Versions" list.
  // For other packet types, it is null.
  final Uint8List? supportedVersions;

  LongHeaderPacket({
    required this.fixedBit,
    required this.identifiedType,
    required this.isVersionNegotiation,
    required this.version,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    this.tokenLength,
    this.token,
    this.retryToken,
    this.retryIntegrityTag,
    this.reservedBits,
    this.packetNumberLengthBits,
    this.length,
    this.packetNumberRaw,
    this.decodedPacketNumber,
    this.packetPayload,
    this.supportedVersions,
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
      // (This is a strict check. For now, allow parsing but note it.)
      if ((firstByte & 0x3F) != 0) {
        // print('Warning: Version Negotiation packet has non-zero unused bits: 0x${(firstByte & 0x3F).toRadixString(16)}');
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
      typeSpecificBitsValue =
          (firstByte &
          0x0F); // Only 4 bits for these types (Reserved Bits + PN Length)
    }

    // Common CID parsing (applies to all Long Header Packet types, including VN)
    if (datagramBytes.length < offset + 1) {
      throw FormatException(
        'Datagram too short to read Destination Connection ID Length.',
      );
    }
    final int destCidLength = byteData.getUint8(offset++);
    // For QUIC V1, max CID len is 20. VN allows up to 2040.
    if (version == 0x00000001 && destCidLength > 20 && !isVersionNegotiation) {
      throw FormatException(
        'Destination Connection ID Length ($destCidLength) exceeds 20 bytes for QUIC Version 1 non-VN packet.',
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
    // For QUIC V1, max CID len is 20. VN allows up to 2040.
    if (version == 0x00000001 &&
        sourceCidLength > 20 &&
        !isVersionNegotiation) {
      throw FormatException(
        'Source Connection ID Length ($sourceCidLength) exceeds 20 bytes for QUIC Version 1 non-VN packet.',
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

    // Initialize all optional fields to null
    int? tokenLength;
    Uint8List? token;
    Uint8List? retryToken;
    Uint8List? retryIntegrityTag;
    int? reservedBits;
    int? packetNumberLengthBits;
    int? length;
    Uint8List? packetNumberRaw;
    int? decodedPacketNumber;
    Uint8List? packetPayload;
    Uint8List? supportedVersions; // Specifically for VN packets

    if (isVersionNegotiation) {
      // For Version Negotiation, the remainder of the packet is the list of supported versions.
      supportedVersions = (offset < datagramBytes.lengthInBytes)
          ? Uint8List.fromList(datagramBytes.sublist(offset))
          : null;
      offset = datagramBytes
          .lengthInBytes; // All remaining bytes consumed by VN payload
    } else if (identifiedType == QuicLongHeaderType.initial) {
      // Initial Packet specific fields: Token Length, Token, then Length, PN, Payload
      if (datagramBytes.length < offset + 1) {
        throw FormatException(
          'Datagram too short to read Token Length field (VLQ header).',
        );
      }
      final tokenLengthEntry = QuicVariableLengthInteger.decode(
        datagramBytes,
        offset,
      );
      tokenLength = tokenLengthEntry.key;
      offset += tokenLengthEntry.value;

      if (tokenLength > 0) {
        if (datagramBytes.length < offset + tokenLength) {
          throw FormatException(
            'Datagram too short to read Token ($tokenLength bytes).',
          );
        }
        token = Uint8List.fromList(
          datagramBytes.sublist(offset, offset + tokenLength),
        );
        offset += tokenLength;
      } else {
        token = Uint8List(0); // Empty token if length is 0
      }

      // Now parse common fields for packets with PN & Length
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
          'Packet number length ($pnBytes bytes) exceeds remaining packet data for Initial packet. Remaining: ${datagramBytes.lengthInBytes - offset}',
        );
      }
      packetNumberRaw = Uint8List.fromList(
        datagramBytes.sublist(offset, offset + pnBytes),
      );
      offset += pnBytes;

      decodedPacketNumber = QuicPacketNumber.decode(
        packetNumberRaw,
        packetNumberLengthBits,
        largestReceivedPn,
      );

      final int expectedPayloadEnd =
          offset + (length - pnBytes); // Length field includes PN and Payload
      if (expectedPayloadEnd > datagramBytes.lengthInBytes) {
        throw FormatException(
          'Declared packet length ($length) exceeds actual datagram size for Initial packet. Expected end: $expectedPayloadEnd, Actual length: ${datagramBytes.lengthInBytes}',
        );
      }
      packetPayload = Uint8List.fromList(
        datagramBytes.sublist(offset, expectedPayloadEnd),
      );
      offset = expectedPayloadEnd;
    } else if (identifiedType == QuicLongHeaderType.zeroRtt ||
        identifiedType == QuicLongHeaderType.handshake) {
      // 0-RTT and Handshake Packets: Reserved, PN Length, Length, PN, Payload
      reservedBits = (typeSpecificBitsValue & 0x0C) >> 2;
      packetNumberLengthBits = typeSpecificBitsValue & 0x03;

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
          'Packet number length ($pnBytes bytes) exceeds remaining packet data for ${identifiedType.name} packet. Remaining: ${datagramBytes.lengthInBytes - offset}',
        );
      }
      packetNumberRaw = Uint8List.fromList(
        datagramBytes.sublist(offset, offset + pnBytes),
      );
      offset += pnBytes;

      decodedPacketNumber = QuicPacketNumber.decode(
        packetNumberRaw,
        packetNumberLengthBits,
        largestReceivedPn,
      );

      final int expectedPayloadEnd =
          offset + (length - pnBytes); // Length field includes PN and Payload
      if (expectedPayloadEnd > datagramBytes.lengthInBytes) {
        throw FormatException(
          'Declared packet length ($length) exceeds actual datagram size for ${identifiedType.name} packet. Expected end: $expectedPayloadEnd, Actual length: ${datagramBytes.lengthInBytes}',
        );
      }
      packetPayload = Uint8List.fromList(
        datagramBytes.sublist(offset, expectedPayloadEnd),
      );
      offset = expectedPayloadEnd;
    } else if (identifiedType == QuicLongHeaderType.retry) {
      // Retry Packet specific fields: Unused (from first byte), Retry Token, Retry Integrity Tag
      // It does NOT have Length, PN, Payload fields.
      // The lower 4 bits of the first byte are 'Unused'.
      reservedBits = null; // No reserved bits field for Retry
      packetNumberLengthBits = null; // No PN length field for Retry

      // Retry Token (variable length)
      if (datagramBytes.length < offset + 1) {
        throw FormatException(
          'Datagram too short to read Retry Token Length field (VLQ header).',
        );
      }
      final retryTokenLengthEntry = QuicVariableLengthInteger.decode(
        datagramBytes,
        offset,
      );
      final int retryTokLen = retryTokenLengthEntry.key;
      offset += retryTokenLengthEntry.value;

      if (datagramBytes.length < offset + retryTokLen) {
        throw FormatException(
          'Datagram too short to read Retry Token ($retryTokLen bytes).',
        );
      }
      retryToken = Uint8List.fromList(
        datagramBytes.sublist(offset, offset + retryTokLen),
      );
      offset += retryTokLen;

      // Retry Integrity Tag (fixed 16 bytes)
      const int retryTagLength = 16;
      if (datagramBytes.length < offset + retryTagLength) {
        throw FormatException(
          'Datagram too short to read Retry Integrity Tag ($retryTagLength bytes).',
        );
      }
      retryIntegrityTag = Uint8List.fromList(
        datagramBytes.sublist(offset, offset + retryTagLength),
      );
      offset += retryTagLength;
    }

    return LongHeaderPacket(
      fixedBit: fixedBit,
      identifiedType: identifiedType,
      isVersionNegotiation: isVersionNegotiation,
      version: version,
      destinationConnectionId: destinationConnectionId,
      sourceConnectionId: sourceConnectionId,
      tokenLength: tokenLength,
      token: token,
      retryToken: retryToken,
      retryIntegrityTag: retryIntegrityTag,
      reservedBits: reservedBits,
      packetNumberLengthBits: packetNumberLengthBits,
      length: length,
      packetNumberRaw: packetNumberRaw,
      decodedPacketNumber: decodedPacketNumber,
      packetPayload: packetPayload,
      supportedVersions: supportedVersions,
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
      // We'll set them to 0 explicitly during serialization.
      firstByte &= 0xC0; // Clear the lower 6 bits (0x3F)
    } else if (identifiedType == QuicLongHeaderType.retry) {
      // For Retry, the type is 0x03. The lower 4 bits are 'Unused'.
      firstByte |=
          (identifiedType.value! << 4) & 0x30; // Long Packet Type (0x03)
      // The RFC says "Unused (4)". We'll represent them as 0 during serialization,
      // unless a specific `reservedBits` or `packetNumberLengthBits` were intended
      // to populate these (which they aren't for Retry).
      firstByte &=
          0xF0; // Clear the lower 4 bits (0x0F) - effectively setting 'Unused' to 0.
    } else {
      // For Initial, 0-RTT, Handshake, use the identifiedType's value for the 2 bits.
      firstByte |=
          (identifiedType.value! << 4) & 0x30; // Long Packet Type (2 bits)

      // For these types, Reserved Bits and Packet Number Length bits are present.
      if (reservedBits != null && packetNumberLengthBits != null) {
        firstByte |= (reservedBits! << 2) & 0x0C; // Reserved Bits
        firstByte |= (packetNumberLengthBits! & 0x03); // Packet Number Length
      } else {
        // If these fields are null for a non-VN, non-Retry packet, ensure the 4 bits are 0.
        firstByte &= 0xF0; // Clear lower 4 bits
      }
    }
    bytes.add(firstByte);

    // Version (32)
    final versionBytes = ByteData(4);
    versionBytes.setUint32(0, version, Endian.big);
    bytes.addAll(versionBytes.buffer.asUint8List());

    // Destination Connection ID Length (8)
    bytes.add(destinationConnectionId.length);
    // Destination Connection ID (0..2040)
    bytes.addAll(destinationConnectionId);

    // Source Connection ID Length (8)
    bytes.add(sourceConnectionId.length);
    // Source Connection ID (0..2040)
    bytes.addAll(sourceConnectionId);

    // --- Type-specific fields ---
    if (isVersionNegotiation) {
      if (supportedVersions != null) {
        bytes.addAll(supportedVersions!);
      }
    } else if (identifiedType == QuicLongHeaderType.initial) {
      // Token Length (i)
      bytes.addAll(QuicVariableLengthInteger.encode(token?.length ?? 0));
      // Token (..)
      if (token != null && token!.isNotEmpty) {
        bytes.addAll(token!);
      }

      // Length (i)
      if (length == null)
        throw StateError(
          'Initial packet must have a length field for serialization.',
        );
      bytes.addAll(QuicVariableLengthInteger.encode(length!));

      // Packet Number (1-4 bytes)
      if (packetNumberRaw == null)
        throw StateError(
          'Initial packet must have raw packet number for serialization.',
        );
      bytes.addAll(packetNumberRaw!);

      // Packet Payload
      if (packetPayload == null)
        throw StateError(
          'Initial packet must have packet payload for serialization.',
        );
      bytes.addAll(packetPayload!);
    } else if (identifiedType == QuicLongHeaderType.zeroRtt ||
        identifiedType == QuicLongHeaderType.handshake) {
      // Length (i)
      if (length == null)
        throw StateError(
          '${identifiedType.name} packet must have a length field for serialization.',
        );
      bytes.addAll(QuicVariableLengthInteger.encode(length!));

      // Packet Number (1-4 bytes)
      if (packetNumberRaw == null)
        throw StateError(
          '${identifiedType.name} packet must have raw packet number for serialization.',
        );
      bytes.addAll(packetNumberRaw!);

      // Packet Payload
      if (packetPayload == null)
        throw StateError(
          '${identifiedType.name} packet must have packet payload for serialization.',
        );
      bytes.addAll(packetPayload!);
    } else if (identifiedType == QuicLongHeaderType.retry) {
      // Retry Token (..)
      if (retryToken == null)
        throw StateError(
          'Retry packet must have a retry token for serialization.',
        );
      bytes.addAll(QuicVariableLengthInteger.encode(retryToken!.length));
      bytes.addAll(retryToken!);

      // Retry Integrity Tag (128)
      if (retryIntegrityTag == null || retryIntegrityTag!.length != 16) {
        throw StateError(
          'Retry packet must have a 16-byte integrity tag for serialization.',
        );
      }
      bytes.addAll(retryIntegrityTag!);
    }
    return Uint8List.fromList(bytes);
  }

  @override
  String toString() {
    String pnInfo = '';
    String tokenInfo = '';
    String retryInfo = '';
    String payloadInfo = '';
    String supportedVersionsInfo = '';

    if (isVersionNegotiation) {
      supportedVersionsInfo =
          'Supported Versions Length: ${supportedVersions?.length ?? 0} bytes, Supported Versions: ${supportedVersions?.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}, ';
    } else if (identifiedType == QuicLongHeaderType.initial) {
      tokenInfo =
          'Token Length: $tokenLength, Token: ${token?.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}, ';
      pnInfo =
          'PN Length Bits: $packetNumberLengthBits, Raw PN: ${packetNumberRaw?.map((e) => e.toRadixString(16).padLeft(2, '0')).join(' ')}, Decoded PN: $decodedPacketNumber, ';
      payloadInfo =
          'Length (payload+PN): $length, Packet Payload Size: ${packetPayload?.length ?? 0} bytes, ';
    } else if (identifiedType == QuicLongHeaderType.zeroRtt ||
        identifiedType == QuicLongHeaderType.handshake) {
      pnInfo =
          'PN Length Bits: $packetNumberLengthBits, Raw PN: ${packetNumberRaw?.map((e) => e.toRadixString(16).padLeft(2, '0')).join(' ')}, Decoded PN: $decodedPacketNumber, ';
      payloadInfo =
          'Length (payload+PN): $length, Packet Payload Size: ${packetPayload?.length ?? 0} bytes, ';
    } else if (identifiedType == QuicLongHeaderType.retry) {
      retryInfo =
          'Retry Token Length: ${retryToken?.length ?? 0}, Retry Token: ${retryToken?.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}, Retry Integrity Tag: ${retryIntegrityTag?.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}, ';
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
        '  $tokenInfo'
        '  $retryInfo'
        '  $pnInfo'
        '  $payloadInfo'
        '  $supportedVersionsInfo'
        '}';
  }
}
