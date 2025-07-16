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
  final bool fixedBit; // Fixed Bit (1) = 1 (unless Version Negotiation)
  @override
  final QuicLongHeaderType identifiedType; // The overall type of the long header packet
  @override
  final bool isVersionNegotiation; // Convenience flag for Version Negotiation
  @override
  final int version; // Version (32)

  @override
  final Uint8List destinationConnectionId; // Destination Connection ID (0..160)
  @override
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

void main() {
  print("Quick packet: ${LongHeaderPacket.parse(quicPacketBytes)}");
}

final quicPacketBytes = Uint8List.fromList([
  192,
  0,
  0,
  0,
  1,
  17,
  73,
  123,
  162,
  85,
  69,
  142,
  31,
  64,
  38,
  188,
  154,
  53,
  16,
  158,
  110,
  168,
  14,
  0,
  0,
  68,
  229,
  232,
  94,
  173,
  132,
  54,
  93,
  251,
  48,
  198,
  21,
  21,
  79,
  214,
  92,
  28,
  244,
  190,
  97,
  25,
  68,
  181,
  40,
  219,
  241,
  53,
  49,
  89,
  76,
  12,
  138,
  250,
  225,
  60,
  26,
  34,
  179,
  10,
  168,
  156,
  5,
  252,
  12,
  117,
  171,
  104,
  225,
  253,
  174,
  39,
  241,
  80,
  237,
  20,
  234,
  96,
  169,
  184,
  145,
  109,
  199,
  3,
  237,
  40,
  176,
  167,
  41,
  233,
  23,
  193,
  167,
  252,
  104,
  220,
  74,
  101,
  133,
  241,
  223,
  111,
  99,
  35,
  19,
  20,
  233,
  130,
  153,
  17,
  25,
  93,
  75,
  29,
  249,
  141,
  189,
  43,
  136,
  9,
  129,
  214,
  75,
  94,
  175,
  187,
  246,
  167,
  74,
  19,
  87,
  116,
  65,
  45,
  48,
  134,
  60,
  2,
  68,
  181,
  115,
  201,
  103,
  217,
  167,
  220,
  223,
  104,
  183,
  214,
  189,
  3,
  198,
  46,
  11,
  184,
  199,
  255,
  93,
  43,
  139,
  205,
  191,
  106,
  55,
  122,
  141,
  208,
  25,
  27,
  147,
  100,
  166,
  55,
  248,
  46,
  51,
  61,
  130,
  134,
  202,
  2,
  77,
  66,
  67,
  242,
  1,
  238,
  142,
  46,
  72,
  228,
  16,
  253,
  18,
  79,
  65,
  149,
  221,
  133,
  194,
  159,
  241,
  113,
  179,
  5,
  35,
  175,
  67,
  94,
  53,
  223,
  66,
  174,
  6,
  33,
  41,
  199,
  213,
  13,
  225,
  200,
  255,
  214,
  152,
  51,
  39,
  35,
  117,
  80,
  218,
  102,
  81,
  218,
  245,
  106,
  74,
  189,
  16,
  235,
  148,
  40,
  129,
  136,
  33,
  101,
  180,
  32,
  23,
  84,
  4,
  248,
  144,
  205,
  223,
  111,
  127,
  54,
  124,
  209,
  148,
  244,
  188,
  149,
  150,
  155,
  100,
  212,
  121,
  197,
  43,
  21,
  164,
  239,
  119,
  250,
  247,
  83,
  38,
  144,
  20,
  46,
  85,
  89,
  74,
  171,
  82,
  94,
  46,
  44,
  15,
  28,
  9,
  223,
  224,
  51,
  92,
  112,
  24,
  180,
  76,
  12,
  133,
  99,
  62,
  9,
  93,
  14,
  118,
  117,
  158,
  30,
  116,
  64,
  76,
  145,
  172,
  37,
  223,
  120,
  49,
  54,
  154,
  212,
  92,
  29,
  248,
  135,
  36,
  129,
  194,
  148,
  128,
  242,
  75,
  248,
  117,
  13,
  30,
  74,
  218,
  248,
  238,
  107,
  191,
  198,
  44,
  178,
  162,
  196,
  125,
  32,
  174,
  30,
  73,
  223,
  224,
  162,
  241,
  203,
  215,
  182,
  44,
  234,
  196,
  158,
  2,
  203,
  103,
  198,
  148,
  0,
  123,
  78,
  46,
  138,
  162,
  97,
  189,
  28,
  8,
  182,
  144,
  114,
  218,
  218,
  92,
  124,
  242,
  94,
  42,
  218,
  126,
  16,
  59,
  181,
  7,
  41,
  35,
  193,
  198,
  49,
  214,
  10,
  40,
  137,
  101,
  173,
  2,
  238,
  194,
  124,
  17,
  66,
  67,
  140,
  251,
  106,
  41,
  70,
  43,
  62,
  105,
  33,
  46,
  54,
  22,
  144,
  12,
  59,
  204,
  18,
  157,
  51,
  38,
  181,
  151,
  234,
  198,
  185,
  227,
  17,
  212,
  171,
  90,
  137,
  233,
  152,
  198,
  205,
  15,
  99,
  231,
  128,
  102,
  26,
  188,
  1,
  237,
  138,
  203,
  5,
  49,
  212,
  150,
  51,
  252,
  63,
  205,
  119,
  57,
  148,
  32,
  148,
  214,
  3,
  210,
  88,
  9,
  101,
  248,
  22,
  235,
  24,
  242,
  100,
  0,
  182,
  53,
  133,
  35,
  103,
  190,
  149,
  65,
  207,
  0,
  6,
  233,
  252,
  48,
  84,
  211,
  120,
  66,
  112,
  190,
  223,
  25,
  233,
  208,
  186,
  52,
  152,
  69,
  95,
  227,
  191,
  99,
  173,
  48,
  218,
  151,
  197,
  29,
  220,
  114,
  211,
  89,
  236,
  130,
  28,
  202,
  238,
  82,
  162,
  76,
  72,
  144,
  0,
  61,
  225,
  202,
  19,
  8,
  95,
  251,
  98,
  2,
  69,
  111,
  233,
  209,
  94,
  67,
  178,
  239,
  101,
  4,
  179,
  136,
  129,
  143,
  170,
  61,
  129,
  67,
  57,
  160,
  96,
  98,
  47,
  65,
  15,
  102,
  106,
  250,
  19,
  2,
  207,
  223,
  236,
  237,
  221,
  114,
  72,
  49,
  33,
  39,
  51,
  165,
  184,
  224,
  130,
  61,
  34,
  117,
  114,
  103,
  39,
  28,
  173,
  19,
  64,
  179,
  248,
  94,
  210,
  69,
  235,
  45,
  131,
  170,
  10,
  218,
  95,
  122,
  170,
  58,
  151,
  46,
  152,
  42,
  1,
  193,
  207,
  168,
  181,
  48,
  31,
  201,
  64,
  239,
  177,
  191,
  61,
  174,
  118,
  6,
  242,
  130,
  174,
  101,
  31,
  219,
  93,
  190,
  237,
  167,
  38,
  188,
  121,
  119,
  39,
  5,
  113,
  74,
  141,
  210,
  197,
  64,
  208,
  103,
  225,
  227,
  117,
  240,
  18,
  164,
  118,
  50,
  35,
  40,
  104,
  94,
  22,
  26,
  142,
  55,
  133,
  253,
  207,
  243,
  116,
  134,
  54,
  55,
  102,
  101,
  89,
  201,
  194,
  177,
  105,
  113,
  206,
  207,
  41,
  92,
  176,
  217,
  140,
  122,
  161,
  134,
  82,
  94,
  151,
  157,
  136,
  17,
  27,
  61,
  121,
  130,
  76,
  90,
  205,
  130,
  161,
  207,
  27,
  14,
  49,
  164,
  156,
  85,
  164,
  115,
  68,
  53,
  178,
  177,
  99,
  157,
  26,
  111,
  184,
  56,
  182,
  44,
  20,
  14,
  229,
  48,
  61,
  235,
  127,
  149,
  129,
  96,
  185,
  194,
  152,
  141,
  161,
  199,
  205,
  123,
  246,
  255,
  63,
  216,
  19,
  157,
  239,
  3,
  130,
  135,
  139,
  32,
  173,
  209,
  174,
  209,
  70,
  82,
  189,
  243,
  156,
  43,
  33,
  39,
  164,
  213,
  104,
  144,
  225,
  140,
  67,
  229,
  48,
  23,
  240,
  224,
  144,
  168,
  70,
  77,
  163,
  213,
  41,
  0,
  197,
  81,
  86,
  72,
  158,
  13,
  232,
  2,
  144,
  197,
  154,
  213,
  110,
  67,
  74,
  187,
  136,
  93,
  0,
  82,
  44,
  207,
  58,
  16,
  93,
  163,
  91,
  253,
  57,
  135,
  85,
  177,
  224,
  57,
  43,
  91,
  132,
  147,
  46,
  169,
  145,
  30,
  159,
  25,
  65,
  105,
  162,
  216,
  4,
  253,
  3,
  20,
  36,
  198,
  52,
  125,
  139,
  1,
  140,
  187,
  255,
  26,
  197,
  195,
  141,
  108,
  135,
  48,
  60,
  91,
  28,
  131,
  44,
  160,
  216,
  52,
  106,
  87,
  174,
  169,
  181,
  36,
  128,
  227,
  84,
  243,
  236,
  138,
  68,
  169,
  198,
  185,
  75,
  121,
  75,
  168,
  38,
  100,
  130,
  226,
  115,
  9,
  178,
  31,
  89,
  178,
  188,
  86,
  77,
  8,
  100,
  247,
  143,
  174,
  110,
  10,
  171,
  225,
  39,
  208,
  91,
  96,
  150,
  100,
  247,
  137,
  167,
  84,
  82,
  51,
  1,
  158,
  62,
  3,
  110,
  117,
  236,
  8,
  138,
  67,
  173,
  62,
  25,
  209,
  150,
  215,
  203,
  26,
  172,
  45,
  231,
  79,
  101,
  147,
  193,
  48,
  214,
  210,
  231,
  222,
  132,
  239,
  173,
  173,
  116,
  178,
  64,
  151,
  63,
  98,
  5,
  24,
  56,
  147,
  200,
  245,
  205,
  55,
  63,
  116,
  44,
  177,
  127,
  37,
  121,
  67,
  119,
  207,
  23,
  174,
  60,
  219,
  134,
  179,
  234,
  13,
  153,
  213,
  252,
  65,
  212,
  109,
  224,
  164,
  76,
  208,
  41,
  15,
  217,
  144,
  1,
  173,
  10,
  94,
  1,
  153,
  197,
  215,
  113,
  58,
  24,
  53,
  0,
  199,
  0,
  124,
  225,
  227,
  176,
  73,
  82,
  149,
  144,
  9,
  37,
  245,
  176,
  13,
  200,
  38,
  64,
  0,
  102,
  78,
  229,
  155,
  219,
  236,
  17,
  117,
  227,
  23,
  225,
  53,
  20,
  12,
  227,
  81,
  242,
  108,
  80,
  11,
  160,
  232,
  160,
  20,
  83,
  204,
  169,
  34,
  214,
  85,
  25,
  7,
  61,
  188,
  231,
  199,
  75,
  60,
  80,
  245,
  252,
  208,
  164,
  61,
  40,
  234,
  228,
  30,
  179,
  146,
  166,
  166,
  24,
  97,
  22,
  167,
  28,
  19,
  237,
  130,
  47,
  140,
  192,
  242,
  61,
  207,
  176,
  18,
  70,
  189,
  13,
  155,
  80,
  226,
  140,
  14,
  164,
  100,
  202,
  20,
  192,
  67,
  46,
  11,
  55,
  90,
  136,
  150,
  210,
  98,
  248,
  243,
  170,
  162,
  210,
  251,
  25,
  147,
  43,
  31,
  218,
  143,
  230,
  187,
  96,
  96,
  56,
  140,
  211,
  14,
  84,
  139,
  210,
  138,
  110,
  80,
  150,
  200,
  15,
  74,
  208,
  42,
  154,
  29,
  181,
  42,
  87,
  121,
  75,
  104,
  128,
  81,
  131,
  152,
  53,
  122,
  21,
  168,
  69,
  10,
  138,
  238,
  144,
  215,
  216,
  112,
  67,
  246,
  207,
  8,
  67,
  71,
  213,
  226,
  36,
  240,
  90,
  125,
  9,
  78,
  247,
  85,
  199,
  106,
  172,
  52,
  88,
  222,
  2,
  140,
  178,
  229,
  46,
  6,
  246,
  148,
  145,
  200,
  143,
  166,
  117,
  91,
  233,
  184,
  242,
  124,
  216,
  56,
  59,
  254,
  31,
  64,
  141,
  3,
  185,
  176,
  209,
  231,
  193,
  80,
  5,
  177,
  227,
  47,
  145,
  146,
  184,
  198,
  57,
  169,
  183,
  21,
  184,
  116,
  129,
  197,
  187,
  249,
  101,
  175,
  116,
  136,
  132,
  166,
  196,
  179,
  13,
  156,
  249,
  41,
  149,
]);
