// quic_transport_parameters.dart
import 'dart:typed_data';
import 'quic_variable_length_integer.dart'; // Assuming this file exists and works

/// Defines the identifiers for QUIC Transport Parameters.
/// See RFC 9000, Section 18.2.
enum QuicTransportParameterId {
  originalDestinationConnectionId(0x00),
  maxIdleTimeout(0x01),
  statelessResetToken(0x02),
  maxUdpPayloadSize(0x03),
  initialMaxData(0x04),
  initialMaxStreamDataBidiLocal(0x05),
  initialMaxStreamDataBidiRemote(0x06),
  initialMaxStreamDataUni(0x07),
  initialMaxStreamsBidi(0x08),
  initialMaxStreamsUni(0x09),
  ackDelayExponent(0x0a),
  maxAckDelay(0x0b),
  disableActiveMigration(0x0c),
  preferredAddress(0x0d),
  activeConnectionIdLimit(0x0e),
  initialSourceConnectionId(0x0f),
  retrySourceConnectionId(0x10);

  final int value;
  const QuicTransportParameterId(this.value);

  static QuicTransportParameterId? fromValue(int value) {
    // Check for reserved parameters: 31 * N + 27
    if ((value - 27) % 31 == 0 && value >= 27) {
      // It's a reserved ID. We can return null or a special 'reserved' type
      // For now, let's return null and let the parser handle it as unknown.
      // Or we could have a static `isReserved(int id)` method.
    }

    for (var id in QuicTransportParameterId.values) {
      if (id.value == value) {
        return id;
      }
    }
    return null;
  }

  /// Checks if a given integer ID is a reserved transport parameter.
  /// Reserved IDs are of the form 31 * N + 27.
  static bool isReserved(int id) {
    return (id - 27) % 31 == 0 && id >= 27;
  }
}

/// Represents the complex structure of the Preferred Address transport parameter.
/// See RFC 9000, Section 18.2, Figure 22.
class PreferredAddress {
  final Uint8List ipv4Address; // 4 bytes
  final int ipv4Port; // 2 bytes
  final Uint8List ipv6Address; // 16 bytes
  final int ipv6Port; // 2 bytes
  final Uint8List
  connectionId; // Variable length (indicated by Connection ID Length)
  final Uint8List statelessResetToken; // 16 bytes

  PreferredAddress({
    required this.ipv4Address,
    required this.ipv4Port,
    required this.ipv6Address,
    required this.ipv6Port,
    required this.connectionId,
    required this.statelessResetToken,
  }) : assert(ipv4Address.length == 4, 'IPv4 address must be 4 bytes.'),
       assert(ipv6Address.length == 16, 'IPv6 address must be 16 bytes.'),
       assert(
         statelessResetToken.length == 16,
         'Stateless Reset Token must be 16 bytes.',
       );

  /// Parses a PreferredAddress from its raw byte value.
  factory PreferredAddress.parse(Uint8List valueBytes) {
    // Minimum possible length (4 IPv4 + 2 IPv4 Port + 16 IPv6 + 2 IPv6 Port + 1 ConnID Len + 1 ConnID + 16 SRT)
    // Here, 1 ConnID byte implies minimum CID length of 1.
    // If CID could be 0, min length would be 4+2+16+2+1+0+16 = 41 bytes.
    // But RFC 9000 says "A server MUST NOT include a zero-length connection ID in this transport parameter."
    // So minimum CID length is 1, making total min length 42 bytes.
    if (valueBytes.length < 42) {
      throw FormatException(
        'Preferred Address value bytes too short. Minimum 42 bytes.',
      );
    }

    final ByteData byteData = ByteData.view(valueBytes.buffer);
    int offset = 0;

    final Uint8List ipv4Address = Uint8List.fromList(
      valueBytes.sublist(offset, offset + 4),
    );
    offset += 4;

    final int ipv4Port = byteData.getUint16(offset, Endian.big);
    offset += 2;

    final Uint8List ipv6Address = Uint8List.fromList(
      valueBytes.sublist(offset, offset + 16),
    );
    offset += 16;

    final int ipv6Port = byteData.getUint16(offset, Endian.big);
    offset += 2;

    final int connectionIdLength = byteData.getUint8(offset++);

    if (connectionIdLength == 0) {
      throw FormatException(
        'Preferred Address Connection ID Length MUST NOT be 0.',
      );
    }

    if (valueBytes.length < offset + connectionIdLength + 16) {
      throw FormatException(
        'Preferred Address value bytes too short for Connection ID or Stateless Reset Token.',
      );
    }

    final Uint8List connectionId = Uint8List.fromList(
      valueBytes.sublist(offset, offset + connectionIdLength),
    );
    offset += connectionIdLength;

    final Uint8List statelessResetToken = Uint8List.fromList(
      valueBytes.sublist(offset, offset + 16),
    );
    offset += 16;

    if (offset != valueBytes.length) {
      throw FormatException(
        'Preferred Address value bytes had unread trailing data.',
      );
    }

    return PreferredAddress(
      ipv4Address: ipv4Address,
      ipv4Port: ipv4Port,
      ipv6Address: ipv6Address,
      ipv6Port: ipv6Port,
      connectionId: connectionId,
      statelessResetToken: statelessResetToken,
    );
  }

  /// Serializes the PreferredAddress object into its raw byte value.
  Uint8List toBytes() {
    final List<int> bytes = [];
    final ByteData portData = ByteData(2);

    bytes.addAll(ipv4Address);
    portData.setUint16(0, ipv4Port, Endian.big);
    bytes.addAll(portData.buffer.asUint8List());

    bytes.addAll(ipv6Address);
    portData.setUint16(0, ipv6Port, Endian.big);
    bytes.addAll(portData.buffer.asUint8List());

    if (connectionId.isEmpty) {
      throw StateError(
        'Preferred Address Connection ID MUST NOT be zero-length for serialization.',
      );
    }
    bytes.add(connectionId.length);
    bytes.addAll(connectionId);

    bytes.addAll(statelessResetToken);

    return Uint8List.fromList(bytes);
  }

  @override
  String toString() {
    return 'PreferredAddress(\n'
        '  IPv4: ${ipv4Address.join('.')}:${ipv4Port},\n'
        '  IPv6: [${ipv6Address.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}]:${ipv6Port},\n'
        '  Conn ID Length: ${connectionId.length}, Conn ID: ${connectionId.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')},\n'
        '  Stateless Reset Token: ${statelessResetToken.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}\n'
        ')';
  }
}

/// Represents the sequence of QUIC Transport Parameters.
/// See RFC 9000, Section 18, Figure 20.
class QuicTransportParameters {
  // Stores the raw byte values for each parameter ID.
  final Map<QuicTransportParameterId, Uint8List> _parameters = {};
  final Map<int, Uint8List> _unknownParameters =
      {}; // For handling unknown/reserved IDs

  // getter for _unknownParameters to allow testing and inspection
  Map<int, Uint8List> get unknownParameters => _unknownParameters;

  QuicTransportParameters();

  /// Creates a [QuicTransportParameters] object by parsing a byte sequence.
  factory QuicTransportParameters.parse(Uint8List rawBytes) {
    final QuicTransportParameters params = QuicTransportParameters();
    int offset = 0;

    while (offset < rawBytes.length) {
      // Transport Parameter ID (i)
      final idEntry = QuicVariableLengthInteger.decode(rawBytes, offset);
      final int paramIdRaw = idEntry.key;
      offset += idEntry.value;

      // Transport Parameter Length (i)
      final lengthEntry = QuicVariableLengthInteger.decode(rawBytes, offset);
      final int paramLength = lengthEntry.key;
      offset += lengthEntry.value;

      // Transport Parameter Value (..)
      if (rawBytes.length < offset + paramLength) {
        throw FormatException(
          'Transport parameter value too short for ID 0x${paramIdRaw.toRadixString(16)}. Expected $paramLength bytes, got ${rawBytes.length - offset}.',
        );
      }
      final Uint8List paramValue = Uint8List.fromList(
        rawBytes.sublist(offset, offset + paramLength),
      );
      offset += paramLength;

      final QuicTransportParameterId? identifiedId =
          QuicTransportParameterId.fromValue(paramIdRaw);

      if (identifiedId != null) {
        params._parameters[identifiedId] = paramValue;
      } else if (QuicTransportParameterId.isReserved(paramIdRaw)) {
        // Handle reserved parameters: RFC 9000 Section 18.1 says they must be ignored.
        // We can store them to verify parsing, but a real impl would discard.
        params._unknownParameters[paramIdRaw] = paramValue;
        // print('Ignoring reserved transport parameter ID: 0x${paramIdRaw.toRadixString(16)}');
      } else {
        // Unknown parameter, also ignore according to QUIC protocol.
        params._unknownParameters[paramIdRaw] = paramValue;
        // print('Ignoring unknown transport parameter ID: 0x${paramIdRaw.toRadixString(16)}');
      }
    }
    return params;
  }

  /// Serializes the transport parameters into a byte sequence.
  Uint8List toBytes() {
    final List<int> bytes = [];

    // Sort parameters by ID to ensure canonical encoding (optional but good practice)
    final sortedIds = _parameters.keys.toList()
      ..sort((a, b) => a.value.compareTo(b.value));

    for (final id in sortedIds) {
      final value = _parameters[id]!;
      bytes.addAll(QuicVariableLengthInteger.encode(id.value));
      bytes.addAll(QuicVariableLengthInteger.encode(value.length));
      bytes.addAll(value);
    }
    // Also include unknown parameters if they were parsed and need to be re-serialized
    // (e.g., if we're forwarding or debugging). For strict spec compliance, might omit.
    // For now, let's not re-serialize unknown/reserved, as they're ignored by receiver anyway.
    // However, if an endpoint receives an unknown parameter, it SHOULD preserve it and
    // re-transmit it if it's acting as a forwarder. For a direct endpoint, it's just ignored.
    // For this serialization, we'll only serialize explicitly known and set parameters.

    return Uint8List.fromList(bytes);
  }

  /// Sets an integer-valued transport parameter.
  /// Integer values are encoded as variable-length integers.
  void setInteger(QuicTransportParameterId id, int value) {
    _parameters[id] = Uint8List.fromList(
      QuicVariableLengthInteger.encode(value),
    );
  }

  /// Gets an integer-valued transport parameter.
  /// Returns null if the parameter is not present or cannot be parsed as an integer.
  int? getInteger(QuicTransportParameterId id) {
    final valueBytes = _parameters[id];
    if (valueBytes == null || valueBytes.isEmpty) {
      return null; // Or 0, depending on default behavior specified per parameter
    }
    try {
      return QuicVariableLengthInteger.decode(valueBytes).key;
    } on FormatException {
      // Value not a valid VLQ
      return null;
    }
  }

  /// Sets a byte-sequence valued transport parameter.
  void setBytes(QuicTransportParameterId id, Uint8List value) {
    _parameters[id] = value;
  }

  /// Gets a byte-sequence valued transport parameter.
  Uint8List? getBytes(QuicTransportParameterId id) {
    return _parameters[id];
  }

  /// Sets the `preferred_address` transport parameter.
  void setPreferredAddress(PreferredAddress address) {
    _parameters[QuicTransportParameterId.preferredAddress] = address.toBytes();
  }

  /// Gets the `preferred_address` transport parameter.
  PreferredAddress? getPreferredAddress() {
    final valueBytes = _parameters[QuicTransportParameterId.preferredAddress];
    if (valueBytes == null) return null;
    try {
      return PreferredAddress.parse(valueBytes);
    } on FormatException {
      // Malformed preferred address
      return null;
    }
  }

  /// Sets the `disable_active_migration` transport parameter (zero-length).
  void setDisableActiveMigration() {
    _parameters[QuicTransportParameterId.disableActiveMigration] = Uint8List(0);
  }

  /// Checks if `disable_active_migration` parameter is present.
  bool get isDisableActiveMigration {
    return _parameters.containsKey(
      QuicTransportParameterId.disableActiveMigration,
    );
  }

  /// Checks if a parameter is present.
  bool contains(QuicTransportParameterId id) {
    return _parameters.containsKey(id);
  }

  /// Clears all parameters.
  void clear() {
    _parameters.clear();
    _unknownParameters.clear();
  }

  @override
  String toString() {
    final StringBuffer sb = StringBuffer('QuicTransportParameters {\n');
    _parameters.forEach((id, value) {
      String valueStr;
      // Provide more readable output for common types
      switch (id) {
        case QuicTransportParameterId.maxIdleTimeout:
        case QuicTransportParameterId.maxUdpPayloadSize:
        case QuicTransportParameterId.initialMaxData:
        case QuicTransportParameterId.initialMaxStreamDataBidiLocal:
        case QuicTransportParameterId.initialMaxStreamDataBidiRemote:
        case QuicTransportParameterId.initialMaxStreamDataUni:
        case QuicTransportParameterId.initialMaxStreamsBidi:
        case QuicTransportParameterId.initialMaxStreamsUni:
        case QuicTransportParameterId.ackDelayExponent:
        case QuicTransportParameterId.maxAckDelay:
        case QuicTransportParameterId.activeConnectionIdLimit:
          valueStr = (getInteger(id)?.toString() ?? 'N/A (parse error)');
          break;
        case QuicTransportParameterId.statelessResetToken:
        case QuicTransportParameterId.originalDestinationConnectionId:
        case QuicTransportParameterId.initialSourceConnectionId:
        case QuicTransportParameterId.retrySourceConnectionId:
          valueStr =
              '0x${value.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}';
          break;
        case QuicTransportParameterId.disableActiveMigration:
          valueStr = 'true';
          break;
        case QuicTransportParameterId.preferredAddress:
          valueStr = getPreferredAddress()?.toString() ?? 'N/A (parse error)';
          break;
        default:
          valueStr =
              '0x${value.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')} (raw)';
      }
      sb.write(
        '  ${id.name} (0x${id.value.toRadixString(16).padLeft(2, '0')}): length=${value.length}, value=${valueStr}\n',
      );
    });
    _unknownParameters.forEach((id, value) {
      sb.write(
        '  UNKNOWN/RESERVED (0x${id.toRadixString(16).padLeft(2, '0')}): length=${value.length}, value=0x${value.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')} (ignored)\n',
      );
    });
    sb.write('}');
    return sb.toString();
  }
}
