// Assumed imports based on the Python code.
// You will need to use a Dart crypto library like 'pointycastle' or 'cryptography' for the AESGCM functionality.
import 'dart:collection';
import 'dart:typed_data';
import '../buffer.dart';
import 'range_set.dart';
import 'crypto.dart'; // To get AESGCM and other crypto functions

import '../tls.dart'; // Placeholder for tls utilities.
import 'package:quic_dart/quic/ipaddress.dart'; // Placeholder for IPAddress functionality.

const PACKET_LONG_HEADER = 0x80;
const PACKET_FIXED_BIT = 0x40;
const PACKET_SPIN_BIT = 0x20;

const CONNECTION_ID_MAX_SIZE = 20;
const PACKET_NUMBER_MAX_SIZE = 4;
final RETRY_AEAD_KEY_VERSION_1 = Uint8List.fromList([
  0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76,
  0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
]);
final RETRY_AEAD_KEY_VERSION_2 = Uint8List.fromList([
  0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb,
  0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
]);
final RETRY_AEAD_NONCE_VERSION_1 = Uint8List.fromList([
  0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98,
  0x25, 0xbb
]);
final RETRY_AEAD_NONCE_VERSION_2 = Uint8List.fromList([
  0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef,
  0xb0, 0x4a
]);
const RETRY_INTEGRITY_TAG_SIZE = 16;
const STATELESS_RESET_TOKEN_SIZE = 16;

enum QuicErrorCode {
  NO_ERROR,
  INTERNAL_ERROR,
  CONNECTION_REFUSED,
  FLOW_CONTROL_ERROR,
  STREAM_LIMIT_ERROR,
  STREAM_STATE_ERROR,
  FINAL_SIZE_ERROR,
  FRAME_ENCODING_ERROR,
  TRANSPORT_PARAMETER_ERROR,
  CONNECTION_ID_LIMIT_ERROR,
  PROTOCOL_VIOLATION,
  INVALID_TOKEN,
  APPLICATION_ERROR,
  CRYPTO_BUFFER_EXCEEDED,
  KEY_UPDATE_ERROR,
  AEAD_LIMIT_REACHED,
  VERSION_NEGOTIATION_ERROR,
  CRYPTO_ERROR,
}

enum QuicPacketType {
  INITIAL,
  ZERO_RTT,
  HANDSHAKE,
  RETRY,
  VERSION_NEGOTIATION,
  ONE_RTT,
}

// For backwards compatibility only, use `QuicPacketType` in new code.
const PACKET_TYPE_INITIAL = QuicPacketType.INITIAL;

// QUIC version 1
// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
const PACKET_LONG_TYPE_ENCODE_VERSION_1 = {
  QuicPacketType.INITIAL: 0,
  QuicPacketType.ZERO_RTT: 1,
  QuicPacketType.HANDSHAKE: 2,
  QuicPacketType.RETRY: 3,
};
final PACKET_LONG_TYPE_DECODE_VERSION_1 = PACKET_LONG_TYPE_ENCODE_VERSION_1.map((k, v) => MapEntry(v, k));

// QUIC version 2
// https://datatracker.ietf.org/doc/html/rfc9369#section-3.2
const PACKET_LONG_TYPE_ENCODE_VERSION_2 = {
  QuicPacketType.INITIAL: 1,
  QuicPacketType.ZERO_RTT: 2,
  QuicPacketType.HANDSHAKE: 3,
  QuicPacketType.RETRY: 0,
};
final PACKET_LONG_TYPE_DECODE_VERSION_2 = PACKET_LONG_TYPE_ENCODE_VERSION_2.map((k, v) => MapEntry(v, k));

enum QuicProtocolVersion {
  NEGOTIATION(0),
  VERSION_1(0x00000001),
  VERSION_2(0x6B3343CF);

  final int value;
  const QuicProtocolVersion(this.value);
}

class QuicHeader {
  final int? version;
  final QuicPacketType packetType;
  final int packetLength;
  final Uint8List destinationCid;
  final Uint8List sourceCid;
  final Uint8List token;
  final Uint8List integrityTag;
  final List<int> supportedVersions;

  QuicHeader({
    this.version,
    required this.packetType,
    required this.packetLength,
    required this.destinationCid,
    required this.sourceCid,
    required this.token,
    required this.integrityTag,
    required this.supportedVersions,
  });
}

int decodePacketNumber(int truncated, int numBits, int expected) {
  final window = 1 << numBits;
  final halfWindow = window ~/ 2;
  var candidate = (expected & ~(window - 1)) | truncated;
  if (candidate <= expected - halfWindow && candidate < (1 << 62) - window) {
    return candidate + window;
  } else if (candidate > expected + halfWindow && candidate >= window) {
    return candidate - window;
  } else {
    return candidate;
  }
}

Uint8List getRetryIntegrityTag(Uint8List packetWithoutTag, Uint8List originalDestinationCid, int version) {
  final buf = Buffer(capacity: 1 + originalDestinationCid.length + packetWithoutTag.length);
  buf.pushUint8(originalDestinationCid.length);
  buf.pushBytes(originalDestinationCid);
  buf.pushBytes(packetWithoutTag);
  // assert(buf.eof());

  late Uint8List aeadKey;
  late Uint8List aeadNonce;
  if (version == QuicProtocolVersion.VERSION_2.value) {
    aeadKey = RETRY_AEAD_KEY_VERSION_2;
    aeadNonce = RETRY_AEAD_NONCE_VERSION_2;
  } else {
    aeadKey = RETRY_AEAD_KEY_VERSION_1;
    aeadNonce = RETRY_AEAD_NONCE_VERSION_1;
  }

  // Placeholder for AES-128-GCM, needs an external library.
  // This is a conceptual representation.
  // final aead = AESGCM(aeadKey);
  // final integrityTag = aead.encrypt(aeadNonce, Uint8List(0), buf.data);
  // assert(integrityTag.length == RETRY_INTEGRITY_TAG_SIZE);
  // return integrityTag;
  return Uint8List(RETRY_INTEGRITY_TAG_SIZE);
}

bool getSpinBit(int firstByte) {
  return (firstByte & PACKET_SPIN_BIT) != 0;
}

bool isLongHeader(int firstByte) {
  return (firstByte & PACKET_LONG_HEADER) != 0;
}

String prettyProtocolVersion(int version) {
  String versionName;
  try {
    versionName = QuicProtocolVersion.values.firstWhere((e) => e.value == version).name;
  } on StateError {
    versionName = "UNKNOWN";
  }
  return "0x${version.toRadixString(16).padLeft(8, '0')} ($versionName)";
}

QuicHeader pullQuicHeader(Buffer buf, {int? hostCidLength}) {
  final packetStart = buf.tell();

  int? version;
  Uint8List integrityTag = Uint8List(0);
  List<int> supportedVersions = [];
  Uint8List token = Uint8List(0);

  final firstByte = buf.pullUint8();
  if (isLongHeader(firstByte)) {
    // Long Header Packets.
    version = buf.pullUint32();

    final destinationCidLength = buf.pullUint8();
    if (destinationCidLength > CONNECTION_ID_MAX_SIZE) {
      throw FormatException("Destination CID is too long ($destinationCidLength bytes)");
    }
    final destinationCid = buf.pullBytes(destinationCidLength);

    final sourceCidLength = buf.pullUint8();
    if (sourceCidLength > CONNECTION_ID_MAX_SIZE) {
      throw FormatException("Source CID is too long ($sourceCidLength bytes)");
    }
    final sourceCid = buf.pullBytes(sourceCidLength);

    late QuicPacketType packetType;
    int packetEnd;
    if (version == QuicProtocolVersion.NEGOTIATION.value) {
      // Version Negotiation Packet.
      packetType = QuicPacketType.VERSION_NEGOTIATION;
      while (!buf.eof()) {
        supportedVersions.add(buf.pullUint32());
      }
      packetEnd = buf.tell();
    } else {
      if ((firstByte & PACKET_FIXED_BIT) == 0) {
        throw FormatException("Packet fixed bit is zero");
      }

      if (version == QuicProtocolVersion.VERSION_2.value) {
        packetType = PACKET_LONG_TYPE_DECODE_VERSION_2[(firstByte & 0x30) >> 4]!;
      } else {
        packetType = PACKET_LONG_TYPE_DECODE_VERSION_1[(firstByte & 0x30) >> 4]!;
      }

      int restLength;
      if (packetType == QuicPacketType.INITIAL) {
        final tokenLength = buf.pullUintVar();
        token = buf.pullBytes(tokenLength);
        restLength = buf.pullUintVar();
      } else if (packetType == QuicPacketType.ZERO_RTT) {
        restLength = buf.pullUintVar();
      } else if (packetType == QuicPacketType.HANDSHAKE) {
        restLength = buf.pullUintVar();
      } else {
        final tokenLength = buf.capacity - buf.tell() - RETRY_INTEGRITY_TAG_SIZE;
        token = buf.pullBytes(tokenLength);
        integrityTag = buf.pullBytes(RETRY_INTEGRITY_TAG_SIZE);
        restLength = 0;
      }

      // Check remainder length.
      packetEnd = buf.tell() + restLength;
      if (packetEnd > buf.capacity) {
        throw FormatException("Packet payload is truncated");
      }
    }
    return QuicHeader(
      version: version,
      packetType: packetType,
      packetLength: packetEnd - packetStart,
      destinationCid: destinationCid,
      sourceCid: sourceCid,
      token: token,
      integrityTag: integrityTag,
      supportedVersions: supportedVersions,
    );
  } else {
    // Short Header Packets.
    if ((firstByte & PACKET_FIXED_BIT) == 0) {
      throw FormatException("Packet fixed bit is zero");
    }

    final packetType = QuicPacketType.ONE_RTT;
    final destinationCid = buf.pullBytes(hostCidLength!);
    final sourceCid = Uint8List(0);
    final packetEnd = buf.capacity;

    return QuicHeader(
      version: version,
      packetType: packetType,
      packetLength: packetEnd - packetStart,
      destinationCid: destinationCid,
      sourceCid: sourceCid,
      token: token,
      integrityTag: integrityTag,
      supportedVersions: supportedVersions,
    );
  }
}

int encodeLongHeaderFirstByte(int version, QuicPacketType packetType, int bits) {
  final longTypeEncode = (version == QuicProtocolVersion.VERSION_2.value)
      ? PACKET_LONG_TYPE_ENCODE_VERSION_2
      : PACKET_LONG_TYPE_ENCODE_VERSION_1;
  return (PACKET_LONG_HEADER | PACKET_FIXED_BIT | (longTypeEncode[packetType]! << 4) | bits);
}

Uint8List encodeQuicRetry(int version, Uint8List sourceCid, Uint8List destinationCid, Uint8List originalDestinationCid, Uint8List retryToken, {int unused = 0}) {
  final buf = Buffer(capacity: 7 + destinationCid.length + sourceCid.length + retryToken.length + RETRY_INTEGRITY_TAG_SIZE);
  buf.pushUint8(encodeLongHeaderFirstByte(version, QuicPacketType.RETRY, unused));
  buf.pushUint32(version);
  buf.pushUint8(destinationCid.length);
  buf.pushBytes(destinationCid);
  buf.pushUint8(sourceCid.length);
  buf.pushBytes(sourceCid);
  buf.pushBytes(retryToken);
  buf.pushBytes(getRetryIntegrityTag(buf.data, originalDestinationCid, version));
  // assert(buf.eof());
  return buf.data;
}

Uint8List encodeQuicVersionNegotiation(Uint8List sourceCid, Uint8List destinationCid, List<int> supportedVersions) {
  final buf = Buffer(capacity: 7 + destinationCid.length + sourceCid.length + 4 * supportedVersions.length);
  // Dart's equivalent of os.urandom(1)[0]
  buf.pushUint8(Random().nextInt(256) | PACKET_LONG_HEADER);
  buf.pushUint32(QuicProtocolVersion.NEGOTIATION.value);
  buf.pushUint8(destinationCid.length);
  buf.pushBytes(destinationCid);
  buf.pushUint8(sourceCid.length);
  buf.pushBytes(sourceCid);
  for (final version in supported_versions) {
    buf.pushUint32(version);
  }
  return buf.data;
}

// TLS EXTENSION

class QuicPreferredAddress {
  final Tuple<String, int>? ipv4Address;
  final Tuple<String, int>? ipv6Address;
  final Uint8List connectionId;
  final Uint8List statelessResetToken;

  QuicPreferredAddress({
    this.ipv4Address,
    this.ipv6Address,
    required this.connectionId,
    required this.statelessResetToken,
  });
}

class QuicVersionInformation {
  final int chosenVersion;
  final List<int> availableVersions;

  QuicVersionInformation({
    required this.chosenVersion,
    required this.availableVersions,
  });
}

class QuicTransportParameters {
  Uint8List? originalDestinationConnectionId;
  int? maxIdleTimeout;
  Uint8List? statelessResetToken;
  int? maxUdpPayloadSize;
  int? initialMaxData;
  int? initialMaxStreamDataBidiLocal;
  int? initialMaxStreamDataBidiRemote;
  int? initialMaxStreamDataUni;
  int? initialMaxStreamsBidi;
  int? initialMaxStreamsUni;
  int? ackDelayExponent;
  int? maxAckDelay;
  bool? disableActiveMigration;
  QuicPreferredAddress? preferredAddress;
  int? activeConnectionIdLimit;
  Uint8List? initialSourceConnectionId;
  Uint8List? retrySourceConnectionId;
  QuicVersionInformation? versionInformation;
  int? maxDatagramFrameSize;
  Uint8List? quantumReadiness;

  QuicTransportParameters({
    this.originalDestinationConnectionId,
    this.maxIdleTimeout,
    this.statelessResetToken,
    this.maxUdpPayloadSize,
    this.initialMaxData,
    this.initialMaxStreamDataBidiLocal,
    this.initialMaxStreamDataBidiRemote,
    this.initialMaxStreamDataUni,
    this.initialMaxStreamsBidi,
    this.initialMaxStreamsUni,
    this.ackDelayExponent,
    this.maxAckDelay,
    this.disableActiveMigration = false,
    this.preferredAddress,
    this.activeConnectionIdLimit,
    this.initialSourceConnectionId,
    this.retrySourceConnectionId,
    this.versionInformation,
    this.maxDatagramFrameSize,
    this.quantumReadiness,
  });
}

const PARAMS = {
  0x00: "original_destination_connection_id",
  0x01: "max_idle_timeout",
  0x02: "stateless_reset_token",
  0x03: "max_udp_payload_size",
  0x04: "initial_max_data",
  0x05: "initial_max_stream_data_bidi_local",
  0x06: "initial_max_stream_data_bidi_remote",
  0x07: "initial_max_stream_data_uni",
  0x08: "initial_max_streams_bidi",
  0x09: "initial_max_streams_uni",
  0x0A: "ack_delay_exponent",
  0x0B: "max_ack_delay",
  0x0C: "disable_active_migration",
  0x0D: "preferred_address",
  0x0E: "active_connection_id_limit",
  0x0F: "initial_source_connection_id",
  0x10: "retry_source_connection_id",
  0x11: "version_information",
  0x0020: "max_datagram_frame_size",
  0x0C37: "quantum_readiness",
};

// Placeholder for `Tuple` class
class Tuple<T1, T2> {
  final T1 item1;
  final T2 item2;
  Tuple(this.item1, this.item2);
}

// Placeholder for IPAddress
class IPAddress {
  final Uint8List packed;
  IPAddress(String address) : packed = Uint8List(0); // placeholder
}

QuicPreferredAddress pullQuicPreferredAddress(Buffer buf) {
  Tuple<String, int>? ipv4Address;
  final ipv4Host = buf.pullBytes(4);
  final ipv4Port = buf.pullUint16();
  if (!listEquals(ipv4Host, Uint8List(4))) {
    ipv4Address = Tuple(IPAddress.ipv4(ipv4Host).toString(), ipv4Port);
  }

  Tuple<String, int>? ipv6Address;
  final ipv6Host = buf.pullBytes(16);
  final ipv6Port = buf.pullUint16();
  if (!listEquals(ipv6Host, Uint8List(16))) {
    ipv6Address = Tuple(IPAddress.ipv6(ipv6Host).toString(), ipv6Port);
  }

  final connectionIdLength = buf.pullUint8();
  final connectionId = buf.pullBytes(connectionIdLength);
  final statelessResetToken = buf.pullBytes(16);

  return QuicPreferredAddress(
    ipv4Address: ipv4Address,
    ipv6Address: ipv6Address,
    connectionId: connectionId,
    statelessResetToken: statelessResetToken,
  );
}

void pushQuicPreferredAddress(Buffer buf, QuicPreferredAddress preferredAddress) {
  if (preferredAddress.ipv4Address != null) {
    buf.pushBytes(IPAddress(preferredAddress.ipv4Address!.item1).packed);
    buf.pushUint16(preferredAddress.ipv4Address!.item2);
  } else {
    buf.pushBytes(Uint8List(6));
  }

  if (preferredAddress.ipv6Address != null) {
    buf.pushBytes(IPAddress(preferredAddress.ipv6Address!.item1).packed);
    buf.pushUint16(preferredAddress.ipv6Address!.item2);
  } else {
    buf.pushBytes(Uint8List(18));
  }

  buf.pushUint8(preferredAddress.connectionId.length);
  buf.pushBytes(preferredAddress.connectionId);
  buf.pushBytes(preferredAddress.statelessResetToken);
}

QuicVersionInformation pullQuicVersionInformation(Buffer buf, int length) {
  final chosenVersion = buf.pullUint32();
  final availableVersions = <int>[];
  for (int i = 0; i < length ~/ 4 - 1; i++) {
    availableVersions.add(buf.pullUint32());
  }

  if (chosenVersion == 0 || availableVersions.contains(0)) {
    throw FormatException("Version Information must not contain version 0");
  }

  return QuicVersionInformation(
    chosenVersion: chosenVersion,
    availableVersions: availableVersions,
  );
}

void pushQuicVersionInformation(Buffer buf, QuicVersionInformation versionInformation) {
  buf.pushUint32(versionInformation.chosenVersion);
  for (final version in versionInformation.availableVersions) {
    buf.pushUint32(version);
  }
}

QuicTransportParameters pullQuicTransportParameters(Buffer buf) {
  final params = QuicTransportParameters();
  while (!buf.eof()) {
    final paramId = buf.pullUintVar();
    final paramLen = buf.pullUintVar();
    final paramStart = buf.tell();
    if (PARAMS.containsKey(paramId)) {
      final paramName = PARAMS[paramId];
      if (paramName == "original_destination_connection_id" ||
          paramName == "stateless_reset_token" ||
          paramName == "initial_source_connection_id" ||
          paramName == "retry_source_connection_id" ||
          paramName == "quantum_readiness") {
        (params as dynamic).originalDestinationConnectionId = buf.pullBytes(paramLen);
      } else if (paramName == "max_idle_timeout" ||
          paramName == "max_udp_payload_size" ||
          paramName == "initial_max_data" ||
          paramName == "initial_max_stream_data_bidi_local" ||
          paramName == "initial_max_stream_data_bidi_remote" ||
          paramName == "initial_max_stream_data_uni" ||
          paramName == "initial_max_streams_bidi" ||
          paramName == "initial_max_streams_uni" ||
          paramName == "ack_delay_exponent" ||
          paramName == "max_ack_delay" ||
          paramName == "active_connection_id_limit" ||
          paramName == "max_datagram_frame_size") {
        (params as dynamic).maxIdleTimeout = buf.pullUintVar();
      } else if (paramName == "disable_active_migration") {
        (params as dynamic).disableActiveMigration = true;
      } else if (paramName == "preferred_address") {
        (params as dynamic).preferredAddress = pullQuicPreferredAddress(buf);
      } else if (paramName == "version_information") {
        (params as dynamic).versionInformation = pullQuicVersionInformation(buf, paramLen);
      }
    } else {
      buf.pullBytes(paramLen);
    }
    if (buf.tell() != paramStart + paramLen) {
      throw FormatException("Transport parameter length does not match");
    }
  }
  return params;
}

void pushQuicTransportParameters(Buffer buf, QuicTransportParameters params) {
  for (final paramId in PARAMS.keys) {
    final paramName = PARAMS[paramId];
    final paramValue = (params as dynamic).$paramName;
    if (paramValue != null && paramValue != false) {
      final paramBuf = Buffer(capacity: 65536);
      if (paramName == "original_destination_connection_id" ||
          paramName == "stateless_reset_token" ||
          paramName == "initial_source_connection_id" ||
          paramName == "retry_source_connection_id" ||
          paramName == "quantum_readiness") {
        paramBuf.pushBytes(paramValue);
      } else if (paramName == "max_idle_timeout" ||
          paramName == "max_udp_payload_size" ||
          paramName == "initial_max_data" ||
          paramName == "initial_max_stream_data_bidi_local" ||
          paramName == "initial_max_stream_data_bidi_remote" ||
          paramName == "initial_max_stream_data_uni" ||
          paramName == "initial_max_streams_bidi" ||
          paramName == "initial_max_streams_uni" ||
          paramName == "ack_delay_exponent" ||
          paramName == "max_ack_delay" ||
          paramName == "active_connection_id_limit" ||
          paramName == "max_datagram_frame_size") {
        paramBuf.pushUintVar(paramValue);
      } else if (paramName == "preferred_address") {
        pushQuicPreferredAddress(paramBuf, paramValue);
      } else if (paramName == "version_information") {
        pushQuicVersionInformation(paramBuf, paramValue);
      }
      buf.pushUintVar(paramId);
      buf.pushUintVar(paramBuf.tell());
      buf.pushBytes(paramBuf.data);
    }
  }
}

// FRAMES

enum QuicFrameType {
  PADDING(0x00),
  PING(0x01),
  ACK(0x02),
  ACK_ECN(0x03),
  RESET_STREAM(0x04),
  STOP_SENDING(0x05),
  CRYPTO(0x06),
  NEW_TOKEN(0x07),
  STREAM_BASE(0x08),
  MAX_DATA(0x10),
  MAX_STREAM_DATA(0x11),
  MAX_STREAMS_BIDI(0x12),
  MAX_STREAMS_UNI(0x13),
  DATA_BLOCKED(0x14),
  STREAM_DATA_BLOCKED(0x15),
  STREAMS_BLOCKED_BIDI(0x16),
  STREAMS_BLOCKED_UNI(0x17),
  NEW_CONNECTION_ID(0x18),
  RETIRE_CONNECTION_ID(0x19),
  PATH_CHALLENGE(0x1A),
  PATH_RESPONSE(0x1B),
  TRANSPORT_CLOSE(0x1C),
  APPLICATION_CLOSE(0x1D),
  HANDSHAKE_DONE(0x1E),
  DATAGRAM(0x30),
  DATAGRAM_WITH_LENGTH(0x31);

  final int value;
  const QuicFrameType(this.value);
}

final NON_ACK_ELICITING_FRAME_TYPES = {
  QuicFrameType.ACK,
  QuicFrameType.ACK_ECN,
  QuicFrameType.PADDING,
  QuicFrameType.TRANSPORT_CLOSE,
  QuicFrameType.APPLICATION_CLOSE,
};

final NON_IN_FLIGHT_FRAME_TYPES = {
  QuicFrameType.ACK,
  QuicFrameType.ACK_ECN,
  QuicFrameType.TRANSPORT_CLOSE,
  QuicFrameType.APPLICATION_CLOSE,
};

final PROBING_FRAME_TYPES = {
  QuicFrameType.PATH_CHALLENGE,
  QuicFrameType.PATH_RESPONSE,
  QuicFrameType.PADDING,
  QuicFrameType.NEW_CONNECTION_ID,
};

class QuicResetStreamFrame {
  final int errorCode;
  final int finalSize;
  final int streamId;

  QuicResetStreamFrame({
    required this.errorCode,
    required this.finalSize,
    required this.streamId,
  });
}

class QuicStopSendingFrame {
  final int errorCode;
  final int streamId;

  QuicStopSendingFrame({
    required this.errorCode,
    required this.streamId,
  });
}

class QuicStreamFrame {
  final Uint8List data;
  final bool fin;
  final int offset;

  QuicStreamFrame({
    this.data = const Uint8List(0),
    this.fin = false,
    this.offset = 0,
  });
}

Tuple<RangeSet, int> pullAckFrame(Buffer buf) {
  final rangeset = RangeSet();
  var end = buf.pullUintVar(); // largest acknowledged
  final delay = buf.pullUintVar();
  final ackRangeCount = buf.pullUintVar();
  final ackCount = buf.pullUintVar(); // first ack range
  rangeset.add(end - ackCount, end + 1);
  end -= ackCount;
  for (int i = 0; i < ackRangeCount; i++) {
    end -= buf.pullUintVar() + 2;
    final newAckCount = buf.pullUintVar();
    rangeset.add(end - newAckCount, end + 1);
    end -= newAckCount;
  }
  return Tuple(rangeset, delay);
}

int pushAckFrame(Buffer buf, RangeSet rangeset, int delay) {
  final ranges = rangeset.length;
  var index = ranges - 1;
  var r = rangeset.ranges[index];
  buf.pushUintVar(r[1] - 1);
  buf.pushUintVar(delay);
  buf.pushUintVar(index);
  buf.pushUintVar(r[1] - 1 - r[0]);
  var start = r[0];
  while (index > 0) {
    index -= 1;
    r = rangeset.ranges[index];
    buf.pushUintVar(start - r[1] - 1);
    buf.pushUintVar(r[1] - r[0] - 1);
    start = r[0];
  }
  return ranges;
}