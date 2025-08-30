// Filename: packet.dart
import 'dart:typed_data';
import 'buffer.dart';
import 'range_set.dart';

// --- Constants ---
const packetLongHeader = 0x80;
const packetFixedBit = 0x40;
const connectionIdMaxSize = 20;

class QuicProtocolVersion {
  static const int negotiation = 0;
  static const int version1 = 0x00000001;
  static const int version2 = 0x6B3343CF;
}

enum QuicPacketType {
  initial,
  zeroRtt,
  handshake,
  retry,
  versionNegotiation,
  oneRtt,
}

const Map<int, QuicPacketType> packetLongTypeDecodeVersion1 = {
  0: QuicPacketType.initial,
  1: QuicPacketType.zeroRtt,
  2: QuicPacketType.handshake,
  3: QuicPacketType.retry,
};

enum QuicFrameType {
  padding,
  ping,
  ack,
  ackWithEcn,
  resetStream,
  stopSending,
  crypto,
  newToken,
  stream,
  streamWithFin,
  streamWithLen,
  streamWithLenFin,
  streamWithOff,
  streamWithOffFin,
  streamWithOffLen,
  streamWithOffLenFin,
  maxData,
  maxStreamData,
  maxStreamsBidi,
  maxStreamsUni,
  dataBlocked,
  streamDataBlocked,
  streamsBlockedBidi,
  streamsBlockedUni,
  newConnectionId,
  retireConnectionId,
  pathChallenge,
  pathResponse,
  connectionClose,
  applicationClose,
  handshakeDone,
  datagram,
  datagramWithLength,
}

// --- Data Classes ---
class QuicHeader {
  final int? version;
  final QuicPacketType packetType;
  final Uint8List destinationCid;
  final Uint8List sourceCid;
  final int packetLength;
  final Uint8List? token;

  QuicHeader({
    this.version,
    required this.packetType,
    required this.destinationCid,
    required this.sourceCid,
    required this.packetLength,
    this.token,
  });
}

class QuicStreamFrame {
  final int offset;
  final Uint8List data;
  final bool fin;
  QuicStreamFrame({this.offset = 0, required this.data, this.fin = false});
}

// --- Parsing Logic ---
QuicHeader pullQuicHeader(Buffer buf, {required int hostCidLength}) {
  final packetStart = buf.tell();
  final firstByte = buf.pullUint8();

  if ((firstByte & packetLongHeader) != 0) {
    // Long Header
    final version = buf.pullUint32();
    if (version == QuicProtocolVersion.negotiation) {
      // Incomplete: Full Version Negotiation parsing needed
      return QuicHeader(
        version: version,
        packetType: QuicPacketType.versionNegotiation,
        destinationCid: Uint8List(0),
        sourceCid: Uint8List(0),
        packetLength: buf.capacity - packetStart,
      );
    }

    final dcidLen = buf.pullUint8();
    if (dcidLen > connectionIdMaxSize)
      throw Exception("Destination CID too long");
    final dcid = buf.pullBytes(dcidLen);

    final scidLen = buf.pullUint8();
    if (scidLen > connectionIdMaxSize) throw Exception("Source CID too long");
    final scid = buf.pullBytes(scidLen);

    final longType = (firstByte & 0x30) >> 4;
    final packetType = packetLongTypeDecodeVersion1[longType]!;

    Uint8List? token;
    if (packetType == QuicPacketType.initial) {
      final tokenLen = buf.pullUintVar();
      token = buf.pullBytes(tokenLen);
    }

    final length = buf.pullUintVar();
    final packetLength = buf.tell() + length - packetStart;
    if (packetLength > buf.capacity)
      throw Exception("Packet payload truncated");

    return QuicHeader(
      version: version,
      packetType: packetType,
      destinationCid: dcid,
      sourceCid: scid,
      packetLength: packetLength,
      token: token,
    );
  } else {
    // Short Header
    final dcid = buf.pullBytes(hostCidLength);
    return QuicHeader(
      packetType: QuicPacketType.oneRtt,
      destinationCid: dcid,
      sourceCid: Uint8List(0),
      packetLength: buf.capacity - packetStart,
    );
  }
}

(RangeSet, int) pullAckFrame(Buffer buf) {
  final rangeset = RangeSet();
  final largestAcked = buf.pullUintVar();
  final ackDelay = buf.pullUintVar();
  final ackRangeCount = buf.pullUintVar();

  var end = largestAcked;
  var firstAckRange = buf.pullUintVar();
  rangeset.add(end - firstAckRange, end + 1);
  end -= firstAckRange;

  for (var i = 0; i < ackRangeCount; i++) {
    end -= buf.pullUintVar() + 1; // Gap
    var ackRange = buf.pullUintVar();
    rangeset.add(end - ackRange, end + 1);
    end -= ackRange;
  }
  return (rangeset, ackDelay);
}
