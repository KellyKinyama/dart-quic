// Imports required for the types and data structures.
import 'dart:typed_data';

// This is not a standard library class. You'd need to add a package like
// quiver to your pubspec.yaml if you need a CircularDeque.
// dependencies:
//   quiver: ^3.2.1
import 'package:quiver/collection.dart';

// Represents a raw buffer of bytes. Replaces C++ `BufPtr` and `folly::IOBuf`.
typedef Buf = Uint8List;

// Time representations in Dart. Replaces C++ `std::chrono::microseconds`.
// typedef Duration = Duration;
typedef TimePoint = DateTime;

// Nullable versions of integer types for optional values.
typedef OptionalIntegral<T extends int> = T?;

// --- Enums ---

enum PacketNumberSpace {
  initial,
  handshake,
  appData,
}

enum TokenType {
  retryToken,
  newToken,
}

enum HeaderForm {
  long(1),
  short(0);

  final int value;
  const HeaderForm(this.value);
}

enum ProtectionType {
  initial,
  handshake,
  zeroRtt,
  keyPhaseZero,
  keyPhaseOne,
}

// --- Constants ---

const int kHeaderFormMask = 0x80;
const int kMaxPacketNumEncodingSize = 4;
const int kNumInitialAckBlocksPerFrame = 3;

// --- Structs and Classes ---

class StreamId {
  final int value;
  const StreamId(this.value);

  @override
  bool operator ==(Object other) => other is StreamId && value == other.value;
  @override
  int get hashCode => value.hashCode;
}

typedef StreamGroupId = StreamId;

class ApplicationErrorCode {
  final int value;
  const ApplicationErrorCode(this.value);

  @override
  bool operator ==(Object other) => other is ApplicationErrorCode && value == other.value;
  @override
  int get hashCode => value.hashCode;
}

class QuicErrorCode {
  final int value;
  const QuicErrorCode(this.value);

  @override
  bool operator ==(Object other) => other is QuicErrorCode && value == other.value;
  @override
  int get hashCode => value.hashCode;
}

class FrameType {
  final int value;
  const FrameType(this.value);

  static const FrameType ack = FrameType(0);
  static const FrameType padding = FrameType(1);
  // ... other frame types as needed

  @override
  bool operator ==(Object other) => other is FrameType && value == other.value;
  @override
  int get hashCode => value.hashCode;
}

class PacketNum {
  final int value;
  const PacketNum(this.value);

  @override
  bool operator ==(Object other) => other is PacketNum && value == other.value;
  @override
  int get hashCode => value.hashCode;
}

class ConnectionId {
  final Uint8List data;
  const ConnectionId(this.data);

  @override
  bool operator ==(Object other) => other is ConnectionId && _listEquals(data, other.data);
  @override
  int get hashCode => Object.hashAll(data);
}

class StatelessResetToken {
  final Uint8List token;
  const StatelessResetToken(this.token);

  @override
  bool operator ==(Object other) => other is StatelessResetToken && _listEquals(token, other.token);
  @override
  int get hashCode => Object.hashAll(token);
}

bool _listEquals<T>(List<T>? a, List<T>? b) {
  if (a == null || b == null) return a == b;
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Represents `IntervalSet<PacketNum>`. Since Dart doesn't have a direct equivalent
// to IntervalSet, we can model it with a List of Interval objects.
class Interval<T> {
  final T start;
  final T end;
  const Interval(this.start, this.end);

  @override
  bool operator ==(Object other) => other is Interval && start == other.start && end == other.end;
  @override
  int get hashCode => Object.hash(start, end);
}
typedef AckBlocks = List<Interval<PacketNum>>;

// --- Frame Definitions (Sealed Interface Pattern) ---

sealed interface QuicFrame {}
sealed interface QuicSimpleFrame extends QuicFrame {}
sealed interface QuicWriteFrame extends QuicFrame {}

class PaddingFrame implements QuicFrame, QuicWriteFrame {
  final int numFrames;
  const PaddingFrame({this.numFrames = 1});

  @override
  bool operator ==(Object other) => other is PaddingFrame && numFrames == other.numFrames;
  @override
  int get hashCode => numFrames.hashCode;
}

class PingFrame implements QuicSimpleFrame, QuicWriteFrame {
  const PingFrame();
  @override
  bool operator ==(Object other) => other is PingFrame;
  @override
  int get hashCode => 0; // A constant value is acceptable for an empty class.
}

class KnobFrame implements QuicSimpleFrame, QuicWriteFrame {
  final int knobSpace;
  final int id;
  final Buf blob;
  final int len;

  const KnobFrame({
    required this.knobSpace,
    required this.id,
    required this.blob,
  }) : len = blob.length;

  @override
  bool operator ==(Object other) =>
      other is KnobFrame &&
      knobSpace == other.knobSpace &&
      id == other.id &&
      len == other.len &&
      _listEquals(blob, other.blob);
  @override
  int get hashCode => Object.hash(knobSpace, id, len, Object.hashAll(blob));
}

class AckFrequencyFrame implements QuicSimpleFrame, QuicWriteFrame {
  final int sequenceNumber;
  final int packetTolerance;
  final int updateMaxAckDelay;
  final int reorderThreshold;

  const AckFrequencyFrame({
    required this.sequenceNumber,
    required this.packetTolerance,
    required this.updateMaxAckDelay,
    required this.reorderThreshold,
  });

  @override
  bool operator ==(Object other) =>
      other is AckFrequencyFrame &&
      sequenceNumber == other.sequenceNumber &&
      packetTolerance == other.packetTolerance &&
      updateMaxAckDelay == other.updateMaxAckDelay &&
      reorderThreshold == other.reorderThreshold;
  @override
  int get hashCode =>
      Object.hash(sequenceNumber, packetTolerance, updateMaxAckDelay, reorderThreshold);
}

class ImmediateAckFrame implements QuicFrame, QuicWriteFrame {
  const ImmediateAckFrame();
  @override
  bool operator ==(Object other) => other is ImmediateAckFrame;
  @override
  int get hashCode => 0;
}

class RstStreamFrame implements QuicFrame, QuicWriteFrame {
  final StreamId streamId;
  final ApplicationErrorCode errorCode;
  final int finalSize;
  final int? reliableSize;

  const RstStreamFrame({
    required this.streamId,
    required this.errorCode,
    required this.finalSize,
    this.reliableSize,
  });

  @override
  bool operator ==(Object other) =>
      other is RstStreamFrame &&
      streamId == other.streamId &&
      errorCode == other.errorCode &&
      finalSize == other.finalSize &&
      reliableSize == other.reliableSize;
  @override
  int get hashCode => Object.hash(streamId, errorCode, finalSize, reliableSize);
}

class ReadCryptoFrame implements QuicFrame {
  final int offset;
  final Buf data;

  ReadCryptoFrame({
    required this.offset,
    required this.data,
  });

  @override
  bool operator ==(Object other) =>
      other is ReadCryptoFrame &&
      offset == other.offset &&
      _listEquals(data, other.data);
  @override
  int get hashCode => Object.hash(offset, Object.hashAll(data));
}

class NewTokenFrame implements QuicSimpleFrame, QuicWriteFrame {
  final Buf token;

  const NewTokenFrame({required this.token});

  @override
  bool operator ==(Object other) =>
      other is NewTokenFrame && _listEquals(token, other.token);
  @override
  int get hashCode => Object.hashAll(token);
}

class ReadNewTokenFrame implements QuicFrame {
  final Buf token;

  const ReadNewTokenFrame({required this.token});

  @override
  bool operator ==(Object other) =>
      other is ReadNewTokenFrame && _listEquals(token, other.token);
  @override
  int get hashCode => Object.hashAll(token);
}

// ... and so on for all the other frame types (MaxDataFrame, etc.)

// A few more complex examples:

class ReceivedPacket {
  final PacketNum pktNum;
  final ReceivedUdpPacketTimings timings;
  const ReceivedPacket({required this.pktNum, required this.timings});
}

class WriteAckFrameState {
  final AckBlocks acks;
  final ReceivedPacket? largestRecvdPacketInfo;
  final ReceivedPacket? lastRecvdPacketInfo;
  // CircularDeque needs a package like `quiver`
  final CircularDeque<ReceivedPacket> recvdPacketInfos;
  final int ecnECT0CountReceived;
  final int ecnECT1CountReceived;
  final int ecnCECountReceived;

  const WriteAckFrameState({
    required this.acks,
    this.largestRecvdPacketInfo,
    this.lastRecvdPacketInfo,
    required this.recvdPacketInfos,
    this.ecnECT0CountReceived = 0,
    this.ecnECT1CountReceived = 0,
    this.ecnCECountReceived = 0,
  });
}

// --- Header Definitions ---

class LongHeaderInvariant {
  final QuicVersion version;
  final ConnectionId srcConnId;
  final ConnectionId dstConnId;
  const LongHeaderInvariant({
    required this.version,
    required this.srcConnId,
    required this.dstConnId,
  });
}

class LongHeader {
  final PacketNum packetSequenceNum;
  final LongHeaderType longHeaderType;
  final LongHeaderInvariant invariant;
  final String? token;

  const LongHeader._internal({
    required this.longHeaderType,
    required this.packetSequenceNum,
    required this.invariant,
    this.token,
  });

  factory LongHeader({
    required LongHeaderType type,
    required ConnectionId srcConnId,
    required ConnectionId dstConnId,
    required PacketNum packetNum,
    required QuicVersion version,
    String? token,
  }) {
    return LongHeader._internal(
      longHeaderType: type,
      packetSequenceNum: packetNum,
      invariant: LongHeaderInvariant(
        version: version,
        srcConnId: srcConnId,
        dstConnId: dstConnId,
      ),
      token: token,
    );
  }

  PacketNumberSpace get packetNumberSpace => longHeaderType.packetNumberSpace;
  // ... other methods
}

enum LongHeaderType {
  initial(0x0),
  zeroRtt(0x1),
  handshake(0x2),
  retry(0x3);

  final int value;
  const LongHeaderType(this.value);

  PacketNumberSpace get packetNumberSpace {
    switch (this) {
      case LongHeaderType.initial:
      case LongHeaderType.retry:
        return PacketNumberSpace.initial;
      case LongHeaderType.handshake:
        return PacketNumberSpace.handshake;
      case LongHeaderType.zeroRtt:
        return PacketNumberSpace.appData;
    }
  }
}

// --- End of converted code ---