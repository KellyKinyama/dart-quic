// quic_frame_types.dart (new file)
import 'dart:typed_data';
import '../quic_variable_length_integer.dart'; // Assuming this exists

/// Defines the identifiers for QUIC Frame Types.
/// See RFC 9000, Section 19.
enum QuicFrameType {
  padding(0x00),
  ping(0x01),
  ack(0x02), // Also 0x03 for ACK with ECN
  resetStream(0x04),
  stopSending(0x05),
  crypto(0x06),
  newToken(0x07),
  // STREAM frames use a range of types 0x08-0x0f based on flags
  streamBase(0x08), // Base for STREAM frames
  maxData(0x10),
  maxStreamData(0x11),
  maxStreamsBidi(0x12), // MAX_STREAMS (bidirectional)
  maxStreamsUni(0x13), // MAX_STREAMS (unidirectional)
  dataBlocked(0x14),
  streamDataBlocked(0x15),
  streamsBlockedBidi(0x16), // STREAMS_BLOCKED (bidirectional)
  streamsBlockedUni(0x17), // STREAMS_BLOCKED (unidirectional)
  newConnectionId(0x18),
  retireConnectionId(0x19),
  pathChallenge(0x1a),
  pathResponse(0x1b),
  connectionCloseQuic(0x1c), // CONNECTION_CLOSE for QUIC errors
  connectionCloseApplication(0x1d), // CONNECTION_CLOSE for Application errors
  handshakeDone(0x1e);

  final int value;
  const QuicFrameType(this.value);

  /// Converts an integer frame type value to its enum.
  /// Handles STREAM, ACK, MAX_STREAMS, STREAMS_BLOCKED variations.
  static QuicFrameType fromValue(int value) {
    if (value >= 0x08 && value <= 0x0f) {
      return QuicFrameType.streamBase; // Represents all STREAM frame types
    }
    if (value == 0x02 || value == 0x03) {
      return QuicFrameType.ack; // Represents both ACK and ACK_ECN
    }
    if (value == 0x12) return QuicFrameType.maxStreamsBidi;
    if (value == 0x13) return QuicFrameType.maxStreamsUni;
    if (value == 0x16) return QuicFrameType.streamsBlockedBidi;
    if (value == 0x17) return QuicFrameType.streamsBlockedUni;
    if (value == 0x1c) return QuicFrameType.connectionCloseQuic;
    if (value == 0x1d) return QuicFrameType.connectionCloseApplication;

    for (var type in QuicFrameType.values) {
      if (type.value == value) {
        return type;
      }
    }
    throw ArgumentError(
      'Unknown QUIC frame type: 0x${value.toRadixString(16)}',
    );
  }

  /// Helper to determine if a type is a STREAM frame type.
  bool isStream() => value >= 0x08 && value <= 0x0f;

  /// Helper to determine if a type is an ACK frame type.
  bool isAck() => value == 0x02 || value == 0x03;

  /// Helper to determine if a type is a CONNECTION_CLOSE frame type.
  bool isConnectionClose() => value == 0x1c || value == 0x1d;

  /// Helper to determine if a type is a MAX_STREAMS frame type.
  bool isMaxStreams() => value == 0x12 || value == 0x13;

  /// Helper to determine if a type is a STREAMS_BLOCKED frame type.
  bool isStreamsBlocked() => value == 0x16 || value == 0x17;
}

/// Abstract base class for all QUIC frames.
abstract class QuicFrame {
  /// The raw frame type value as received or to be sent.
  final int rawType;

  /// The conceptual type of the frame. For STREAM and ACK frames, this
  /// will be the base type (e.g., QuicFrameType.streamBase, QuicFrameType.ack)
  /// allowing access to flags via rawType.
  QuicFrameType get type;

  QuicFrame(this.rawType);

  /// Encodes the frame into a byte list.
  Uint8List encode();

  /// Returns the length of the frame in bytes when encoded.
  int get encodedLength;

  /// Provides a string representation of the frame for debugging.
  @override
  String toString();
}

// Implement specific frame classes below...
// quic_frame_types.dart (continued)

/// PADDING Frame (Type = 0x00)
class PaddingFrame extends QuicFrame {
  PaddingFrame() : super(QuicFrameType.padding.value);

  @override
  QuicFrameType get type => QuicFrameType.padding;

  factory PaddingFrame.decode(Uint8List data, int offset) {
    if (data.isEmpty ||
        offset >= data.length ||
        data[offset] != QuicFrameType.padding.value) {
      throw FormatException('Invalid PADDING frame data at offset $offset');
    }
    return PaddingFrame();
  }

  @override
  Uint8List encode() {
    return Uint8List.fromList([rawType]);
  }

  @override
  int get encodedLength => 1;

  @override
  String toString() =>
      'PaddingFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')})';
}

/// PING Frame (Type = 0x01)
class PingFrame extends QuicFrame {
  PingFrame() : super(QuicFrameType.ping.value);

  @override
  QuicFrameType get type => QuicFrameType.ping;

  factory PingFrame.decode(Uint8List data, int offset) {
    if (data.isEmpty ||
        offset >= data.length ||
        data[offset] != QuicFrameType.ping.value) {
      throw FormatException('Invalid PING frame data at offset $offset');
    }
    return PingFrame();
  }

  @override
  Uint8List encode() {
    return Uint8List.fromList([rawType]);
  }

  @override
  int get encodedLength => 1;

  @override
  String toString() =>
      'PingFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')})';
}

/// HANDSHAKE_DONE Frame (Type = 0x1e)
class HandshakeDoneFrame extends QuicFrame {
  HandshakeDoneFrame() : super(QuicFrameType.handshakeDone.value);

  @override
  QuicFrameType get type => QuicFrameType.handshakeDone;

  factory HandshakeDoneFrame.decode(Uint8List data, int offset) {
    if (data.isEmpty ||
        offset >= data.length ||
        data[offset] != QuicFrameType.handshakeDone.value) {
      throw FormatException(
        'Invalid HANDSHAKE_DONE frame data at offset $offset',
      );
    }
    return HandshakeDoneFrame();
  }

  @override
  Uint8List encode() {
    return Uint8List.fromList([rawType]);
  }

  @override
  int get encodedLength => 1;

  @override
  String toString() =>
      'HandshakeDoneFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')})';
}

// quic_frame_types.dart (continued)

/// MAX_DATA Frame (Type = 0x10)
class MaxDataFrame extends QuicFrame {
  final int maximumData;

  MaxDataFrame(this.maximumData) : super(QuicFrameType.maxData.value);

  @override
  QuicFrameType get type => QuicFrameType.maxData;

  factory MaxDataFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    if (typeEntry.key != QuicFrameType.maxData.value) {
      throw FormatException(
        'Invalid MAX_DATA frame type: 0x${typeEntry.key.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final maxDataEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += maxDataEntry.value;

    return MaxDataFrame(maxDataEntry.key);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(maximumData));
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(maximumData);
  }

  @override
  String toString() =>
      'MaxDataFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Maximum Data: $maximumData)';
}

/// DATA_BLOCKED Frame (Type = 0x14)
class DataBlockedFrame extends QuicFrame {
  final int maximumData;

  DataBlockedFrame(this.maximumData) : super(QuicFrameType.dataBlocked.value);

  @override
  QuicFrameType get type => QuicFrameType.dataBlocked;

  factory DataBlockedFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    if (typeEntry.key != QuicFrameType.dataBlocked.value) {
      throw FormatException(
        'Invalid DATA_BLOCKED frame type: 0x${typeEntry.key.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final maxDataEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += maxDataEntry.value;

    return DataBlockedFrame(maxDataEntry.key);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(maximumData));
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(maximumData);
  }

  @override
  String toString() =>
      'DataBlockedFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Maximum Data: $maximumData)';
}

// quic_frame_types.dart (continued)

/// MAX_STREAM_DATA Frame (Type = 0x11)
class MaxStreamDataFrame extends QuicFrame {
  final int streamId;
  final int maximumStreamData;

  MaxStreamDataFrame(this.streamId, this.maximumStreamData)
    : super(QuicFrameType.maxStreamData.value);

  @override
  QuicFrameType get type => QuicFrameType.maxStreamData;

  factory MaxStreamDataFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    if (typeEntry.key != QuicFrameType.maxStreamData.value) {
      throw FormatException(
        'Invalid MAX_STREAM_DATA frame type: 0x${typeEntry.key.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final streamIdEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += streamIdEntry.value;

    final maxStreamDataEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += maxStreamDataEntry.value;

    return MaxStreamDataFrame(streamIdEntry.key, maxStreamDataEntry.key);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(streamId));
    bytes.addAll(QuicVariableLengthInteger.encode(maximumStreamData));
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(streamId) +
        QuicVariableLengthInteger.getEncodedLength(maximumStreamData);
  }

  @override
  String toString() =>
      'MaxStreamDataFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Stream ID: $streamId, Max Stream Data: $maximumStreamData)';
}

/// STREAM_DATA_BLOCKED Frame (Type = 0x15)
class StreamDataBlockedFrame extends QuicFrame {
  final int streamId;
  final int maximumStreamData;

  StreamDataBlockedFrame(this.streamId, this.maximumStreamData)
    : super(QuicFrameType.streamDataBlocked.value);

  @override
  QuicFrameType get type => QuicFrameType.streamDataBlocked;

  factory StreamDataBlockedFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    if (typeEntry.key != QuicFrameType.streamDataBlocked.value) {
      throw FormatException(
        'Invalid STREAM_DATA_BLOCKED frame type: 0x${typeEntry.key.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final streamIdEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += streamIdEntry.value;

    final maxStreamDataEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += maxStreamDataEntry.value;

    return StreamDataBlockedFrame(streamIdEntry.key, maxStreamDataEntry.key);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(streamId));
    bytes.addAll(QuicVariableLengthInteger.encode(maximumStreamData));
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(streamId) +
        QuicVariableLengthInteger.getEncodedLength(maximumStreamData);
  }

  @override
  String toString() =>
      'StreamDataBlockedFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Stream ID: $streamId, Max Stream Data: $maximumStreamData)';
}

/// STOP_SENDING Frame (Type = 0x05)
class StopSendingFrame extends QuicFrame {
  final int streamId;
  final int applicationProtocolErrorCode;

  StopSendingFrame(this.streamId, this.applicationProtocolErrorCode)
    : super(QuicFrameType.stopSending.value);

  @override
  QuicFrameType get type => QuicFrameType.stopSending;

  factory StopSendingFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    if (typeEntry.key != QuicFrameType.stopSending.value) {
      throw FormatException(
        'Invalid STOP_SENDING frame type: 0x${typeEntry.key.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final streamIdEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += streamIdEntry.value;

    final errorCodeEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += errorCodeEntry.value;

    return StopSendingFrame(streamIdEntry.key, errorCodeEntry.key);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(streamId));
    bytes.addAll(
      QuicVariableLengthInteger.encode(applicationProtocolErrorCode),
    );
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(streamId) +
        QuicVariableLengthInteger.getEncodedLength(
          applicationProtocolErrorCode,
        );
  }

  @override
  String toString() =>
      'StopSendingFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Stream ID: $streamId, Error Code: $applicationProtocolErrorCode)';
}

/// RESET_STREAM Frame (Type = 0x04)
class ResetStreamFrame extends QuicFrame {
  final int streamId;
  final int applicationProtocolErrorCode;
  final int finalSize;

  ResetStreamFrame(
    this.streamId,
    this.applicationProtocolErrorCode,
    this.finalSize,
  ) : super(QuicFrameType.resetStream.value);

  @override
  QuicFrameType get type => QuicFrameType.resetStream;

  factory ResetStreamFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    if (typeEntry.key != QuicFrameType.resetStream.value) {
      throw FormatException(
        'Invalid RESET_STREAM frame type: 0x${typeEntry.key.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final streamIdEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += streamIdEntry.value;

    final errorCodeEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += errorCodeEntry.value;

    final finalSizeEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += finalSizeEntry.value;

    return ResetStreamFrame(
      streamIdEntry.key,
      errorCodeEntry.key,
      finalSizeEntry.key,
    );
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(streamId));
    bytes.addAll(
      QuicVariableLengthInteger.encode(applicationProtocolErrorCode),
    );
    bytes.addAll(QuicVariableLengthInteger.encode(finalSize));
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(streamId) +
        QuicVariableLengthInteger.getEncodedLength(
          applicationProtocolErrorCode,
        ) +
        QuicVariableLengthInteger.getEncodedLength(finalSize);
  }

  @override
  String toString() =>
      'ResetStreamFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Stream ID: $streamId, Error Code: $applicationProtocolErrorCode, Final Size: $finalSize)';
}

// quic_frame_types.dart (continued)
// Helper class for ECN counts within ACK frame
class EcnCounts {
  final int ect0Count;
  final int ect1Count;
  final int ecnCeCount;

  EcnCounts({
    required this.ect0Count,
    required this.ect1Count,
    required this.ecnCeCount,
  });

  factory EcnCounts.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final ect0Entry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += ect0Entry.value;

    final ect1Entry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += ect1Entry.value;

    final ecnCeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += ecnCeEntry.value;

    return EcnCounts(
      ect0Count: ect0Entry.key,
      ect1Count: ect1Entry.key,
      ecnCeCount: ecnCeEntry.key,
    );
  }

  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(ect0Count));
    bytes.addAll(QuicVariableLengthInteger.encode(ect1Count));
    bytes.addAll(QuicVariableLengthInteger.encode(ecnCeCount));
    return Uint8List.fromList(bytes);
  }

  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(ect0Count) +
        QuicVariableLengthInteger.getEncodedLength(ect1Count) +
        QuicVariableLengthInteger.getEncodedLength(ecnCeCount);
  }

  @override
  String toString() =>
      'ECT0: $ect0Count, ECT1: $ect1Count, ECN-CE: $ecnCeCount';
}

// Helper class for ACK Range within ACK frame
class AckRange {
  final int gap; // Number of contiguous unacknowledged packets
  final int ackRangeLength; // Number of contiguous acknowledged packets

  AckRange({required this.gap, required this.ackRangeLength});

  factory AckRange.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final gapEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += gapEntry.value;

    final ackRangeLengthEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += ackRangeLengthEntry.value;

    return AckRange(gap: gapEntry.key, ackRangeLength: ackRangeLengthEntry.key);
  }

  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(gap));
    bytes.addAll(QuicVariableLengthInteger.encode(ackRangeLength));
    return Uint8List.fromList(bytes);
  }

  int get encodedLength {
    return QuicVariableLengthInteger.getEncodedLength(gap) +
        QuicVariableLengthInteger.getEncodedLength(ackRangeLength);
  }

  @override
  String toString() => 'Gap: $gap, Length: $ackRangeLength';
}

/// ACK Frame (Type = 0x02 or 0x03)
class AckFrame extends QuicFrame {
  final int largestAcknowledged;
  final int ackDelay;
  final int firstAckRange;
  final List<AckRange> ackRanges;
  final EcnCounts? ecnCounts; // Present if rawType is 0x03

  AckFrame({
    required int rawType,
    required this.largestAcknowledged,
    required this.ackDelay,
    required this.firstAckRange,
    this.ackRanges = const [],
    this.ecnCounts,
  }) : super(rawType) {
    if ((rawType == 0x03 && ecnCounts == null) ||
        (rawType == 0x02 && ecnCounts != null)) {
      throw ArgumentError(
        'ECN counts must be present if and only if rawType is 0x03.',
      );
    }
    if (!type.isAck()) {
      throw ArgumentError(
        'Invalid rawType for AckFrame: 0x${rawType.toRadixString(16)}',
      );
    }
  }

  @override
  QuicFrameType get type => QuicFrameType.ack;

  bool get hasEcn => rawType == 0x03;

  factory AckFrame.decode(Uint8List data, int offset) {
    int currentOffset = offset;
    final typeEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    final int frameRawType = typeEntry.key;
    if (!QuicFrameType.fromValue(frameRawType).isAck()) {
      throw FormatException(
        'Invalid ACK frame type: 0x${frameRawType.toRadixString(16)}',
      );
    }
    currentOffset += typeEntry.value;

    final largestAckedEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += largestAckedEntry.value;

    final ackDelayEntry = QuicVariableLengthInteger.decode(data, currentOffset);
    currentOffset += ackDelayEntry.value;

    final ackRangeCountEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    final int ackRangeCount = ackRangeCountEntry.key;
    currentOffset += ackRangeCountEntry.value;

    final firstAckRangeEntry = QuicVariableLengthInteger.decode(
      data,
      currentOffset,
    );
    currentOffset += firstAckRangeEntry.value;

    final List<AckRange> parsedAckRanges = [];
    for (int i = 0; i < ackRangeCount; i++) {
      final gapEntry = QuicVariableLengthInteger.decode(data, currentOffset);
      currentOffset += gapEntry.value;
      final ackRangeLengthEntry = QuicVariableLengthInteger.decode(
        data,
        currentOffset,
      );
      currentOffset += ackRangeLengthEntry.value;
      parsedAckRanges.add(
        AckRange(gap: gapEntry.key, ackRangeLength: ackRangeLengthEntry.key),
      );
    }

    EcnCounts? parsedEcnCounts;
    if (frameRawType == 0x03) {
      parsedEcnCounts = EcnCounts.decode(data, currentOffset);
      currentOffset += parsedEcnCounts.encodedLength;
    }

    // Ensure all bytes for this frame were consumed
    // This check is typically done by a higher-level frame parser, but useful for individual frame decoding factories.
    // However, since frame decoding factory methods typically receive only the *frame's* bytes,
    // we need to be careful with this check. Let's rely on the overall frame parser for length checks.
    // For now, assume the provided `data` starts exactly at the frame and ends at its boundary.

    return AckFrame(
      rawType: frameRawType,
      largestAcknowledged: largestAckedEntry.key,
      ackDelay: ackDelayEntry.key,
      firstAckRange: firstAckRangeEntry.key,
      ackRanges: parsedAckRanges,
      ecnCounts: parsedEcnCounts,
    );
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];
    bytes.addAll(QuicVariableLengthInteger.encode(rawType));
    bytes.addAll(QuicVariableLengthInteger.encode(largestAcknowledged));
    bytes.addAll(QuicVariableLengthInteger.encode(ackDelay));
    bytes.addAll(
      QuicVariableLengthInteger.encode(ackRanges.length),
    ); // ACK Range Count
    bytes.addAll(QuicVariableLengthInteger.encode(firstAckRange));

    for (final range in ackRanges) {
      bytes.addAll(range.encode());
    }

    if (hasEcn) {
      if (ecnCounts == null) {
        throw StateError('ACK frame type 0x03 requires ECN counts.');
      }
      bytes.addAll(ecnCounts!.encode());
    }
    return Uint8List.fromList(bytes);
  }

  @override
  int get encodedLength {
    int length =
        QuicVariableLengthInteger.getEncodedLength(rawType) +
        QuicVariableLengthInteger.getEncodedLength(largestAcknowledged) +
        QuicVariableLengthInteger.getEncodedLength(ackDelay) +
        QuicVariableLengthInteger.getEncodedLength(ackRanges.length) +
        QuicVariableLengthInteger.getEncodedLength(firstAckRange);

    for (final range in ackRanges) {
      length += range.encodedLength;
    }

    if (hasEcn) {
      length += ecnCounts!.encodedLength;
    }
    return length;
  }

  @override
  String toString() {
    final StringBuffer sb = StringBuffer(
      'AckFrame (Type: 0x${rawType.toRadixString(16).padLeft(2, '0')}, Largest Acked: $largestAcknowledged, ACK Delay: $ackDelay, First ACK Range: $firstAckRange',
    );
    if (ackRanges.isNotEmpty) {
      sb.write(
        ', ACK Ranges: [${ackRanges.map((e) => e.toString()).join(', ')}]',
      );
    }
    if (hasEcn && ecnCounts != null) {
      sb.write(', ECN: {${ecnCounts.toString()}}');
    }
    sb.write(')');
    return sb.toString();
  }
}
