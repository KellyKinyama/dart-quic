import 'dart:typed_data';

import '../packet/quic_initial.dart';
import '../stream/quic_stream_frame.dart';
// Assume VarInt helper from previous steps is available
// import 'path/to/varint_helper.dart';

// Abstract base class for all QUIC Frames
abstract class QuicFrame {
  final int type; // Varint for frame type

  QuicFrame(this.type);

  Uint8List toBytes();
  // Factory for parsing any frame type (would be implemented in a FrameParser utility)
  factory QuicFrame.parse(Uint8List data, int offset) {
    final frameType = VarInt.read(data, offset);
    switch (frameType) {
      case 0x01: // PING (example, not discussed but common control frame)
      // return QuicPingFrame.parse(data, offset);
      case 0x04: // MAX_DATA
        return QuicMaxDataFrame.parse(data, offset);
      case 0x05: // MAX_STREAM_DATA
        return QuicMaxStreamDataFrame.parse(data, offset);
      case 0x06: // MAX_STREAMS (Bidirectional)
      case 0x07: // MAX_STREAMS (Unidirectional)
        return QuicMaxStreamsFrame.parse(data, offset);
      case 0x14: // DATA_BLOCKED
        return QuicDataBlockedFrame.parse(data, offset);
      case 0x15: // STREAM_DATA_BLOCKED
        return QuicStreamDataBlockedFrame.parse(data, offset);
      case 0x16: // STREAMS_BLOCKED (Bidirectional)
      case 0x17: // STREAMS_BLOCKED (Unidirectional)
        return QuicStreamsBlockedFrame.parse(data, offset);
      case int _: // STREAM frames from 0x08 to 0x0F
        if (frameType >= 0x08 && frameType <= 0x0F) {
          return QuicStreamFrame.parse(data, offset);
        }
        break;
      default:
        // Handle unknown or unimplemented frame types
        throw FormatException(
          'Unknown QUIC Frame Type: 0x${frameType.toRadixString(16)}',
        );
    }
    throw FormatException('Failed to parse QUIC Frame at offset $offset');
  }
}

// -------------------- Receiver-Sent Flow Control Frames --------------------

class QuicMaxDataFrame extends QuicFrame {
  static const int TYPE = 0x04;
  final int maximumData; // Varint

  QuicMaxDataFrame({required this.maximumData}) : super(TYPE);

  factory QuicMaxDataFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != TYPE)
      throw FormatException('Invalid frame type for MaxData Frame.');

    final maximumData = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(maximumData);

    return QuicMaxDataFrame(maximumData: maximumData);
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(maximumData));
    return builder.toBytes();
  }

  @override
  String toString() => 'MaxDataFrame(maxData: $maximumData)';
}

class QuicMaxStreamDataFrame extends QuicFrame {
  static const int TYPE = 0x05;
  final int streamId; // Varint
  final int maximumStreamData; // Varint

  QuicMaxStreamDataFrame({
    required this.streamId,
    required this.maximumStreamData,
  }) : super(TYPE);

  factory QuicMaxStreamDataFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != TYPE)
      throw FormatException('Invalid frame type for MaxStreamData Frame.');

    final streamId = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(streamId);

    final maximumStreamData = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(maximumStreamData);

    return QuicMaxStreamDataFrame(
      streamId: streamId,
      maximumStreamData: maximumStreamData,
    );
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(streamId));
    builder.add(VarInt.write(maximumStreamData));
    return builder.toBytes();
  }

  @override
  String toString() =>
      'MaxStreamDataFrame(streamId: $streamId, maxStreamData: $maximumStreamData)';
}

class QuicMaxStreamsFrame extends QuicFrame {
  // Types: 0x06 for Bidirectional, 0x07 for Unidirectional
  final int maximumStreams; // Varint

  QuicMaxStreamsFrame.bidi({required int maximumStreams})
    : this._internal(0x06, maximumStreams);
  QuicMaxStreamsFrame.uni({required int maximumStreams})
    : this._internal(0x07, maximumStreams);

  QuicMaxStreamsFrame._internal(int type, this.maximumStreams) : super(type);

  factory QuicMaxStreamsFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != 0x06 && type != 0x07)
      throw FormatException('Invalid frame type for MaxStreams Frame.');

    final maximumStreams = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(maximumStreams);

    return QuicMaxStreamsFrame._internal(type, maximumStreams);
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(maximumStreams));
    return builder.toBytes();
  }

  @override
  String toString() =>
      'MaxStreamsFrame(type: ${type == 0x06 ? 'Bidi' : 'Uni'}, maxStreams: $maximumStreams)';
}

// -------------------- Sender-Sent Flow Control Blocked Frames --------------------

class QuicDataBlockedFrame extends QuicFrame {
  static const int TYPE = 0x14;
  final int connectionLimit; // Varint, the limit that caused the blocking

  QuicDataBlockedFrame({required this.connectionLimit}) : super(TYPE);

  factory QuicDataBlockedFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != TYPE)
      throw FormatException('Invalid frame type for DataBlocked Frame.');

    final connectionLimit = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(connectionLimit);

    return QuicDataBlockedFrame(connectionLimit: connectionLimit);
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(connectionLimit));
    return builder.toBytes();
  }

  @override
  String toString() => 'DataBlockedFrame(limit: $connectionLimit)';
}

class QuicStreamDataBlockedFrame extends QuicFrame {
  static const int TYPE = 0x15;
  final int streamId; // Varint
  final int
  streamDataLimit; // Varint, the limit that caused the blocking on this stream

  QuicStreamDataBlockedFrame({
    required this.streamId,
    required this.streamDataLimit,
  }) : super(TYPE);

  factory QuicStreamDataBlockedFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != TYPE)
      throw FormatException('Invalid frame type for StreamDataBlocked Frame.');

    final streamId = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(streamId);

    final streamDataLimit = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(streamDataLimit);

    return QuicStreamDataBlockedFrame(
      streamId: streamId,
      streamDataLimit: streamDataLimit,
    );
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(streamId));
    builder.add(VarInt.write(streamDataLimit));
    return builder.toBytes();
  }

  @override
  String toString() =>
      'StreamDataBlockedFrame(streamId: $streamId, limit: $streamDataLimit)';
}

class QuicStreamsBlockedFrame extends QuicFrame {
  // Types: 0x16 for Bidirectional, 0x17 for Unidirectional
  final int
  streamLimit; // Varint, the limit that caused the blocking for stream creation

  QuicStreamsBlockedFrame.bidi({required int streamLimit})
    : this._internal(0x16, streamLimit);
  QuicStreamsBlockedFrame.uni({required int streamLimit})
    : this._internal(0x17, streamLimit);

  QuicStreamsBlockedFrame._internal(int type, this.streamLimit) : super(type);

  factory QuicStreamsBlockedFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != 0x16 && type != 0x17)
      throw FormatException('Invalid frame type for StreamsBlocked Frame.');

    final streamLimit = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(streamLimit);

    return QuicStreamsBlockedFrame._internal(type, streamLimit);
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(streamLimit));
    return builder.toBytes();
  }

  @override
  String toString() =>
      'StreamsBlockedFrame(type: ${type == 0x16 ? 'Bidi' : 'Uni'}, limit: $streamLimit)';
}

// Dummy QuicCryptoFrame for testing
class QuicCryptoFrame extends QuicFrame {
  final int offset;
  final int length;
  final Uint8List cryptoData;

  QuicCryptoFrame({
    required int type,
    required this.offset,
    required this.length,
    required this.cryptoData,
  }) : super(type);

  factory QuicCryptoFrame.parse(Uint8List data, int startOffset) {
    int currentOffset = startOffset;
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);

    final offset = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(offset);

    final length = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(length);

    final cryptoData = data.sublist(currentOffset, currentOffset + length);

    return QuicCryptoFrame(
      type: type,
      offset: offset,
      length: length,
      cryptoData: cryptoData,
    );
  }

  @override
  Uint8List toBytes() {
    // TODO: implement toBytes
    throw UnimplementedError();
  }
}
