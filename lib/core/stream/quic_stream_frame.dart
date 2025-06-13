import 'dart:typed_data';

import '../flow_control/frame.dart';
import '../packet/quic_initial.dart';
// Assuming VarInt helper is available from previous steps
// import 'path/to/varint_helper.dart';

class QuicStreamFrame extends QuicFrame {
  final int type; // This is a varint, and its lowest bit is the FIN bit
  final int streamId; // Varint
  final int offset; // Varint
  final int length; // Varint, length of streamData
  final Uint8List streamData;

  // Constructor
  QuicStreamFrame({
    required this.type,
    required this.streamId,
    required this.offset,
    required this.length,
    required this.streamData,
  }) : super(type) {
    if (streamData.length != length) {
      throw ArgumentError('StreamData length does not match specified length.');
    }
  }

  // Check if the FIN bit is set
  bool get isFinSet => (type & 0x01) == 0x01;

  // Factory constructor for parsing from bytes
  factory QuicStreamFrame.parse(Uint8List data, int startOffset) {
    int currentOffset = startOffset;

    // Read Type (varint)
    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);

    // Read Stream ID (varint)
    final streamId = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(streamId);

    // Read Offset (varint)
    final offset = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(offset);

    // Read Length (varint)
    final length = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(length);

    // Read Stream Data
    if (currentOffset + length > data.length) {
      throw FormatException(
        'Malformed STREAM frame: data length exceeds bounds.',
      );
    }
    final streamData = data.sublist(currentOffset, currentOffset + length);
    currentOffset += length;

    return QuicStreamFrame(
      type: type,
      streamId: streamId,
      offset: offset,
      length: length,
      streamData: streamData,
    );
  }

  // Method to serialize the frame into bytes
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(streamId));
    builder.add(VarInt.write(offset));
    builder.add(VarInt.write(length));
    builder.add(streamData);
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'QuicStreamFrame(Type: 0x${type.toRadixString(16)}, Stream ID: $streamId, Offset: $offset, Length: $length, FIN: $isFinSet, Data: ${streamData.length} bytes)';
  }
}
