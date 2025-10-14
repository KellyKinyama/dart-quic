import 'dart:typed_data';

/// Represents a Variable-Length Integer (VLI) as defined in QUIC.
/// This is a utility class that would typically be in a separate 'auxiliary.dart' or 'utils.dart' file.
class VariableLengthInteger {
  final int value;
  final int byteLength;

  VariableLengthInteger(this.value, this.byteLength);

  factory VariableLengthInteger.decode(Uint8List bytes, int offset) {
    if (bytes.isEmpty || offset >= bytes.length) {
      throw const FormatException('Cannot decode VLI: Insufficient data.');
    }

    final int firstByte = bytes[offset];
    int lengthIndicator =
        (firstByte >> 6); // Extract the two most significant bits

    int byteLength;
    int value;

    switch (lengthIndicator) {
      case 0: // 1-byte encoding
        byteLength = 1;
        value = firstByte & 0x3F; // Mask out the two most significant bits
        break;
      case 1: // 2-byte encoding
        byteLength = 2;
        if (offset + 1 >= bytes.length) {
          throw const FormatException(
            'Cannot decode 2-byte VLI: Insufficient data.',
          );
        }
        value = (firstByte & 0x3F) << 8 | bytes[offset + 1];
        break;
      case 2: // 4-byte encoding
        byteLength = 4;
        if (offset + 3 >= bytes.length) {
          throw const FormatException(
            'Cannot decode 4-byte VLI: Insufficient data.',
          );
        }
        value =
            (firstByte & 0x3F) << 24 |
            bytes[offset + 1] << 16 |
            bytes[offset + 2] << 8 |
            bytes[offset + 3];
        break;
      case 3: // 8-byte encoding
        byteLength = 8;
        if (offset + 7 >= bytes.length) {
          throw const FormatException(
            'Cannot decode 8-byte VLI: Insufficient data.',
          );
        }
        // Handle 64-bit value properly with BigInt for values exceeding 2^53
        // For simplicity and common QUIC scenarios, directly using int might suffice,
        // but for full RFC compliance, BigInt would be safer for 8-byte VLIs.
        // As Dart ints are 64-bit, direct conversion is fine for up to 2^63-1.
        value =
            (firstByte & 0x3F) << 56 |
            bytes[offset + 1] << 48 |
            bytes[offset + 2] << 40 |
            bytes[offset + 3] << 32 |
            bytes[offset + 4] << 24 |
            bytes[offset + 5] << 16 |
            bytes[offset + 6] << 8 |
            bytes[offset + 7];
        break;
      default:
        throw const FormatException('Invalid VLI length indicator.');
    }
    return VariableLengthInteger(value, byteLength);
  }

  // Helper for encoding VLI (not strictly required by the prompt, but good for completeness)
  Uint8List encode() {
    if (value < 64) {
      return Uint8List.fromList([value]);
    } else if (value < 16384) {
      return Uint8List.fromList([0x40 | (value >> 8), value & 0xFF]);
    } else if (value < 1073741824) {
      return Uint8List.fromList([
        0x80 | (value >> 24),
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
      ]);
    } else if (value < 4611686018427387904) {
      // 2^62 - 1, max value for 8-byte VLI
      final ByteData bd = ByteData(8);
      bd.setUint64(0, value);
      final Uint8List bytes = bd.buffer.asUint8List();
      return Uint8List.fromList([
        0xC0 | (bytes[0] & 0x3F),
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
      ]);
    } else {
      throw ArgumentError(
        'Value too large for QUIC Variable-Length Integer encoding: $value',
      );
    }
  }
}

/// Abstract base class for all QUIC frames.
/// Each frame has a type, and methods for parsing from and encoding to bytes.
abstract class QuicFrame {
  final int type;

  QuicFrame(this.type);

  /// Factory method to parse a QUIC frame from a byte buffer.
  /// Returns the parsed QuicFrame and the number of bytes consumed.
  static QuicFrame parse(Uint8List bytes, int offset) {
    if (bytes.isEmpty || offset >= bytes.length) {
      throw const FormatException(
        'Cannot parse QUIC frame: Insufficient data.',
      );
    }

    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      offset,
    );
    final int frameType = frameTypeVli.value;
    offset += frameTypeVli.byteLength;

    switch (frameType) {
      case 0x01: // PING frame type
        return PingFrame.parse(
          bytes,
          offset - frameTypeVli.byteLength,
        ); // Pass the entire frame starting from type byte
      case 0x04: // RESET_STREAM frame type
        return ResetStreamFrame.parse(bytes, offset - frameTypeVli.byteLength);
      case 0x09: // RETIRE_CONNECTION_ID frame type
        return RetireConnectionIdFrame.parse(
          bytes,
          offset - frameTypeVli.byteLength,
        );
      case 0x05: // STOP_SENDING frame type
        return StopSendingFrame.parse(bytes, offset - frameTypeVli.byteLength);
      case 0x0F: // STREAM_DATA_BLOCKED frame type
        return StreamDataBlockedFrame.parse(
          bytes,
          offset - frameTypeVli.byteLength,
        );
      // case int _: // Stream frames (0x08-0x0F based on flags, often just 0x08 for simple STREAM)
      //   // Stream frame types range from 0x08 to 0x0F, depending on flags (FIN, LEN, OFF)
      //   // Check if the type falls within the STREAM frame range (0x08 to 0x0F, inclusive)
      //   if ((frameType & 0xF8) == 0x08) {
      //     return StreamFrame.parse(bytes, offset - frameTypeVli.byteLength);
      //   }
      //   throw FormatException('Unsupported or unrecognized QUIC frame type: 0x${frameType.toRadixString(16)}');
      case 0x06: // STREAMS_BLOCKED frame type (unidirectional)
        return StreamsBlockedFrame.parse(
          bytes,
          offset - frameTypeVli.byteLength,
        );
      case 0x07: // STREAMS_BLOCKED frame type (bidirectional)
        return StreamsBlockedFrame.parse(
          bytes,
          offset - frameTypeVli.byteLength,
        );
      // Add other frame types here as needed
      default:
        throw FormatException(
          'Unsupported or unrecognized QUIC frame type: 0x${frameType.toRadixString(16)}',
        );
    }
  }

  /// Encodes the frame into a byte buffer.
  Uint8List encode();
}

/// Represents a range of packet numbers, used in ACK frames.
/// Not a QUIC frame itself, but a helper class.
class Range {
  final int first;
  final int length;

  Range(this.first, this.length);

  @override
  String toString() {
    return 'Range(first: $first, length: $length)';
  }
}

/// Represents the type of stream (unidirectional or bidirectional).
/// Defined in RFC 9000, Section 2.1.
enum StreamType {
  bidirectional(0x00), // Stream ID is 0, 4, 8, ...
  unidirectional(0x01); // Stream ID is 2, 6, 10, ...

  final int idBit;

  const StreamType(this.idBit);

  // Helper to determine stream type from stream ID
  static StreamType fromStreamId(int streamId) {
    if (streamId % 2 == 0) {
      return StreamType.bidirectional;
    } else {
      return StreamType.unidirectional;
    }
  }
}

/// PING Frame (Type 0x01)
/// PING frames (type 0x01) are sent to solicit an acknowledgment from the recipient.
/// PING frames contain no fields.
class PingFrame extends QuicFrame {
  PingFrame() : super(0x01); // QUIC PING frame type is 0x01

  factory PingFrame.parse(Uint8List bytes, int offset) {
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      offset,
    );
    if (frameTypeVli.value != 0x01) {
      throw FormatException(
        'Invalid frame type for PingFrame: 0x${frameTypeVli.value.toRadixString(16)}',
      );
    }
    // PingFrame has no payload, just the type byte(s)
    return PingFrame();
  }

  @override
  Uint8List encode() {
    return Uint8List.fromList([type]);
  }

  @override
  String toString() {
    return 'PingFrame(type: 0x${type.toRadixString(16)})';
  }
}

/// RESET_STREAM Frame (Type 0x04)
/// The RESET_STREAM frame (type 0x04) is used to abruptly terminate a stream.
/// It contains a Stream ID, Application Protocol Error Code, and Final Size.
class ResetStreamFrame extends QuicFrame {
  final int streamId;
  final int applicationProtocolErrorCode;
  final int finalSize;

  ResetStreamFrame({
    required this.streamId,
    required this.applicationProtocolErrorCode,
    required this.finalSize,
  }) : super(0x04); // QUIC RESET_STREAM frame type is 0x04

  factory ResetStreamFrame.parse(Uint8List bytes, int offset) {
    int currentOffset = offset;
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    if (frameTypeVli.value != 0x04) {
      throw FormatException(
        'Invalid frame type for ResetStreamFrame: 0x${frameTypeVli.value.toRadixString(16)}',
      );
    }
    currentOffset += frameTypeVli.byteLength;

    final VariableLengthInteger streamIdVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    currentOffset += streamIdVli.byteLength;

    final VariableLengthInteger errorCodeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    currentOffset += errorCodeVli.byteLength;

    final VariableLengthInteger finalSizeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    // currentOffset += finalSizeVli.byteLength; // Not needed for parsing, but for next frame it would be

    return ResetStreamFrame(
      streamId: streamIdVli.value,
      applicationProtocolErrorCode: errorCodeVli.value,
      finalSize: finalSizeVli.value,
    );
  }

  @override
  Uint8List encode() {
    // Encoding logic: Type (VLI) + Stream ID (VLI) + Application Protocol Error Code (VLI) + Final Size (VLI)
    final BytesBuilder builder = BytesBuilder();
    builder.add(
      VariableLengthInteger(type, 0).encode(),
    ); // Encode type as VLI (length will be determined by value)
    builder.add(VariableLengthInteger(streamId, 0).encode());
    builder.add(
      VariableLengthInteger(applicationProtocolErrorCode, 0).encode(),
    );
    builder.add(VariableLengthInteger(finalSize, 0).encode());
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'ResetStreamFrame(type: 0x${type.toRadixString(16)}, streamId: $streamId, errorCode: $applicationProtocolErrorCode, finalSize: $finalSize)';
  }
}

/// RETIRE_CONNECTION_ID Frame (Type 0x09)
/// The RETIRE_CONNECTION_ID frame (type 0x09) is used by an endpoint to indicate that it will no longer use a connection ID that was issued by its peer.
/// It contains a Sequence Number.
class RetireConnectionIdFrame extends QuicFrame {
  final int sequenceNumber;

  RetireConnectionIdFrame({required this.sequenceNumber})
    : super(0x09); // QUIC RETIRE_CONNECTION_ID frame type is 0x09

  factory RetireConnectionIdFrame.parse(Uint8List bytes, int offset) {
    int currentOffset = offset;
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    if (frameTypeVli.value != 0x09) {
      throw FormatException(
        'Invalid frame type for RetireConnectionIdFrame: 0x${frameTypeVli.value.toRadixString(16)}',
      );
    }
    currentOffset += frameTypeVli.byteLength;

    final VariableLengthInteger sequenceNumberVli =
        VariableLengthInteger.decode(bytes, currentOffset);
    // currentOffset += sequenceNumberVli.byteLength; // Not needed for parsing

    return RetireConnectionIdFrame(sequenceNumber: sequenceNumberVli.value);
  }

  @override
  Uint8List encode() {
    final BytesBuilder builder = BytesBuilder();
    builder.add(VariableLengthInteger(type, 0).encode());
    builder.add(VariableLengthInteger(sequenceNumber, 0).encode());
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'RetireConnectionIdFrame(type: 0x${type.toRadixString(16)}, sequenceNumber: $sequenceNumber)';
  }
}

/// STOP_SENDING Frame (Type 0x05)
/// The STOP_SENDING frame (type 0x05) is used by an endpoint to communicate that it no longer wishes to receive data on a stream.
/// It contains a Stream ID and Application Protocol Error Code.
class StopSendingFrame extends QuicFrame {
  final int streamId;
  final int applicationProtocolErrorCode;

  StopSendingFrame({
    required this.streamId,
    required this.applicationProtocolErrorCode,
  }) : super(0x05); // QUIC STOP_SENDING frame type is 0x05

  factory StopSendingFrame.parse(Uint8List bytes, int offset) {
    int currentOffset = offset;
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    if (frameTypeVli.value != 0x05) {
      throw FormatException(
        'Invalid frame type for StopSendingFrame: 0x${frameTypeVli.value.toRadixString(16)}',
      );
    }
    currentOffset += frameTypeVli.byteLength;

    final VariableLengthInteger streamIdVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    currentOffset += streamIdVli.byteLength;

    final VariableLengthInteger errorCodeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    // currentOffset += errorCodeVli.byteLength; // Not needed for parsing

    return StopSendingFrame(
      streamId: streamIdVli.value,
      applicationProtocolErrorCode: errorCodeVli.value,
    );
  }

  @override
  Uint8List encode() {
    final BytesBuilder builder = BytesBuilder();
    builder.add(VariableLengthInteger(type, 0).encode());
    builder.add(VariableLengthInteger(streamId, 0).encode());
    builder.add(
      VariableLengthInteger(applicationProtocolErrorCode, 0).encode(),
    );
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'StopSendingFrame(type: 0x${type.toRadixString(16)}, streamId: $streamId, errorCode: $applicationProtocolErrorCode)';
  }
}

/// STREAM_DATA_BLOCKED Frame (Type 0x0F)
/// A STREAM_DATA_BLOCKED frame (type 0x0F) is used to indicate that the sender is unable to send data on a stream due to stream-level flow control.
/// It contains a Stream ID and Maximum Stream Data.
class StreamDataBlockedFrame extends QuicFrame {
  final int streamId;
  final int maximumStreamData;

  StreamDataBlockedFrame({
    required this.streamId,
    required this.maximumStreamData,
  }) : super(0x0F); // QUIC STREAM_DATA_BLOCKED frame type is 0x0F

  factory StreamDataBlockedFrame.parse(Uint8List bytes, int offset) {
    int currentOffset = offset;
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    if (frameTypeVli.value != 0x0F) {
      throw FormatException(
        'Invalid frame type for StreamDataBlockedFrame: 0x${frameTypeVli.value.toRadixString(16)}',
      );
    }
    currentOffset += frameTypeVli.byteLength;

    final VariableLengthInteger streamIdVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    currentOffset += streamIdVli.byteLength;

    final VariableLengthInteger maximumStreamDataVli =
        VariableLengthInteger.decode(bytes, currentOffset);
    // currentOffset += maximumStreamDataVli.byteLength; // Not needed for parsing

    return StreamDataBlockedFrame(
      streamId: streamIdVli.value,
      maximumStreamData: maximumStreamDataVli.value,
    );
  }

  @override
  Uint8List encode() {
    final BytesBuilder builder = BytesBuilder();
    builder.add(VariableLengthInteger(type, 0).encode());
    builder.add(VariableLengthInteger(streamId, 0).encode());
    builder.add(VariableLengthInteger(maximumStreamData, 0).encode());
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'StreamDataBlockedFrame(type: 0x${type.toRadixString(16)}, streamId: $streamId, maximumStreamData: $maximumStreamData)';
  }
}

/// STREAM Frame (Type 0x08-0x0F)
/// STREAM frames (type 0x08-0x0f) transmit stream data and the offset of that data in the stream.
/// The STREAM frame type field uses the least significant two bits to signal the presence of the Offset and Length fields.
/// - 0x04 (0x0100) - OFFSET bit: The Offset field is present.
/// - 0x02 (0x0010) - LEN bit: The Length field is present.
/// - 0x01 (0x0001) - FIN bit: This is the final Stream frame from the sender for this stream.
class StreamFrame extends QuicFrame {
  final int streamId;
  final int offset; // Optional, depends on OFFSET bit
  final int? length; // Optional, depends on LEN bit
  final Uint8List streamData;
  final bool fin; // FIN bit

  StreamFrame({
    required int type, // This type includes the flags
    required this.streamId,
    this.offset = 0, // Default to 0 if OFFSET bit is not set
    this.length, // Null if LEN bit is not set
    required this.streamData,
    this.fin = false,
  }) : super(type); // The type value includes the flags (FIN, LEN, OFF)

  // Flag constants
  static const int finBit = 0x01;
  static const int lenBit = 0x02;
  static const int offsetBit = 0x04;
  static const int baseType = 0x08; // Base for STREAM frames

  factory StreamFrame.parse(Uint8List bytes, int offset) {
    int currentOffset = offset;
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    final int frameType = frameTypeVli.value;

    // Check if it's a valid STREAM frame type (0x08 to 0x0F)
    if ((frameType & 0xF8) != baseType) {
      throw FormatException(
        'Invalid frame type for StreamFrame: 0x${frameType.toRadixString(16)}',
      );
    }

    currentOffset += frameTypeVli.byteLength;

    final bool fin = (frameType & finBit) != 0;
    final bool hasLength = (frameType & lenBit) != 0;
    final bool hasOffset = (frameType & offsetBit) != 0;

    final VariableLengthInteger streamIdVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    currentOffset += streamIdVli.byteLength;

    int parsedOffset = 0;
    if (hasOffset) {
      final VariableLengthInteger offsetVli = VariableLengthInteger.decode(
        bytes,
        currentOffset,
      );
      parsedOffset = offsetVli.value;
      currentOffset += offsetVli.byteLength;
    }

    int? parsedLength;
    if (hasLength) {
      final VariableLengthInteger lengthVli = VariableLengthInteger.decode(
        bytes,
        currentOffset,
      );
      parsedLength = lengthVli.value;
      currentOffset += lengthVli.byteLength;
    }

    // Remaining bytes are stream data
    final Uint8List streamData = Uint8List.fromList(
      bytes.sublist(currentOffset, bytes.length),
    );

    // If length field is present, verify it matches the actual data length
    if (hasLength && parsedLength != streamData.length) {
      throw FormatException(
        'Stream frame length mismatch. Declared: $parsedLength, Actual: ${streamData.length}',
      );
    }

    return StreamFrame(
      type: frameType,
      streamId: streamIdVli.value,
      offset: parsedOffset,
      length: parsedLength,
      streamData: streamData,
      fin: fin,
    );
  }

  @override
  Uint8List encode() {
    final BytesBuilder builder = BytesBuilder();

    // Determine the actual frame type byte based on flags
    int actualType = baseType;
    if (fin) actualType |= finBit;
    if (length != null) actualType |= lenBit;
    if (offset != 0)
      actualType |= offsetBit; // Only set OFFSET bit if offset is non-zero

    builder.add(VariableLengthInteger(actualType, 0).encode());
    builder.add(VariableLengthInteger(streamId, 0).encode());
    if (offset != 0) {
      // Only add offset if it's non-zero
      builder.add(VariableLengthInteger(offset, 0).encode());
    }
    if (length != null) {
      builder.add(VariableLengthInteger(length!, 0).encode());
    }
    builder.add(streamData);
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'StreamFrame(type: 0x${type.toRadixString(16)}, streamId: $streamId, offset: $offset, length: $length, fin: $fin, dataLength: ${streamData.length})';
  }
}

/// STREAMS_BLOCKED Frame (Types 0x06 and 0x07)
/// A STREAMS_BLOCKED frame (type 0x06 for bidirectional streams, type 0x07 for unidirectional streams) is used to indicate that the sender is unable to open more streams of a certain type.
/// It contains a Maximum Streams field.
class StreamsBlockedFrame extends QuicFrame {
  final StreamType streamType;
  final int maximumStreams;

  StreamsBlockedFrame({required this.streamType, required this.maximumStreams})
    : super(
        streamType == StreamType.bidirectional ? 0x06 : 0x07,
      ); // Type 0x06 for bidirectional, 0x07 for unidirectional

  factory StreamsBlockedFrame.parse(Uint8List bytes, int offset) {
    int currentOffset = offset;
    final VariableLengthInteger frameTypeVli = VariableLengthInteger.decode(
      bytes,
      currentOffset,
    );
    final int frameType = frameTypeVli.value;

    StreamType parsedStreamType;
    if (frameType == 0x06) {
      parsedStreamType = StreamType.bidirectional;
    } else if (frameType == 0x07) {
      parsedStreamType = StreamType.unidirectional;
    } else {
      throw FormatException(
        'Invalid frame type for StreamsBlockedFrame: 0x${frameType.toRadixString(16)}',
      );
    }
    currentOffset += frameTypeVli.byteLength;

    final VariableLengthInteger maximumStreamsVli =
        VariableLengthInteger.decode(bytes, currentOffset);
    // currentOffset += maximumStreamsVli.byteLength; // Not needed for parsing

    return StreamsBlockedFrame(
      streamType: parsedStreamType,
      maximumStreams: maximumStreamsVli.value,
    );
  }

  @override
  Uint8List encode() {
    final BytesBuilder builder = BytesBuilder();
    builder.add(VariableLengthInteger(type, 0).encode());
    builder.add(VariableLengthInteger(maximumStreams, 0).encode());
    return builder.toBytes();
  }

  @override
  String toString() {
    return 'StreamsBlockedFrame(type: 0x${type.toRadixString(16)}, streamType: $streamType, maximumStreams: $maximumStreams)';
  }
}
