// quic_frame_parser.dart (new file)
import 'dart:typed_data';
import '../quic_variable_length_integer.dart';
import 'quic_frame_types.dart'; // Import all frame classes defined above

/// A utility class for parsing and encoding sequences of QUIC frames.
class QuicFrameParser {
  /// Parses a byte stream into a list of [QuicFrame] objects.
  static List<QuicFrame> parseFrames(Uint8List data) {
    final List<QuicFrame> frames = [];
    int offset = 0;

    while (offset < data.length) {
      if (data.length - offset < 1) {
        // Must at least have a type byte
        throw FormatException(
          'Incomplete frame at end of data. Remaining bytes: ${data.length - offset}',
        );
      }

      final typeEntry = QuicVariableLengthInteger.decode(data, offset);
      final int rawFrameType = typeEntry.key;
      final int typeLength = typeEntry.value;

      QuicFrame frame;
      int frameStartOffset =
          offset; // Keep track of where the current frame started

      try {
        final QuicFrameType parsedType = QuicFrameType.fromValue(rawFrameType);

        switch (parsedType) {
          case QuicFrameType.padding:
            frame = PaddingFrame.decode(data, offset);
            break;
          case QuicFrameType.ping:
            frame = PingFrame.decode(data, offset);
            break;
          case QuicFrameType.handshakeDone:
            frame = HandshakeDoneFrame.decode(data, offset);
            break;
          case QuicFrameType.maxData:
            frame = MaxDataFrame.decode(data, offset);
            break;
          case QuicFrameType.dataBlocked:
            frame = DataBlockedFrame.decode(data, offset);
            break;
          case QuicFrameType.maxStreamData:
            frame = MaxStreamDataFrame.decode(data, offset);
            break;
          case QuicFrameType.streamDataBlocked:
            frame = StreamDataBlockedFrame.decode(data, offset);
            break;
          case QuicFrameType.stopSending:
            frame = StopSendingFrame.decode(data, offset);
            break;
          case QuicFrameType.resetStream:
            frame = ResetStreamFrame.decode(data, offset);
            break;
          case QuicFrameType.ack:
            // ACK frame type needs special handling for rawType 0x02 vs 0x03
            frame = AckFrame.decode(data, offset);
            break;
          // Add other frame types here as they are implemented
          case QuicFrameType.crypto:
          case QuicFrameType.newToken:
          case QuicFrameType.streamBase: // STREAM frames have flags in type
          case QuicFrameType.maxStreamsBidi:
          case QuicFrameType.maxStreamsUni:
          case QuicFrameType.streamsBlockedBidi:
          case QuicFrameType.streamsBlockedUni:
          case QuicFrameType.newConnectionId:
          case QuicFrameType.retireConnectionId:
          case QuicFrameType.pathChallenge:
          case QuicFrameType.pathResponse:
          case QuicFrameType.connectionCloseQuic:
          case QuicFrameType.connectionCloseApplication:
            // For unimplemented frames, we can skip them by just reading the type and length
            // or throw an error indicating unimplemented parsing.
            // For now, let's just log and skip for demonstration
            print(
              'Warning: Frame type 0x${rawFrameType.toRadixString(16)} parsing not implemented. Skipping.',
            );
            // To correctly skip, we'd need to know the length of the frame.
            // For frames without an explicit length field (like STREAM 0x08),
            // this is problematic. For now, we'll assume they have a fixed minimum size
            // or an explicit length field. This is a simplification for a partially implemented parser.
            // A robust parser would need to know the structure of all frames.
            throw UnimplementedError(
              'Parsing for frame type 0x${rawFrameType.toRadixString(16)} is not yet implemented.',
            );

          default:
            throw FormatException(
              'Unknown frame type: 0x${rawFrameType.toRadixString(16)} at offset $offset',
            );
        }
        frames.add(frame);
        offset += frame.encodedLength; // Move offset past the current frame
      } on FormatException catch (e) {
        print(
          'Error parsing frame at offset $frameStartOffset (Type: 0x${rawFrameType.toRadixString(16)}): $e',
        );
        // Depending on strictness, we might terminate connection or skip the frame
        // For now, we'll just stop parsing further frames if one is malformed.
        throw e;
      } on UnimplementedError catch (e) {
        print(
          'Error: $e. Cannot fully parse packet without all frame implementations.',
        );
        throw e; // Re-throw to indicate incomplete parsing
      }
    }
    return frames;
  }

  /// Encodes a list of [QuicFrame] objects into a single byte stream.
  static Uint8List encodeFrames(List<QuicFrame> frames) {
    final List<int> bytes = [];
    for (final frame in frames) {
      bytes.addAll(frame.encode());
    }
    return Uint8List.fromList(bytes);
  }
}
