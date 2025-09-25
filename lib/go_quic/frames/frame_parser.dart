import 'dart:convert';
import 'dart:typed_data';

import '../buffer.dart';

import 'dart:typed_data';

// Base class for all QUIC frames
abstract class QuicFrame {
  const QuicFrame();
}

// --- Frame Type Definitions ---

class PaddingFrame extends QuicFrame {
  final int length;
  const PaddingFrame({this.length = 1});
}

class PingFrame extends QuicFrame {
  const PingFrame();
}

class AckRange {
  final int gap;
  final int length;
  const AckRange({required this.gap, required this.length});
}

class EcnCounts {
  final int ect0;
  final int ect1;
  final int ce;
  const EcnCounts({required this.ect0, required this.ect1, required this.ce});
}

class AckFrame extends QuicFrame {
  final int largest;
  final int delay;
  final int firstRange;
  final List<AckRange> ranges;
  final EcnCounts? ecn;

  const AckFrame({
    required this.largest,
    required this.delay,
    required this.firstRange,
    this.ranges = const [],
    this.ecn,
  });
}

class ResetStreamFrame extends QuicFrame {
  final int id;
  final int error;
  final int finalSize;

  const ResetStreamFrame({
    required this.id,
    required this.error,
    required this.finalSize,
  });
}

class StopSendingFrame extends QuicFrame {
  final int id;
  final int error;
  const StopSendingFrame({required this.id, required this.error});
}

class CryptoFrame extends QuicFrame {
  final int offset;
  final Uint8List data;
  const CryptoFrame({required this.offset, required this.data});
}

class NewTokenFrame extends QuicFrame {
  final Uint8List token;
  const NewTokenFrame({required this.token});
}

class StreamFrame extends QuicFrame {
  final int id;
  final int offset;
  final bool fin;
  final Uint8List data;

  const StreamFrame({
    required this.id,
    this.offset = 0,
    this.fin = false,
    required this.data,
  });
}

class MaxDataFrame extends QuicFrame {
  final int max;
  const MaxDataFrame({required this.max});
}

class MaxStreamDataFrame extends QuicFrame {
  final int id;
  final int max;
  const MaxStreamDataFrame({required this.id, required this.max});
}

class MaxStreamsFrame extends QuicFrame {
  final int max;
  final bool isBidi;
  const MaxStreamsFrame({required this.max, this.isBidi = true});
}

class DataBlockedFrame extends QuicFrame {
  final int limit;
  const DataBlockedFrame({required this.limit});
}

class StreamDataBlockedFrame extends QuicFrame {
  final int id;
  final int limit;
  const StreamDataBlockedFrame({required this.id, required this.limit});
}

class StreamsBlockedFrame extends QuicFrame {
  final int limit;
  final bool isBidi;
  const StreamsBlockedFrame({required this.limit, this.isBidi = true});
}

class NewConnectionIdFrame extends QuicFrame {
  final int seq;
  final int retire;
  final Uint8List connId;
  final Uint8List token;

  const NewConnectionIdFrame({
    required this.seq,
    required this.retire,
    required this.connId,
    required this.token,
  });
}

class RetireConnectionIdFrame extends QuicFrame {
  final int seq;
  const RetireConnectionIdFrame({required this.seq});
}

class PathChallengeFrame extends QuicFrame {
  final Uint8List data;
  const PathChallengeFrame({required this.data});
}

class PathResponseFrame extends QuicFrame {
  final Uint8List data;
  const PathResponseFrame({required this.data});
}

class ConnectionCloseFrame extends QuicFrame {
  final int error;
  final int frameType;
  final String reason;
  final bool isApplication;

  const ConnectionCloseFrame({
    required this.error,
    this.frameType = 0,
    this.reason = "",
    this.isApplication = false,
  });
}

class HandshakeDoneFrame extends QuicFrame {
  const HandshakeDoneFrame();
}

// Add other frame classes as needed...

/// Parses a byte buffer and decodes it into a list of QUIC frames.
List<QuicFrame> parseQuicFrames(Uint8List data) {
  final buffer = Buffer(data: data);
  final frames = <QuicFrame>[];

  // The try-catch block gracefully handles any buffer read errors.
  // If the packet is malformed, we stop parsing and return what we have.
  try {
    while (!buffer.eof) {
      final type = buffer.pullUint8();

      // PADDING frames are simply ignored after being read.
      if (type == 0x00) {
        continue;
      }
      // STREAM frames (0x08 to 0x0f)
      else if (type >= 0x08 && type <= 0x0f) {
        final hasOff = (type & 0x04) != 0;
        final hasLen = (type & 0x02) != 0;
        final fin = (type & 0x01) != 0;

        final id = buffer.pullVarInt();
        final offset = hasOff ? buffer.pullVarInt() : 0;

        // If length is not present, the data extends to the end of the packet.
        final len = hasLen ? buffer.pullVarInt() : buffer.remaining;
        final data = buffer.pullBytes(len);

        frames.add(StreamFrame(id: id, offset: offset, fin: fin, data: data));
      }
      // ACK frames (0x02, 0x03)
      else if (type == 0x02 || type == 0x03) {
        final hasEcn = (type & 0x01) != 0;
        final largest = buffer.pullVarInt();
        final delay = buffer.pullVarInt();
        final rangeCount = buffer.pullVarInt();
        final firstRange = buffer.pullVarInt();

        final ranges = <AckRange>[];
        for (var i = 0; i < rangeCount; i++) {
          final gap = buffer.pullVarInt();
          final len = buffer.pullVarInt();
          ranges.add(AckRange(gap: gap, length: len));
        }

        EcnCounts? ecn;
        if (hasEcn) {
          final ect0 = buffer.pullVarInt();
          final ect1 = buffer.pullVarInt();
          final ce = buffer.pullVarInt();
          ecn = EcnCounts(ect0: ect0, ect1: ect1, ce: ce);
        }

        frames.add(
          AckFrame(
            largest: largest,
            delay: delay,
            firstRange: firstRange,
            ranges: ranges,
            ecn: ecn,
          ),
        );
      }
      // All other frame types
      else {
        switch (type) {
          case 0x01: // PING
            frames.add(const PingFrame());
            break;

          case 0x04: // RESET_STREAM
            final id = buffer.pullVarInt();
            final error = buffer.pullUint16();
            final finalSize = buffer.pullVarInt();
            frames.add(
              ResetStreamFrame(id: id, error: error, finalSize: finalSize),
            );
            break;

          case 0x05: // STOP_SENDING
            final id = buffer.pullVarInt();
            final error = buffer.pullUint16();
            frames.add(StopSendingFrame(id: id, error: error));
            break;

          case 0x06: // CRYPTO
            final offset = buffer.pullVarInt();
            final len = buffer.pullVarInt();
            final data = buffer.pullBytes(len);
            frames.add(CryptoFrame(offset: offset, data: data));
            break;

          case 0x07: // NEW_TOKEN
            final len = buffer.pullVarInt();
            final token = buffer.pullBytes(len);
            frames.add(NewTokenFrame(token: token));
            break;

          case 0x10: // MAX_DATA
            final max = buffer.pullVarInt();
            frames.add(MaxDataFrame(max: max));
            break;

          case 0x11: // MAX_STREAM_DATA
            final id = buffer.pullVarInt();
            final max = buffer.pullVarInt();
            frames.add(MaxStreamDataFrame(id: id, max: max));
            break;

          case 0x12: // MAX_STREAMS (Bidi)
          case 0x13: // MAX_STREAMS (Uni)
            final max = buffer.pullVarInt();
            frames.add(MaxStreamsFrame(max: max, isBidi: type == 0x12));
            break;

          case 0x18: // NEW_CONNECTION_ID
            final seq = buffer.pullVarInt();
            final retire = buffer.pullVarInt();
            final len = buffer.pullUint8();
            final connId = buffer.pullBytes(len);
            final token = buffer.pullBytes(
              16,
            ); // Stateless Reset Token is always 16 bytes
            frames.add(
              NewConnectionIdFrame(
                seq: seq,
                retire: retire,
                connId: connId,
                token: token,
              ),
            );
            break;

          case 0x19: // RETIRE_CONNECTION_ID
            final seq = buffer.pullVarInt();
            frames.add(RetireConnectionIdFrame(seq: seq));
            break;

          case 0x1a: // PATH_CHALLENGE
          case 0x1b: // PATH_RESPONSE
            final data = buffer.pullBytes(8);
            if (type == 0x1a) {
              frames.add(PathChallengeFrame(data: data));
            } else {
              frames.add(PathResponseFrame(data: data));
            }
            break;

          case 0x1c: // CONNECTION_CLOSE (QUIC)
          case 0x1d: // CONNECTION_CLOSE (Application)
            final isApplication = type == 0x1d;
            final error = buffer.pullUint16();
            final frameType = isApplication ? 0 : buffer.pullVarInt();
            final reasonLen = buffer.pullVarInt();
            final reasonBytes = buffer.pullBytes(reasonLen);
            final reason = utf8.decode(reasonBytes);
            frames.add(
              ConnectionCloseFrame(
                error: error,
                isApplication: isApplication,
                frameType: frameType,
                reason: reason,
              ),
            );
            break;

          case 0x1e: // HANDSHAKE_DONE
            frames.add(const HandshakeDoneFrame());
            break;

          default:
            // Unknown frame type, stop parsing to avoid errors.
            // You could also add an 'UnknownFrame' type to the list if needed.
            // print('Encountered unknown frame type: 0x${type.toRadixString(16)}');
            return frames;
        }
      }
    }
  } catch (e) {
    // A BufferReadError likely means the packet was malformed or truncated.
    print('Error parsing frames: $e');
  }

  return frames;
}

/// Encodes a list of QUIC frames into a single byte buffer.
Uint8List encodeQuicFrames(List<QuicFrame> frames) {
  // Create a single buffer to write all frames into.
  // This is highly efficient as it avoids multiple allocations.
  final buffer = Buffer(data: Uint8List(0));

  for (final frame in frames) {
    // Use a switch on the object's runtimeType for clean, type-safe handling.
    switch (frame.runtimeType) {
      case PaddingFrame:
        final f = frame as PaddingFrame;
        // A new Uint8List is zero-filled by default.
        buffer.pushBytes(Uint8List(f.length));
        break;

      case PingFrame:
        buffer.pushUint8(0x01);
        break;

      case AckFrame:
        final f = frame as AckFrame;
        final hasEcn = f.ecn != null;
        buffer.pushUint8(hasEcn ? 0x03 : 0x02); // Type byte
        buffer.pushUintVar(f.largest);
        buffer.pushUintVar(f.delay);
        buffer.pushUintVar(f.ranges.length);
        buffer.pushUintVar(f.firstRange);

        for (final range in f.ranges) {
          buffer.pushUintVar(range.gap);
          buffer.pushUintVar(range.length);
        }

        if (hasEcn) {
          buffer.pushUintVar(f.ecn!.ect0);
          buffer.pushUintVar(f.ecn!.ect1);
          buffer.pushUintVar(f.ecn!.ce);
        }
        break;

      case ResetStreamFrame:
        final f = frame as ResetStreamFrame;
        buffer.pushUint8(0x04);
        buffer.pushUintVar(f.id);
        buffer.pushUint16(f.error); // Pushing a 16-bit error code
        buffer.pushUintVar(f.finalSize);
        break;

      case StopSendingFrame:
        final f = frame as StopSendingFrame;
        buffer.pushUint8(0x05);
        buffer.pushUintVar(f.id);
        buffer.pushUint16(f.error);
        break;

      case CryptoFrame:
        final f = frame as CryptoFrame;
        buffer.pushUint8(0x06);
        buffer.pushUintVar(f.offset);
        buffer.pushUintVar(f.data.length);
        buffer.pushBytes(f.data);
        break;

      case NewTokenFrame:
        final f = frame as NewTokenFrame;
        buffer.pushUint8(0x07);
        buffer.pushUintVar(f.token.length);
        buffer.pushBytes(f.token);
        break;

      case StreamFrame:
        final f = frame as StreamFrame;
        var typeByte = 0x08;
        final hasOffset = f.offset > 0;
        final hasLen = f.data.isNotEmpty;

        if (hasOffset) typeByte |= 0x04; // OFF bit
        if (hasLen) typeByte |= 0x02; // LEN bit
        if (f.fin) typeByte |= 0x01; // FIN bit

        buffer.pushUint8(typeByte);
        buffer.pushUintVar(f.id);
        if (hasOffset) {
          buffer.pushUintVar(f.offset);
        }
        if (hasLen) {
          buffer.pushUintVar(f.data.length);
          buffer.pushBytes(f.data);
        }
        break;

      case MaxDataFrame:
        final f = frame as MaxDataFrame;
        buffer.pushUint8(0x10);
        buffer.pushUintVar(f.max);
        break;

      case MaxStreamDataFrame:
        final f = frame as MaxStreamDataFrame;
        buffer.pushUint8(0x11);
        buffer.pushUintVar(f.id);
        buffer.pushUintVar(f.max);
        break;

      case MaxStreamsFrame:
        final f = frame as MaxStreamsFrame;
        buffer.pushUint8(f.isBidi ? 0x12 : 0x13);
        buffer.pushUintVar(f.max);
        break;

      case NewConnectionIdFrame:
        final f = frame as NewConnectionIdFrame;
        buffer.pushUint8(0x18);
        buffer.pushUintVar(f.seq);
        buffer.pushUintVar(f.retire);
        buffer.pushUint8(f.connId.length); // Length is a single byte
        buffer.pushBytes(f.connId);
        buffer.pushBytes(f.token); // Stateless Reset Token is 16 bytes
        break;

      case RetireConnectionIdFrame:
        final f = frame as RetireConnectionIdFrame;
        buffer.pushUint8(0x19);
        buffer.pushUintVar(f.seq);
        break;

      case PathChallengeFrame:
        final f = frame as PathChallengeFrame;
        buffer.pushUint8(0x1a);
        buffer.pushBytes(f.data); // Data is 8 bytes
        break;

      case PathResponseFrame:
        final f = frame as PathResponseFrame;
        buffer.pushUint8(0x1b);
        buffer.pushBytes(f.data); // Data is 8 bytes
        break;

      case ConnectionCloseFrame:
        final f = frame as ConnectionCloseFrame;
        buffer.pushUint8(f.isApplication ? 0x1d : 0x1c);
        buffer.pushUint16(f.error);
        if (!f.isApplication) {
          buffer.pushUintVar(f.frameType);
        }
        final reasonBytes = utf8.encode(f.reason);
        buffer.pushUintVar(reasonBytes.length);
        buffer.pushBytes(reasonBytes);
        break;

      case HandshakeDoneFrame:
        buffer.pushUint8(0x1e);
        break;

      default:
        // Optionally handle unknown frame types
        // print('Unsupported frame type: ${frame.runtimeType}');
        break;
    }
  }

  // Return the underlying Uint8List containing all the encoded data.
  return buffer.toBytes();
}

void main() {
  // 1. Create a list of frames to encode.
  final framesToEncode = <QuicFrame>[
    PingFrame(),
    StreamFrame(
      id: 2,
      offset: 1024,
      fin: true,
      data: Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]),
    ),
    MaxDataFrame(max: 987654),
  ];

  // 2. Encode the frames into a byte buffer.
  final encodedData = encodeQuicFrames(framesToEncode);
  print('Encoded ${encodedData.length} bytes.');

  // 3. Parse the bytes back into frame objects.
  final decodedFrames = parseQuicFrames(encodedData);
  print('Decoded ${decodedFrames.length} frames:');

  // 4. Verify the results.
  for (final frame in decodedFrames) {
    print('- Decoded frame of type: ${frame.runtimeType}');
    if (frame is StreamFrame) {
      print(
        '  Stream ID: ${frame.id}, Fin: ${frame.fin}, Data Length: ${frame.data.length}',
      );
    }
  }
}
