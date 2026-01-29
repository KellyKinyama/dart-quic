import 'dart:convert';
import 'dart:typed_data';

import 'buffer.dart';
import 'handshake/handshake.dart';

sealed class QuicFrame {
  final String type;
  final Uint8List data;
  const QuicFrame({required this.type, required this.data});
}

class PingFrame extends QuicFrame {
  @override
  final Uint8List data;
  const PingFrame({required this.data}) : super(type: 'ping', data: data);
}

class PaddingFrame extends QuicFrame {
  final int length;

  @override
  final Uint8List data;
  const PaddingFrame({required this.length, required this.data})
    : super(type: 'padding', data: data);
}

class AckFrame extends QuicFrame {
  @override
  final Uint8List data;
  final int largest;
  final int delay;
  final int firstRange;
  final List<AckRange> ranges;
  final Map<String, int>? ecn;

  const AckFrame({
    required this.largest,
    required this.delay,
    required this.firstRange,
    required this.ranges,
    this.ecn,
    required this.data,
  }) : super(type: 'ack', data: data);
}

class AckRange {
  final int gap;
  final int length;
  const AckRange(this.gap, this.length);
}

class CryptoFrame extends QuicFrame {
  final int offset;

  @override
  // final String type;
  final Uint8List data;
  const CryptoFrame({required this.offset, required this.data})
    : super(type: 'crypto', data: data);

  @override
  String toString() {
    // TODO: implement toString
    return "CrypoFrame(offset: $offset)";
  }
}

class StreamFrame extends QuicFrame {
  final int id;
  final int offset;
  final bool fin;
  final Uint8List data;
  const StreamFrame({
    required this.id,
    required this.offset,
    required this.fin,
    required this.data,
  }) : super(type: 'stream', data: data);
}

class HandshakeDoneFrame extends QuicFrame {
  final Uint8List data;
  const HandshakeDoneFrame({required this.data})
    : super(type: 'handshake_done', data: data);
}

class ConnectionCloseFrame extends QuicFrame {
  final bool isApplication;
  final int errorCode;
  final int? triggerFrameType;
  final String reason;
  final Uint8List data;
  const ConnectionCloseFrame({
    required this.data,
    required this.isApplication,
    required this.errorCode,
    this.triggerFrameType,
    required this.reason,
  }) : super(type: 'connection_close', data: data);
}

class NewConnectionIdFrame extends QuicFrame {
  final int sequenceNumber;
  final int retirePriorTo;
  final Uint8List connectionId;
  final Uint8List statelessResetToken;
  final Uint8List data;

  const NewConnectionIdFrame({
    required this.data,
    required this.sequenceNumber,
    required this.retirePriorTo,
    required this.connectionId,
    required this.statelessResetToken,
  }) : super(type: 'new_connection_id', data: data);
}

class ResetStreamFrame extends QuicFrame {
  final int streamId;
  final int errorCode;
  final int finalSize;
  final Uint8List data;
  const ResetStreamFrame({
    required this.data,
    required this.streamId,
    required this.errorCode,
    required this.finalSize,
  }) : super(type: 'reset_stream', data: data);
}

class StopSendingFrame extends QuicFrame {
  final int streamId;
  final int errorCode;
  final Uint8List data;

  const StopSendingFrame({
    required this.data,
    required this.streamId,
    required this.errorCode,
  }) : super(type: 'stop_sending', data: data);
}

class DatagramFrame extends QuicFrame {
  final Uint8List data;
  const DatagramFrame({required this.data})
    : super(type: 'datagram', data: data);
}

final List<QuicFrame> localFrames = [];

List<QuicFrame> parse_quic_frames(Uint8List data) {
  final buffer = Buffer(data: data);
  // final List<QuicFrame> localFrames = [];

  while (buffer.remaining > 0) {
    final type = buffer.pullUint8();

    // Skip Padding
    if (type == 0x00) continue;

    try {
      if (type == 0x01) {
        // PING
        localFrames.add(PingFrame(data: Uint8List(0)));
      } else if (type == 0x02 || type == 0x03) {
        // ACK

        final largest = buffer.pullVarInt();
        final delay = buffer.pullVarInt();
        final count = buffer.pullVarInt();
        final firstRange = buffer.pullVarInt();

        final List<AckRange> ranges = [];
        for (int i = 0; i < count; i++) {
          final gap = buffer.pullVarInt();
          final len = buffer.pullVarInt();
          ranges.add(AckRange(gap, len));
        }

        // Handle ECN if type is 0x03
        if (type == 0x03) {
          buffer.pullVarInt(); // ect0
          buffer.pullVarInt(); // ect1
          buffer.pullVarInt(); // ce
        }

        localFrames.add(
          AckFrame(
            data: Uint8List(0),
            largest: largest,
            delay: delay,
            firstRange: firstRange, // FIXED: Matches the variable defined above
            ranges: ranges,
          ),
        );
      } else if (type == 0x06) {
        // CRYPTO
        final offset = buffer.pullVarInt();
        final length = buffer.pullVarInt();
        final cryptoData = buffer.pullBytes(length);
        if (offset == 0) {
          localFrames.removeWhere(
            (cryptoFrame) => cryptoFrame.runtimeType == CryptoFrame,
          );
        }
        localFrames.add(CryptoFrame(offset: offset, data: cryptoData));

        List<CryptoFrame> cryptoFrames = [];
        for (final frame in localFrames) {
          if (frame.runtimeType == CryptoFrame) {
            cryptoFrames.add(frame as CryptoFrame);
          }
        }
        if (cryptoFrames.isEmpty) {
          throw Exception("No Crypto Frames found");
        }

        // cryptoFrames.reduce((value, element) {
        //   value as CryptoFrame;
        //   element as CryptoFrame;
        //   return CryptoFrame(
        //     offset: value.offset,
        //     data: Uint8List.fromList([...value.data, ...element.data]),
        //   );
        // });

        // final cryptoFrame = cryptoFrames.first as CryptoFrame;
        // try {
        final tlsMessages = parseTlsMessages(cryptoFrames);
      } else if (type >= 0x08 && type <= 0x0f) {
        // STREAM
        final id = buffer.pullVarInt();
        int offset = 0;
        if ((type & 0x04) != 0) offset = buffer.pullVarInt();

        int length = 0;
        if ((type & 0x02) != 0) length = buffer.pullVarInt();

        final streamData = buffer.pullBytes(length);
        localFrames.add(
          StreamFrame(
            id: id,
            offset: offset,
            data: streamData,
            fin: (type & 0x01) != 0,
          ),
        );
      } else if (type == 0x1c || type == 0x1d) {
        // CONNECTION_CLOSE
        final isApp = (type == 0x1d);
        final errorCode = buffer.pullVarInt();

        // Transport Close (0x1c) has an extra Frame Type field
        if (!isApp) {
          buffer.pullVarInt(); // frameType
        }

        final reasonLen = buffer.pullVarInt();
        final reason = String.fromCharCodes(buffer.pullBytes(reasonLen));

        localFrames.add(
          ConnectionCloseFrame(
            data: Uint8List(0),
            errorCode: errorCode,
            isApplication: isApp,
            reason: reason,
          ),
        );
      } else if (type == 0x1e) {
        // HANDSHAKE_DONE
        localFrames.add(HandshakeDoneFrame(data: Uint8List(0)));
      } else {
        print(
          "      [DEBUG] Unknown Frame 0x${type.toRadixString(16)} at pos ${buffer.readOffset - 1}",
        );
        break; // Stop parsing this packet to prevent cascading alignment errors
      }
    } catch (e) {
      print("      [ERR] Malformed frame 0x${type.toRadixString(16)}: $e");
      break;
    }
  }
  return localFrames;
}
