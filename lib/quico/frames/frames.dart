
// Base class for all QUIC frames
import 'dart:typed_data';

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
  CryptoFrame({required this.offset, required this.data}) {
    // Buffer buffer=Buffer(data: data);

    // Now, parse the TLS messages inside the crypto data
    // final tlsMessages = parseTlsMessages(data);
    // if (tlsMessages.isEmpty) throw Exception("Empty tls messages");
    // final frame = CryptoFrame(offset, length, tlsMessages);
    // print('✅ Parsed tls mesesages $tlsMessages');
    // // Print details of the first TLS message found
    // if (frame.messages.isNotEmpty) {
    //   print(frame.messages.first);
    // }
  }
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