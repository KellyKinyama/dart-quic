import 'dart:typed_data';
import 'dart:math';
import 'dart:convert';
import 'buffer.dart'; // Ensure your Buffer class is in this path

/// Main Connection State and Logic
class QuicConnection {
  final String id;
  int status = 4; // 0: Connecting, 1: Connected, 2: Disconnected

  String? fromIp;
  int? fromPort;
  int version = 1;

  // TLS / Secrets
  Uint8List? handshakeSecret;
  List<Uint8List> tlsTranscript = [];

  // Streams
  final Map<int, QuicStream> receivingStreams = {};
  final Map<int, H3RequestStream> h3Requests = {};

  // H3 Identifiers
  int? controlStreamId;
  int? qpackEncoderStreamId;
  int? qpackDecoderStreamId;

  // QPACK Dynamic Table
  int qpackTableCapacity = 0;
  int qpackMaxTableCapacity = 0;
  List<List<String>> qpackDynamicTable = [];

  QuicConnection(this.id);

  /// The heart of the packet processing
  void handlePacket(Map<String, dynamic> packet) {
    if (packet['type'] == 'initial') {
      _processInitial(packet);
    } else if (packet['type'] == 'handshake') {
      _processHandshake(packet);
    } else if (packet['type'] == '1rtt') {
      _processAppData(packet);
    }
  }

  void _processInitial(Map<String, dynamic> packet) {
    // 1. Decrypt (using your existing decrypt_quic_packet)
    // 2. Parse Frames
    // 3. If CRYPTO frame: add to tlsTranscript, handle ClientHello
  }

  void _processHandshake(Map<String, dynamic> packet) {
    // Process Handshake packets and move to status 1 (Connected)
  }

  void _processAppData(Map<String, dynamic> packet) {
    // Here we parse QUIC frames like STREAM or DATAGRAM
    var frames = packet['frames'] as List<dynamic>;
    for (var frame in frames) {
      if (frame['type'] == 'stream') {
        _onStreamFrame(frame);
      } else if (frame['type'] == 'datagram') {
        _onDatagramFrame(frame);
      }
    }
  }

  void _onStreamFrame(Map<String, dynamic> frame) {
    int streamId = frame['stream_id'];
    var stream = receivingStreams.putIfAbsent(
      streamId,
      () => QuicStream(streamId),
    );

    stream.chunks[frame['offset']] = frame['data'];
    stream.needCheck = true;

    _processH3Logic();
  }

  void _processH3Logic() {
    for (var streamId in receivingStreams.keys) {
      var stream = receivingStreams[streamId]!;
      if (!stream.needCheck) continue;

      // Identify Unidirectional Streams (Control, QPACK, etc.)
      if (_isUnidirectional(streamId) && stream.type == null) {
        _identifyStreamType(stream);
      }

      // Dispatch based on type
      if (streamId == controlStreamId) {
        _handleControlStream(stream);
      } else if (streamId == qpackEncoderStreamId) {
        _handleQpackEncoder(stream);
      } else if (!_isUnidirectional(streamId)) {
        _handleHttpRequest(stream);
      }

      stream.needCheck = false;
    }
  }

  bool _isUnidirectional(int id) => (id % 4 == 2) || (id % 4 == 3);

  void _identifyStreamType(QuicStream stream) {
    if (stream.chunks.containsKey(0)) {
      int type = stream.chunks[0]![0];
      stream.type = type;
      if (type == 0x00) controlStreamId = stream.id;
      if (type == 0x02) qpackEncoderStreamId = stream.id;
      if (type == 0x03) qpackDecoderStreamId = stream.id;
    }
  }

  void _handleControlStream(QuicStream stream) {
    // Use your extractH3FramesFromChunks logic here
    // If Frame Type 4: update qpackMaxTableCapacity
  }

  void _handleQpackEncoder(QuicStream stream) {
    // Process QPACK instructions and update qpackDynamicTable
  }

  void _handleHttpRequest(QuicStream stream) {
    var reqState = h3Requests.putIfAbsent(stream.id, () => H3RequestStream());
    // Parse H3 Frames -> QPACK -> Dispatch to your Server Handler
  }

  void _onDatagramFrame(Map<String, dynamic> frame) {
    // WebTransport Datagram logic
  }
}

/// Helper class for Stream data reassembly
class QuicStream {
  final int id;
  int? type;
  final Map<int, Uint8List> chunks = {};
  bool needCheck = false;
  bool isFinished = false;
  QuicStream(this.id);
}

/// Helper class for HTTP/3 request state
class H3RequestStream {
  int readOffset = 0;
  Map<String, String> headers = {};
  bool headersProcessed = false;
}
