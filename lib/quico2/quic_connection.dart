import 'dart:async';
import 'dart:typed_data';
import 'dart:math';
import 'dart:convert';
import 'buffer.dart';
import 'crypto.dart';
import 'quic_packet.dart'; // Ensure your Buffer class is in this path

// Add this helper at the top or inside the class
String _hex(Uint8List? bytes, {int limit = 4}) {
  if (bytes == null) return 'null';
  if (bytes.isEmpty) return 'empty';
  var str = bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join('')
      .toUpperCase();
  if (str.length > limit * 2) return '${str.substring(0, limit * 2)}...';
  return str;
}

class QuicConnectionParams {
  final ConnectionStatus connection_status;
  final String sni;

  var incoming_packet;

  Uint8List? cert;

  Uint8List? key;

  var key_type;

  var scid;

  Uint8List? dcid;

  int? version;

  int? from_port;

  String? from_ip;
  QuicPacketType? type;
  Uint8List? data;
  Uint8List? stream_id;
  bool? fin;

  // Constructor with default values to prevent initialization errors
  QuicConnectionParams({
    this.connection_status = ConnectionStatus.Initial,
    this.sni = '',
    this.cert,
    this.key,
    this.from_ip,
    this.from_port,
    this.dcid,
    this.scid,
    this.version,
    this.incoming_packet,
    this.type,
    this.data,
    this.stream_id,
    this.fin,
  });

  // Optional: Factory to create from a QuicConnection object
  factory QuicConnectionParams.fromConnection(QuicConnection conn) {
    return QuicConnectionParams(
      connection_status: conn.connection_status,
      sni: conn.sni ?? '',
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('QuicConnectionParams {');
    buffer.writeln('  status: $connection_status');
    buffer.writeln('  sni:    $sni');

    if (from_ip != null || from_port != null) {
      buffer.writeln('  remote: $from_ip:$from_port');
    }

    if (version != null) {
      buffer.writeln('  ver:    0x${version!.toRadixString(16)}');
    }

    if (dcid != null) buffer.writeln('  dcid:   ${_hex(dcid)}');
    if (scid != null) buffer.writeln('  scid:   ${_hex(scid)}');

    // Summarize complex objects rather than printing raw bytes
    if (cert != null) {
      buffer.writeln('  cert:   [Uint8List: ${cert!.length} bytes]');
    }

    if (key != null) {
      buffer.writeln('  key:    [${key_type ?? "private"} key present]');
    }

    if (incoming_packet != null) {
      // Assuming incoming_packet is a Map or has a type field
      var type = (incoming_packet is Map) ? incoming_packet['type'] : 'present';
      buffer.writeln('  packet: [Type: $type]');
    }

    buffer.write('}');
    return buffer.toString();
  }
}

/// Main Connection State and Logic
// class QuicConnection {
//   final String id;

//   // --- Status & Network ---
//   int connection_status = 0; // 0: Connecting, 1: Connected, 2: Disconnected
//   String? sni;
//   dynamic from_ip;
//   int from_port = 0;
//   int version = 1;
//   Uint8List? original_dcid;
//   List<Uint8List> their_cids = [];

//   // --- TLS / Secrets ---
//   int tls_cipher_selected = 0;
//   List<int> tls_signature_algorithms = [];
//   List<Uint8List> tls_transcript = [];

//   // Handshake Secrets
//   Uint8List? tls_handshake_secret;
//   Uint8List? tls_server_handshake_traffic_secret;
//   Uint8List? tls_client_handshake_traffic_secret;

//   // Application Secrets
//   Uint8List? tls_client_app_traffic_secret;
//   Uint8List? tls_server_app_traffic_secret;

//   // --- Keys & IVs (Read/Write) ---
//   Uint8List? init_read_key;
//   Uint8List? init_read_iv;
//   Uint8List? init_read_hp;

//   Uint8List? handshake_read_key;
//   Uint8List? handshake_read_iv;
//   Uint8List? handshake_read_hp;

//   Uint8List? app_read_key;
//   Uint8List? app_read_iv;
//   Uint8List? app_read_hp;

//   // --- Packet Number Tracking ---
//   int receiving_init_pn_largest = -1;
//   int receiving_handshake_pn_largest = -1;
//   int receiving_app_pn_largest = -1;

//   List<int> receiving_init_pn_ranges = [];
//   List<int> receiving_handshake_pn_ranges = [];
//   List<int> receiving_app_pn_ranges = [];

//   List<int> sending_init_pn_acked_ranges = [];
//   List<int> sending_handshake_pn_acked_ranges = [];

//   // History format: [[pn, time, length], ...]
//   List<List<dynamic>> receiving_app_pn_history = [];
//   List<int> receiving_app_pn_pending_ack = [];

//   // --- CRYPTO Frame Reassembly ---
//   Map<int, Uint8List> receiving_init_chunks = {};
//   Map<int, Uint8List> receiving_handshake_chunks = {};
//   int receiving_init_from_offset = 0;
//   int receiving_handshake_from_offset = 0;

//   List<int> receiving_init_ranges = [];
//   List<int> receiving_handshake_ranges = [];

//   // --- Streams & Application Layers ---
//   // Key: streamId, Value: Map of stream state
//   Map<int, dynamic> receiving_streams = {};
//   Map<int, dynamic> h3_wt_sessions = {};

//   // HTTP/3 Specifics
//   int? controlStreamId;
//   int? qpackEncoderStreamId;
//   int? qpackDecoderStreamId;
//   int qpackTableCapacity = 0;
//   int qpackMaxTableCapacity = 0;
//   List<List<String>> qpackDynamicTable = [];

//   Timer? receiving_streams_next_check_timer;

//   String? fromIp;
//   int? fromPort;

//   // TLS / Secrets
//   Uint8List? handshakeSecret;
//   List<Uint8List> tlsTranscript = [];

//   // Streams
//   final Map<int, QuicStream> receivingStreams = {};
//   final Map<int, H3RequestStream> h3Requests = {};

//   // H3 Identifiers

//   // QPACK Dynamic Table
//   // --- Status & Network ---

//   // --- TLS / Secrets ---

//   // --- Keys & IVs (Read) ---

//   // --- Keys & IVs (Write) - ADDED ---
//   Uint8List? init_write_key;
//   Uint8List? init_write_iv;
//   Uint8List? init_write_hp;
//   Uint8List? handshake_write_key;
//   Uint8List? handshake_write_iv;
//   Uint8List? handshake_write_hp;
//   Uint8List? app_write_key;
//   Uint8List? app_write_iv;
//   Uint8List? app_write_hp;

//   // --- Packet Number Tracking ---
//   // --- Sending Packet Number Counters - ADDED ---
//   int sending_init_pn_next = 0;
//   int sending_handshake_pn_next = 0;
//   int sending_app_pn_base = 0;

//   // --- Offsets for Sending - ADDED ---
//   int sending_init_offset_next = 0;
//   int sending_handshake_offset_next = 0;
//   Map<int, dynamic> sending_streams = {};

//   bool? tls_finished_ok;

//   var tls_alpn_selected;

//   var remote_max_udp_payload_size;

//   var remote_ack_delay_exponent;

//   var h3_remote_qpack_dynamic_table;

//   var h3_remote_qpack_table_capacity;

//   var h3_remote_qpack_table_base_index;

//   var sending_app_pn_in_flight;

//   var sending_app_pn_history;

//   var h3_remote_control_stream_id;

//   var h3_remote_qpack_encoder_stream_id;

//   var h3_remote_qpack_decoder_stream_id;

//   int? h3_remote_control_from_offset;

//   var h3_remote_qpack_max_table_capacity;

//   var h3_remote_max_header_size;

//   var h3_remote_datagram_support;

//   int? h3_remote_qpack_encoder_from_offset;

//   var h3_http_request_streams;

//   var rtt_history;

//   // ... (rest of your existing properties: history, reassembly, H3, etc.)

//   QuicConnection(this.id);

//   /// The heart of the packet processing
//   void handlePacket(Map<String, dynamic> packet) {
//     if (packet['type'] == 'initial') {
//       _processInitial(packet);
//     } else if (packet['type'] == 'handshake') {
//       _processHandshake(packet);
//     } else if (packet['type'] == '1rtt') {
//       _processAppData(packet);
//     }
//   }

//   void _processInitial(Map<String, dynamic> packet) {
//     // 1. Decrypt (using your existing decrypt_quic_packet)
//     // 2. Parse Frames
//     // 3. If CRYPTO frame: add to tlsTranscript, handle ClientHello
//   }

//   void _processHandshake(Map<String, dynamic> packet) {
//     // Process Handshake packets and move to status 1 (Connected)
//   }

//   void _processAppData(Map<String, dynamic> packet) {
//     // Here we parse QUIC frames like STREAM or DATAGRAM
//     var frames = packet['frames'] as List<dynamic>;
//     for (var frame in frames) {
//       if (frame['type'] == 'stream') {
//         _onStreamFrame(frame);
//       } else if (frame['type'] == 'datagram') {
//         _onDatagramFrame(frame);
//       }
//     }
//   }

//   void _onStreamFrame(Map<String, dynamic> frame) {
//     int streamId = frame['stream_id'];
//     var stream = receivingStreams.putIfAbsent(
//       streamId,
//       () => QuicStream(streamId),
//     );

//     stream.chunks[frame['offset']] = frame['data'];
//     stream.needCheck = true;

//     _processH3Logic();
//   }

//   void _processH3Logic() {
//     for (var streamId in receivingStreams.keys) {
//       var stream = receivingStreams[streamId]!;
//       if (!stream.needCheck) continue;

//       // Identify Unidirectional Streams (Control, QPACK, etc.)
//       if (_isUnidirectional(streamId) && stream.type == null) {
//         _identifyStreamType(stream);
//       }

//       // Dispatch based on type
//       if (streamId == controlStreamId) {
//         _handleControlStream(stream);
//       } else if (streamId == qpackEncoderStreamId) {
//         _handleQpackEncoder(stream);
//       } else if (!_isUnidirectional(streamId)) {
//         _handleHttpRequest(stream);
//       }

//       stream.needCheck = false;
//     }
//   }

//   bool _isUnidirectional(int id) => (id % 4 == 2) || (id % 4 == 3);

//   void _identifyStreamType(QuicStream stream) {
//     if (stream.chunks.containsKey(0)) {
//       int type = stream.chunks[0]![0];
//       stream.type = type;
//       if (type == 0x00) controlStreamId = stream.id;
//       if (type == 0x02) qpackEncoderStreamId = stream.id;
//       if (type == 0x03) qpackDecoderStreamId = stream.id;
//     }
//   }

//   void _handleControlStream(QuicStream stream) {
//     // Use your extractH3FramesFromChunks logic here
//     // If Frame Type 4: update qpackMaxTableCapacity
//   }

//   void _handleQpackEncoder(QuicStream stream) {
//     // Process QPACK instructions and update qpackDynamicTable
//   }

//   void _handleHttpRequest(QuicStream stream) {
//     var reqState = h3Requests.putIfAbsent(stream.id, () => H3RequestStream());
//     // Parse H3 Frames -> QPACK -> Dispatch to your Server Handler
//   }

//   void _onDatagramFrame(Map<String, dynamic> frame) {
//     // WebTransport Datagram logic
//   }

//   @override
//   String toString() {
//     final statusMap = {0: 'Connecting', 1: 'Connected', 2: 'Disconnected'};
//     final statusStr = statusMap[connection_status] ?? 'Unknown';

//     final buffer = StringBuffer();
//     buffer.writeln('QuicConnection(id: $id) [${statusStr}]');
//     buffer.writeln('--------------------------------------------');

//     // Network Info
//     buffer.writeln('  Remote: $from_ip:$from_port');
//     buffer.writeln('  SNI:    ${sni ?? "N/A"}');
//     buffer.writeln('  Ver:    0x${version.toRadixString(16)}');

//     // Connection IDs
//     buffer.writeln('  DCID:   ${_hex(original_dcid, limit: 8)}');
//     buffer.writeln('  CIDs:   ${their_cids.length} stored');

//     // Secrets & TLS
//     buffer.writeln(
//       '  TLS:    Cipher(0x${tls_cipher_selected.toRadixString(16)}) '
//       'Transcript(${tls_transcript.length} msgs)',
//     );

//     // Logic for which keys are available
//     String keyInfo = [
//       if (init_read_key != null) 'Initial',
//       if (handshake_read_key != null) 'Handshake',
//       if (app_read_key != null) '1-RTT',
//     ].join(', ');
//     buffer.writeln('  Keys:   [${keyInfo.isEmpty ? "None" : keyInfo}]');

//     // Packet Numbering
//     buffer.writeln(
//       '  PN Max: Init($receiving_init_pn_largest), '
//       'Hnd($receiving_handshake_pn_largest), '
//       'App($receiving_app_pn_largest)',
//     );

//     // Streams & H3
//     buffer.writeln('  Streams: Active(${receiving_streams.length})');
//     if (controlStreamId != null) {
//       buffer.writeln(
//         '  H3 IDs:  Control($controlStreamId), '
//         'Encoder($qpackEncoderStreamId), '
//         'Decoder($qpackDecoderStreamId)',
//       );
//     }

//     if (h3Requests.isNotEmpty) {
//       buffer.writeln('  H3 Reqs: ${h3Requests.keys.toList()}');
//     }

//     buffer.writeln('QuicConnection(id: $id) [$statusStr]');
//     buffer.writeln('  Remote: $from_ip:$from_port');
//     buffer.writeln('  DCID:   ${_hex(original_dcid, limit: 8)}');
//     buffer.writeln(
//       '  PN Sent: Init($sending_init_pn_next), Hnd($sending_handshake_pn_next), App($sending_app_pn_base)',
//     );
//     return buffer.toString();

//     return buffer.toString();
//   }
// }

enum ConnectionStatus {
  Connecting(0),
  Connected(1),
  Disconnected(2),
  Closing(3),
  Initial(4);

  const ConnectionStatus(this.value);
  final int value;
}

class StreamData {
  late (int, Uint8List) chunks;
  late int from_offset;
  Map<int, int>? in_flight_ranges;

  List<int>? acked_ranges;

  int? total_size = 0;

  Uint8List? pending_data;

  int? send_offset_next;

  int? write_offset_next;

  int? pending_offset_start;
  int? offset_next;

  late List<int> receiving_ranges;

  late Map<int, dynamic> receiving_chunks;

  var need_check;

  StreamData({
    this.pending_data,
    this.write_offset_next,
    this.pending_offset_start,
    this.send_offset_next,
    this.total_size,
    this.in_flight_ranges,
    this.acked_ranges,
    this.offset_next,
  });
}

class QuicConnection {
  late ConnectionStatus connection_status = ConnectionStatus.Initial;
  String? from_ip;
  int? from_port;
  int version = 1;

  List<Uint8List> my_cids = [];
  List<Uint8List> their_cids = [];
  Uint8List? original_dcid;

  // TLS State
  String? sni;
  int? tls_cipher_selected;
  String? tls_alpn_selected;
  List<int> tls_signature_algorithms = [];
  Uint8List? tls_handshake_secret;
  Uint8List? tls_shared_secret;
  Uint8List? tls_early_secret;
  List<Uint8List> tls_transcript = [];
  late int tls_handshake_step;
  bool tls_finished_ok = false;
  Uint8List? tls_server_public_key;
  Uint8List? tls_server_private_key;

  // Traffic Secrets
  Uint8List? tls_client_handshake_traffic_secret;
  Uint8List? tls_server_handshake_traffic_secret;
  Uint8List? tls_client_app_traffic_secret;
  Uint8List? tls_server_app_traffic_secret;

  // Keys & IVs (Initial, Handshake, App)
  Uint8List? init_read_key;
  Uint8List? init_read_iv;
  Uint8List? init_read_hp;
  Uint8List? init_write_key;
  Uint8List? init_write_iv;
  Uint8List? init_write_hp;

  Uint8List? handshake_read_key;
  Uint8List? handshake_read_iv;
  Uint8List? handshake_read_hp;
  Uint8List? handshake_write_key;
  Uint8List? handshake_write_iv;
  Uint8List? handshake_write_hp;

  Uint8List? app_read_key;
  Uint8List? app_read_iv;
  Uint8List? app_read_hp;
  Uint8List? app_write_key;
  Uint8List? app_write_iv;
  Uint8List? app_write_hp;
  bool read_key_phase = false;

  // Transmission State
  late int sending_init_pn_next;
  List<int> sending_init_chunks = [];
  late int sending_init_offset_next;
  List<List<int>> sending_init_pn_acked_ranges = [];
  Map<int, int> sending_app_pn_in_flight = {};

  Map<int, StreamData> sending_streams =
      {}; // sending_streams: Record<number, any>;
  late int sending_stream_id_next;

  // Congestion & RTT
  late int max_sending_packet_size;
  Set<int> sending_app_pn_in_fligh = {};
  List<List<int>> rtt_history = [];

  // Receiving State
  Map<int, Uint8List> receiving_init_chunks = {};
  Map<int, StreamData> receiving_streams = {};

  // H3 & QPACK
  int? h3_remote_control_stream_id;
  dynamic h3_remote_qpack_dynamic_table;
  late int h3_remote_qpack_table_capacity;
  Map<int, dynamic> h3_wt_sessions = {};

  late int sending_app_pn_base;

  List<List<int>> sending_app_pn_history = [];

  Map<int, List<int>> receiving_app_pn_history = {};

  String id;

  late int h3_remote_qpack_encoder_stream_id;

  late int h3_remote_qpack_decoder_stream_id;

  late int h3_remote_control_from_offset;

  var h3_remote_qpack_max_table_capacity;

  var h3_remote_max_header_size;

  var h3_remote_datagram_support;

  var h3_remote_qpack_encoder_from_offset;

  var h3_remote_qpack_table_base_index;

  var h3_http_request_streams;

  var sending_quic_packet_now;

  Timer? next_send_quic_packet_timer;

  var max_sending_total_bytes_per_sec;

  var max_sending_packets_per_sec;

  var max_sending_bytes_in_flight;

  num? min_sending_packet_size;

  num? max_sending_packets_in_flight;

  late List<int> receiving_app_pn_pending_ack = [];

  int? remote_ack_delay_exponent;

  late int receiving_init_from_offset = 0;

  late int receiving_handshake_from_offset = 0;

  late var receiving_handshake_chunks;

  late List<int> receiving_handshake_pn_ranges;

  late List<int> receiving_init_pn_ranges = [];

  late var receiving_handshake_ranges;

  List<int> receiving_init_ranges = [];

  late var receiving_init_pn_largest = 0;

  late var receiving_handshake_pn_largest = 0;

  late List<int> receiving_app_pn_ranges;

  late var receiving_app_pn_largest;

  late var remote_max_udp_payload_size;

  late var sending_handshake_pn_next;

  late var qpackDynamicTable;

  late var qpackTableCapacity;

  late var qpackMaxTableCapacity;

  QuicConnection(this.id);
}

class QuicServer {
  Map<String, QuicConnection> connections = {};
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

extension QuicKeyManager on QuicConnection {
  /// Ensures keys are available for the given type and returns them
  ({Uint8List key, Uint8List iv, Uint8List hp}) getWriteKeys(
    QuicPacketType type,
  ) {
    switch (type) {
      case QuicPacketType.initial:
        if (init_read_key == null) {
          // Logic to derive if missing
          var d = quic_derive_init_secrets(original_dcid!, version, 'write');
          init_read_key = d.key;
          init_read_iv = d.iv;
          init_read_hp = d.hp;
        }
        return (key: init_read_key!, iv: init_read_iv!, hp: init_read_hp!);

      case QuicPacketType.handshake:
        if (handshake_read_key == null) {
          var d = quic_derive_from_tls_secrets(
            tls_server_handshake_traffic_secret!,
            'sha256',
          );
          handshake_read_key = d.key;
          handshake_read_iv = d.iv;
          handshake_read_hp = d.hp;
        }
        return (
          key: handshake_read_key!,
          iv: handshake_read_iv!,
          hp: handshake_read_hp!,
        );

      case QuicPacketType.oneRtt:
        if (app_read_key == null) {
          var d = quic_derive_from_tls_secrets(
            tls_server_app_traffic_secret!,
            'sha256',
          );
          app_read_key = d.key;
          app_read_iv = d.iv;
          app_read_hp = d.hp;
        }
        return (key: app_read_key!, iv: app_read_iv!, hp: app_read_hp!);
      default:
        throw Exception("Unsupported packet type for encryption");
    }
  }
}
