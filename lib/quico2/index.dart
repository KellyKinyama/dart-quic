import 'dart:math';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:dart_quic/quico2/handshake/finished.dart';
import 'package:hex/hex.dart';

import 'ecdsa.dart';

import 'handshake/extensions/extensions.dart';
import 'handshake/handshake.dart';
import 'utils.dart';
import 'crypto.dart';
import 'dart:convert';
import 'dart:async';

import 'flat_ranges.dart';
import 'h3.dart'; // For Timer

import 'dart:io';

import 'quic_connection.dart';
import 'quic_frame.dart';
import 'quic_packet.dart';

var new_quic_connection = (
  connection_status:
      4, //0 - connecting... | 1 - connected | 2 - disconnected | ...

  from_ip: null,
  from_port: null,

  version: 1,

  my_cids: [], // SCIDים שאתה נתת (כנראה אחד ראשוני ועוד future)
  their_cids: [], // DCIDים שהצד השני השתמש בהם (כלומר שלך כשרת)
  original_dcid: null, // ל־Initial ול־Retry
  //tls stuff...
  sni: null,

  tls_cipher_selected: null,
  tls_alpn_selected: null,

  tls_signature_algorithms: [],

  tls_handshake_secret: null,
  tls_shared_secret: null,
  tls_early_secret: null,

  tls_transcript: [],
  tls_handshake_step: 0,
  tls_finished_ok: false,

  tls_server_public_key: null,
  tls_server_private_key: null,

  tls_client_handshake_traffic_secret: null,
  tls_server_handshake_traffic_secret: null,

  tls_client_app_traffic_secret: null,
  tls_server_app_traffic_secret: null,

  //....
  init_read_key: null,
  init_read_iv: null,
  init_read_hp: null,

  init_write_key: null,
  init_write_iv: null,
  init_write_hp: null,

  handshake_read_key: null,
  handshake_read_iv: null,
  handshake_read_hp: null,

  handshake_write_key: null,
  handshake_write_iv: null,
  handshake_write_hp: null,

  app_prev_read_key: null,
  app_prev_read_iv: null,
  app_prev_read_hp: null,

  app_read_key: null,
  app_read_iv: null,
  app_read_hp: null,

  read_key_phase: false,

  app_write_key: null,
  app_write_iv: null,
  app_write_hp: null,

  //sending...
  sending_init_pn_next: 1,
  sending_init_chunks: [],
  sending_init_offset_next: 0,
  sending_init_pn_acked_ranges: [],

  sending_handshake_pn_next: 1,
  sending_handshake_chunks: [],
  sending_handshake_offset_next: 0,
  sending_handshake_pn_acked_ranges: [],

  sending_streams: {},
  sending_stream_id_next: 0,

  max_sending_packets_per_sec: 1000,
  max_sending_total_bytes_per_sec: 150000,
  max_sending_packet_size: 1200,
  min_sending_packet_size: 35,

  max_sending_packets_in_flight: 20,
  max_sending_bytes_in_flight: 150000,

  sending_app_pn_base: 1,
  sending_app_pn_history: [],
  rtt_history: [],
  sending_app_pn_in_flight: new Set(),

  next_send_quic_packet_timer: null,
  sending_quic_packet_now: false,

  //received...
  receiving_init_pn_largest: -1,
  receiving_init_pn_ranges: [],
  receiving_init_chunks: {},
  receiving_init_from_offset: 0,
  receiving_init_ranges: [], //מערך שטוח של מ עד

  receiving_handshake_pn_largest: -1,
  receiving_handshake_pn_ranges: [],
  receiving_handshake_chunks: {},
  receiving_handshake_from_offset: 0,
  receiving_handshake_ranges: [], //מערך שטוח של מ עד

  receiving_app_pn_largest: -1,
  receiving_app_pn_ranges: [],
  receiving_app_pn_history: [],

  receiving_app_pn_pending_ack: [],

  receiving_streams: {}, // stream_id → stream object
  receiving_streams_next_check_timer: null,

  remote_ack_delay_exponent: 3,
  remote_max_udp_payload_size: 1000,

  h3_remote_control_stream_id: null,
  h3_remote_control_from_offset: 1,

  h3_remote_qpack_encoder_stream_id: null,
  h3_remote_qpack_encoder_from_offset: 1,

  h3_remote_qpack_decoder_stream_id: null,
  h3_remote_qpack_decoder_from_offset: 1,

  h3_http_request_streams: {},

  h3_remote_max_header_size: 0, //מתקבל ב settings - אחרי פיענוח
  h3_remote_qpack_max_table_capacity:
      0, //מתקבל ב settings - גודל הטבלה המקסימלי
  h3_remote_datagram_support: null,

  h3_remote_qpack_table_base_index: 0,
  h3_remote_qpack_table_capacity: 0,
  h3_remote_qpack_dynamic_table: [],

  h3_wt_sessions: {},

  // 🗺️ congestion control / flow control (אפשר להוסיף בהמשך)
);

void evict_qpack_remote_dynamic_table_if_needed(
  QuicServer server,
  QuicConnection quic_connection_id,
) {
  if (quic_connection_id != null) {
    var connection = quic_connection_id;
    var entries = connection
        .qpackDynamicTable; // Using the field from your class definition
    var capacity = connection.qpackMaxTableCapacity;

    // 1. Calculate current size
    var total_size = 0;
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i][0];
      var value = entries[i][1];
      // RFC 9204: Each entry has an overhead of 32 bytes
      total_size += (name.length) + (value.length) + 32 as int;
    }

    // 2. Debug: Initial state
    if (total_size > capacity) {
      print("--- QPACK Eviction Started [ID: ${connection.id}] ---");
      print("Current Size: $total_size bytes | Max Capacity: $capacity bytes");
      print("Entry count before: ${entries.length}");
    }

    var evicted_count = 0;

    // 3. Evict old entries
    // Note: In QPACK, the oldest entries are at the beginning of the list (index 0)
    // but the logic depends on how you push them. Assuming FIFO:
    while (total_size > capacity && entries.isNotEmpty) {
      // Dart uses removeAt(0) for oldest or removeLast() for newest.
      // Standard QPACK evicts the oldest entry.
      var removed = entries.removeAt(0);
      var removed_size = removed[0].length + removed[1].length + 32;
      total_size -= removed_size as int;
      evicted_count++;

      print("  > Evicting: ${removed[0]}=${removed[1]} ($removed_size bytes)");
    }

    // 4. Debug: Final state
    if (evicted_count > 0) {
      print("Eviction complete. Removed $evicted_count entries.");
      print("Final Size: $total_size bytes");
      print("--- QPACK Eviction Finished ---");
    }
  }
}

bool insert_into_qpack_remote_encoder_dynamic_table(
  QuicServer server,
  QuicConnection quic_connection_id,
  String name,
  String value,
) {
  if (quic_connection_id != null) {
    var entry_size = name.length + value.length + 32;
    var capacity = quic_connection_id.qpackMaxTableCapacity;

    if (entry_size > capacity) {
      print(
        "QPACK [${quic_connection_id.id}]: Insertion FAILED. Entry size $entry_size > capacity $capacity",
      );
      return false;
    }

    // unshift in JS is insert(0, ...) in Dart
    quic_connection_id.qpackDynamicTable.insert(0, [name, value]);

    // QPACK tracking: Base Index is critical for identifying headers
    quic_connection_id.qpackTableCapacity++;

    print(
      "QPACK [${quic_connection_id.id}]: Inserted '$name'. "
      "New Base Index: ${quic_connection_id.qpackTableCapacity} | Size: $entry_size bytes",
    );

    evict_qpack_remote_dynamic_table_if_needed(server, quic_connection_id);

    return true;
  }
  return false;
}

dynamic create_wt_session_object(
  QuicServer server,
  QuicConnection quic_connection_id,
  int stream_id,
  Map<String, String> headers,
) {
  print(
    "WebTransport [${quic_connection_id.id}]: Creating session on Stream ID $stream_id",
  );

  var wt;
  wt = (
    id: stream_id,
    headers: headers,

    send: (Uint8List data) {
      print(
        "WebTransport [${quic_connection_id.id}]: Sending datagram (${data.length} bytes) on Session $stream_id",
      );

      send_quic_frames_packet(
        server,
        quic_connection_id, // Using String ID as per previous function sig
        QuicPacketType.oneRtt,
        [
          DatagramFrame(
            data: concatUint8Arrays([writeVarInt(stream_id), data]),
          ),
        ],
      );
    },

    close: () {
      print(
        "WebTransport [${quic_connection_id.id}]: Closing Session $stream_id",
      );
      wt.internal.isOpen = false;
      // Optional: Send H3_DATAGRAM_CAPS_FORBIDDEN or similar closure
    },

    onmessage: null,
    onclose: null,
    onerror: null,
    onstream: null,

    internal: (
      incoming_uni_streams: {},
      outgoing_uni_streams: {},
      control_stream_id: stream_id,
      isOpen: true,
    ),
  );

  return wt;
}

// void send_quic_frames_packet(
//   QuicServer server,
//   String quic_connection_id,
//   QuicPacketType type,
//   frames,
// ) {
//   if (server.connections[quic_connection_id] != null) {
//     var write_key = null;
//     var write_iv = null;
//     var write_hp = null;

//     var packet_number = 1;

//     if (type == QuicPacketType.initial) {
//       if (server.connections[quic_connection_id].init_write_key != null &&
//           server.connections[quic_connection_id].init_write_iv != null &&
//           server.connections[quic_connection_id].init_write_hp != null) {
//         write_key = server.connections[quic_connection_id].init_write_key;
//         write_iv = server.connections[quic_connection_id].init_write_iv;
//         write_hp = server.connections[quic_connection_id].init_write_hp;
//       } else {
//         var d = quic_derive_init_secrets(
//           server.connections[quic_connection_id].original_dcid,
//           server.connections[quic_connection_id].version,
//           'write',
//         );

//         write_key = d.key;
//         write_iv = d.iv;
//         write_hp = d.hp;

//         server.connections[quic_connection_id].init_write_key = d.key;
//         server.connections[quic_connection_id].init_write_iv = d.iv;
//         server.connections[quic_connection_id].init_write_hp = d.hp;
//       }

//       packet_number =
//           server.connections[quic_connection_id].sending_init_pn_next + 0;
//     } else if (type == 'handshake') {
//       if (server.connections[quic_connection_id].handshake_write_key != null &&
//           server.connections[quic_connection_id].handshake_write_iv != null &&
//           server.connections[quic_connection_id].handshake_write_hp != null) {
//         write_key = server.connections[quic_connection_id].handshake_write_key;
//         write_iv = server.connections[quic_connection_id].handshake_write_iv;
//         write_hp = server.connections[quic_connection_id].handshake_write_hp;
//       } else if (server
//               .connections[quic_connection_id]
//               .tls_server_handshake_traffic_secret !=
//           null) {
//         var d = quic_derive_from_tls_secrets(
//           server
//               .connections[quic_connection_id]
//               .tls_server_handshake_traffic_secret,
//           'sha256',
//         );

//         write_key = d.key;
//         write_iv = d.iv;
//         write_hp = d.hp;

//         server.connections[quic_connection_id].handshake_write_key = d.key;
//         server.connections[quic_connection_id].handshake_write_iv = d.iv;
//         server.connections[quic_connection_id].handshake_write_hp = d.hp;
//       }

//       packet_number =
//           server.connections[quic_connection_id].sending_handshake_pn_next + 0;
//     } else if (type == '1rtt') {
//       if (server.connections[quic_connection_id].app_write_key != null &&
//           server.connections[quic_connection_id].app_write_iv != null &&
//           server.connections[quic_connection_id].app_write_hp != null) {
//         write_key = server.connections[quic_connection_id].app_write_key;
//         write_iv = server.connections[quic_connection_id].app_write_iv;
//         write_hp = server.connections[quic_connection_id].app_write_hp;
//       } else if (server
//               .connections[quic_connection_id]
//               .tls_server_app_traffic_secret !=
//           null) {
//         var d = quic_derive_from_tls_secrets(
//           server.connections[quic_connection_id].tls_server_app_traffic_secret,
//           'sha256',
//         );

//         write_key = d.key;
//         write_iv = d.iv;
//         write_hp = d.hp;

//         server.connections[quic_connection_id].app_write_key = d.key;
//         server.connections[quic_connection_id].app_write_iv = d.iv;
//         server.connections[quic_connection_id].app_write_hp = d.hp;
//       }

//       packet_number =
//           server.connections[quic_connection_id].sending_app_pn_base + 0;
//     }

//     //console.log('sending packet_number==');
//     //console.log(packet_number);

//     var dcid = Uint8List(0);

//     if (server.connections[quic_connection_id].their_cids.length > 0) {
//       dcid = server.connections[quic_connection_id].their_cids[0];
//     }

//     var encodedFrames = encode_quic_frames(frames);
//     var encrypted_quic_packet = encrypt_quic_packet(
//       type,
//       encodedFrames,
//       write_key,
//       write_iv,
//       write_hp,
//       packet_number,
//       dcid,
//       server.connections[quic_connection_id].original_dcid,
//       Uint8List(0),
//     );

//     if (type == 'initial') {
//       server.connections[quic_connection_id].sending_init_pn_next++;
//     } else if (type == 'handshake') {
//       server.connections[quic_connection_id].sending_handshake_pn_next++;
//     } else if (type == '1rtt') {
//       var now = DateTime.now();
//       server.connections[quic_connection_id].sending_app_pn_history.push([
//         now,
//         encodedFrames.length,
//       ]);
//       server.connections[quic_connection_id].sending_app_pn_base++;
//     }

//     send_udp_packet(
//       server,
//       encrypted_quic_packet,
//       server.connections[quic_connection_id].from_port,
//       server.connections[quic_connection_id].from_ip,
//       () {},
//     );
//   }
// }

void send_quic_frames_packet(
  QuicServer server,
  QuicConnection conn,
  QuicPacketType type,
  List<QuicFrame> frames,
) {
  // --- DEBUG: Frame Summary ---
  final frameSummary = frames
      .map((f) => f is Map ? f.type : f.runtimeType)
      .join(', ');
  print('┌── SENDING QUIC PACKET [${conn.id}]');
  print('│ Type: ${type.name} | Frames: [$frameSummary]');

  // 1. Get Security Context
  final secrets = conn.getWriteKeys(type);

  // 2. Determine Packet Number and Destination CID
  int packetNumber;
  if (type == QuicPacketType.initial) {
    packetNumber = conn.receiving_init_pn_largest + 1;
  } else if (type == QuicPacketType.handshake) {
    packetNumber = conn.receiving_handshake_pn_largest + 1;
  } else {
    packetNumber = conn.receiving_app_pn_largest + 1;
  }

  // Use the first available CID from the peer, or empty if none (for initial)
  Uint8List dcid = conn.their_cids.isNotEmpty
      ? conn.their_cids.first
      : Uint8List(0);

  // var values = products.map((product) => product['price'] as double);
  final Map<String, QuicFrame> mapped = {};

  for (final frame in frames) {
    mapped[frame.type] = frame;
  }
  // 3. Encode and Encrypt
  var encodedFrames = encode_quic_frames(mapped);

  // --- DEBUG: Payload Info ---
  print(
    '│ PN: $packetNumber | DCID: ${dcid.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}',
  );
  print('│ Payload size: ${encodedFrames.length} bytes (before encryption)');

  var encryptedPacket = encrypt_quic_packet(
    type,
    encodedFrames,
    secrets.key,
    secrets.iv,
    secrets.hp,
    packetNumber,
    dcid,
    conn.original_dcid!,
    Uint8List(0), // Token
  );

  // 4. Update Connection Stats / History
  _updatePacketHistory(conn, type, packetNumber, encodedFrames.length);

  // 5. Physical Send
  send_udp_packet(server, encryptedPacket, conn.from_port!, conn.from_ip!, () {
    // --- DEBUG: Post-send ---
    print('└─> UDP Datagram dispatched to ${conn.from_ip}:${conn.from_port}');
  });
}

void _updatePacketHistory(
  QuicConnection conn,
  QuicPacketType type,
  int pn,
  int len,
) {
  // --- DEBUG: Tracking ---
  // print('   [History] Recording PN $pn in space ${type.name}');

  if (type == QuicPacketType.initial) {
    // increment your counters here
  } else if (type == QuicPacketType.oneRtt) {
    conn.receiving_app_pn_history[pn]!.add(type.value);
  }
}

void send_udp_packet(
  QuicServer server,
  Uint8List data,
  int port,
  String ip,
  callback,
) {
  // throw UnimplementedError("intended");
  if (ip.indexOf(':') >= 0) {
    server._udp6!.send(data, InternetAddress(ip), port);
  } else {
    if (server._udp4 == null) {
      print(
        "│   [TEST] Intercepted outgoing UDP packet (${data.length} bytes)",
      );
      return; // Don't crash in tests!
    }
    print("Sending to $ip:$port (${data.length} bytes)");
    server._udp4!.send(data, InternetAddress(ip), port);
  }
}

void send_quic_packet(
  QuicServer server,
  QuicConnection quic_connection_id,
  QuicPacketType type,
  encoded_frames,
  callback,
) {
  if (server.connections[quic_connection_id] != null) {
    var write_key = null;
    var write_iv = null;
    var write_hp = null;

    var packet_number = 1;

    if (type == QuicPacketType.initial) {
      if (quic_connection_id.init_write_key != null &&
          quic_connection_id.init_write_iv != null &&
          quic_connection_id.init_write_hp != null) {
        write_key = quic_connection_id.init_write_key;
        write_iv = quic_connection_id.init_write_iv;
        write_hp = quic_connection_id.init_write_hp;
      } else {
        var d = quic_derive_init_secrets(
          quic_connection_id.original_dcid!,
          quic_connection_id.version,
          'write',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        quic_connection_id.init_write_key = d.key;
        quic_connection_id.init_write_iv = d.iv;
        quic_connection_id.init_write_hp = d.hp;
      }

      packet_number = quic_connection_id.sending_init_pn_next + 0;
    } else if (type == QuicPacketType.handshake) {
      if (quic_connection_id.handshake_write_key != null &&
          quic_connection_id.handshake_write_iv != null &&
          quic_connection_id.handshake_write_hp != null) {
        write_key = quic_connection_id.handshake_write_key;
        write_iv = quic_connection_id.handshake_write_iv;
        write_hp = quic_connection_id.handshake_write_hp;
      } else if (quic_connection_id.tls_server_handshake_traffic_secret !=
          null) {
        var d = quic_derive_from_tls_secrets(
          quic_connection_id.tls_server_handshake_traffic_secret,
          'sha256',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        quic_connection_id.handshake_write_key = d.key;
        quic_connection_id.handshake_write_iv = d.iv;
        quic_connection_id.handshake_write_hp = d.hp;
      }

      packet_number = quic_connection_id.sending_handshake_pn_next + 0;
    } else if (type == QuicPacketType.oneRtt) {
      if (quic_connection_id.app_write_key != null &&
          quic_connection_id.app_write_iv != null &&
          quic_connection_id.app_write_hp != null) {
        write_key = quic_connection_id.app_write_key;
        write_iv = quic_connection_id.app_write_iv;
        write_hp = quic_connection_id.app_write_hp;
      } else if (quic_connection_id.tls_server_app_traffic_secret != null) {
        var d = quic_derive_from_tls_secrets(
          quic_connection_id.tls_server_app_traffic_secret,
          'sha256',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        quic_connection_id.app_write_key = d.key;
        quic_connection_id.app_write_iv = d.iv;
        quic_connection_id.app_write_hp = d.hp;
      }

      packet_number = quic_connection_id.sending_app_pn_base + 0;
    }

    //console.log('sending packet_number==');
    //console.log(packet_number);

    var dcid = Uint8List(0);

    if (quic_connection_id.their_cids.length > 0) {
      dcid = quic_connection_id.their_cids[0];
    }

    var encrypted_quic_packet = encrypt_quic_packet(
      type,
      encoded_frames,
      write_key,
      write_iv,
      write_hp,
      packet_number,
      dcid,
      quic_connection_id.original_dcid!,
      Uint8List(0),
    );

    send_udp_packet(
      server,
      encrypted_quic_packet,
      quic_connection_id.from_port!,
      quic_connection_id.from_ip!,
      (is_sent) {
        if (callback is Function) {
          callback(is_sent);
        }
      },
    );
  }
}

// void process_quic_tls_message(
//   QuicServer server,
//   QuicConnection quic_connection_id,
//  List<TlsHandshakeMessage> tls_message,
// ) {
//   if (server.connections[quic_connection_id] != null) {
//     var hs = parse_tls_message(tls_message);
//     if (hs.type == 0x01) {
//       var parsed = parse_tls_client_hello(hs.body);

//       quic_connection_id.tls_signature_algorithms = parsed.signature_algorithms;
//       quic_connection_id.tls_transcript = [tls_message];

//       var a = handle_client_hello(parsed);

//       //console.log('handle_client_hello:');
//       //console.log(parsed);

//       var quic_transport_parameters = parse_transport_parameters(
//         parsed.quic_transport_parameters_raw,
//       );
//       //console.log('quic_transport_parameters:');
//       //console.dir(quic_transport_parameters, { depth: null });

//       if (quic_transport_parameters.contains('ack_delay_exponent')) {
//         quic_connection_id.remote_ack_delay_exponent =
//             quic_transport_parameters['ack_delay_exponent'];
//       }

//       if (quic_transport_parameters.contains('max_udp_payload_size')) {
//         quic_connection_id.remote_max_udp_payload_size =
//             quic_transport_parameters['max_udp_payload_size'];
//       }

//       quic_connection_id.tls_cipher_selected = a.selected_cipher;

//       var server_random = Uint8List.fromList(
//         List.generate(32, (index) => Random.secure().nextInt(255)),
//       ); // crypto.randomBytes(32);
//       var server_hello = build_server_hello(
//         server_random,
//         a.server_public_key,
//         parsed.session_id,
//         quic_connection_id.tls_cipher_selected!,
//         a.selected_group,
//       );

//       quic_connection_id.tls_transcript.add(server_hello);

//       set_sending_quic_chunk(
//         server,
//         quic_connection_id,
//         QuicConnectionParams(type: QuicPacketType.initial, data: server_hello),
//       );

//       var cipher_info = get_cipher_info(
//         quic_connection_id.tls_cipher_selected!,
//       );
//       var hash_func = cipher_info.hash;

//       var b = tls_derive_handshake_secrets(
//         a.shared_secret,
//         concatUint8Arrays(quic_connection_id.tls_transcript),
//         // hash_func,
//       );

//       quic_connection_id.tls_handshake_secret = b.handshake_secret;

//       quic_connection_id.tls_client_handshake_traffic_secret =
//           b.client_handshake_traffic_secret;

//       quic_connection_id.tls_server_handshake_traffic_secret =
//           b.server_handshake_traffic_secret;

//       var quic_ext_data = build_quic_ext({
//         'original_destination_connection_id': quic_connection_id.original_dcid,
//         'initial_source_connection_id': quic_connection_id.original_dcid,
//         'max_udp_payload_size': 65527,
//         'max_idle_timeout': 30000,
//         'stateless_reset_token': Uint8List.fromList(List.filled(16, 0xab)),
//         'initial_max_data': 1048576,
//         'initial_max_stream_data_bidi_local': 262144,
//         'initial_max_stream_data_bidi_remote': 262144,
//         'initial_max_stream_data_uni': 131072,
//         'initial_max_streams_bidi': 100,
//         'initial_max_streams_uni': 3,
//         'ack_delay_exponent': 3,
//         'max_ack_delay': 25,
//         'disable_active_migration': true,
//         'active_connection_id_limit': 4,
//         'max_datagram_frame_size': 65527,
//         'web_accepted_origins': [
//           "*", // או הדומיין שלך
//         ],
//       });

//       var supported_alpn = ['h3'];
//       var selected_alpn = null;

//       for (var i in supported_alpn) {
//         if (selected_alpn == null) {
//           for (var i2 in parsed.alpn) {
//             if (parsed.alpn[i2] == supported_alpn.contains(i)) {
//               selected_alpn = parsed.alpn[i2];
//               break;
//             }
//           }
//         }
//       }

//       quic_connection_id.tls_alpn_selected = selected_alpn;

//       var enc_ext = build_encrypted_extensions([
//         (type: 0x10, data: build_alpn_ext(selected_alpn)),
//         (type: 0x39, data: quic_ext_data),
//       ]);

//       quic_connection_id.tls_transcript.add(enc_ext);

//       set_sending_quic_chunk(
//         server,
//         quic_connection_id,
//         QuicConnectionParams(type: QuicPacketType.handshake, data: enc_ext),
//       );

//       set_quic_connection(
//         server,
//         quic_connection_id,
//         QuicConnectionParams(sni: parsed.sni),
//       );
//     } else if (hs.type == 20) {
//       //finished from client here...
//       var cipher_info = get_cipher_info(
//         quic_connection_id.tls_cipher_selected!,
//       );
//       var hash_func = cipher_info.hash;

//       var finished_key = hkdf_expand_label(
//         quic_connection_id.tls_client_handshake_traffic_secret!,
//         'finished',
//         Uint8List(0),
//         hash_func.outputLen,
//         // hash_func,
//       );

//       var expected_client_finished = hmac(
//         cipher_info.str,
//         finished_key,
//         hash_transcript(quic_connection_id.tls_transcript, hash_func),
//       );

//       if (arraybufferEqual(
//             expected_client_finished,
//             Uint8List.fromList(hs.body),
//           ) ==
//           true) {
//         //finished ok!!!!!!

//         //console.log('finished ok!!!!!!!');
//         quic_connection_id.tls_finished_ok = true;
//       }
//     } else {
//       //console.log('tls other:');
//       //console.log(hs);
//     }
//   }
// }

void process_quic_tls_message(
  QuicServer server,
  QuicConnection quic_connection_id,
  TlsHandshakeMessage tls_message,
) {
  if (server.connections[quic_connection_id.id] != null) {
    // var hs = parse_tls_message(tls_message);
    if (tls_message is ClientHello) {
      // var parsed = parse_tls_client_hello(hs.body);
      tls_message = tls_message as ClientHello;

      quic_connection_id.tls_signature_algorithms = tls_message.cipherSuites;
      quic_connection_id.tls_transcript.add(tls_message.toBytes());

      print("handling client hello");
      var a = handle_client_hello(tls_message);

      //console.log('handle_client_hello:');
      //console.log(parsed);

      // var quic_transport_parameters = parse_transport_parameters(
      //   parsed.quic_transport_parameters_raw,
      // );
      //console.log('quic_transport_parameters:');
      //console.dir(quic_transport_parameters, { depth: null });

      final quic_transport_parameters =
          tls_message.extensions.firstWhere(
                (test) => test.runtimeType == TransportParameters,
              )
              as TransportParameters;

      for (final tp in quic_transport_parameters.params) {
        if (tp.id == TransportParameterType.ack_delay_exponent) {
          quic_connection_id.remote_ack_delay_exponent = tp.id_vli;
          // quic_transport_parameters['ack_delay_exponent'];
        }
        if (tp.id == TransportParameterType.max_udp_payload_size) {
          // if (quic_transport_parameters.contains('max_udp_payload_size')) {
          quic_connection_id.remote_max_udp_payload_size = tp.id_vli;
        }
      }

      quic_connection_id.tls_cipher_selected = a.selected_cipher;

      var server_random = Uint8List.fromList(
        List.generate(32, (index) => Random.secure().nextInt(255)),
      ); // crypto.randomBytes(32);
      final server_hello = build_server_hello(
        server_random,
        a.server_public_key!,
        tls_message.legacySessionId,
        quic_connection_id.tls_cipher_selected!,
        a.selected_group!,
      );

      quic_connection_id.tls_transcript.add(server_hello);

      set_sending_quic_chunk(
        server,
        quic_connection_id,
        QuicConnectionParams(type: QuicPacketType.initial, data: server_hello),
      );

      var cipher_info = get_cipher_info(
        quic_connection_id.tls_cipher_selected!,
      );
      // var hash_func = cipher_info.hash;

      var b = tls_derive_handshake_secrets(
        a.shared_secret!,
        concatUint8Arrays(quic_connection_id.tls_transcript),
        // hash_func,
      );

      quic_connection_id.tls_handshake_secret = b.handshake_secret;

      quic_connection_id.tls_client_handshake_traffic_secret =
          b.client_handshake_traffic_secret;

      quic_connection_id.tls_server_handshake_traffic_secret =
          b.server_handshake_traffic_secret;

      var quic_ext_data = build_quic_ext({
        'original_destination_connection_id': quic_connection_id.original_dcid!,
        'initial_source_connection_id': quic_connection_id.original_dcid!,
        'max_udp_payload_size': 65527,
        'max_idle_timeout': 30000,
        'stateless_reset_token': Uint8List.fromList(List.filled(16, 0xab)),
        'initial_max_data': 1048576,
        'initial_max_stream_data_bidi_local': 262144,
        'initial_max_stream_data_bidi_remote': 262144,
        'initial_max_stream_data_uni': 131072,
        'initial_max_streams_bidi': 100,
        'initial_max_streams_uni': 3,
        'ack_delay_exponent': 3,
        'max_ack_delay': 25,
        'disable_active_migration': true,
        'active_connection_id_limit': 4,
        'max_datagram_frame_size': 65527,
        'web_accepted_origins': [
          "*", // או הדומיין שלך
        ],
      });

      var supported_alpn = ['h3'];
      var selected_alpn = 'h3';

      // for (var i in supported_alpn) {
      //   if (selected_alpn == null) {
      //     for (var i2 in parsed.alpn) {
      //       if (parsed.alpn[i2] == supported_alpn.contains(i)) {
      //         selected_alpn = parsed.alpn[i2];
      //         break;
      //       }
      //     }
      //   }
      // }

      quic_connection_id.tls_alpn_selected = selected_alpn;

      var enc_ext = build_encrypted_extensions([
        (type: 0x10, data: build_alpn_ext(selected_alpn)),
        (type: 0x39, data: quic_ext_data),
      ]);

      quic_connection_id.tls_transcript.add(enc_ext);
      print("set_sending_quic_chunk");
      set_sending_quic_chunk(
        server,
        quic_connection_id,
        QuicConnectionParams(type: QuicPacketType.handshake, data: enc_ext),
      );
      print("set_quic_connection");
      set_quic_connection(
        server,
        quic_connection_id,
        QuicConnectionParams(sni: ''),
      );
    } else if (tls_message is Finished) {
      //finished from client here...
      var cipher_info = get_cipher_info(
        quic_connection_id.tls_cipher_selected!,
      );
      // var hash_func = cipher_info.hash;

      var finished_key = hkdf_expand_label(
        quic_connection_id.tls_client_handshake_traffic_secret!,
        'finished',
        Uint8List(0),
        64,
        // hash_func.outputLen,
        // hash_func,
      );

      var expected_client_finished = hmac(
        'HMAC-SHA256',
        // cipher_info.str,
        finished_key,
        hash_transcript(
          concatUint8Arrays(quic_connection_id.tls_transcript),
          //  hash_func
        ),
      );

      if (arraybufferEqual(
            expected_client_finished,
            Uint8List.fromList(tls_message.toBytes()),
          ) ==
          true) {
        //finished ok!!!!!!

        //console.log('finished ok!!!!!!!');
        quic_connection_id.tls_finished_ok = true;
      }
    } else {
      //console.log('tls other:');
      //console.log(hs);
    }
  }
}

extension QuicOffsetExtension on QuicConnection {
  // Helper to manage crypto/stream offsets internally
  int next_crypto_offset(QuicPacketType type, int len) {
    if (type == QuicPacketType.initial) {
      int current = receiving_init_from_offset;
      receiving_init_from_offset += len;
      return current;
    } else {
      int current = receiving_handshake_from_offset;
      receiving_handshake_from_offset += len;
      return current;
    }
  }

  int next_stream_offset(int stream_id, int len) {
    var stream = receiving_streams.putIfAbsent(
      stream_id,
      () => StreamData(offset_next: 0),
    );
    int current = stream.offset_next!;
    stream.offset_next = current + len;
    return current;
  }
}

void set_sending_quic_chunk(
  QuicServer server,
  QuicConnection quic_connection_id,
  QuicConnectionParams options,
) {
  final conn = server.connections[quic_connection_id.id];
  if (conn == null) return;

  // 1. Extract data from options or incoming_packet
  // (Assuming data might be in options.incoming_packet or passed as a field)
  final Uint8List? data = options.incoming_packet is Uint8List
      ? options.incoming_packet
      : options.data!;

  if (data == null) throw Exception("data is $data");

  // 2. Determine Type and Stream Logic
  // Using QuicPacketType enum instead of strings for safety
  QuicPacketType packet_type = options.type ?? QuicPacketType.oneRtt;

  // Use dcid/scid as a hint for stream_id if that's where you store it
  int? stream_id = options.from_port; // Example mapping, adjust to your logic
  bool fin = false;

  List<Map<String, QuicFrame>> frames = [];

  // 3. Build appropriate Frame
  if (packet_type == QuicPacketType.initial ||
      packet_type == QuicPacketType.handshake) {
    frames.add({
      'crypto': CryptoFrame(
        // type: 'crypto',
        offset: conn.next_crypto_offset(packet_type, data.length),
        data: data,
      ),
    });
  } else if (packet_type == QuicPacketType.oneRtt && stream_id != null) {
    frames.add({
      'type': StreamFrame(
        id: stream_id,
        offset: conn.next_stream_offset(stream_id, data.length),
        fin: fin,
        data: data,
      ),
    });
  }

  // 4. Send the constructed frame
  print("Send the constructed frame");
  List<QuicFrame> mapped = [];
  for (final frame in frames) {
    mapped.addAll(frame.values);
  }
  if (frames.isNotEmpty) {
    send_quic_frames_packet(server, conn, packet_type, mapped);
  }
}

void set_quic_connection(
  QuicServer server,
  QuicConnection quic_connection_id,
  QuicConnectionParams options,
) {
  var is_modified = false;

  // 1. Ensure the connection exists in the server state
  if (!server.connections.containsKey(quic_connection_id.id)) {
    print("      [CONN] Creating new state for ${quic_connection_id.id}");
    server.connections[quic_connection_id.id] = QuicConnection(
      quic_connection_id.id,
    );
  } else {
    print("      [CONN] Modifying state for ${quic_connection_id.id}");

    is_modified = true;
  }

  final conn = server.connections[quic_connection_id.id]!;

  // 2. Capture previous state
  var prev_params = QuicConnectionParams(
    connection_status: conn.connection_status,
    sni: conn.sni ?? '',
  );

  // 3. Update connection state based on passed options
  if (options.from_ip != null && conn.from_ip != options.from_ip) {
    conn.from_ip = options.from_ip;
    is_modified = true;
  }

  if (options.from_port != null && conn.from_port != options.from_port) {
    conn.from_port = options.from_port!;
    is_modified = true;
  }

  if (options.version != null && conn.version != options.version) {
    print(
      "      [CONN] Version negotiated: 0x${options.version!.toRadixString(16)}",
    );
    conn.version = options.version!;
    is_modified = true;
  }

  if (options.dcid != null && options.dcid!.isNotEmpty) {
    if (conn.original_dcid == null ||
        !arraybufferEqual(options.dcid!, conn.original_dcid!)) {
      conn.original_dcid = options.dcid;
      is_modified = true;
    }
  }

  if (options.scid != null && options.scid!.isNotEmpty) {
    bool is_scid_exist = conn.their_cids.any(
      (cid) => arraybufferEqual(options.scid!, cid),
    );
    if (!is_scid_exist) {
      conn.their_cids.add(options.scid!);
      is_modified = true;
    }
  }

  if (options.sni != null && conn.sni != options.sni) {
    conn.sni = options.sni;
    is_modified = true;
  }

  if (options.connection_status != null &&
      conn.connection_status != options.connection_status) {
    print(
      "      [CONN] Status change: ${conn.connection_status} -> ${options.connection_status}",
    );
    conn.connection_status = options.connection_status!;
    is_modified = true;

    if (conn.connection_status == ConnectionStatus.Connected) {
      print("      [CONN] Connection ESTABLISHED. Clearing buffers.");
      conn.tls_transcript = [];
      conn.receiving_init_chunks = {};
      conn.receiving_handshake_chunks = {};
    }
  }

  // 4. Trigger logic if state was changed
  if (is_modified == true) {
    var address_str = '${conn.from_ip}:${conn.from_port}';
    if (server.addressBinds[address_str] != quic_connection_id.id) {
      server.addressBinds[address_str] = quic_connection_id.id;
    }

    var current_params = QuicConnectionParams(
      connection_status: conn.connection_status,
      sni: conn.sni ?? '',
    );
    print("calling quic_connection from set_quic_connection");
    quic_connection(server, quic_connection_id, current_params, prev_params);
  }

  // 5. Handle TLS Certificate Injection
  if (options.cert != null && options.key != null) {
    print("      [TLS] Injecting Server Certificate and signing Handshake...");
    // ... [Certificate logic remains as per your previous version]
  }

  // 6. Handle Incoming Packet Processing
  if (options.incoming_packet != null) {
    var incoming_packet = options.incoming_packet!;
    print(
      "      [PKT] Processing incoming packet of type ${incoming_packet['type']}, runtime type ${incoming_packet['type'].runtimeType}",
    );
    QuicPacketType type = incoming_packet['type'] as QuicPacketType;

    var read_key;
    var read_iv;
    var read_hp;
    var largest_pn = -1;

    // --- CRITICAL FIX: Assign values to read_key/iv/hp ---
    if (type == QuicPacketType.initial) {
      if (conn.init_read_key == null) {
        print("      [SEC] Deriving INITIAL secrets");
        var d = quic_derive_init_secrets(
          conn.original_dcid!,
          conn.version,
          'read',
        );
        conn.init_read_key = d.key;
        conn.init_read_iv = d.iv;
        conn.init_read_hp = d.hp;
      }
      read_key = conn.init_read_key;
      read_iv = conn.init_read_iv;
      read_hp = conn.init_read_hp;
      largest_pn = conn.receiving_init_pn_largest;
    } else if (type == QuicPacketType.handshake) {
      if (conn.handshake_read_key == null &&
          conn.tls_client_handshake_traffic_secret != null) {
        print("      [SEC] Deriving HANDSHAKE secrets");
        var d = quic_derive_from_tls_secrets(
          conn.tls_client_handshake_traffic_secret,
          "sha256",
        );
        conn.handshake_read_key = d.key;
        conn.handshake_read_iv = d.iv;
        conn.handshake_read_hp = d.hp;
      }
      read_key = conn.handshake_read_key;
      read_iv = conn.handshake_read_iv;
      read_hp = conn.handshake_read_hp;
      largest_pn = conn.receiving_handshake_pn_largest;
    } else if (type == QuicPacketType.oneRtt) {
      if (conn.app_read_key == null &&
          conn.tls_client_app_traffic_secret != null) {
        var d = quic_derive_from_tls_secrets(
          conn.tls_client_app_traffic_secret,
          "sha256",
        );
        conn.app_read_key = d.key;
        conn.app_read_iv = d.iv;
        conn.app_read_hp = d.hp;
      }
      read_key = conn.app_read_key;
      read_iv = conn.app_read_iv;
      read_hp = conn.app_read_hp;
      largest_pn = conn.receiving_app_pn_largest;
    }

    // Now this block will finally execute because keys aren't null
    if (read_key != null && read_iv != null) {
      var decrypted_packet = decrypt_quic_packet(
        incoming_packet['data'],
        read_key,
        read_iv,
        read_hp,
        conn.original_dcid!,
        largest_pn,
      );

      if (decrypted_packet != null && decrypted_packet.plaintext.isNotEmpty) {
        print(
          "      [PKT] Decrypted PN: ${decrypted_packet.packet_number} ($type)",
        );

        var need_check_tls_chunks = false;
        var need_check_receiving_streams = false;
        var is_new_packet = false;

        // Register Packet Number in correct range
        if (type == QuicPacketType.initial) {
          is_new_packet = FlatRanges.add(conn.receiving_init_pn_ranges, [
            decrypted_packet.packet_number,
            decrypted_packet.packet_number,
          ]);
          if (conn.receiving_init_pn_largest < decrypted_packet.packet_number)
            conn.receiving_init_pn_largest = decrypted_packet.packet_number;
        } else if (type == QuicPacketType.handshake) {
          is_new_packet = FlatRanges.add(conn.receiving_handshake_pn_ranges, [
            decrypted_packet.packet_number,
            decrypted_packet.packet_number,
          ]);
          if (conn.receiving_handshake_pn_largest <
              decrypted_packet.packet_number)
            conn.receiving_handshake_pn_largest =
                decrypted_packet.packet_number;
        } else if (type == QuicPacketType.oneRtt) {
          is_new_packet = FlatRanges.add(conn.receiving_app_pn_ranges, [
            decrypted_packet.packet_number,
            decrypted_packet.packet_number,
          ]);
          if (conn.receiving_app_pn_largest < decrypted_packet.packet_number)
            conn.receiving_app_pn_largest = decrypted_packet.packet_number;
        }

        if (is_new_packet) {
          var ack_eliciting = false;

          // Use the new typed parser
          List<QuicFrame> frames = parse_quic_frames(
            decrypted_packet.plaintext,
          );

          for (var f in frames) {
            // Using a Switch Expression/Pattern Matching for type safety
            switch (f) {
              case CryptoFrame():
                print(
                  "      [TLS] Crypto Frame: offset ${f.offset}, len ${f.data.length}",
                );

                var isInitial = (type == QuicPacketType.initial);
                var targetRanges = isInitial
                    ? conn.receiving_init_ranges
                    : conn.receiving_handshake_ranges;
                var targetChunks = isInitial
                    ? conn.receiving_init_chunks
                    : conn.receiving_handshake_chunks;

                if (FlatRanges.add(targetRanges, [
                  f.offset,
                  f.offset + f.data.length,
                ])) {
                  targetChunks[f.offset] = f.data;
                  need_check_tls_chunks = true;
                }
                ack_eliciting = true;

              case StreamFrame():
                print(
                  "      [STRM] Stream Frame ID ${f.id} (Offset: ${f.offset}, Fin: ${f.fin})",
                );
                // ... Your specific Stream reassembly logic here ...
                ack_eliciting = true;
                need_check_receiving_streams = true;

              case PingFrame() ||
                  NewConnectionIdFrame() ||
                  HandshakeDoneFrame():
                // These frames don't carry data for TLS/Stream but must be acknowledged
                ack_eliciting = true;

              case ConnectionCloseFrame():
                print("      [CONN] Peer sent ConnectionClose: ${f.reason}");
                conn.connection_status =
                    ConnectionStatus.Disconnected; // Terminated
                is_modified = true;

              default:
                // Other frame types (MaxData, etc.)
                break;
            }
          }

          // 7. Acknowledgment Logic
          if (ack_eliciting) {
            var ack_frame_to_send = <QuicFrame>[];

            // Choose the correct PN range tracker based on packet encryption level
            if (type == QuicPacketType.initial) {
              ack_frame_to_send.add(
                build_ack_info_from_ranges(
                  conn.receiving_init_pn_ranges,
                  null,
                  0,
                )!,
              );
            } else if (type == QuicPacketType.handshake) {
              ack_frame_to_send.add(
                build_ack_info_from_ranges(
                  conn.receiving_handshake_pn_ranges,
                  null,
                  0,
                )!,
              );
            }

            if (ack_frame_to_send.isNotEmpty) {
              // Send the ACK back using the same encryption level
              QuicPacketType responseType = (type is QuicPacketType)
                  ? type
                  : QuicPacketType.initial;

              send_quic_frames_packet(
                server,
                conn,
                responseType,
                ack_frame_to_send,
              );
            }
          }
        }

        // var tls_messages = [];
        // Process TLS reassembly
        if (need_check_tls_chunks) {
          var targetChunks = (type == QuicPacketType.initial)
              ? conn.receiving_init_chunks
              : conn.receiving_handshake_chunks;
          var targetOffset = (type == QuicPacketType.initial)
              ? conn.receiving_init_from_offset
              : conn.receiving_handshake_from_offset;

          print("extract_tls_messages_from_chunks");
          final ext = extract_tls_messages_from_chunks(
            targetChunks,
            targetOffset,
          );
          if (type == QuicPacketType.initial) {
            conn.receiving_init_from_offset = ext.new_from_offset;
          } else {
            conn.receiving_handshake_from_offset = ext.new_from_offset;
          }

          print("Going to process tls messages: ${ext.tls_messages}");

          for (var msg in ext.tls_messages) {
            process_quic_tls_message(server, quic_connection_id, msg);
          }
        } else {}
      } else {
        print("      [ERR] Decryption FAILED for $type packet.");
      }
    } else {
      print("      [DEBUG] Skip Processing: No $type keys yet.");
    }
  }
}

// Utility to handle byte array equality in Dart
bool arraybufferEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void quic_connection(
  QuicServer server,
  QuicConnection quic_connection_id,
  QuicConnectionParams current_params,
  QuicConnectionParams prev_params,
) {
  print("Quic connection callback for ${quic_connection_id.id}");
  print("Connection status: ${current_params.connection_status}");
  if (current_params != null) {
    if (current_params.connection_status != prev_params.connection_status) {
      // איתות שיש לנו בצלחה פעם ראשונה
      if (current_params.connection_status == ConnectionStatus.Connected) {
        send_quic_frames_packet(
          server,
          quic_connection_id,
          QuicPacketType.oneRtt,
          [HandshakeDoneFrame(data: Uint8List(0))],
        );
      }

      if (current_params.connection_status == ConnectionStatus.Connected) {
        var settings_frame = build_settings_frame({
          'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 65536,
          'SETTINGS_MAX_FIELD_SECTION_SIZE': 65536,
          'SETTINGS_ENABLE_WEBTRANSPORT': 1,
          'SETTINGS_H3_DATAGRAM': 1,
          'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
          'SETTINGS_WT_MAX_SESSIONS': 1,
        });

        var control_stream_frames = build_h3_frames([
          {'frame_type': 0x04, 'payload': settings_frame},
        ]);

        quic_stream_write(
          server,
          quic_connection_id,
          Uint8List.fromList([3]),
          concatUint8Arrays([
            Uint8List.fromList([0x00]),
            control_stream_frames,
          ]),
          false,
        );

        quic_stream_write(
          server,
          quic_connection_id,
          Uint8List.fromList([7]),
          Uint8List.fromList([0x02]),
          false,
        );

        quic_stream_write(
          server,
          quic_connection_id,
          Uint8List.fromList([11]),
          Uint8List.fromList([0x03]),
          false,
        );
      }
    }

    if (current_params.sni != prev_params.sni) {
      server.options.sniCallback?.call(current_params.sni, (
        dynamic err,
        dynamic creds,
      ) {
        if (err == null && creds != null) {
          set_quic_connection(
            server,
            quic_connection_id,
            QuicConnectionParams(
              cert:
                  creds['cert'], // Assuming QuicConnectionParams has a 'cert' field
              key:
                  creds['key'], // Assuming QuicConnectionParams has a 'key' field
            ),
          );
        }
      });
    }
  }
}

void quic_stream_write(
  QuicServer server,
  QuicConnection quic_connection_id,
  Uint8List stream_id,
  Uint8List data,
  bool fin,
) {
  if (server.connections.containsKey(quic_connection_id) == true) {
    if (server.connections[quic_connection_id]!.sending_streams.containsKey(
          stream_id,
        ) ==
        false) {
      server.connections[quic_connection_id]!.sending_streams[int.parse(
        stream_id.toString(),
      )] = StreamData(
        pending_data: null,
        write_offset_next: 0,
        pending_offset_start: 0,
        send_offset_next: 0,
        total_size: 0,

        in_flight_ranges: {},
        acked_ranges: [],
      );
    }

    var stream =
        server.connections[quic_connection_id]!.sending_streams[stream_id]!;

    var start_offset = stream.write_offset_next;
    var end_offset = start_offset! + data.length;
    stream.write_offset_next = end_offset;

    if (fin == true) {
      stream.total_size = end_offset; // הגודל הסופי של הזרם
    }

    // קבע את התחלת ה־pending לפי acked_ranges
    var pending_offset_start = 0;
    if (stream.acked_ranges!.length > 0 && stream.acked_ranges![0] == 0) {
      pending_offset_start = stream.acked_ranges![1];
    }

    // גזור רק את החלק שטרם קיבל ACK
    var skip = math.max(pending_offset_start - start_offset!, 0);
    if (skip >= data.length) return; // אין מה להוסיף

    // equivalent to .slice(skip)
    var trimmed_data = data.sublist(skip as int);

    if (stream.pending_data == null) {
      stream.pending_data = trimmed_data;
      stream.pending_offset_start = start_offset + skip;
    } else {
      // מיזוג ל־Uint8Array חדש
      Uint8List old = stream.pending_data!;
      var old_offset = stream.pending_offset_start;
      var new_offset = start_offset + skip;

      var new_start = math.min(old_offset!, new_offset);
      var new_end = math.max(
        old_offset + old.length,
        new_offset + trimmed_data.length,
      );
      var total_len = new_end - new_start;

      var merged = Uint8List(total_len as int);

      // העתק ישן (merged.set equivalent in Dart)
      merged.setRange(
        old_offset - new_start,
        (old_offset - new_start) + old.length,
        old,
      );

      // העתק חדש
      merged.setRange(
        new_offset - new_start,
        (new_offset - new_start) + trimmed_data.length,
        trimmed_data,
      );

      stream.pending_data = merged;
      stream.pending_offset_start = new_start;
    }

    prepare_and_send_quic_packet(server, quic_connection_id.id);
  }
}

// Mock/Placeholder for the flat-ranges utility
// class FlatRanges {
//   static bool add(List<int> existingRanges, List<int> newRange) {
//     // Complex logic is mocked here. Assumes addition is successful for flow control.
//     existingRanges.addAll(newRange);
//     return true;
//   }

//   static bool remove(List<int> existingRanges, List<int> newRange) {
//     // Complex logic is mocked here. Assumes addition is successful for flow control.
//     existingRanges.addAll(newRange);
//     return true;
//   }

//   static invert(acked_ranges, int i, total_bytes) {}
// }

void prepare_and_send_quic_packet(
  QuicServer server,
  String quic_connection_id,
) {
  var conn = server.connections[quic_connection_id];
  if (conn == null) return;

  if (conn.sending_quic_packet_now == false) {
    conn.sending_quic_packet_now = true;

    if (conn.next_send_quic_packet_timer != null) {
      conn.next_send_quic_packet_timer!.cancel();
      conn.next_send_quic_packet_timer = null;
    }

    var now = DateTime.now().millisecondsSinceEpoch;

    var total_bytes_last_1s = 0;
    var packet_count_last_1s = 0;

    int? oldest_packet_time_bytes;
    int? oldest_packet_time_packets;

    // סריקת ההיסטוריה
    for (var i = 0; i < conn.sending_app_pn_history.length; i++) {
      var entry = conn.sending_app_pn_history[i];
      var ts = entry[0];
      var size = entry[1];

      if (ts > now - 1000) {
        total_bytes_last_1s += size as int;
        packet_count_last_1s++;
      } else {
        if (oldest_packet_time_bytes == null ||
            ts < oldest_packet_time_bytes!) {
          oldest_packet_time_bytes = ts;
        }
        if (oldest_packet_time_packets == null ||
            ts < oldest_packet_time_packets!) {
          oldest_packet_time_packets = ts;
        }
      }
    }

    var bytes_left = conn.max_sending_total_bytes_per_sec - total_bytes_last_1s;
    var packets_left = conn.max_sending_packets_per_sec - packet_count_last_1s;

    var in_flight_packet_count = conn.sending_app_pn_in_flight.length;
    var in_flight_total_bytes = 0;

    for (var pn in conn.sending_app_pn_in_flight.values) {
      var pn_index =
          pn - (conn.sending_app_pn_base - conn.sending_app_pn_history.length);
      if (pn_index >= 0 && pn_index < conn.sending_app_pn_history.length) {
        var info = conn.sending_app_pn_history[pn_index];
        if (info != null) {
          in_flight_total_bytes = in_flight_total_bytes + (info[1] as int);
        }
      }
    }

    var in_flight_room =
        conn.max_sending_bytes_in_flight - in_flight_total_bytes;
    var allowed_packet_size = min(
      bytes_left,
      min(conn.max_sending_packet_size as int, in_flight_room as int),
    );

    if (packets_left > 0 &&
        allowed_packet_size >= conn.min_sending_packet_size! &&
        in_flight_packet_count < conn.max_sending_packets_in_flight! &&
        in_flight_total_bytes + allowed_packet_size <=
            conn.max_sending_bytes_in_flight) {
      List<Uint8List> encoded_frames = [];
      Map<dynamic, dynamic> update_streams = {};
      List<dynamic> remove_pending_ack = [];

      if (conn.receiving_app_pn_pending_ack.isNotEmpty) {
        var ack_delay_ms = 0;
        var largest_pn = conn.receiving_app_pn_pending_ack.last;

        for (var i2 = 0; i2 < conn.receiving_app_pn_history.length; i2++) {
          var history_entry = conn.receiving_app_pn_history[i2];
          if (history_entry![0] == largest_pn) {
            // Note: original used pn_recv from history scan
            ack_delay_ms = now - (history_entry![1] as int);
            break;
          }
        }

        var delay_ns = ack_delay_ms * 1000000;
        var ack_delay_raw = (delay_ns / (1 << conn.remote_ack_delay_exponent!))
            .floor();

        var ack_frame = build_ack_info_from_ranges(
          conn.receiving_app_pn_pending_ack,
          null,
          ack_delay_raw,
        );
        encoded_frames.add(encode_quic_frames({'ack': ack_frame!}));

        remove_pending_ack = List.from(conn.receiving_app_pn_pending_ack);
      }

      var active_stream_count =
          server.connections[quic_connection_id]!.sending_streams.length;
      var per_stream_bytes = active_stream_count > 0
          ? (allowed_packet_size / active_stream_count).floor()
          : 0;

      server.connections[quic_connection_id]!.sending_streams.forEach((
        stream_id,
        stream_val,
      ) {
        var result = get_quic_stream_chunks_to_send(
          server,
          quic_connection_id,
          int.parse(stream_id.toString()),
          per_stream_bytes,
        );
        var chunks = result['chunks'];
        var send_offset_next = result['send_offset_next'];

        if (chunks.length > 0) {
          List<int> chunks_ranges = [];
          for (var i = 0; i < chunks.length; i++) {
            var is_fin = false;
            if (chunks[i].offset + chunks[i].data.length >=
                server
                    .connections[quic_connection_id]!
                    .sending_streams[stream_id]!
                    .total_size) {
              is_fin = true;
            }

            final frame = StreamFrame(
              id: int.parse(stream_id.toString()),
              offset: chunks[i].offset,
              fin: is_fin,
              data: chunks[i].data,
            );

            // var stream_frame = {
            //   'type': 'stream',
            //   'id': int.parse(stream_id.toString()),
            //   'offset': chunks[i].offset,
            //   'fin': is_fin,
            //   'data': chunks[i].data,
            // };

            encoded_frames.add(encode_quic_frames({'stream': frame}));
            chunks_ranges.add(chunks[i].offset);
            chunks_ranges.add(chunks[i].offset + chunks[i].data.length);
          }

          chunks_ranges.sort();

          update_streams[stream_id] = {
            'chunks_ranges': chunks_ranges,
            'send_offset_next': send_offset_next,
          };
        }
      });

      if (encoded_frames.length > 0) {
        Uint8List all_encoded_frames;
        if (encoded_frames.length == 1) {
          all_encoded_frames = encoded_frames[0];
        } else {
          all_encoded_frames = concatUint8Arrays(encoded_frames);
        }

        send_quic_packet(
          server,
          conn,
          QuicPacketType.oneRtt,
          all_encoded_frames,
          (bool is_sent) {
            if (is_sent == true) {
              now = DateTime.now().millisecondsSinceEpoch;
              var packet_number =
                  server.connections[quic_connection_id]!.sending_app_pn_base;

              conn.sending_app_pn_history.add([now, all_encoded_frames.length]);
              conn.sending_app_pn_in_flight[packet_number] = packet_number;

              update_streams.forEach((stream_id, data) {
                server
                        .connections[quic_connection_id]!
                        .sending_streams[stream_id]!
                        .in_flight_ranges![packet_number] =
                    data['chunks_ranges'];
                server
                        .connections[quic_connection_id]!
                        .sending_streams[stream_id]!
                        .send_offset_next =
                    data['send_offset_next'];
              });

              if (remove_pending_ack.isNotEmpty) {
                FlatRanges.remove(
                  conn.receiving_app_pn_pending_ack,
                  remove_pending_ack as List<int>,
                );
              }

              server.connections[quic_connection_id]!.sending_app_pn_base++;
            }

            conn.next_send_quic_packet_timer = Timer(Duration.zero, () {
              conn.sending_quic_packet_now = false;
              conn.next_send_quic_packet_timer = null;
              prepare_and_send_quic_packet(server, quic_connection_id);
            });
          },
        );
      } else {
        conn.next_send_quic_packet_timer = null;
        conn.sending_quic_packet_now = false;
      }
    } else {
      List<int> wait_options = [];

      if (packets_left <= 0 && oldest_packet_time_packets != null) {
        var wait_packets = max(0, (oldest_packet_time_packets! + 1000) - now);
        wait_options.add(wait_packets);
      }

      if (bytes_left < conn.min_sending_packet_size &&
          oldest_packet_time_bytes != null) {
        var wait_bytes = max(0, (oldest_packet_time_bytes! + 1000) - now);
        wait_options.add(wait_bytes);
      }

      if (wait_options.isNotEmpty) {
        int max_wait = wait_options.reduce(max);
        conn.next_send_quic_packet_timer = Timer(
          Duration(milliseconds: max_wait),
          () {
            conn.next_send_quic_packet_timer = null;
            conn.sending_quic_packet_now = false;
            prepare_and_send_quic_packet(server, quic_connection_id);
          },
        );
      } else {
        conn.sending_quic_packet_now = false;
      }
    }
  }
}

void process_quic_receiving_streams(
  QuicServer server,
  QuicConnection quic_connection_id,
) {
  if (server.connections.containsKey(quic_connection_id) == true) {
    var conn = server.connections[quic_connection_id];

    // Iterating through receiving_streams map
    for (var stream_id in conn!.receiving_streams!.keys.toList()) {
      var current_stream = conn.receiving_streams[stream_id]!;

      if (current_stream.need_check == true) {
        current_stream.need_check = false;

        var stream_type = null;

        // Check against known H3 stream IDs
        if (conn.h3_remote_control_stream_id == stream_id) {
          stream_type = 0;
        } else if (conn.h3_remote_qpack_encoder_stream_id == stream_id) {
          stream_type = 2;
        } else if (conn.h3_remote_qpack_decoder_stream_id ==
            int.parse(stream_id.toString())) {
          stream_type = 3;
        }

        if (current_stream!.receiving_ranges.length >= 2) {
          int s_id = int.parse(stream_id.toString());
          bool is_unidirectional = (s_id % 2 == 0) != (s_id % 4 == 0);

          if (is_unidirectional) {
            if (stream_type == null &&
                current_stream.receiving_chunks.containsKey(0)) {
              var first_byte = current_stream.receiving_chunks[0][0];

              switch (first_byte) {
                case 0x00:
                  conn.h3_remote_control_stream_id = s_id;
                  stream_type = 0;
                  break;
                case 0x01:
                  // Push Stream
                  break;
                case 0x02:
                  conn.h3_remote_qpack_encoder_stream_id = s_id;
                  stream_type = 2;
                  break;
                case 0x03:
                  conn.h3_remote_qpack_decoder_stream_id = s_id;
                  stream_type = 3;
                  break;
              }
            }
          } else {
            stream_type = 4;
          }
        }

        // Logic for Control Stream (Type 0)
        if (stream_type == 0) {
          var ext = extract_h3_frames_from_chunks(
            current_stream.receiving_chunks,
            conn.h3_remote_control_from_offset!,
          );
          conn.h3_remote_control_from_offset = ext.new_from_offset;
          var h3_frames = ext.frames;

          if (h3_frames.length > 0) {
            for (var i = 0; i < h3_frames.length; i++) {
              if (h3_frames[i].frame_type == 4) {
                var control_settings = parse_h3_settings_frame(
                  h3_frames[i].payload,
                );

                if (control_settings.containsKey(
                      'SETTINGS_QPACK_MAX_TABLE_CAPACITY',
                    ) &&
                    control_settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'] > 0) {
                  conn.h3_remote_qpack_max_table_capacity =
                      control_settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'];
                  evict_qpack_remote_dynamic_table_if_needed(
                    server,
                    quic_connection_id,
                  );
                }

                if (control_settings.containsKey(
                      'SETTINGS_MAX_FIELD_SECTION_SIZE',
                    ) &&
                    control_settings['SETTINGS_MAX_FIELD_SECTION_SIZE'] > 0) {
                  conn.h3_remote_max_header_size =
                      control_settings['SETTINGS_MAX_FIELD_SECTION_SIZE'];
                }

                if (control_settings.containsKey('SETTINGS_H3_DATAGRAM') &&
                    control_settings['SETTINGS_H3_DATAGRAM'] > 0) {
                  conn.h3_remote_datagram_support =
                      control_settings['SETTINGS_H3_DATAGRAM'] > 0;
                }
              }
            }
          }
        }
        // Logic for QPACK Encoder Stream (Type 2)
        else if (stream_type == 2) {
          var ext = extract_qpack_encoder_instructions_from_chunks(
            current_stream.receiving_chunks,
            conn.h3_remote_qpack_encoder_from_offset!,
          );
          conn.h3_remote_qpack_encoder_from_offset = ext.new_from_offset;

          List<dynamic> arr_inserts = [];

          for (var i = 0; i < ext.instructions.length; i++) {
            var instr = ext.instructions[i];
            if (instr.type == 'set_dynamic_table_capacity') {
              conn.h3_remote_qpack_table_capacity = instr.capacity;
            } else if (instr.type == 'insert_with_name_ref' ||
                instr.type == 'insert_without_name_ref') {
              var name;
              var value = instr.value;

              if (instr.type == 'insert_with_name_ref') {
                if (instr.from_static_table == true) {
                  if (instr.name_index < qpack_static_table_entries.length) {
                    name = qpack_static_table_entries[instr.name_index][0];
                  }
                } else {
                  var base_index = conn.h3_remote_qpack_table_base_index;
                  var dynamic_index = base_index - 1 - instr.name_index;
                  var dynamic_table = conn.h3_remote_qpack_dynamic_table;

                  if (dynamic_index >= 0 &&
                      dynamic_index < dynamic_table.length) {
                    name = dynamic_table[dynamic_index][0];
                  }
                }
              } else {
                name = instr.name;
              }

              if (name != null) {
                arr_inserts.add([name, value]);
              }
            }
          }

          if (arr_inserts.length > 0) {
            for (var i = 0; i < arr_inserts.length; i++) {
              insert_into_qpack_remote_encoder_dynamic_table(
                server,
                quic_connection_id,
                arr_inserts[i][0],
                arr_inserts[i][1],
              );
            }
          }
        }
        // Logic for HTTP3 Request Stream (Type 4)
        else if (stream_type == 4) {
          if (conn.h3_http_request_streams.containsKey(stream_id) == false) {
            conn.h3_http_request_streams[stream_id] = {
              'from_offset': 0,
              'response_headers': {},
              'header_sent': false,
              'response_body': null,
            };
          }

          var ext = extract_h3_frames_from_chunks(
            current_stream.receiving_chunks,
            conn.h3_http_request_streams[stream_id]['from_offset'],
          );

          conn.h3_http_request_streams[stream_id]['from_offset'] =
              ext.new_from_offset;
          var h3_frames = ext.frames;

          if (h3_frames.length > 0) {
            for (var i = 0; i < h3_frames.length; i++) {
              if (h3_frames[i].frame_type == 1) {
                // Header frame
                Map<String, dynamic> headers = {};
                var dynamic_table = conn.h3_remote_qpack_dynamic_table;
                var header_block = parse_qpack_header_block(
                  h3_frames[i].payload,
                );

                if (header_block.insert_count <= dynamic_table.length) {
                  bool used_dynamic_ref = false;

                  for (var i2 = 0; i2 < header_block.headers.length; i2++) {
                    var h = header_block.headers[i2];
                    if (h.type == 'indexed') {
                      if (h.from_static_table == true) {
                        if (h.index < qpack_static_table_entries.length) {
                          headers[qpack_static_table_entries[h.index][0]] =
                              qpack_static_table_entries[h.index][1];
                        }
                      } else {
                        used_dynamic_ref = true;
                        var dynamic_index =
                            header_block.base_index - 1 - h.index;
                        if (dynamic_index >= 0 &&
                            dynamic_index < dynamic_table.length) {
                          headers[dynamic_table[dynamic_index][0]] =
                              dynamic_table[dynamic_index][1];
                        }
                      }
                    } else if (h.type == 'literal_with_name_ref') {
                      if (h.from_static_table == true) {
                        if (h.name_index < qpack_static_table_entries.length) {
                          headers[qpack_static_table_entries[h.name_index][0]] =
                              h.value;
                        }
                      } else {
                        used_dynamic_ref = true;
                        var dynamic_index =
                            header_block.base_index - 1 - h.name_index;
                        if (dynamic_index >= 0 &&
                            dynamic_index < dynamic_table.length) {
                          headers[dynamic_table[dynamic_index][0]] = h.value;
                        }
                      }
                    } else if (h.type == 'literal_with_literal_name') {
                      headers[h.name] = h.value;
                    }
                  }
                  if (used_dynamic_ref) {
                    // build_qpack_block_header_ack(stream_id) logic here
                  }
                }

                if (headers[':protocol'] == 'webtransport') {
                  if (server._webtransport_handler != null) {
                    if (conn.h3_wt_sessions.containsKey(stream_id) == false) {
                      var headers_payload = build_http3_literal_headers_frame(
                        [
                              {'name': ":status", 'value': "200"},
                            ]
                            as Map<String, dynamic>,
                      );

                      var http3_response = build_h3_frames([
                        {'frame_type': 1, 'payload': headers_payload},
                      ]);

                      set_sending_quic_chunk(
                        server,
                        quic_connection_id,
                        QuicConnectionParams(
                          type: QuicPacketType.oneRtt,
                          stream_id: Uint8List.fromList([stream_id]),
                          fin: false,
                          data: http3_response,
                        ),
                      );

                      var wt = create_wt_session_object(
                        server,
                        quic_connection_id,
                        stream_id,
                        headers.map(
                          (key, value) => MapEntry(key, value.toString()),
                        ),
                      );
                      conn.h3_wt_sessions[stream_id] = wt;
                      server._webtransport_handler!(wt);
                    }
                  }
                } else {
                  if (server._handler != null) {
                    var req = {
                      'method': headers[':method'],
                      'path': headers[':path'],
                      'headers': headers,
                      'connection_id': quic_connection_id,
                      'stream_id': stream_id,
                    };
                    var res = build_response_object(
                      server,
                      quic_connection_id,
                      stream_id,
                    );
                    server._handler!(req, res);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

dynamic build_response_object(
  dynamic server,
  dynamic quic_connection_id,
  dynamic stream_id,
) {
  return {
    'statusCode': null,
    'headersSent': false,
    'socket': null,

    'writeHead': (dynamic statusCode, Map<String, dynamic> headers) {
      var request_stream = server
          .connections[quic_connection_id]
          .h3_http_request_streams[stream_id];

      // Copy headers to the stream state
      headers.forEach((header_name, value) {
        request_stream['response_headers'][header_name] = value;
      });

      if (request_stream['response_headers'].containsKey(":status") == false) {
        request_stream['response_headers'][":status"] = statusCode.toString();

        var headers_payload = build_http3_literal_headers_frame(
          request_stream['response_headers'],
        );

        var http3_response = build_h3_frames([
          {'frame_type': 1, 'payload': headers_payload},
        ]);

        quic_stream_write(
          server,
          quic_connection_id,
          stream_id,
          http3_response,
          false,
        );
      }
    },

    'writeEarlyHints': (dynamic hints) {
      // Logic for early hints
    },

    'write': (dynamic chunk) {
      var http3_response = build_h3_frames([
        {'frame_type': 0, 'payload': chunk},
      ]);

      quic_stream_write(
        server,
        quic_connection_id,
        stream_id,
        http3_response,
        false,
      );
    },

    'end': (dynamic chunk) {
      if (chunk != null) {
        var http3_response = build_h3_frames([
          {'frame_type': 0, 'payload': chunk},
        ]);

        quic_stream_write(
          server,
          quic_connection_id,
          stream_id,
          http3_response,
          true,
        );
      } else {
        quic_stream_write(
          server,
          quic_connection_id,
          stream_id,
          Uint8List(0),
          true,
        );
      }
    },
  };
}

Map<String, dynamic> get_quic_stream_chunks_to_send(
  QuicServer server,
  String quic_connection_id,
  int stream_id,
  int allowed_bytes,
) {
  var conn = server.connections[quic_connection_id]!;
  // if (conn == null) return {};

  var stream = conn.sending_streams[stream_id];
  if (stream == null || stream.pending_data == null) {
    return {
      'chunks': [],
      'send_offset_next': stream != null ? stream.send_offset_next : 0,
    };
  }

  // Determine total size of the stream
  int total_bytes = (stream.total_size) != null
      ? stream.total_size!
      : stream.write_offset_next!;

  int base_offset = stream.pending_offset_start!;
  int send_offset_next = stream.send_offset_next!;

  // relative_missing: Inverting acked ranges to find "holes" (gaps) in the data
  // Assuming FlatRanges.invert is a helper available in your project
  List<int> relative_missing = FlatRanges.invert(
    stream.acked_ranges!,
    0,
    total_bytes,
  );

  // Convert relative gaps to absolute offsets
  for (int i = 0; i < relative_missing.length; i++) {
    relative_missing[i] += base_offset;
  }

  List<Map<String, dynamic>> chunks = [];
  int total_bytes_used = 0;
  int? first_chunk_offset;

  // Phase 1: Moving forward from the last known send position
  for (int i = 0; i < relative_missing.length; i += 2) {
    int f = relative_missing[i];
    int t = relative_missing[i + 1];

    if (f <= send_offset_next && send_offset_next < t) {
      int offset = send_offset_next;

      while (offset < t && total_bytes_used < allowed_bytes) {
        int space_left = allowed_bytes - total_bytes_used;
        int len = min(space_left, t - offset);
        if (len <= 0) break;

        first_chunk_offset ??= offset;

        int rel_start = offset - base_offset;
        int rel_end = rel_start + len;

        // Use sublist for Uint8List slicing
        Uint8List chunk_data = stream.pending_data!.sublist(rel_start, rel_end);

        chunks.add({'offset': offset, 'data': chunk_data});

        total_bytes_used += len;
        offset += len;
      }
      break;
    }
  }

  // Phase 2: Filling remaining capacity with missing data from the beginning (Retransmission)
  if (total_bytes_used < allowed_bytes && first_chunk_offset != null) {
    for (int i = 0; i < relative_missing.length; i += 2) {
      int f = relative_missing[i];
      int t = relative_missing[i + 1];

      int offset = f;
      while (offset < t &&
          offset < first_chunk_offset! &&
          total_bytes_used < allowed_bytes) {
        int space_left = allowed_bytes - total_bytes_used;
        int len = [
          space_left,
          t - offset,
          first_chunk_offset! - offset,
        ].reduce(min);

        if (len <= 0) break;

        int rel_start = offset - base_offset;
        int rel_end = rel_start + len;
        Uint8List chunk_data = stream.pending_data!.sublist(rel_start, rel_end);

        chunks.add({'offset': offset, 'data': chunk_data});

        total_bytes_used += len;
        offset += len;
      }
    }
  }

  // Calculate the next send pointer
  int new_send_offset = send_offset_next;
  for (var chunk in chunks) {
    if (chunk['offset'] == new_send_offset) {
      new_send_offset = chunk['offset'] + (chunk['data'] as Uint8List).length;
    } else {
      // If there is a gap, the sequential pointer stops here
      break;
    }
  }

  return {'chunks': chunks, 'send_offset_next': new_send_offset};
}

void process_ack_frame(
  QuicServer server,
  QuicConnection quicConnectionId,
  AckFrame frame, // Changed from Map to typed AckFrame
) {
  if (!server.connections.containsKey(quicConnectionId.id)) return;

  var conn = server.connections[quicConnectionId.id]!;

  // 1. Convert ACK frame info into flat ranges [start, end, start, end...]
  // This uses the helper function we refined earlier
  List<int> ackedRanges = quic_acked_info_to_ranges(frame);

  /* 1) RTT and Throughput Estimation */
  int largestPn = frame.largest;

  // We only measure RTT if the largest acknowledged packet was one we tracked
  if (conn.sending_app_pn_in_flight[largestPn] != null) {
    int now = DateTime.now().millisecondsSinceEpoch;

    // ACK delay is usually encoded with a multiplier (default 2^3 = 8)
    // Formula: (delay_value * 8) / 1000 to get milliseconds
    int ackDelayMs = ((frame.delay * 8) / 1000).round();

    // Calculate index in history buffer
    int pnIndex =
        (largestPn -
                (conn.sending_app_pn_base - conn.sending_app_pn_history.length))
            .toInt();

    if (pnIndex >= 0 && pnIndex < conn.sending_app_pn_history.length) {
      var entry = conn.sending_app_pn_history[pnIndex];
      int startTime = entry[0]; // Original send time

      int receivedTimeEstimate = now - ackDelayMs;
      int measuredRtt = now - startTime - ackDelayMs;

      // Throughput Sent Calculation
      int sentBytesDuring = 0;
      int sentPacketsDuring = 0;
      for (int i = pnIndex; i < conn.sending_app_pn_history.length; i++) {
        var historyEntry = conn.sending_app_pn_history[i];
        if (receivedTimeEstimate >= historyEntry[0]) {
          sentBytesDuring += historyEntry[1];
          sentPacketsDuring++;
        }
      }

      // Throughput Received Calculation
      int receivedBytesDuring = 0;
      int receivedPacketsDuring = 0;
      for (var recvEntry in conn.receiving_app_pn_history.values) {
        int tsRecv = recvEntry[1];
        int sizeRecv = recvEntry[2];
        if (tsRecv > receivedTimeEstimate) break;
        if (tsRecv >= startTime) {
          receivedBytesDuring += sizeRecv;
          receivedPacketsDuring++;
        }
      }

      // Record RTT history if it's a unique new measurement
      var rttHistory = conn.rtt_history;
      bool isDuplicate = false;
      if (rttHistory.isNotEmpty) {
        var last = rttHistory.last;
        if (last[0] == startTime && last[1] == receivedTimeEstimate) {
          isDuplicate = true;
        }
      }

      if (!isDuplicate) {
        rttHistory.add([
          startTime, // 0 - Sent time
          receivedTimeEstimate, // 1 - ACK received estimate
          sentBytesDuring, // 2 - Bytes sent in interval
          sentPacketsDuring, // 3 - Packets sent in interval
          receivedBytesDuring, // 4 - Bytes received in interval
          receivedPacketsDuring, // 5 - Packets received in interval
          measuredRtt, // 6 - The RTT value
        ]);
      }
    }
  }

  /* 2) Update In-Flight and Acknowledged Data */
  // Use a copy of the in-flight list to safely modify the original set during iteration
  var pnsInFlight = List<int>.from(conn.sending_app_pn_in_flight as Iterable);

  for (int pn in pnsInFlight) {
    bool isAcked = false;
    // Check if PN falls within any of the acknowledged ranges
    for (int i = 0; i < ackedRanges.length; i += 2) {
      if (pn >= ackedRanges[i] && pn <= ackedRanges[i + 1]) {
        isAcked = true;
        break;
      }
    }

    if (isAcked) {
      conn.sending_app_pn_in_flight.remove(pn);

      // Clean up stream tracking
      for (var streamId in conn.sending_streams.keys.toList()) {
        var stream = conn.sending_streams[streamId]!;

        if (stream.in_flight_ranges![pn] != null) {
          var rangeToAck = stream.in_flight_ranges![pn];

          // Add this specific packet's byte range to the stream's acknowledged ranges
          FlatRanges.add(stream.acked_ranges!, [rangeToAck!]);
          stream.in_flight_ranges!.remove(pn);

          // Check if the stream is 100% acknowledged
          if (stream.acked_ranges!.length == 2 &&
              (stream.total_size ?? 0) > 0) {
            if (stream.acked_ranges![0] == 0 &&
                stream.acked_ranges![1] == stream.total_size) {
              print(
                "      [STRM] Stream $streamId fully acknowledged. Removing.",
              );
              conn.sending_streams.remove(streamId);
            }
          }
        }
      }
    }
  }
}

typedef SNICallbackFunction =
    void Function(String servername, Function callback);

class QuicServerOptions {
  final SNICallbackFunction? sniCallback;

  // You can add more options here later, like:
  // final int maxIdleTimeout;
  // final bool allowInsecure;

  QuicServerOptions({this.sniCallback});
}

class QuicServer {
  RawDatagramSocket? _udp4;
  RawDatagramSocket? _udp6;
  int? _port;

  Function? _handler;
  Function? _webtransport_handler;

  // Now using the typed class property
  final QuicServerOptions options;

  // The constructor now expects the QuicServerOptions class
  QuicServer(this.options);

  /// Starts the QUIC server
  Future<void> listen(
    int port, [
    String host = '::',
    Function? callback,
  ]) async {
    _port = port;

    // Setup IPv4
    if (host == '::' || host.contains('.')) {
      String host4 = host.contains('.')
          ? host
          : InternetAddress.anyIPv4.address;
      _udp4 = await RawDatagramSocket.bind(host4, _port!);
      _udp4?.listen((event) => _handleSocketEvent(_udp4, event));
    }

    // Setup IPv6 - Fixed to use anyIPv6
    if (host == '::' || host.contains(':')) {
      String host6 = host.contains(':')
          ? host
          : InternetAddress.anyIPv6.address;
      _udp6 = await RawDatagramSocket.bind(host6, _port!);
      _udp6?.listen((event) => _handleSocketEvent(_udp6, event));
    }

    if (callback != null) callback();
  }

  void _handleSocketEvent(RawDatagramSocket? socket, RawSocketEvent event) {
    if (event == RawSocketEvent.read) {
      Datagram? dg = socket?.receive();
      if (dg != null) {
        _receivingUdpQuicPacket(dg.address.address, dg.port, dg.data);
      }
    }
  }

  void _receivingUdpQuicPacket(String address, int port, Uint8List msg) {
    receiving_udp_quic_packet(this, address, port, msg);
  }

  // final Function? sniCallback;
  // Change this to match your function call
  // final Function? SNICallback;

  // Connection state
  final Map<String, QuicConnection> connections = {};
  final Map<String, dynamic> addressBinds = {};

  // QuicServer({Map<String, dynamic>? options})
  //   : SNICallback = options?['SNICallback'];

  /// Starts the QUIC server on the specified port and host

  /// Event registration (Mirroring Node.js .on pattern)
  void on(String event, Function cb) {
    switch (event) {
      case 'request':
        _handler = cb;
        break;
      case 'webtransport':
        _webtransport_handler = cb;
        break;
      // Other events (OCSP, session resumption) would be initialized here
      default:
        break;
    }
  }

  /// Shutdown the server sockets
  void close() {
    _udp4?.close();
    _udp6?.close();
  }
}

// Factory function to match the original API style
QuicServer createServer(QuicServerOptions options, [Function? handler]) {
  var server = QuicServer(options);
  if (handler != null) {
    server.on('request', handler);
  }
  return server;
}

void receiving_udp_quic_packet(
  QuicServer server,
  String from_ip,
  int from_port,
  Uint8List udp_packet_data,
) {
  // --- DEBUG: Inbound Datagram ---
  print("┌── RECEIVING UDP DATAGRAM");
  print("│ From: $from_ip:$from_port | Size: ${udp_packet_data.length} bytes");

  List<QuicPacket> quic_packets = parse_quic_datagram(udp_packet_data);
  print("│ Parsed ${quic_packets.length} QUIC packets");

  if (quic_packets.isEmpty) {
    print("└─> No valid QUIC packets found. Dropping datagram.");
    return;
  }

  int packet_index = 0;
  for (var packet in quic_packets) {
    packet_index++;
    print(
      "│ [Packet $packet_index] Type: ${packet.type?.name} | Ver: ${packet.version}",
    );

    String? quic_connection_id;
    String? dcid_str;

    if (packet.dcid != null && (packet.dcid as Uint8List).isNotEmpty) {
      dcid_str = packet.dcid!
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
    }

    // 3. Identify the Connection ID
    if (dcid_str != null) {
      if (server.connections.containsKey(dcid_str)) {
        quic_connection_id = dcid_str;
        print("│   Routing: Match found via DCID ($dcid_str)");
      }
    } else {
      String address_str = "$from_ip:$from_port";
      if (server.addressBinds.containsKey(address_str)) {
        String existing_cid = server.addressBinds[address_str];
        if (server.connections.containsKey(existing_cid)) {
          quic_connection_id = existing_cid;
          print(
            "│   Routing: Match found via Address Binding ($address_str -> $existing_cid)",
          );
        }
      }
    }

    // 4. Handle New or Unknown Connections
    bool is_new_connection = false;
    if (quic_connection_id == null) {
      is_new_connection = true;
      if (dcid_str != null) {
        quic_connection_id = dcid_str;
      } else {
        var rng = Random();
        quic_connection_id =
            (rng.nextInt(1 << 31).toString() + rng.nextInt(1 << 31).toString());
      }
      print(
        "│   Routing: No existing connection. Assigning ID: $quic_connection_id",
      );
    }

    Map<String, dynamic> build_params = {
      'from_ip': from_ip,
      'from_port': from_port,
    };

    if (packet.dcid != null && (packet.dcid as Uint8List).isNotEmpty)
      build_params['dcid'] = packet.dcid;
    if (packet.scid != null && (packet.scid as Uint8List).isNotEmpty)
      build_params['scid'] = packet.scid;
    if (packet.version != null) build_params['version'] = packet.version;

    final type = packet.type!;
    if (type == QuicPacketType.initial ||
        type == QuicPacketType.handshake ||
        type == QuicPacketType.oneRtt) {
      build_params['incoming_packet'] = {'type': type, 'data': packet.raw};
    }

    // 7. Hand over to the connection manager
    if (!server.connections.containsKey(quic_connection_id)) {
      print("│   Action: Creating new QuicConnection object");
      server.connections[quic_connection_id!] = QuicConnection(
        quic_connection_id,
      );
      String address_str = "$from_ip:$from_port";
      server.addressBinds[address_str] = quic_connection_id;
    }

    final current_connection = server.connections[quic_connection_id]!;

    print("│   Action: Dispatching to set_quic_connection");
    set_quic_connection(
      server,
      current_connection,
      QuicConnectionParams(
        from_ip: build_params['from_ip'],
        from_port: build_params['from_port'],
        dcid: build_params['dcid'],
        scid: build_params['scid'],
        version: build_params['version'],
        incoming_packet: build_params['incoming_packet'],
      ),
    );
  }
  print("└── PROCESSING COMPLETE");
}
