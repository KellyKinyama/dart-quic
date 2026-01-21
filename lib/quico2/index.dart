import 'dart:math';
import 'dart:math' as math;
import 'dart:typed_data';

import 'ecdsa.dart';

import '../quico/utils.dart';
import 'crypto.dart';
import 'dart:convert';
import 'dart:async';

import 'h3.dart'; // For Timer

import 'dart:io';

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
  server,
  Uint8List quic_connection_id,
) {
  if (server.connections.contain(quic_connection_id)) {
    var connection = server.connections[quic_connection_id];
    var entries = connection.h3_remote_qpack_dynamic_table;
    var capacity = connection.h3_remote_qpack_table_capacity;

    // חישוב גודל כולל של כל הערכים בטבלה
    var totalSize = 0;
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i][0];
      var value = entries[i][1];
      totalSize += (name.length as int) + (value.length + 32) as int;
    }

    // הדחה של ערכים ישנים עד שהטבלה בגבולות המותר
    while (totalSize > capacity && entries.length > 0) {
      var removed = entries.pop(); // מסיר את הערך האחרון
      var removedSize = removed[0].length + removed[1].length + 32;
      totalSize -= removedSize as int;
    }
  }
}

bool insert_into_qpack_remote_encoder_dynamic_table(
  server,
  quic_connection_id,
  name,
  value,
) {
  if (server.connections.contain(quic_connection_id)) {
    var entry_size = name.length + value.length + 32;

    if (entry_size >
        server.connections[quic_connection_id].h3_remote_qpack_table_capacity)
      return false;

    server.connections[quic_connection_id].h3_remote_qpack_dynamic_table
        .unshift([name, value]);
    server.connections[quic_connection_id].h3_remote_qpack_table_base_index++;

    evict_qpack_remote_dynamic_table_if_needed(server, quic_connection_id);

    return true;
  }
  return false;
}

dynamic create_wt_session_object(
  server,
  quic_connection_id,
  stream_id,
  headers,
) {
  var wt;
  wt = (
    id: stream_id,

    //quic_connection: conn_id,
    headers: {},

    send: (data) {
      send_quic_frames_packet(server, quic_connection_id, '1rtt', [
        (
          type: 'datagram',
          data: concatUint8Arrays([writeVarInt(stream_id), data]),
        ),
      ]);
    },

    close: () {
      wt.internal.isOpen = false;
      // שלח CONTROL_FRAME של סוג close אם צריך
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

void send_quic_frames_packet(server, quic_connection_id, type, frames) {
  if (server.connections.contain(quic_connection_id)) {
    var write_key = null;
    var write_iv = null;
    var write_hp = null;

    var packet_number = 1;

    if (type == 'initial') {
      if (server.connections[quic_connection_id].init_write_key != null &&
          server.connections[quic_connection_id].init_write_iv != null &&
          server.connections[quic_connection_id].init_write_hp != null) {
        write_key = server.connections[quic_connection_id].init_write_key;
        write_iv = server.connections[quic_connection_id].init_write_iv;
        write_hp = server.connections[quic_connection_id].init_write_hp;
      } else {
        var d = quic_derive_init_secrets(
          server.connections[quic_connection_id].original_dcid,
          server.connections[quic_connection_id].version,
          'write',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        server.connections[quic_connection_id].init_write_key = d.key;
        server.connections[quic_connection_id].init_write_iv = d.iv;
        server.connections[quic_connection_id].init_write_hp = d.hp;
      }

      packet_number =
          server.connections[quic_connection_id].sending_init_pn_next + 0;
    } else if (type == 'handshake') {
      if (server.connections[quic_connection_id].handshake_write_key != null &&
          server.connections[quic_connection_id].handshake_write_iv != null &&
          server.connections[quic_connection_id].handshake_write_hp != null) {
        write_key = server.connections[quic_connection_id].handshake_write_key;
        write_iv = server.connections[quic_connection_id].handshake_write_iv;
        write_hp = server.connections[quic_connection_id].handshake_write_hp;
      } else if (server
              .connections[quic_connection_id]
              .tls_server_handshake_traffic_secret !=
          null) {
        var d = quic_derive_from_tls_secrets(
          server
              .connections[quic_connection_id]
              .tls_server_handshake_traffic_secret,
          'sha256',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        server.connections[quic_connection_id].handshake_write_key = d.key;
        server.connections[quic_connection_id].handshake_write_iv = d.iv;
        server.connections[quic_connection_id].handshake_write_hp = d.hp;
      }

      packet_number =
          server.connections[quic_connection_id].sending_handshake_pn_next + 0;
    } else if (type == '1rtt') {
      if (server.connections[quic_connection_id].app_write_key != null &&
          server.connections[quic_connection_id].app_write_iv != null &&
          server.connections[quic_connection_id].app_write_hp != null) {
        write_key = server.connections[quic_connection_id].app_write_key;
        write_iv = server.connections[quic_connection_id].app_write_iv;
        write_hp = server.connections[quic_connection_id].app_write_hp;
      } else if (server
              .connections[quic_connection_id]
              .tls_server_app_traffic_secret !=
          null) {
        var d = quic_derive_from_tls_secrets(
          server.connections[quic_connection_id].tls_server_app_traffic_secret,
          'sha256',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        server.connections[quic_connection_id].app_write_key = d.key;
        server.connections[quic_connection_id].app_write_iv = d.iv;
        server.connections[quic_connection_id].app_write_hp = d.hp;
      }

      packet_number =
          server.connections[quic_connection_id].sending_app_pn_base + 0;
    }

    //console.log('sending packet_number==');
    //console.log(packet_number);

    var dcid = Uint8List(0);

    if (server.connections[quic_connection_id].their_cids.length > 0) {
      dcid = server.connections[quic_connection_id].their_cids[0];
    }

    var encodedFrames = encode_quic_frames(frames);
    var encrypted_quic_packet = encrypt_quic_packet(
      type,
      encodedFrames,
      write_key,
      write_iv,
      write_hp,
      packet_number,
      dcid,
      server.connections[quic_connection_id].original_dcid,
      Uint8List(0),
    );

    if (type == 'initial') {
      server.connections[quic_connection_id].sending_init_pn_next++;
    } else if (type == 'handshake') {
      server.connections[quic_connection_id].sending_handshake_pn_next++;
    } else if (type == '1rtt') {
      var now = DateTime.now();
      server.connections[quic_connection_id].sending_app_pn_history.push([
        now,
        encodedFrames.length,
      ]);
      server.connections[quic_connection_id].sending_app_pn_base++;
    }

    send_udp_packet(
      server,
      encrypted_quic_packet,
      server.connections[quic_connection_id].from_port,
      server.connections[quic_connection_id].from_ip,
      () {},
    );
  }
}

void send_udp_packet(server, data, port, ip, callback) {
  if (ip.indexOf(':') >= 0) {
    server._udp6.send(data, port, ip, (error) {
      if (error) {
        callback(false);
      } else {
        callback(true);
      }
    });
  } else {
    server._udp4.send(data, port, ip, (error) {
      if (error) {
        callback(false);
      } else {
        callback(true);
      }
    });
  }
}

void send_quic_packet(
  server,
  quic_connection_id,
  type,
  encoded_frames,
  callback,
) {
  if (server.connections.contains(quic_connection_id)) {
    var write_key = null;
    var write_iv = null;
    var write_hp = null;

    var packet_number = 1;

    if (type == 'initial') {
      if (server.connections[quic_connection_id].init_write_key != null &&
          server.connections[quic_connection_id].init_write_iv != null &&
          server.connections[quic_connection_id].init_write_hp != null) {
        write_key = server.connections[quic_connection_id].init_write_key;
        write_iv = server.connections[quic_connection_id].init_write_iv;
        write_hp = server.connections[quic_connection_id].init_write_hp;
      } else {
        var d = quic_derive_init_secrets(
          server.connections[quic_connection_id].original_dcid,
          server.connections[quic_connection_id].version,
          'write',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        server.connections[quic_connection_id].init_write_key = d.key;
        server.connections[quic_connection_id].init_write_iv = d.iv;
        server.connections[quic_connection_id].init_write_hp = d.hp;
      }

      packet_number =
          server.connections[quic_connection_id].sending_init_pn_next + 0;
    } else if (type == 'handshake') {
      if (server.connections[quic_connection_id].handshake_write_key != null &&
          server.connections[quic_connection_id].handshake_write_iv != null &&
          server.connections[quic_connection_id].handshake_write_hp != null) {
        write_key = server.connections[quic_connection_id].handshake_write_key;
        write_iv = server.connections[quic_connection_id].handshake_write_iv;
        write_hp = server.connections[quic_connection_id].handshake_write_hp;
      } else if (server
              .connections[quic_connection_id]
              .tls_server_handshake_traffic_secret !=
          null) {
        var d = quic_derive_from_tls_secrets(
          server
              .connections[quic_connection_id]
              .tls_server_handshake_traffic_secret,
          'sha256',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        server.connections[quic_connection_id].handshake_write_key = d.key;
        server.connections[quic_connection_id].handshake_write_iv = d.iv;
        server.connections[quic_connection_id].handshake_write_hp = d.hp;
      }

      packet_number =
          server.connections[quic_connection_id].sending_handshake_pn_next + 0;
    } else if (type == '1rtt') {
      if (server.connections[quic_connection_id].app_write_key != null &&
          server.connections[quic_connection_id].app_write_iv != null &&
          server.connections[quic_connection_id].app_write_hp != null) {
        write_key = server.connections[quic_connection_id].app_write_key;
        write_iv = server.connections[quic_connection_id].app_write_iv;
        write_hp = server.connections[quic_connection_id].app_write_hp;
      } else if (server
              .connections[quic_connection_id]
              .tls_server_app_traffic_secret !=
          null) {
        var d = quic_derive_from_tls_secrets(
          server.connections[quic_connection_id].tls_server_app_traffic_secret,
          'sha256',
        );

        write_key = d.key;
        write_iv = d.iv;
        write_hp = d.hp;

        server.connections[quic_connection_id].app_write_key = d.key;
        server.connections[quic_connection_id].app_write_iv = d.iv;
        server.connections[quic_connection_id].app_write_hp = d.hp;
      }

      packet_number =
          server.connections[quic_connection_id].sending_app_pn_base + 0;
    }

    //console.log('sending packet_number==');
    //console.log(packet_number);

    var dcid = Uint8List(0);

    if (server.connections[quic_connection_id].their_cids.length > 0) {
      dcid = server.connections[quic_connection_id].their_cids[0];
    }

    var encrypted_quic_packet = encrypt_quic_packet(
      type,
      encoded_frames,
      write_key,
      write_iv,
      write_hp,
      packet_number,
      dcid,
      server.connections[quic_connection_id].original_dcid,
      Uint8List(0),
    );

    send_udp_packet(
      server,
      encrypted_quic_packet,
      server.connections[quic_connection_id].from_port,
      server.connections[quic_connection_id].from_ip,
      (is_sent) {
        if (callback is Function) {
          callback(is_sent);
        }
      },
    );
  }
}

void process_quic_tls_message(server, quic_connection_id, tls_message) {
  if (server.connections.contains(quic_connection_id)) {
    var hs = parse_tls_message(tls_message);
    if (hs.type == 0x01) {
      var parsed = parse_tls_client_hello(hs.body);

      server.connections[quic_connection_id].tls_signature_algorithms =
          parsed.signature_algorithms;
      server.connections[quic_connection_id].tls_transcript = [tls_message];

      var a = handle_client_hello(parsed);

      //console.log('handle_client_hello:');
      //console.log(parsed);

      var quic_transport_parameters = parse_transport_parameters(
        parsed.quic_transport_parameters_raw,
      );
      //console.log('quic_transport_parameters:');
      //console.dir(quic_transport_parameters, { depth: null });

      if (quic_transport_parameters.contains('ack_delay_exponent')) {
        server.connections[quic_connection_id].remote_ack_delay_exponent =
            quic_transport_parameters['ack_delay_exponent'];
      }

      if (quic_transport_parameters.contains('max_udp_payload_size')) {
        server.connections[quic_connection_id].remote_max_udp_payload_size =
            quic_transport_parameters['max_udp_payload_size'];
      }

      server.connections[quic_connection_id].tls_cipher_selected =
          a.selected_cipher;

      var server_random = Uint8List.fromList(
        List.generate(32, (index) => Random.secure().nextInt(255)),
      ); // crypto.randomBytes(32);
      var server_hello = build_server_hello(
        server_random,
        a.server_public_key,
        parsed.session_id,
        server.connections[quic_connection_id].tls_cipher_selected,
        a.selected_group,
      );

      server.connections[quic_connection_id].tls_transcript.push(server_hello);

      set_sending_quic_chunk(server, quic_connection_id, (
        type: 'initial',
        data: server_hello,
      ));

      var cipher_info = get_cipher_info(
        server.connections[quic_connection_id].tls_cipher_selected,
      );
      var hash_func = cipher_info.hash;

      var b = tls_derive_handshake_secrets(
        a.shared_secret,
        server.connections[quic_connection_id].tls_transcript,
        // hash_func,
      );

      server.connections[quic_connection_id].tls_handshake_secret =
          b.handshake_secret;

      server
              .connections[quic_connection_id]
              .tls_client_handshake_traffic_secret =
          b.client_handshake_traffic_secret;

      server
              .connections[quic_connection_id]
              .tls_server_handshake_traffic_secret =
          b.server_handshake_traffic_secret;

      var quic_ext_data = build_quic_ext({
        'original_destination_connection_id':
            server.connections[quic_connection_id].original_dcid,
        'initial_source_connection_id':
            server.connections[quic_connection_id].original_dcid,
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
      var selected_alpn = null;

      for (var i in supported_alpn) {
        if (selected_alpn == null) {
          for (var i2 in parsed.alpn) {
            if (parsed.alpn[i2] == supported_alpn.contains(i)) {
              selected_alpn = parsed.alpn[i2];
              break;
            }
          }
        }
      }

      server.connections[quic_connection_id].tls_alpn_selected = selected_alpn;

      var enc_ext = build_encrypted_extensions([
        (type: 0x10, data: build_alpn_ext(selected_alpn)),
        (type: 0x39, data: quic_ext_data),
      ]);

      server.connections[quic_connection_id].tls_transcript.add(enc_ext);

      set_sending_quic_chunk(server, quic_connection_id, (
        type: 'handshake',
        data: enc_ext,
      ));

      set_quic_connection(server, quic_connection_id, (sni: parsed.sni));
    } else if (hs.type == 20) {
      //finished from client here...
      var cipher_info = get_cipher_info(
        server.connections[quic_connection_id].tls_cipher_selected,
      );
      var hash_func = cipher_info.hash;

      var finished_key = hkdf_expand_label(
        server
            .connections[quic_connection_id]
            .tls_client_handshake_traffic_secret,
        'finished',
        Uint8List(0),
        hash_func.outputLen,
        // hash_func,
      );

      var expected_client_finished = hmac(
        cipher_info.str,
        finished_key,
        hash_transcript(
          server.connections[quic_connection_id].tls_transcript,
          hash_func,
        ),
      );

      if (arraybufferEqual(
            expected_client_finished,
            Uint8List.fromList(hs.body),
          ) ==
          true) {
        //finished ok!!!!!!

        //console.log('finished ok!!!!!!!');
        server.connections[quic_connection_id].tls_finished_ok = true;
      }
    } else {
      //console.log('tls other:');
      //console.log(hs);
    }
  }
}

void set_sending_quic_chunk(server, quic_connection_id, options) {
  if (server.connections.contain(quic_connection_id)) {
    var type = null;
    var data = null;
    var stream_id = null;
    var fin = false;

    if (options is dynamic) {
      if (options.contains('type')) {
        type = options.type;
      }

      if (options.contains('data')) {
        data = options.data;
      }

      if (options.contains('stream_id')) {
        stream_id = options.stream_id;
        type = '1rtt';
      }

      if (options.contains('fin')) {
        fin = options.fin;
      }
    }

    if (type == 'initial') {
      //server.connections[quic_connection_id].sending_init_chunks.push(data);

      send_quic_frames_packet(server, quic_connection_id, 'initial', [
        (
          type: 'crypto',
          offset:
              server.connections[quic_connection_id].sending_init_offset_next,
          data: data,
        ),
      ]);

      server.connections[quic_connection_id].sending_init_offset_next =
          server.connections[quic_connection_id].sending_init_offset_next +
          data.byteLength;
    } else if (type == 'handshake') {
      //server.connections[quic_connection_id].sending_handshake_chunks.push(data);

      send_quic_frames_packet(server, quic_connection_id, 'handshake', [
        (
          type: 'crypto',
          offset: server
              .connections[quic_connection_id]
              .sending_handshake_offset_next,
          data: data,
        ),
      ]);

      server.connections[quic_connection_id].sending_handshake_offset_next =
          server.connections[quic_connection_id].sending_handshake_offset_next +
          data.byteLength;
    } else if (type == '1rtt') {
      if (stream_id != null) {
        if (server.connections[quic_connection_id].sending_streams.contains(
          stream_id,
        )) {
          server.connections[quic_connection_id].sending_streams[stream_id] = (
            offset_next: 0,
          );
        }

        send_quic_frames_packet(server, quic_connection_id, '1rtt', [
          (
            type: 'stream',
            id: stream_id,
            offset: server
                .connections[quic_connection_id]
                .sending_streams[stream_id]
                .offset_next,
            fin: fin,
            data: data,
          ),
        ]);

        server
                .connections[quic_connection_id]
                .sending_streams[stream_id]
                .offset_next =
            server
                .connections[quic_connection_id]
                .sending_streams[stream_id]
                .offset_next +
            data.byteLength;
      }
    }
  }
}

void set_quic_connection(
  dynamic server,
  dynamic quic_connection_id,
  dynamic options,
) {
  var is_modified = false;

  if (server.connections.containsKey(quic_connection_id)) {
    // Assuming new_quic_connection is defined in your scope
    // server.connections[quic_connection_id] = new_quic_connection;
    is_modified = true;
  }

  var prev_params = {
    'connection_status':
        server.connections[quic_connection_id].connection_status,
    'sni': server.connections[quic_connection_id].sni,
  };

  if (options is dynamic) {
    // Note: Use .containsKey() for Map or check for null on dynamic objects
    if (options.containsKey('from_ip')) {
      if (server.connections[quic_connection_id].from_ip !=
          options['from_ip']) {
        server.connections[quic_connection_id].from_ip = options['from_ip'];
        is_modified = true;
      }
    }

    if (options.containsKey('from_port')) {
      if (server.connections[quic_connection_id].from_port !=
          options['from_port']) {
        server.connections[quic_connection_id].from_port = options['from_port'];
        is_modified = true;
      }
    }

    if (options.containsKey('version')) {
      if (server.connections[quic_connection_id].version !=
          options['version']) {
        server.connections[quic_connection_id].version = options['version'];
        is_modified = true;
      }
    }

    if (options.containsKey('dcid') &&
        options['dcid'] != null &&
        options['dcid'].length > 0) {
      if (server.connections[quic_connection_id].original_dcid == null ||
          server.connections[quic_connection_id].original_dcid.length <= 0 ||
          arraybufferEqual(
                options['dcid'],
                server.connections[quic_connection_id].original_dcid,
              ) ==
              false) {
        server.connections[quic_connection_id].original_dcid = options['dcid'];
        is_modified = true;
      }
    }

    if (options.containsKey('scid') &&
        options['scid'] != null &&
        options['scid'].length > 0) {
      var is_scid_exist = false;
      for (
        var i = 0;
        i < server.connections[quic_connection_id].their_cids.length;
        i++
      ) {
        if (arraybufferEqual(
              options['scid'],
              server.connections[quic_connection_id].their_cids[i],
            ) ==
            true) {
          is_scid_exist = true;
          break;
        }
      }

      if (is_scid_exist == false) {
        server.connections[quic_connection_id].their_cids.add(options['scid']);
        is_modified = true;
      }
    }

    if (options.containsKey('sni')) {
      if (server.connections[quic_connection_id].sni != options['sni']) {
        server.connections[quic_connection_id].sni = options['sni'];
        is_modified = true;
      }
    }

    if (options.containsKey('connection_status')) {
      if (server.connections[quic_connection_id].connection_status !=
          options['connection_status']) {
        server.connections[quic_connection_id].connection_status =
            options['connection_status'];
        is_modified = true;

        if (server.connections[quic_connection_id].connection_status == 1) {
          server.connections[quic_connection_id].tls_transcript = [];
          server.connections[quic_connection_id].receiving_init_chunks = {};
          server.connections[quic_connection_id].receiving_handshake_chunks =
              {};
        }
      }
    }
  }

  if (is_modified == true) {
    var address_str =
        server.connections[quic_connection_id].from_ip.toString() +
        ':' +
        server.connections[quic_connection_id].from_port.toString();
    if (server.address_binds.containsKey(address_str) == false ||
        server.address_binds[address_str] != quic_connection_id) {
      server.address_binds[address_str] = quic_connection_id;
    }

    quic_connection(server, quic_connection_id, {
      'connection_status':
          server.connections[quic_connection_id].connection_status,
      'sni': server.connections[quic_connection_id].sni,
    }, prev_params);
  }

  if (options is Map) {
    if (options.containsKey('cert') && options.containsKey('key')) {
      var cipher_info = get_cipher_info(
        server.connections[quic_connection_id].tls_cipher_selected,
      );
      var hash_func = cipher_info['hash'];

      // Note: In Dart, X509 processing usually requires a library like 'basic_utils' or 'cryptography'
      var cert_der = options['cert']; // Assuming this is already Uint8List
      var certificate = build_certificate([
        {'cert': cert_der, 'extensions': Uint8List(0)},
      ]);

      server.connections[quic_connection_id].tls_transcript.add(certificate);

      set_sending_quic_chunk(server, quic_connection_id, {
        'type': 'handshake',
        'data': certificate,
      });

      var label = utf8.encode("TLS 1.3, server CertificateVerify");
      var separator = Uint8List.fromList([0x00]);
      var handshake_hash = hash_transcript(
        server.connections[quic_connection_id].tls_transcript,
        hash_func,
      );
      var padding = Uint8List(64)..fillRange(0, 64, 0x20);

      var signed_data = Uint8List.fromList([
        ...padding,
        ...label,
        ...separator,
        ...handshake_hash,
      ]);

      var ALGO_BY_TYPE = {'rsa': 0x0804, 'ec': 0x0403, 'ed25519': 0x0807};

      // In Dart, you'd extract the key type from your key object
      var keyType = options['key_type'];
      var algo_candidate = ALGO_BY_TYPE[keyType];

      if (algo_candidate == null) {
        throw Exception(
          "Unsupported private key type for TLS 1.3 CertificateVerify: " +
              keyType.toString(),
        );
      }

      if (server.connections[quic_connection_id].tls_signature_algorithms
              .contains(algo_candidate) ==
          false) {
        throw Exception(
          "Client did not offer compatible signature algorithm for key type $keyType",
        );
      }

      var signature = Uint8List.fromList(
        ecdsaSign(options['key'], signed_data),
      );
      // You will need to implement your crypto.sign equivalent using a Dart package
      // signature = dart_crypto_sign(keyType, signed_data, options['key']);

      var cert_verify = build_certificate_verify(algo_candidate, signature);
      server.connections[quic_connection_id].tls_transcript.add(cert_verify);

      set_sending_quic_chunk(server, quic_connection_id, {
        'type': 'handshake',
        'data': cert_verify,
      });

      var finished_key = hkdf_expand_label(
        server
            .connections[quic_connection_id]
            .tls_server_handshake_traffic_secret,
        'finished',
        Uint8List(0),
        hash_func.outputLen,
        // hash_func,
      );
      var verify_data = hmac(
        cipher_info['str'],
        finished_key,
        hash_transcript(
          server.connections[quic_connection_id].tls_transcript,
          hash_func,
        ),
      );

      var finished = build_finished(verify_data);
      server.connections[quic_connection_id].tls_transcript.add(finished);

      set_sending_quic_chunk(server, quic_connection_id, {
        'type': 'handshake',
        'data': finished,
      });

      var c = tls_derive_app_secrets(
        server.connections[quic_connection_id].tls_handshake_secret,
        server.connections[quic_connection_id].tls_transcript,
        // hash_func,
      );
      server.connections[quic_connection_id].tls_client_app_traffic_secret =
          c.client_application_traffic_secret;
      server.connections[quic_connection_id].tls_server_app_traffic_secret =
          c.server_application_traffic_secret;
    }

    if (options.containsKey('incoming_packet')) {
      var incoming_packet = options['incoming_packet'];
      if (incoming_packet.containsKey('type')) {
        var read_key;
        var read_iv;
        var read_hp;
        var largest_pn = -1;

        var type = incoming_packet['type'];

        if (type == 'initial') {
          if (server.connections[quic_connection_id].init_read_key != null) {
            read_key = server.connections[quic_connection_id].init_read_key;
            read_iv = server.connections[quic_connection_id].init_read_iv;
            read_hp = server.connections[quic_connection_id].init_read_hp;
          } else {
            var d = quic_derive_init_secrets(
              server.connections[quic_connection_id].original_dcid,
              server.connections[quic_connection_id].version,
              'read',
            );
            read_key = server.connections[quic_connection_id].init_read_key =
                d.key;
            read_iv = server.connections[quic_connection_id].init_read_iv =
                d.iv;
            read_hp = server.connections[quic_connection_id].init_read_hp =
                d.hp;
          }
          largest_pn =
              server.connections[quic_connection_id].receiving_init_pn_largest;
        } else if (type == 'handshake') {
          if (server.connections[quic_connection_id].handshake_read_key !=
              null) {
            read_key =
                server.connections[quic_connection_id].handshake_read_key;
            read_iv = server.connections[quic_connection_id].handshake_read_iv;
            read_hp = server.connections[quic_connection_id].handshake_read_hp;
          } else if (server
                  .connections[quic_connection_id]
                  .tls_client_handshake_traffic_secret !=
              null) {
            var d = quic_derive_from_tls_secrets(
              server
                  .connections[quic_connection_id]
                  .tls_client_handshake_traffic_secret,
              "sha256",
            );
            read_key =
                server.connections[quic_connection_id].handshake_read_key =
                    d.key;
            read_iv = server.connections[quic_connection_id].handshake_read_iv =
                d.iv;
            read_hp = server.connections[quic_connection_id].handshake_read_hp =
                d.hp;
          }
          largest_pn = server
              .connections[quic_connection_id]
              .receiving_handshake_pn_largest;
        } else if (type == '1rtt') {
          if (server.connections[quic_connection_id].app_read_key != null) {
            read_key = server.connections[quic_connection_id].app_read_key;
            read_iv = server.connections[quic_connection_id].app_read_iv;
            read_hp = server.connections[quic_connection_id].app_read_hp;
          } else if (server
                  .connections[quic_connection_id]
                  .tls_client_app_traffic_secret !=
              null) {
            var d = quic_derive_from_tls_secrets(
              server
                  .connections[quic_connection_id]
                  .tls_client_app_traffic_secret,
              "sha256",
            );
            read_key = server.connections[quic_connection_id].app_read_key =
                d.key;
            read_iv = server.connections[quic_connection_id].app_read_iv = d.iv;
            read_hp = server.connections[quic_connection_id].app_read_hp = d.hp;
          }
          largest_pn =
              server.connections[quic_connection_id].receiving_app_pn_largest;
        }

        if (read_key != null && read_iv != null) {
          var decrypted_packet = decrypt_quic_packet(
            incoming_packet['data'],
            read_key,
            read_iv,
            read_hp,
            server.connections[quic_connection_id].original_dcid,
            largest_pn,
          );

          if (decrypted_packet != null &&
              decrypted_packet.plaintext != null &&
              decrypted_packet.plaintext.length > 0) {
            var need_check_tls_chunks = false;
            var is_new_packet = false;
            var need_check_receiving_streams = false;

            if (type == 'initial') {
              is_new_packet = flat_ranges.add(
                server.connections[quic_connection_id].receiving_init_pn_ranges,
                [
                  decrypted_packet.packet_number,
                  decrypted_packet.packet_number,
                ],
              );
              if (server
                      .connections[quic_connection_id]
                      .receiving_init_pn_largest <
                  decrypted_packet.packet_number) {
                server
                        .connections[quic_connection_id]
                        .receiving_init_pn_largest =
                    decrypted_packet.packet_number;
              }
            } else if (type == 'handshake') {
              is_new_packet = flat_ranges.add(
                server
                    .connections[quic_connection_id]
                    .receiving_handshake_pn_ranges,
                [
                  decrypted_packet.packet_number,
                  decrypted_packet.packet_number,
                ],
              );
              if (server
                      .connections[quic_connection_id]
                      .receiving_handshake_pn_largest <
                  decrypted_packet.packet_number) {
                server
                        .connections[quic_connection_id]
                        .receiving_handshake_pn_largest =
                    decrypted_packet.packet_number;
              }
            } else if (type == '1rtt') {
              is_new_packet = flat_ranges.add(
                server.connections[quic_connection_id].receiving_app_pn_ranges,
                [
                  decrypted_packet.packet_number,
                  decrypted_packet.packet_number,
                ],
              );
              if (server
                      .connections[quic_connection_id]
                      .receiving_app_pn_largest <
                  decrypted_packet.packet_number) {
                server
                        .connections[quic_connection_id]
                        .receiving_app_pn_largest =
                    decrypted_packet.packet_number;
              }
              if (server.connections[quic_connection_id].connection_status !=
                  1) {
                set_quic_connection(server, quic_connection_id, {
                  'connection_status': 1,
                });
              }
            }

            if (is_new_packet == true) {
              var ack_eliciting = false;
              var frames = parse_quic_frames(decrypted_packet.plaintext);

              for (var i = 0; i < frames.length; i++) {
                var f = frames[i];
                if (ack_eliciting == false &&
                    ([
                      'stream',
                      'crypto',
                      'new_connection_id',
                      'handshake_done',
                      'path_challenge',
                      'path_response',
                      'ping',
                    ].contains(f.type))) {
                  ack_eliciting = true;
                }

                if (f.type == 'crypto') {
                  if (type == 'initial') {
                    if (flat_ranges.add(
                          server
                              .connections[quic_connection_id]
                              .receiving_init_ranges,
                          [f.offset, f.offset + f.data.length],
                        ) ==
                        true) {
                      if (server
                                  .connections[quic_connection_id]
                                  .receiving_init_chunks
                                  .containsKey(f.offset) ==
                              false ||
                          server
                                  .connections[quic_connection_id]
                                  .receiving_init_chunks[f.offset]
                                  .length <
                              f.data.length) {
                        server
                                .connections[quic_connection_id]
                                .receiving_init_chunks[f.offset] =
                            f.data;
                      }
                      need_check_tls_chunks = true;
                    }
                  } else if (type == 'handshake') {
                    if (flat_ranges.add(
                          server
                              .connections[quic_connection_id]
                              .receiving_handshake_ranges,
                          [f.offset, f.offset + f.data.length],
                        ) ==
                        true) {
                      if (server
                                  .connections[quic_connection_id]
                                  .receiving_handshake_chunks
                                  .containsKey(f.offset) ==
                              false ||
                          server
                                  .connections[quic_connection_id]
                                  .receiving_handshake_chunks[f.offset]
                                  .length <
                              f.data.length) {
                        server
                                .connections[quic_connection_id]
                                .receiving_handshake_chunks[f.offset] =
                            f.data;
                      }
                      need_check_tls_chunks = true;
                    }
                  }
                } else if (f.type == 'stream') {
                  if (server.connections[quic_connection_id].receiving_streams
                          .containsKey(f.id) ==
                      false) {
                    server.connections[quic_connection_id].receiving_streams[f
                        .id] = {
                      'receiving_chunks': {},
                      'total_size': 0,
                      'receiving_ranges': [],
                      'need_check': false,
                    };
                  }
                  var stream = server
                      .connections[quic_connection_id]
                      .receiving_streams[f.id];
                  if (flat_ranges.add(stream['receiving_ranges'], [
                        f.offset,
                        f.offset + f.data.length,
                      ]) ==
                      true) {
                    if (stream['receiving_chunks'].containsKey(f.offset) ==
                            false ||
                        stream['receiving_chunks'][f.offset].length <
                            f.data.length) {
                      stream['receiving_chunks'][f.offset] = f.data;
                    }
                    if (f.containsKey('fin') && f['fin'] == true) {
                      stream['total_size'] = f.data.length + f.offset;
                    }
                    stream['need_check'] = true;
                    need_check_receiving_streams = true;
                  }
                } else if (f.type == 'datagram') {
                  var wt_datagram = parse_webtransport_datagram(f.data);
                  if (server.connections[quic_connection_id].h3_wt_sessions
                      .containsKey(wt_datagram.stream_id)) {
                    var session = server
                        .connections[quic_connection_id]
                        .h3_wt_sessions[wt_datagram.stream_id];
                    if (session.ondatagram != null) {
                      session.ondatagram(wt_datagram.data);
                    }
                  }
                } else if (f.type == 'ack') {
                  if (type == 'initial') {
                    var acked_ranges = quic_acked_info_to_ranges(f);
                    flat_ranges.add(
                      server
                          .connections[quic_connection_id]
                          .sending_init_pn_acked_ranges,
                      acked_ranges,
                    );
                  } else if (type == 'handshake') {
                    var acked_ranges = quic_acked_info_to_ranges(f);
                    flat_ranges.add(
                      server
                          .connections[quic_connection_id]
                          .sending_handshake_pn_acked_ranges,
                      acked_ranges,
                    );
                  } else if (type == '1rtt') {
                    process_ack_frame(server, quic_connection_id, f);
                  }
                }
              }

              if (type == '1rtt') {
                var now = DateTime.now().millisecondsSinceEpoch;
                server.connections[quic_connection_id].receiving_app_pn_history
                    .add([
                      decrypted_packet.packet_number,
                      now,
                      incoming_packet['data'].length,
                    ]);
              }

              if (ack_eliciting == true) {
                var ack_frame_to_send = [];
                if (type == 'initial') {
                  ack_frame_to_send.add(
                    build_ack_info_from_ranges(
                      server
                          .connections[quic_connection_id]
                          .receiving_init_pn_ranges,
                      null,
                      0,
                    ),
                  );
                } else if (type == 'handshake') {
                  ack_frame_to_send.add(
                    build_ack_info_from_ranges(
                      server
                          .connections[quic_connection_id]
                          .receiving_handshake_pn_ranges,
                      null,
                      0,
                    ),
                  );
                } else if (type == '1rtt') {
                  flat_ranges.add(
                    server
                        .connections[quic_connection_id]
                        .receiving_app_pn_pending_ack,
                    [
                      decrypted_packet.packet_number,
                      decrypted_packet.packet_number,
                    ],
                  );
                  prepare_and_send_quic_packet(server, quic_connection_id);
                }

                if (ack_frame_to_send.length > 0) {
                  send_quic_frames_packet(
                    server,
                    quic_connection_id,
                    type,
                    ack_frame_to_send,
                  );
                }
              }
            }

            var tls_messages = [];
            if (need_check_tls_chunks == true) {
              if (type == 'initial') {
                var ext = extract_tls_messages_from_chunks(
                  server.connections[quic_connection_id].receiving_init_chunks,
                  server
                      .connections[quic_connection_id]
                      .receiving_init_from_offset,
                );
                tls_messages = ext.tls_messages;
                server
                        .connections[quic_connection_id]
                        .receiving_init_from_offset =
                    ext.new_from_offset;
              } else if (type == 'handshake') {
                var ext = extract_tls_messages_from_chunks(
                  server
                      .connections[quic_connection_id]
                      .receiving_handshake_chunks,
                  server
                      .connections[quic_connection_id]
                      .receiving_handshake_from_offset,
                );
                tls_messages = ext.tls_messages;
                server
                        .connections[quic_connection_id]
                        .receiving_handshake_from_offset =
                    ext.new_from_offset;
              }
            }

            if (tls_messages.length > 0) {
              for (var i = 0; i < tls_messages.length; i++) {
                process_quic_tls_message(
                  server,
                  quic_connection_id,
                  tls_messages[i],
                );
              }
            }

            if (need_check_receiving_streams == true) {
              if (server
                      .connections[quic_connection_id]
                      .receiving_streams_next_check_timer ==
                  null) {
                server
                    .connections[quic_connection_id]
                    .receiving_streams_next_check_timer = Timer(
                  Duration(milliseconds: 5),
                  () {
                    server
                            .connections[quic_connection_id]
                            .receiving_streams_next_check_timer =
                        null;
                    process_quic_receiving_streams(server, quic_connection_id);
                  },
                );
              }
            }
          }
        }
      }
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
  dynamic server,
  dynamic quic_connection_id,
  dynamic current_params,
  dynamic prev_params,
) {
  if (current_params != null) {
    if (current_params.connection_status != prev_params.connection_status) {
      // איתות שיש לנו בצלחה פעם ראשונה
      if (current_params.connection_status == 1) {
        send_quic_frames_packet(server, quic_connection_id, '1rtt', [
          {'type': 'handshake_done'},
        ]);
      }

      if (current_params.connection_status == 1) {
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
          3,
          concatUint8Arrays([
            Uint8List.fromList([0x00]),
            control_stream_frames,
          ]),
          false,
        );

        quic_stream_write(
          server,
          quic_connection_id,
          7,
          Uint8List.fromList([0x02]),
          false,
        );

        quic_stream_write(
          server,
          quic_connection_id,
          11,
          Uint8List.fromList([0x03]),
          false,
        );
      }
    }

    if (current_params.sni != prev_params.sni) {
      server.SNICallback(current_params.sni, (dynamic err, dynamic creds) {
        if (err == null && creds != null) {
          // Maintaining the record/map structure for the options parameter
          set_quic_connection(server, quic_connection_id, {
            'cert': creds.cert,
            'key': creds.key,
          });
        } else {
          // Handle error or missing credentials
        }
      });
    }
  }
}

void quic_stream_write(
  dynamic server,
  dynamic quic_connection_id,
  dynamic stream_id,
  Uint8List data,
  bool fin,
) {
  if (server.connections.containsKey(quic_connection_id) == true) {
    if (server.connections[quic_connection_id].sending_streams.containsKey(
          stream_id,
        ) ==
        false) {
      server.connections[quic_connection_id].sending_streams[stream_id] = {
        'pending_data': null,
        'write_offset_next': 0,
        'pending_offset_start': 0,
        'send_offset_next': 0,
        'total_size': 0,

        'in_flight_ranges': {},
        'acked_ranges': [],
      };
    }

    var stream =
        server.connections[quic_connection_id].sending_streams[stream_id];

    var start_offset = stream['write_offset_next'];
    var end_offset = start_offset + data.length;
    stream['write_offset_next'] = end_offset;

    if (fin == true) {
      stream['total_size'] = end_offset; // הגודל הסופי של הזרם
    }

    // קבע את התחלת ה־pending לפי acked_ranges
    var pending_offset_start = 0;
    if (stream['acked_ranges'].length > 0 && stream['acked_ranges'][0] == 0) {
      pending_offset_start = stream['acked_ranges'][1];
    }

    // גזור רק את החלק שטרם קיבל ACK
    var skip = math.max(pending_offset_start - start_offset, 0);
    if (skip >= data.length) return; // אין מה להוסיף

    // equivalent to .slice(skip)
    var trimmed_data = data.sublist(skip as int);

    if (stream['pending_data'] == null) {
      stream['pending_data'] = trimmed_data;
      stream['pending_offset_start'] = start_offset + skip;
    } else {
      // מיזוג ל־Uint8Array חדש
      Uint8List old = stream['pending_data'];
      var old_offset = stream['pending_offset_start'];
      var new_offset = start_offset + skip;

      var new_start = math.min(old_offset, new_offset);
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

      stream['pending_data'] = merged;
      stream['pending_offset_start'] = new_start;
    }

    prepare_and_send_quic_packet(server, quic_connection_id);
  }
}

// Mock/Placeholder for the flat-ranges utility
class flat_ranges {
  static bool add(List<int> existingRanges, List<int> newRange) {
    // Complex logic is mocked here. Assumes addition is successful for flow control.
    existingRanges.addAll(newRange);
    return true;
  }

  static bool remove(List<int> existingRanges, List<int> newRange) {
    // Complex logic is mocked here. Assumes addition is successful for flow control.
    existingRanges.addAll(newRange);
    return true;
  }

  static invert(acked_ranges, int i, total_bytes) {}
}

void prepare_and_send_quic_packet(dynamic server, dynamic quic_connection_id) {
  var conn = server.connections[quic_connection_id];
  if (conn == null) return;

  if (conn.sending_quic_packet_now == false) {
    conn.sending_quic_packet_now = true;

    if (conn.next_send_quic_packet_timer != null) {
      conn.next_send_quic_packet_timer.cancel();
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

    for (var pn in conn.sending_app_pn_in_flight) {
      var pn_index =
          pn.toInt() -
          (conn.sending_app_pn_base - conn.sending_app_pn_history.length);
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
        allowed_packet_size >= conn.min_sending_packet_size &&
        in_flight_packet_count < conn.max_sending_packets_in_flight &&
        in_flight_total_bytes + allowed_packet_size <=
            conn.max_sending_bytes_in_flight) {
      List<Uint8List> encoded_frames = [];
      Map<dynamic, dynamic> update_streams = {};
      List<dynamic> remove_pending_ack = [];

      if (conn.receiving_app_pn_pending_ack.length > 0) {
        var ack_delay_ms = 0;
        var largest_pn = conn.receiving_app_pn_pending_ack.last;

        for (var i2 = 0; i2 < conn.receiving_app_pn_history.length; i2++) {
          var history_entry = conn.receiving_app_pn_history[i2];
          if (history_entry[0] == largest_pn) {
            // Note: original used pn_recv from history scan
            ack_delay_ms = now - (history_entry[1] as int);
            break;
          }
        }

        var delay_ns = ack_delay_ms * 1000000;
        var ack_delay_raw = (delay_ns / (1 << conn.remote_ack_delay_exponent))
            .floor();

        var ack_frame = build_ack_info_from_ranges(
          conn.receiving_app_pn_pending_ack,
          null,
          ack_delay_raw,
        );
        encoded_frames.add(encode_quic_frames([ack_frame]));

        remove_pending_ack = List.from(conn.receiving_app_pn_pending_ack);
      }

      var active_stream_count =
          server.connections[quic_connection_id].sending_streams.length;
      var per_stream_bytes = active_stream_count > 0
          ? (allowed_packet_size / active_stream_count).floor()
          : 0;

      server.connections[quic_connection_id].sending_streams.forEach((
        stream_id,
        stream_val,
      ) {
        var result = get_quic_stream_chunks_to_send(
          server,
          quic_connection_id,
          int.parse(stream_id.toString()),
          per_stream_bytes,
        );
        var chunks = result.chunks;
        var send_offset_next = result.send_offset_next;

        if (chunks.length > 0) {
          List<int> chunks_ranges = [];
          for (var i = 0; i < chunks.length; i++) {
            var is_fin = false;
            if (chunks[i].offset + chunks[i].data.length >=
                server
                    .connections[quic_connection_id]
                    .sending_streams[stream_id]['total_size']) {
              is_fin = true;
            }

            var stream_frame = {
              'type': 'stream',
              'id': int.parse(stream_id.toString()),
              'offset': chunks[i].offset,
              'fin': is_fin,
              'data': chunks[i].data,
            };

            encoded_frames.add(encode_quic_frames([stream_frame]));
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

        send_quic_packet(server, quic_connection_id, '1rtt', all_encoded_frames, (
          bool is_sent,
        ) {
          if (is_sent == true) {
            now = DateTime.now().millisecondsSinceEpoch;
            var packet_number =
                server.connections[quic_connection_id].sending_app_pn_base;

            conn.sending_app_pn_history.add([now, all_encoded_frames.length]);
            conn.sending_app_pn_in_flight.add(packet_number);

            update_streams.forEach((stream_id, data) {
              server
                      .connections[quic_connection_id]
                      .sending_streams[stream_id]['in_flight_ranges'][packet_number] =
                  data['chunks_ranges'];
              server
                      .connections[quic_connection_id]
                      .sending_streams[stream_id]['send_offset_next'] =
                  data['send_offset_next'];
            });

            if (remove_pending_ack.isNotEmpty) {
              flat_ranges.remove(
                conn.receiving_app_pn_pending_ack,
                remove_pending_ack as List<int>,
              );
            }

            server.connections[quic_connection_id].sending_app_pn_base++;
          }

          conn.next_send_quic_packet_timer = Timer(Duration.zero, () {
            conn.sending_quic_packet_now = false;
            conn.next_send_quic_packet_timer = null;
            prepare_and_send_quic_packet(server, quic_connection_id);
          });
        });
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
  dynamic server,
  dynamic quic_connection_id,
) {
  if (server.connections.containsKey(quic_connection_id) == true) {
    var conn = server.connections[quic_connection_id];

    // Iterating through receiving_streams map
    for (var stream_id in conn.receiving_streams.keys.toList()) {
      var current_stream = conn.receiving_streams[stream_id];

      if (current_stream['need_check'] == true) {
        current_stream['need_check'] = false;

        var stream_type = null;

        // Check against known H3 stream IDs
        if (conn.h3_remote_control_stream_id ==
            int.parse(stream_id.toString())) {
          stream_type = 0;
        } else if (conn.h3_remote_qpack_encoder_stream_id ==
            int.parse(stream_id.toString())) {
          stream_type = 2;
        } else if (conn.h3_remote_qpack_decoder_stream_id ==
            int.parse(stream_id.toString())) {
          stream_type = 3;
        }

        if (current_stream['receiving_ranges'].length >= 2) {
          int s_id = int.parse(stream_id.toString());
          bool is_unidirectional = (s_id % 2 == 0) != (s_id % 4 == 0);

          if (is_unidirectional) {
            if (stream_type == null &&
                current_stream['receiving_chunks'].containsKey(0)) {
              var first_byte = current_stream['receiving_chunks'][0][0];

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
            current_stream['receiving_chunks'],
            conn.h3_remote_control_from_offset,
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
            current_stream['receiving_chunks'],
            conn.h3_remote_qpack_encoder_from_offset,
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
            current_stream['receiving_chunks'],
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

                      set_sending_quic_chunk(server, quic_connection_id, {
                        'type': '1rtt',
                        'stream_id': int.parse(stream_id.toString()),
                        'fin': false,
                        'data': http3_response,
                      });

                      var wt = create_wt_session_object(
                        server,
                        quic_connection_id,
                        stream_id,
                        headers,
                      );
                      conn.h3_wt_sessions[stream_id] = wt;
                      server._webtransport_handler(wt);
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
                    server._handler(req, res);
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
          int.parse(stream_id.toString()),
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
        int.parse(stream_id.toString()),
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
          int.parse(stream_id.toString()),
          http3_response,
          true,
        );
      } else {
        quic_stream_write(
          server,
          quic_connection_id,
          int.parse(stream_id.toString()),
          Uint8List(0),
          true,
        );
      }
    },
  };
}

dynamic get_quic_stream_chunks_to_send(
  dynamic server,
  String quic_connection_id,
  int stream_id,
  int allowed_bytes,
) {
  var conn = server.connections[quic_connection_id];
  if (conn == null) return null;

  var stream = conn.sending_streams[stream_id];
  if (stream == null || stream.pending_data == null) {
    return {
      'chunks': [],
      'send_offset_next': stream != null ? stream.send_offset_next : 0,
    };
  }

  // Determine total size of the stream
  int total_bytes = (stream.total_size is int)
      ? stream.total_size
      : stream.write_offset_next;

  int base_offset = stream.pending_offset_start;
  int send_offset_next = stream.send_offset_next;

  // relative_missing: Inverting acked ranges to find "holes" (gaps) in the data
  // Assuming flat_ranges.invert is a helper available in your project
  List<int> relative_missing = flat_ranges.invert(
    stream.acked_ranges,
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
        Uint8List chunk_data = stream.pending_data.sublist(rel_start, rel_end);

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
        Uint8List chunk_data = stream.pending_data.sublist(rel_start, rel_end);

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
  dynamic server,
  String quicConnectionId,
  Map<String, dynamic> frame,
) {
  if (server.connections.containsKey(quicConnectionId)) {
    var conn = server.connections[quicConnectionId];

    // Convert ACK frame info into a list of flat ranges [start, end, start, end...]
    List<int> ackedRanges = quic_acked_info_to_ranges(frame);

    /* 1) RTT and Throughput Estimation */
    if (frame.containsKey('largest') && frame.containsKey('delay')) {
      int largestPn = frame['largest'];

      if (conn.sending_app_pn_in_flight.contains(largestPn)) {
        // Current timestamp in milliseconds
        int now = DateTime.now().millisecondsSinceEpoch;

        int ackDelayRaw = frame['delay'];
        // ACK delay is encoded; multiply by 2^ack_delay_exponent (usually 3)
        int ackDelayMs = ((ackDelayRaw * 8) / 1000).round();

        // Calculate index in the history buffer based on packet number
        int pnIndex =
            (largestPn -
                    (conn.sending_app_pn_base -
                        conn.sending_app_pn_history.length))
                .toInt();

        if (pnIndex >= 0 && pnIndex < conn.sending_app_pn_history.length) {
          var entry = conn.sending_app_pn_history[pnIndex];
          int startTime = entry[0]; // Time when this packet was originally sent

          int receivedTimeEstimate = now - ackDelayMs;
          int measuredRtt = now - startTime - ackDelayMs;

          // Calculate bandwidth sent during this RTT window
          int sentBytesDuring = 0;
          int sentPacketsDuring = 0;
          for (int i = pnIndex; i < conn.sending_app_pn_history.length; i++) {
            var historyEntry = conn.sending_app_pn_history[i];
            if (receivedTimeEstimate >= historyEntry[0]) {
              sentBytesDuring += (historyEntry[1] as int);
              sentPacketsDuring++;
            }
          }

          // Calculate bandwidth received by us during the same window
          int receivedBytesDuring = 0;
          int receivedPacketsDuring = 0;
          for (var entry in conn.receiving_app_pn_history) {
            int tsRecv = entry[1];
            int sizeRecv = entry[2];
            if (tsRecv > receivedTimeEstimate) {
              break;
            } else if (tsRecv >= startTime) {
              receivedBytesDuring += sizeRecv;
              receivedPacketsDuring++;
            }
          }

          // Record RTT history if it's a new unique measurement
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
    }

    /* 2) Update In-Flight and Acknowledged Data */
    // Iterate through a copy of the set to allow deletion while looping
    var pnsInFlight = List<int>.from(conn.sending_app_pn_in_flight);

    for (int pn in pnsInFlight) {
      bool isAcked = false;
      for (int i = 0; i < ackedRanges.length; i += 2) {
        if (pn >= ackedRanges[i] && pn <= ackedRanges[i + 1]) {
          isAcked = true;
          break;
        }
      }

      if (isAcked) {
        // Remove from global in-flight tracking
        conn.sending_app_pn_in_flight.remove(pn);

        // Update specific streams associated with this packet
        List<dynamic> streamIds = conn.sending_streams.keys.toList();
        for (var streamId in streamIds) {
          var stream = conn.sending_streams[streamId];

          if (stream.containsKey('in_flight_ranges') &&
              stream['in_flight_ranges'].containsKey(pn)) {
            // Add the bytes that were in this packet to the acked_ranges for the stream
            var rangeToAck = stream['in_flight_ranges'][pn];
            flat_ranges.add(stream['acked_ranges'], rangeToAck);

            // Clear the tracking for this packet on this stream
            stream['in_flight_ranges'].remove(pn);

            // Check if stream is fully acknowledged
            if (stream['acked_ranges'].length == 2 &&
                stream.containsKey('total_size') &&
                stream['total_size'] > 0) {
              if (stream['acked_ranges'][0] == 0 &&
                  stream['acked_ranges'][1] == stream['total_size']) {
                // Stream is 100% complete and acknowledged by peer
                conn.sending_streams.remove(streamId);
              }
            }
          }
        }
      }
    }
  }
}

class QuicServer {
  RawDatagramSocket? _udp4;
  RawDatagramSocket? _udp6;
  int? _port;

  // Handlers
  Function? _handler;
  Function? _webtransport_handler;
  final Function? sniCallback;

  // Connection state
  final Map<String, dynamic> connections = {};
  final Map<String, dynamic> addressBinds = {};

  QuicServer({Map<String, dynamic>? options})
    : sniCallback = options?['SNICallback'];

  /// Starts the QUIC server on the specified port and host
  Future<void> listen(
    int port, [
    String host = '::',
    Function? callback,
  ]) async {
    _port = port;

    // 1. Setup IPv4 Socket
    if (host == '::' || host.contains('.')) {
      String host4 = host.contains('.')
          ? host
          : InternetAddress.anyIPv4.address;
      _udp4 = await RawDatagramSocket.bind(host4, _port!);

      _udp4?.listen((RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          Datagram? dg = _udp4?.receive();
          if (dg != null) {
            _receivingUdpQuicPacket(dg.address.address, dg.port, dg.data);
          }
        }
      });
    }

    // 2. Setup IPv6 Socket
    String host6 = host.contains(':') ? host : InternetAddress.anyIPv6.address;
    _udp6 = await RawDatagramSocket.bind(InternetAddress.anyIPv4, _port!);

    _udp6?.listen((RawSocketEvent event) {
      if (event == RawSocketEvent.read) {
        Datagram? dg = _udp6?.receive();
        if (dg != null) {
          _receivingUdpQuicPacket(dg.address.address, dg.port, dg.data);
        }
      }
    });

    if (callback != null) {
      callback();
    }
  }

  /// Internal dispatcher for incoming UDP packets
  void _receivingUdpQuicPacket(String address, int port, Uint8List msg) {
    // This calls the global packet processing logic translated previously
    receiving_udp_quic_packet(this, address, port, msg);
  }

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
QuicServer createServer(Map<String, dynamic> options, [Function? handler]) {
  var server = QuicServer(options: options);
  if (handler != null) {
    server.on('request', handler);
  }
  return server;
}

void receiving_udp_quic_packet(
  dynamic server,
  String from_ip,
  int from_port,
  Uint8List udp_packet_data,
) {
  // 1. Parse the raw UDP datagram into individual QUIC packets
  // This calls your previously translated parse_quic_datagram logic
  List<Map<String, dynamic>?> quic_packets = parse_quic_datagram(
    udp_packet_data,
  );

  if (quic_packets.isEmpty) return;

  for (var packet in quic_packets) {
    if (packet == null) continue;

    String? quic_connection_id;
    String? dcid_str;

    // 2. Extract Destination Connection ID (DCID) as a hex string if it exists
    if (packet.containsKey('dcid') &&
        packet['dcid'] != null &&
        (packet['dcid'] as Uint8List).isNotEmpty) {
      dcid_str = (packet['dcid'] as Uint8List)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
    }

    // 3. Identify the Connection ID
    if (dcid_str != null) {
      // If we already know this DCID, use it
      if (server.connections.containsKey(dcid_str)) {
        quic_connection_id = dcid_str;
      }
    } else {
      // Fallback: Check if this IP:Port is bound to an existing connection
      String address_str = "$from_ip:$from_port";
      if (server.address_binds.containsKey(address_str)) {
        String existing_cid = server.address_binds[address_str];
        if (server.connections.containsKey(existing_cid)) {
          quic_connection_id = existing_cid;
        }
      }
    }

    // 4. Handle New or Unknown Connections
    if (quic_connection_id == null) {
      if (dcid_str != null) {
        quic_connection_id = dcid_str;
      } else {
        // Generate a random ID if no DCID is present (e.g., specific Short Headers)
        // Using a 53-bit range to mirror JavaScript's MAX_SAFE_INTEGER
        var rng = Random();
        quic_connection_id =
            (rng.nextInt(1 << 31).toString() + rng.nextInt(1 << 31).toString());
      }
    }

    // 5. Build parameters for the connection state machine
    Map<String, dynamic> build_params = {
      'from_ip': from_ip,
      'from_port': from_port,
    };

    if (packet.containsKey('dcid') && packet['dcid'] != null) {
      build_params['dcid'] = packet['dcid'];
    }

    if (packet.containsKey('scid') && packet['scid'] != null) {
      build_params['scid'] = packet['scid'];
    }

    if (packet.containsKey('version') && packet['version'] != null) {
      build_params['version'] = packet['version'];
    }

    // 6. Map the packet types (Initial, Handshake, 1-RTT)
    String type = packet['type'];
    if (type == 'initial' || type == 'handshake' || type == '1rtt') {
      build_params['incoming_packet'] = {
        'type': type,
        'data': packet['raw'], // The raw encrypted/protected bytes
      };
    }

    // 7. Hand over to the connection manager
    set_quic_connection(server, quic_connection_id!, build_params);
  }
}
