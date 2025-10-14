import 'dart:async';
import 'dart:typed_data';

import 'dart:math';

import 'package:hex/hex.dart'; // Assumed to be used for hex encoding/decoding

// Assuming existence of this function for Uint8List content comparison
bool listEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Mock/Placeholder for the flat-ranges utility
class FlatRanges {
  static bool add(List<int> existingRanges, List<int> newRange) {
    // Complex logic is mocked here. Assumes addition is successful for flow control.
    existingRanges.addAll(newRange);
    return true;
  }
}

enum ConnectionStatus { connecting, connected, disconnected }

class QuicConnection {
  var receiving_handshake_chunks;

  var connection_status;

  var sni;

  var from_ip;

  var from_port;

  var version;

  var original_dcid;

  var their_cids;

  List tls_transcript = [];

  Map receiving_init_chunks = {};

  var init_read_key;

  Uint8List? init_read_iv;

  Uint8List? init_read_hp;

  int receiving_init_pn_largest = -1;

  var handshake_read_key;

  Uint8List? handshake_read_iv;

  Uint8List? handshake_read_hp;

  var tls_client_handshake_traffic_secret;

  int receiving_handshake_pn_largest = -1;

  var app_read_key;

  Uint8List? app_read_iv;

  Uint8List? app_read_hp;

  var tls_client_app_traffic_secret;

  int receiving_app_pn_largest = -1;

  var receiving_init_pn_ranges;

  var receiving_handshake_pn_ranges;

  var receiving_app_pn_ranges;

  var receiving_init_ranges;

  var receiving_handshake_ranges;

  var receiving_streams;

  var h3_wt_sessions;

  List<int> sending_init_pn_acked_ranges = [];

  List<int> sending_handshake_pn_acked_ranges = [];

  var receiving_app_pn_history;

  List<int> receiving_app_pn_pending_ack = [];

  int receiving_init_from_offset = 0;

  int receiving_handshake_from_offset = 0;

  var receiving_streams_next_check_timer;
}

// Mock for external dependency objects
final sha256 = (outputLen: 32);

class Options {
  Options({this.connection_status});
  var from_ip;

  var from_port;

  var version;

  var dcid;

  var scid;

  var sni;

  var connection_status;

  var incoming_packet;

  var cert;

  var key;
}

// Placeholders for external functions used in the flow (full implementation required elsewhere)
dynamic quic_derive_init_secrets(
  Uint8List dcid,
  int version,
  String direction,
) => throw UnimplementedError();
dynamic quic_derive_from_tls_secrets(Uint8List secret, dynamic hashFunc) =>
    throw UnimplementedError();
dynamic decrypt_quic_packet(
  Uint8List array,
  Uint8List key,
  Uint8List iv,
  Uint8List hp,
  Uint8List dcid,
  int largestPn,
) => throw UnimplementedError();
dynamic parse_quic_frames(Uint8List plaintext) => throw UnimplementedError();
dynamic quic_acked_info_to_ranges(dynamic ackFrame) =>
    throw UnimplementedError();
void process_ack_frame(QuicServer server, Uint8List id, dynamic frame) =>
    throw UnimplementedError();
dynamic build_ack_info_from_ranges(List<int> ranges, dynamic delay, int ecn) =>
    throw UnimplementedError();
void prepare_and_send_quic_packet(QuicServer server, Uint8List id) =>
    throw UnimplementedError();
void send_quic_frames_packet(
  QuicServer server,
  Uint8List id,
  String type,
  List<dynamic> frames,
) => throw UnimplementedError();
dynamic extract_tls_messages_from_chunks(dynamic chunks, int offset) =>
    throw UnimplementedError();
void process_quic_tls_message(QuicServer server, Uint8List id, dynamic msg) =>
    throw UnimplementedError();
void process_quic_receiving_streams(QuicServer server, Uint8List id) =>
    throw UnimplementedError();
void quic_connection(
  QuicServer server,
  Uint8List quic_connection_id, {
  ConnectionStatus? connection_status,
  String? sni,
  dynamic prev_params,
}) {}
dynamic parse_webtransport_datagram(Uint8List data) =>
    throw UnimplementedError();

void set_quic_connection(
  QuicServer server,
  Uint8List quic_connection_id,
  Options options,
) {
  // Dart local variable for easier access
  QuicConnection? connection = server.connections[quic_connection_id];
  bool is_modified = false;

  // 1. Connection Initialization
  if (connection == null) {
    connection = QuicConnection();
    server.connections[quic_connection_id] = connection;
    is_modified = true;
  }

  // Pre-update parameters for the callback (quic_connection)
  final prev_params = (
    connection_status: connection.connection_status,
    sni: connection.sni,
  );

  // 2. Options Update (Connection Parameter Overwrites)
  {
    // Fix: access using `connection`
    final conn = connection;

    if (options.from_ip != null && conn.from_ip != options.from_ip) {
      conn.from_ip = options.from_ip;
      is_modified = true;
    }

    if (options.from_port != null && conn.from_port != options.from_port) {
      conn.from_port = options.from_port;
      is_modified = true;
    }

    if (options.version != null && conn.version != options.version) {
      conn.version = options.version!;
      is_modified = true;
    }

    // DCID (Original) Update
    if (options.dcid != null && options.dcid!.isNotEmpty) {
      if (conn.original_dcid == null ||
          conn.original_dcid!.isEmpty ||
          !listEquals(options.dcid!, conn.original_dcid!)) {
        conn.original_dcid = options.dcid;
        is_modified = true;
      }
    }

    // SCID (Peer's DCID) Update
    if (options.scid != null && options.scid!.isNotEmpty) {
      bool is_scid_exist = conn.their_cids.any(
        (cid) => listEquals(options.scid!, cid),
      );

      if (is_scid_exist == false) {
        conn.their_cids.add(options.scid!);
        is_modified = true;
      }
    }

    if (options.sni != null && conn.sni != options.sni) {
      conn.sni = options.sni;
      is_modified = true;
    }

    // Connection Status Update (and cleanup for transition to connected)
    if (options.connection_status != null &&
        conn.connection_status != options.connection_status) {
      conn.connection_status = options.connection_status!;
      is_modified = true;

      // Cleanup on transition to Connected (JS: connection_status==1)
      if (conn.connection_status == ConnectionStatus.connected) {
        conn.tls_transcript = [];
        // Assuming dynamic map types here
        conn.receiving_init_chunks = {};
        conn.receiving_handshake_chunks = {};
      }
    }
  }

  // 3. Post-Update and Event Dispatch
  if (is_modified == true) {
    final conn = connection!;

    // Address Binding (Fixes required assuming QuicServer.address_binds is a Map)
    if (conn.from_ip != null && conn.from_port != null) {
      final address_str = '${conn.from_ip}:${conn.from_port}';
      if (server.address_binds[address_str] == null ||
          !listEquals(server.address_binds[address_str]!, quic_connection_id)) {
        server.address_binds[address_str] = quic_connection_id;
      }
    }

    // External event handler call (quic_connection)
    quic_connection(
      server,
      quic_connection_id,
      connection_status: conn.connection_status,
      sni: conn.sni,
      prev_params: prev_params,
    );
  }

  // 4. TLS Certificate and Signing Logic (Skipped for portability)
  if (options.cert != null && options.key != null) {
    // WARNING: This section relies on complex, platform-dependent APIs (crypto.X509Certificate,
    // crypto.createPrivateKey, crypto.sign, TextEncoder, Buffer) not available in standard Dart.
    // A complete port requires integrating packages for X.509 parsing, key loading,
    // and PKI signing (e.g., using FFI or highly specialized Dart crypto libraries).

    // The original logic would proceed to:
    // 1. Build and send the Server Certificate.
    // 2. Build and send the CertificateVerify message (involves private key signing).
    // 3. Build and send the Finished message.
    // 4. Derive the 1-RTT Application Traffic Secrets.
  }

  // 5. Incoming Packet Processing Logic
  if (options.incoming_packet != null) {
    final incomingPacket = options.incoming_packet as Map<String, dynamic>;

    if (incomingPacket['type'] != null) {
      final conn = connection!;

      Uint8List? read_key;
      Uint8List? read_iv;
      Uint8List? read_hp;
      int largest_pn = -1;
      final packetType = incomingPacket['type'] as String;

      // --- Key and Largest PN Selection ---
      if (packetType == 'initial') {
        if (conn.init_read_key != null) {
          read_key = conn.init_read_key;
          read_iv = conn.init_read_iv;
          read_hp = conn.init_read_hp;
        } else if (conn.original_dcid != null) {
          final d = quic_derive_init_secrets(
            conn.original_dcid!,
            conn.version,
            'read',
          );
          read_key = d.key as Uint8List;
          read_iv = d.iv as Uint8List;
          read_hp = d.hp as Uint8List;
          conn.init_read_key = read_key;
          conn.init_read_iv = read_iv;
          conn.init_read_hp = read_hp;
        }
        largest_pn = conn.receiving_init_pn_largest;
      } else if (packetType == 'handshake') {
        if (conn.handshake_read_key != null) {
          read_key = conn.handshake_read_key;
          read_iv = conn.handshake_read_iv;
          read_hp = conn.handshake_read_hp;
        } else if (conn.tls_client_handshake_traffic_secret != null) {
          final d = quic_derive_from_tls_secrets(
            conn.tls_client_handshake_traffic_secret!,
            sha256,
          );
          read_key = d.key as Uint8List;
          read_iv = d.iv as Uint8List;
          read_hp = d.hp as Uint8List;
          conn.handshake_read_key = read_key;
          conn.handshake_read_iv = read_iv;
          conn.handshake_read_hp = read_hp;
        }
        largest_pn = conn.receiving_handshake_pn_largest;
      } else if (packetType == '1rtt') {
        if (conn.app_read_key != null) {
          read_key = conn.app_read_key;
          read_iv = conn.app_read_iv;
          read_hp = conn.app_read_hp;
        } else if (conn.tls_client_app_traffic_secret != null) {
          final d = quic_derive_from_tls_secrets(
            conn.tls_client_app_traffic_secret!,
            sha256,
          );
          read_key = d.key as Uint8List;
          read_iv = d.iv as Uint8List;
          read_hp = d.hp as Uint8List;
          conn.app_read_key = read_key;
          conn.app_read_iv = read_iv;
          conn.app_read_hp = read_hp;
        }
        largest_pn = conn.receiving_app_pn_largest;
      }

      // --- Decryption and Authentication ---
      if (read_key != null && read_iv != null && conn.original_dcid != null) {
        final decrypted_packet = decrypt_quic_packet(
          incomingPacket['data'] as Uint8List,
          read_key,
          read_iv,
          read_hp!,
          conn.original_dcid!,
          largest_pn,
        );

        if (decrypted_packet != null &&
            decrypted_packet.plaintext != null &&
            decrypted_packet.plaintext!.isNotEmpty) {
          bool need_check_tls_chunks = false;
          bool is_new_packet = false;
          bool need_check_receiving_streams = false;
          final packetNumber = decrypted_packet.packetNumber as int;

          // --- Packet Number Recording (PN Range Update) ---
          List<int> pnRanges = packetType == 'initial'
              ? conn.receiving_init_pn_ranges
              : packetType == 'handshake'
              ? conn.receiving_handshake_pn_ranges
              : conn.receiving_app_pn_ranges;

          is_new_packet = FlatRanges.add(pnRanges, [
            packetNumber,
            packetNumber,
          ]);

          // Update largest PN
          if (packetType == 'initial' &&
              conn.receiving_init_pn_largest < packetNumber) {
            conn.receiving_init_pn_largest = packetNumber;
          } else if (packetType == 'handshake' &&
              conn.receiving_handshake_pn_largest < packetNumber) {
            conn.receiving_handshake_pn_largest = packetNumber;
          } else if (packetType == '1rtt') {
            if (conn.receiving_app_pn_largest < packetNumber) {
              conn.receiving_app_pn_largest = packetNumber;
            }
            // Status transition on 1-RTT packet arrival
            if (conn.connection_status != ConnectionStatus.connected) {
              set_quic_connection(
                server,
                quic_connection_id,
                Options(connection_status: ConnectionStatus.connected),
              );
            }
          }

          // --- Frame Processing ---
          if (is_new_packet == true) {
            bool ack_eliciting = false;
            final frames = parse_quic_frames(
              decrypted_packet.plaintext! as Uint8List,
            );

            for (final frame in frames) {
              final frameType = frame.type as String;

              // Determine if frame is ACK-eliciting
              if (!ack_eliciting &&
                  (frameType == 'stream' ||
                      frameType == 'crypto' ||
                      frameType == 'new_connection_id' ||
                      frameType == 'handshake_done' ||
                      frameType == 'path_challenge' ||
                      frameType == 'path_response' ||
                      frameType == 'ping')) {
                ack_eliciting = true;
              }

              if (frameType == 'crypto') {
                // Crypto frame data aggregation
                final offset = frame.offset as int;
                final data = frame.data as Uint8List;
                dynamic receivingChunks = packetType == 'initial'
                    ? conn.receiving_init_chunks
                    : conn.receiving_handshake_chunks;
                List<int> receivingRanges = packetType == 'initial'
                    ? conn.receiving_init_ranges
                    : conn.receiving_handshake_ranges;

                if (FlatRanges.add(receivingRanges, [
                  offset,
                  offset + data.length,
                ])) {
                  // If new range, update chunk (only if new or larger data)
                  if (receivingChunks[offset] == null ||
                      (receivingChunks[offset] as Uint8List).length <
                          data.length) {
                    receivingChunks[offset] = data;
                  }
                  need_check_tls_chunks = true;
                }
              } else if (frameType == 'stream') {
                // Stream frame data aggregation
                final streamId = frame.id;
                final offset = frame.offset as int;
                final data = frame.data as Uint8List;

                conn.receiving_streams[streamId] ??= {
                  'receiving_chunks': {},
                  'total_size': 0,
                  'receiving_ranges': <int>[],
                  'need_check': false,
                };

                final stream =
                    conn.receiving_streams[streamId] as Map<String, dynamic>;
                if (FlatRanges.add(stream['receiving_ranges'] as List<int>, [
                  offset,
                  offset + data.length,
                ])) {
                  final chunksMap =
                      stream['receiving_chunks'] as Map<dynamic, dynamic>;
                  if (chunksMap[offset] == null ||
                      (chunksMap[offset] as Uint8List).length < data.length) {
                    chunksMap[offset] = data;
                  }

                  if (frame.fin == true) {
                    stream['total_size'] = data.length + offset;
                  }

                  stream['need_check'] = true;
                  need_check_receiving_streams = true;
                }
              } else if (frameType == 'datagram') {
                // WebTransport Datagram
                final wt_datagram = parse_webtransport_datagram(
                  frame.data as Uint8List,
                );
                final session = conn.h3_wt_sessions[wt_datagram.stream_id];
                if (session != null && session.ondatagram is Function) {
                  // session.ondatagram(wt_datagram.data);
                }
              } else if (frameType == 'ack') {
                // ACK Frame processing
                if (packetType == 'initial') {
                  FlatRanges.add(
                    conn.sending_init_pn_acked_ranges,
                    quic_acked_info_to_ranges(frame) as List<int>,
                  );
                } else if (packetType == 'handshake') {
                  FlatRanges.add(
                    conn.sending_handshake_pn_acked_ranges,
                    quic_acked_info_to_ranges(frame) as List<int>,
                  );
                } else if (packetType == '1rtt') {
                  process_ack_frame(server, quic_connection_id, frame);
                }
              }
            }

            // --- Post-Frame Actions and ACK Response ---

            if (packetType == '1rtt') {
              // Add packet to history (for RTT/congestion control)
              final now = DateTime.now().millisecondsSinceEpoch; // Dart Time
              // Original code: [decrypted_packet.packet_number, now, options['incoming_packet']['data'].byteLength]
              conn.receiving_app_pn_history.add(packetNumber);
            }

            if (ack_eliciting == true) {
              final List<dynamic> ack_frame_to_send = [];

              if (packetType == 'initial') {
                ack_frame_to_send.add(
                  build_ack_info_from_ranges(
                    conn.receiving_init_pn_ranges,
                    null,
                    0,
                  ),
                );
              } else if (packetType == 'handshake') {
                ack_frame_to_send.add(
                  build_ack_info_from_ranges(
                    conn.receiving_handshake_pn_ranges,
                    null,
                    0,
                  ),
                );
              } else if (packetType == '1rtt') {
                // Add to pending ACK list
                FlatRanges.add(conn.receiving_app_pn_pending_ack, [
                  packetNumber,
                  packetNumber,
                ]);
                // Prepare and send data/ACK packet immediately
                prepare_and_send_quic_packet(server, quic_connection_id);
              }

              if (ack_frame_to_send.isNotEmpty) {
                // Sends a new QUIC packet containing only the generated ACK frames
                send_quic_frames_packet(
                  server,
                  quic_connection_id,
                  packetType,
                  ack_frame_to_send,
                );
              }
            }
          }

          // --- TLS Message Assembly and Processing ---
          if (need_check_tls_chunks == true) {
            final ext = (packetType == 'initial')
                ? extract_tls_messages_from_chunks(
                    conn.receiving_init_chunks,
                    conn.receiving_init_from_offset,
                  )
                : extract_tls_messages_from_chunks(
                    conn.receiving_handshake_chunks,
                    conn.receiving_handshake_from_offset,
                  );

            for (final msg in ext.tls_messages as List<dynamic>) {
              process_quic_tls_message(server, quic_connection_id, msg);
            }

            if (packetType == 'initial') {
              conn.receiving_init_from_offset = ext.new_from_offset as int;
            } else {
              conn.receiving_handshake_from_offset = ext.new_from_offset as int;
            }
          }

          // --- Stream Processing Timer ---
          if (need_check_receiving_streams == true) {
            conn.receiving_streams_next_check_timer ??= Timer(
              Duration(milliseconds: 5),
              () {
                conn.receiving_streams_next_check_timer = null;
                process_quic_receiving_streams(server, quic_connection_id);
              },
            );
          }
        }
      }
    }
  }
}

// / --- Placeholder Classes/Types (Must be defined elsewhere in your project) ---

/// Defines the structure of a simplified QUIC packet parsed from the datagram.
/// Using a map is pragmatic if the structure is dynamic, but classes are preferred.
typedef QuicPacket = Map<String, dynamic>;

/// Represents the QUIC server object.
class QuicServer {
  // Key: DCID in hex string format (e.g., 'a1b2c3d4')
  // Value: The QuicConnection object (dynamic for this example)
  final Map<Uint8List, dynamic> connections = {};

  // Key: IP:Port string (e.g., '192.168.1.1:12345')
  // Value: DCID in hex string format
  final Map<String, String> addressBinds = {};

  var address_binds;
}

// --- Required External Functions (Must be defined elsewhere) ---

// Needs to be implemented to parse one or more QUIC packets from a UDP datagram.
List<QuicPacket> parseQuicDatagram(Uint8List udpPacketData) {
  // Placeholder implementation
  return [];
}

// Needs to be implemented to create or update a QUIC connection object.
vvoid setQuicConnection(String quicConnectionId, Map<String, dynamic> options) {
    bool isModified = false;

    if (!connections.containsKey(quicConnectionId)) {
      connections[quicConnectionId] = QuicConnection();
      isModified = true;
    }

    var connection = connections[quicConnectionId]!;
    
    // Backup previous parameters for event
    var prevParams = {
      'connection_status': connection.connectionStatus,
      'sni': connection.sni
    };

    // ... (Logic to update connection properties, setting isModified = true if changes occur) ...

    Uint8List? dcid = options['dcid'] as Uint8List?;
    if (dcid != null && dcid.isNotEmpty) {
      // Dart: Use uint8ListEqual helper to compare Uint8List content
      if (connection.originalDcid == null || !uint8ListEqual(dcid, connection.originalDcid!)) {
        connection.originalDcid = dcid;
        isModified = true;
      }
    }

    // ... (rest of property updates) ...
    
    if (isModified) {
      var addressStr = '${connection.fromIp}:${connection.fromPort}';
      addressBinds[addressStr] = quicConnectionId;
      
      quicConnection(quicConnectionId,
          {'connection_status': connection.connectionStatus, 'sni': connection.sni},
          prevParams);
    }

    // TLS Certificate and Key handling (Highly dependent on Dart's crypto libraries like PointyCastle)
    if (options.containsKey('cert') && options.containsKey('key')) {
      /* // This section requires specific Dart/Flutter packages for X509 parsing, 
      // signing (e.g., package:pointycastle, package:cryptography) and HMAC/Hashing.
      // The logic flow remains the same, but the function calls are different:
      
      // 1. Get cipher info (hash function)
      // var cipherInfo = getCipherInfo(connection.tlsCipherSelected);
      // var hashFunc = cipherInfo['hash']; 

      // 2. Build Certificate Message (Uint8List certDer = ...; assuming buildCertificate is available)
      // var certificate = buildCertificate([{'cert': certDer, 'extensions': Uint8List(0)}]);
      // connection.tlsTranscript.add(certificate);
      // setSendingQuicChunk(quicConnectionId, {'type': 'handshake', 'data': certificate});

      // 3. Build Certificate Verify Message
      // var privateKeyObj = // ... parse key
      // var label = Uint8List.fromList(utf8.encode('TLS 1.3, server CertificateVerify'));
      // var separator = Uint8List.fromList([0x00]);
      // var handshakeHash = hashTranscript(connection.tlsTranscript, hashFunc);
      // var padding = Uint8List.fromList(List.filled(64, 0x20));
      // var signedData = concatUint8Arrays([padding, label, separator, handshakeHash]);

      // 4. Compute Signature (using Dart crypto libraries and chosen algorithm)
      // var signature = // ... signature logic ...
      
      // var certificateVerify = buildCertificateVerify(algoCandidate, signature);
      // setSendingQuicChunk(quicConnectionId, {'type': 'handshake', 'data': certificateVerify});
      */
    }
  }

// --- The Ported Dart Function ---

/// Processes an incoming UDP datagram containing one or more QUIC packets.
void receivingUdpQuicPacket(
  QuicServer server,
  String fromIp,
  int fromPort,
  Uint8List udpPacketData,
) {
  final List<QuicPacket> quicPackets = parseQuicDatagram(udpPacketData);
  final Random random = Random.secure();

  if (quicPackets.isNotEmpty) {
    for (final quicPacket in quicPackets) {
      if (quicPacket.isNotEmpty) {
        dynamic quicConnectionId;
        String? dcidStr;

        // 1. Get DCID as Hex String
        if (quicPacket.containsKey('dcid') &&
            quicPacket['dcid'] is Uint8List &&
            (quicPacket['dcid'] as Uint8List).isNotEmpty) {
          Uint8List dcidBytes = quicPacket['dcid'] as Uint8List;
          // In Dart, we use the `hex` package to convert Uint8List to hex string.
          dcidStr = HEX.encode(dcidBytes);
        }

        // 2. Find existing connection ID
        if (dcidStr != null) {
          // Check for connection by DCID
          if (server.connections.containsKey(dcidStr)) {
            quicConnectionId = dcidStr;
          }
        } else {
          // Fallback: check for connection by IP:Port binding (stateless reset/initial handshake)
          final String addressStr = '$fromIp:$fromPort';
          if (server.addressBinds.containsKey(addressStr)) {
            final String connId = server.addressBinds[addressStr]!;
            if (server.connections.containsKey(connId)) {
              quicConnectionId = connId;
            }
          }
        }

        // 3. Assign new connection ID if none found
        if (quicConnectionId == null) {
          if (dcidStr != null) {
            // Use the DCID for a new connection (Initial packet)
            quicConnectionId = dcidStr;
          } else {
            // Generate a large random number as a temporary ID (unbound connection)
            // Using MAX_SAFE_INTEGER equivalent: 2^53 - 1
            quicConnectionId = random.nextInt(9007199254740991);
          }
        }

        // 4. Build parameters for connection handler
        final Map<String, dynamic> buildParams = {
          'from_ip': fromIp,
          'from_port': fromPort,
        };

        if (quicPacket.containsKey('dcid') &&
            quicPacket['dcid'] is Uint8List &&
            (quicPacket['dcid'] as Uint8List).isNotEmpty) {
          buildParams['dcid'] = quicPacket['dcid'];
        }

        if (quicPacket.containsKey('scid') &&
            quicPacket['scid'] is Uint8List &&
            (quicPacket['scid'] as Uint8List).isNotEmpty) {
          buildParams['scid'] = quicPacket['scid'];
        }

        if (quicPacket.containsKey('version') &&
            quicPacket['version'] != null) {
          buildParams['version'] = quicPacket['version'];
        }

        // 5. Package the incoming packet data
        final String? packetType = quicPacket['type'] as String?;
        final Uint8List? rawData = quicPacket['raw'] as Uint8List?;

        if (packetType != null && rawData != null) {
          if (['initial', 'handshake', '1rtt'].contains(packetType)) {
            buildParams['incoming_packet'] = {
              'type': packetType,
              'data': rawData,
            };
          }
        }

        // 6. Dispatch to the connection handler
        setQuicConnection(server, quicConnectionId, buildParams);
      }
    }
  }
}
