This port translates the provided JavaScript QUIC/HTTP/3 server logic into idiomatic Dart, utilizing class definitions for structured state management (replacing JavaScript objects) and Dart conventions (like camelCase).

Since Dart does not have built-in equivalents for all Node.js/QUIC-specific cryptographic or networking helpers (e.g., crypto.createHmac, parse_quic_datagram, writeVarInt), the functions rely on placeholder types and methods that would need to be implemented using external Dart packages (like package:pointycastle, package:typed_data, and a QUIC/HTTP/3 implementation).

Dart Connection State Class
The new_quic_connection object is ported to the QuicConnectionState class for strong typing and better organization.

Dart

import 'dart:typed_data';
import 'dart:convert';
import 'dart:math'; // For Random()

// --- PLACEHOLDER UTILITIES & CRYPTO ---
// These declarations simulate the required external dependencies (from utils.js, crypto.js, h3.js)
abstract class HashFunc {
  Uint8List call(Uint8List data);
  int get outputLen;
}
class CipherInfo {
  final String str;
  final HashFunc hash;
  CipherInfo(this.str, this.hash);
}
class PrivateKeyPlaceholder {
  final String asymmetricKeyType;
  PrivateKeyPlaceholder(this.asymmetricKeyType);
}
class X509CertificatePlaceholder {
  final Uint8List raw;
  X509CertificatePlaceholder(Uint8List cert) : raw = cert;
}

// Utility Placeholders
Uint8List concatUint8Arrays(List<Uint8List> buffers) => throw UnimplementedError('concatUint8Arrays');
Uint8List writeVarInt(int value) => throw UnimplementedError('writeVarInt');
bool arraybufferEqual(ByteBuffer a, ByteBuffer b) => throw UnimplementedError('arraybufferEqual');
String toHexString(Uint8List data) => throw UnimplementedError('toHexString');
String generateQuicConnectionId() => Random().nextInt(9007199254740991).toString();

// Crypto Placeholders
CipherInfo getCipherInfo(dynamic selectedCipher) => throw UnimplementedError('getCipherInfo');
Uint8List hashTranscript(List<Uint8List> messages, HashFunc hashFunc) => throw UnimplementedError('hashTranscript');
Uint8List hkdfExpandLabel(Uint8List secret, String label, Uint8List context, int length, HashFunc hashFunc) => throw UnimplementedError('hkdfExpandLabel');
dynamic tlsDeriveAppSecrets(Uint8List handshakeSecret, List<Uint8List> transcript, HashFunc hashFunc) => throw UnimplementedError('tlsDeriveAppSecrets');
Uint8List buildCertificate(List<Map<String, dynamic>> certs) => throw UnimplementedError('buildCertificate');
Uint8List buildCertificateVerify(int algo, Uint8List signature) => throw UnimplementedError('buildCertificateVerify');
Uint8List buildFinished(Uint8List verifyData) => throw UnimplementedError('buildFinished');
Uint8List hmac(String hash, Uint8List key, Uint8List data) => throw UnimplementedError('hmac');
Uint8List cryptoSign(String? hash, Uint8List data, dynamic key, [Map<String, dynamic>? options]) => throw UnimplementedError('cryptoSign');
PrivateKeyPlaceholder cryptoCreatePrivateKey(Uint8List key) => throw UnimplementedError('cryptoCreatePrivateKey');
X509CertificatePlaceholder cryptoCreateX509Certificate(Uint8List cert) => throw UnimplementedError('cryptoCreateX509Certificate');

// HTTP/3 & QUIC I/O Placeholders
Uint8List buildHttp3LiteralHeadersFrame(Map<String, dynamic> headers) => throw UnimplementedError('buildHttp3LiteralHeadersFrame');
Uint8List buildH3Frames(List<Map<String, dynamic>> frames) => throw UnimplementedError('buildH3Frames');
void quicStreamWrite(Server server, String quicConnectionId, int streamId, Uint8List data, bool fin) => throw UnimplementedError('quicStreamWrite');
void setSendingQuicChunk(Server server, String quicConnectionId, Map<String, dynamic> chunk) => throw UnimplementedError('setSendingQuicChunk');
void sendQuicFramesPacket(Server server, String quicConnectionId, String encryptionLevel, List<dynamic> frames) => throw UnimplementedError('sendQuicFramesPacket');
dynamic parseQuicDatagram(Uint8List udpPacketData) => throw UnimplementedError('parseQuicDatagram');
dynamic extractH3FramesFromChunks(Map<int, Uint8List> chunks, int offset) => throw UnimplementedError('extractH3FramesFromChunks');
dynamic parseH3SettingsFrame(Uint8List payload) => throw UnimplementedError('parseH3SettingsFrame');
dynamic extractQpackEncoderInstructionsFromChunks(Map<int, Uint8List> chunks, int offset) => throw UnimplementedError('extractQpackEncoderInstructionsFromChunks');
dynamic parseQpackHeaderBlock(Uint8List payload) => throw UnimplementedError('parseQpackHeaderBlock');
Uint8List buildQpackBlockHeaderAck(int streamId) => throw UnimplementedError('buildQpackBlockHeaderAck');
const List<List<String>> qpackStaticTableEntries = []; // Placeholder for the static table data
void quicConnection(Server server, String quicConnectionId, Map<String, dynamic> newParams, Map<String, dynamic> prevParams) { /* Connection event handler */ }
class ReceivingStream {
  bool needCheck = false;
  List<int> receivingRanges = [];
  Map<int, Uint8List> receivingChunks = {};
}

// Minimal Server class to hold connection state
class Server {
  Map<String, QuicConnectionState> connections = {};
  Map<String, dynamic> addressBinds = {};
  Function? _handler; 
  Function? _webtransportHandler; 
}


class QuicConnectionState {
  int connectionStatus = 4;
  String? fromIp;
  int? fromPort;
  int version = 1;
  List<Uint8List> myCids = [];
  List<Uint8List> theirCids = [];
  Uint8List? originalDcid;
  String? sni;
  dynamic tlsCipherSelected;
  dynamic tlsAlpnSelected;
  List<int> tlsSignatureAlgorithms = [];
  Uint8List? tlsHandshakeSecret;
  Uint8List? tlsSharedSecret;
  Uint8List? tlsEarlySecret;
  List<Uint8List> tlsTranscript = [];
  int tlsHandshakeStep = 0;
  bool tlsFinishedOk = false;
  dynamic tlsServerPublicKey;
  dynamic tlsServerPrivateKey;
  Uint8List? tlsClientHandshakeTrafficSecret;
  Uint8List? tlsServerHandshakeTrafficSecret;
  Uint8List? tlsClientAppTrafficSecret;
  Uint8List? tlsServerAppTrafficSecret;
  Uint8List? initReadKey;
  Uint8List? initReadIv;
  Uint8List? initReadHp;
  Uint8List? initWriteKey;
  Uint8List? initWriteIv;
  Uint8List? initWriteHp;
  Uint8List? handshakeReadKey;
  Uint8List? handshakeReadIv;
  Uint8List? handshakeReadHp;
  Uint8List? handshakeWriteKey;
  Uint8List? handshakeWriteIv;
  Uint8List? handshakeWriteHp;
  Uint8List? appPrevReadKey;
  Uint8List? appPrevReadIv;
  Uint8List? appPrevReadHp;
  Uint8List? appReadKey;
  Uint8List? appReadIv;
  Uint8List? appReadHp;
  bool readKeyPhase = false;
  Uint8List? appWriteKey;
  Uint8List? appWriteIv;
  Uint8List? appWriteHp;
  int sendingInitPnNext = 1;
  List<dynamic> sendingInitChunks = [];
  int sendingInitOffsetNext = 0;
  List<dynamic> sendingInitPnAckedRanges = [];
  int sendingHandshakePnNext = 1;
  List<dynamic> sendingHandshakeChunks = [];
  int sendingHandshakeOffsetNext = 0;
  List<dynamic> sendingHandshakePnAckedRanges = [];
  Map<int, dynamic> sendingStreams = {};
  int sendingStreamIdNext = 0;
  int maxSendingPacketsPerSec = 1000;
  int maxSendingTotalBytesPerSec = 150000;
  int maxSendingPacketSize = 1200;
  int minSendingPacketSize = 35;
  int maxSendingPacketsInFlight = 20;
  int maxSendingBytesInFlight = 150000;
  int sendingAppPnBase = 1;
  List<dynamic> sendingAppPnHistory = [];
  List<dynamic> rttHistory = [];
  Set<int> sendingAppPnInFlight = {};
  dynamic nextSendQuicPacketTimer;
  bool sendingQuicPacketNow = false;
  int receivingInitPnLargest = -1;
  List<dynamic> receivingInitPnRanges = [];
  Map<int, Uint8List> receivingInitChunks = {};
  int receivingInitFromOffset = 0;
  List<int> receivingInitRanges = [];
  int receivingHandshakePnLargest = -1;
  List<dynamic> receivingHandshakePnRanges = [];
  Map<int, Uint8List> receivingHandshakeChunks = {};
  int receivingHandshakeFromOffset = 0;
  List<int> receivingHandshakeRanges = [];
  int receivingAppPnLargest = -1;
  List<dynamic> receivingAppPnRanges = [];
  List<dynamic> receivingAppPnHistory = [];
  List<dynamic> receivingAppPnPendingAck = [];
  Map<String, ReceivingStream> receivingStreams = {};
  dynamic receivingStreamsNextCheckTimer;
  int remoteAckDelayExponent = 3;
  int remoteMaxUdpPayloadSize = 1000;
  int? h3RemoteControlStreamId;
  int h3RemoteControlFromOffset = 1;
  int? h3RemoteQpackEncoderStreamId;
  int h3RemoteQpackEncoderFromOffset = 1;
  int? h3RemoteQpackDecoderStreamId;
  int h3RemoteQpackDecoderFromOffset = 1;
  Map<String, dynamic> h3HttpRequestStreams = {};
  int h3RemoteMaxHeaderSize = 0;
  int h3RemoteQpackMaxTableCapacity = 0;
  bool? h3RemoteDatagramSupport;
  int h3RemoteQpackTableBaseIndex = 0;
  int h3RemoteQpackTableCapacity = 0;
  List<List<String>> h3RemoteQpackDynamicTable = [];
  Map<String, dynamic> h3WtSessions = {};

  QuicConnectionState(); // Dart constructor
}
Dart Ported Functions
evictQpackRemoteDynamicTableIfNeeded
Dart

void evictQpackRemoteDynamicTableIfNeeded(Server server, String quicConnectionId) {
  if (server.connections.containsKey(quicConnectionId)) {
    var connection = server.connections[quicConnectionId]!;
    var entries = connection.h3RemoteQpackDynamicTable;
    var capacity = connection.h3RemoteQpackTableCapacity;

    // Calculate total size of all entries in the table
    var totalSize = 0;
    for (var entry in entries) {
      var name = entry[0];
      var value = entry[1];
      totalSize += name.length + value.length + 32; // 32 bytes overhead
    }

    // Evict oldest entries (at the end of the list) until within capacity
    while (totalSize > capacity && entries.isNotEmpty) {
      var removed = entries.removeLast(); // Equivalent to JS Array.pop()
      var removedSize = removed[0].length + removed[1].length + 32;
      totalSize -= removedSize;
    }
  }
}
insertIntoQpackRemoteEncoderDynamicTable
Dart

bool insertIntoQpackRemoteEncoderDynamicTable(Server server, String quicConnectionId, String name, String value) {
  if (server.connections.containsKey(quicConnectionId)) {
    var connection = server.connections[quicConnectionId]!;
    var entrySize = name.length + value.length + 32;

    if (entrySize > connection.h3RemoteQpackTableCapacity) return false;

    // Equivalent to JS Array.unshift()
    connection.h3RemoteQpackDynamicTable.insert(0, [name, value]);
    connection.h3RemoteQpackTableBaseIndex++;

    evictQpackRemoteDynamicTableIfNeeded(server, quicConnectionId);

    return true;
  }
  return false;
}
WebTransportSession Class (Port of create_wt_session_object)
Dart

// A class representing a WebTransport session
class WebTransportSession {
  final int id;
  final String quicConnectionId;
  final Server server;
  Map<String, dynamic> headers;
  
  bool _isOpen = true;

  // Callbacks
  Function(Uint8List)? onmessage;
  Function()? onclose;
  Function(dynamic)? onerror;
  Function(int)? onstream;

  WebTransportSession({
    required this.server,
    required this.quicConnectionId,
    required this.id,
    required this.headers,
  });

  void send(Uint8List data) {
    // Prepend Stream ID as VarInt for WebTransport Datagram format
    final payload = concatUint8Arrays([writeVarInt(id), data]);
    
    // JS: send_quic_frames_packet(server,quic_connection_id,'1rtt',[{ type: 'datagram', data: payload }])
    sendQuicFramesPacket(server, quicConnectionId, '1rtt', [
      {'type': 'datagram', 'data': payload}
    ]);
  }

  void close() {
    _isOpen = false;
    onclose?.call();
    // TODO: Send H/3 CLOSE_WEBTRANSPORT_STREAM Control Frame
  }

  bool get isOpen => _isOpen;
}

WebTransportSession createWtSessionObject(Server server, String quicConnectionId, int streamId, Map<String, dynamic> headers) {
  return WebTransportSession(
    server: server,
    quicConnectionId: quicConnectionId,
    id: streamId,
    headers: headers,
  );
}
QuicHttpResponse Class (Port of build_response_object)
Dart

// A class representing an HTTP/3 Response object
class QuicHttpResponse {
  final Server server;
  final String quicConnectionId;
  final int streamId;
  
  int? statusCode;
  bool headersSent = false;
  dynamic socket; 

  QuicHttpResponse({
    required this.server,
    required this.quicConnectionId,
    required this.streamId,
  });
  
  QuicConnectionState get connection => server.connections[quicConnectionId]!;
  Map<String, dynamic> get requestStreamState => connection.h3HttpRequestStreams['$streamId']!;

  void writeHead(int statusCode, Map<String, dynamic> headers) {
    // Merge new headers
    requestStreamState['response_headers'].addAll(headers);

    // Only send HEADERS frame once
    if (!requestStreamState['response_headers'].containsKey(':status')) {
      requestStreamState['response_headers'][':status'] = statusCode.toString();

      final headersPayload = buildHttp3LiteralHeadersFrame(requestStreamState['response_headers']);
      
      final http3Response = buildH3Frames([
        {'frame_type': 1, 'payload': headersPayload} // Frame Type 1: HEADERS
      ]);

      quicStreamWrite(server, quicConnectionId, streamId, http3Response, false);
      
      headersSent = true;
    }
  }

  void writeEarlyHints(dynamic hints) {
    // JS implementation was empty
  }

  void write(Uint8List chunk) {
    final http3Response = buildH3Frames([
      {'frame_type': 0, 'payload': chunk} // Frame Type 0: DATA
    ]);

    quicStreamWrite(server, quicConnectionId, streamId, http3Response, false);
  }

  void end(Uint8List? chunk) {
    if (chunk != null && chunk.isNotEmpty) {
      final http3Response = buildH3Frames([
        {'frame_type': 0, 'payload': chunk}
      ]);
      quicStreamWrite(server, quicConnectionId, streamId, http3Response, true); // fin: true
    } else {
      quicStreamWrite(server, quicConnectionId, streamId, Uint8List(0), true); // fin: true with empty data
    }
  }
}

QuicHttpResponse buildResponseObject(Server server, String quicConnectionId, int streamId) {
  return QuicHttpResponse(
    server: server,
    quicConnectionId: quicConnectionId,
    streamId: streamId,
  );
}
processQuicReceivingStreams
Dart

void processQuicReceivingStreams(Server server, String quicConnectionId) {
  if (server.connections.containsKey(quicConnectionId)) {
    var connection = server.connections[quicConnectionId]!;

    for (var streamIdStr in connection.receivingStreams.keys) {
      final streamId = int.parse(streamIdStr);
      final stream = connection.receivingStreams[streamIdStr]!;

      if (stream.needCheck) {
        stream.needCheck = false;
        int? streamType;

        // 1. Identify Stream Type (if already known from connection state)
        if (connection.h3RemoteControlStreamId == streamId) {
          streamType = 0;
        } else if (connection.h3RemoteQpackEncoderStreamId == streamId) {
          streamType = 2;
        } else if (connection.h3RemoteQpackDecoderStreamId == streamId) {
          streamType = 3;
        }

        if (stream.receivingRanges.length >= 2) {
          final isUnidirectional = (streamId % 2 == 0) != (streamId % 4 == 0); 
          
          // 2. Identify Stream Type (if unknown and has data)
          if (isUnidirectional) {
            if (streamType == null && stream.receivingChunks.containsKey(0)) {
              final firstByte = stream.receivingChunks[0]![0];
              switch (firstByte) {
                case 0x00: connection.h3RemoteControlStreamId = streamId; streamType = 0; break;
                case 0x01: streamType = 1; break; // Push Stream
                case 0x02: connection.h3RemoteQpackEncoderStreamId = streamId; streamType = 2; break;
                case 0x03: connection.h3RemoteQpackDecoderStreamId = streamId; streamType = 3; break;
              }
            }
          } else {
            streamType = 4; // Bidirectional (HTTP Request/Response)
          }

          // 3. Process Stream Content based on Type
          if (streamType != null) {
            switch (streamType) {
              case 0: // Control Stream
                var ext = extractH3FramesFromChunks(stream.receivingChunks, connection.h3RemoteControlFromOffset);
                connection.h3RemoteControlFromOffset = ext['new_from_offset'] as int;
                List<dynamic> h3Frames = ext['frames'];

                for (var frame in h3Frames) {
                  if (frame['frame_type'] == 4) { // SETTINGS Frame
                    var controlSettings = parseH3SettingsFrame(frame['payload'] as Uint8List);
                    if (controlSettings.containsKey('SETTINGS_QPACK_MAX_TABLE_CAPACITY') && controlSettings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'] > 0) {
                      connection.h3RemoteQpackMaxTableCapacity = controlSettings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'];
                      evictQpackRemoteDynamicTableIfNeeded(server, quicConnectionId);
                    }
                    if (controlSettings.containsKey('SETTINGS_MAX_FIELD_SECTION_SIZE') && controlSettings['SETTINGS_MAX_FIELD_SECTION_SIZE'] > 0) {
                      connection.h3RemoteMaxHeaderSize = controlSettings['SETTINGS_MAX_FIELD_SECTION_SIZE'];
                    }
                    if (controlSettings.containsKey('SETTINGS_H3_DATAGRAM') && controlSettings['SETTINGS_H3_DATAGRAM'] > 0) {
                      connection.h3RemoteDatagramSupport = controlSettings['SETTINGS_H3_DATAGRAM'] > 0;
                    }
                  }
                }
                break;

              case 2: // QPACK Encoder Stream
                var ext = extractQpackEncoderInstructionsFromChunks(stream.receivingChunks, connection.h3RemoteQpackEncoderFromOffset);
                connection.h3RemoteQpackEncoderFromOffset = ext['new_from_offset'] as int;
                List<dynamic> instructions = ext['instructions'];
                
                List<List<String>> inserts = [];

                for (var instruction in instructions) {
                  if (instruction['type'] == 'set_dynamic_table_capacity') {
                    connection.h3RemoteQpackTableCapacity = instruction['capacity'] as int;
                    evictQpackRemoteDynamicTableIfNeeded(server, quicConnectionId);
                  } else if (instruction['type'] == 'insert_with_name_ref' || instruction['type'] == 'insert_without_name_ref') {
                    String? name;
                    String value = instruction['value'] as String;

                    if (instruction['type'] == 'insert_with_name_ref') {
                      int nameIndex = instruction['name_index'] as int;
                      if (instruction['from_static_table'] == true) {
                        if (nameIndex < qpackStaticTableEntries.length) {
                          name = qpackStaticTableEntries[nameIndex][0];
                        }
                      } else {
                        var baseIndex = connection.h3RemoteQpackTableBaseIndex;
                        var dynamicIndex = baseIndex - 1 - nameIndex;
                        var dynamicTable = connection.h3RemoteQpackDynamicTable;

                        if (dynamicIndex >= 0 && dynamicIndex < dynamicTable.length) {
                          name = dynamicTable[dynamicIndex][0];
                        }
                      }
                    } else { 
                      name = instruction['name'] as String;
                    }

                    if (name != null) {
                      inserts.add([name, value]);
                    }
                  }
                }

                if (inserts.isNotEmpty) {
                  for (var insert in inserts) {
                    insertIntoQpackRemoteEncoderDynamicTable(server, quicConnectionId, insert[0], insert[1]);
                  }
                  // TODO: build_qpack_known_received_count(inserts.length);
                }
                break;

              case 3: // QPACK Decoder Stream (no logic provided)
                break;

              case 4: // HTTP/3 Request Stream
                final streamIdStrKey = '$streamId';
                if (!connection.h3HttpRequestStreams.containsKey(streamIdStrKey)) {
                  connection.h3HttpRequestStreams[streamIdStrKey] = {
                    'from_offset': 0, 'response_headers': <String, dynamic>{}, 'header_sent': false, 'response_body': null,
                  };
                }

                var reqState = connection.h3HttpRequestStreams[streamIdStrKey]!;
                var ext = extractH3FramesFromChunks(stream.receivingChunks, reqState['from_offset'] as int);
                reqState['from_offset'] = ext['new_from_offset'] as int;
                List<dynamic> h3Frames = ext['frames'];

                for (var frame in h3Frames) {
                  if (frame['frame_type'] == 1) { // HEADERS Frame (Request)
                    final headers = <String, String>{};
                    final dynamicTable = connection.h3RemoteQpackDynamicTable;
                    final headerBlock = parseQpackHeaderBlock(frame['payload'] as Uint8List);
                    
                    bool usedDynamicRef = false;
                    
                    if ((headerBlock['insert_count'] as int) <= dynamicTable.length) {
                      for (var header in headerBlock['headers']) {
                        // QPACK Decoding logic...
                        if (header['type'] != 'literal_with_literal_name') usedDynamicRef = usedDynamicRef || header['from_static_table'] == false;

                        // Simplified QPACK consumption based on original JS
                        if (header['type'] == 'indexed' || header['type'] == 'literal_with_name_ref') {
                          int index = header['type'] == 'indexed' ? header['index'] : header['name_index'];
                          if (header['from_static_table'] == true) {
                            if (index < qpackStaticTableEntries.length) {
                              headers[qpackStaticTableEntries[index][0]] = header['type'] == 'indexed' ? qpackStaticTableEntries[index][1] : header['value'];
                            }
                          } else {
                            var dynamicIndex = headerBlock['base_index'] as int - 1 - index;
                            if (dynamicIndex >= 0 && dynamicIndex < dynamicTable.length) {
                              headers[dynamicTable[dynamicIndex][0]] = header['type'] == 'indexed' ? dynamicTable[dynamicIndex][1] : header['value'];
                            }
                          }
                        } else if (header['type'] == 'literal_with_literal_name') {
                          headers[header['name']] = header['value'];
                        }
                      }

                      if (usedDynamicRef) {
                        // TODO: build and send the: buildQpackBlockHeaderAck(streamId)
                      }
                    }
                    
                    // Request Handling
                    if (headers[':protocol'] == 'webtransport') {
                      if (server._webtransportHandler != null && !connection.h3WtSessions.containsKey(streamIdStrKey)) {
                        final headersPayload = buildHttp3LiteralHeadersFrame({':status': '200'});
                        final http3Response = buildH3Frames([{'frame_type': 1, 'payload': headersPayload}]);
                        setSendingQuicChunk(server, quicConnectionId, {'type': '1rtt', 'stream_id': streamId, 'fin': false, 'data': http3Response});
                        var wt = createWtSessionObject(server, quicConnectionId, streamId, headers);
                        connection.h3WtSessions[streamIdStrKey] = wt;
                        server._webtransportHandler!(wt);
                      }
                    } else if (server._handler != null) {
                      var req = {'method': headers[':method'], 'path': headers[':path'], 'headers': headers, 'connection_id': quicConnectionId, 'stream_id': streamId};
                      var res = buildResponseObject(server, quicConnectionId, streamId);
                      server._handler!(req, res);
                    }
                  }
                }
                break;
            }
          }
        }
      }
    }
  }
}
receivingUdpQuicPacket
Dart

void receivingUdpQuicPacket(Server server, String fromIp, int fromPort, Uint8List udpPacketData) {
  List<dynamic> quicPackets = parseQuicDatagram(udpPacketData);

  if (quicPackets.isNotEmpty) {
    for (var packet in quicPackets) {
      if (packet != null) {
        String? quicConnectionId;
        String? dcidStr;

        if (packet.containsKey('dcid') && packet['dcid'] != null && (packet['dcid'] as Uint8List).isNotEmpty) {
          dcidStr = toHexString(packet['dcid']);
        }

        if (dcidStr != null && server.connections.containsKey(dcidStr)) {
          quicConnectionId = dcidStr;
        } else {
          final addressStr = '$fromIp:$fromPort';
          if (server.addressBinds.containsKey(addressStr)) {
            final boundId = server.addressBinds[addressStr] as String;
            if (server.connections.containsKey(boundId)) {
              quicConnectionId = boundId;
            }
          }
        }

        if (quicConnectionId == null) {
          quicConnectionId = dcidStr ?? generateQuicConnectionId();
        }

        final buildParams = <String, dynamic>{
          'from_ip': fromIp,
          'from_port': fromPort,
        };

        if (packet.containsKey('dcid') && packet['dcid'] is Uint8List && (packet['dcid'] as Uint8List).isNotEmpty) {
          buildParams['dcid'] = packet['dcid'];
        }

        if (packet.containsKey('scid') && packet['scid'] is Uint8List && (packet['scid'] as Uint8List).isNotEmpty) {
          buildParams['scid'] = packet['scid'];
        }

        if (packet.containsKey('version') && packet['version'] != null) {
          buildParams['version'] = packet['version'];
        }

        final packetType = packet['type'] as String?;
        if (packetType != null && ['initial', 'handshake', '1rtt'].contains(packetType)) {
          buildParams['incoming_packet'] = {
            'type': packetType,
            'data': packet['raw'] // Raw bytes of the packet
          };
        }
        
        setQuicConnection(server, quicConnectionId, buildParams);
      }
    }
  }
}
setQuicConnection
Dart

void setQuicConnection(Server server, String quicConnectionId, Map<String, dynamic> options) {
  bool isModified = false;

  if (!server.connections.containsKey(quicConnectionId)) {
    server.connections[quicConnectionId] = QuicConnectionState();
    isModified = true;
  }

  var connection = server.connections[quicConnectionId]!;

  var prevParams = {
    'connection_status': connection.connectionStatus,
    'sni': connection.sni
  };

  // 1. Update simple fields (from_ip, from_port, version, sni)
  if (options.containsKey('from_ip') && connection.fromIp != options['from_ip']) {
    connection.fromIp = options['from_ip'] as String;
    isModified = true;
  }
  if (options.containsKey('from_port') && connection.fromPort != options['from_port']) {
    connection.fromPort = options['from_port'] as int;
    isModified = true;
  }
  if (options.containsKey('version') && connection.version != options['version']) {
    connection.version = options['version'] as int;
    isModified = true;
  }
  if (options.containsKey('sni') && connection.sni != options['sni']) {
    connection.sni = options['sni'] as String;
    isModified = true;
  }

  // 2. Update CIDs
  if (options.containsKey('dcid') && options['dcid'] is Uint8List && (options['dcid'] as Uint8List).isNotEmpty) {
    var newDcid = options['dcid'] as Uint8List;
    if (connection.originalDcid == null || connection.originalDcid!.isEmpty || !arraybufferEqual(newDcid.buffer, connection.originalDcid!.buffer)) {
      connection.originalDcid = newDcid;
      isModified = true;
    }
  }
  if (options.containsKey('scid') && options['scid'] is Uint8List && (options['scid'] as Uint8List).isNotEmpty) {
    var newScid = options['scid'] as Uint8List;
    var isScidExist = connection.theirCids.any((cid) => arraybufferEqual(newScid.buffer, cid.buffer));
    if (!isScidExist) {
      connection.theirCids.add(newScid);
      isModified = true;
    }
  }

  // 3. Update connection status
  if (options.containsKey('connection_status') && connection.connectionStatus != options['connection_status']) {
    connection.connectionStatus = options['connection_status'] as int;
    isModified = true;
    if (connection.connectionStatus == 1) { // Cleanup for connected state
      connection.tlsTranscript = [];
      connection.receivingInitChunks = {};
      connection.receivingHandshakeChunks = {};
    }
  }

  // 4. Handle modifications and fire connection event
  if (isModified) {
    if (connection.fromIp != null && connection.fromPort != null) {
      var addressStr = '${connection.fromIp}:${connection.fromPort}';
      if (!server.addressBinds.containsKey(addressStr) || server.addressBinds[addressStr] != quicConnectionId) {
        server.addressBinds[addressStr] = quicConnectionId;
      }
    }
    quicConnection(server, quicConnectionId, 
      {'connection_status': connection.connectionStatus, 'sni': connection.sni}, 
      prevParams
    );
  }

  // 5. Handle Certificate/Key options (Server Handshake Logic)
  if (options.containsKey('cert') && options.containsKey('key')) {
    final certBytes = options['cert'] as Uint8List;
    final keyBytes = options['key'] as Uint8List;
    
    if (connection.tlsCipherSelected == null) {
      throw Exception("TLS cipher must be selected before sending server certificate/key.");
    }
    
    final cipherInfo = getCipherInfo(connection.tlsCipherSelected);
    final hashFunc = cipherInfo.hash;

    // A. Certificate message
    final cert = cryptoCreateX509Certificate(certBytes);
    final certDer = cert.raw;
    final certificateMsg = buildCertificate([{'cert': certDer, 'extensions': Uint8List(0)}]);
    connection.tlsTranscript.add(certificateMsg);
    setSendingQuicChunk(server, quicConnectionId, {'type': 'handshake', 'data': certificateMsg});

    // B. CertificateVerify message
    final privateKeyObj = cryptoCreatePrivateKey(keyBytes);
    final label = utf8.encode("TLS 1.3, server CertificateVerify");
    final separator = Uint8List.fromList([0x00]);
    final handshakeHash = hashTranscript(connection.tlsTranscript, hashFunc);
    final padding = Uint8List(64).map((_) => 0x20).toList(); // 64 spaces
    final signedData = concatUint8Arrays([Uint8List.fromList(padding), Uint8List.fromList(label), separator, handshakeHash]);

    const algoByType = {'rsa': 0x0804, 'ec': 0x0403, 'ed25519': 0x0807};
    final keyType = privateKeyObj.asymmetricKeyType;
    final algoCandidate = algoByType[keyType];
    
    if (algoCandidate == null || !connection.tlsSignatureAlgorithms.contains(algoCandidate)) {
      throw Exception("Unsupported key type or incompatible signature algorithm offered by client.");
    }

    Uint8List signature;
    if (keyType == 'rsa') {
      signature = cryptoSign('sha256', signedData, privateKeyObj, {'padding': 'pss', 'saltLength': hashFunc.outputLen});
    } else if (keyType == 'ec') {
      signature = cryptoSign('sha256', signedData, privateKeyObj);
    } else if (keyType == 'ed25519') {
      signature = cryptoSign(null, signedData, privateKeyObj);
    } else {
      throw Exception('Unreachable');
    }
    
    final certVerifyMsg = buildCertificateVerify(algoCandidate, signature);
    connection.tlsTranscript.add(certVerifyMsg);
    setSendingQuicChunk(server, quicConnectionId, {'type': 'handshake', 'data': certVerifyMsg});

    // C. Finished message
    final finishedKey = hkdfExpandLabel(
      connection.tlsServerHandshakeTrafficSecret!, 'finished', Uint8List(0), hashFunc.outputLen, hashFunc,
    );
    final verifyData = hmac(
      cipherInfo.str, finishedKey, hashTranscript(connection.tlsTranscript, hashFunc)
    );
    final finishedMsg = buildFinished(verifyData);
    connection.tlsTranscript.add(finishedMsg);
    setSendingQuicChunk(server, quicConnectionId, {'type': 'handshake', 'data': finishedMsg});
    
    // D. Application Secrets Derivation
    final secrets = tlsDeriveAppSecrets(connection.tlsHandshakeSecret!, connection.tlsTranscript, hashFunc);
    connection.tlsClientAppTrafficSecret = secrets.clientApplicationTrafficSecret;
    connection.tlsServerAppTrafficSecret = secrets.serverApplicationTrafficSecret;
  }
}







port every function i posted


This port translates the provided JavaScript functions and state object into Dart, adopting Dart's class-based structure for state management, using Uint8List for byte arrays, and utilizing placeholder functions for QUIC-specific networking and cryptographic operations (which would typically be handled by external Dart packages).

1. Dart Core Classes and Utilities
Since the original JS code relies heavily on external modules (./utils, ./crypto, etc.), the Dart port requires corresponding placeholder definitions.

Dart

import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

// --- PLACEHOLDER UTILITIES & CRYPTO ---
// These abstract or mock classes/functions simulate required dependencies.

// Utility Placeholders
typedef QuicHandler = void Function(dynamic req, dynamic res);
typedef WebTransportHandler = void Function(WebTransportSession session);

Uint8List concatUint8Arrays(List<Uint8List> buffers) => throw UnimplementedError('concatUint8Arrays: Implement using package:typed_data or similar.');
Uint8List writeVarInt(int value) => throw UnimplementedError('writeVarInt: Implement QUIC VarInt encoding.');
bool arraybufferEqual(ByteBuffer a, ByteBuffer b) => throw UnimplementedError('arraybufferEqual: Implement logic to compare two ArrayBuffers/ByteBuffers.');
String toHexString(Uint8List data) => throw UnimplementedError('toHexString: Implement byte array to hex string conversion.');
String generateQuicConnectionId() => (Random().nextInt(9007199254740991) * 1000).toInt().toString();

// Crypto Placeholders
abstract class HashFunc {
  Uint8List call(Uint8List data);
  int get outputLen; // e.g., 32 for SHA256
}
class CipherInfo {
  final String str;
  final HashFunc hash;
  CipherInfo(this.str, this.hash);
}
class PrivateKeyPlaceholder {
  final String asymmetricKeyType; // 'rsa', 'ec', 'ed25519'
  PrivateKeyPlaceholder(this.asymmetricKeyType);
}
class X509CertificatePlaceholder {
  final Uint8List raw;
  X509CertificatePlaceholder(Uint8List cert) : raw = cert;
}

CipherInfo getCipherInfo(dynamic selectedCipher) => throw UnimplementedError('getCipherInfo');
Uint8List hashTranscript(List<Uint8List> messages, HashFunc hashFunc) => throw UnimplementedError('hashTranscript');
Uint8List hkdfExpandLabel(Uint8List secret, String label, Uint8List context, int length, HashFunc hashFunc) => throw UnimplementedError('hkdfExpandLabel');
dynamic tlsDeriveAppSecrets(Uint8List handshakeSecret, List<Uint8List> transcript, HashFunc hashFunc) => throw UnimplementedError('tlsDeriveAppSecrets');
Uint8List buildCertificate(List<Map<String, dynamic>> certs) => throw UnimplementedError('buildCertificate: Implement TLS Certificate message construction.');
Uint8List buildCertificateVerify(int algo, Uint8List signature) => throw UnimplementedError('buildCertificateVerify');
Uint8List buildFinished(Uint8List verifyData) => throw UnimplementedError('buildFinished');
Uint8List hmac(String hash, Uint8List key, Uint8List data) => throw UnimplementedError('hmac: Implement using package:pointycastle or similar.');
Uint8List cryptoSign(String? hash, Uint8List data, dynamic key, [Map<String, dynamic>? options]) => throw UnimplementedError('cryptoSign');
PrivateKeyPlaceholder cryptoCreatePrivateKey(Uint8List key) => throw UnimplementedError('cryptoCreatePrivateKey');
X509CertificatePlaceholder cryptoCreateX509Certificate(Uint8List cert) => throw UnimplementedError('cryptoCreateX509Certificate');

// HTTP/3 & QUIC I/O Placeholders
Uint8List buildHttp3LiteralHeadersFrame(Map<String, dynamic> headers) => throw UnimplementedError('buildHttp3LiteralHeadersFrame');
Uint8List buildH3Frames(List<Map<String, dynamic>> frames) => throw UnimplementedError('buildH3Frames');
void quicStreamWrite(Server server, String quicConnectionId, int streamId, Uint8List data, bool fin) => throw UnimplementedError('quicStreamWrite');
void setSendingQuicChunk(Server server, String quicConnectionId, Map<String, dynamic> chunk) => throw UnimplementedError('setSendingQuicChunk');
void sendQuicFramesPacket(Server server, String quicConnectionId, String encryptionLevel, List<dynamic> frames) => throw UnimplementedError('sendQuicFramesPacket');
dynamic parseQuicDatagram(Uint8List udpPacketData) => throw UnimplementedError('parseQuicDatagram');
dynamic extractH3FramesFromChunks(Map<int, Uint8List> chunks, int offset) => throw UnimplementedError('extractH3FramesFromChunks');
dynamic parseH3SettingsFrame(Uint8List payload) => throw UnimplementedError('parseH3SettingsFrame');
dynamic extractQpackEncoderInstructionsFromChunks(Map<int, Uint8List> chunks, int offset) => throw UnimplementedError('extractQpackEncoderInstructionsFromChunks');
dynamic parseQpackHeaderBlock(Uint8List payload) => throw UnimplementedError('parseQpackHeaderBlock');
Uint8List buildQpackBlockHeaderAck(int streamId) => throw UnimplementedError('buildQpackBlockHeaderAck');
void quicConnection(Server server, String quicConnectionId, Map<String, dynamic> newParams, Map<String, dynamic> prevParams) { /* Connection event handler */ }

// Mock QPACK Static Table
const List<List<String>> qpackStaticTableEntries = []; 

// Minimal Stream & Server classes
class ReceivingStream {
  bool needCheck = false;
  List<int> receivingRanges = [];
  Map<int, Uint8List> receivingChunks = {};
}
class Server {
  Map<String, QuicConnectionState> connections = {};
  Map<String, dynamic> addressBinds = {};
  QuicHandler? _handler; 
  WebTransportHandler? _webtransportHandler; 
}
2. Ported QUIC Connection State (new_quic_connection)
The JS object is ported to a Dart class, initializing all fields to their default or null state.

Dart

class QuicConnectionState {
  // Connection Status (0: connecting, 1: connected, 2: disconnected, 4: unknown)
  int connectionStatus = 4; 

  String? fromIp;
  int? fromPort;
  int version = 1;

  // CIDs
  List<Uint8List> myCids = []; // SCIDs
  List<Uint8List> theirCids = []; // DCIDs used by peer
  Uint8List? originalDcid; // Initial/Retry DCID

  // TLS Stuff
  String? sni;
  dynamic tlsCipherSelected;
  dynamic tlsAlpnSelected;
  List<int> tlsSignatureAlgorithms = [];
  Uint8List? tlsHandshakeSecret;
  Uint8List? tlsSharedSecret;
  Uint8List? tlsEarlySecret;
  List<Uint8List> tlsTranscript = [];
  int tlsHandshakeStep = 0;
  bool tlsFinishedOk = false;
  dynamic tlsServerPublicKey;
  dynamic tlsServerPrivateKey;
  Uint8List? tlsClientHandshakeTrafficSecret;
  Uint8List? tlsServerHandshakeTrafficSecret;
  Uint8List? tlsClientAppTrafficSecret;
  Uint8List? tlsServerAppTrafficSecret;

  // Crypto Keys (Initial)
  Uint8List? initReadKey;
  Uint8List? initReadIv;
  Uint8List? initReadHp;
  Uint8List? initWriteKey;
  Uint8List? initWriteIv;
  Uint8List? initWriteHp;
  
  // Crypto Keys (Handshake)
  Uint8List? handshakeReadKey;
  Uint8List? handshakeReadIv;
  Uint8List? handshakeReadHp;
  Uint8List? handshakeWriteKey;
  Uint8List? handshakeWriteIv;
  Uint8List? handshakeWriteHp;

  // Crypto Keys (Application)
  Uint8List? appPrevReadKey;
  Uint8List? appPrevReadIv;
  Uint8List? appPrevReadHp;
  Uint8List? appReadKey;
  Uint8List? appReadIv;
  Uint8List? appReadHp;
  bool readKeyPhase = false;
  Uint8List? appWriteKey;
  Uint8List? appWriteIv;
  Uint8List? appWriteHp;

  // Sending
  int sendingInitPnNext = 1;
  List<dynamic> sendingInitChunks = [];
  int sendingInitOffsetNext = 0;
  List<dynamic> sendingInitPnAckedRanges = [];
  int sendingHandshakePnNext = 1;
  List<dynamic> sendingHandshakeChunks = [];
  int sendingHandshakeOffsetNext = 0;
  List<dynamic> sendingHandshakePnAckedRanges = [];
  Map<int, dynamic> sendingStreams = {};
  int sendingStreamIdNext = 0;
  int maxSendingPacketsPerSec = 1000;
  int maxSendingTotalBytesPerSec = 150000;
  int maxSendingPacketSize = 1200;
  int minSendingPacketSize = 35;
  int maxSendingPacketsInFlight = 20;
  int maxSendingBytesInFlight = 150000;
  int sendingAppPnBase = 1;
  List<dynamic> sendingAppPnHistory = [];
  List<dynamic> rttHistory = [];
  Set<int> sendingAppPnInFlight = {};
  dynamic nextSendQuicPacketTimer;
  bool sendingQuicPacketNow = false;

  // Receiving
  int receivingInitPnLargest = -1;
  List<dynamic> receivingInitPnRanges = [];
  Map<int, Uint8List> receivingInitChunks = {};
  int receivingInitFromOffset = 0;
  List<int> receivingInitRanges = [];
  int receivingHandshakePnLargest = -1;
  List<dynamic> receivingHandshakePnRanges = [];
  Map<int, Uint8List> receivingHandshakeChunks = {};
  int receivingHandshakeFromOffset = 0;
  List<int> receivingHandshakeRanges = [];
  int receivingAppPnLargest = -1;
  List<dynamic> receivingAppPnRanges = [];
  List<dynamic> receivingAppPnHistory = [];
  List<dynamic> receivingAppPnPendingAck = [];
  Map<String, ReceivingStream> receivingStreams = {};
  dynamic receivingStreamsNextCheckTimer;
  int remoteAckDelayExponent = 3;
  int remoteMaxUdpPayloadSize = 1000;

  // HTTP/3 State
  int? h3RemoteControlStreamId;
  int h3RemoteControlFromOffset = 1;
  int? h3RemoteQpackEncoderStreamId;
  int h3RemoteQpackEncoderFromOffset = 1;
  int? h3RemoteQpackDecoderStreamId;
  int h3RemoteQpackDecoderFromOffset = 1;
  Map<String, dynamic> h3HttpRequestStreams = {};
  int h3RemoteMaxHeaderSize = 0;
  int h3RemoteQpackMaxTableCapacity = 0;
  bool? h3RemoteDatagramSupport;
  int h3RemoteQpackTableBaseIndex = 0;
  int h3RemoteQpackTableCapacity = 0;
  List<List<String>> h3RemoteQpackDynamicTable = []; // [name, value]
  Map<String, dynamic> h3WtSessions = {};

  QuicConnectionState(); // Default constructor
}
3. Ported QPACK and Handlers
evictQpackRemoteDynamicTableIfNeeded
Dart

void evictQpackRemoteDynamicTableIfNeeded(Server server, String quicConnectionId) {
  if (server.connections.containsKey(quicConnectionId)) {
    var connection = server.connections[quicConnectionId]!;
    var entries = connection.h3RemoteQpackDynamicTable;
    var capacity = connection.h3RemoteQpackTableCapacity;

    // Calculate total size
    var totalSize = 0;
    for (var entry in entries) {
      var name = entry[0];
      var value = entry[1];
      // Note: Dart strings use UTF-16 code units for length, which might differ from JS/QUIC's byte length. 
      // Assuming byte length for name/value here for logic port.
      totalSize += name.length + value.length + 32; 
    }

    // Evict oldest entries (at the end of the list) until within capacity
    while (totalSize > capacity && entries.isNotEmpty) {
      var removed = entries.removeLast(); // Equivalent to JS Array.pop()
      var removedSize = removed[0].length + removed[1].length + 32;
      totalSize -= removedSize;
    }
  }
}
insertIntoQpackRemoteEncoderDynamicTable
Dart

bool insertIntoQpackRemoteEncoderDynamicTable(Server server, String quicConnectionId, String name, String value) {
  if (server.connections.containsKey(quicConnectionId)) {
    var connection = server.connections[quicConnectionId]!;
    var entrySize = name.length + value.length + 32;

    if (entrySize > connection.h3RemoteQpackTableCapacity) return false;

    // Equivalent to JS Array.unshift()
    connection.h3RemoteQpackDynamicTable.insert(0, [name, value]);
    connection.h3RemoteQpackTableBaseIndex++;

    evictQpackRemoteDynamicTableIfNeeded(server, quicConnectionId);

    return true;
  }
  return false;
}
WebTransportSession Class (Port of create_wt_session_object)
Dart

class WebTransportSession {
  final int id;
  final String quicConnectionId;
  final Server server;
  Map<String, dynamic> headers;
  
  bool _isOpen = true;

  // Callbacks
  Function(Uint8List)? onmessage;
  Function()? onclose;
  Function(dynamic)? onerror;
  Function(int)? onstream;

  WebTransportSession({
    required this.server,
    required this.quicConnectionId,
    required this.id,
    required this.headers,
  });

  void send(Uint8List data) {
    // Prepend Stream ID as VarInt for WebTransport Datagram format
    final payload = concatUint8Arrays([writeVarInt(id), data]);
    
    // JS: send_quic_frames_packet(server,quic_connection_id,'1rtt',[{ type: 'datagram', data: payload }])
    sendQuicFramesPacket(server, quicConnectionId, '1rtt', [
      {'type': 'datagram', 'data': payload}
    ]);
  }

  void close() {
    _isOpen = false;
    // TODO: Send H/3 control frame if needed
    onclose?.call();
  }

  bool get isOpen => _isOpen;
}

WebTransportSession createWtSessionObject(Server server, String quicConnectionId, int streamId, Map<String, dynamic> headers) {
  return WebTransportSession(
    server: server,
    quicConnectionId: quicConnectionId,
    id: streamId,
    headers: headers,
  );
}
QuicHttpResponse Class (Port of build_response_object)
Dart

class QuicHttpResponse {
  final Server server;
  final String quicConnectionId;
  final int streamId;
  
  int? statusCode;
  bool headersSent = false;
  dynamic socket; 

  QuicHttpResponse({
    required this.server,
    required this.quicConnectionId,
    required this.streamId,
  });
  
  QuicConnectionState get connection => server.connections[quicConnectionId]!;
  Map<String, dynamic> get requestStreamState => connection.h3HttpRequestStreams['$streamId']!;

  void writeHead(int statusCode, Map<String, dynamic> headers) {
    // Merge new headers
    requestStreamState['response_headers'].addAll(headers);

    // Only send HEADERS frame once
    if (!requestStreamState['response_headers'].containsKey(':status')) {
      requestStreamState['response_headers'][':status'] = statusCode;

      final headersPayload = buildHttp3LiteralHeadersFrame(requestStreamState['response_headers'] as Map<String, dynamic>);
      
      final http3Response = buildH3Frames([
        {'frame_type': 1, 'payload': headersPayload} // Frame Type 1: HEADERS
      ]);

      quicStreamWrite(server, quicConnectionId, streamId, http3Response, false);
      
      headersSent = true;
    }
  }

  void writeEarlyHints(dynamic hints) {
    // JS implementation was empty
  }

  void write(Uint8List chunk) {
    final http3Response = buildH3Frames([
      {'frame_type': 0, 'payload': chunk} // Frame Type 0: DATA
    ]);

    quicStreamWrite(server, quicConnectionId, streamId, http3Response, false);
  }

  void end(Uint8List? chunk) {
    if (chunk != null && chunk.isNotEmpty) {
      final http3Response = buildH3Frames([
        {'frame_type': 0, 'payload': chunk}
      ]);
      quicStreamWrite(server, quicConnectionId, streamId, http3Response, true); // fin: true
    } else {
      quicStreamWrite(server, quicConnectionId, streamId, Uint8List(0), true); // fin: true
    }
  }
}

QuicHttpResponse buildResponseObject(Server server, String quicConnectionId, int streamId) {
  return QuicHttpResponse(
    server: server,
    quicConnectionId: quicConnectionId,
    streamId: streamId,
  );
}
4. Ported Packet and Stream Processing
processQuicReceivingStreams
Dart

void processQuicReceivingStreams(Server server, String quicConnectionId) {
  if (!server.connections.containsKey(quicConnectionId)) return;
  
  var connection = server.connections[quicConnectionId]!;

  for (var streamIdStr in connection.receivingStreams.keys) {
    final streamId = int.parse(streamIdStr);
    final stream = connection.receivingStreams[streamIdStr]!;

    if (stream.needCheck) {
      stream.needCheck = false;
      int? streamType;

      // 1. Identify Stream Type (if already known from connection state)
      if (connection.h3RemoteControlStreamId == streamId) {
        streamType = 0;
      } else if (connection.h3RemoteQpackEncoderStreamId == streamId) {
        streamType = 2;
      } else if (connection.h3RemoteQpackDecoderStreamId == streamId) {
        streamType = 3;
      }

      if (stream.receivingRanges.length >= 2) {
        final isUnidirectional = (streamId % 2 == 0) != (streamId % 4 == 0); 
        
        // 2. Identify Stream Type (if unknown and has data)
        if (isUnidirectional) {
          if (streamType == null && stream.receivingChunks.containsKey(0)) {
            final firstByte = stream.receivingChunks[0]![0];
            switch (firstByte) {
              case 0x00: connection.h3RemoteControlStreamId = streamId; streamType = 0; break;
              case 0x01: streamType = 1; break; // Push Stream
              case 0x02: connection.h3RemoteQpackEncoderStreamId = streamId; streamType = 2; break;
              case 0x03: connection.h3RemoteQpackDecoderStreamId = streamId; streamType = 3; break;
              default: /* Unknown Unidirectional Stream */ break;
            }
          }
        } else {
          streamType = 4; // Bidirectional (HTTP Request/Response)
        }

        // 3. Process Stream Content based on Type
        if (streamType != null) {
          switch (streamType) {
            case 0: // Control Stream
              var ext = extractH3FramesFromChunks(stream.receivingChunks, connection.h3RemoteControlFromOffset);
              connection.h3RemoteControlFromOffset = ext['new_from_offset'] as int;
              List<dynamic> h3Frames = ext['frames'];

              for (var frame in h3Frames) {
                if (frame['frame_type'] == 4) { // SETTINGS Frame
                  var controlSettings = parseH3SettingsFrame(frame['payload'] as Uint8List);
                  
                  if (controlSettings.containsKey('SETTINGS_QPACK_MAX_TABLE_CAPACITY') && controlSettings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'] > 0) {
                    connection.h3RemoteQpackMaxTableCapacity = controlSettings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'] as int;
                    evictQpackRemoteDynamicTableIfNeeded(server, quicConnectionId);
                  }
                  if (controlSettings.containsKey('SETTINGS_MAX_FIELD_SECTION_SIZE') && controlSettings['SETTINGS_MAX_FIELD_SECTION_SIZE'] > 0) {
                    connection.h3RemoteMaxHeaderSize = controlSettings['SETTINGS_MAX_FIELD_SECTION_SIZE'] as int;
                  }
                  if (controlSettings.containsKey('SETTINGS_H3_DATAGRAM')) {
                    connection.h3RemoteDatagramSupport = (controlSettings['SETTINGS_H3_DATAGRAM'] as int) > 0;
                  }
                }
              }
              break;

            case 2: // QPACK Encoder Stream
              var ext = extractQpackEncoderInstructionsFromChunks(stream.receivingChunks, connection.h3RemoteQpackEncoderFromOffset);
              connection.h3RemoteQpackEncoderFromOffset = ext['new_from_offset'] as int;
              List<dynamic> instructions = ext['instructions'];
              
              List<List<String>> inserts = [];

              for (var instruction in instructions) {
                if (instruction['type'] == 'set_dynamic_table_capacity') {
                  connection.h3RemoteQpackTableCapacity = instruction['capacity'] as int;
                  evictQpackRemoteDynamicTableIfNeeded(server, quicConnectionId);
                } else if (instruction['type'] == 'insert_with_name_ref' || instruction['type'] == 'insert_without_name_ref') {
                  String? name;
                  String value = instruction['value'] as String;

                  if (instruction['type'] == 'insert_with_name_ref') {
                    int nameIndex = instruction['name_index'] as int;
                    if (instruction['from_static_table'] == true) {
                      if (nameIndex < qpackStaticTableEntries.length) {
                        name = qpackStaticTableEntries[nameIndex][0];
                      }
                    } else {
                      // Dynamic table reference
                      var baseIndex = connection.h3RemoteQpackTableBaseIndex;
                      var dynamicIndex = baseIndex - 1 - nameIndex;
                      var dynamicTable = connection.h3RemoteQpackDynamicTable;

                      if (dynamicIndex >= 0 && dynamicIndex < dynamicTable.length) {
                        name = dynamicTable[dynamicIndex][0];
                      }
                    }
                  } else { 
                    name = instruction['name'] as String;
                  }

                  if (name != null) {
                    inserts.add([name, value]);
                  }
                }
              }

              if (inserts.isNotEmpty) {
                for (var insert in inserts) {
                  insertIntoQpackRemoteEncoderDynamicTable(server, quicConnectionId, insert[0], insert[1]);
                }
                // TODO: build and send build_qpack_known_received_count(inserts.length)
              }
              break;

            case 3: // QPACK Decoder Stream (nothing to do here based on JS)
              break;

            case 4: // HTTP/3 Request Stream
              final streamIdStrKey = '$streamId';
              if (!connection.h3HttpRequestStreams.containsKey(streamIdStrKey)) {
                connection.h3HttpRequestStreams[streamIdStrKey] = {
                  'from_offset': 0, 'response_headers': <String, dynamic>{}, 'header_sent': false, 'response_body': null,
                };
              }

              var reqState = connection.h3HttpRequestStreams[streamIdStrKey]!;
              var ext = extractH3FramesFromChunks(stream.receivingChunks, reqState['from_offset'] as int);
              reqState['from_offset'] = ext['new_from_offset'] as int;
              List<dynamic> h3Frames = ext['frames'];

              for (var frame in h3Frames) {
                if (frame['frame_type'] == 1) { // HEADERS Frame (Request)
                  final headers = <String, String>{};
                  final dynamicTable = connection.h3RemoteQpackDynamicTable;
                  final headerBlock = parseQpackHeaderBlock(frame['payload'] as Uint8List);
                  
                  bool usedDynamicRef = false;
                  
                  if ((headerBlock['insert_count'] as int) <= dynamicTable.length) {
                    for (var header in headerBlock['headers']) {
                      // Check for dynamic reference usage
                      if (header['type'] == 'indexed' && header['from_static_table'] == false) {
                        usedDynamicRef = true;
                      } else if (header['type'] == 'literal_with_name_ref' && header['from_static_table'] == false) {
                        usedDynamicRef = true;
                      }

                      // Decode Header
                      if (header['type'] == 'indexed') {
                        if (header['from_static_table'] == true) {
                          if (header['index'] < qpackStaticTableEntries.length) {
                            headers[qpackStaticTableEntries[header['index']][0]] = qpackStaticTableEntries[header['index']][1];
                          }
                        } else {
                          var dynamicIndex = headerBlock['base_index'] as int - 1 - header['index'];
                          if (dynamicIndex >= 0 && dynamicIndex < dynamicTable.length) {
                            var entry = dynamicTable[dynamicIndex];
                            headers[entry[0]] = entry[1];
                          }
                        }
                      } else if (header['type'] == 'literal_with_name_ref') {
                        var value = header['value'] as String;
                        if (header['from_static_table'] == true) {
                          if (header['name_index'] < qpackStaticTableEntries.length) {
                            headers[qpackStaticTableEntries[header['name_index']][0]] = value;
                          }
                        } else {
                          var dynamicIndex = headerBlock['base_index'] as int - 1 - header['name_index'];
                          if (dynamicIndex >= 0 && dynamicIndex < dynamicTable.length) {
                            var entry = dynamicTable[dynamicIndex];
                            headers[entry[0]] = value;
                          }
                        }
                      } else if (header['type'] == 'literal_with_literal_name') {
                        headers[header['name'] as String] = header['value'] as String;
                      }
                    }

                    if (usedDynamicRef) {
                      // build and send the: buildQpackBlockHeaderAck(streamId)
                    }
                  }
                  
                  // Request Dispatching
                  if (headers[':protocol'] == 'webtransport') {
                    if (server._webtransportHandler != null && !connection.h3WtSessions.containsKey(streamIdStrKey)) {
                      // Send 200 response for WebTransport
                      final headersPayload = buildHttp3LiteralHeadersFrame({':status': '200'});
                      final http3Response = buildH3Frames([{'frame_type': 1, 'payload': headersPayload}]);
                      setSendingQuicChunk(server, quicConnectionId, {'type': '1rtt', 'stream_id': streamId, 'fin': false, 'data': http3Response});
                      
                      var wt = createWtSessionObject(server, quicConnectionId, streamId, headers);
                      connection.h3WtSessions[streamIdStrKey] = wt;
                      server._webtransportHandler!(wt);
                    }
                  } else if (server._handler != null) {
                    var req = {
                      'method': headers[':method'], 'path': headers[':path'], 'headers': headers, 
                      'connection_id': quicConnectionId, 'stream_id': streamId
                    };
                    var res = buildResponseObject(server, quicConnectionId, streamId);
                    server._handler!(req, res);
                  }
                }
              }
              break;
          }
        }
      }
    }
  }
}
receivingUdpQuicPacket
Dart

void receivingUdpQuicPacket(Server server, String fromIp, int fromPort, Uint8List udpPacketData) {
  List<dynamic> quicPackets = parseQuicDatagram(udpPacketData);

  if (quicPackets.isNotEmpty) {
    for (var packet in quicPackets) {
      if (packet != null) {
        String? quicConnectionId;
        String? dcidStr;

        if (packet.containsKey('dcid') && packet['dcid'] is Uint8List && (packet['dcid'] as Uint8List).isNotEmpty) {
          dcidStr = toHexString(packet['dcid']);
        }

        // 1. Try to find connection by DCID (if present)
        if (dcidStr != null && server.connections.containsKey(dcidStr)) {
          quicConnectionId = dcidStr;
        } 
        
        // 2. Fallback: Try to find connection by IP:Port binding (for 0-RTT/stateless initial)
        if (quicConnectionId == null) {
          final addressStr = '$fromIp:$fromPort';
          if (server.addressBinds.containsKey(addressStr)) {
            final boundId = server.addressBinds[addressStr] as String;
            if (server.connections.containsKey(boundId)) {
              quicConnectionId = boundId;
            }
          }
        }

        // 3. Fallback: Assign a new ID (use DCID if present, otherwise generate random)
        quicConnectionId ??= dcidStr ?? generateQuicConnectionId();

        final buildParams = <String, dynamic>{
          'from_ip': fromIp,
          'from_port': fromPort,
        };

        if (packet.containsKey('dcid') && packet['dcid'] is Uint8List && (packet['dcid'] as Uint8List).isNotEmpty) {
          buildParams['dcid'] = packet['dcid'];
        }

        if (packet.containsKey('scid') && packet['scid'] is Uint8List && (packet['scid'] as Uint8List).isNotEmpty) {
          buildParams['scid'] = packet['scid'];
        }

        if (packet.containsKey('version') && packet['version'] != null) {
          buildParams['version'] = packet['version'];
        }

        final packetType = packet['type'] as String?;
        if (packetType != null && ['initial', 'handshake', '1rtt'].contains(packetType)) {
          buildParams['incoming_packet'] = {
            'type': packetType,
            'data': packet['raw'] // Raw bytes of the packet
          };
        }
        
        setQuicConnection(server, quicConnectionId, buildParams);
      }
    }
  }
}
setQuicConnection
Dart

void setQuicConnection(Server server, String quicConnectionId, Map<String, dynamic> options) {
  bool isModified = false;

  if (!server.connections.containsKey(quicConnectionId)) {
    server.connections[quicConnectionId] = QuicConnectionState();
    isModified = true;
  }

  var connection = server.connections[quicConnectionId]!;

  var prevParams = {
    'connection_status': connection.connectionStatus,
    'sni': connection.sni
  };

  // 1. Update simple fields
  if (options.containsKey('from_ip') && connection.fromIp != options['from_ip']) {
    connection.fromIp = options['from_ip'] as String;
    isModified = true;
  }
  if (options.containsKey('from_port') && connection.fromPort != options['from_port']) {
    connection.fromPort = options['from_port'] as int;
    isModified = true;
  }
  if (options.containsKey('version') && connection.version != options['version']) {
    connection.version = options['version'] as int;
    isModified = true;
  }
  if (options.containsKey('sni') && connection.sni != options['sni']) {
    connection.sni = options['sni'] as String;
    isModified = true;
  }

  // 2. Update CIDs
  if (options.containsKey('dcid') && options['dcid'] is Uint8List && (options['dcid'] as Uint8List).isNotEmpty) {
    var newDcid = options['dcid'] as Uint8List;
    if (connection.originalDcid == null || connection.originalDcid!.isEmpty || !arraybufferEqual(newDcid.buffer, connection.originalDcid!.buffer)) {
      connection.originalDcid = newDcid;
      isModified = true;
    }
  }
  if (options.containsKey('scid') && options['scid'] is Uint8List && (options['scid'] as Uint8List).isNotEmpty) {
    var newScid = options['scid'] as Uint8List;
    var isScidExist = connection.theirCids.any((cid) => arraybufferEqual(newScid.buffer, cid.buffer));
    if (!isScidExist) {
      connection.theirCids.add(newScid);
      isModified = true;
    }
  }

  // 3. Update connection status
  if (options.containsKey('connection_status') && connection.connectionStatus != options['connection_status']) {
    connection.connectionStatus = options['connection_status'] as int;
    isModified = true;
    if (connection.connectionStatus == 1) { // Cleanup on successful connection
      connection.tlsTranscript = [];
      connection.receivingInitChunks = {};
      connection.receivingHandshakeChunks = {};
    }
  }

  // 4. Handle modifications and fire connection event
  if (isModified) {
    if (connection.fromIp != null && connection.fromPort != null) {
      var addressStr = '${connection.fromIp}:${connection.fromPort}';
      if (!server.addressBinds.containsKey(addressStr) || server.addressBinds[addressStr] != quicConnectionId) {
        server.addressBinds[addressStr] = quicConnectionId;
      }
    }
    quicConnection(server, quicConnectionId, 
      {'connection_status': connection.connectionStatus, 'sni': connection.sni}, 
      prevParams
    );
  }

  // 5. Handle Certificate/Key options (Server Handshake Logic)
  if (options.containsKey('cert') && options.containsKey('key')) {
    final certBytes = options['cert'] as Uint8List;
    final keyBytes = options['key'] as Uint8List;
    
    final cipherInfo = getCipherInfo(connection.tlsCipherSelected);
    final hashFunc = cipherInfo.hash;

    // A. Certificate message
    final cert = cryptoCreateX509Certificate(certBytes);
    final certDer = cert.raw;
    final certificateMsg = buildCertificate([{'cert': certDer, 'extensions': Uint8List(0)}]);
    connection.tlsTranscript.add(certificateMsg);
    setSendingQuicChunk(server, quicConnectionId, {'type': 'handshake', 'data': certificateMsg});

    // B. CertificateVerify message
    final privateKeyObj = cryptoCreatePrivateKey(keyBytes);
    final label = Uint8List.fromList(utf8.encode("TLS 1.3, server CertificateVerify"));
    final separator = Uint8List.fromList([0x00]);
    final handshakeHash = hashTranscript(connection.tlsTranscript, hashFunc);
    final padding = Uint8List(64).map((_) => 0x20).toList(); // 64 spaces (0x20)
    final signedData = concatUint8Arrays([Uint8List.fromList(padding), label, separator, handshakeHash]);

    const algoByType = {'rsa': 0x0804, 'ec': 0x0403, 'ed25519': 0x0807};
    final keyType = privateKeyObj.asymmetricKeyType;
    final algoCandidate = algoByType[keyType];
    
    if (algoCandidate == null || !connection.tlsSignatureAlgorithms.contains(algoCandidate)) {
      throw Exception("Unsupported key type or incompatible signature algorithm offered by client: $keyType");
    }

    Uint8List signature;
    if (keyType == 'rsa') {
      // Dart crypto libraries would need specific options for RSA-PSS
      signature = cryptoSign('sha256', signedData, privateKeyObj, {'padding': 'pss', 'saltLength': hashFunc.outputLen});
    } else if (keyType == 'ec') {
      signature = cryptoSign('sha256', signedData, privateKeyObj);
    } else if (keyType == 'ed25519') {
      signature = cryptoSign(null, signedData, privateKeyObj);
    } else {
      throw Exception('Key type $keyType not supported for signing.');
    }
    
    final certVerifyMsg = buildCertificateVerify(algoCandidate, signature);
    connection.tlsTranscript.add(certVerifyMsg);
    setSendingQuicChunk(server, quicConnectionId, {'type': 'handshake', 'data': certVerifyMsg});

    // C. Finished message
    final finishedKey = hkdfExpandLabel(
      connection.tlsServerHandshakeTrafficSecret!, 'finished', Uint8List(0), hashFunc.outputLen, hashFunc,
    );
    final verifyData = hmac(
      cipherInfo.str, finishedKey, hashTranscript(connection.tlsTranscript, hashFunc)
    );
    final finishedMsg = buildFinished(verifyData);
    connection.tlsTranscript.add(finishedMsg);
    setSendingQuicChunk(server, quicConnectionId, {'type': 'handshake', 'data': finishedMsg});
    
    // D. Application Secrets Derivation
    final secrets = tlsDeriveAppSecrets(connection.tlsHandshakeSecret!, connection.tlsTranscript, hashFunc);
    connection.tlsClientAppTrafficSecret = secrets.client_application_traffic_secret as Uint8List;
    connection.tlsServerAppTrafficSecret = secrets.server_application_traffic_secret as Uint8List;
  }

  // 6. Handle incoming packet (Logic incomplete in provided JS snippet)
  if (options.containsKey('incoming_packet')) {
    // ... the rest of the JS function logic was truncated ...
    // The structure indicates that the next step would involve selecting read keys 
    // based on 'type' and packet number, and then processing frames.
  }
}