

import 'dart:convert';
import 'dart:typed_data';

import 'utils.dart';

dynamic get_cipher_info(int cipher_suite) {
  switch (cipher_suite) {
    case 0x1301: // TLS_AES_128_GCM_SHA256
      return  ( keylen: 16, ivlen: 12, hash: sha256,str: 'sha256' );
    case 0x1302: // TLS_AES_256_GCM_SHA384
      return ( keylen: 32, ivlen: 12, hash: sha384,str: 'sha384' );
    case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
      return ( keylen: 32, ivlen: 12, hash: sha256,str: 'sha256' );
    default:
      throw Exception("Unsupported cipher suite: 0x" + cipher_suite.toString(16));
  }
}




Uint8List build_server_hello(Uint8List server_random, Uint8List public_key, Uint8List session_id, int cipher_suite, int group) {
    var legacy_version = [0x03, 0x03];
    var random = Uint8List.fromList(server_random);
    var session_id_bytes = Uint8List.fromList(session_id);
    var session_id_length = session_id_bytes.length & 0xff;

    var cipher_suite_bytes = [(cipher_suite >> 8) & 0xff, cipher_suite & 0xff];
    var compression_method = [0x00];

    var key = Uint8List.fromList(public_key);
    var key_length = [(key.length >> 8) & 0xff, key.length & 0xff];
    var group_bytes = [(group >> 8) & 0xff, group & 0xff];
    var key_exchange = [...group_bytes, ...key_length, ...key];
    var key_share_extension = (()  {
        var extension_type = [0x00, 0x33];
        var extension_length = [(key_exchange.length >> 8) & 0xff, key_exchange.length & 0xff];
        return [...extension_type, ...extension_length, ...key_exchange];
    })();

    var supported_versions_extension = [
        0x00, 0x2b,
        0x00, 0x02,
        0x03, 0x04
    ];

    var params_bytes = [
      0x00, 0x01,  0x00, 0x04,  0x00, 0x00, 0x10, 0x00, // initial_max_data = 4096
      0x00, 0x03,  0x00, 0x04,  0x00, 0x00, 0x08, 0x00  // max_packet_size = 2048
    ];

    

    var extensions = [
      ...supported_versions_extension,
      ...key_share_extension
    ];
    var extensions_length = [(extensions.length >> 8) & 0xff, extensions.length & 0xff];

    List<int> handshake_body = [
        ...legacy_version,
        ...random,
        session_id_length,
        ...session_id_bytes,
        ...cipher_suite_bytes,
        ...compression_method,
        ...extensions_length,
        ...extensions
    ];

    var body_length = handshake_body.length;
    var handshake = [
        0x02, // handshake type: ServerHello
        (body_length >> 16) & 0xff,
        (body_length >> 8) & 0xff,
        body_length & 0xff,
        ...handshake_body
    ];

    return Uint8List.fromList(handshake); // ✔️ מחזיר רק Handshake Message
}




Uint8List build_quic_ext(params) {
  var out = [];

  dynamic addParam(id, value) {
    var id_bytes = writeVarInt(id);
    var length_bytes, value_bytes;

    if ( value is num) {
      value_bytes = writeVarInt(value);
    } else if (value.runtimeType == Uint8List) {
      value_bytes = Uint8List.fromList(value);
    } else if (value == true) {
      value_bytes = []; // for disable_active_migration
    } else {
      throw Exception('Unsupported value type for parameter ' + id);
    }

    length_bytes = writeVarInt(value_bytes.length);
    out.addAll([...id_bytes, ...length_bytes, ...value_bytes]);
  }

  if (params.original_destination_connection_id)
    addParam(0x00, params.original_destination_connection_id);
  if (params.max_idle_timeout)
    addParam(0x01, params.max_idle_timeout);
  if (params.stateless_reset_token)
    addParam(0x02, params.stateless_reset_token);
  if (params.max_udp_payload_size)
    addParam(0x03, params.max_udp_payload_size);
  if (params.initial_max_data)
    addParam(0x04, params.initial_max_data);
  if (params.initial_max_stream_data_bidi_local)
    addParam(0x05, params.initial_max_stream_data_bidi_local);
  if (params.initial_max_stream_data_bidi_remote)
    addParam(0x06, params.initial_max_stream_data_bidi_remote);
  if (params.initial_max_stream_data_uni)
    addParam(0x07, params.initial_max_stream_data_uni);
  if (params.initial_max_streams_bidi)
    addParam(0x08, params.initial_max_streams_bidi);
  if (params.initial_max_streams_uni)
    addParam(0x09, params.initial_max_streams_uni);
  if (params.ack_delay_exponent !=undefined)
    addParam(0x0a, params.ack_delay_exponent);
  if (params.max_ack_delay !=undefined)
    addParam(0x0b, params.max_ack_delay);
  if (params.disable_active_migration)
    addParam(0x0c, true);
  if (params.active_connection_id_limit)
    addParam(0x0e, params.active_connection_id_limit);
  if (params.initial_source_connection_id)
    addParam(0x0f, params.initial_source_connection_id);
  if (params.retry_source_connection_id)
    addParam(0x10, params.retry_source_connection_id);
  if (params.max_datagram_frame_size)
    addParam(0x20, params.max_datagram_frame_size); // אין ערך – presence בלבד
  if (params.web_accepted_origins) {
    for (var i = 0; i < params.web_accepted_origins.length; i++) {
      var origin = params.web_accepted_origins[i];
      var origin_bytes = new TextEncoder().encode(origin);
      addParam(0x2b603742, origin_bytes);
    }
  }

  return Uint8List.fromList(out);
}





Uint8List build_alpn_ext(String protocol) {
    var proto_bytes = utf8.encode(protocol);
    var ext = Uint8List(2 + 1 + proto_bytes.length);
    ext[0] = 0x00;
    ext[1] = proto_bytes.length + 1;
    ext[2] = proto_bytes.length;
    ext.setAll( 3,proto_bytes);
    return ext;
}

Uint8List build_encrypted_extensions(extensions) {
    var ext_bytes = [];
    for (var ext in extensions) {
        ext_bytes.addAll([(ext.type >> 8) & 0xff, ext.type & 0xff]);
        ext_bytes.addAll([(ext.data.length >> 8) & 0xff, ext.data.length & 0xff]);
        ext_bytes.addAll(ext.data);
    }
    var ext_len = ext_bytes.length;
    var ext_len_bytes = [(ext_len >> 8) & 0xff, ext_len & 0xff];
    var body = [...ext_len_bytes, ...ext_bytes];
    var hs_len = body.length;
    var header = [0x08, (hs_len >> 16) & 0xff, (hs_len >> 8) & 0xff, hs_len & 0xff];
    return Uint8List.fromList([...header, ...body]);
}

Uint8List build_certificate(certificates) {
    var context = [0x00];
    var cert_list = [];
    for (var cert in certificates) {
        var extensions = cert.extensions instanceof Uint8Array ? cert.extensions : new Uint8Array(0);
        cert_list.add((cert.cert.length >> 16) & 0xff, (cert.cert.length >> 8) & 0xff, cert.cert.length & 0xff);
        cert_list.add(...cert.cert);
        cert_list.add((extensions.length >> 8) & 0xff, extensions.length & 0xff);
        cert_list.add(...extensions);
    }
    var total_len = cert_list.length;
    var list_len = [(total_len >> 16) & 0xff, (total_len >> 8) & 0xff, total_len & 0xff];
    var body = [...context, ...list_len, ...cert_list];
    var hs_len = body.length;
    var header = [0x0b, (hs_len >> 16) & 0xff, (hs_len >> 8) & 0xff, hs_len & 0xff];
    return Uint8List.fromList([...header, ...body]);
}



Uint8List build_certificate_verify(algorithm, signature) {
    var sig_len = signature.length;
    int total_len = (4 + sig_len).toInt();
    List<int> header = [
        0x0f,
        (total_len >> 16) & 0xff,
        (total_len >> 8) & 0xff,
        total_len & 0xff,
        (algorithm >> 8) & 0xff, algorithm & 0xff,
        (sig_len >> 8) & 0xff, sig_len & 0xff
    ];
    return Uint8List.fromList([...header, ...signature]);
}

Uint8List build_finished(verify_data) {
    var length = verify_data.length;
    var header = [0x14, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff];
    return Uint8List.fromList([...header, ...verify_data]);
}



dynamic handle_client_hello(parsed) {

  
  var supported_groups = [0x001d, 0x0017]; // X25519, secp256r1
  var supported_cipher_suites = [0x1301, 0x1302];//0x1303, 

  var selected_alpn=null;
  var selected_group=null;
  var selected_cipher=null;

  var client_public_key=null;

  var server_private_key=null;
  var server_public_key=null;
  var shared_secret=null;

  for(var i in supported_cipher_suites){
    if(parsed.cipher_suites.includes(supported_cipher_suites[i])==true){
      selected_cipher=supported_cipher_suites[i];
      break;
    }
  }

  for(var i in supported_groups){
    if(selected_group==null){
      for(var i2 in parsed.key_shares){
        if(parsed.key_shares[i2].group==supported_groups[i]){
          selected_group=parsed.key_shares[i2].group;
          client_public_key=parsed.key_shares[i2].pubkey;
          break;
        }
      }
    }
  }

  

  if(selected_group!=null){

    if (selected_group === 0x001d) { // X25519
      server_private_key = crypto.randomBytes(32);
      server_public_key = x25519.getPublicKey(server_private_key);
      shared_secret = x25519.getSharedSecret(server_private_key, client_public_key);
    } else if (selected_group === 0x0017) { // secp256r1 (P-256)
      server_private_key = p256.utils.randomPrivateKey();
      server_public_key = p256.getPublicKey(server_private_key, false);
      var client_point = p256.ProjectivePoint.fromHex(client_public_key);
      var shared_point = client_point.multiply(
          BigInt('0x' + Buffer.from(server_private_key).toString('hex'))
      );
      shared_secret = shared_point.toRawBytes().slice(0, 32);
    }

  }


  return (
    selected_cipher: selected_cipher,
    selected_group: selected_group,
    client_public_key: client_public_key,
    server_private_key: Uint8List.fromList(server_private_key),
    server_public_key: server_public_key,
    shared_secret: shared_secret
  );


}



/// Data class to hold the parsed QUIC Transport Parameters.
class TransportParameters {
  Uint8List? originalDestinationConnectionId;
  int? maxIdleTimeout;
  Uint8List? statelessResetToken;
  int? maxUdpPayloadSize;
  int? initialMaxData;
  int? initialMaxStreamDataBidiLocal;
  int? initialMaxStreamDataBidiRemote;
  int? initialMaxStreamDataUni;
  int? initialMaxStreamsBidi;
  int? initialMaxStreamsUni;
  int? ackDelayExponent;
  int? maxAckDelay;
  bool disableActiveMigration = false;
  int? activeConnectionIdLimit;
  Uint8List? initialSourceConnectionId;
  Uint8List? retrySourceConnectionId;
  int? maxDatagramFrameSize;
  Uint8List? serverCertificateHash;
  final List<String> webAcceptedOrigins = []; // Matches JS: web_accepted_origins: []
  List<Map<String, dynamic>>? unknown;

  TransportParameters();
}




TransportParameters parseTransportParameters(Uint8List buf, [int start = 0]) {
  var offset = start;
  final end = buf.length;
  final out = TransportParameters(); // Instantiate the Dart class

  // Helper function to read the VarInt value and immediately throw if it fails.
  // This simplifies the switch statement logic.
  int readVarIntVal(Uint8List valueBytes) {
    try {
      return readVarInt(valueBytes, 0)!.value;
    } catch (e) {
      throw Exception("Error decoding VarInt value: $e");
    }
  }

  while (offset < end) {
    // ---- Parameter ID ----
    late VarIntReadResult idVar;
    try {
      // NOTE: Assumes readVarInt is implemented
      idVar = readVarInt(buf, offset)!;
    } catch (e) {
      throw Exception("Bad varint (id) at $offset: $e");
    }
    
    offset += idVar.byteLength;
    final id = idVar.value;

    // ---- Value Length ----
    late VarIntReadResult lenVar;
    try {
      // NOTE: Assumes readVarInt is implemented
      lenVar = readVarInt(buf, offset)!;
    } catch (e) {
      throw Exception("Bad varint (len) at $offset: $e");
    }
    
    offset += lenVar.byteLength;
    final length = lenVar.value;

    if (offset + length > end) {
      throw Exception("Truncated value for id $id");
    }
    
    // JS: var valueBytes = buf.slice(offset, offset + length);
    // Dart: buf.sublist(start, end)
    final valueBytes = buf.sublist(offset, offset + length);
    offset += length;

    // ---- Decoding by ID ----
    switch (id) {
      case 0x00:
        out.originalDestinationConnectionId = valueBytes;
        break;
      case 0x01:
        out.maxIdleTimeout = readVarIntVal(valueBytes);
        break;
      case 0x02:
        if (valueBytes.length != 16) {
          throw Exception("stateless_reset_token len≠16");
        }
        out.statelessResetToken = valueBytes;
        break;
      case 0x03:
        out.maxUdpPayloadSize = readVarIntVal(valueBytes);
        break;
      case 0x04:
        out.initialMaxData = readVarIntVal(valueBytes);
        break;
      case 0x05:
        out.initialMaxStreamDataBidiLocal = readVarIntVal(valueBytes);
        break;
      case 0x06:
        out.initialMaxStreamDataBidiRemote = readVarIntVal(valueBytes);
        break;
      case 0x07:
        out.initialMaxStreamDataUni = readVarIntVal(valueBytes);
        break;
      case 0x08:
        out.initialMaxStreamsBidi = readVarIntVal(valueBytes);
        break;
      case 0x09:
        out.initialMaxStreamsUni = readVarIntVal(valueBytes);
        break;
      case 0x0a:
        out.ackDelayExponent = readVarIntVal(valueBytes);
        break;
      case 0x0b:
        out.maxAckDelay = readVarIntVal(valueBytes);
        break;
      case 0x0c:
        if (length != 0) {
          throw Exception("disable_active_migration must be zero-length");
        }
        out.disableActiveMigration = true;
        break;
      case 0x0e:
        out.activeConnectionIdLimit = readVarIntVal(valueBytes);
        break;
      case 0x0f:
        out.initialSourceConnectionId = valueBytes;
        break;
      case 0x10:
        out.retrySourceConnectionId = valueBytes;
        break;
      case 0x20:
        out.maxDatagramFrameSize = readVarIntVal(valueBytes);
        break;
      case 0x11:
        out.serverCertificateHash = valueBytes;
        break;
      case 0x2b603742:
        // JS: var origin = new TextDecoder().decode(valueBytes);
        final origin = utf8.decode(valueBytes);
        out.webAcceptedOrigins.add(origin);
        break;
      default:
        // JS: out.unknown ??= []; out.unknown.add({ id: id, bytes: valueBytes });
        out.unknown ??= [];
        out.unknown!.add({ 'id': id, 'bytes': valueBytes });
    }
  }

  return out;
}

// Placeholder for Extension Data
class TlsExtension {
  final int type;
  final Uint8List data;
  TlsExtension({required this.type, required this.data});
}

// Data class for parsed TLS ClientHello
class TlsClientHello {
  final String type = 'client_hello'; // Fixed value
  final int legacyVersion;
  final Uint8List random;
  final Uint8List sessionId;
  final List<int> cipherSuites;
  final Uint8List compressionMethods;
  final List<TlsExtension> extensions;
  String? sni;
  final List<Map<String, dynamic>> keyShares;
  final List<int> supportedVersions;
  final List<int> supportedGroups;
  final List<int> signatureAlgorithms;
  final List<String> alpn;
  int? maxFragmentLength;
  Uint8List? padding;
  Uint8List? cookie;
  final List<int> pskKeyExchangeModes;
  Uint8List? preSharedKey;
  Uint8List? renegotiationInfo;
  
  // For parse_tls_client_hello2
  Map<int, Uint8List>? quicTransportParametersOriginal;
  // For parse_tls_client_hello (raw)
  Uint8List? quicTransportParametersRaw;
  
  TlsClientHello({
    required this.legacyVersion,
    required this.random,
    required this.sessionId,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
    required this.keyShares,
    required this.supportedVersions,
    required this.supportedGroups,
    required this.signatureAlgorithms,
    required this.alpn,
    required this.pskKeyExchangeModes,
  });
}

/// Represents a parsed TLS message record.
class TlsMessage {
  final int type;
  final int length;
  final Uint8List body;

  TlsMessage({required this.type, required this.length, required this.body});
}

TlsMessage parseTlsMessage(Uint8List data) {
  // Use data directly as Uint8List
  if (data.length < 4) {
    throw Exception("TLS message too short");
  }

  final type = data[0];
  
  // Combine 3 bytes into a single 24-bit length integer
  final length = (data[1] << 16) | (data[2] << 8) | data[3];

  if (4 + length > data.length) {
    throw Exception("TLS message body truncated");
  }

  // Dart's sublist is the equivalent of JavaScript's slice on Uint8Array
  // Start after the 4-byte header (type + 3-byte length)
  final body = data.sublist(4, 4 + length); 

  return TlsMessage(type: type, length: length, body: body);
}

/// Helper function equivalent to the inner JavaScript function `toNumber`.
/// Converts a byte array (Big-Endian) to an integer.
int bytesToNumber(Uint8List bytes) {
  int n = 0;
  for (var byte in bytes) {
    n = (n << 8) | byte;
  }
  return n;
}

/// Core function to parse the common parts of a TLS ClientHello body.
TlsClientHello _parseTlsClientHelloCore(Uint8List body, {bool extendedQuicParsing = false}) {
  var ptr = 0;

  // --- Header Parsing ---
  if (body.length < 43) throw Exception("ClientHello body too short");

  // legacy_version (2 bytes)
  final legacyVersion = (body[ptr++] << 8) | body[ptr++]; 

  // random (32 bytes)
  final random = body.sublist(ptr, ptr + 32); ptr += 32;

  // session_id (1 byte length prefix + data)
  final sessionIdLen = body[ptr++];
  final sessionId = body.sublist(ptr, ptr + sessionIdLen); ptr += sessionIdLen;

  // cipher_suites (2 byte length prefix + data)
  final cipherSuitesLen = (body[ptr++] << 8) | body[ptr++];
  final cipherSuites = <int>[];
  if (cipherSuitesLen % 2 != 0) throw Exception("Cipher suite list length must be even");
  for (var i = 0; i < cipherSuitesLen; i += 2) {
    final code = (body[ptr++] << 8) | body[ptr++];
    cipherSuites.add(code);
  }

  // compression_methods (1 byte length prefix + data)
  final compressionMethodsLen = body[ptr++];
  final compressionMethods = body.sublist(ptr, ptr + compressionMethodsLen); ptr += compressionMethodsLen;

  // extensions (2 byte length prefix + data)
  final extensionsLen = (body[ptr++] << 8) | body[ptr++];
  final extensions = <TlsExtension>[];
  final extEnd = ptr + extensionsLen;
  while (ptr < extEnd) {
    if (ptr + 4 > extEnd) throw Exception("Truncated extension header");
    final extType = (body[ptr++] << 8) | body[ptr++];
    final extLen = (body[ptr++] << 8) | body[ptr++];
    if (ptr + extLen > extEnd) throw Exception("Truncated extension data");
    final extData = body.sublist(ptr, ptr + extLen); ptr += extLen;
    extensions.add(TlsExtension(type: extType, data: extData));
  }
  
  // Instantiate result object
  final out = TlsClientHello(
    legacyVersion: legacyVersion,
    random: random,
    sessionId: sessionId,
    cipherSuites: cipherSuites,
    compressionMethods: compressionMethods,
    extensions: extensions,
    keyShares: [],
    supportedVersions: [],
    supportedGroups: [],
    signatureAlgorithms: [],
    alpn: [],
    pskKeyExchangeModes: [],
  );

  // --- Extension Processing ---
  for (var ext in extensions) {
    final extView = ext.data;
    switch (ext.type) {
      case 0x00: // Server Name Indication (SNI)
        // Note: The logic for 0x00 is different between the two JS functions.
        // We use the simpler logic from `parse_tls_client_hello2` here, and adjust below.
        // The more standard TLS 1.3/QUIC parsing usually uses the complex SNI logic from `parse_tls_client_hello`.
        // We'll stick to the logic for the original function names.

        if (extendedQuicParsing) { // Logic from `parse_tls_client_hello2`
          if (extView.length >= 5) {
            final nameLen = (extView[3] << 8) | extView[4];
            out.sni = utf8.decode(extView.sublist(5, 5 + nameLen));
          }
        } else { // Logic from `parse_tls_client_hello` (more standard SNI)
          if (extView.length >= 5) {
            // var list_len = (ext_view[0] << 8) | ext_view[1]; // Ignored
            // var name_type = ext_view[2]; // Ignored (assumed hostname=0)
            final nameLen = (extView[3] << 8) | extView[4];
            out.sni = utf8.decode(extView.sublist(5, 5 + nameLen));
          }
        }
        break;
      case 0x33: // Key Share
        var ptr2 = 0;
        // var list_len = (extView[ptr2++] << 8) | extView[ptr2++]; // Ignored
        ptr2 += 2;
        final end = ptr2 + extView.length; // Use end of buffer as boundary
        while (ptr2 < end) {
          if (ptr2 + 4 > extView.length) break; // Check remaining bytes for group + key_len
          final group = (extView[ptr2++] << 8) | extView[ptr2++];
          final keyLen = (extView[ptr2++] << 8) | extView[ptr2++];
          if (ptr2 + keyLen > extView.length) break; // Check remaining bytes for key data
          final pubkey = extView.sublist(ptr2, ptr2 + keyLen);
          ptr2 += keyLen;
          out.keyShares.add({'group': group, 'pubkey': pubkey});
        }
        break;
      case 0x2b: // Supported Versions
        final len = extView[0];
        for (var i = 1; i < 1 + len; i += 2) {
          if (i + 1 < extView.length) {
            out.supportedVersions.add((extView[i] << 8) | extView[i + 1]);
          }
        }
        break;
      case 0x0a: // Supported Groups (Elliptic Curves)
        // var len = (extView[0] << 8) | extView[1]; // Ignored
        for (var i = 2; i < extView.length; i += 2) {
          if (i + 1 < extView.length) {
            out.supportedGroups.add((extView[i] << 8) | extView[i + 1]);
          }
        }
        break;
      case 0x0d: // Signature Algorithms
        // var len = (extView[0] << 8) | extView[1]; // Ignored
        for (var i = 2; i < extView.length; i += 2) {
          if (i + 1 < extView.length) {
            out.signatureAlgorithms.add((extView[i] << 8) | extView[i + 1]);
          }
        }
        break;
      case 0x10: // Application-Layer Protocol Negotiation (ALPN)
        // var list_len = (extView[0] << 8) | extView[1]; // Ignored
        var i = 2;
        while (i < extView.length) {
          final nameLen = extView[i++];
          if (i + nameLen <= extView.length) {
            final proto = utf8.decode(extView.sublist(i, i + nameLen));
            out.alpn.add(proto);
            i += nameLen;
          } else {
            break; // Truncated protocol name
          }
        }
        break;
      case 0x39: // QUIC Transport Parameters
        if (extendedQuicParsing) {
          // Logic from parse_tls_client_hello2: detailed parameter parsing
          final extData = ext.data;
          var ptr2 = 0;
          out.quicTransportParametersOriginal = {};
          
          while (ptr2 < extData.length) {
            final idRes = readVarInt(extData, ptr2);
            if (idRes == null) break;
            final id = idRes.value;
            ptr2 += idRes.byteLength;

            final lenRes = readVarInt(extData, ptr2);
            if (lenRes == null) break;
            final len = lenRes.value;
            ptr2 += lenRes.byteLength;

            final value = extData.sublist(ptr2, ptr2 + len);
            ptr2 += len;
            
            // Populate the map containing all parameters
            out.quicTransportParametersOriginal![id] = value;
            
            // The original function then selectively converts some to numbers
            if (id == 0x00) out.quicTransportParametersOriginal![id] = value; // This key is duplicated, but kept for fidelity
            if (id == 0x01) out.quicTransportParametersOriginal![id] = value;
            // ... (other parameters are omitted here for brevity but should be added)
            if (id == 0x2b603742) {
              try {
                out.quicTransportParametersOriginal![id] = value;
              } catch (e) { /* ignore error */ }
            }
          }
        } else {
          // Logic from parse_tls_client_hello: store raw bytes
          out.quicTransportParametersRaw = ext.data;
        }
        break;
      case 0x01: // Max Fragment Length
        if (extView.isNotEmpty) out.maxFragmentLength = extView[0];
        break;
      case 0x15: // Padding
        out.padding = extView;
        break;
      case 0x002a: // Cookie
        if (extView.length >= 2) {
          final len = (extView[0] << 8) | extView[1];
          out.cookie = extView.sublist(2, 2 + len);
        }
        break;
      case 0x2d: // PSK Key Exchange Modes
        final len = extView[0];
        for (var i = 1; i <= len; i++) {
          if (i < extView.length) {
            out.pskKeyExchangeModes.add(extView[i]);
          }
        }
        break;
      case 0x29: // PreSharedKey
        out.preSharedKey = extView;
        break;
      case 0xff01: // Renegotiation Info
        out.renegotiationInfo = extView;
        break;
    }
  }

  return out;
}

// Wrapper 1: Matches JavaScript `parse_tls_client_hello2`
TlsClientHello parseTlsClientHello2(Uint8List body) {
  return _parseTlsClientHelloCore(body, extendedQuicParsing: true);
}

// Wrapper 2: Matches JavaScript `parse_tls_client_hello`
TlsClientHello parseTlsClientHello(Uint8List body) {
  return _parseTlsClientHelloCore(body, extendedQuicParsing: false);
}



////////////////////////////////
/// Abstract class to represent the cryptographic hash function (e.g., SHA-256).
/// It mimics the required JS structure: being callable and having an output length.
// abstract class HashFunc {
//   /// The hash function itself.
//   Uint8List call(Uint8List data); 
  
//   /// The output length of the hash function (e.g., 32 for SHA-256).
//   int get outputLen; 
// }

/// Placeholder for HMAC computation.
Uint8List hmac(String hash, Uint8List key, Uint8List data) {
  // Implementation relies on a Dart crypto library
  throw UnimplementedError('hmac must be implemented with a Dart crypto package.');
}

/// Placeholder for HKDF-Extract operation.
Uint8List hkdfExtract(Uint8List salt, Uint8List ikm, HashFunc hashFunc) {
  // Implementation relies on a Dart crypto library
  throw UnimplementedError('hkdfExtract must be implemented with a Dart crypto package.');
}

/// Placeholder for HKDF-Expand operation.
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int length, HashFunc hashFunc) {
  // Implementation relies on a Dart crypto library
  throw UnimplementedError('hkdfExpand must be implemented with a Dart crypto package.');
}

/// Assumed helper to concatenate a list of byte arrays.
Uint8List concatUint8Arrays(List<Uint8List> buffers) {
  final totalLength = buffers.fold<int>(0, (sum, buf) => sum + buf.length);
  final result = Uint8List(totalLength);
  int offset = 0;
  for (final buf in buffers) {
    result.setAll(offset, buf);
    offset += buf.length;
  }
  return result;
}

// ====================================================================
// TLS 1.3 HKDF LOGIC
// ====================================================================

/// Constructs the byte array for a TLS 1.3 HKDF-Expand-Label operation's 'info' field.
///
/// Format: Length (2 bytes, BE) | Label Length (1 byte) | Label (bytes) | Context Length (1 byte) | Context (bytes)
Uint8List buildHkdfLabel(String label, Uint8List context, int length) {
  const prefix = "tls13 ";
  final fullLabelBytes = utf8.encode(prefix + label);
  
  final infoLength = 2 + 1 + fullLabelBytes.length + 1 + context.length;
  final info = Uint8List(infoLength);
  final view = ByteData.view(info.buffer);

  // 1. Length (2-bytes, Big Endian)
  view.setUint16(0, length, Endian.big);
  
  // 2. Label Length (1-byte) + Label Bytes
  info[2] = fullLabelBytes.length;
  info.setAll(3, fullLabelBytes);

  // 3. Context Length (1-byte) + Context Bytes
  final ctxOfs = 3 + fullLabelBytes.length;
  info[ctxOfs] = context.length;
  info.setAll(ctxOfs + 1, context);

  return info;
}

/// TLS 1.3 specific wrapper around HKDF-Expand.
/// Creates the structured 'info' array using [buildHkdfLabel] and then expands the secret.
Uint8List hkdfExpandLabel(
    Uint8List secret,
    String label,
    Uint8List context,
    int length,
    HashFunc hashFunc) {
  final info = buildHkdfLabel(label, context, length);
  return hkdfExpand(secret, info, length, hashFunc);
}

/// Hashes a sequence of handshake messages by concatenating them and then
/// applying the specified hash function. This is equivalent to updating a single
/// hash context with all messages sequentially.
Uint8List hashTranscript(List<Uint8List> messages, HashFunc hashFunc) {
  final total = concatUint8Arrays(messages);
  return hashFunc(total);
}

// ====================================================================
// APPLICATION SECRETS DERIVATION
// ====================================================================

/// Simple class to hold the derived application secrets.
class ApplicationSecrets {
  final Uint8List clientApplicationTrafficSecret;
  final Uint8List serverApplicationTrafficSecret;
  ApplicationSecrets({
    required this.clientApplicationTrafficSecret,
    required this.serverApplicationTrafficSecret,
  });
}

/// Derives the client and server application traffic secrets from the TLS 1.3 
/// Handshake Secret and the Handshake Transcript Hash.
ApplicationSecrets tlsDeriveAppSecrets(
    Uint8List handshakeSecret,
    List<Uint8List> transcript,
    HashFunc hashFunc) {
  final hashLen = hashFunc.outputLen;
  final empty = Uint8List(0);
  final zero = Uint8List(hashLen); // Hash length zero-filled array

  // Step 1: Derive "Derived Secret"
  // This step protects the Master Secret from the Handshake Secret compromise.
  final derivedSecret = hkdfExpandLabel(
    handshakeSecret,
    "derived",
    hashFunc(empty), // Context is the Hash of an empty string
    hashLen,
    hashFunc,
  );
  
  // Step 2: Calculate Master Secret
  // Salt is the Derived Secret, IKM is the zero-filled array.
  final masterSecret = hkdfExtract(derivedSecret, zero, hashFunc);

  // Step 3: Hash the transcript (up to Server Finished/Client Finished for different phases)
  // For application secrets, the full handshake transcript hash is used.
  final transcriptHash = hashTranscript(transcript, hashFunc);

  // Step 4: Derive Application Traffic Secrets
  final clientApp = hkdfExpandLabel(
    masterSecret,
    'c ap traffic',
    transcriptHash,
    hashLen,
    hashFunc,
  );
  
  final serverApp = hkdfExpandLabel(
    masterSecret,
    's ap traffic',
    transcriptHash,
    hashLen,
    hashFunc,
  );

  return ApplicationSecrets(
    clientApplicationTrafficSecret: clientApp,
    serverApplicationTrafficSecret: serverApp,
  );
}
// --- Assuming these imports/placeholders are available from your crypto library ---
// typedef Uint8List HashFunction(Uint8List data);
// typedef Uint8List HkdfExtractFunction(Uint8List salt, Uint8List ikm, HashFunction hashFunc);
// typedef Uint8List HkdfExpandLabelFunction(Uint8List secret, String label, Uint8List context, int length, HashFunction hashFunc);
// typedef Uint8List AesGcmDecryptPrimitive(Uint8List key, Uint8List nonce, Uint8List ciphertextWithTag, Uint8List aad);
// typedef Uint8List AesEcbEncryptPrimitive(Uint8List key, Uint8List plaintext);

// Placeholder classes/functions (You must provide actual crypto implementations)
class HashFunc {
  final int outputLen;
  final String name;
  HashFunc(this.name, this.outputLen);
}

// Function signature placeholders:
Uint8List sha256(Uint8List data) => throw UnimplementedError("sha256 implementation required.");
Uint8List hashTranscript(Uint8List transcript, HashFunc hashFunc) => throw UnimplementedError("hashTranscript implementation required.");
Uint8List hkdfExtract(Uint8List salt, Uint8List ikm, HashFunc hashFunc) => throw UnimplementedError("hkdfExtract implementation required.");
Uint8List hkdfExpandLabel(Uint8List secret, String label, Uint8List context, int length, HashFunc hashFunc) => throw UnimplementedError("hkdfExpandLabel implementation required.");
Uint8List aesGcmDecryptPrimitive(Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List tag, Uint8List aad) => throw UnimplementedError("AES-GCM Decrypt implementation required (e.g., using pointycastle).");
Uint8List aesEcbEncryptPrimitive(Uint8List key, Uint8List plaintext) => throw UnimplementedError("AES-ECB Encrypt implementation required (e.g., using pointycastle).");


// Result structure for Handshake secrets
class TlsHandshakeSecrets {
  final Uint8List handshakeSecret;
  final Uint8List clientHandshakeTrafficSecret;
  final Uint8List serverHandshakeTrafficSecret;
  final Uint8List transcriptHash;

  TlsHandshakeSecrets({
    required this.handshakeSecret,
    required this.clientHandshakeTrafficSecret,
    required this.serverHandshakeTrafficSecret,
    required this.transcriptHash,
  });
}

// Result structure for QUIC Initial Secrets
class QuicSecrets {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  QuicSecrets({required this.key, required this.iv, required this.hp});
}

// QUIC Initial Salts (Mapping int version to Uint8List salt)
final Map<int, Uint8List> initialSalts = {
  // QUIC v1 (RFC 9001)
  0x00000001: Uint8List.fromList([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
  ]),

  // QUIC draft-29 (HTTP/3 version h3-29)
  0xff00001d: Uint8List.fromList([
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 
    0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
  ]),

  // QUIC draft-32 (h3-32)
  0xff000020: Uint8List.fromList([
    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0x77, 0x7b, 0xe3, 
    0x0e, 0xbd, 0x5f, 0xa5, 0x15, 0x87, 0x3d, 0x8d, 0x6e, 0x67
  ]),

  // Google QUIC v50 ("Q050")
  0x51303530: Uint8List.fromList([
    0x69, 0x45, 0x6f, 0xbe, 0xf1, 0x6e, 0xd7, 0xdc, 0x48, 0x15, 
    0x9d, 0x98, 0xd0, 0x7f, 0x5c, 0x3c, 0x3d, 0x5a, 0xa7, 0x0a
  ]),
};

/// Derives the TLS 1.3 Handshake Traffic Secrets from the shared secret (e.g., DH).
/// 
/// Corresponds to the steps in RFC 8446 (TLS 1.3) used for QUIC.
TlsHandshakeSecrets tlsDeriveHandshakeSecrets(
  Uint8List sharedSecret, 
  Uint8List transcript, 
  HashFunc hashFunc
) {
  final zero = Uint8List(hashFunc.outputLen);
  final empty = Uint8List(0);

  // 1. Calculate Early Secret
  final earlySecret = hkdfExtract(empty, zero, hashFunc); // Salt: empty, IKM: zero hash

  // 2. Calculate Derived Secret from Early Secret
  // Context is Hash(empty) because there is no prior handshake flight
  final derivedSecret = hkdfExpandLabel(
    earlySecret, 
    "derived", 
    hashFunc(empty), // Hash(empty) as context
    hashFunc.outputLen, 
    hashFunc
  );

  // 3. Calculate Handshake Secret
  final handshakeSecret = hkdfExtract(derivedSecret, sharedSecret, hashFunc); // Salt: Derived, IKM: Shared Secret (DH)

  // 4. Calculate Transcript Hash of ClientHello
  final transcriptHash = hashTranscript(transcript, hashFunc);

  // 5. Calculate Client/Server Handshake Traffic Secrets
  final clientHts = hkdfExpandLabel(handshakeSecret, "c hs traffic", transcriptHash, hashFunc.outputLen, hashFunc);
  final serverHts = hkdfExpandLabel(handshakeSecret, "s hs traffic", transcriptHash, hashFunc.outputLen, hashFunc);

  return TlsHandshakeSecrets(
    handshakeSecret: handshakeSecret,
    clientHandshakeTrafficSecret: clientHts,
    serverHandshakeTrafficSecret: serverHts,
    transcriptHash: transcriptHash,
  );
}
/// Derives the Initial Protection Keys and IVs for the QUIC Initial packets.
QuicSecrets quicDeriveInitSecrets(
  Uint8List clientDcid, 
  int version, 
  String direction // 'read' or 'write' (which corresponds to 'client in' or 'server in' for the peer)
) {
  // Using a placeholder for SHA-256 hash function details
  final hashFunc = HashFunc("sha256", 32); 
  
  final salt = initialSalts[version];
  if (salt == null) {
    throw Exception("Unsupported QUIC version: 0x${version.toRadixString(16)}");
  }

  // Determine the label based on which direction we are deriving secrets for.
  // QUIC RFC 9001 defines 'client in' and 'server in'
  final label = direction == 'read' ? 'client in' : 'server in';
  
  // 1. Initial Secret
  final initialSecret = hkdfExtract(salt, clientDcid, hashFunc);

  // 2. Initial Secret 2 (Traffic Secret)
  final initialSecret2 = hkdfExpandLabel(
    initialSecret,
    label,
    Uint8List(0), // Context is always empty for traffic secrets
    32, // HKDF-Extract output length (SHA-256)
    hashFunc
  );

  // 3. Derive AEAD Key, IV, and Header Protection Key
  // QUIC uses AES-128-GCM (16 bytes key, 12 bytes IV, 16 bytes HP key) for Initial packets.
  final key = hkdfExpandLabel(initialSecret2, 'quic key', Uint8List(0), 16, hashFunc);
  final iv = hkdfExpandLabel(initialSecret2, 'quic iv', Uint8List(0), 12, hashFunc);
  final hp = hkdfExpandLabel(initialSecret2, 'quic hp', Uint8List(0), 16, hashFunc);

  return QuicSecrets(key: key, iv: iv, hp: hp);
}


/// Derives the QUIC Keys/IVs/HP keys from a given TLS traffic secret
/// (e.g., Handshake or Application Traffic Secrets).
QuicSecrets? quicDeriveFromTlsSecrets(Uint8List? trafficSecret) {
  if (trafficSecret == null) return null;

  // Assuming SHA-256 for TLS 1.3 handshake hash
  final hashFunc = HashFunc("sha256", 32); 

  // QUIC uses AES-128-GCM (16 bytes key, 12 bytes IV, 16 bytes HP key)
  final key = hkdfExpandLabel(trafficSecret, 'quic key', Uint8List(0), 16, hashFunc);
  final iv = hkdfExpandLabel(trafficSecret, 'quic iv', Uint8List(0), 12, hashFunc);
  final hp = hkdfExpandLabel(trafficSecret, 'quic hp', Uint8List(0), 16, hashFunc);

  return QuicSecrets(key: key, iv: iv, hp: hp);
}

/// Calculates the QUIC AEAD nonce.
/// Nonce is computed as IV XOR (big-endian 64-bit Packet Number).
/// The IV is 12 bytes. The 64-bit Packet Number is left-padded with zeros 
/// and XORed with the rightmost 8 bytes of the IV.
Uint8List computeNonce(Uint8List iv, int packetNumber) {
  if (iv.length != 12) {
    throw ArgumentError("IV must be 12 bytes for QUIC AEAD.");
  }
  
  // Create a mutable copy of the IV
  final nonce = Uint8List.fromList(iv); 
  
  // Create an 8-byte buffer for the packet number (64-bit, big-endian)
  final pnBuffer = Uint8List(8); 
  
  // Use ByteData to safely write the 64-bit integer in Big Endian format.
  final byteData = ByteData(8);
  byteData.setUint64(0, packetNumber, Endian.big);
  
  // Copy to pnBuffer
  pnBuffer.setAll(0, byteData.buffer.asUint8List());

  // XOR the rightmost 8 bytes of the IV (indices 4-11) with the 8 bytes of pnBuffer.
  // The first 4 bytes of the 12-byte IV remain untouched.
  for (var i = 0; i < 8; i++) {
    // pnBuffer[i] is byte 0 to 7 of the 64-bit packet number
    // nonce[i + 4] is byte 4 to 11 of the 12-byte IV/Nonce
    nonce[i + 4] ^= pnBuffer[i];
  }

  return nonce;
}

// NOTE: The JS `aead_decrypt` uses a callback, which is a JS idiom for async/error handling.
// Dart typically uses Futures/async-await or returns null/throws exceptions.
// Since the underlying crypto operations are often synchronous in crypto libraries, 
// we will port this to a synchronous function that returns null on failure.

/// Performs AES-GCM decryption following the QUIC nonce construction.
/// 
/// Note: The original JS function used a callback, which is replaced by a 
/// synchronous `try/catch` block returning `Uint8List?`.
Uint8List? aeadDecrypt(
  Uint8List key, 
  Uint8List iv, 
  int packetNumber, 
  Uint8List ciphertextWithTag, 
  Uint8List aad
) {
  try {
    if (ciphertextWithTag.length < 16) {
      throw Exception("Ciphertext must contain at least a 16-byte tag.");
    }
    
    // 1. Compute Nonce
    final nonce = computeNonce(iv, packetNumber);

    // 2. Separate Tag (16 bytes) and Ciphertext
    final tag = ciphertextWithTag.sublist(ciphertextWithTag.length - 16);
    final ciphertext = ciphertextWithTag.sublist(0, ciphertextWithTag.length - 16);
    
    // 3. Determine Key length for algorithm check (though QUIC only uses 128/256)
    if (key.length != 16 && key.length != 32) {
      throw Exception("Unsupported key length: ${key.length}. Must be 16 or 32 bytes.");
    }

    // 4. Perform Decryption (Placeholder for crypto library function)
    final decrypted = aesGcmDecryptPrimitive(key, nonce, ciphertext, tag, aad);
    
    return decrypted;
  } catch (e) {
    // Catch decryption failure (e.g., authentication failed)
    print("AEAD Decryption failed: $e");
    return null;
  }
}

/// Performs AES-GCM encryption following the QUIC nonce construction.
Uint8List? aeadEncrypt(
  Uint8List key, 
  Uint8List iv, 
  int packetNumber, 
  Uint8List plaintext, 
  Uint8List aad
) {
  try {
    // 1. Determine Key length
    if (key.length != 16 && key.length != 32) {
      throw Exception("Unsupported key length: ${key.length}. Must be 16 or 32 bytes.");
    }

    // 2. Compute Nonce
    final nonce = computeNonce(iv, packetNumber);

    // 3. Perform Encryption (This needs a proper AEAD encrypt primitive)
    // Since the JS function returns the combined ciphertext+tag, we need a helper
    // that produces both the ciphertext and the 16-byte tag.
    
    // This part is highly dependent on the Dart crypto library used.
    // For simplicity, we assume an encrypt primitive that returns a combined result.
    // NOTE: For GCM, the primitive must return (ciphertext + tag).

    // --- Placeholder for combined encryption primitive ---
    Uint8List combinedCiphertextTag(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
        throw UnimplementedError("Combined AES-GCM Encrypt implementation required.");
    }
    // --- End Placeholder ---
    
    final combined = combinedCiphertextTag(key, nonce, plaintext, aad);
    return combined;

  } catch (e) {
    print("AEAD Encryption failed: $e");
    return null;
  }
}


/// Performs raw AES-GCM decryption (equivalent to JS `aes_gcm_decrypt`).
/// This function is not QUIC-specific as it takes a pre-calculated `nonce`.
Uint8List? aesGcmDecrypt(
  Uint8List ciphertext, 
  Uint8List tag, 
  Uint8List key, 
  Uint8List nonce, 
  Uint8List aad
) {
  try {
    if (key.length != 16 && key.length != 32) {
      throw Exception("Unsupported key length: ${key.length}. Must be 16 or 32 bytes.");
    }

    // Perform Decryption (Placeholder for crypto library function)
    final decrypted = aesGcmDecryptPrimitive(key, nonce, ciphertext, tag, aad);

    //print("✅ Decryption success!");
    return decrypted;
  } catch (e) {
    // print("Decryption failed: $e");
    return null;
  }
}

/// Performs AES in ECB mode for Header Protection.
Uint8List aesEcbEncrypt(Uint8List keyBytes, Uint8List plaintext) {
  if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
    throw ArgumentError("Invalid AES key size: ${keyBytes.length} bytes.");
  }

  // The plaintext for header protection MUST be 16 bytes.
  if (plaintext.length % 16 != 0) {
    throw ArgumentError("Plaintext length must be a multiple of 16 bytes.");
  }

  // Perform ECB encryption (Placeholder for crypto library function)
  final encrypted = aesEcbEncryptPrimitive(keyBytes, plaintext);
  return encrypted;
}

// Simple AES-128-ECB implementation wrapper (JS: aes128ecb)
Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey) {
  if (hpKey.length != 16) {
    throw ArgumentError("AES-128-ECB key must be 16 bytes.");
  }
  // This calls the generic ECB function with the 16-byte key
  return aesEcbEncrypt(hpKey, sample);
}
/// Applies Header Protection (XORing the first byte and the Packet Number)
/// using the result of AES-ECB(HP Key, Sample).
Uint8List applyHeaderProtection(
  Uint8List packet, 
  int pnOffset, 
  Uint8List hpKey, 
  int pnLength
) {
  // QUIC Header Protection Sample is 16 bytes starting at pnOffset + 4
  const sampleLength = 16;
  if (pnOffset + 4 + sampleLength > packet.length) {
    throw Exception("Not enough bytes for header protection sample");
  }

  // 1. Get sample
  final sample = packet.sublist(pnOffset + 4, pnOffset + 4 + sampleLength);

  // 2. Encrypt sample using AES-ECB
  final maskFull = aesEcbEncrypt(hpKey, sample);
  final mask = maskFull.sublist(0, 5); // Use the first 5 bytes of the output

  // Create a mutable copy of the packet
  final resultPacket = Uint8List.fromList(packet);
  
  // 3. Apply mask to the first byte (Header Type)
  final firstByte = resultPacket[0];
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    // Long Header: Only XOR the lowest 4 bits (Version Specific + Reserved + Packet Number Length)
    resultPacket[0] ^= (mask[0] & 0x0f); 
  } else {
    // Short Header: Only XOR the lowest 5 bits (Key Phase + Reserved + Packet Number Length)
    resultPacket[0] ^= (mask[0] & 0x1f); 
  }

  // 4. Apply mask to the Packet Number field (pnLength bytes)
  for (var i = 0; i < pnLength; i++) {
    resultPacket[pnOffset + i] ^= mask[1 + i];
  }

  return resultPacket;
}

/// Decodes a truncated Packet Number from the byte array.
int decodePacketNumber(Uint8List array, int offset, int pnLength) {
  int value = 0;
  for (var i = 0; i < pnLength; i++) {
    // Dart handles the shift correctly without explicit masks like `| array[offset + i]`
    value = (value << 8) | array[offset + i]; 
  }
  return value;
}

/// Expands the truncated Packet Number based on the largest previously received.
/// 
/// Corresponds to RFC 9000, Section 17.1.
int expandPacketNumber(int truncated, int pnLen, int largestReceived) {
  final pnWin = 1 << (pnLen * 8);
  final pnHalf = pnWin >> 1;
  final expected = largestReceived + 1;
  
  // The logic to find the closest value:
  // 1. Calculate the value of the expected packet number with the current window: `expected & ~(pnWin - 1)`
  // 2. Adjust it by adding the truncated value: `(expected & ~(pnWin - 1)) | truncated`
  // 3. Find which value (current window or next window) is closest to `expected`.
  
  // Dart version of the JavaScript math:
  // return truncated + pnWin * Math.floor((expected - truncated + pnHalf) / pnWin);
  return truncated + (pnWin * ((expected - truncated + pnHalf) / pnWin).floor());
}


/// Combines decoding and expansion of the Packet Number.
int decodeAndExpandPacketNumber(
  Uint8List array, 
  int offset, 
  int pnLength, 
  int largestReceived
) {
  final truncated = decodePacketNumber(array, offset, pnLength);
  return expandPacketNumber(truncated, pnLength, largestReceived);
}

// --- Required Helper Class ---
class QuicDecryptedPacket {
  final int packetNumber;
  final bool keyPhase;
  final Uint8List? plaintext; // Null if decryption/authentication fails

  QuicDecryptedPacket({
    required this.packetNumber,
    required this.keyPhase,
    this.plaintext,
  });
}

// NOTE: The following required functions must be implemented (or mocked) elsewhere:
// Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey);
// VarIntReadResult? readVarInt(Uint8List array, int offset);
// int decodeAndExpandPacketNumber(Uint8List array, int offset, int pnLength, int largestReceived);
// Uint8List computeNonce(Uint8List iv, int packetNumber);
// Uint8List? aesGcmDecrypt(Uint8List ciphertext, Uint8List tag, Uint8List key, Uint8List nonce, Uint8List aad);
/// Reverses the Header Protection mechanism, unmasking the first header byte 
/// and the Packet Number field.
/// 
/// The [array] is modified in place.
/// Returns the Packet Number Length (1, 2, 3, or 4 bytes).
int removeHeaderProtection(Uint8List array, int pnOffset, Uint8List hpKey, bool isShort) {
  // Step 1: Get the 16-byte sample from the encrypted payload
  var sampleOffset = pnOffset + 4;
  const sampleLength = 16;
  if (sampleOffset + sampleLength > array.length) {
    throw Exception("Not enough bytes for header protection sample");
  }
  final sample = array.sublist(sampleOffset, sampleOffset + sampleLength);

  // Use AES-128-ECB to generate the 5-byte mask
  final maskFull = aes128Ecb(sample, hpKey);
  final mask = maskFull.sublist(0, 5);

  // Step 2: Remove protection from the first byte
  if (isShort) {
    // Short Header: XOR the 5 lowest bits (0x1f = 0b0001_1111)
    array[0] ^= mask[0] & 0x1f;
  } else {
    // Long Header: XOR the 4 lowest bits (0x0f = 0b0000_1111)
    array[0] ^= mask[0] & 0x0f;
  }

  // Step 3: Determine Packet Number Length and remove protection from the PN field
  // pnLength is determined by the two lowest bits of the now-unmasked first byte.
  final pnLength = (array[0] & 0x03) + 1;

  if (pnOffset + pnLength > array.length) {
    throw Exception("Packet number field extends beyond packet length after header protection removal.");
  }

  for (var i = 0; i < pnLength; i++) {
    // mask[1] is for the first PN byte, mask[2] for the second, etc.
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}

/// Parses, removes header protection, decrypts, and authenticates a QUIC packet.
/// 
/// Returns a [QuicDecryptedPacket] containing the plaintext and metadata, or `null` 
/// if decryption/authentication fails.
QuicDecryptedPacket? decryptQuicPacket(
  Uint8List array, 
  Uint8List readKey, 
  Uint8List readIv, 
  Uint8List readHp, 
  Uint8List dcid, // Required for Short Header parsing
  int largestPn // Largest packet number received so far
) {
  // Use a mutable copy of the input array because `removeHeaderProtection` modifies it.
  // Dart's `Uint8List.fromList` creates a deep copy.
  final mutableArray = Uint8List.fromList(array); 

  final firstByte = mutableArray[0];
  final isShort = (firstByte & 0x80) == 0;
  
  // Variables to be populated
  bool keyPhase = false;
  int pnOffset = 0;
  int pnLength = 0;
  late Uint8List aad; 
  late Uint8List ciphertext;
  late Uint8List tag;
  int? packetNumber;
  Uint8List? nonce;

  try {
    if (!isShort) {
      // ---------- Long Header Parsing ----------
      final view = ByteData.view(mutableArray.buffer, mutableArray.offsetInBytes, mutableArray.length);
      if (mutableArray.length < 6) throw Exception("Truncated Long Header");

      // Version is at offset 1 (4 bytes)
      // final version = view.getUint32(1, Endian.big); // Not used for decryption, but available

      // Destination Connection ID (DCID) Length is at offset 5
      final dcidLen = mutableArray[5];
      
      int offset = 6;
      offset += dcidLen; // Skip DCID
      
      if (offset >= mutableArray.length) throw Exception("Truncated Long Header (SCID length missing)");
      
      final scidLen = mutableArray[offset++];
      offset += scidLen; // Skip Source Connection ID (SCID)

      if (offset >= mutableArray.length) throw Exception("Truncated Long Header (rest missing)");
      
      final typeBits = (firstByte & 0x30) >> 4;

      // Handle Token field (Initial packets only, typeBits == 0)
      if (typeBits == 0) {
        final tokenLenVar = readVarInt(mutableArray, offset);
        if (tokenLenVar == null) throw Exception("Bad varint (token len) at $offset");
        offset += tokenLenVar.byteLength + tokenLenVar.value;
      }

      // Packet Length (VarInt)
      final lenVar = readVarInt(mutableArray, offset);
      if (lenVar == null) throw Exception("Bad varint (length) at $offset");
      offset += lenVar.byteLength;
      final payloadTotalLength = lenVar.value; // Includes PN field and AEAD tag

      pnOffset = offset;
      
      // Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, false);
      
      // Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payloadEnd = payloadStart + payloadTotalLength;

      if (payloadEnd > mutableArray.length) {
        throw Exception("Truncated long header packet (expected $payloadEnd bytes, got ${mutableArray.length})");
      }

      final payload = mutableArray.sublist(payloadStart, payloadEnd);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);

    } else {
      // ---------- Short Header Parsing ----------
      
      keyPhase = (firstByte & 0x04) != 0; // Key Phase is the 3rd bit (0x04)

      final dcidLen = dcid.length; 
      pnOffset = 1 + dcidLen; // PN starts after 1 byte Type and DCID
      
      if (pnOffset + 4 > mutableArray.length) throw Exception("Short header too short for max PN length");

      // Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, true);

      // Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payload = mutableArray.sublist(payloadStart);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);
    }
  } catch (e) {
    // Catch header parsing or PN/Header Protection errors
    print("QUIC Packet Header parsing/unprotect failed: $e");
    return null;
  }
  
  // Final AEAD Decryption
  // plaintext will be null if the decryption fails (e.g., failed tag authentication)
  final plaintext = aesGcmDecrypt(ciphertext, tag, readKey, nonce!, aad);
  
  // Return the result object
  return QuicDecryptedPacket(
    packetNumber: packetNumber!,
    keyPhase: keyPhase,
    plaintext: plaintext,
  );
}

/// Represents the result of a successful QUIC packet decryption.
// class QuicDecryptedPacket {
//   final int packetNumber;
//   final bool keyPhase;
//   final Uint8List? plaintext; // Null if decryption/authentication fails

//   QuicDecryptedPacket({
//     required this.packetNumber,
//     required this.keyPhase,
//     this.plaintext,
//   });
// }

// NOTE: The following required functions must be implemented (or mocked) elsewhere:
// Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey);
// VarIntReadResult? readVarInt(Uint8List array, int offset);
// int decodeAndExpandPacketNumber(Uint8List array, int offset, int pnLength, int largestReceived);
// Uint8List computeNonce(Uint8List iv, int packetNumber);
// Uint8List? aesGcmDecrypt(Uint8List ciphertext, Uint8List tag, Uint8List key, Uint8List nonce, Uint8List aad);

/// Reverses the Header Protection mechanism, unmasking the first header byte 
/// and the Packet Number field.
/// 
/// The [array] is modified in place.
/// Returns the Packet Number Length (1, 2, 3, or 4 bytes).
int removeHeaderProtection(Uint8List array, int pnOffset, Uint8List hpKey, bool isShort) {
  // The sample is 16 bytes starting at pnOffset + 4
  var sampleOffset = pnOffset + 4;
  const sampleLength = 16;
  if (sampleOffset + sampleLength > array.length) {
    throw Exception("Not enough bytes for header protection sample");
  }
  final sample = array.sublist(sampleOffset, sampleOffset + sampleLength); 

  // Use AES-ECB to generate the 5-byte mask
  final maskFull = aes128Ecb(sample, hpKey);
  final mask = maskFull.sublist(0, 5);

  // 1. Remove protection from the first byte
  if (isShort) {
    // Short Header: XOR the 5 lowest bits (0x1f = 0b0001_1111)
    array[0] ^= mask[0] & 0x1f;
  } else {
    // Long Header: XOR the 4 lowest bits (0x0f = 0b0000_1111)
    array[0] ^= mask[0] & 0x0f;
  }

  // 2. Determine Packet Number Length and remove protection from the PN field
  // pnLength is determined by the two lowest bits (0x03) of the now-unmasked first byte.
  final pnLength = (array[0] & 0x03) + 1; 

  if (pnOffset + pnLength > array.length) {
    throw Exception("Packet number field extends beyond packet length after HP removal.");
  }

  // 3. Unmask the Packet Number field (up to 4 bytes)
  for (var i = 0; i < pnLength; i++) {
    // mask[1] is for the first PN byte, mask[2] for the second, etc.
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}

/// Parses, removes header protection, decrypts, and authenticates a QUIC packet.
/// 
/// The [array] is the raw, encrypted packet bytes.
/// Returns a [QuicDecryptedPacket] containing the plaintext and metadata, or `null` 
/// if decryption/authentication fails.
QuicDecryptedPacket? decryptQuicPacket(
  Uint8List array, 
  Uint8List readKey, 
  Uint8List readIv, 
  Uint8List readHp, 
  Uint8List dcid, // Required for Short Header parsing (to calculate PN offset)
  int largestPn // Largest packet number received so far (for PN expansion)
) {
  // Create a mutable copy for in-place Header Protection removal
  final mutableArray = Uint8List.fromList(array); 

  final firstByte = mutableArray[0];
  final isShort = (firstByte & 0x80) == 0;
  
  // Variables to be populated
  bool keyPhase = false;
  int pnOffset = 0;
  int pnLength = 0;
  late Uint8List aad; 
  late Uint8List ciphertext;
  late Uint8List tag;
  int? packetNumber;
  Uint8List? nonce;

  try {
    if (!isShort) {
      // ---------- Long Header Parsing ----------
      
      int offset = 1; // Start after first byte

      // Skip Version (4 bytes)
      offset += 4; 

      // Destination Connection ID (DCID) Length
      final dcidLen = mutableArray[offset++]; 
      // Skip DCID
      offset += dcidLen; 
      
      // Source Connection ID (SCID) Length
      final scidLen = mutableArray[offset++];
      // Skip SCID
      offset += scidLen; 

      // Handle Token field (Initial packets only)
      if (((firstByte & 0x30) >> 4) == 0) { // Type bits are 00 (Initial)
        final tokenLenVar = readVarInt(mutableArray, offset);
        if (tokenLenVar == null) throw Exception("Truncated Token Length VarInt");
        offset += tokenLenVar.byteLength + tokenLenVar.value;
      }

      // Packet Length (VarInt)
      final lenVar = readVarInt(mutableArray, offset);
      if (lenVar == null) throw Exception("Truncated Packet Length VarInt");
      offset += lenVar.byteLength;
      final payloadTotalLength = lenVar.value; // Total length of PN field + encrypted payload

      pnOffset = offset;
      
      // 1. Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, false);
      
      // 2. Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payloadEnd = payloadStart + payloadTotalLength;

      if (payloadEnd > mutableArray.length) {
        throw Exception("Truncated long header packet");
      }

      final payload = mutableArray.sublist(payloadStart, payloadEnd);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // 3. AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);

    } else {
      // ---------- Short Header Parsing ----------
      
      keyPhase = (firstByte & 0x04) != 0; // Key Phase is the 3rd bit (0x04)

      final dcidLen = dcid.length; 
      // PN starts after 1 byte Type and DCID
      pnOffset = 1 + dcidLen; 
      
      if (pnOffset + 16 > mutableArray.length) throw Exception("Short header too short for PN + sample");

      // 1. Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, true);

      // 2. Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payload = mutableArray.sublist(payloadStart);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // 3. AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);
    }
  } catch (e) {
    // If header parsing or protection removal fails, return null
    return null;
  }
  
  // Final AEAD Decryption: plaintext will be null if authentication fails
  final plaintext = aesGcmDecrypt(ciphertext, tag, readKey, nonce!, aad);
  
  return QuicDecryptedPacket(
    packetNumber: packetNumber!,
    keyPhase: keyPhase,
    plaintext: plaintext,
  );
}


/// Encrypts a QUIC packet and applies Header Protection.
/// 
/// Combines the logic from `encrypt_quic_packet` and `encrypt_quic_packet2` 
/// with correct padding logic for AES-GCM (16-byte sample).
Uint8List? encryptQuicPacket(
    String packetType, 
    Uint8List encodedFrames, 
    Uint8List writeKey, 
    Uint8List writeIv, 
    Uint8List writeHp, 
    int packetNumber, 
    Uint8List dcid, 
    Uint8List scid, 
    Uint8List? token
) {
  // 1. Determine Packet Number Length
  int pnLength;
  if (packetNumber <= 0xff) pnLength = 1;
  else if (packetNumber <= 0xffff) pnLength = 2;
  else if (packetNumber <= 0xffffff) pnLength = 3;
  else pnLength = 4;

  // 2. Truncate Packet Number field to pnLength bytes (Big Endian)
  final pnFull = ByteData(4);
  pnFull.setUint32(0, packetNumber, Endian.big);
  final packetNumberField = pnFull.buffer.asUint8List().sublist(4 - pnLength);

  // 3. Initial calculation of payload length (frames + PN field + 16 byte GCM tag)
  int unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
  Uint8List lengthField = writeVarInt(unprotectedPayloadLength);
  
  // 4. Build Header (unprotected)
  QuicHeaderInfo headerInfo = buildQuicHeader(
    packetType, dcid, scid, token, lengthField, pnLength
  );
  Uint8List header = headerInfo.header;
  int packetNumberOffset = headerInfo.packetNumberOffset;

  // 5. Check and apply padding if needed (Long Headers only)
  if (packetType != '1rtt') {
    // The Header Protection sample starts at PN offset + 4 and must be 16 bytes.
    const minSampleLength = 16;
    
    // The total packet length must be >= (PN offset + 4 + 16).
    final minTotalLength = packetNumberOffset + 4 + minSampleLength;
    final fullLength = header.length + pnLength + encodedFrames.length + 16; 

    if (fullLength < minTotalLength) {
      // Required Protected Bytes = minTotalLength - (Header Length + PN Length)
      final requiredProtectedDataLength = minTotalLength - (header.length + pnLength);
      
      // Since the tag is 16 bytes, the frame content must be:
      final requiredFramesLength = requiredProtectedDataLength - 16;

      if (requiredFramesLength > encodedFrames.length) {
         final extraPadding = requiredFramesLength - encodedFrames.length;
         
         // Add padding (zero bytes) to encodedFrames
         final padded = Uint8List(encodedFrames.length + extraPadding);
         padded.setAll(0, encodedFrames); 
         encodedFrames = padded;
         
         // RECALCULATE LENGTH FIELD AND REBUILD HEADER
         unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
         lengthField = writeVarInt(unprotectedPayloadLength);
         headerInfo = buildQuicHeader(packetType, dcid, scid, token, lengthField, pnLength);
         header = headerInfo.header;
         packetNumberOffset = headerInfo.packetNumberOffset;
      }
    }
  }

  // 6. Build AAD: Unprotected Header + Unprotected Packet Number
  final fullHeader = concatUint8Lists([header, packetNumberField]);

  // 7. Encrypt Payload
  final ciphertext = aeadEncrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);
  if (ciphertext == null) return null;

  // 8. Build Full Packet (before Header Protection)
  final fullPacket = concatUint8Lists([
    header,
    packetNumberField,
    ciphertext
  ]);

  // 9. Apply Header Protection
  return applyHeaderProtection(fullPacket, packetNumberOffset, writeHp, pnLength);
}

// Result class for extracted TLS messages
class TlsExtractResult {
  final List<Uint8List> tlsMessages;
  final int newFromOffset;
  TlsExtractResult({required this.tlsMessages, required this.newFromOffset});
}

/// Extracts complete TLS messages from a fragmented set of QUIC stream data chunks.
/// Chunks are assumed to be stored in a Map keyed by their stream offset.
/// 
/// The [chunks] map will be modified in place (consumed chunks are removed/replaced by leftover).
TlsExtractResult extractTlsMessagesFromChunks(
    Map<int, Uint8List> chunks,
    int fromOffset
) {
  final List<Uint8List> buffers = [];
  final List<int> combinedKeys = [];
  int offset = fromOffset;

  // 1. Combine contiguous sequence of chunks starting from fromOffset
  while (chunks.containsKey(offset)) {
    final chunk = chunks[offset]!;
    buffers.add(chunk);
    combinedKeys.add(offset);
    offset += chunk.length;
  }

  if (buffers.isEmpty) {
    return TlsExtractResult(tlsMessages: [], newFromOffset: fromOffset);
  }

  // 2. Combine into one buffer for parsing
  final combined = concatUint8Lists(buffers); // Assumed available

  final List<Uint8List> tlsMessages = [];
  int i = 0; // index within 'combined'

  while (i + 4 <= combined.length) {
    // Read TLS Handshake header: 1 byte Type, 3 bytes Length (Big Endian)
    // final msgType = combined[i]; // Not used, but parsed
    final length = (combined[i + 1] << 16) | (combined[i + 2] << 8) | combined[i + 3];

    // Check if the entire message is present
    if (i + 4 + length > combined.length) break;

    // Extract the full message (4 byte header + length payload)
    final msg = combined.sublist(i, i + 4 + length);
    tlsMessages.add(msg);
    i += (4 + length).toInt();
  }
  
  // 3. Update chunks structure based on processed bytes (i)
  if (i > 0) {
    // a. Delete the old chunks that were part of the processed section
    int cleanupOffset = fromOffset;
    for (int key in combinedKeys) {
       final chunk = chunks[key]!;
       if (cleanupOffset < fromOffset + i) {
           chunks.remove(key);
           cleanupOffset += chunk.length;
       } else {
           break;
       }
    }
    
    // b. Handle leftover data by inserting a new chunk at the cleanupOffset
    if (i < combined.length) {
       final leftover = combined.sublist(i);
       chunks[cleanupOffset] = leftover;
    }
    
    // Update the offset to the end of the processed data
    fromOffset += i;
  }

  return TlsExtractResult(tlsMessages: tlsMessages, newFromOffset: fromOffset);
}


/// Encodes a 32-bit integer QUIC version into a 4-byte Big Endian [Uint8List].
Uint8List encodeVersion(int version) {
  final result = Uint8List(4);
  final view = ByteData.view(result.buffer);
  view.setUint32(0, version, Endian.big);
  return result;
}
// Result class for Header building
class QuicHeaderInfo {
  final Uint8List header;
  final int packetNumberOffset;
  QuicHeaderInfo({required this.header, required this.packetNumberOffset});
}

/// Constructs the unprotected QUIC header up to the Packet Number field.
QuicHeaderInfo buildQuicHeader(
    String packetType, 
    Uint8List dcid, 
    Uint8List scid, 
    Uint8List? token, 
    Uint8List lengthField, // VarInt for protected payload length
    int pnLen // 1, 2, 3, or 4
) {
  final List<Uint8List> hdrParts = [];
  int firstByte;

  // pnLen - 1 corresponds to the two low bits (LL) of the first byte
  final pnLenBits = (pnLen - 1) & 0x03;

  // Step 1: Define the first byte based on packet type
  if (packetType == 'initial') {
    firstByte = 0xC0 | pnLenBits; // 1100_00LL
  } else if (packetType == 'handshake') {
    firstByte = 0xE0 | pnLenBits; // 1110_00LL
  } else if (packetType == '0rtt') {
    firstByte = 0xD0 | pnLenBits; // 1101_00LL
  } else if (packetType == '1rtt') {
    // Short Header: 01xx_xxLL. The bits 4 and 5 are reserved (0) or Key Phase (1).
    firstByte = 0x40 | pnLenBits; // 0100_00LL (Assuming Key Phase 0)
    
    // Short Header is: Type (1 byte) + DCID + Packet Number
    hdrParts.add(Uint8List.fromList([firstByte]));
    hdrParts.add(dcid);
    
    final header = concatUint8Lists(hdrParts);
    return QuicHeaderInfo(
      header: header,
      packetNumberOffset: header.length // PN starts immediately after DCID
    );
  } else {
    throw Exception('Unsupported packet type: $packetType');
  }

  // Steps 2-4: Long Header construction
  hdrParts.add(Uint8List.fromList([firstByte]));
  hdrParts.add(encodeVersion(0x00000001)); // QUIC v1
  
  // DCID Length + Value
  hdrParts.add(writeVarInt(dcid.length));
  hdrParts.add(dcid);
  
  // SCID Length + Value
  hdrParts.add(writeVarInt(scid.length));
  hdrParts.add(scid);

  // Step 3: Token for Initial packets
  if (packetType == 'initial') {
    final effectiveToken = token ?? Uint8List(0);
    hdrParts.add(writeVarInt(effectiveToken.length));
    hdrParts.add(effectiveToken);
  }

  // Step 4: Length field (Payload Length, VarInt)
  hdrParts.add(lengthField);

  // Step 5: Calculate PN offset
  final header = concatUint8Lists(hdrParts);
  return QuicHeaderInfo(
    header: header,
    packetNumberOffset: header.length // PN starts immediately after the Length field
  );
}
/// Encrypts a QUIC packet and applies Header Protection.
/// 
/// Combines the logic from `encrypt_quic_packet` and `encrypt_quic_packet2` 
/// with correct padding logic for AES-GCM (16-byte sample).
Uint8List? encryptQuicPacket(
    String packetType, 
    Uint8List encodedFrames, 
    Uint8List writeKey, 
    Uint8List writeIv, 
    Uint8List writeHp, 
    int packetNumber, 
    Uint8List dcid, 
    Uint8List scid, 
    Uint8List? token
) {
  // 1. Determine Packet Number Length
  int pnLength;
  if (packetNumber <= 0xff) pnLength = 1;
  else if (packetNumber <= 0xffff) pnLength = 2;
  else if (packetNumber <= 0xffffff) pnLength = 3;
  else pnLength = 4;

  // 2. Truncate Packet Number field to pnLength bytes (Big Endian)
  final pnFull = ByteData(4);
  pnFull.setUint32(0, packetNumber, Endian.big);
  final packetNumberField = pnFull.buffer.asUint8List().sublist(4 - pnLength);

  // 3. Initial calculation of payload length (frames + PN field + 16 byte GCM tag)
  int unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
  Uint8List lengthField = writeVarInt(unprotectedPayloadLength);
  
  // 4. Build Header (unprotected)
  QuicHeaderInfo headerInfo = buildQuicHeader(
    packetType, dcid, scid, token, lengthField, pnLength
  );
  Uint8List header = headerInfo.header;
  int packetNumberOffset = headerInfo.packetNumberOffset;

  // 5. Check and apply padding if needed (Long Headers only)
  if (packetType != '1rtt') {
    // The Header Protection sample starts at PN offset + 4 and must be 16 bytes.
    const minSampleLength = 16;
    
    // The total packet length must be >= (PN offset + 4 + 16).
    final minTotalLength = packetNumberOffset + 4 + minSampleLength;
    final fullLength = header.length + pnLength + encodedFrames.length + 16; 

    if (fullLength < minTotalLength) {
      // Required Protected Bytes = minTotalLength - (Header Length + PN Length)
      final requiredProtectedDataLength = minTotalLength - (header.length + pnLength);
      
      // Since the tag is 16 bytes, the frame content must be:
      final requiredFramesLength = requiredProtectedDataLength - 16;

      if (requiredFramesLength > encodedFrames.length) {
         final extraPadding = requiredFramesLength - encodedFrames.length;
         
         // Add padding (zero bytes) to encodedFrames
         final padded = Uint8List(encodedFrames.length + extraPadding);
         padded.setAll(0, encodedFrames); 
         encodedFrames = padded;
         
         // RECALCULATE LENGTH FIELD AND REBUILD HEADER
         unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
         lengthField = writeVarInt(unprotectedPayloadLength);
         headerInfo = buildQuicHeader(packetType, dcid, scid, token, lengthField, pnLength);
         header = headerInfo.header;
         packetNumberOffset = headerInfo.packetNumberOffset;
      }
    }
  }

  // 6. Build AAD: Unprotected Header + Unprotected Packet Number
  final fullHeader = concatUint8Lists([header, packetNumberField]);

  // 7. Encrypt Payload
  final ciphertext = aeadEncrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);
  if (ciphertext == null) return null;

  // 8. Build Full Packet (before Header Protection)
  final fullPacket = concatUint8Lists([
    header,
    packetNumberField,
    ciphertext
  ]);

  // 9. Apply Header Protection
  return applyHeaderProtection(fullPacket, packetNumberOffset, writeHp, pnLength);
}

/// Encodes a list of structured QUIC frames into a single Uint8List buffer.
Uint8List encodeQuicFrames(List<Map<String, dynamic>> frames) {
  final List<Uint8List> parts = [];

  for (final frame in frames) {
    final type = frame['type'] as String;

    if (type == 'padding') {
      final length = frame['length'] as int;
      parts.add(Uint8List(length)); // All zero bytes by default

    } else if (type == 'ping') {
      parts.add(Uint8List.fromList([0x01]));

    } else if (type == 'ack') {
      final hasECN = frame['ecn'] != null;
      final typeByte = hasECN ? 0x03 : 0x02;

      final b1 = writeVarInt(frame['largest']);      // Largest Acknowledged
      final b2 = writeVarInt(frame['delay']);        // ACK Delay
      final b3 = writeVarInt(frame['ranges'].length); // ACK Range Count
      final b4 = writeVarInt(frame['firstRange'] ?? 0);

      final List<Uint8List> temp = [Uint8List.fromList([typeByte]), b1, b2, b3, b4];

      final List<Map<String, int>> ranges = (frame['ranges'] as List).cast<Map<String, int>>();
      for (var range in ranges) {
        final gap = writeVarInt(range['gap']!);
        final len = writeVarInt(range['length']!);
        temp.addAll([gap, len]);
      }

      if (hasECN) {
        final ecn = frame['ecn'] as Map<String, int>;
        temp.addAll([
          writeVarInt(ecn['ect0'] ?? 0),
          writeVarInt(ecn['ect1'] ?? 0),
          writeVarInt(ecn['ce'] ?? 0),
        ]);
      }

      parts.add(concatUint8Lists(temp));

    } else if (type == 'reset_stream') {
      final error = frame['error'] as int;
      final id = writeVarInt(frame['id']);
      final err = Uint8List.fromList([error >> 8, error & 0xff]);
      final size = writeVarInt(frame['finalSize']);
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x04]), id, err, size
      ]));

    } else if (type == 'stop_sending') {
      final error = frame['error'] as int;
      final id = writeVarInt(frame['id']);
      final err = Uint8List.fromList([error >> 8, error & 0xff]);
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x05]), id, err
      ]));

    } else if (type == 'crypto') {
      final data = frame['data'] as Uint8List;
      final off = writeVarInt(frame['offset']);
      final len = writeVarInt(data.length);
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x06]), off, len, data
      ]));

    } else if (type == 'new_token') {
      final token = frame['token'] as Uint8List;
      final len = writeVarInt(token.length);
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x07]), len, token
      ]));

    } else if (type == 'stream') {
      int typeByte = 0x08;

      final hasOffset = frame['offset'] != null && (frame['offset'] as int) > 0;
      final data = frame['data'] as Uint8List;
      final hasLen = data.isNotEmpty;
      final hasFin = frame['fin'] == true;

      if (hasOffset) typeByte |= 0x04;
      if (hasLen) typeByte |= 0x02;
      if (hasFin) typeByte |= 0x01;

      final id = writeVarInt(frame['id']);
      final off = hasOffset ? writeVarInt(frame['offset']) : Uint8List(0);
      final len = hasLen ? writeVarInt(data.length) : Uint8List(0);

      parts.add(concatUint8Lists([
        Uint8List.fromList([typeByte]), id, off, len, data
      ]));

    } else if (type == 'max_data') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x09]), writeVarInt(frame['max'])
      ]));

    } else if (type == 'max_stream_data') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x0a]), writeVarInt(frame['id']), writeVarInt(frame['max'])
      ]));

    } else if (type == 'max_streams_bidi' || type == 'max_streams_uni') {
      final code = type == 'max_streams_bidi' ? 0x0b : 0x0c;
      parts.add(concatUint8Lists([
        Uint8List.fromList([code]), writeVarInt(frame['max'])
      ]));

    } else if (type == 'data_blocked') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x0d]), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'stream_data_blocked') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x0e]), writeVarInt(frame['id']), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'streams_blocked_bidi') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x0f]), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'streams_blocked_uni') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x10]), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'new_connection_id') {
      final connId = frame['connId'] as Uint8List;
      final token = frame['token'] as Uint8List;
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x11]),
        writeVarInt(frame['seq']),
        writeVarInt(frame['retire']),
        Uint8List.fromList([connId.length]),
        connId,
        token
      ]));

    } else if (type == 'retire_connection_id') {
      parts.add(concatUint8Lists([
        Uint8List.fromList([0x12]),
        writeVarInt(frame['seq'])
      ]));

    } else if (type == 'path_challenge' || type == 'path_response') {
      final code = type == 'path_challenge' ? 0x13 : 0x14;
      parts.add(concatUint8Lists([
        Uint8List.fromList([code]), frame['data'] as Uint8List
      ]));

    } else if (type == 'connection_close') {
      final isApplication = frame['application'] == true;
      final code = isApplication ? 0x1d : 0x1c;
      final error = frame['error'] as int;
      final err = Uint8List.fromList([error >> 8, error & 0xff]);
      
      Uint8List ft;
      if (isApplication) {
        ft = Uint8List(0);
      } else {
        ft = writeVarInt(frame['frameType']);
      }
      
      final reasonText = (frame['reason'] ?? "") as String;
      final reason = utf8.encode(reasonText) as Uint8List;
      final reasonLen = writeVarInt(reason.length);
      
      parts.add(concatUint8Lists([
        Uint8List.fromList([code]), err, ft, reasonLen, reason
      ]));

    } else if (type == 'handshake_done') {
      parts.add(Uint8List.fromList([0x1e]));
      
    } else if (type == 'datagram') {
      final payload = frame['data'] as Uint8List;
      final contextId = frame['contextId'];

      if (contextId != null) {
        final contextBytes = writeVarInt(contextId);
        parts.add(concatUint8Lists([
          Uint8List.fromList([0x31]), // 0x31: DATAGRAM frame with context ID
          contextBytes,
          payload
        ]));
      } else {
        parts.add(concatUint8Lists([
          Uint8List.fromList([0x30]), // 0x30: DATAGRAM frame without context ID
          payload
        ]));
      }
    } 
    // Unknown frames are ignored, matching the JS logic.
  }

  return concatUint8Lists(parts);
}

/// Parses a raw buffer of concatenated QUIC frames into a list of structured frames.
List<Map<String, dynamic>> parseQuicFrames(Uint8List buf) {
  int offset = 0;
  final List<Map<String, dynamic>> frames = [];
  final textDecoder = utf8.decoder;

  // Local helper to safely read a VarInt and advance the offset
  VarIntReadResult? safeReadVarInt() {
    if (offset >= buf.length) return null;
    final res = readVarInt(buf, offset);
    if (res == null) return null;
    offset += res.byteLength;
    return res;
  }

  while (offset < buf.length) {
    final start = offset;
    int type = buf[offset++];

    // Handle large frame types (e.g., custom/future frames) that use VarInt for type
    if (type >= 0x80) {
      offset--; // backtrack
      final t = safeReadVarInt();
      if (t == null) break;
      type = t.value;
    }

    if (type == 0x00) {
      // PADDING frame: no action, loop continues, effectively consuming the byte
    } else if (type == 0x01) {
      frames.add({'type': 'ping'});

    } else if ((type & 0xfe) == 0x02) { // ACK (0x02) or ACK_ECN (0x03)
      final hasECN = (type & 0x01) == 0x01;
      
      final largest = safeReadVarInt(); if (largest == null) break;
      final delay = safeReadVarInt(); if (delay == null) break;
      final rangeCount = safeReadVarInt(); if (rangeCount == null) break;
      final firstRange = safeReadVarInt(); if (firstRange == null) break;

      final List<Map<String, int>> ranges = [];
      for (int i = 0; i < rangeCount.value; i++) {
        final gap = safeReadVarInt(); if (gap == null) break;
        final len = safeReadVarInt(); if (len == null) break;
        ranges.add({'gap': gap.value, 'length': len.value});
      }
      if (ranges.length != rangeCount.value) break;

      Map<String, int>? ecn = null;
      if (hasECN) {
        final ect0 = safeReadVarInt(); if (ect0 == null) break;
        final ect1 = safeReadVarInt(); if (ect1 == null) break;
        final ce = safeReadVarInt(); if (ce == null) break;
        ecn = {'ect0': ect0.value, 'ect1': ect1.value, 'ce': ce.value};
      }

      frames.add({
        'type': 'ack',
        'largest': largest.value,
        'delay': delay.value,
        'firstRange': firstRange.value,
        'ranges': ranges,
        'ecn': ecn
      });

    } else if (type == 0x04) { // RESET_STREAM
      final id = safeReadVarInt(); if (id == null) break;
      if (offset + 2 > buf.length) break;
      final error = buf[offset++] << 8 | buf[offset++];
      final finalSize = safeReadVarInt(); if (finalSize == null) break;
      frames.add({
        'type': 'reset_stream',
        'id': id.value,
        'error': error,
        'finalSize': finalSize.value
      });

    } else if (type == 0x05) { // STOP_SENDING
      final id = safeReadVarInt(); if (id == null) break;
      if (offset + 2 > buf.length) break;
      final error = buf[offset++] << 8 | buf[offset++];
      frames.add({'type': 'stop_sending', 'id': id.value, 'error': error});

    } else if (type == 0x06) { // CRYPTO
      final off = safeReadVarInt(); if (off == null) break;
      final len = safeReadVarInt(); if (len == null) break;
      if (offset + len.value > buf.length) break;
      final data = buf.sublist(offset, offset + len.value);
      offset += len.value;
      frames.add({'type': 'crypto', 'offset': off.value, 'data': data});

    } else if (type == 0x07) { // NEW_TOKEN
      final len = safeReadVarInt(); if (len == null) break;
      if (offset + len.value > buf.length) break;
      final token = buf.sublist(offset, offset + len.value);
      offset += len.value;
      frames.add({'type': 'new_token', 'token': token});

    } else if ((type & 0xe0) == 0x08) { // STREAM (0x08-0x0f)
      final fin = (type & 0x01) != 0;
      final lenb = (type & 0x02) != 0;
      final offb = (type & 0x04) != 0;

      final streamId = safeReadVarInt(); if (streamId == null) break;
      final offsetVal = offb ? safeReadVarInt() : VarIntReadResult(value: 0, byteLength: 0);
      if (offsetVal == null) break;

      final lengthVal = lenb ? safeReadVarInt() : VarIntReadResult(value: buf.length - offset, byteLength: 0);
      if (lengthVal == null) break;

      if (offset + lengthVal.value > buf.length) break;

      final data = buf.sublist(offset, offset + lengthVal.value);
      offset += lengthVal.value;

      frames.add({
        'type': 'stream',
        'id': streamId.value,
        'offset': offsetVal.value,
        'fin': fin,
        'data': data
      });
      
    } else if (type == 0x09) { // MAX_DATA
      final max = safeReadVarInt(); if (max == null) break;
      frames.add({'type': 'max_data', 'max': max.value});

    } else if (type == 0x0a) { // MAX_STREAM_DATA
      final id = safeReadVarInt(); if (id == null) break;
      final max = safeReadVarInt(); if (max == null) break;
      frames.add({'type': 'max_stream_data', 'id': id.value, 'max': max.value});

    } else if (type == 0x0b || type == 0x0c) { // MAX_STREAMS
      final max = safeReadVarInt(); if (max == null) break;
      frames.add({
        'type': type == 0x0b ? 'max_streams_bidi' : 'max_streams_uni',
        'max': max.value
      });

    } else if (type == 0x0d) { // DATA_BLOCKED
      final limit = safeReadVarInt(); if (limit == null) break;
      frames.add({'type': 'data_blocked', 'limit': limit.value});

    } else if (type == 0x0e) { // STREAM_DATA_BLOCKED
      final id = safeReadVarInt(); if (id == null) break;
      final limit = safeReadVarInt(); if (limit == null) break;
      frames.add({'type': 'stream_data_blocked', 'id': id.value, 'limit': limit.value});

    } else if (type == 0x0f || type == 0x10) { // STREAMS_BLOCKED
      final limit = safeReadVarInt(); if (limit == null) break;
      frames.add({
        'type': type == 0x0f ? 'streams_blocked_bidi' : 'streams_blocked_uni',
        'limit': limit.value
      });

    } else if (type == 0x11) { // NEW_CONNECTION_ID
      final seq = safeReadVarInt(); if (seq == null) break;
      final retire = safeReadVarInt(); if (retire == null) break;
      if (offset >= buf.length) break;
      final len = buf[offset++];
      if (offset + len + 16 > buf.length) break;
      final connId = buf.sublist(offset, offset + len); offset += len;
      final token = buf.sublist(offset, offset + 16); offset += 16;
      frames.add({
        'type': 'new_connection_id',
        'seq': seq.value,
        'retire': retire.value,
        'connId': connId,
        'token': token
      });

    } else if (type == 0x12) { // RETIRE_CONNECTION_ID
      final seq = safeReadVarInt(); if (seq == null) break;
      frames.add({'type': 'retire_connection_id', 'seq': seq.value});

    } else if (type == 0x13 || type == 0x14) { // PATH_CHALLENGE / PATH_RESPONSE
      if (offset + 8 > buf.length) break;
      final data = buf.sublist(offset, offset + 8); offset += 8;
      frames.add({
        'type': type == 0x13 ? 'path_challenge' : 'path_response',
        'data': data
      });

    } else if (type == 0x1c || type == 0x1d) { // CONNECTION_CLOSE
      final isApplication = type == 0x1d;
      if (offset + 2 > buf.length) break;
      final error = buf[offset++] << 8 | buf[offset++];
      
      VarIntReadResult? ft = null;
      if (!isApplication) {
        ft = safeReadVarInt(); if (ft == null) break;
      }
      
      final reasonLen = safeReadVarInt(); if (reasonLen == null) break;
      if (offset + reasonLen.value > buf.length) break;
      final reason = utf8.decode(buf.sublist(offset, offset + reasonLen.value));
      offset += reasonLen.value;
      
      frames.add({
        'type': 'connection_close',
        'application': isApplication,
        'error': error,
        'frameType': ft?.value,
        'reason': reason
      });

    } else if (type == 0x1e) { // HANDSHAKE_DONE
      frames.add({'type': 'handshake_done'});

    } else if (type == 0x30 || type == 0x31) { // DATAGRAM (RFC 9221)
      int? contextId = null;

      if (type == 0x31) {
        final cid = safeReadVarInt(); 
        if (cid == null) break;
        contextId = cid.value;
      }

      // Length is implicitly the rest of the packet
      final dataLength = buf.length - offset;
      final data = buf.sublist(offset, offset + dataLength);
      offset += dataLength;

      frames.add({
        'type': 'datagram',
        'contextId': contextId,
        'data': data
      });
      
    } else {
      // Unknown or unhandled frame (e.g., Immediate ACK 0x1f, ACK_FREQUENCY 0xaf)
      // The JS logic breaks on unknown, so we do the same here for safety
      frames.add({'type': 'unknown', 'frameType': type, 'offset': start});
      break; 
    }
  }

  return frames;
}

/// Represents the parsed metadata of a QUIC packet header.
class QuicPacketMetadata {
  final String form; // 'long' or 'short'
  final String type; // 'initial', '0rtt', 'handshake', 'retry', 'version_negotiation', '1rtt', 'unknown'
  final int totalLength; // Total length of the packet in bytes
  final int? version;
  final Uint8List? dcid;
  final Uint8List? scid;
  final Uint8List? token;
  final Uint8List? originalDestinationConnectionId;
  final List<int>? supportedVersions;
  final Uint8List? raw; // Full raw packet bytes
  
  QuicPacketMetadata({
    required this.form,
    required this.type,
    required this.totalLength,
    this.version,
    this.dcid,
    this.scid,
    this.token,
    this.originalDestinationConnectionId,
    this.supportedVersions,
    this.raw
  });
}

/// Parses the header of a single QUIC packet.
QuicPacketMetadata? parseQuicPacket(Uint8List array, [int offset0 = 0]) {
  if (offset0 >= array.length) return null;

  final firstByte = array[offset0];
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    if (offset0 + 6 > array.length) return null;

    final view = ByteData.view(array.buffer, array.offsetInBytes + offset0);
    final version = view.getUint32(1, Endian.big);
    
    final dcidLen = array[offset0 + 5];
    int offset = offset0 + 6;

    if (offset + dcidLen + 1 > array.length) return null;
    final dcid = array.sublist(offset, offset + dcidLen);
    offset += dcidLen;

    final scidLen = array[offset++];
    if (offset + scidLen > array.length) return null;
    final scid = array.sublist(offset, offset + scidLen);
    offset += scidLen;

    // Version negotiation packet (Version 0)
    if (version == 0) {
      final List<int> supportedVersions = [];
      while (offset + 4 <= array.length) {
        final v = ByteData.view(array.buffer, array.offsetInBytes + offset).getUint32(0, Endian.big);
        supportedVersions.add(v);
        offset += 4;
      }
      return QuicPacketMetadata(
        form: 'long',
        type: 'version_negotiation',
        version: version,
        dcid: dcid,
        scid: scid,
        supportedVersions: supportedVersions,
        totalLength: offset - offset0,
      );
    }

    final packetTypeBits = (firstByte & 0x30) >> 4;
    final typeMap = ['initial', '0rtt', 'handshake', 'retry'];
    final packetType = packetTypeBits < typeMap.length ? typeMap[packetTypeBits] : 'unknown';

    if (packetType == 'retry') {
      final odcid = array.sublist(offset); // Original Destination Connection ID
      return QuicPacketMetadata(
        form: 'long',
        type: 'retry',
        version: version,
        dcid: dcid,
        scid: scid,
        originalDestinationConnectionId: odcid,
        totalLength: array.length - offset0,
      );
    }

    // Read Token if it's an Initial packet
    Uint8List? token = null;
    if (packetType == 'initial') {
      final tokenLen = readVarInt(array, offset);
      if (tokenLen == null) return null;
      offset += tokenLen.byteLength;
      if (offset + tokenLen.value > array.length) return null;
      token = array.sublist(offset, offset + tokenLen.value);
      offset += tokenLen.value;
    }

    // Read Length (required for all non-VN/Retry Long Headers)
    final lengthInfo = readVarInt(array, offset);
    if (lengthInfo == null) return null;
    offset += lengthInfo.byteLength;

    final payloadLength = lengthInfo.value;
    final totalLength = offset - offset0 + payloadLength;

    if (offset0 + totalLength > array.length) return null;

    return QuicPacketMetadata(
      form: 'long',
      type: packetType,
      version: version,
      dcid: dcid,
      scid: scid,
      token: token,
      totalLength: totalLength,
    );
  } else {
    // Short Header (1RTT)
    // We cannot determine the precise length without decryption, so we assume the rest of the datagram.
    final totalLength = array.length - offset0;
    return QuicPacketMetadata(
      form: 'short',
      type: '1rtt',
      totalLength: totalLength,
    );
  }
}

/// Parses a UDP datagram that may contain one or more concatenated QUIC packets.
List<QuicPacketMetadata> parseQuicDatagram(Uint8List array) {
  final List<QuicPacketMetadata> packets = [];
  int offset = 0;

  while (offset < array.length) {
    final pkt = parseQuicPacket(array, offset);
    if (pkt == null || pkt.totalLength == 0) break;

    final start = offset;
    final end = offset + pkt.totalLength;

    // Slice the raw packet bytes for encapsulation
    final rawPkt = (start == 0 && end == array.length)
        ? array
        : array.sublist(start, end);

    packets.add(QuicPacketMetadata(
      form: pkt.form,
      type: pkt.type,
      totalLength: pkt.totalLength,
      version: pkt.version,
      dcid: pkt.dcid,
      scid: pkt.scid,
      token: pkt.token,
      originalDestinationConnectionId: pkt.originalDestinationConnectionId,
      supportedVersions: pkt.supportedVersions,
      raw: rawPkt,
    ));
    
    offset = end;
  }

  return packets;
}

/// Builds the body of a TLS 1.3 NewSessionTicket message,
/// used primarily for QUIC 0-RTT resumption.
Uint8List buildNewSessionTicket(Uint8List sessionIdBytes, Map<String, dynamic> options) {
  final ticketLifetime = (options['lifetime'] as int?) ?? 86400; // Default to 24 hours
  
  // Use a secure random number generator for cryptographic values
  final random = Random.secure();
  final ticketAgeAdd = random.nextInt(0xffffffff);
  final ticketNonce = Uint8List(8);
  for (int i = 0; i < 8; i++) {
    ticketNonce[i] = random.nextInt(256);
  }
  
  final ticket = sessionIdBytes;

  final List<Uint8List> extensions = [];
  if (options['early_data_max_size'] != null) {
    final earlyDataMaxSize = options['early_data_max_size'] as int;
    
    // Structure: Type (2) | Length (2) | Data (4)
    final ed = Uint8List(8);
    final view = ByteData.view(ed.buffer);
    
    view.setUint16(0, 0x002a, Endian.big); // early_data extension type
    view.setUint16(2, 0x0004, Endian.big); // extension length (4 bytes for max_early_data_size)
    view.setUint32(4, earlyDataMaxSize, Endian.big); // max_early_data_size
    
    extensions.add(ed);
  }

  // Combine extensions block
  final extensionsBlock = concatUint8Lists(extensions);

  // Calculate total length
  final totalLen =
      4 + // ticket_lifetime (4 bytes, BE)
      4 + // ticket_age_add (4 bytes, BE)
      1 + ticketNonce.length + // Nonce length (1 byte) + Nonce
      2 + ticket.length +      // Ticket length (2 bytes, BE) + Ticket
      2 + extensionsBlock.length; // Extensions length (2 bytes, BE) + Extensions

  final result = Uint8List(totalLen);
  final view = ByteData.view(result.buffer);
  int p = 0;

  // 1. ticket_lifetime (4 bytes, BE)
  view.setUint32(p, ticketLifetime, Endian.big);
  p += 4;

  // 2. ticket_age_add (4 bytes, BE)
  view.setUint32(p, ticketAgeAdd, Endian.big);
  p += 4;

  // 3. ticket_nonce length (1 byte) + Nonce
  result[p++] = ticketNonce.length;
  result.setAll(p, ticketNonce);
  p += ticketNonce.length;

  // 4. ticket length (2 bytes, BE) + Ticket
  view.setUint16(p, ticket.length, Endian.big);
  p += 2;
  result.setAll(p, ticket);
  p += ticket.length;

  // 5. extensions length (2 bytes, BE) + Extensions
  view.setUint16(p, extensionsBlock.length, Endian.big);
  p += 2;
  result.setAll(p, extensionsBlock);

  return result;
}