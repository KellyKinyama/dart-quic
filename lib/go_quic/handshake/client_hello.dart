import 'dart:convert';
import 'dart:typed_data';

// import 'package:hex/hex.dart';

import 'package:hex/hex.dart';

import '../buffer.dart';
import '../cipher_suites.dart';
import 'extensions/extensions.dart';
import 'handshake.dart';

class ClientHello extends TlsHandshakeMessage {
  final int legacyVersion;
  final Uint8List random;
  final Uint8List legacySessionId;
  final List<int> cipherSuites;
  final Uint8List legacyCompressionMethods;
  final List<Extension> extensions;
  ClientHello({
    // required int length,
    required this.legacyVersion,
    required this.random,
    required this.legacySessionId,
    required this.cipherSuites,
    required this.legacyCompressionMethods,
    required this.extensions,
  }) : super(0x01);

  // factory ClientHello.fromBytes(Buffer buffer) {
  //   final legacyVersion = buffer.pullUint16();
  //   final random = buffer.pullBytes(32);
  //   final sessionIdLen = buffer.pullUint8();
  //   final legacySessionId = buffer.pullBytes(sessionIdLen);
  //   final cipherSuitesLen = buffer.pullUint16();
  //   final List<int> cipherSuites = [];
  //   for (int i = 0; i < cipherSuitesLen / 2; i++) {
  //     cipherSuites.add(buffer.pullUint16());
  //   }
  //   final compressionMethodsLen = buffer.pullUint8();
  //   final legacyCompressionMethods = buffer.pullBytes(compressionMethodsLen);
  //   final extensionsLen = buffer.pullUint16();
  //   final List<Extension> extensions = [];
  //   int extensionsRead = 0;
  //   while (extensionsRead < extensionsLen) {
  //     final extType = buffer.pullUint16();
  //     final extLen = buffer.pullUint16();
  //     final extData = buffer.pullBytes(extLen);
  //     extensions.add(Extension(extType, extData));
  //     extensionsRead += 4 + extLen;
  //   }
  //   return ClientHello(
  //     // length: length,
  //     legacyVersion: legacyVersion,
  //     random: random,
  //     legacySessionId: legacySessionId,
  //     cipherSuites: cipherSuites,
  //     legacyCompressionMethods: legacyCompressionMethods,
  //     extensions: extensions,
  //   );
  // }

  // factory ClientHello.fromBytes(Buffer buffer) {
  //   final legacyVersion = buffer.pullUint16();
  //   final random = buffer.pullBytes(32);
  //   final sessionIdLen = buffer.pullUint8();
  //   final legacySessionId = buffer.pullBytes(sessionIdLen);
  //   final cipherSuitesLen = buffer.pullUint16();
  //   final List<int> cipherSuites = [];
  //   for (int i = 0; i < cipherSuitesLen / 2; i++) {
  //     cipherSuites.add(buffer.pullUint16());
  //   }
  //   final compressionMethodsLen = buffer.pullUint8();
  //   final legacyCompressionMethods = buffer.pullBytes(compressionMethodsLen);

  //   // --- FIX IS HERE ---
  //   // Replace the manual loop with a single call to the factory function
  //   final extensionsBytes = buffer.pullVector(2);
  //   final extensions = parseExtensions(Buffer(data: extensionsBytes));

  //   return ClientHello(
  //     legacyVersion: legacyVersion,
  //     random: random,
  //     legacySessionId: legacySessionId,
  //     cipherSuites: cipherSuites,
  //     legacyCompressionMethods: legacyCompressionMethods,
  //     extensions: extensions,
  //   );
  // }

  // client_hello.dart

  factory ClientHello.fromBytes(Buffer buffer) {
    final legacyVersion = buffer.pullUint16();
    final random = buffer.pullBytes(32);
    final legacySessionId = buffer.pullVector(1);

    final cipherSuitesBytes = buffer.pullVector(2);
    final cipherSuitesBuffer = Buffer(data: cipherSuitesBytes);
    final List<int> cipherSuites = [];
    while (!cipherSuitesBuffer.eof) {
      cipherSuites.add(cipherSuitesBuffer.pullUint16());
    }

    final legacyCompressionMethods = buffer.pullVector(1);

    // --- CORRECTED FIX ---
    // Just call parseExtensions directly on the main buffer.
    // It will handle reading the length and parsing all extensions.
    // final extensions = parseExtensions(buffer);
    final extensions = parseExtensions(
      buffer,
      messageType: HandshakeType.client_hello,
    );

    return ClientHello(
      legacyVersion: legacyVersion,
      random: random,
      legacySessionId: legacySessionId,
      cipherSuites: cipherSuites,
      legacyCompressionMethods: legacyCompressionMethods,
      extensions: extensions,
    );
  }

  // In class ClientHello

  Uint8List toBytes() {
    final buffer = Buffer();
    buffer.pushUint16(legacyVersion);
    buffer.pushBytes(random);
    buffer.pushVector(legacySessionId, 1);

    // Create a temporary buffer for cipher suites
    final suitesBuffer = Buffer();
    for (final suite in cipherSuites) {
      suitesBuffer.pushUint16(suite);
    }
    buffer.pushVector(suitesBuffer.toBytes(), 2);

    buffer.pushVector(legacyCompressionMethods, 1);

    // --- SERIALIZE EXTENSIONS ---
    // Use the helper function to create the entire extensions block.
    final Uint8List extensionsBytes = serializeExtensions(extensions);

    // Add the resulting block of bytes to the main buffer.
    buffer.pushBytes(extensionsBytes);

    return buffer.toBytes();
  }

  dynamic parse_tls_client_hello(body) {
    var view = Uint8List.view(body);
    var ptr = 0;

    final legacy_version = (view[ptr++] << 8) | view[ptr++];
    final random = view.sublist(ptr, ptr + 32);
    ptr += 32;
    final session_id_len = view[ptr++];
    final session_id = view.sublist(ptr, ptr + session_id_len);
    ptr += session_id_len;

    int cipher_suites_len = (view[ptr++] << 8) | view[ptr++];
    List<int> cipher_suites = [];
    for (var i = 0; i < cipher_suites_len; i += 2) {
      var code = (view[ptr++] << 8) | view[ptr++];
      cipher_suites.add(code);
    }

    var compression_methods_len = view[ptr++];
    var compression_methods = view.sublist(ptr, ptr + compression_methods_len);
    ptr += compression_methods_len;

    var extensions_len = (view[ptr++] << 8) | view[ptr++];
    final extensions = <HsExtension>[];
    var ext_end = ptr + extensions_len;
    while (ptr < ext_end) {
      var ext_type = (view[ptr++] << 8) | view[ptr++];
      var ext_len = (view[ptr++] << 8) | view[ptr++];
      var ext_data = view.sublist(ptr, ptr + ext_len);
      ptr += ext_len;
      extensions.add(HsExtension(type: ext_type, data: ext_data));
    }

    var sni = null;
    var key_shares = [];
    var supported_versions = [];
    var supported_groups = [];
    var signature_algorithms = [];
    var alpn = [];
    var max_fragment_length = null;
    var padding = null;
    var cookie = null;
    var psk_key_exchange_modes = [];
    var pre_shared_key = null;
    var renegotiation_info = null;
    var quic_transport_parameters_raw = null;

    for (var ext in extensions) {
      var ext_view = Uint8List.view(ext.data.buffer);
      if (ext.type == 0x00) {
        // SNI
        var list_len = (ext_view[0] << 8) | ext_view[1];
        var name_type = ext_view[2];
        var name_len = (ext_view[3] << 8) | ext_view[4];
        var name = utf8.decode(ext_view.sublist(5, 5 + name_len));
        sni = name;
      }
      if (ext.type == 0x33) {
        var ptr2 = 0;
        var list_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
        var end = ptr2 + list_len;
        while (ptr2 < end) {
          var group = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
          var key_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
          var pubkey = ext_view.sublist(ptr2, ptr2 + key_len);
          ptr2 += key_len;
          key_shares.add(KeyShareEntry(group, pubkey));
        }
      }
      if (ext.type == 0x2b) {
        // supported_versions
        var len = ext_view[0];
        for (var i = 1; i < 1 + len; i += 2) {
          var ver = (ext_view[i] << 8) | ext_view[i + 1];
          supported_versions.add(ver);
        }
      }
      if (ext.type == 0x0a) {
        // supported_groups
        var len = (ext_view[0] << 8) | ext_view[1];
        for (var i = 2; i < 2 + len; i += 2) {
          supported_groups.add((ext_view[i] << 8) | ext_view[i + 1]);
        }
      }
      if (ext.type == 0x0d) {
        // signature_algorithms
        var len = (ext_view[0] << 8) | ext_view[1];
        for (var i = 2; i < 2 + len; i += 2) {
          signature_algorithms.add((ext_view[i] << 8) | ext_view[i + 1]);
        }
      }
      if (ext.type == 0x10) {
        // ALPN
        var list_len = (ext_view[0] << 8) | ext_view[1];
        var i = 2;
        while (i < 2 + list_len) {
          var name_len = ext_view[i++];
          var proto = utf8.decode(ext_view.sublist(i, i + name_len));
          alpn.add(proto);
          i += name_len;
        }
      }
      if (ext.type == 0x39) {
        // quic_transport_parameters
        quic_transport_parameters_raw = ext.data;
      }
      if (ext.type == 0x01) {
        // Max Fragment Length
        max_fragment_length = ext_view[0];
      }
      if (ext.type == 0x15) {
        // Padding
        padding = ext_view;
      }
      if (ext.type == 0x002a) {
        // Cookie
        var len = (ext_view[0] << 8) | ext_view[1];
        cookie = ext_view.sublist(2, 2 + len);
      }
      if (ext.type == 0x2d) {
        // PSK Key Exchange Modes
        var len = ext_view[0];
        for (var i = 1; i <= len; i++) {
          psk_key_exchange_modes.sublist(ext_view[i]);
        }
      }
      if (ext.type == 0x29) {
        // PreSharedKey (placeholder)
        pre_shared_key = ext_view;
      }
      if (ext.type == 0xff01) {
        // Renegotiation Info
        renegotiation_info = ext_view;
      }
    }

    return (
      type: 'client_hello',
      legacy_version,
      random,
      session_id,
      cipher_suites,
      compression_methods,
      extensions,
      sni,
      key_shares,
      supported_versions,
      supported_groups,
      signature_algorithms,
      alpn,
      max_fragment_length,
      padding,
      cookie,
      psk_key_exchange_modes,
      pre_shared_key,
      renegotiation_info,
      quic_transport_parameters_raw,
    );
  }

//   function handle_client_hello(parsed) {

  
//   var supported_groups = [0x001d, 0x0017]; // X25519, secp256r1
//   var supported_cipher_suites = [0x1301, 0x1302];//0x1303, 

//   var selected_alpn=null;
//   var selected_group=null;
//   var selected_cipher=null;

//   var client_public_key=null;

//   var server_private_key=null;
//   var server_public_key=null;
//   var shared_secret=null;

//   for(var i in supported_cipher_suites){
//     if(parsed.cipher_suites.includes(supported_cipher_suites[i])==true){
//       selected_cipher=supported_cipher_suites[i];
//       break;
//     }
//   }

//   for(var i in supported_groups){
//     if(selected_group==null){
//       for(var i2 in parsed.key_shares){
//         if(parsed.key_shares[i2].group==supported_groups[i]){
//           selected_group=parsed.key_shares[i2].group;
//           client_public_key=parsed.key_shares[i2].pubkey;
//           break;
//         }
//       }
//     }
//   }

  

//   if(selected_group!==null){

//     if (selected_group === 0x001d) { // X25519
//       server_private_key = crypto.randomBytes(32);
//       server_public_key = x25519.getPublicKey(server_private_key);
//       shared_secret = x25519.getSharedSecret(server_private_key, client_public_key);
//     } else if (selected_group === 0x0017) { // secp256r1 (P-256)
//       server_private_key = p256.utils.randomPrivateKey();
//       server_public_key = p256.getPublicKey(server_private_key, false);
//       var client_point = p256.ProjectivePoint.fromHex(client_public_key);
//       var shared_point = client_point.multiply(
//           BigInt('0x' + Buffer.from(server_private_key).toString('hex'))
//       );
//       shared_secret = shared_point.toRawBytes().slice(0, 32);
//     }

//   }


//   return {
//     selected_cipher: selected_cipher,
//     selected_group: selected_group,
//     client_public_key: client_public_key,
//     server_private_key: new Uint8Array(server_private_key),
//     server_public_key: server_public_key,
//     shared_secret: shared_secret
//   }


// }


  @override
  // String toString() =>
  //     '  - TLS ClientHello(extensions: ${extensions.length})\n${extensions.join('\n')}';
  String toString() {
    final suites = cipherSuites
        .map((s) => cipherSuitesMap[s] ?? 'Unknown (0x${s.toRadixString(16)})')
        .join(', ');
    return '''
TLS ClientHello (Type 0x01):
- Version: 0x${legacyVersion.toRadixString(16)}
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Cipher Suites: [$suites]
- Extensions Count: $extensions''';
  }
}

void main() {
  // final buffer = Buffer(data: recv_data);
  // final msgType = buffer.pullUint8();
  // print("msgType: $msgType");
  // final length = buffer.pullUint24();
  // final messageBody = buffer.pullBytes(length);
  final ch = ClientHello.fromBytes(Buffer(data: recv_data));
  print("certificateVerify: $ch");
  print("To bytes: ${HEX.encode(ch.toBytes())}");

  print("Expected: ${HEX.encode(recv_data)}");
}

final recv_data = Uint8List.fromList([
  0x03,
  0x03,
  0xf0,
  0x5d,
  0x41,
  0x2d,
  0x24,
  0x35,
  0x27,
  0xfd,
  0x90,
  0xb5,
  0xb4,
  0x24,
  0x9d,
  0x4a,
  0x69,
  0xf8,
  0x97,
  0xb5,
  0xcf,
  0xfe,
  0xe3,
  0x8d,
  0x4c,
  0xec,
  0xc7,
  0x8f,
  0xd0,
  0x25,
  0xc6,
  0xeb,
  0xe1,
  0x33,
  0x20,
  0x67,
  0x7e,
  0xb6,
  0x52,
  0xad,
  0x12,
  0x51,
  0xda,
  0x7a,
  0xe4,
  0x5d,
  0x3f,
  0x19,
  0x2c,
  0xd1,
  0xbf,
  0xaf,
  0xca,
  0xa8,
  0xc5,
  0xfe,
  0x59,
  0x2f,
  0x1b,
  0x2f,
  0x2a,
  0x96,
  0x1e,
  0x12,
  0x83,
  0x35,
  0xae,
  0x00,
  0x02,
  0x13,
  0x02,
  0x01,
  0x00,
  0x00,
  0x45,
  0x00,
  0x2b,
  0x00,
  0x03,
  0x02,
  0x03,
  0x04,
  0x00,
  0x0a,
  0x00,
  0x06,
  0x00,
  0x04,
  0x00,
  0x1d,
  0x00,
  0x17,
  0x00,
  0x33,
  0x00,
  0x26,
  0x00,
  0x24,
  0x00,
  0x1d,
  0x00,
  0x20,
  0x49,
  0x51,
  0x50,
  0xa9,
  0x0a,
  0x47,
  0x82,
  0xfe,
  0xa7,
  0x47,
  0xf5,
  0xcb,
  0x55,
  0x19,
  0xdc,
  0xf0,
  0xce,
  0x0d,
  0xee,
  0x9c,
  0xdc,
  0x04,
  0x93,
  0xbd,
  0x84,
  0x9e,
  0xea,
  0xf7,
  0xd3,
  0x93,
  0x64,
  0x2f,
  0x00,
  0x0d,
  0x00,
  0x06,
  0x00,
  0x04,
  0x04,
  0x03,
  0x08,
  0x07,
]);
