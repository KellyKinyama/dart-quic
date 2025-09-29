// --- Helper Maps for readable output ---
import 'dart:typed_data';

import '../buffer.dart';
import '../frames/frames.dart';
import 'certificate.dart';
import 'certificate_verify.dart';
import 'client_hello.dart';
import 'encrypted_extensions.dart';
// import 'extensions/extensions.dart';
import 'finished.dart';
import 'server_hello.dart';

export 'client_hello.dart';

const Map<int, String> handshakeTypeMap = {
  1: 'ClientHello',
  2: 'ServerHello',
  8: 'EncryptedExtensions',
  11: 'Certificate',
  15: 'CertificateVerify',
  20: 'Finished',
};
const Map<int, String> cipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
};
const Map<int, String> supportedCipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  // 0x1302: 'TLS_AES_256_GCM_SHA384',
};
const Map<int, String> namedGroupMap = {
  0x001d: 'x25519',
  0x001e: 'x448',
  // 0x0017: 'prime256v1',
  0x0017: 'secp256r1',
  0x0018: 'secp384r1',
  0x0019: 'secp521r1',
  0x0100: 'ffdhe2048',
  0x0101: 'ffdhe3072',
  0x0102: 'ffdhe4096',
  0x0103: 'ffdhe6144',
  0x0104: 'ffdhe8192',
  0x0012: 'secp256k1',
};
const Map<int, String> supportedNamedGroupMap = {
  0x001d: 'x25519',
  // 0x001e: 'x448',
  // 0x0017: 'prime256v1',
  0x0017: 'secp256r1',
  // 0x0018: 'secp384r1',
  // 0x0019: 'secp521r1',
  // 0x0100: 'ffdhe2048',
  // 0x0101: 'ffdhe3072',
  // 0x0102: 'ffdhe4096',
  // 0x0103: 'ffdhe6144',
  // 0x0104: 'ffdhe8192',
  // 0x0012: 'secp256k1',
};
const Map<int, String> extensionTypesMap = {
  0: 'server_name',
  5: 'status_request',
  10: 'supported_groups',
  11: 'ec_points_format',
  13: 'signature_algorithms',
  16: 'application_layer_protocol_negotiation',
  18: 'signed_certificate_timestamp',
  21: 'padding',
  22: 'encrypt_then_mac',
  23: 'extended_master_secret',
  27: 'compress_certificate',
  28: 'record_size_limit',
  35: 'session_ticket',
  41: 'pre_shared_key',
  42: 'early_data',
  43: 'supported_versions',
  45: 'psk_key_exchange_modes',
  49: 'post_handshake_auth',
  51: 'key_share',
  57: 'quic_transport_parameters',
  13172: 'next_protocol_negotiation',
  17513: 'application_settings',
  65281: 'renegotiation_info',
  65535: 'none',
};

const Map<int, String> protocolVersionMap = {
  0x0304: 'TLS 1.3',
  0x0303: 'TLS 1.2',
};

// enum NamedCurve {
//   prime256v1(0x0017),
//   prime384v1(0x0018),
//   prime521v1(0x0019),
//   x25519(0x001D),
//   x448(0x001E),
//   ffdhe2048(0x0100),
//   ffdhe3072(0x0101),
//   ffdhe4096(0x0102),
//   ffdhe6144(0x0103),
//   ffdhe8192(0x0104),
//   secp256k1(0x0012),
//   Unsupported(0);

const Map<int, String> signatureSchemeMap = {
  // 0x0807: 'ed25519',
  // 0x0403: 'ecdsa_secp256r1_sha256',
  0x0203: 'ecdsa_sha1',
  0x0403: 'ecdsa_secp256r1_sha256',
  0x0503: 'ecdsa_secp384r1_sha384',
  0x0603: 'ecdsa_secp521r1_sha512',
  0x0807: 'ed25519',
  0x0808: 'ed448',

  0x0809: 'rsa_pss_pss_sha256',
  0x080a: 'rsa_pss_pss_sha384',
  0x080b: 'rsa_pss_pss_sha512',
  0x0804: 'rsa_pss_rsae_sha256',
  0x0805: 'rsa_pss_rsae_sha384',
  0x0806: 'rsa_pss_rsae_sha512',
  0x0401: 'rsa_pkcs1_sha256',
  0x0501: 'rsa_pkcs1_sha384',
  0x0601: 'rsa_pkcs1_sha512',
};

/// Based on RFC 8446, Section 4.
class HandshakeType {
  // This class is a namespace and should not be instantiated.
  HandshakeType._();

  static const int client_hello = 1;
  static const int server_hello = 2;
  static const int new_session_ticket = 4;
  static const int end_of_early_data = 5;
  static const int encrypted_extensions = 8;
  static const int certificate = 11;
  static const int certificate_request = 13;
  static const int certificate_verify = 15;
  static const int finished = 20;
  static const int key_update = 24;
}

// #############################################################################
// ## SECTION 2: TLS DATA CLASSES
// #############################################################################
class TlsHandshakeType {
  final int msgType;
  final int length;
  final Uint8List messageBody;

  TlsHandshakeType({
    required this.msgType,
    required this.length,
    required this.messageBody,
  });

  factory TlsHandshakeType.fromBytes(Buffer buffer) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();
    final messageBody = buffer.pullBytes(length);

    return TlsHandshakeType(
      msgType: msgType,
      length: length,
      messageBody: messageBody,
    );
  }
}

abstract class TlsHandshakeMessage {
  final int msgType;
  String get typeName => handshakeTypeMap[msgType] ?? 'Unknown';
  TlsHandshakeMessage(this.msgType);
}

TlsHandshakeMessage parseHandshakeBody(int msgType, int length, Buffer buffer) {
  switch (msgType) {
    case 0x01: // ClientHello
      // print("Parsing client hello");
      // buffer.pullUint16(); // Skip legacy_version
      // buffer.pullBytes(32); // Skip random
      // buffer.pullVector(1); // Skip legacy_session_id
      // buffer.pullVector(2); // Skip cipher_suites
      // buffer.pullVector(1); // Skip legacy_compression_methods
      // final extensions = parseExtensions(buffer);
      return ClientHello.fromBytes(buffer);
    // return ClientHello(extensions: extensions);
    case 2: // ServerHellod
      return ServerHello.fromBytes(buffer);
    case 8: // EncryptedExtensions
      return EncryptedExtensions.fromBytes(buffer);
    case 11: // Certificate

      return Certificate.fromBytes(buffer);
    case 15: // CertificateVerify
      return CertificateVerify.fromBytes(buffer);
    case 20: // Finished
      return Finished(buffer.data.sublist(buffer.readOffset));
    default:
      // return UnknownHandshakeMessage(msgType, buffer.pullBytes(length));
      throw UnimplementedError(
        "UnknownHandshakeMessage($msgType, ${buffer.pullBytes(length)}",
      );
  }
}

List<TlsHandshakeMessage> parseTlsMessages(List<CryptoFrame> cryptoFrames) {
  cryptoFrames.reduce((value, element) {
    final buffer = Buffer(data: element.data);

    final msgType = buffer.pullUint8();

    if (handshakeTypeMap[msgType] == null) {
      print("Message type: ${handshakeTypeMap[msgType] ?? msgType}");
      throw Exception("Unknown message type: $msgType");
    }

    print("Message type: ${handshakeTypeMap[msgType] ?? msgType}");
    final length = buffer.pullUint24();
    return CryptoFrame(
      offset: value.offset,
      data: Uint8List.fromList([...value.data, ...buffer.data]),
    );
  });

  final buffer = Buffer(data: cryptoFrames.first.data);
  final messages = <TlsHandshakeMessage>[];

  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    print("Message type: ${handshakeTypeMap[msgType] ?? msgType}");
    final length = buffer.pullUint24();

    try {
      // if (handshakeTypeMap[msgType] == null) {
      //   throw Exception("Unknown message type: $msgType");
      // }
      final messageBody = buffer.pullBytes(length);
      messages.add(
        parseHandshakeBody(msgType, length, Buffer(data: messageBody)),
      );
    } catch (e, st) {
      print(e);
      print(st);
      print(messages);
      break;
    }
  }
  return messages;
}
