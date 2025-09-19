// --- Helper Maps for readable output ---
import 'dart:typed_data';

import '../buffer.dart';
import 'certificate.dart';
import 'certificate_verify.dart';
import 'client_hello.dart';
import 'encrypted_extensions.dart';
// import 'extensions/extensions.dart';
import 'finished.dart';
import 'server_hello.dart';

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
const Map<int, String> extensionTypesMap = {
  43: 'supported_versions',
  51: 'key_share',
  57: 'quic_transport_parameters',
};

const Map<int, String> protocolVersionMap = {
  0x0304: 'TLS 1.3',
  0x0303: 'TLS 1.2',
};

const Map<int, String> namedGroupMap = {
  0x001d: 'x25519',
  0x0017: 'secp256r1',
  0x0018: 'secp384r1',
};

const Map<int, String> signatureSchemeMap = {
  0x0807: 'ed25519',
  0x0403: 'ecdsa_secp256r1_sha256',
};

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

List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];

  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();

    try {
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
