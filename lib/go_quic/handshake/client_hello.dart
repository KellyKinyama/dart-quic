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
    final buffer = Buffer.empty();
    buffer.pushUint16(legacyVersion);
    buffer.pushBytes(random);
    buffer.pushVector(legacySessionId, 1);

    // Create a temporary buffer for cipher suites
    final suitesBuffer = Buffer.empty();
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
