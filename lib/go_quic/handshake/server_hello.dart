import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../buffer.dart';
import 'extensions/extensions.dart';
import 'handshake.dart';

// class ServerHello {
//   final Uint8List random;
//   final Uint8List legacySessionIdEcho;
//   final int cipherSuite;
//   final List<Extension> extensions;
//   ServerHello({
//     required this.random,
//     required this.legacySessionIdEcho,
//     required this.cipherSuite,
//     required this.extensions,
//   });

//   factory ServerHello.fromBytes(Uint8List buf) {
//     Buffer buffer = Buffer(data: buf);
//     buffer.pullUint16(); // Skip legacy_version
//     final random = buffer.pullBytes(32);
//     final legacySessionIdEcho = buffer.pullVector(
//       1,
//     ); // Skip legacy_session_id_echo
//     final cipherSuite = buffer.pullUint16();
//     buffer.pullUint8(); // Skip legacy_compression_method
//     return ServerHello(
//       random: random,
//       legacySessionIdEcho: legacySessionIdEcho,
//       cipherSuite: cipherSuite,
//       extensions: parseExtensions(buffer),
//     );
//   }

//   @override
//   String toString() =>
//       'ServerHello(random: ${HEX.encode(random.sublist(0, 4))}..., suite: 0x${cipherSuite.toRadixString(16)}, extensions: $extensions)';
// }

class ServerHello extends TlsHandshakeMessage {
  final Uint8List random;
  final int cipherSuite;
  final List<Extension> extensions;
  ServerHello({
    required this.random,
    required this.cipherSuite,
    required this.extensions,
  }) : super(2);

  factory ServerHello.fromBytes(Buffer buffer) {
    // Buffer buffer = Buffer(data: buf);
    buffer.pullUint16(); // Skip legacy_version
    final random = buffer.pullBytes(32);
    final legacySessionIdEcho = buffer.pullVector(
      1,
    ); // Skip legacy_session_id_echo
    final cipherSuite = buffer.pullUint16();
    buffer.pullUint8(); // Skip legacy_compression_method
    return ServerHello(
      random: random,
      cipherSuite: cipherSuite,
      extensions: parseExtensions(
        buffer,
        messageType: HandshakeType.server_hello,
      ),
    );
  }
  @override
  String toString() =>
      'ServerHello(random: ${HEX.encode(random.sublist(0, 4))}..., suite: ${cipherSuitesMap[cipherSuite] ?? cipherSuite}, extensions: $extensions)';

  // In class ServerHello

  /// Serializes the ServerHello message body from this object's properties.
  @override
  Uint8List toBytes() {
    final buffer = Buffer();

    // Fixed values for TLS 1.3
    buffer.pushUint16(0x0303); // legacy_version
    buffer.pushBytes(random);
    buffer.pushVector(
      Uint8List(32),
      1,
    ); // legacy_session_id_echo (can be a 32-byte echo of ClientHello's)
    buffer.pushUint16(cipherSuite);
    buffer.pushUint8(0); // legacy_compression_method

    // Use the powerful helper function to serialize all extensions.
    // This replaces the entire manual extension-building loop from the JS code.
    buffer.pushBytes(serializeExtensions(extensions));

    return buffer.toBytes();
  }

  Uint8List buildServerHello(
    List<int> serverRandom,
    List<int> publicKey,
    List<int> sessionId,
    int cipherSuite,
    int group,
  ) {
    List<int> legacyVersion = [0x03, 0x03];
    List<int> random = Uint8List.fromList(serverRandom);
    List<int> sessionIdBytes = Uint8List.fromList(sessionId);
    int sessionIdLength = sessionIdBytes.length & 0xff;

    List<int> cipherSuiteBytes = [
      (cipherSuite >> 8) & 0xff,
      cipherSuite & 0xff,
    ];
    List<int> compressionMethod = [0x00];

    List<int> key = Uint8List.fromList(publicKey);
    List<int> keyLength = [(key.length >> 8) & 0xff, key.length & 0xff];
    List<int> groupBytes = [(group >> 8) & 0xff, group & 0xff];
    List<int> keyExchange = [...groupBytes, ...keyLength, ...key];
    final keyShareExtension = (() {
      List<int> extensionType = [0x00, 0x33];
      final extensionLength = [
        (keyExchange.length >> 8) & 0xff,
        keyExchange.length & 0xff,
      ];
      return [...extensionType, ...extensionLength, ...keyExchange];
    })();

    List<int> supportedVersionsExtension = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

    // List<int> paramsBytes = [
    //   0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00, // initial_max_data = 4096
    //   0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x08, 0x00, // max_packet_size = 2048
    // ];

    List<int> extensions = [
      ...supportedVersionsExtension,
      ...keyShareExtension,
    ];
    List<int> extensionsLength = [
      (extensions.length >> 8) & 0xff,
      extensions.length & 0xff,
    ];

    List<int> handshakeBody = [
      ...legacyVersion,
      ...random,
      sessionIdLength,
      ...sessionIdBytes,
      ...cipherSuiteBytes,
      ...compressionMethod,
      ...extensionsLength,
      ...extensions,
    ];

    final bodyLength = handshakeBody.length;
    List<int> handshake = [
      0x02, // handshake type: ServerHello
      (bodyLength >> 16) & 0xff,
      (bodyLength >> 8) & 0xff,
      bodyLength & 0xff,
      ...handshakeBody,
    ];

    return Uint8List.fromList(handshake); // ✔️ מחזיר רק Handshake Message
  }
}

// void main() {
//   final serverHello = ServerHello.fromBytes(Buffer(data: serverHelloData));
//   print(serverHello);
//   print("encoded:  ${HEX.encode(serverHello.toBytes())}");
//   print("Expected: ${HEX.encode(serverHelloData)}");
// }

void main() {
  print("--- Decoding Demo ---");
  final decodedHello = ServerHello.fromBytes(Buffer(data: serverHelloData));
  print("Decoded Original: $decodedHello");

  print("\n--- Encoding Demo ---");
  // This demonstrates the proper "build then serialize" workflow.
  // First, we create the specific Extension objects.
  final keyShareEntry = KeyShareEntry(
    23, // x25519
    Uint8List.fromList(
      HEX.decode(
        '2766693dd8d176a88f6ae6610689e1e9cd63ef2e794124862637fa83d9fd'
        'a3c5aabcaab58586982154bc81ed303542b289d6a4c494754149907803aa'
        'f56dfc47',
      ),
    ),
  );

  // For ServerHello, KeyShare data isn't a list, it's the entry itself.
  final keyShareExtData = keyShareEntry.toBytes();
  final keyShareExtension = KeyShareExtension.fromBytes(
    keyShareExtData,
    messageType: HandshakeType.server_hello,
  );

  // For ServerHello, SupportedVersions data is just the selected version.
  final supportedVersionsExtData = Buffer()..pushUint16(0x0304);
  final supportedVersionsExtension = SupportedVersionsExtension.fromBytes(
    supportedVersionsExtData.toBytes(),
  );

  // Second, we construct the ServerHello message with its properties.
  final constructedHello = ServerHello(
    random: serverHelloData.sublist(2, 34),
    cipherSuite: 0x1302, // TLS_AES_256_GCM_SHA384
    extensions: [supportedVersionsExtension, keyShareExtension],
  );
  print("Constructed New:  $constructedHello");

  // Finally, we serialize the constructed object to bytes.
  final encodedBytes = constructedHello.toBytes();

  print("\n--- Verification ---");
  // Note: We only compare the message body, not the handshake header.
  final originalBody = serverHelloData.sublist(4);
  print(
    "Encoded new body matches original body: ${HEX.encode(encodedBytes) == HEX.encode(originalBody)}",
  );
}

// test "ServerHello decode & encode" {
// zig fmt: off
final serverHelloData = Uint8List.fromList([
  0x03,
  0x03,
  0x11,
  0x08,
  0x43,
  0x1b,
  0xd0,
  0x42,
  0x9e,
  0x61,
  0xff,
  0x65,
  0x44,
  0x41,
  0x91,
  0xfc,
  0x56,
  0x10,
  0xf8,
  0x27,
  0x53,
  0xd9,
  0x68,
  0xc8,
  0x13,
  0x00,
  0xb1,
  0xec,
  0x11,
  0xd5,
  0x7d,
  0x90,
  0xa5,
  0x43,
  0x20,
  0xc4,
  0x8a,
  0x5c,
  0x30,
  0xa8,
  0x50,
  0x1b,
  0x2e,
  0xc2,
  0x45,
  0x76,
  0xd7,
  0xf0,
  0x11,
  0x52,
  0xa0,
  0x16,
  0x57,
  0x07,
  0xdf,
  0x01,
  0x30,
  0x47,
  0x5b,
  0x94,
  0xbc,
  0xe7,
  0x86,
  0x1e,
  0x41,
  0x97,
  0x65,
  0x13,
  0x02,
  0x00,
  0x00,
  0x4f,
  0x00,
  0x2b,
  0x00,
  0x02,
  0x03,
  0x04,
  0x00,
  0x33,
  0x00,
  0x45,
  0x00,
  0x17,
  0x00,
  0x41,
  0x04,
  0x27,
  0x66,
  0x69,
  0x3d,
  0xd8,
  0xd1,
  0x76,
  0xa8,
  0x8f,
  0x6a,
  0xe6,
  0x61,
  0x06,
  0x89,
  0xe1,
  0xe9,
  0xcd,
  0x63,
  0xef,
  0x2e,
  0x79,
  0x41,
  0x24,
  0x86,
  0x26,
  0x37,
  0xfa,
  0x83,
  0xd9,
  0xfd,
  0xa3,
  0xc5,
  0xaa,
  0xbc,
  0xaa,
  0xb5,
  0x85,
  0x86,
  0x98,
  0x21,
  0x54,
  0xbc,
  0x81,
  0xed,
  0x30,
  0x35,
  0x42,
  0xb2,
  0x89,
  0xd6,
  0xa4,
  0xc4,
  0x94,
  0x75,
  0x41,
  0x49,
  0x90,
  0x78,
  0x03,
  0xaa,
  0xf5,
  0x6d,
  0xfc,
  0x47,
]);
