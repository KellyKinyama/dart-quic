import 'dart:typed_data';
import 'package:hex/hex.dart';

/// A simple buffer to read data sequentially from a Uint8List.
class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;

  Buffer({required Uint8List data})
    : _byteData = data.buffer.asByteData(
        data.offsetInBytes,
        data.lengthInBytes,
      );

  int pullUint8() {
    final val = _byteData.getUint8(_readOffset);
    _readOffset += 1;
    return val;
  }

  int pullUint16() {
    final val = _byteData.getUint16(_readOffset);
    _readOffset += 2;
    return val;
  }

  int pullUint24() {
    final high = _byteData.getUint8(_readOffset);
    final low = _byteData.getUint16(_readOffset + 1);
    _readOffset += 3;
    return (high << 16) | low;
  }

  Uint8List pullBytes(int len) {
    if (_readOffset + len > length) {
      throw Exception('Buffer underflow');
    }
    final bytes = _byteData.buffer.asUint8List(
      _byteData.offsetInBytes + _readOffset,
      len,
    );
    _readOffset += len;
    return bytes;
  }

  Uint8List pullVector(int lenBytes) {
    int vecLen;
    if (lenBytes == 1)
      vecLen = pullUint8();
    else if (lenBytes == 2)
      vecLen = pullUint16();
    else
      throw ArgumentError('Vector length must be 1 or 2 bytes');
    return pullBytes(vecLen);
  }
}

// --- Data Classes to hold parsed information ---

class Extension {
  final int type;
  final Uint8List data;
  Extension(this.type, this.data);
  @override
  String toString() => 'Extension(type: $type, data_len: ${data.length})';
}

class ClientHello {
  final int legacyVersion;
  final Uint8List random;
  final Uint8List legacySessionId;
  final List<int> cipherSuites;
  final Uint8List legacyCompressionMethods;
  final List<Extension> extensions;

  ClientHello({
    required this.legacyVersion,
    required this.random,
    required this.legacySessionId,
    required this.cipherSuites,
    required this.legacyCompressionMethods,
    required this.extensions,
  });

  @override
  String toString() =>
      '''ClientHello(
  legacyVersion: 0x${legacyVersion.toRadixString(16)},
  random: ${HEX.encode(random)},
  legacySessionId: ${HEX.encode(legacySessionId)},
  cipherSuites: ${cipherSuites.map((s) => '0x${s.toRadixString(16)}').join(', ')},
  extensions: ${extensions.length}
)''';
}

class Handshake {
  final int msgType;
  final dynamic body; // Can be ClientHello, ServerHello, etc.
  Handshake(this.msgType, this.body);
  @override
  String toString() => 'Handshake(type: $msgType)\n  body: $body';
}

// --- Parser Functions ---

List<Extension> _parseExtensions(Buffer buffer) {
  final extensions = <Extension>[];
  final totalExtLen = buffer.pullUint16();
  final extEndOffset = buffer._readOffset + totalExtLen;

  while (buffer._readOffset < extEndOffset) {
    final extType = buffer.pullUint16();
    final extData = buffer.pullVector(2);
    extensions.add(Extension(extType, extData));
  }
  return extensions;
}

ClientHello _parseClientHello(Buffer buffer) {
  final legacyVersion = buffer.pullUint16();
  final random = buffer.pullBytes(32);
  final legacySessionId = buffer.pullVector(1);
  final cipherSuitesBytes = buffer.pullVector(2);
  final legacyCompressionMethods = buffer.pullVector(1);
  final extensions = _parseExtensions(buffer);

  final cipherSuites = <int>[];
  for (var i = 0; i < cipherSuitesBytes.length; i += 2) {
    cipherSuites.add(
      ByteData.view(
        cipherSuitesBytes.buffer,
        cipherSuitesBytes.offsetInBytes + i,
        2,
      ).getUint16(0),
    );
  }

  return ClientHello(
    legacyVersion: legacyVersion,
    random: random,
    legacySessionId: legacySessionId,
    cipherSuites: cipherSuites,
    legacyCompressionMethods: legacyCompressionMethods,
    extensions: extensions,
  );
}

Handshake parseHandshakeMessage(Buffer buffer) {
  final msgType = buffer.pullUint8();
  final length = buffer.pullUint24();

  dynamic body;
  switch (msgType) {
    case 1: // client_hello
      body = _parseClientHello(buffer);
      break;
    // Add cases for other handshake messages like ServerHello (2), etc.
    default:
      throw UnimplementedError(
        'Parser for message type $msgType not implemented.',
      );
  }

  return Handshake(msgType, body);
}

// --- Builder Functions ---

Uint8List _buildExtensions(List<Extension> extensions) {
  final extBuilder = BytesBuilder();
  for (final ext in extensions) {
    final extDataBuilder = BytesBuilder()
      ..add((ByteData(2)..setUint16(0, ext.type)).buffer.asUint8List())
      ..add((ByteData(2)..setUint16(0, ext.data.length)).buffer.asUint8List())
      ..add(ext.data);
    extBuilder.add(extDataBuilder.toBytes());
  }

  final allExtBytes = extBuilder.toBytes();
  final finalBuilder = BytesBuilder()
    ..add((ByteData(2)..setUint16(0, allExtBytes.length)).buffer.asUint8List())
    ..add(allExtBytes);
  return finalBuilder.toBytes();
}

Uint8List _buildClientHello(ClientHello message) {
  final builder = BytesBuilder();

  // legacy_version and random
  builder.add(
    (ByteData(2)..setUint16(0, message.legacyVersion)).buffer.asUint8List(),
  );
  builder.add(message.random);

  // legacy_session_id
  builder.addByte(message.legacySessionId.length);
  builder.add(message.legacySessionId);

  // cipher_suites
  final csBytes = Uint8List(message.cipherSuites.length * 2);
  for (var i = 0; i < message.cipherSuites.length; i++) {
    ByteData.view(csBytes.buffer).setUint16(i * 2, message.cipherSuites[i]);
  }
  builder.add((ByteData(2)..setUint16(0, csBytes.length)).buffer.asUint8List());
  builder.add(csBytes);

  // legacy_compression_methods
  builder.addByte(message.legacyCompressionMethods.length);
  builder.add(message.legacyCompressionMethods);

  // extensions
  builder.add(_buildExtensions(message.extensions));

  return builder.toBytes();
}

Uint8List buildHandshakeMessage(Handshake message) {
  final builder = BytesBuilder();

  Uint8List bodyBytes;
  if (message.body is ClientHello) {
    bodyBytes = _buildClientHello(message.body);
  } else {
    throw UnimplementedError(
      'Builder for message type ${message.msgType} not implemented.',
    );
  }

  // Prepend the Handshake container header
  builder.addByte(message.msgType);
  final lengthData = ByteData(4);
  lengthData.setUint32(0, bodyBytes.length);
  builder.add(lengthData.buffer.asUint8List().sublist(1, 4)); // uint24 length
  builder.add(bodyBytes);

  return builder.toBytes();
}

void main() {
  // 1. Create a sample ClientHello object
  final clientHelloObject = ClientHello(
    legacyVersion: 0x0303,
    random: Uint8List.fromList(List.generate(32, (i) => i)),
    legacySessionId: Uint8List(0),
    cipherSuites: [
      0x1301,
      0x1302,
    ], // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    legacyCompressionMethods: Uint8List.fromList([0x00]),
    extensions: [
      Extension(
        43,
        Uint8List.fromList([0x02, 0x03, 0x04]),
      ), // supported_versions
      Extension(
        10,
        Uint8List.fromList([0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]),
      ), // supported_groups
    ],
  );

  final handshakeMessage = Handshake(1, clientHelloObject);

  // 2. Build it into raw bytes
  print('--- Building Handshake Message ---');
  final rawBytes = buildHandshakeMessage(handshakeMessage);
  print('✅ Success! Built ${rawBytes.length} bytes.');
  print('   - Hex: ${HEX.encode(rawBytes.sublist(0, 48))}...');

  // 3. Parse the raw bytes back into an object
  print('\n--- Parsing Handshake Message ---');
  final buffer = Buffer(data: rawBytes);
  final parsedMessage = parseHandshakeMessage(buffer);
  print('✅ Success! Parsed message:');
  print(parsedMessage);
}
