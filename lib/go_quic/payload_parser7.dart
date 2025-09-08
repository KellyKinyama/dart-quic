import 'dart:typed_data';
import 'package:hex/hex.dart';

// #############################################################################
// ## SECTION 1: UTILITY AND EXTENSIONS
// #############################################################################

/// An extension to add the missing setUint24 method to ByteData.
extension ByteDataWriter on ByteData {
  void setUint24(int offset, int value) {
    setUint8(offset, (value >> 16) & 0xFF);
    setUint8(offset + 1, (value >> 8) & 0xFF);
    setUint8(offset + 2, value & 0xFF);
  }
}

/// A simple buffer to read data sequentially from a Uint8List.
class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;
  int get remaining => length - _readOffset;

  Buffer({required Uint8List data})
    : _byteData = data.buffer.asByteData(
        data.offsetInBytes,
        data.lengthInBytes,
      );

  int pullUint8() {
    final v = _byteData.getUint8(_readOffset);
    _readOffset += 1;
    return v;
  }

  int pullUint16() {
    final v = _byteData.getUint16(_readOffset);
    _readOffset += 2;
    return v;
  }

  int pullUint24() {
    final h = pullUint8();
    final l = pullUint16();
    return (h << 16) | l;
  }

  Uint8List pullBytes(int len) {
    if (_readOffset + len > length) throw Exception('Buffer underflow');
    final b = _byteData.buffer.asUint8List(
      _byteData.offsetInBytes + _readOffset,
      len,
    );
    _readOffset += len;
    return b;
  }

  Uint8List pullVector(int lenBytes) {
    int vecLen;
    if (lenBytes == 1)
      vecLen = pullUint8();
    else if (lenBytes == 2)
      vecLen = pullUint16();
    else if (lenBytes == 3)
      vecLen = pullUint24();
    else
      throw ArgumentError('Vector length must be 1, 2, or 3 bytes');
    return pullBytes(vecLen);
  }
}

// #############################################################################
// ## SECTION 2: TLS DATA CLASSES
// #############################################################################

abstract class TlsHandshakeMessage {
  final int msgType;
  String get typeName => _handshakeTypeMap[msgType] ?? 'Unknown';
  TlsHandshakeMessage(this.msgType);
}

class TlsExtension {
  final int type;
  final Uint8List data;
  TlsExtension(this.type, this.data);
  String get typeName =>
      _extensionTypesMap[type] ?? 'Unknown (0x${type.toRadixString(16)})';
  @override
  String toString() => '  - Ext: $typeName, Length: ${data.length}';
}

class ClientHello extends TlsHandshakeMessage {
  final Uint8List random;
  final Uint8List legacySessionId;
  final List<int> cipherSuites;
  final List<TlsExtension> extensions;
  ClientHello({
    required this.random,
    required this.legacySessionId,
    required this.cipherSuites,
    required this.extensions,
  }) : super(0x01);

  @override
  String toString() {
    final suites = cipherSuites
        .map((s) => _cipherSuitesMap[s] ?? 'Unknown (0x${s.toRadixString(16)})')
        .join(',\n    ');
    return '''
✅ Parsed ClientHello (Type 0x01):
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Session ID Length: ${legacySessionId.length}
- Cipher Suites:
    $suites
- Extensions Count: ${extensions.length}
${extensions.join('\n')}''';
  }
}

class UnknownHandshakeMessage extends TlsHandshakeMessage {
  final Uint8List body;
  UnknownHandshakeMessage(int msgType, this.body) : super(msgType);
  @override
  String toString() =>
      'ℹ️ Parsed UnknownHandshake(type: $msgType, len: ${body.length})';
}

// #############################################################################
// ## SECTION 3: PARSER LOGIC
// #############################################################################

List<TlsExtension> _parseExtensions(Buffer buffer) {
  if (buffer.remaining < 2) return [];
  final totalExtLen = buffer.pullUint16();
  final extensions = <TlsExtension>[];
  final extEndOffset = buffer._readOffset + totalExtLen;
  while (buffer._readOffset < extEndOffset) {
    final extType = buffer.pullUint16();
    final extData = buffer.pullVector(2);
    extensions.add(TlsExtension(extType, extData));
  }
  return extensions;
}

ClientHello _parseClientHelloBody(Buffer buffer) {
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  final legacySessionId = buffer.pullVector(1);
  final cipherSuitesBytes = buffer.pullVector(2);
  final cipherSuites = <int>[];
  final csBuffer = Buffer(data: cipherSuitesBytes);
  while (!csBuffer.eof) {
    cipherSuites.add(csBuffer.pullUint16());
  }
  buffer.pullVector(1); // Skip legacy_compression_methods
  final extensions = _parseExtensions(buffer);

  if (buffer.remaining > 0) {
    throw Exception('Extra data found at the end of ClientHello body');
  }

  return ClientHello(
    random: random,
    legacySessionId: legacySessionId,
    cipherSuites: cipherSuites,
    extensions: extensions,
  );
}

List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];
  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();
    final messageBuffer = Buffer(data: buffer.pullBytes(length));
    switch (msgType) {
      case 0x01:
        messages.add(_parseClientHelloBody(messageBuffer));
        break;
      default:
        messages.add(
          UnknownHandshakeMessage(
            msgType,
            messageBuffer.pullBytes(messageBuffer.length),
          ),
        );
    }
  }
  return messages;
}

// #############################################################################
// ## SECTION 4: BUILDER LOGIC
// #############################################################################

Uint8List _buildExtensions(List<TlsExtension> extensions) {
  final extBuilder = BytesBuilder();
  for (final ext in extensions) {
    extBuilder.add((ByteData(2)..setUint16(0, ext.type)).buffer.asUint8List());
    extBuilder.add(
      (ByteData(2)..setUint16(0, ext.data.length)).buffer.asUint8List(),
    );
    extBuilder.add(ext.data);
  }
  final allExtBytes = extBuilder.toBytes();
  return (BytesBuilder()
        ..add(
          (ByteData(2)..setUint16(0, allExtBytes.length)).buffer.asUint8List(),
        )
        ..add(allExtBytes))
      .toBytes();
}

Uint8List _buildClientHelloBody(ClientHello msg) {
  final csBuilder = BytesBuilder();
  for (final suite in msg.cipherSuites) {
    csBuilder.add((ByteData(2)..setUint16(0, suite)).buffer.asUint8List());
  }
  final csBytes = csBuilder.toBytes();

  return (BytesBuilder()
        ..add([0x03, 0x03]) // legacy_version
        ..add(msg.random)
        ..addByte(msg.legacySessionId.length)
        ..add(msg.legacySessionId)
        ..add((ByteData(2)..setUint16(0, csBytes.length)).buffer.asUint8List())
        ..add(csBytes)
        ..add([0x01, 0x00]) // legacy_compression_methods
        ..add(_buildExtensions(msg.extensions)))
      .toBytes();
}

Uint8List buildTlsMessage(TlsHandshakeMessage msg) {
  Uint8List bodyBytes;
  switch (msg.msgType) {
    case 0x01:
      bodyBytes = _buildClientHelloBody(msg as ClientHello);
      break;
    default:
      throw UnimplementedError(
        'Builder for msgType ${msg.msgType} not implemented.',
      );
  }
  final header = ByteData(4)
    ..setUint8(0, msg.msgType)
    ..setUint24(1, bodyBytes.length);

  return (BytesBuilder()
        ..add(header.buffer.asUint8List())
        ..add(bodyBytes))
      .toBytes();
}

// #############################################################################
// ## SECTION 5: DEMONSTRATION
// #############################################################################

void main() {
  // 1. Create a ClientHello object in code
  final clientHelloObject = ClientHello(
    random: Uint8List(32)..fillRange(0, 32, 0xAA),
    legacySessionId: Uint8List.fromList([0, 1, 2, 3]),
    cipherSuites: [0x1301, 0x1302],
    extensions: [
      TlsExtension(
        0,
        Uint8List.fromList(
          [
            0,
            0,
            0,
            10,
            0,
            8,
            0,
            0,
            0,
            5,
            'h',
            'e',
            'l',
            'l',
            'o',
          ].map((e) => e is String ? e.codeUnitAt(0) : e as int).toList(),
        ),
      ),
      TlsExtension(43, Uint8List.fromList([0x03, 0x04])),
    ],
  );

  print("--- Building a ClientHello Object ---");
  print(clientHelloObject.toString().replaceAll("Parsed", "Original"));

  // 2. Build the object into bytes
  final builtBytes = buildTlsMessage(clientHelloObject);
  print("\n✅ Built ${builtBytes.length} bytes successfully.");
  print("   Hex: ${HEX.encode(builtBytes.sublist(0, 16))}...");

  // 3. Parse the bytes back into an object
  print("\n--- Parsing the Built Bytes (Round Trip) ---");
  final parsedMessage = parseTlsMessages(builtBytes).first as ClientHello;
  print(parsedMessage);

  // 4. Verify
  if (parsedMessage.random.toString() == clientHelloObject.random.toString() &&
      parsedMessage.cipherSuites.toString() ==
          clientHelloObject.cipherSuites.toString()) {
    print(
      "\n👍 Verification successful: Parsed object matches the original object.",
    );
  } else {
    print("\n👎 Verification failed.");
  }
}

// --- Helper Maps for readable output ---
const Map<int, String> _handshakeTypeMap = {1: 'ClientHello', 2: 'ServerHello'};
const Map<int, String> _cipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
};
const Map<int, String> _extensionTypesMap = {
  0: 'server_name',
  43: 'supported_versions',
  // ... other extensions can be added here
};
