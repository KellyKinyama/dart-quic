import 'dart:typed_data';
import 'package:hex/hex.dart';

// import 'tls/client_hello.dart';

// #############################################################################
// ## SECTION 1: UTILITY BUFFER CLASS
// #############################################################################
/// An extension to add the missing setUint24 method to ByteData.
extension ByteDataWriter on ByteData {
  void setUint24(int offset, int value) {
    // Write the 24-bit integer as three separate bytes (big-endian).
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

  int pullVarInt() {
    final firstByte = _byteData.getUint8(_readOffset);
    final prefix = firstByte >> 6;
    final len = 1 << prefix;
    if (_readOffset + len > length)
      throw Exception('VarInt read would overflow buffer');
    int val = firstByte & 0x3F;
    for (int i = 1; i < len; i++) {
      val = (val << 8) | _byteData.getUint8(_readOffset + i);
    }
    _readOffset += len;
    return val;
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

// class ClientHello extends TlsHandshakeMessage {
//   // ClientHello class is defined but not the focus of this update
//   ClientHello() : super(0x01);
// }
// class ClientHello extends TlsHandshakeMessage {
//   final Uint8List random;
//   final List<int> cipherSuites;
//   final List<TlsExtension> extensions;
//   ClientHello({
//     required this.random,
//     required this.cipherSuites,
//     required this.extensions,
//   }) : super(1);
//   @override
//   String toString() =>
//       'ClientHello(random: ${HEX.encode(random.sublist(0, 4))}..., suites: ${cipherSuites.length}, extensions: ${extensions.length})';
// }

class ServerHello extends TlsHandshakeMessage {
  final Uint8List random;
  final Uint8List legacySessionIdEcho;
  final int cipherSuite;
  final List<TlsExtension> extensions;

  ServerHello({
    required this.random,
    required this.legacySessionIdEcho,
    required this.cipherSuite,
    required this.extensions,
  }) : super(0x02);

  @override
  String toString() {
    return '''
✅ Parsed ServerHello (Type 0x02):
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Session ID Echo Length: ${legacySessionIdEcho.length}
- Cipher Suite: ${_cipherSuitesMap[cipherSuite] ?? 'Unknown'}
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
  int extensionsRead = 0;
  while (extensionsRead < totalExtLen && buffer.remaining > 0) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);
    extensions.add(TlsExtension(extType, extData));
    extensionsRead += 4 + extLen;
  }
  return extensions;
}

ClientHello _parseClientHelloBody(Buffer buffer) {
  // Parser is defined but not the focus of this update
  // buffer.pullUint16(); // Skip legacy_version
  // final random = buffer.pullBytes(32);
  // final legacySessionIdEcho = buffer.pullVector(1);
  // final cipherSuite = buffer.pullUint16();
  // buffer.pullUint8(); // Skip legacy_compression_method
  // final extensions = _parseExtensions(buffer);
 
}

ServerHello _parseServerHelloBody(Buffer buffer) {
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  final legacySessionIdEcho = buffer.pullVector(1);
  final cipherSuite = buffer.pullUint16();
  buffer.pullUint8(); // Skip legacy_compression_method
  final extensions = _parseExtensions(buffer);
  return ServerHello(
    random: random,
    legacySessionIdEcho: legacySessionIdEcho,
    cipherSuite: cipherSuite,
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
        // ClientHello
        // messages.add(_parseClientHelloBody(messageBuffer));
        _parseClientHelloBody(messageBuffer);
        break;
      case 0x02:
        messages.add(_parseServerHelloBody(messageBuffer));
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
  final lenBuilder = BytesBuilder()
    ..add((ByteData(2)..setUint16(0, allExtBytes.length)).buffer.asUint8List());
  return (BytesBuilder()
        ..add(lenBuilder.toBytes())
        ..add(allExtBytes))
      .toBytes();
}

Uint8List _buildServerHelloBody(ServerHello msg) {
  return (BytesBuilder()
        ..add([0x03, 0x03]) // legacy_version
        ..add(msg.random)
        ..addByte(msg.legacySessionIdEcho.length)
        ..add(msg.legacySessionIdEcho)
        ..add((ByteData(2)..setUint16(0, msg.cipherSuite)).buffer.asUint8List())
        ..addByte(0) // legacy_compression_method
        ..add(_buildExtensions(msg.extensions)))
      .toBytes();
}

Uint8List buildTlsMessage(TlsHandshakeMessage msg) {
  Uint8List bodyBytes;
  switch (msg.msgType) {
    case 0x02:
      bodyBytes = _buildServerHelloBody(msg as ServerHello);
      break;
    default:
      throw UnimplementedError(
        'Builder for message type ${msg.msgType} not implemented.',
      );
  }
  final header =
      (ByteData(4)
            ..setUint8(0, msg.msgType)
            ..setUint24(1, bodyBytes.length))
          .buffer
          .asUint8List();
  return (BytesBuilder()
        ..add(header)
        ..add(bodyBytes))
      .toBytes();
}

// #############################################################################
// ## SECTION 5: DEMONSTRATION
// #############################################################################

void main() {
  // This is the ServerHello message from the CRYPTO frame in RFC 9001, Appendix A.3
  final rfcServerHelloData = HEX.decode(
    '02000056' // Handshake Type (2), Length (86)
    '0303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a12' // Version + Random
    '00' // Session ID Echo length (is 0 in this RFC example)
    '1301' // Cipher Suite (TLS_AES_128_GCM_SHA256)
    '00' // Compression Method
    '002e' // Extensions Length (46)
    '00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a' // key_share
    '002b00020304', // supported_versions
  );

  print("--- Parsing ServerHello from RFC 9001 ---");
  final parsedMessages = parseTlsMessages(
    Uint8List.fromList(rfcServerHelloData),
  );
  final originalMessage = parsedMessages.first as ServerHello;
  print(originalMessage);

  print("\n--- Building ServerHello and Verifying (Round Trip Test) ---");
  // 1. Build the parsed object back into bytes
  final builtBytes = buildTlsMessage(originalMessage);
  print("✅ Built ${builtBytes.length} bytes successfully.");

  // 2. Parse the bytes we just built
  final reParsedMessage = parseTlsMessages(builtBytes).first as ServerHello;
  print("✅ Re-parsed the built bytes successfully.");

  // 3. Verify
  if (HEX.encode(builtBytes) == HEX.encode(rfcServerHelloData)) {
    print("👍 Verification successful: Built bytes match original RFC data.");
  } else {
    print(
      "👎 Verification failed: Built bytes do not match original RFC data.",
    );
  }
}

// --- Helper Maps for readable output ---
const Map<int, String> _handshakeTypeMap = {1: 'ClientHello', 2: 'ServerHello'};
const Map<int, String> _cipherSuitesMap = {0x1301: 'TLS_AES_128_GCM_SHA256'};
const Map<int, String> _extensionTypesMap = {
  0x002b: 'supported_versions',
  0x0033: 'key_share',
};
