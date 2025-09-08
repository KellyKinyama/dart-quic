import 'dart:typed_data';
import 'package:hex/hex.dart';

// #############################################################################
// ## SECTION 1: UTILITY BUFFER CLASS
// #############################################################################

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
    if (_readOffset + len > length)
      throw Exception('Buffer underflow while pulling $len bytes');
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
    if (_readOffset + len > length) {
      throw Exception('VarInt read would overflow buffer');
    }
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

class ClientHello extends TlsHandshakeMessage {
  final Uint8List random;
  final List<int> cipherSuites;
  final List<TlsExtension> extensions;
  ClientHello({
    required this.random,
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
- Cipher Suites:
    $suites
- Extensions Count: ${extensions.length}''';
  }
}

class ServerHello extends TlsHandshakeMessage {
  // (Implementation from previous response)
  ServerHello() : super(0x02);
}

// (Other server-side data classes omitted for brevity)

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
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  buffer.pullVector(1); // Skip legacy_session_id

  final cipherSuitesBytes = buffer.pullVector(2);
  final cipherSuites = <int>[];
  final csBuffer = Buffer(data: cipherSuitesBytes);
  while (!csBuffer.eof) {
    cipherSuites.add(csBuffer.pullUint16());
  }

  buffer.pullVector(1); // Skip legacy_compression_methods
  final extensions = _parseExtensions(buffer);

  return ClientHello(
    random: random,
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
      case 0x01: // ClientHello
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
// ## SECTION 4: DEMONSTRATION
// #############################################################################

void parsePayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = Buffer(data: plaintextPayload);

  try {
    while (!buffer.eof && buffer._byteData.getUint8(buffer._readOffset) != 0) {
      final frameType = buffer.pullVarInt();
      if (frameType == 0x06) {
        // CRYPTO Frame
        final offset = buffer.pullVarInt();
        final length = buffer.pullVarInt();
        final cryptoData = buffer.pullBytes(length);
        print('✅ Parsed CRYPTO Frame: offset: $offset, length: $length');
        final tlsMessages = parseTlsMessages(cryptoData);
        for (final msg in tlsMessages) {
          print(msg);
        }
      } else {
        print('ℹ️ Skipping frame type 0x${frameType.toRadixString(16)}');
      }
    }
  } catch (e) {
    print('\n🛑 An error occurred during parsing: $e');
  }
  print('\n🎉 Payload parsing complete.');
}

void main() {
  // The ClientHello payload from RFC 9001, Appendix A.2
  final rfcClientHelloPayload =
      (BytesBuilder()
            ..add(
              HEX.decode(
                '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
                '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
                '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
                '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
                'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
                '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
                '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
                '75300901100f088394c8f03e51570806048000ffff',
              ),
            )
            ..add(Uint8List(920)) // Padding to simulate a real initial packet
            )
          .toBytes();

  print("--- Running with RFC 9001 ClientHello Payload ---");
  parsePayload(rfcClientHelloPayload);
}

// --- Helper Maps for readable output ---
const Map<int, String> _handshakeTypeMap = {
  1: 'ClientHello',
  2: 'ServerHello',
  8: 'EncryptedExtensions',
  11: 'Certificate',
  15: 'CertificateVerify',
  20: 'Finished',
};
const Map<int, String> _cipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
};
const Map<int, String> _extensionTypesMap = {
  0: 'server_name',
  5: 'status_request',
  10: 'supported_groups',
  16: 'application_layer_protocol_negotiation',
  35: 'pre_shared_key',
  43: 'supported_versions',
  44: 'cookie',
  45: 'psk_key_exchange_modes',
  51: 'key_share',
  57: 'quic_transport_parameters',
  28: 'session_ticket',
  13: 'signature_algorithms',
};
