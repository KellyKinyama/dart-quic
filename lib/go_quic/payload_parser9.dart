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

  int pullUint32() {
    final v = _byteData.getUint32(_readOffset);
    _readOffset += 4;
    return v;
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
// ## SECTION 2: DATA CLASSES (QUIC and TLS)
// #############################################################################

// QUIC Frame Data Class
class CryptoFrame {
  final int offset;
  final int length;
  final List<TlsHandshakeMessage> messages;
  CryptoFrame(this.offset, this.length, this.messages) {
    // parseTlsMessages(Uint8List cryptoData)
  }

  @override
  String toString() {
    final messageTypes = messages.map((m) => m.typeName).join(', ');
    return 'CryptoFrame(offset: $offset, length: $length, messages: [$messageTypes])';
  }
}

// TLS Handshake Data Classes
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
  String toString() => '    - Ext: $typeName, Length: ${data.length}';
}

class ClientHello extends TlsHandshakeMessage {
  final List<TlsExtension> extensions;
  ClientHello({required this.extensions}) : super(0x01);
  @override
  String toString() =>
      '  - TLS ClientHello(extensions: ${extensions.length})\n${extensions.join('\n')}';
}

class UnknownHandshakeMessage extends TlsHandshakeMessage {
  UnknownHandshakeMessage(int msgType) : super(msgType);
  @override
  String toString() => '  - TLS UnknownHandshake(type: $msgType)';
}

// #############################################################################
// ## SECTION 3: PARSER LOGIC (QUIC and TLS)
// #############################################################################

// TLS Parsers
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

TlsHandshakeMessage _parseHandshakeBody(int msgType, Buffer buffer) {
  switch (msgType) {
    case 0x01: // ClientHello
      buffer.pullUint16(); // Skip legacy_version
      buffer.pullBytes(32); // Skip random
      buffer.pullVector(1); // Skip legacy_session_id
      buffer.pullVector(2); // Skip cipher_suites
      buffer.pullVector(1); // Skip legacy_compression_methods
      final extensions = _parseExtensions(buffer);
      return ClientHello(extensions: extensions);
    // Other message parsers could be added here
    default:
      return UnknownHandshakeMessage(msgType);
  }
}

List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];
  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();
    // Ensure we don't over-read
    if (length > buffer.remaining)
      throw Exception('Invalid TLS message length');
    final messageBuffer = Buffer(data: buffer.pullBytes(length));
    messages.add(_parseHandshakeBody(msgType, messageBuffer));
  }
  return messages;
}

// QUIC Payload Parser
void parsePayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = Buffer(data: plaintextPayload);
  int frameCount = 0;

  try {
    while (!buffer.eof) {
      if (buffer._byteData.getUint8(buffer._readOffset) == 0) {
        buffer.pullUint8(); // Consume PADDING byte and loop again
        continue;
      }

      final frameType = buffer.pullVarInt();
      frameCount++;
      switch (frameType) {
        case 0x06: // CRYPTO Frame
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
          final cryptoData = buffer.pullBytes(length);
          // Now, parse the TLS messages inside the crypto data
          final tlsMessages = parseTlsMessages(cryptoData);
          final frame = CryptoFrame(offset, length, tlsMessages);
          print('✅ Parsed Frame $frameCount: $frame');
          // Print details of the first TLS message found
          if (frame.messages.isNotEmpty) {
            print(frame.messages.first);
          }
          break;
        default:
          print(
            '⚠️ Parsed Frame $frameCount: Skipping unknown frame type: 0x${frameType.toRadixString(16)}',
          );
          return; // Stop on unknown frames for safety
      }
    }
  } catch (e, st) {
    print('\n🛑 An error occurred during parsing: $e');
    print(st);
  }
  print('\n🎉 Payload parsing complete.');
}

// #############################################################################
// ## SECTION 4: DEMONSTRATION
// #############################################################################

void main() {
  // This is the full, decrypted payload from RFC 9001, Appendix A.2
  // It contains one CRYPTO frame followed by PADDING frames.
  final rfcInitialPayload =
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
            ..add(Uint8List(1162 - 242))) // 242 is the crypto frame size
          .toBytes();

  parsePayload(rfcInitialPayload);
}

// Helper Maps for readable output
const Map<int, String> _handshakeTypeMap = {1: 'ClientHello'};
const Map<int, String> _extensionTypesMap = {
  0: 'server_name',
  5: 'status_request',
  10: 'supported_groups',
  16: 'application_layer_protocol_negotiation',
  35: 'pre_shared_key',
  41: 'early_data',
  43: 'supported_versions',
  45: 'psk_key_exchange_modes',
  51: 'key_share',
  57: 'quic_transport_parameters',
  13: 'signature_algorithms',
};
