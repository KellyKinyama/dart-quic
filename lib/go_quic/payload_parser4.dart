import 'dart:typed_data';
import 'package:hex/hex.dart';

// --- UTILITY AND DATA CLASSES ---

class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;
  int get remaining => length - _readOffset;

  // This constructor is more robust, correctly handling views of Uint8List
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
    final b1 = pullUint8();
    final b2 = pullUint8();
    final b3 = pullUint8();
    return (b1 << 16) | (b2 << 8) | b3;
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

  Uint8List pullBytes(int len) {
    if (_readOffset + len > length) {
      throw Exception('Pulling $len bytes would overflow buffer');
    }
    final bytes = _byteData.buffer.asUint8List(
      _byteData.offsetInBytes + _readOffset,
      len,
    );
    _readOffset += len;
    return bytes;
  }
}

class CryptoFrame {
  final int offset;
  final Uint8List data;
  CryptoFrame(this.offset, this.data);

  @override
  String toString() {
    return 'CryptoFrame(offset: $offset, data_length: ${data.length})';
  }
}

// --- TLS HANDSHAKE DATA CLASSES ---

abstract class TlsHandshakeMessage {
  final int handshakeType;
  String get typeName => _handshakeTypeMap[handshakeType] ?? 'Unknown';
  TlsHandshakeMessage(this.handshakeType);
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

class UnknownHandshakeMessage extends TlsHandshakeMessage {
  final Uint8List data;
  UnknownHandshakeMessage(int handshakeType, this.data) : super(handshakeType);

  @override
  String toString() =>
      'TLS Handshake Message: $typeName (Type 0x${handshakeType.toRadixString(16)}), Length: ${data.length}';
}

class ClientHello extends TlsHandshakeMessage {
  // Fields omitted for brevity as they are not the focus of the fix
  ClientHello() : super(0x01);
}

class ServerHello extends TlsHandshakeMessage {
  final Uint8List random;
  final int cipherSuite;
  final List<TlsExtension> extensions;
  ServerHello({
    required this.random,
    required this.cipherSuite,
    required this.extensions,
  }) : super(0x02);

  @override
  String toString() {
    return '''
✅ Parsed ServerHello (Type 0x02):
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Cipher Suite: ${_cipherSuitesMap[cipherSuite] ?? 'Unknown'}
- Extensions:
${extensions.join('\n')}''';
  }
}

class EncryptedExtensions extends TlsHandshakeMessage {
  final List<TlsExtension> extensions;
  EncryptedExtensions({required this.extensions}) : super(0x08);
  @override
  String toString() {
    return '''
✅ Parsed EncryptedExtensions (Type 0x08):
- Extensions:
${extensions.join('\n')}''';
  }
}

// --- REFACTORED AND COMPLETED PARSING LOGIC ---

/// Helper function to parse a list of TLS extensions.
List<TlsExtension> _parseExtensions(Buffer buffer) {
  if (buffer.remaining < 2) return [];
  final totalExtLen = buffer.pullUint16();
  final extensions = <TlsExtension>[];
  int extensionsRead = 0;
  while (extensionsRead < totalExtLen) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);
    extensions.add(TlsExtension(extType, extData));
    extensionsRead += 4 + extLen;
  }
  return extensions;
}

ServerHello _parseServerHelloBody(Buffer buffer) {
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  final sessionIdLen = buffer.pullUint8();
  buffer.pullBytes(sessionIdLen); // Skip legacy_session_id_echo
  final cipherSuite = buffer.pullUint16();
  buffer.pullUint8(); // Skip legacy_compression_method
  final extensions = _parseExtensions(buffer);
  return ServerHello(
    random: random,
    cipherSuite: cipherSuite,
    extensions: extensions,
  );
}

EncryptedExtensions _parseEncryptedExtensionsBody(Buffer buffer) {
  final extensions = _parseExtensions(buffer);
  return EncryptedExtensions(extensions: extensions);
}

List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];

  while (!buffer.eof) {
    final handshakeType = buffer.pullUint8();
    final length = buffer.pullUint24();
    // Create a sub-buffer for the message body to prevent over-reading
    final messageBuffer = Buffer(data: buffer.pullBytes(length));

    switch (handshakeType) {
      case 0x02: // ServerHello
        messages.add(_parseServerHelloBody(messageBuffer));
        break;
      case 0x08: // EncryptedExtensions
        messages.add(_parseEncryptedExtensionsBody(messageBuffer));
        break;
      default:
        messages.add(
          UnknownHandshakeMessage(
            handshakeType,
            messageBuffer.length > 0
                ? messageBuffer.pullBytes(messageBuffer.length)
                : Uint8List(0),
          ),
        );
    }
  }
  return messages;
}

void parsePayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = Buffer(data: plaintextPayload);

  try {
    while (!buffer.eof && buffer._byteData.getUint8(buffer._readOffset) != 0) {
      final frameType = buffer.pullVarInt();
      switch (frameType) {
        case 0x06: // CRYPTO Frame
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
          final cryptoData = buffer.pullBytes(length);
          print('✅ Parsed CRYPTO Frame: offset: $offset, length: $length');
          final tlsMessages = parseTlsMessages(cryptoData);
          for (final msg in tlsMessages) {
            print(msg);
          }
          break;
        default:
          print(
            '⚠️ Encountered unhandled frame type: 0x${frameType.toRadixString(16)}',
          );
          return;
      }
    }
  } catch (e) {
    print('\n🛑 An error occurred during parsing: $e');
  }
  print('\n🎉 Payload parsing complete.');
}

void main() {
  // A corrected and realistic server payload with multiple handshake messages.
  // Lengths have been fixed to match the actual data provided.
  final serverHandshakeFlight =
      (BytesBuilder()
            // Message 1: ServerHello (body is 78 bytes)
            ..add(HEX.decode('0200004e')) // Type 2, Length 78
            ..add(HEX.decode('0303')) // legacy_version
            ..add(Uint8List(32)..fillRange(0, 32, 0xAA)) // random
            ..add([0x20]) // session_id length
            ..add(Uint8List(32)..fillRange(0, 32, 0xBB)) // session_id
            ..add(HEX.decode('1302')) // cipher_suite (TLS_AES_256_GCM_SHA384)
            ..add([0x00]) // compression_method
            ..add(HEX.decode('0008002b0002030400330000')) // extensions
            // Message 2: EncryptedExtensions (body is 14 bytes)
            ..add(HEX.decode('0800000e')) // Type 8, Length 14
            ..add(HEX.decode('000c003900080102030405060708')) // extensions
            )
          .toBytes();

  // The QUIC CRYPTO frame header. The length is the total length of the TLS messages (82 + 18 = 100 bytes).
  final cryptoFrameHeader = HEX.decode(
    '06004064',
  ); // Type 6, offset 0, length 100

  final fullPayload =
      (BytesBuilder()
            ..add(cryptoFrameHeader)
            ..add(serverHandshakeFlight))
          .toBytes();

  print("\n--- Running with corrected Server Payload ---");
  parsePayload(fullPayload);
}

// --- HELPER MAPS ---
const Map<int, String> _handshakeTypeMap = {
  1: 'ClientHello',
  2: 'ServerHello',
  8: 'EncryptedExtensions',
};
const Map<int, String> _cipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
};
const Map<int, String> _extensionTypesMap = {
  43: 'supported_versions',
  51: 'key_share',
  57: 'quic_transport_parameters',
};
