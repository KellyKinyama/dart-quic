import 'dart:typed_data';
import 'package:hex/hex.dart';

// --- UTILITY AND DATA CLASSES (Buffer is unchanged) ---

class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;
  int get remaining => length - _readOffset;

  Buffer({required Uint8List data}) : _byteData = data.buffer.asByteData();

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
    final bytes = _byteData.buffer.asUint8List(_readOffset, len);
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

// --- NEW: Generic Handshake Message Classes ---

/// Base class for all parsed TLS Handshake messages.
abstract class TlsHandshakeMessage {
  final int handshakeType;
  final int length;
  String get typeName => _handshakeTypeMap[handshakeType] ?? 'Unknown';
  TlsHandshakeMessage(this.handshakeType, this.length);
}

/// A message type we haven't implemented a specific parser for yet.
class UnknownHandshakeMessage extends TlsHandshakeMessage {
  final Uint8List data;
  UnknownHandshakeMessage(int handshakeType, int length, this.data)
    : super(handshakeType, length);

  @override
  String toString() {
    return 'TLS Handshake Message: $typeName (Type 0x${handshakeType.toRadixString(16)}), Length: $length';
  }
}

class TlsExtension {
  final int type;
  final Uint8List data;
  TlsExtension(this.type, this.data);
  String get typeName =>
      _extensionTypesMap[type] ?? 'Unknown (0x${type.toRadixString(16)})';
}

class ClientHello extends TlsHandshakeMessage {
  final int legacyVersion;
  final Uint8List random;
  final Uint8List legacySessionId;
  final List<int> cipherSuites;
  final Uint8List legacyCompressionMethods;
  final List<TlsExtension> extensions;

  ClientHello({
    required int length,
    required this.legacyVersion,
    required this.random,
    required this.legacySessionId,
    required this.cipherSuites,
    required this.legacyCompressionMethods,
    required this.extensions,
  }) : super(0x01, length);

  @override
  String toString() {
    final suites = cipherSuites
        .map((s) => _cipherSuitesMap[s] ?? 'Unknown (0x${s.toRadixString(16)})')
        .join(', ');
    return '''
TLS ClientHello (Type 0x01):
- Version: 0x${legacyVersion.toRadixString(16)}
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Cipher Suites: [$suites]
- Extensions Count: ${extensions.length}''';
  }
}

// --- REFACTORED PARSING LOGIC ---

/// Parses one or more TLS handshake messages from the CRYPTO frame data.
List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];

  while (!buffer.eof) {
    final handshakeType = buffer.pullUint8();
    final length = buffer.pullUint24();
    final messageData = buffer.pullBytes(length);

    // Use a sub-buffer to parse the specific message type
    final messageBuffer = Buffer(data: messageData);

    switch (handshakeType) {
      case 0x01: // ClientHello
        messages.add(_parseClientHelloBody(messageBuffer, length));
        break;
      // Add other cases here as needed, e.g., ServerHello (0x02)
      // case 0x02:
      //   messages.add(_parseServerHelloBody(messageBuffer, length));
      //   break;
      default:
        messages.add(
          UnknownHandshakeMessage(handshakeType, length, messageData),
        );
    }
  }
  return messages;
}

ClientHello _parseClientHelloBody(Buffer buffer, int length) {
  final legacyVersion = buffer.pullUint16();
  final random = buffer.pullBytes(32);
  final sessionIdLen = buffer.pullUint8();
  final legacySessionId = buffer.pullBytes(sessionIdLen);
  final cipherSuitesLen = buffer.pullUint16();
  final List<int> cipherSuites = [];
  for (int i = 0; i < cipherSuitesLen / 2; i++) {
    cipherSuites.add(buffer.pullUint16());
  }
  final compressionMethodsLen = buffer.pullUint8();
  final legacyCompressionMethods = buffer.pullBytes(compressionMethodsLen);
  final extensionsLen = buffer.pullUint16();
  final List<TlsExtension> extensions = [];
  int extensionsRead = 0;
  while (extensionsRead < extensionsLen) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);
    extensions.add(TlsExtension(extType, extData));
    extensionsRead += 4 + extLen;
  }
  return ClientHello(
    length: length,
    legacyVersion: legacyVersion,
    random: random,
    legacySessionId: legacySessionId,
    cipherSuites: cipherSuites,
    legacyCompressionMethods: legacyCompressionMethods,
    extensions: extensions,
  );
}

/// Parses the plaintext payload of a QUIC packet.
void parsePayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = Buffer(data: plaintextPayload);
  int frameCount = 0;

  try {
    while (!buffer.eof) {
      if (buffer._byteData.getUint8(buffer._readOffset) == 0) {
        buffer.pullUint8(); // Consume single padding byte and continue
        continue;
      }

      final frameType = buffer.pullVarInt();
      frameCount++;

      switch (frameType) {
        case 0x06: // CRYPTO Frame
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
          final cryptoData = buffer.pullBytes(length);
          final frame = CryptoFrame(offset, cryptoData);
          print('✅ Parsed Frame $frameCount: $frame');

          final tlsMessages = parseTlsMessages(cryptoData);
          for (final msg in tlsMessages) {
            print(msg); // Print the formatted message
          }
          break;

        default:
          print(
            '⚠️ Parsed Frame $frameCount: Encountered unhandled frame type: 0x${frameType.toRadixString(16)}',
          );
          // Stop parsing if we hit an unknown frame we can't skip
          return;
      }
    }
  } catch (e) {
    print('\n🛑 An error occurred during parsing: $e');
  }
  print('\n🎉 Payload parsing complete.');
}

void main() {
  // Use the valid ClientHello from RFC 9001 for a successful demonstration
  final rfcPayload = BytesBuilder()
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
    ..add(Uint8List(920)); // Add padding to simulate a real initial packet

  print("--- Running with RFC 9001 ClientHello Payload ---");
  parsePayload(rfcPayload.toBytes());

  // Example of a server's first crypto data (ServerHello, EncryptedExtensions, etc.)
  // This would have previously crashed the parser.
  final serverPayload = HEX.decode(
    '0600405a' // CRYPTO frame header
    '02000056' // ServerHello message header
    '0303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200'
    '130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d10'
    '81287c834d5311bcf32bb9da1a'
    '08000000', // EncryptedExtensions (example, not real)
  );
  print("\n--- Running with a simulated Server Payload ---");
  parsePayload(Uint8List.fromList(serverPayload));
}

// --- HELPER MAPS ---

const Map<int, String> _handshakeTypeMap = {
  1: 'ClientHello',
  2: 'ServerHello',
  4: 'NewSessionTicket',
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
  16: 'application_layer_protocol_negotiation',
  43: 'supported_versions',
  51: 'key_share',
  57: 'quic_transport_parameters',
  // Add other common extension types as needed
};
