import 'dart:typed_data';
import 'package:hex/hex.dart';

// #############################################################################
// ## SECTION 1: UTILITY AND EXTENSIONS (Unchanged)
// #############################################################################

extension ByteDataWriter on ByteData {
  void setUint24(int offset, int value) {
    setUint8(offset, (value >> 16) & 0xFF);
    setUint8(offset + 1, (value >> 8) & 0xFF);
    setUint8(offset + 2, value & 0xFF);
  }
}

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
}

// #############################################################################
// ## SECTION 2: TLS DATA CLASSES (Unchanged)
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
  ClientHello() : super(0x01);
  @override
  String toString() => '✅ Parsed ClientHello';
}

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
  String toString() =>
      '✅ Parsed ServerHello(suite: ${_cipherSuitesMap[cipherSuite]}, extensions: ${extensions.length})';
}

class NewSessionTicket extends TlsHandshakeMessage {
  NewSessionTicket() : super(0x04);
  @override
  String toString() => '✅ Parsed NewSessionTicket';
}

class EndOfEarlyData extends TlsHandshakeMessage {
  EndOfEarlyData() : super(0x05);
  @override
  String toString() => '✅ Parsed EndOfEarlyData';
}

class EncryptedExtensions extends TlsHandshakeMessage {
  final List<TlsExtension> extensions;
  EncryptedExtensions({required this.extensions}) : super(0x08);
  @override
  String toString() =>
      '✅ Parsed EncryptedExtensions(extensions: ${extensions.length})';
}

class CertificateEntry {
  final Uint8List certData;
  final List<TlsExtension> extensions;
  CertificateEntry(this.certData, this.extensions);
}

class Certificate extends TlsHandshakeMessage {
  final Uint8List certificateRequestContext;
  final List<CertificateEntry> certificateList;
  Certificate({
    required this.certificateRequestContext,
    required this.certificateList,
  }) : super(0x0b);
  @override
  String toString() => '✅ Parsed Certificate(certs: ${certificateList.length})';
}

class CertificateRequest extends TlsHandshakeMessage {
  CertificateRequest() : super(0x0d);
  @override
  String toString() => '✅ Parsed CertificateRequest';
}

class CertificateVerify extends TlsHandshakeMessage {
  final int algorithm;
  final Uint8List signature;
  CertificateVerify(this.algorithm, this.signature) : super(0x0f);
  @override
  String toString() =>
      '✅ Parsed CertificateVerify(alg: 0x${algorithm.toRadixString(16)}, sig_len: ${signature.length})';
}

class Finished extends TlsHandshakeMessage {
  final Uint8List verifyData;
  Finished(this.verifyData) : super(0x14);
  @override
  String toString() =>
      '✅ Parsed Finished(verify_data_len: ${verifyData.length})';
}

class KeyUpdate extends TlsHandshakeMessage {
  KeyUpdate() : super(0x18);
  @override
  String toString() => '✅ Parsed KeyUpdate';
}

class UnknownHandshakeMessage extends TlsHandshakeMessage {
  final Uint8List body;
  UnknownHandshakeMessage(int msgType, this.body) : super(msgType);
  @override
  String toString() =>
      'ℹ️ Parsed UnknownHandshake(type: $msgType, len: ${body.length})';
}

// #############################################################################
// ## SECTION 3: PARSER LOGIC (Unchanged)
// #############################################################################

/// Helper function to parse a message and verify buffer consumption
T parseMessage<T extends TlsHandshakeMessage>(
  Buffer buffer,
  T Function(Buffer) parser,
) {
  final message = parser(buffer);
  if (buffer.remaining > 0) {
    throw Exception(
      'Extra ${buffer.remaining} bytes found at the end of ${message.typeName} body',
    );
  }
  return message;
}

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

List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];
  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();
    final messageBuffer = Buffer(data: buffer.pullBytes(length));

    switch (msgType) {
      case 0x02: // ServerHello
        messages.add(
          parseMessage(messageBuffer, (b) {
            b.pullUint16();
            final random = b.pullBytes(32);
            final legacySessionIdEcho = b.pullVector(1);
            final cipherSuite = b.pullUint16();
            b.pullUint8();
            final extensions = _parseExtensions(b);
            return ServerHello(
              random: random,
              legacySessionIdEcho: legacySessionIdEcho,
              cipherSuite: cipherSuite,
              extensions: extensions,
            );
          }),
        );
        break;

      case 0x08: // EncryptedExtensions
        messages.add(
          parseMessage(
            messageBuffer,
            (b) => EncryptedExtensions(extensions: _parseExtensions(b)),
          ),
        );
        break;

      case 0x0b: // Certificate
        messages.add(
          parseMessage(messageBuffer, (b) {
            final context = b.pullVector(1);
            final certListBytes = b.pullVector(3);
            final certListBuffer = Buffer(data: certListBytes);
            final certs = <CertificateEntry>[];
            while (!certListBuffer.eof) {
              certs.add(
                CertificateEntry(
                  certListBuffer.pullVector(3),
                  _parseExtensions(certListBuffer),
                ),
              );
            }
            return Certificate(
              certificateRequestContext: context,
              certificateList: certs,
            );
          }),
        );
        break;

      case 0x0f: // CertificateVerify
        messages.add(
          parseMessage(
            messageBuffer,
            (b) => CertificateVerify(b.pullUint16(), b.pullVector(2)),
          ),
        );
        break;

      case 0x14: // Finished
        messages.add(
          parseMessage(
            messageBuffer,
            (b) => Finished(b.pullBytes(b.remaining)),
          ),
        );
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

void main() {
  // CORRECTED: A realistic, concatenated server handshake flight with accurate lengths.
  final serverHandshakeFlight =
      (BytesBuilder()
            // Message 1: ServerHello (body is 82 bytes)
            ..add(HEX.decode('02000052')) // Type 2, Length 82
            ..add(
              HEX.decode(
                '0303' // legacy_version
                    +
                    'aa' *
                        32 // random
                        +
                    '20' +
                    'bb' *
                        32 // legacy_session_id_echo
                        +
                    '1302' // cipher_suite
                    +
                    '00' // legacy_compression_method
                    +
                    '000a' // extensions length (10)
                    +
                    '002b00020304' // supported_versions (6 bytes)
                    +
                    '00330000', // key_share (4 bytes)
              ),
            )
            // Message 2: EncryptedExtensions (body is 14 bytes)
            ..add(HEX.decode('0800000e')) // Type 8, Length 14
            ..add(
              HEX.decode(
                '000c' // extensions length (12)
                    +
                    '003900080102030405060708', // quic_transport_parameters (12 bytes)
              ),
            )
            // Message 3: Certificate (body is 22 bytes)
            ..add(HEX.decode('0b000016')) // Type 11, Length 22
            ..add(
              HEX.decode(
                '00' // certificate_request_context_length (0)
                    +
                    '000012' // certificate_list length (18)
                    +
                    '00000d' +
                    'cc' *
                        13 // cert_data (16 bytes)
                        +
                    '0000', // extensions length (0)
              ),
            )
            // Message 4: CertificateVerify (body is 6 bytes)
            ..add(HEX.decode('0f000006')) // Type 15, Length 6
            ..add(
              HEX.decode(
                '0804' // algorithm
                    +
                    '0002' +
                    'dd' * 2, // signature
              ),
            )
            // Message 5: Finished (body is 32 bytes)
            ..add(HEX.decode('14000020')) // Type 20, Length 32
            ..add(Uint8List(32)..fillRange(0, 32, 0xEE)))
          .toBytes();

  print("--- Parsing Simulated Server Handshake Flight ---");
  try {
    final tlsMessages = parseTlsMessages(serverHandshakeFlight);
    for (final msg in tlsMessages) {
      print(msg);
    }
  } catch (e, st) {
    print('\n🛑 An error occurred during parsing: $e');
    print(st);
  }
}

// --- Helper Maps for readable output ---
const Map<int, String> _handshakeTypeMap = {
  1: 'ClientHello',
  2: 'ServerHello',
  4: 'NewSessionTicket',
  5: 'EndOfEarlyData',
  8: 'EncryptedExtensions',
  11: 'Certificate',
  13: 'CertificateRequest',
  15: 'CertificateVerify',
  20: 'Finished',
  24: 'KeyUpdate',
};
const Map<int, String> _cipherSuitesMap = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
};
const Map<int, String> _extensionTypesMap = {
  0x002b: 'supported_versions',
  0x0033: 'key_share',
  0x0039: 'quic_transport_parameters',
};
