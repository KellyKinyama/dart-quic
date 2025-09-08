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
}

// #############################################################################
// ## SECTION 2: TLS DATA CLASSES
// #############################################################################

abstract class TlsHandshakeMessage {
  final int msgType;
  String get typeName => _handshakeTypeMap[msgType] ?? 'Unknown';
  TlsHandshakeMessage(this.msgType);
}

class Extension {
  final int type;
  final Uint8List data;
  Extension(this.type, this.data);
  @override
  String toString() =>
      'Extension(type: ${_extensionTypesMap[type] ?? type}, len: ${data.length})';
}

class ClientHello extends TlsHandshakeMessage {
  final Uint8List random;
  final List<int> cipherSuites;
  final List<Extension> extensions;
  ClientHello({
    required this.random,
    required this.cipherSuites,
    required this.extensions,
  }) : super(1);
  @override
  String toString() =>
      'ClientHello(random: ${HEX.encode(random.sublist(0, 4))}..., suites: ${cipherSuites.length}, extensions: ${extensions.length})';
}

class ServerHello extends TlsHandshakeMessage {
  final Uint8List random;
  final int cipherSuite;
  final List<Extension> extensions;
  ServerHello({
    required this.random,
    required this.cipherSuite,
    required this.extensions,
  }) : super(2);
  @override
  String toString() =>
      'ServerHello(random: ${HEX.encode(random.sublist(0, 4))}..., suite: ${_cipherSuitesMap[cipherSuite] ?? cipherSuite}, extensions: ${extensions.length})';
}

class EncryptedExtensions extends TlsHandshakeMessage {
  final List<Extension> extensions;
  EncryptedExtensions({required this.extensions}) : super(8);
  @override
  String toString() => 'EncryptedExtensions(extensions: ${extensions.length})';
}

class CertificateEntry {
  final Uint8List certData;
  final List<Extension> extensions;
  CertificateEntry(this.certData, this.extensions);
  @override
  String toString() =>
      'CertificateEntry(len: ${certData.length}, extensions: ${extensions.length})';
}

class Certificate extends TlsHandshakeMessage {
  final Uint8List certificateRequestContext;
  final List<CertificateEntry> certificateList;
  Certificate({
    required this.certificateRequestContext,
    required this.certificateList,
  }) : super(11);
  @override
  String toString() =>
      'Certificate(context_len: ${certificateRequestContext.length}, certs: ${certificateList.length})';
}

class CertificateVerify extends TlsHandshakeMessage {
  final int algorithm;
  final Uint8List signature;
  CertificateVerify(this.algorithm, this.signature) : super(15);
  @override
  String toString() =>
      'CertificateVerify(alg: 0x${algorithm.toRadixString(16)}, sig_len: ${signature.length})';
}

class Finished extends TlsHandshakeMessage {
  final Uint8List verifyData;
  Finished(this.verifyData) : super(20);
  @override
  String toString() => 'Finished(verify_data: ${HEX.encode(verifyData)})';
}

class UnknownHandshakeMessage extends TlsHandshakeMessage {
  final Uint8List body;
  UnknownHandshakeMessage(int msgType, this.body) : super(msgType);
  @override
  String toString() => 'UnknownHandshake(type: $msgType, len: ${body.length})';
}

// #############################################################################
// ## SECTION 3: PARSER LOGIC
// #############################################################################

List<Extension> _parseExtensions(Buffer buffer) {
  if (buffer.eof) return [];
  final totalExtLen = buffer.pullUint16();
  final extEndOffset = buffer._readOffset + totalExtLen;
  final extensions = <Extension>[];
  while (buffer._readOffset < extEndOffset) {
    extensions.add(Extension(buffer.pullUint16(), buffer.pullVector(2)));
  }
  return extensions;
}

TlsHandshakeMessage _parseHandshakeBody(
  int msgType,
  int length,
  Buffer buffer,
) {
  switch (msgType) {
    
    case 2: // ServerHello
      buffer.pullUint16(); // Skip legacy_version
      final random = buffer.pullBytes(32);
      buffer.pullVector(1); // Skip legacy_session_id_echo
      final cipherSuite = buffer.pullUint16();
      buffer.pullUint8(); // Skip legacy_compression_method
      return ServerHello(
        random: random,
        cipherSuite: cipherSuite,
        extensions: _parseExtensions(buffer),
      );
    case 8: // EncryptedExtensions
      return EncryptedExtensions(extensions: _parseExtensions(buffer));
    case 11: // Certificate
      final context = buffer.pullVector(1);
      final certListBytes = buffer.pullVector(3);
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
    case 15: // CertificateVerify
      return CertificateVerify(buffer.pullUint16(), buffer.pullVector(2));
    case 20: // Finished
      return Finished(buffer.pullBytes(length));
    default:
      return UnknownHandshakeMessage(msgType, buffer.pullBytes(length));
  }
}

List<TlsHandshakeMessage> parseTlsMessages(Uint8List cryptoData) {
  final buffer = Buffer(data: cryptoData);
  final messages = <TlsHandshakeMessage>[];
  while (buffer.remaining > 0) {
    final msgType = buffer.pullUint8();
    final length = buffer.pullUint24();
    final messageBody = buffer.pullBytes(length);
    messages.add(
      _parseHandshakeBody(msgType, length, Buffer(data: messageBody)),
    );
  }
  return messages;
}

// #############################################################################
// ## SECTION 4: DEMONSTRATION
// #############################################################################

void main() {
  // A realistic, concatenated server response for a CRYPTO frame.
  // Contains ServerHello, EncryptedExtensions, Certificate, CertificateVerify, and Finished.
  final serverCryptoData =
      (BytesBuilder()
            // ServerHello
            ..add([0x02, 0x00, 0x00, 0x5a]) // type, length
            ..add([0x03, 0x03]) // legacy_version
            ..add(Uint8List(32)..fillRange(0, 32, 0xAA)) // random
            ..add([0x20]) // session_id_echo length
            ..add(Uint8List(32)..fillRange(0, 32, 0xBB)) // session_id_echo
            ..add([0x13, 0x01]) // cipher_suite
            ..add([0x00]) // compression_method
            ..add(
              HEX.decode(
                '001e002b0002030400330014001d0020c02c60803d48e15f21e0030a8972552291497551e480312a',
              ),
            ) // extensions
            // EncryptedExtensions
            ..add([0x08, 0x00, 0x00, 0x0a]) // type, length
            ..add(HEX.decode('00080039000401020304')) // extensions
            // Certificate
            ..add([0x0b, 0x00, 0x00, 0x17]) // type, length
            ..add([0x00]) // context
            ..add(
              HEX.decode('00001300000d' + '01' * 13 + '0000'),
            ) // cert list with one entry
            // CertificateVerify
            ..add([0x0f, 0x00, 0x00, 0x06]) // type, length
            ..add([0x08, 0x04]) // algorithm
            ..add(HEX.decode('0002' + '02' * 2)) // signature
            // Finished
            ..add([0x14, 0x00, 0x00, 0x20]) // type, length
            ..add(Uint8List(32)..fillRange(0, 32, 0xCC)) // verify_data
            )
          .toBytes();

  print('--- Parsing Simulated Server Handshake Flight ---');
  try {
    final tlsMessages = parseTlsMessages(serverCryptoData);
    for (final msg in tlsMessages) {
      print('✅ Parsed: $msg');
    }
  } catch (e) {
    print('🛑 Error: $e');
  }
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
};
const Map<int, String> _extensionTypesMap = {
  43: 'supported_versions',
  51: 'key_share',
  57: 'quic_transport_parameters',
};
