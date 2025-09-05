import 'dart:convert';
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart' as pc;

// #############################################################################
// ## SECTION 1: UTILITY BUFFER CLASS
// #############################################################################

/// A simple buffer to read data sequentially from a Uint8List.
class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;

  Buffer({required Uint8List data})
      : _byteData = data.buffer.asByteData(data.offsetInBytes, data.lengthInBytes);

  int pullUint8() { final v = _byteData.getUint8(_readOffset); _readOffset += 1; return v; }
  int pullUint16() { final v = _byteData.getUint16(_readOffset); _readOffset += 2; return v; }
  int pullUint24() { final h = _byteData.getUint8(_readOffset); final l = _byteData.getUint16(_readOffset + 1); _readOffset += 3; return (h << 16) | l; }
  int pullUint32() { final v = _byteData.getUint32(_readOffset); _readOffset += 4; return v; }
  Uint8List pullBytes(int len) {
    if (_readOffset + len > length) throw Exception('Buffer underflow');
    final b = _byteData.buffer.asUint8List(_byteData.offsetInBytes + _readOffset, len);
    _readOffset += len;
    return b;
  }
  Uint8List pullVector(int lenBytes) {
    int vecLen;
    if (lenBytes == 1) vecLen = pullUint8();
    else if (lenBytes == 2) vecLen = pullUint16();
    else if (lenBytes == 3) vecLen = pullUint24();
    else throw ArgumentError('Vector length must be 1, 2, or 3 bytes');
    return pullBytes(vecLen);
  }
}

// #############################################################################
// ## SECTION 2: TLS DATA CLASSES
// #############################################################################

class Extension {
  final int type; final Uint8List data;
  Extension(this.type, this.data);
  @override String toString() => 'Extension(type: $type, len: ${data.length})';
}

class ClientHello {
  final Uint8List random; final Uint8List legacySessionId; final List<int> cipherSuites; final List<Extension> extensions;
  ClientHello({required this.random, required this.legacySessionId, required this.cipherSuites, required this.extensions});
  @override String toString() => 'ClientHello(random: ${HEX.encode(random.sublist(0, 4))}..., suites: ${cipherSuites.length}, extensions: ${extensions.length})';
}

class ServerHello {
  final Uint8List random; final Uint8List legacySessionIdEcho; final int cipherSuite; final List<Extension> extensions;
  ServerHello({required this.random, required this.legacySessionIdEcho, required this.cipherSuite, required this.extensions});
  @override String toString() => 'ServerHello(random: ${HEX.encode(random.sublist(0, 4))}..., suite: 0x${cipherSuite.toRadixString(16)}, extensions: ${extensions.length})';
}

class EncryptedExtensions {
  final List<Extension> extensions;
  EncryptedExtensions({required this.extensions});
  @override String toString() => 'EncryptedExtensions(extensions: ${extensions.length})';
}

class CertificateEntry {
  final Uint8List certData; final List<Extension> extensions;
  CertificateEntry(this.certData, this.extensions);
  @override String toString() => 'CertificateEntry(len: ${certData.length}, extensions: ${extensions.length})';
}

class Certificate {
  final Uint8List certificateRequestContext; final List<CertificateEntry> certificateList;
  Certificate({required this.certificateRequestContext, required this.certificateList});
  @override String toString() => 'Certificate(context_len: ${certificateRequestContext.length}, certs: ${certificateList.length})';
}

class CertificateVerify {
  final int algorithm; final Uint8List signature;
  CertificateVerify(this.algorithm, this.signature);
  @override String toString() => 'CertificateVerify(alg: 0x${algorithm.toRadixString(16)}, sig_len: ${signature.length})';
}

class Finished {
  final Uint8List verifyData;
  Finished(this.verifyData);
  @override String toString() => 'Finished(verify_data: ${HEX.encode(verifyData)})';
}

class Handshake {
  final int msgType; final dynamic body;
  Handshake(this.msgType, this.body);
  @override String toString() => 'Handshake(type: $msgType, body: $body)';
}

// #############################################################################
// ## SECTION 3: PARSER LOGIC
// #############################################################################

List<Extension> _parseExtensions(Buffer buffer) {
  final extensions = <Extension>[];
  if (buffer.eof) return extensions;
  final totalExtLen = buffer.pullUint16();
  final extEndOffset = buffer._readOffset + totalExtLen;
  while(buffer._readOffset < extEndOffset) {
    final extType = buffer.pullUint16();
    final extData = buffer.pullVector(2);
    extensions.add(Extension(extType, extData));
  }
  return extensions;
}

ClientHello _parseClientHello(Buffer buffer) {
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  final legacySessionId = buffer.pullVector(1);
  final cipherSuitesBytes = buffer.pullVector(2);
  buffer.pullVector(1); // Skip legacy_compression_methods
  final extensions = _parseExtensions(buffer);
  final cipherSuites = <int>[];
  for (var i = 0; i < cipherSuitesBytes.length; i += 2) {
    cipherSuites.add(ByteData.view(cipherSuitesBytes.buffer, cipherSuitesBytes.offsetInBytes + i, 2).getUint16(0));
  }
  return ClientHello(random: random, legacySessionId: legacySessionId, cipherSuites: cipherSuites, extensions: extensions);
}

ServerHello _parseServerHello(Buffer buffer) {
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  final legacySessionIdEcho = buffer.pullVector(1);
  final cipherSuite = buffer.pullUint16();
  buffer.pullUint8(); // Skip legacy_compression_method
  final extensions = _parseExtensions(buffer);
  return ServerHello(random: random, legacySessionIdEcho: legacySessionIdEcho, cipherSuite: cipherSuite, extensions: extensions);
}

EncryptedExtensions _parseEncryptedExtensions(Buffer buffer) {
  return EncryptedExtensions(extensions: _parseExtensions(buffer));
}

Certificate _parseCertificate(Buffer buffer) {
  final context = buffer.pullVector(1);
  final certListBytes = buffer.pullVector(3);
  final certListBuffer = Buffer(data: certListBytes);
  final certs = <CertificateEntry>[];
  while(!certListBuffer.eof) {
    final certData = certListBuffer.pullVector(3);
    final extensions = _parseExtensions(certListBuffer);
    certs.add(CertificateEntry(certData, extensions));
  }
  return Certificate(certificateRequestContext: context, certificateList: certs);
}

CertificateVerify _parseCertificateVerify(Buffer buffer) {
  final alg = buffer.pullUint16();
  final sig = buffer.pullVector(2);
  return CertificateVerify(alg, sig);
}

Finished _parseFinished(Buffer buffer, int len) {
  return Finished(buffer.pullBytes(len));
}

Handshake parseHandshakeMessage(Buffer buffer) {
  final msgType = buffer.pullUint8();
  final length = buffer.pullUint24();
  dynamic body;
  switch (msgType) {
    case 1: body = _parseClientHello(buffer); break;
    case 2: body = _parseServerHello(buffer); break;
    case 8: body = _parseEncryptedExtensions(buffer); break;
    case 11: body = _parseCertificate(buffer); break;
    case 15: body = _parseCertificateVerify(buffer); break;
    case 20: body = _parseFinished(buffer, length); break;
    default: throw UnimplementedError('Parser for message type $msgType not implemented.');
  }
  return Handshake(msgType, body);
}

// #############################################################################
// ## SECTION 4: BUILDER LOGIC
// #############################################################################

Uint8List _buildExtensions(List<Extension> extensions) {
  final extBuilder = BytesBuilder();
  for (final ext in extensions) {
    extBuilder.add((ByteData(2)..setUint16(0, ext.type)).buffer.asUint8List());
    extBuilder.add((ByteData(2)..setUint16(0, ext.data.length)).buffer.asUint8List());
    extBuilder.add(ext.data);
  }
  final allExtBytes = extBuilder.toBytes();
  return (BytesBuilder()..add((ByteData(2)..setUint16(0, allExtBytes.length)).buffer.asUint8List())..add(allExtBytes)).toBytes();
}

Uint8List _buildClientHello(ClientHello msg) {
  final csBytes = Uint8List(msg.cipherSuites.length * 2);
  for(var i = 0; i < msg.cipherSuites.length; i++) { ByteData.view(csBytes.buffer).setUint16(i * 2, msg.cipherSuites[i]); }
  return (BytesBuilder()
    ..add((ByteData(2)..setUint16(0, 0x0303)).buffer.asUint8List())..add(msg.random)
    ..addByte(msg.legacySessionId.length)..add(msg.legacySessionId)
    ..add((ByteData(2)..setUint16(0, csBytes.length)).buffer.asUint8List())..add(csBytes)
    ..addByte(1)..addByte(0) // Compression
    ..add(_buildExtensions(msg.extensions))
  ).toBytes();
}

Uint8List _buildServerHello(ServerHello msg) {
    return (BytesBuilder()
    ..add((ByteData(2)..setUint16(0, 0x0303)).buffer.asUint8List())..add(msg.random)
    ..addByte(msg.legacySessionIdEcho.length)..add(msg.legacySessionIdEcho)
    ..add((ByteData(2)..setUint16(0, msg.cipherSuite)).buffer.asUint8List())
    ..addByte(0) // Compression
    ..add(_buildExtensions(msg.extensions))
  ).toBytes();
}

Uint8List _buildEncryptedExtensions(EncryptedExtensions msg) {
  return _buildExtensions(msg.extensions);
}

Uint8List _buildCertificate(Certificate msg) {
  final certListBuilder = BytesBuilder();
  for (final entry in msg.certificateList) {
    final certDataBytes = entry.certData;
    certListBuilder.add((ByteData(4)..setUint32(0, certDataBytes.length)).buffer.asUint8List().sublist(1, 4)); // uint24
    certListBuilder.add(certDataBytes);
    certListBuilder.add(_buildExtensions(entry.extensions));
  }
  final certListBytes = certListBuilder.toBytes();
  return (BytesBuilder()
    ..addByte(msg.certificateRequestContext.length)..add(msg.certificateRequestContext)
    ..add((ByteData(4)..setUint32(0, certListBytes.length)).buffer.asUint8List().sublist(1, 4)) // uint24
    ..add(certListBytes)
  ).toBytes();
}

Uint8List _buildCertificateVerify(CertificateVerify msg) {
  return (BytesBuilder()
    ..add((ByteData(2)..setUint16(0, msg.algorithm)).buffer.asUint8List())
    ..add((ByteData(2)..setUint16(0, msg.signature.length)).buffer.asUint8List())..add(msg.signature)
  ).toBytes();
}

Uint8List _buildFinished(Finished msg) {
  return msg.verifyData;
}

Uint8List buildHandshakeMessage(Handshake message) {
  Uint8List bodyBytes;
  switch (message.msgType) {
    case 1: bodyBytes = _buildClientHello(message.body); break;
    case 2: bodyBytes = _buildServerHello(message.body); break;
    case 8: bodyBytes = _buildEncryptedExtensions(message.body); break;
    case 11: bodyBytes = _buildCertificate(message.body); break;
    case 15: bodyBytes = _buildCertificateVerify(message.body); break;
    case 20: bodyBytes = _buildFinished(message.body); break;
    default: throw UnimplementedError('Builder for message type ${message.msgType} not implemented.');
  }
  return (BytesBuilder()
    ..addByte(message.msgType)
    ..add((ByteData(4)..setUint32(0, bodyBytes.length)).buffer.asUint8List().sublist(1, 4)) // uint24 length
    ..add(bodyBytes)
  ).toBytes();
}

// #############################################################################
// ## SECTION 5: DEMONSTRATION
// #############################################################################

void main() {
  final messagesToTest = [
    Handshake(1, ClientHello(
      random: Uint8List.fromList(List.generate(32, (i) => 1)),
      legacySessionId: Uint8List(0),
      cipherSuites: [0x1301, 0x1302],
      extensions: [Extension(43, Uint8List.fromList([0x02, 0x03, 0x04]))],
    )),
    Handshake(2, ServerHello(
      random: Uint8List.fromList(List.generate(32, (i) => 2)),
      legacySessionIdEcho: Uint8List(0),
      cipherSuite: 0x1301,
      extensions: [Extension(43, Uint8List.fromList([0x03, 0x04]))],
    )),
    Handshake(8, EncryptedExtensions(
      extensions: [Extension(0, Uint8List.fromList(utf8.encode('example.com')))],
    )),
    Handshake(11, Certificate(
      certificateRequestContext: Uint8List(0),
      certificateList: [
        CertificateEntry(Uint8List.fromList([1,2,3]), [Extension(18, Uint8List.fromList([4,5,6]))]),
        CertificateEntry(Uint8List.fromList([7,8,9]), []),
      ],
    )),
    Handshake(15, CertificateVerify(
      0x0804, // rsa_pss_rsae_sha256
      Uint8List.fromList(List.generate(256, (i) => 3)),
    )),
    Handshake(20, Finished(
      Uint8List.fromList(List.generate(32, (i) => 4)), // SHA-256 HMAC size
    )),
  ];

  for (final originalMessage in messagesToTest) {
    print('--- Testing Message Type ${originalMessage.msgType} ---');
    print('Original Object: $originalMessage');
    
    // Build
    final rawBytes = buildHandshakeMessage(originalMessage);
    print('✅ Built ${rawBytes.length} bytes: ${HEX.encode(rawBytes.sublist(0, 16))}...');
    
    // Parse
    final parsedMessage = parseHandshakeMessage(Buffer(data: rawBytes));
    print('✅ Parsed Object: $parsedMessage');
    print('');
  }
}