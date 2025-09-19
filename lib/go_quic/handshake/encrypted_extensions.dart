import 'dart:typed_data';

import '../buffer.dart';
import 'extensions/extensions.dart';
import 'handshake.dart';

class EncryptedExtensions extends TlsHandshakeMessage {
  final List<Extension> extensions;
  EncryptedExtensions({required this.extensions}) : super(8);

  factory EncryptedExtensions.fromBytes(Buffer buffer) {
    // Buffer buffer = Buffer(data: buf);
    return EncryptedExtensions(extensions: parseExtensions(buffer));
  }
  @override
  String toString() => 'EncryptedExtensions(extensions: $extensions)';
}

void main() {
  final buffer = Buffer(data: recv_data);
  final msgType = buffer.pullUint8();
  final length = buffer.pullUint24();
  final messageBody = buffer.pullBytes(length);
  final certificate = EncryptedExtensions.fromBytes(Buffer(data: messageBody));
  print("Certificate: $certificate");
}

final recv_data = Uint8List.fromList([
  0x08,
  0x00,
  0x00,
  0x24,
  0x00,
  0x22,
  0x00,
  0x0a,
  0x00,
  0x14,
  0x00,
  0x12,
  0x00,
  0x1d,
  0x00,
  0x17,
  0x00,
  0x18,
  0x00,
  0x19,
  0x01,
  0x00,
  0x01,
  0x01,
  0x01,
  0x02,
  0x01,
  0x03,
  0x01,
  0x04,
  0x00,
  0x1c,
  0x00,
  0x02,
  0x40,
  0x01,
  0x00,
  0x00,
  0x00,
  0x00,
]);
