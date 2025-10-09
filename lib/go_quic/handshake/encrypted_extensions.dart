import 'dart:typed_data';

import '../buffer.dart';
import 'extensions/extensions.dart';
import 'handshake.dart';

class EncryptedExtensions extends TlsHandshakeMessage {
  final List<Extension> extensions;
  EncryptedExtensions({required this.extensions}) : super(8);

  factory EncryptedExtensions.fromBytes(Buffer buffer) {
    // Buffer buffer = Buffer(data: buf);
    return EncryptedExtensions(
      extensions: parseExtensions(
        buffer,
        messageType: HandshakeType.encrypted_extensions.value,
      ),
    );
  }

  // In class EncryptedExtensions

  // Uint8List toBytes() {
  //   final buffer = Buffer();
  //   final extensionsBuffer = Buffer();
  //   for (final ext in extensions) {
  //     // Full implementation requires a toBytes() on each Extension subclass
  //   }
  //   buffer.pushVector(extensionsBuffer.toBytes(), 2);
  //   return buffer.toBytes();
  // }

  @override
  Uint8List toBytes() {
    // This helper function handles the entire process of serializing the list
    // of extensions into a single, length-prefixed byte block.
    return serializeExtensions(
      extensions,
      messageType: HandshakeType.encrypted_extensions.value,
    );
  }

  Uint8List buildEncryptedExtensions(List<Extension> extensions) {
    List<int> ext_bytes = [];
    for (final ext in extensions) {
      ext_bytes.addAll([(ext.type >> 8) & 0xff, ext.type & 0xff]);
      ext_bytes.addAll([(ext.data.length >> 8) & 0xff, ext.data.length & 0xff]);
      ext_bytes.addAll(ext.data);
    }
    final ext_len = ext_bytes.length;
    final ext_len_bytes = [(ext_len >> 8) & 0xff, ext_len & 0xff];
    final body = [...ext_len_bytes, ...ext_bytes];
    final hs_len = body.length;
    final header = [
      0x08,
      (hs_len >> 16) & 0xff,
      (hs_len >> 8) & 0xff,
      hs_len & 0xff,
    ];
    return Uint8List.fromList([...header, ...body]);
  }

  @override
  String toString() => 'EncryptedExtensions(extensions: $extensions)';
}

void main() {
  final buffer = Buffer(data: recv_data);
  final msgType = buffer.pullUint8();
  final length = buffer.pullUint24();
  final messageBody = buffer.pullBytes(length);
  final encryptedExtensions = EncryptedExtensions.fromBytes(
    Buffer(data: messageBody),
  );
  print("EncryptedExtensions: $encryptedExtensions");
  // Example of using the new toBytes() method to re-encode the message
  final reEncodedBody = encryptedExtensions.toBytes();
  print("\nOriginal body length: ${messageBody.length}");
  print("Re-encoded body length: ${reEncodedBody.length}");
  print(
    "Is re-encoded body identical to original? ${reEncodedBody.toString() == messageBody.toString()}",
  );
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
