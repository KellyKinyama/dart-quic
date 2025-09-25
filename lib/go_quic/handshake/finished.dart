import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../buffer.dart';
import 'handshake.dart';

class Finished extends TlsHandshakeMessage {
  final Uint8List verifyData;
  Finished(this.verifyData) : super(20);
  @override
  String toString() => 'Finished(verify_data: ${HEX.encode(verifyData)})';

  // In class Finished

  Uint8List toBytes() {
    // The Finished message body is just the verifyData itself.
    return verifyData;
  }

  Uint8List build_finished(List<int> verify_data) {
    var length = verify_data.length;
    var header = [
      0x14,
      (length >> 16) & 0xff,
      (length >> 8) & 0xff,
      length & 0xff,
    ];
    return Uint8List.fromList([...header, ...verify_data]);
  }
}

void main() {
  final buffer = Buffer(data: recData);
  final msgType = buffer.pullUint8();
  final length = buffer.pullUint24();
  final messageBody = buffer.pullBytes(length);
  final finished = Finished(messageBody);
  print("Finished: $finished");
}

final recData = Uint8List.fromList([
  0x14,
  0x00,
  0x00,
  0x20,
  0x9b,
  0x9b,
  0x14,
  0x1d,
  0x90,
  0x63,
  0x37,
  0xfb,
  0xd2,
  0xcb,
  0xdc,
  0xe7,
  0x1d,
  0xf4,
  0xde,
  0xda,
  0x4a,
  0xb4,
  0x2c,
  0x30,
  0x95,
  0x72,
  0xcb,
  0x7f,
  0xff,
  0xee,
  0x54,
  0x54,
  0xb7,
  0x8f,
  0x07,
  0x18,
]);
