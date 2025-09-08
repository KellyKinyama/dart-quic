import 'dart:typed_data';
import 'package:hex/hex.dart';

import 'payload_parser6.dart';

/// A simple buffer to read data sequentially from a Uint8List.
class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;

  Buffer({required Uint8List data}) : _byteData = data.buffer.asByteData();

  int pullUint8() {
    final val = _byteData.getUint8(_readOffset);
    _readOffset += 1;
    return val;
  }

  int pullVarInt() {
    final firstByte = _byteData.getUint8(_readOffset);
    final prefix = firstByte >> 6;
    final len = 1 << prefix;
    int val = firstByte & 0x3F;
    for (int i = 1; i < len; i++) {
      val = (val << 8) | _byteData.getUint8(_readOffset + i);
    }
    _readOffset += len;
    return val;
  }

  Uint8List pullBytes(int len) {
    final bytes = _byteData.buffer.asUint8List(_readOffset, len);
    _readOffset += len;
    return bytes;
  }
}

/// A data class to hold the contents of a parsed CRYPTO frame.
class CryptoFrame {
  final int offset;
  final Uint8List data;
  CryptoFrame(this.offset, this.data) {
    print(parseTlsMessages(data));
  }

  @override
  String toString() {
    return 'CryptoFrame(offset: $offset, data_length: ${data.length})';
  }
}

/// Parses the plaintext payload of a QUIC Initial packet.
void parsePayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted Payload ---');
  final buffer = Buffer(data: plaintextPayload);
  int frameCount = 0;
  int paddingCount = 0;

  while (!buffer.eof) {
    final frameType = buffer.pullVarInt();
    frameCount++;

    switch (frameType) {
      case 0x06: // CRYPTO Frame
        final offset = buffer.pullVarInt();
        final length = buffer.pullVarInt();
        final cryptoData = buffer.pullBytes(length);

        final frame = CryptoFrame(offset, cryptoData);
        print('✅ Parsed Frame $frameCount: $frame');
        print(
          '   - TLS Handshake Message (Hex): "${HEX.encode(cryptoData.sublist(0, 32))}"...',
        );
        break;

      case 0x00: // PADDING Frame
        paddingCount++;
        // The pullVarInt() already consumed the byte, so we do nothing else.
        break;

      default:
        print(
          '⚠️ Parsed Frame $frameCount: Encountered unknown frame type: 0x${frameType.toRadixString(16)}',
        );
        // In a real implementation, you might throw an error here.
        return;
    }
  }

  if (paddingCount > 0) {
    print(
      '✅ Parsed Frame ${frameCount - paddingCount + 1}-${frameCount}: $paddingCount PADDING frames',
    );
  }
  print('\n🎉 Payload parsing complete.');
}

void main() {
  // This is the beginning of the decrypted payload from your successful test run.
  // It contains one CRYPTO frame followed by PADDING frames (represented by ...).

  // Create a padded version, as a real Initial payload would be
  // final paddedPayload = BytesBuilder()
  //   ..add(decryptedPayload)
  //   ..add(Uint8List(920)); // Add some padding bytes

  // parsePayload(paddedPayload.toBytes());
  parsePayload(plainText);
}

final decryptedPayload = HEX.decode(
  '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
  '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
  '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
  '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
  'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
  '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
  '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
  '75300901100f088394c8f03e51570806048000ffff',
);

final plainText = Uint8List.fromList([
  6,
  0,
  64,
  238,
  1,
  0,
  0,
  234,
  3,
  3,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  0,
  6,
  19,
  1,
  19,
  2,
  19,
  3,
  1,
  0,
  0,
  187,
  0,
  0,
  0,
  24,
  0,
  22,
  0,
  0,
  19,
  101,
  120,
  97,
  109,
  112,
  108,
  101,
  46,
  117,
  108,
  102,
  104,
  101,
  105,
  109,
  46,
  110,
  101,
  116,
  0,
  10,
  0,
  8,
  0,
  6,
  0,
  29,
  0,
  23,
  0,
  24,
  0,
  16,
  0,
  11,
  0,
  9,
  8,
  112,
  105,
  110,
  103,
  47,
  49,
  46,
  48,
  0,
  13,
  0,
  20,
  0,
  18,
  4,
  3,
  8,
  4,
  4,
  1,
  5,
  3,
  8,
  5,
  5,
  1,
  8,
  6,
  6,
  1,
  2,
  1,
  0,
  51,
  0,
  38,
  0,
  36,
  0,
  29,
  0,
  32,
  53,
  128,
  114,
  214,
  54,
  88,
  128,
  209,
  174,
  234,
  50,
  154,
  223,
  145,
  33,
  56,
  56,
  81,
  237,
  33,
  162,
  142,
  59,
  117,
  233,
  101,
  208,
  210,
  205,
  22,
  98,
  84,
  0,
  45,
  0,
  2,
  1,
  1,
  0,
  43,
  0,
  3,
  2,
  3,
  4,
  0,
  57,
  0,
  49,
  3,
  4,
  128,
  0,
  255,
  247,
  4,
  4,
  128,
  160,
  0,
  0,
  5,
  4,
  128,
  16,
  0,
  0,
  6,
  4,
  128,
  16,
  0,
  0,
  7,
  4,
  128,
  16,
  0,
  0,
  8,
  1,
  10,
  9,
  1,
  10,
  10,
  1,
  3,
  11,
  1,
  25,
  15,
  5,
  99,
  95,
  99,
  105,
  100,
]);
