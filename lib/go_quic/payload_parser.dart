import 'dart:typed_data';
import 'package:hex/hex.dart';

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
  CryptoFrame(this.offset, this.data);

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

  // Create a padded version, as a real Initial payload would be
  final paddedPayload = BytesBuilder()
    ..add(decryptedPayload)
    ..add(Uint8List(920)); // Add some padding bytes

  parsePayload(paddedPayload.toBytes());
}
