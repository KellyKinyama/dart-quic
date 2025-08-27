// Filename: test/buffer_test.dart
import 'dart:typed_data';
import 'package:test/test.dart';
import '../buffer.dart'; // Adjust import path as needed

void main() {
  group('BufferTest', () {
    test('pull bytes and tell', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullBytes(3), equals(Uint8List.fromList([8, 7, 6])));
      expect(buf.tell(), equals(3));
    });

    test('pull uint8', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7]));
      expect(buf.pullUint8(), equals(8));
      expect(buf.tell(), equals(1));
    });

    test('pull uint16', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7]));
      expect(buf.pullUint16(), equals(0x0807));
      expect(buf.tell(), equals(2));
    });

    test('pull uint32', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5]));
      expect(buf.pullUint32(), equals(0x08070605));
      expect(buf.tell(), equals(4));
    });

    test('push uint8', () {
      final buf = Buffer(capacity: 1);
      buf.pushUint8(8);
      expect(buf.data, equals(Uint8List.fromList([8])));
    });

    test('push uint16', () {
      final buf = Buffer(capacity: 2);
      buf.pushUint16(0x0807);
      expect(buf.data, equals(Uint8List.fromList([8, 7])));
    });

    test('read out of bounds', () {
      final buf = Buffer(capacity: 1);
      buf.pushUint8(1);
      expect(() => buf.pullUint16(), throwsA(isA<BufferReadError>()));
    });

    test('seek and eof', () {
      final buf = Buffer(data: Uint8List.fromList([1, 2, 3, 4]));
      expect(buf.eof, isFalse);
      buf.seek(4);
      expect(buf.eof, isTrue);
    });
  });

  group('UintVarTest', () {
    void roundtrip(Uint8List data, int value) {
      final readBuf = Buffer(data: data);
      expect(readBuf.pullUintVar(), equals(value));
      expect(readBuf.tell(), equals(data.length));

      final writeBuf = Buffer(capacity: 8);
      writeBuf.pushUintVar(value);
      expect(writeBuf.data, equals(data));
    }

    test('roundtrip var ints', () {
      // 1 byte
      roundtrip(Uint8List.fromList([0x00]), 0);
      roundtrip(Uint8List.fromList([0x25]), 37);

      // 2 bytes
      roundtrip(Uint8List.fromList([0x7b, 0xbd]), 15293);

      // 4 bytes
      roundtrip(Uint8List.fromList([0x9d, 0x7f, 0x3e, 0x7d]), 494878333);
    });
  });
}
