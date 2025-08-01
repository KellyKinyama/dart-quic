// ignore_for_file: unused_import
import 'dart:typed_data';

import 'package:test/test.dart';

// Helper classes to mock the Python exceptions
class BufferReadError extends Error {}

class BufferWriteError extends Error {}

// size_uint_var function from aioquic.buffer
int sizeUintVar(int value) {
  if (value < 0x40) {
    return 1;
  } else if (value < 0x4000) {
    return 2;
  } else if (value < 0x40000000) {
    return 4;
  } else if (value < 0x4000000000000000) {
    return 8;
  }
  throw ArgumentError('Integer is too big for a variable-length integer');
}

// Mock Buffer class from aioquic.buffer
class Buffer {
  Uint8List data;
  int _tell = 0;

  Buffer({Uint8List? data, int? capacity})
    : data = data ?? (capacity != null ? Uint8List(0) : Uint8List(0));

  Uint8List dataSlice(int start, int end) {
    if (start < 0 || end > data.length || start > end) {
      throw BufferReadError();
    }
    return data.sublist(start, end);
  }

  Uint8List pullBytes(int length) {
    if (length < 0 || _tell + length > data.length) {
      throw BufferReadError();
    }
    final result = data.sublist(_tell, _tell + length);
    _tell += length;
    return result;
  }

  int pullUint8() {
    if (_tell + 1 > data.length) {
      throw BufferReadError();
    }
    return data[_tell++];
  }

  int pullUint16() {
    if (_tell + 2 > data.length) {
      throw BufferReadError();
    }
    final result = (data[_tell] << 8) | data[_tell + 1];
    _tell += 2;
    return result;
  }

  int pullUint32() {
    if (_tell + 4 > data.length) {
      throw BufferReadError();
    }
    final result =
        (data[_tell] << 24) |
        (data[_tell + 1] << 16) |
        (data[_tell + 2] << 8) |
        data[_tell + 3];
    _tell += 4;
    return result;
  }

  int pullUint64() {
    if (_tell + 8 > data.length) {
      throw BufferReadError();
    }
    final result =
        (data[_tell] << 56) |
        (data[_tell + 1] << 48) |
        (data[_tell + 2] << 40) |
        (data[_tell + 3] << 32) |
        (data[_tell + 4] << 24) |
        (data[_tell + 5] << 16) |
        (data[_tell + 6] << 8) |
        data[_tell + 7];
    _tell += 8;
    return result;
  }

  int pullUintVar() {
    if (_tell >= data.length) {
      throw BufferReadError();
    }
    final leadingByte = data[_tell];
    final type = leadingByte >> 6;
    int length;
    int value;

    if (type == 0) {
      length = 1;
      value = leadingByte;
    } else if (type == 1) {
      length = 2;
      if (_tell + 1 >= data.length) throw BufferReadError();
      value = ((leadingByte & 0x3f) << 8) | data[_tell + 1];
    } else if (type == 2) {
      length = 4;
      if (_tell + 3 >= data.length) throw BufferReadError();
      value =
          ((leadingByte & 0x3f) << 24) |
          (data[_tell + 1] << 16) |
          (data[_tell + 2] << 8) |
          data[_tell + 3];
    } else {
      // type == 3
      length = 8;
      if (_tell + 7 >= data.length) throw BufferReadError();
      value =
          ((leadingByte & 0x3f) << 56) |
          (data[_tell + 1] << 48) |
          (data[_tell + 2] << 40) |
          (data[_tell + 3] << 32) |
          (data[_tell + 4] << 24) |
          (data[_tell + 5] << 16) |
          (data[_tell + 6] << 8) |
          data[_tell + 7];
    }
    _tell += length;
    return value;
  }

  void pushBytes(Uint8List bytes) {
    if (_tell + bytes.length > data.length) {
      throw BufferWriteError();
    }
    data.setRange(_tell, _tell + bytes.length, bytes);
    _tell += bytes.length;
  }

  void pushUint8(int value) {
    if (_tell + 1 > data.length) {
      throw BufferWriteError();
    }
    data[_tell++] = value;
  }

  void pushUint16(int value) {
    if (_tell + 2 > data.length) {
      throw BufferWriteError();
    }
    data[_tell++] = (value >> 8) & 0xff;
    data[_tell++] = value & 0xff;
  }

  void pushUint32(int value) {
    if (_tell + 4 > data.length) {
      throw BufferWriteError();
    }
    data[_tell++] = (value >> 24) & 0xff;
    data[_tell++] = (value >> 16) & 0xff;
    data[_tell++] = (value >> 8) & 0xff;
    data[_tell++] = value & 0xff;
  }

  void pushUint64(int value) {
    if (_tell + 8 > data.length) {
      throw BufferWriteError();
    }
    data[_tell++] = (value >> 56) & 0xff;
    data[_tell++] = (value >> 48) & 0xff;
    data[_tell++] = (value >> 40) & 0xff;
    data[_tell++] = (value >> 32) & 0xff;
    data[_tell++] = (value >> 24) & 0xff;
    data[_tell++] = (value >> 16) & 0xff;
    data[_tell++] = (value >> 8) & 0xff;
    data[_tell++] = value & 0xff;
  }

  void pushUintVar(int value) {
    if (value < 0x40) {
      pushUint8(value);
    } else if (value < 0x4000) {
      pushUint16(value | 0x4000);
    } else if (value < 0x40000000) {
      pushUint32(value | 0x80000000);
    } else if (value < 0x4000000000000000) {
      pushUint64(value | 0xc000000000000000);
    } else {
      throw ArgumentError('Integer is too big for a variable-length integer');
    }
  }

  int tell() => _tell;
  void seek(int offset) {
    if (offset < 0 || offset > data.length) {
      throw BufferReadError();
    }
    _tell = offset;
  }

  bool eof() => _tell >= data.length;
}

void main() {
  group('Buffer', () {
    test('test_data_slice', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.dataSlice(0, 8), Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.dataSlice(1, 3), Uint8List.fromList([7, 6]));

      expect(() => buf.dataSlice(-1, 3), throwsA(isA<BufferReadError>()));
      expect(() => buf.dataSlice(0, 9), throwsA(isA<BufferReadError>()));
      expect(() => buf.dataSlice(1, 0), throwsA(isA<BufferReadError>()));
    });

    test('test_pull_bytes', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullBytes(3), Uint8List.fromList([8, 7, 6]));
    });

    test('test_pull_bytes_negative', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(() => buf.pullBytes(-1), throwsA(isA<BufferReadError>()));
    });

    test('test_pull_bytes_truncated', () {
      final buf = Buffer(capacity: 0);
      expect(() => buf.pullBytes(2), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 0);
    });

    test('test_pull_bytes_zero', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullBytes(0), Uint8List(0));
    });

    test('test_pull_uint8', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullUint8(), 8);
      expect(buf.tell(), 1);
    });

    test('test_pull_uint8_truncated', () {
      final buf = Buffer(capacity: 0);
      expect(() => buf.pullUint8(), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 0);
    });

    test('test_pull_uint16', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullUint16(), 0x0807);
      expect(buf.tell(), 2);
    });

    test('test_pull_uint16_truncated', () {
      final buf = Buffer(capacity: 1);
      expect(() => buf.pullUint16(), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 0);
    });

    test('test_pull_uint32', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullUint32(), 0x08070605);
      expect(buf.tell(), 4);
    });

    test('test_pull_uint32_truncated', () {
      final buf = Buffer(capacity: 3);
      expect(() => buf.pullUint32(), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 0);
    });

    test('test_pull_uint64', () {
      final buf = Buffer(data: Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.pullUint64(), 0x0807060504030201);
      expect(buf.tell(), 8);
    });

    test('test_pull_uint64_truncated', () {
      final buf = Buffer(capacity: 7);
      expect(() => buf.pullUint64(), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 0);
    });

    test('test_push_bytes', () {
      final buf = Buffer(capacity: 3);
      buf.pushBytes(Uint8List.fromList([8, 7, 6]));
      expect(buf.data, Uint8List.fromList([8, 7, 6]));
      expect(buf.tell(), 3);
    });

    test('test_push_bytes_truncated', () {
      final buf = Buffer(capacity: 3);
      expect(
        () => buf.pushBytes(Uint8List.fromList([8, 7, 6, 5])),
        throwsA(isA<BufferWriteError>()),
      );
      expect(buf.tell(), 0);
    });

    test('test_push_bytes_zero', () {
      final buf = Buffer(capacity: 3);
      buf.pushBytes(Uint8List(0));
      expect(buf.data, Uint8List(3));
      expect(buf.tell(), 0);
    });

    test('test_push_uint8', () {
      final buf = Buffer(capacity: 1);
      buf.pushUint8(0x08);
      expect(buf.data, Uint8List.fromList([8]));
      expect(buf.tell(), 1);
    });

    test('test_push_uint16', () {
      final buf = Buffer(capacity: 2);
      buf.pushUint16(0x0807);
      expect(buf.data, Uint8List.fromList([8, 7]));
      expect(buf.tell(), 2);
    });

    test('test_push_uint32', () {
      final buf = Buffer(capacity: 4);
      buf.pushUint32(0x08070605);
      expect(buf.data, Uint8List.fromList([8, 7, 6, 5]));
      expect(buf.tell(), 4);
    });

    test('test_push_uint64', () {
      final buf = Buffer(capacity: 8);
      buf.pushUint64(0x0807060504030201);
      expect(buf.data, Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]));
      expect(buf.tell(), 8);
    });

    test('test_seek', () {
      final buf = Buffer(
        data: Uint8List.fromList([48, 49, 50, 51, 52, 53, 54, 55]),
      ); // "01234567"
      expect(buf.eof(), false);
      expect(buf.tell(), 0);

      buf.seek(4);
      expect(buf.eof(), false);
      expect(buf.tell(), 4);

      buf.seek(8);
      expect(buf.eof(), true);
      expect(buf.tell(), 8);

      expect(() => buf.seek(-1), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 8);
      expect(() => buf.seek(9), throwsA(isA<BufferReadError>()));
      expect(buf.tell(), 8);
    });
  });

  group('UintVarTest', () {
    void roundtrip(Uint8List data, int value) {
      var buf = Buffer(data: data);
      expect(buf.pullUintVar(), value);
      expect(buf.tell(), data.length);

      buf = Buffer(capacity: 8);
      buf.pushUintVar(value);
      expect(buf.data.sublist(0, data.length), data);
    }

    test('test_uint_var', () {
      // 1 byte
      roundtrip(Uint8List.fromList([0x00]), 0);
      roundtrip(Uint8List.fromList([0x01]), 1);
      roundtrip(Uint8List.fromList([0x25]), 37);
      roundtrip(Uint8List.fromList([0x3f]), 63);

      // 2 bytes
      roundtrip(Uint8List.fromList([0x7b, 0xbd]), 15293);
      roundtrip(Uint8List.fromList([0x7f, 0xff]), 16383);

      // 4 bytes
      roundtrip(Uint8List.fromList([0x9d, 0x7f, 0x3e, 0x7d]), 494878333);
      roundtrip(Uint8List.fromList([0xbf, 0xff, 0xff, 0xff]), 1073741823);

      // 8 bytes
      roundtrip(
        Uint8List.fromList([0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
        151288809941952652,
      );
      roundtrip(
        Uint8List.fromList([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        4611686018427387903,
      );
    });

    test('test_pull_uint_var_truncated', () {
      var buf = Buffer(capacity: 0);
      expect(() => buf.pullUintVar(), throwsA(isA<BufferReadError>()));

      buf = Buffer(data: Uint8List.fromList([0xff]));
      expect(() => buf.pullUintVar(), throwsA(isA<BufferReadError>()));
    });

    test('test_push_uint_var_too_big', () {
      final buf = Buffer(capacity: 8);
      expect(
        () => buf.pushUintVar(4611686018427387904),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('test_size_uint_var', () {
      expect(sizeUintVar(63), 1);
      expect(sizeUintVar(16383), 2);
      expect(sizeUintVar(1073741823), 4);
      expect(sizeUintVar(4611686018427387903), 8);

      expect(
        () => sizeUintVar(4611686018427387904),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
