// Filename: buffer.dart
import 'dart:typed_data';

class BufferReadError implements Exception {
  final String message;
  BufferReadError(this.message);
  @override
  String toString() => 'BufferReadError: $message';
}

class BufferWriteError implements Exception {
  final String message;
  BufferWriteError(this.message);
  @override
  String toString() => 'BufferWriteError: $message';
}

/// An extension to add the missing setUint24 method to ByteData.
extension ByteDataWriter on ByteData {
  void setUint24(int offset, int value) {
    setUint8(offset, (value >> 16) & 0xFF);
    setUint8(offset + 1, (value >> 8) & 0xFF);
    setUint8(offset + 2, value & 0xFF);
  }
}

/// A simple buffer to read data sequentially from a Uint8List.
class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;
  int get remaining => length - _readOffset;
  ByteData get byteData => _byteData;
  int get readOffset => _readOffset;
  Uint8List get data => _byteData.buffer.asUint8List(0);

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
    if (_readOffset + len > length) {
      throw Exception('Buffer underflow at readoffset: $_readOffset');
    }
    final b = _byteData.buffer.asUint8List(
      _byteData.offsetInBytes + _readOffset,
      len,
    );
    _readOffset += len;
    return b;
  }

  Uint8List pullVector(int lenBytes) {
    int vecLen;
    if (lenBytes == 1) {
      vecLen = pullUint8();
    } else if (lenBytes == 2) {
      vecLen = pullUint16();
    } else if (lenBytes == 3) {
      vecLen = pullUint24();
    } else {
      throw ArgumentError('Vector length must be 1, 2, or 3 bytes');
    }
    return pullBytes(vecLen);
  }

  int pullVarInt() {
    final firstByte = _byteData.getUint8(_readOffset);
    final prefix = firstByte >> 6;
    final len = 1 << prefix;
    if (_readOffset + len > length) {
      throw Exception('VarInt read would overflow buffer');
    }
    int val = firstByte & 0x3F;
    for (int i = 1; i < len; i++) {
      val = (val << 8) | _byteData.getUint8(_readOffset + i);
    }
    _readOffset += len;
    return val;
  }
}
