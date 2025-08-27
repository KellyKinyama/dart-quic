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

/// A class for efficient reading and writing of binary data, essential for
/// parsing and building QUIC packets.
class Buffer {
  ByteData _byteData;
  int _readOffset = 0;
  int _writeOffset = 0;

  Buffer({int capacity = 0, Uint8List? data})
      : _byteData = data != null
            ? data.buffer.asByteData()
            : ByteData(capacity) {
    if (data != null) {
      _writeOffset = data.lengthInBytes;
    }
  }

  int get capacity => _byteData.lengthInBytes;
  int get length => _writeOffset;
  bool get eof => _readOffset >= _writeOffset;
  Uint8List get data => _byteData.buffer.asUint8List(0, _writeOffset);

  Uint8List dataSlice(int start, int end) {
    if (start < 0 || end > _writeOffset || start > end) {
      throw BufferReadError('Read out of bounds');
    }
    return _byteData.buffer.asUint8List(start, end - start);
  }
  
  void seek(int pos) {
      if (pos < 0 || pos > capacity) {
          throw BufferReadError('Seek out of bounds');
      }
      _readOffset = pos;
  }

  int tell() => _readOffset;

  // Reading methods
  int pullUint8() {
    if (_readOffset + 1 > _writeOffset) throw BufferReadError('Read out of bounds');
    final val = _byteData.getUint8(_readOffset);
    _readOffset += 1;
    return val;
  }

  int pullUint16() {
    if (_readOffset + 2 > _writeOffset) throw BufferReadError('Read out of bounds');
    final val = _byteData.getUint16(_readOffset, Endian.big);
    _readOffset += 2;
    return val;
  }

  int pullUint32() {
    if (_readOffset + 4 > _writeOffset) throw BufferReadError('Read out of bounds');
    final val = _byteData.getUint32(_readOffset, Endian.big);
    _readOffset += 4;
    return val;
  }

  int pullUintVar() {
    if (_readOffset >= _writeOffset) throw BufferReadError('Read out of bounds');
    final firstByte = _byteData.getUint8(_readOffset);
    final prefix = firstByte >> 6;
    switch (prefix) {
      case 0:
        _readOffset += 1;
        return firstByte & 0x3F;
      case 1:
        if (_readOffset + 2 > _writeOffset) throw BufferReadError('Read out of bounds');
        final val = _byteData.getUint16(_readOffset, Endian.big) & 0x3FFF;
         _readOffset += 2;
        return val;
      case 2:
        if (_readOffset + 4 > _writeOffset) throw BufferReadError('Read out of bounds');
        final val = _byteData.getUint32(_readOffset, Endian.big) & 0x3FFFFFFF;
         _readOffset += 4;
        return val;
      default: // 3
        if (_readOffset + 8 > _writeOffset) throw BufferReadError('Read out of bounds');
        // Dart does not have a native 64-bit integer, this will lose precision for very large numbers
        // but is sufficient for QUIC's 62-bit var-int space.
        final high = _byteData.getUint32(_readOffset, Endian.big) & 0x3FFFFFFF;
        final low = _byteData.getUint32(_readOffset + 4, Endian.big);
        _readOffset += 8;
        return (high << 32) | low;
    }
  }

  Uint8List pullBytes(int len) {
    if (_readOffset + len > _writeOffset) throw BufferReadError('Read out of bounds');
    final bytes = _byteData.buffer.asUint8List(_readOffset, len);
    _readOffset += len;
    return bytes;
  }

  // Writing methods
  void pushUint8(int val) {
    if (_writeOffset + 1 > capacity) throw BufferWriteError('Write out of bounds');
    _byteData.setUint8(_writeOffset, val);
    _writeOffset += 1;
  }
  
  void pushUint16(int val) {
    if (_writeOffset + 2 > capacity) throw BufferWriteError('Write out of bounds');
    _byteData.setUint16(_writeOffset, val, Endian.big);
    _writeOffset += 2;
  }

  void pushUint32(int val) {
    if (_writeOffset + 4 > capacity) throw BufferWriteError('Write out of bounds');
    _byteData.setUint32(_writeOffset, val, Endian.big);
    _writeOffset += 4;
  }
  
  void pushUintVar(int val) {
      if (val <= 0x3F) {
          if (_writeOffset + 1 > capacity) throw BufferWriteError('Write out of bounds');
          pushUint8(val);
      } else if (val <= 0x3FFF) {
          if (_writeOffset + 2 > capacity) throw BufferWriteError('Write out of bounds');
          pushUint16(val | 0x4000);
      } else if (val <= 0x3FFFFFFF) {
          if (_writeOffset + 4 > capacity) throw BufferWriteError('Write out of bounds');
          pushUint32(val | 0x80000000);
      } else if (val <= 0x3FFFFFFFFFFFFFFF) {
          if (_writeOffset + 8 > capacity) throw BufferWriteError('Write out of bounds');
          // Split 62-bit value into two 32-bit parts
          final high = (val >> 32) & 0x3FFFFFFF;
          final low = val & 0xFFFFFFFF;
          _byteData.setUint32(_writeOffset, high | 0xC0000000, Endian.big);
          _byteData.setUint32(_writeOffset + 4, low, Endian.big);
           _writeOffset += 8;
      } else {
          throw ArgumentError('Integer is too big for a variable-length integer');
      }
  }

  void pushBytes(List<int> bytes) {
    if (_writeOffset + bytes.length > capacity) throw BufferWriteError('Write out of bounds');
    _byteData.buffer.asUint8List().setRange(_writeOffset, _writeOffset + bytes.length, bytes);
    _writeOffset += bytes.length;
  }
}