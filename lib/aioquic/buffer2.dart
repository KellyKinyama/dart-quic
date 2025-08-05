import 'dart:typed_data';
import 'dart:math';

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

/// A buffer for reading and writing binary data, mimicking Python's Buffer class.
class Buffer {
  ByteData _byteData;
  int _readIndex = 0;
  int _writeIndex = 0;

  Buffer({int capacity = 0}) : _byteData = ByteData(capacity);

  Buffer.fromBytes(Uint8List bytes)
      : _byteData = bytes.buffer.asByteData(),
        _writeIndex = bytes.length;

  /// The total capacity of the buffer.
  int get capacity => _byteData.lengthInBytes;

  /// The underlying data as a Uint8List.
  Uint8List get data => _byteData.buffer.asUint8List(0, _writeIndex);

  /// Whether the read pointer has reached the end of the written data.
  bool eof() => _readIndex >= _writeIndex;

  /// The number of bytes remaining to be read.
  int get remaining => _writeIndex - _readIndex;

  /// The current read position.
  int tell() => _readIndex;

  void _ensureCapacity(int needed) {
    if (capacity - _writeIndex < needed) {
      final newCapacity = max(capacity * 2, _writeIndex + needed);
      final newByteData = ByteData(newCapacity);
      final newBytes = newByteData.buffer.asUint8List();
      newBytes.setRange(0, _writeIndex, data);
      _byteData = newByteData;
    }
  }

  void pullBytes(int length, Uint8List target) {
    if (remaining < length) {
      throw BufferReadError('Cannot pull $length bytes, only $remaining available');
    }
    target.setRange(0, length, _byteData.buffer.asUint8List(_readIndex, length));
    _readIndex += length;
  }
  
  Uint8List viewBytes(int length) {
     if (remaining < length) {
      throw BufferReadError('Cannot view $length bytes, only $remaining available');
    }
    return _byteData.buffer.asUint8List(_readIndex, length);
  }

  int pullUint8() {
    if (remaining < 1) throw BufferReadError('Not enough data to read a uint8');
    final val = _byteData.getUint8(_readIndex);
    _readIndex++;
    return val;
  }

  int pullUint16() {
    if (remaining < 2) throw BufferReadError('Not enough data to read a uint16');
    final val = _byteData.getUint16(_readIndex, Endian.big);
    _readIndex += 2;
    return val;
  }

  int pullUint32() {
    if (remaining < 4) throw BufferReadError('Not enough data to read a uint32');
    final val = _byteData.getUint32(_readIndex, Endian.big);
    _readIndex += 4;
    return val;
  }

  int pullUintVar() {
    final firstByte = pullUint8();
    final encoding = (firstByte & 0xC0) >> 6;
    final length = 1 << encoding;
    
    var value = firstByte & 0x3F;
    if (length > 1) {
        if(remaining < length -1) {
            throw BufferReadError('Not enough data to read var int');
        }
       for(var i = 1; i < length; i++) {
           value = (value << 8) + pullUint8();
       }
    }
    return value;
  }
  
  void pushBytes(Uint8List bytes) {
    _ensureCapacity(bytes.length);
    _byteData.buffer.asUint8List().setRange(_writeIndex, _writeIndex + bytes.length, bytes);
    _writeIndex += bytes.length;
  }

  void pushUint8(int value) {
    _ensureCapacity(1);
    _byteData.setUint8(_writeIndex, value);
    _writeIndex++;
  }

  void pushUint16(int value) {
    _ensureCapacity(2);
    _byteData.setUint16(_writeIndex, value, Endian.big);
    _writeIndex += 2;
  }

  void pushUint32(int value) {
    _ensureCapacity(4);
    _byteData.setUint32(_writeIndex, value, Endian.big);
    _writeIndex += 4;
  }

  void pushUintVar(int value) {
    if (value < 0x40) {
      pushUint8(value);
    } else if (value < 0x4000) {
      _ensureCapacity(2);
      pushUint16(0x4000 | value);
    } else if (value < 0x40000000) {
      _ensureCapacity(4);
      pushUint32(0x80000000 | value);
    } else {
      _ensureCapacity(8);
      pushUint32(0xC0000000 | (value >> 32));
      pushUint32(value & 0xFFFFFFFF);
    }
  }
}