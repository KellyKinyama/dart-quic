import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

// Custom exceptions for Buffer operations, mirroring the Python version
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

/// A simple class to simulate the functionality of the Python Buffer.
/// It provides methods for reading and writing different integer types and bytes.
class Buffer {
  late ByteData _data;
  int _position = 0;
  final bool _fixedCapacity;

  Buffer({int? capacity, Uint8List? initialData})
    : _fixedCapacity = (capacity != null) {
    if (initialData != null) {
      if (capacity != null && capacity < initialData.length) {
        throw ArgumentError(
          'Capacity must be greater than or equal to initial data length',
        );
      }
      _data = initialData.buffer.asByteData(0, capacity ?? initialData.length);
      _position = 0;
    } else {
      _data = ByteData(capacity ?? 0);
    }
  }

  bool eof() {
    return _position >= _data.lengthInBytes;
  }

  int get capacity => _data.lengthInBytes;

  int get length => _position;

  Uint8List get data => _data.buffer.asUint8List(0, length);

  int tell() {
    return _position;
  }

  void seek(int position) {
    if (position < 0 || position > capacity) {
      throw RangeError('Position out of bounds');
    }
    _position = position;
  }

  void _ensureCapacity(int bytesToWrite) {
    final requiredCapacity = _position + bytesToWrite;
    if (requiredCapacity > capacity) {
      if (_fixedCapacity) {
        throw BufferWriteError(
          'Buffer capacity exceeded. Cannot write $bytesToWrite bytes.',
        );
      }
      // Dynamically resize the buffer
      final newCapacity = max(capacity * 2, requiredCapacity);
      final newData = ByteData(newCapacity);
      if (_position > 0) {
        final currentData = _data.buffer.asUint8List(0, _position);
        newData.buffer.asUint8List().setRange(0, _position, currentData);
      }
      _data = newData;
    }
  }

  void _push(int bytesToWrite, Function(ByteData, int) writeFunc) {
    _ensureCapacity(bytesToWrite);
    writeFunc(_data, _position);
    _position += bytesToWrite;
  }

  int _pull(int bytesToRead, Function(ByteData, int) readFunc) {
    if (_position + bytesToRead > length) {
      throw BufferReadError('Not enough bytes to read');
    }
    final result = readFunc(_data, _position);
    _position += bytesToRead;
    return result;
  }

  // Integer push methods
  void pushUint8(int value) => _push(1, (b, p) => b.setUint8(p, value));
  void pushUint16(int value) =>
      _push(2, (b, p) => b.setUint16(p, value, Endian.big));
  void pushUint32(int value) =>
      _push(4, (b, p) => b.setUint32(p, value, Endian.big));
  void pushUint64(int value) =>
      _push(8, (b, p) => b.setUint64(p, value, Endian.big));

  // Integer pull methods
  int pullUint8() => _pull(1, (b, p) => b.getUint8(p));
  int pullUint16() => _pull(2, (b, p) => b.getUint16(p, Endian.big));
  int pullUint32() => _pull(4, (b, p) => b.getUint32(p, Endian.big));
  int pullUint64() => _pull(8, (b, p) => b.getUint64(p, Endian.big));

  // Bytes push/pull methods
  void pushBytes(Uint8List value) {
    _ensureCapacity(value.length);
    _data.buffer.asUint8List().setRange(
      _position,
      _position + value.length,
      value,
    );
    _position += value.length;
  }

  Uint8List toBytes() {
    return data;
  }

  Uint8List pullBytes(int length) {
    if (_position + length > this.length) {
      throw BufferReadError('Not enough bytes to read');
    }
    final result = _data.buffer.asUint8List(_position, length);
    _position += length;
    return result;
  }

  // QUIC variable-length integer methods
  void pushUintVar(int value) {
    if (value <= 0x3F) {
      _push(1, (b, p) => b.setUint8(p, value));
    } else if (value <= 0x3FFF) {
      _push(2, (b, p) => b.setUint16(p, value | 0x4000, Endian.big));
    } else if (value <= 0x3FFFFFFF) {
      _push(4, (b, p) => b.setUint32(p, value | 0x80000000, Endian.big));
    } else if (value <= 0x3FFFFFFFFFFFFFFF) {
      _push(
        8,
        (b, p) => b.setUint64(p, value | 0xC000000000000000, Endian.big),
      );
    } else {
      throw BufferWriteError(
        "Integer is too big for a variable-length integer",
      );
    }
  }

  int pullUintVar() {
    if (_position + 1 > length) {
      throw BufferReadError(
        'Not enough bytes to read the variable-length integer prefix',
      );
    }
    final firstByte = _data.getUint8(_position);
    final prefix = firstByte >> 6;
    int value;

    if (prefix == 0) {
      value = pullUint8() & 0x3F;
    } else if (prefix == 1) {
      value = pullUint16() & 0x3FFF;
    } else if (prefix == 2) {
      value = pullUint32() & 0x3FFFFFFF;
    } else {
      value = pullUint64() & 0x3FFFFFFFFFFFFFFF;
    }
    return value;
  }
}

// Global constants
const UINT_VAR_MAX = 0x3FFFFFFFFFFFFFFF;
const UINT_VAR_MAX_SIZE = 8;

/// Encode a variable-length unsigned integer.
Uint8List encodeUintVar(int value) {
  final buf = Buffer(capacity: UINT_VAR_MAX_SIZE);
  buf.pushUintVar(value);
  return buf.data;
}

/// Return the number of bytes required to encode the given value
/// as a QUIC variable-length unsigned integer.
int sizeUintVar(int value) {
  if (value < 0) {
    throw ArgumentError('Value must be a non-negative integer');
  } else if (value <= 0x3F) {
    return 1;
  } else if (value <= 0x3FFF) {
    return 2;
  } else if (value <= 0x3FFFFFFF) {
    return 4;
  } else if (value <= 0x3FFFFFFFFFFFFFFF) {
    return 8;
  } else {
    throw ArgumentError("Integer is too big for a variable-length integer");
  }
}
