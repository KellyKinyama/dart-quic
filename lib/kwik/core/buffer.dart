import 'dart:typed_data';

class Buffer {
  Uint8List data;
  int postion = 0;
  int length;

  ByteData bd;

  Buffer(this.data) : bd = ByteData.sublistView(data), length = data.length;

  factory Buffer.allocate(int length) {
    return Buffer(Uint8List(length));
  }
  int getByte() {
    final result = bd.getUint8(postion);
    postion++;
    return result;
  }

  int remaining() {
    return length - postion;
  }

  void get(Uint8List bytes, {int start = 0, int? end}) {
    bytes = data.sublist(postion, postion + bytes.length);
  }

  int position({int? currentPosition}) {
    if (currentPosition != null) {
      postion = currentPosition;
    }
    return postion;
  }

  int getUint16() {
    final result = bd.getUint16(postion);
    postion += 2;
    return result;
  }

  int getUint32() {
    final result = bd.getUint32(postion);
    postion += 4;
    return result;
  }

  int getUint64() {
    final result = bd.getUint64(postion);
    postion += 8;
    return result;
  }

  void putInt(int value) {
    bd.setInt32(postion, value);
      postion += 4;
  }
  void putLong(int value) {
    bd.setUint64(postion,value);
    postion += 8;
  }
}
