// package quicvarint

// import (
// 	"fmt"
// 	"io"
// )

// taken from the QUIC draft
// const (
// Min is the minimum value allowed for a QUIC varint.
import 'dart:typed_data';

const MIN = 0;

// Max is the maximum allowed value for a QUIC varint (2^62-1).
const MAX = maxVarInt8;

const maxVarInt1 = 63;
const maxVarInt2 = 16383;
const maxVarInt4 = 1073741823;
const maxVarInt8 = 4611686018427387903;
// )

class Buffer {
  Uint8List data;
  int postion = 0;

  ByteData bd;

  Buffer(this.data) : bd = ByteData.sublistView(data);

  int getByte() {
    final result = bd.getUint8(postion);
    postion++;
    return result;
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
}

// Read reads a number in the QUIC varint format from r.
int read(Buffer r) {
  final firstByte = r.getByte();
  // if err != nil {
  // 	return 0, err
  // }
  // the first two bits of the first byte encode the length
  final l = 1 << ((firstByte & 0xc0) >> 6);
  final b1 = firstByte & (0xff - 0xc0);
  if (l == 1) {
    return b1;
  }
  final b2 = r.getByte();
  // if err != nil {
  // 	return 0, err
  // }
  if (l == 2) {
    return (b2) + (b1) << 8;
  }
  final b3 = r.getByte();
  // if err != nil {
  // 	return 0, err
  // }
  final b4 = r.getByte();
  // if err != nil {
  // 	return 0, err
  // }
  if (l == 4) {
    return (b4) + (b3) << 8 + (b2) << 16 + (b1) << 24;
  }
  final b5 = r.getByte();
  // if err != nil {
  // 	return 0, err
  // }
  final b6 = r.getByte();

  final b7 = r.getByte();

  final b8 = r.getByte();

  return (b8) + (b7) <<
      8 + (b6) <<
      16 + (b5) <<
      24 + (b4) <<
      32 + (b3) <<
      40 + (b2) <<
      48 + (b1) <<
      56;
}

// Parse reads a number in the QUIC varint format.
// It returns the number of bytes consumed.
(int, int) parse(Uint8List b)
// (uint64 /* value */, int /* bytes consumed */, error)
{
  if (b.isEmpty) {
    throw ArgumentError("EOF");
  }
  final firstByte = b[0];
  // the first two bits of the first byte encode the length
  final l = 1 << ((firstByte & 0xc0) >> 6);
  if (b.length < l) {
    throw ArgumentError("ErrUnexpectedEOF");
  }
  final b0 = firstByte & (0xff - 0xc0);
  if (l == 1) {
    return ((b0), 1);
  }
  if (l == 2) {
    return ((b[1]) + (b0) << 8, 2);
  }
  if (l == 4) {
    return ((b[3]) + (b[2]) << 8 + (b[1]) << 16 + (b0) << 24, 4);
  }
  return (
    (b[7]) + (b[6]) <<
        8 + (b[5]) <<
        16 + (b[4]) <<
        24 + (b[3]) <<
        32 + (b[2]) <<
        40 + (b[1]) <<
        48 + (b0) <<
        56,
    8,
  );
}

// Append appends i in the QUIC varint format.
List<int> append(List<int> b, int i) {
  // List<int> b;
  if (i <= maxVarInt1) {
    b.add(i);
    return b;
  }
  if (i <= maxVarInt2) {
    b.addAll([(i >> 8) | 0x40, (i)]);
    return b;
  }
  if (i <= maxVarInt4) {
    b.addAll([(i >> 24) | 0x80, (i >> 16), (i >> 8), (i)]);
    return b;
  }
  if (i <= maxVarInt8) {
    b.addAll([
      (i >> 56) | 0xc0,
      (i >> 48),
      (i >> 40),
      (i >> 32),
      (i >> 24),
      (i >> 16),
      (i >> 8),
      (i),
    ]);
    return b;
  }
  throw Exception("$i doesn't fit into 62 bits:");
}

// AppendWithLen append i in the QUIC varint format with the desired length.
List<int> appendWithLen(List<int> b, int i, int length) {
  if (length != 1 && length != 2 && length != 4 && length != 8) {
    throw Exception("invalid varint length");
  }
  final l = len(i);
  if (l == length) {
    return append(b, i);
  }
  if (l > length) {
    throw Exception("cannot encode $i in $length bytes");
  }
  switch (length) {
    case 2:
      b = append(b, 64);
    case 4:
      b = append(b, 128);
    case 8:
      b = append(b, 192);
  }
  for (int inlen = 0; inlen < length - l - 1; inlen++) {
    b = append(b, 0);
  }
  for (int j = 0; j < l; j++) {
    b = append(b, (i >> (8 * (l - 1 - j)).toInt()));
  }
  return b;
}

// Len determines the number of bytes that will be needed to write the number i.
int len(int i) {
  if (i <= maxVarInt1) {
    return 1;
  }
  if (i <= maxVarInt2) {
    return 2;
  }
  if (i <= maxVarInt4) {
    return 4;
  }
  if (i <= maxVarInt8) {
    return 8;
  }
  // Don't use a fmt.Sprintf here to format the error message.
  // The function would then exceed the inlining budget.

  throw Exception("value doesn't fit into 62 bits: $i");
}
