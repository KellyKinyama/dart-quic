import 'dart:typed_data';

class DtlsRandom {
  Uint8List gmtUnixTime;
  Uint8List bytes;

  DtlsRandom({required this.gmtUnixTime, required this.bytes});

  static (DtlsRandom, int) decode(Uint8List buf, int offset) {
    final reader = ByteData.sublistView(buf);
    final gmt = buf.sublist(offset, offset + 4);
    offset += 4;
    final randBytes = buf.sublist(offset, offset + 28);
    offset += 28;
    return (DtlsRandom(gmtUnixTime: gmt, bytes: randBytes), offset);
  }

  Uint8List encode() {
    final builder = BytesBuilder();
    builder.add(gmtUnixTime);
    builder.add(bytes);
    return builder.toBytes();
  }

  // @override
  // String toString() =>
  //     'Random(gmt: ${gmtUnixTime.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, bytes: ${bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()})';

  @override
  String toString() =>
      'Random(gmt: ${gmtUnixTime.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}, bytes: $bytes)';
}