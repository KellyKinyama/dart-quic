import 'dart:convert';
import 'dart:typed_data';

// ignore: depend_on_referenced_packages
import 'package:pointycastle/export.dart' as pc;

/// A robust, PointyCastle-based HKDF-Extract function.
Uint8List hkdfExtract(Uint8List ikm, {required Uint8List salt}) {
  final hmac = pc.HMac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(salt));
  return hmac.process(ikm);
}

/// A robust, PointyCastle-based HKDF-Expand function.
Uint8List hkdfExpand({
  required Uint8List prk,
  required Uint8List info,
  required int outputLength,
}) {
  final hmac = pc.HMac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(prk));
  final output = BytesBuilder();
  Uint8List t = Uint8List(0);

  for (int counter = 1; output.length < outputLength; counter++) {
    final input = BytesBuilder()
      ..add(t)
      ..add(info)
      ..addByte(counter);
    t = hmac.process(input.toBytes());
    output.add(t);
  }
  return output.toBytes().sublist(0, outputLength);
}

/// The standard hkdfExpandLabel function.
/// Uint8List hkdfExpandLabel(Uint8List secret, String label, int length) {
Uint8List hkdfExpandLabel({
  required Uint8List secret, // This is the PRK and should be used directly
  required Uint8List context,
  required String label,
  required int length,
}) {
  final labelBytes = utf8.encode('tls13 $label');
  final hkdfLabel = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xff)
    ..addByte(labelBytes.length)
    ..add(labelBytes)
    ..addByte(context.length)
    ..add(context); // Context is empty
  return hkdfExpand(
    prk: secret,
    info: hkdfLabel.toBytes(),
    outputLength: length,
  );
}
