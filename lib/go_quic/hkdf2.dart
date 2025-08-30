import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

/// A spec-compliant HKDF-Extract function using PointyCastle.
Uint8List hkdfExtract(Uint8List ikm, {required Uint8List salt}) {
  final hmac = HMac(SHA256Digest(), 64)..init(KeyParameter(salt));
  return hmac.process(ikm);
}

/// A spec-compliant HKDF-Expand function using PointyCastle.
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int outputLength) {
  final hkdf = HKDFKeyDerivator(SHA256Digest());
  hkdf.init(HkdfParameters(prk, outputLength, info));
  final out = Uint8List(outputLength);
  hkdf.deriveKey(null, 0, out, 0);
  return out;
}

/// The standard hkdfExpandLabel function which now relies on the correct hkdfExpand.
Uint8List hkdfExpandLabel(
  Uint8List secret, // This is the Pseudo-Random Key (PRK)
  Uint8List context,
  String label,
  int length,
) {
  final labelBytes = utf8.encode('tls13 $label');

  final hkdfLabel = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xff)
    ..addByte(labelBytes.length)
    ..add(labelBytes)
    ..addByte(context.length)
    ..add(context);

  return hkdfExpand(secret, hkdfLabel.toBytes(), length);
}
