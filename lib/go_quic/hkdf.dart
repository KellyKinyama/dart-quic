// lib/hkdf.dart
import 'dart:convert';
import 'dart:typed_data';

// import 'package:pointycastle/export.dart';

import 'prf.dart';

/// hkdfExpandLabel expands a label as defined in RFC 8446, section 7.1.
// Uint8List hkdfExpandLabel(
//   // Digest hash,
//   Uint8List secret,
//   Uint8List context,
//   String label,
//   int length,
// ) {
//   final labelBytes = utf8.encode('tls13 $label');

//   final hkdfLabel = BytesBuilder();
//   hkdfLabel.addByte(length >> 8);
//   hkdfLabel.addByte(length & 0xff);
//   hkdfLabel.addByte(labelBytes.length);
//   hkdfLabel.add(labelBytes);
//   hkdfLabel.addByte(context.length);
//   hkdfLabel.add(context);

//   final prk = hkdfExtract(secret);
//   final okm = hkdfExpand(prk, hkdfLabel.toBytes(), length);

//   if (okm.length != length) {
//     throw Exception('quic: HKDF-Expand-Label invocation failed unexpectedly');
//   }
//   return okm;
// }

Uint8List hkdfExpandLabel(
  Uint8List secret, // This is the PRK and should be used directly
  Uint8List context,
  String label,
  int length,
) {
  final labelBytes = utf8.encode('tls13 $label');

  final hkdfLabel = BytesBuilder();
  hkdfLabel.addByte(length >> 8);
  hkdfLabel.addByte(length & 0xff);
  hkdfLabel.addByte(labelBytes.length);
  hkdfLabel.add(labelBytes);
  hkdfLabel.addByte(context.length);
  hkdfLabel.add(context);

  // INCORRECT LINE TO REMOVE:
  // final prk = hkdfExtract(secret);

  // CORRECTED: Use the 'secret' parameter directly in hkdfExpand.
  final okm = hkdfExpand(secret, hkdfLabel.toBytes(), length);

  if (okm.length != length) {
    throw Exception('quic: HKDF-Expand-Label invocation failed unexpectedly');
  }
  return okm;
}
