// lib/hkdf.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// hkdfExpandLabel expands a label as defined in RFC 8446, section 7.1.
Uint8List hkdfExpandLabel(
  Digest hash,
  Uint8List secret,
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

  final prk = HKDFKeyDerivator(hash)..init(Mac('SHA-256/HMAC'), secret);
  final okm = prk.derive(hkdfLabel.toBytes(), length);

  if (okm.length != length) {
    throw Exception('quic: HKDF-Expand-Label invocation failed unexpectedly');
  }
  return okm;
}
