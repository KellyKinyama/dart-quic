// Filename: hkdf.dart
import 'dart:convert';
import 'dart:typed_data';
import 'prf.dart';

/// Implements HKDF-Expand-Label as defined in RFC 8446, section 7.1.
Uint8List hkdfExpandLabel(
  Uint8List secret, // This should be the Pseudo-Random Key (PRK)
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

  final okm = hkdfExpand(secret, hkdfLabel.toBytes(), length);

  if (okm.length != length) {
    throw Exception('QUIC: HKDF-Expand-Label failed unexpectedly');
  }
  return okm;
}
