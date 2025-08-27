import 'dart:convert';
import 'dart:typed_data';
import 'prf.dart';

/// hkdfExpandLabel expands a label as defined in RFC 8446, section 7.1.
/// **Correction**: Removed the redundant and incorrect `hkdfExtract` call.
/// The `secret` passed to this function is already the Pseudorandom Key (PRK).
Uint8List hkdfExpandLabel(
  Uint8List secret,
  Uint8List context,
  String label,
  int length,
) {
  final labelBytes = utf8.encode('tls13 $label');

  final hkdfLabel = BytesBuilder();
  // Encode the length
  hkdfLabel.addByte(length >> 8);
  hkdfLabel.addByte(length & 0xff);
  // Encode the label
  hkdfLabel.addByte(labelBytes.length);
  hkdfLabel.add(labelBytes);
  // Encode the context
  hkdfLabel.addByte(context.length);
  hkdfLabel.add(context);

  // The 'secret' is the PRK, so we use it directly in the expand step.
  final okm = hkdfExpand(secret, hkdfLabel.toBytes(), length);

  if (okm.length != length) {
    throw Exception('quic: HKDF-Expand-Label invocation failed unexpectedly');
  }
  return okm;
}