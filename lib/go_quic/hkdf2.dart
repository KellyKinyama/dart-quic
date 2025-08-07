// lib/hkdf.dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// hkdfExpandLabel expands a label as defined in RFC 8446, section 7.1.
Future<Uint8List> hkdfExpandLabel(
  Hmac hmacAlgorithm,
  Uint8List secret,
  Uint8List context,
  String label,
  int length,
) async {
  final labelBytes = utf8.encode('tls13 $label');

  final hkdfLabel = BytesBuilder();
  hkdfLabel.addByte(length >> 8);
  hkdfLabel.addByte(length & 0xff);
  hkdfLabel.addByte(labelBytes.length);
  hkdfLabel.add(labelBytes);
  hkdfLabel.addByte(context.length);
  hkdfLabel.add(context);

  final prk = await hmacAlgorithm.importKey(key: secret);
  final okm = await Hkdf(
    hmac: hmacAlgorithm,
    outputLength: length,
  ).expand(pseudoRandomKey: prk, info: hkdfLabel.toBytes());

  return Uint8List.fromList(okm);
}
