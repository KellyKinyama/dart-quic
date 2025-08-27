// Filename: hkdf.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// HKDF expands a label as defined in RFC 8446, section 7.1.
Future<Uint8List> hkdfExpandLabel(
  HashAlgorithm hashAlgorithm,
  List<int> secret,
  List<int> context,
  String label,
  int length,
) async {
  final hkdf = Hkdf(hmac: Hmac(hashAlgorithm), outputLength: length);
  final labelBytes = Uint8List.fromList('tls13 $label'.codeUnits);

  final hkdfLabel = BytesBuilder();
  hkdfLabel.add(_uint16bytes(length));
  hkdfLabel.add([labelBytes.length]);
  hkdfLabel.add(labelBytes);
  hkdfLabel.add([context.length]);
  hkdfLabel.add(context);

  final secretKey = SecretKey(secret);
  final newSecretKey = await hkdf.deriveKey(
    secretKey: secretKey,
    info: hkdfLabel.toBytes(),
    // length: length,
  );

  return Uint8List.fromList(await newSecretKey.extractBytes());
}

Uint8List _uint16bytes(int value) {
  final bytes = ByteData(2);
  bytes.setUint16(0, value, Endian.big);
  return bytes.buffer.asUint8List();
}
