// Filename: prf.dart
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// HKDF-Extract using HMAC-SHA256 as defined in RFC 5869.
/// This takes an Input Keying Material (ikm) and a salt to produce a strong
/// Pseudo-Random Key (prk).
Uint8List hkdfExtract(Uint8List ikm, {required Uint8List salt}) {
  final hmac = Hmac(sha256, salt);
  return Uint8List.fromList(hmac.convert(ikm).bytes);
}

/// HKDF-Expand using HMAC-SHA256 as defined in RFC 5869.
/// This takes a Pseudo-Random Key (prk) and expands it to the desired length.
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int outputLength) {
  final hashLength = sha256.convert([]).bytes.length;
  final builder = BytesBuilder();
  var previousBlock = Uint8List(0);
  int counter = 1;

  while (builder.length < outputLength) {
    final hmac = Hmac(sha256, prk);
    final inputBuilder = BytesBuilder();
    inputBuilder.add(previousBlock);
    inputBuilder.add(info);
    inputBuilder.addByte(counter);

    previousBlock = Uint8List.fromList(
      hmac.convert(inputBuilder.toBytes()).bytes,
    );
    builder.add(previousBlock);
    counter++;
  }

  return builder.toBytes().sublist(0, outputLength);
}
