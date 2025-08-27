import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// TLS 1.3 PRF using HKDF (HMAC-based Key Derivation Function)
Uint8List tls13PRF(
  Uint8List secret,
  String label,
  Uint8List seed,
  int outputLength,
) {
  Uint8List info = Uint8List.fromList(utf8.encode(label) + seed);

  // Step 1: Extract
  Uint8List prk = hkdfExtract(secret);

  // Step 2: Expand
  return hkdfExpand(prk, info, outputLength);
}

/// HKDF-Extract using HMAC-SHA256
Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) {
  salt ??= Uint8List(sha256.blockSize); // Default salt = a block size of zeros
  var hmac = Hmac(sha256, salt);
  return Uint8List.fromList(hmac.convert(ikm).bytes);
}

/// HKDF-Expand using HMAC-SHA256
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int outputLength) {
  List<int> output = [];
  Uint8List previousBlock = Uint8List(0);
  int counter = 1;

  while (output.length < outputLength) {
    var hmac = Hmac(sha256, prk);
    var data = Uint8List.fromList([...previousBlock, ...info, counter]);
    previousBlock = Uint8List.fromList(hmac.convert(data).bytes);

    output.addAll(previousBlock);
    counter++;
  }

  return Uint8List.fromList(output.sublist(0, outputLength));
}
