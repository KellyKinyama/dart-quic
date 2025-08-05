import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:convert/convert.dart';

import '../enums.dart';
import 'crypto_pair.dart';

/// TLS 1.3 PRF using HKDF (HMAC-based Key Derivation Function)
Uint8List tls13PRF(
  Uint8List secret,
  String label,
  Uint8List seed,
  int outputLength,
) {
  Uint8List info = Uint8List.fromList(utf8.encode("tls13 $label") + seed);

  // Step 1: Extract
  Uint8List prk = hkdfExtract(secret);

  // Step 2: Expand
  return hkdfExpand(prk, info, outputLength);
}

/// HKDF-Extract using HMAC-SHA256
Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) {
  salt ??= Uint8List(32); // Default salt = 32 zero bytes
  var hmac = Hmac(sha256, salt);
  return Uint8List.fromList(hmac.convert(ikm).bytes);
}

// /// HKDF-Expand using HMAC-SHA256
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int outputLength) {
  List<int> output = [];
  Uint8List previousBlock = Uint8List(0);
  int counter = 1;

  while (output.length < outputLength) {
    var hmac = Hmac(sha256, prk);
    var data = Uint8List.fromList(previousBlock + info + [counter]);
    previousBlock = Uint8List.fromList(hmac.convert(data).bytes);

    output.addAll(previousBlock);
    counter++;
  }

  return Uint8List.fromList(output.sublist(0, outputLength));
}

Uint8List hkdf_label(Uint8List label, Uint8List hashValue, int length) {
  final fullLabel = Uint8List.fromList(utf8.encode("tls13 ") + label);
  final buffer = BytesBuilder();
  buffer.addByte((length >> 8) & 0xFF);
  buffer.addByte(length & 0xFF);
  buffer.addByte(fullLabel.length);
  buffer.add(fullLabel);
  buffer.addByte(hashValue.length);
  buffer.add(hashValue);
  return buffer.toBytes();
}

Uint8List hkdf_expand_label(
  // algorithm: hashes.HashAlgorithm,
  Uint8List secret,
  Uint8List label,
  Uint8List hash_value,
  int length,
) {
  return hkdfExpand(
    // algorithm=algorithm,
    secret,

    hkdf_label(label, hash_value, length),
    length,
  );
}

(Uint8List, Uint8List, Uint8List) derive_key_iv_hp({
  required CipherSuite cipherSuite,
  required Uint8List secret,
  required int version,
})
// -> Tuple[bytes, bytes, bytes]:
{
  int keySize;
  // algorithm = cipher_suite_hash(cipher_suite)
  if (cipherSuite == CipherSuite.AES_256_GCM_SHA384 ||
      cipherSuite == CipherSuite.CHACHA20_POLY1305_SHA256) {
    keySize = 32;
  } else {
    keySize = 16;
  }
  if (version == QuicProtocolVersion.VERSION_2.value) {
    return (
      hkdf_expand_label(
        secret,
        utf8.encode("quicv2 key"),
        utf8.encode(""),
        keySize,
      ),
      hkdf_expand_label(secret, utf8.encode("quicv2 iv"), utf8.encode(""), 12),
      hkdf_expand_label(
        secret,
        utf8.encode("quicv2 hp"),
        utf8.encode(""),
        keySize,
      ),
    );
  } else {
    //     return (
    return (
      hkdf_expand_label(
        secret,
        utf8.encode("quic key"),
        utf8.encode(""),
        keySize,
      ),
      hkdf_expand_label(secret, utf8.encode("quic iv"), utf8.encode(""), 12),
      hkdf_expand_label(
        secret,
        utf8.encode("quic hp"),
        utf8.encode(""),
        keySize,
      ),
    );
    // hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
    // hkdf_expand_label(algorithm, secret, b"quic hp", b"", key_size),
    // )
  }
}

// def hkdf_extract(
//     algorithm: hashes.HashAlgorithm, salt: bytes, key_material: bytes
// ) -> bytes:
//     h = hmac.HMAC(salt, algorithm)
//     h.update(key_material)
//     return h.finalize()

void main() {
  final clientSecret = Uint8List.fromList(
    hex.decode(
      "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    ),
  );

  // final label = utf8.encode("quic key");

  var (key, iv, hp) = derive_key_iv_hp(
    cipherSuite: INITIAL_CIPHER_SUITE,
    secret: clientSecret,
    version: 1,
  );
  print("key: ${hex.encode(key)}");
  print("iv: ${hex.encode(iv)}");
  print("hp: ${hex.encode(hp)}");

  final serverSecret = Uint8List.fromList(
    hex.decode(
      "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
    ),
  );

  // final label = utf8.encode("quic key");
  print("");
  (key, iv, hp) = derive_key_iv_hp(
    cipherSuite: INITIAL_CIPHER_SUITE,
    secret: serverSecret,
    version: 1,
  );
  print("key: ${hex.encode(key)}");
  print("iv: ${hex.encode(iv)}");
  print("hp: ${hex.encode(hp)}");
  // print(hex.encode(hkdfExpand(label, secret, outputLength)));
}
