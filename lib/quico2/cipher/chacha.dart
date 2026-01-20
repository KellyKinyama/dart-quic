import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/modes/gcm.dart';

import '../../fast_crypt/fastcrypt.dart';
// import '../../fast_crypt/src/core/fast_crypt.dart';

Uint8List decrypt(
  Uint8List encryptionKey,
  Uint8List ciphertextWithAuthTag,
  Uint8List nonce,
  Uint8List aead,
) {
  final crypt = FastCrypt();

  // // Decrypt the data
  List<int> decryptedBytes = crypt.decryptBytes(
    ciphertext: ciphertextWithAuthTag.sublist(
      0,
      ciphertextWithAuthTag.length - 16,
    ),
    tag: ciphertextWithAuthTag.sublist(ciphertextWithAuthTag.length - 16),
    key: encryptionKey,
    nonce: nonce,
    aad: aead,
  );

  return Uint8List.fromList(decryptedBytes);
}

Uint8List encrypt(
  Uint8List encryptionKey,
  Uint8List message,
  Uint8List nonce,
  Uint8List aead,
) {
  final crypt = FastCrypt();

  // Sample binary data
  // List<int> data = utf8.encode("Binary Data Example");

  // Encrypt the data
  EncryptedData encrypted = crypt.encryptBytes(
    message,
    key: encryptionKey,
    nonce: nonce,
    aad: aead,
  );

  print('Ciphertext: ${encrypted.ciphertext}');
  print('Tag: ${encrypted.tag}');
  print('Nonce: ${encrypted.nonce}');

  // Decrypt the data
  // List<int> decryptedBytes = crypt.decryptBytes(
  //   ciphertext: encrypted.ciphertext,
  //   tag: encrypted.tag,
  //   key: encrypted.key,
  //   nonce: encrypted.nonce,
  //   aad: aead,
  // );

  return Uint8List.fromList([...encrypted.ciphertext, ...encrypted.tag]);
}

void main() {
  // seal();
}
