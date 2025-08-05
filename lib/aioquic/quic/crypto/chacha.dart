import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import 'crypto_pair.dart';

class ChachaCipher extends AEAD {
  final algorithm = Chacha20.poly1305Aead();
  Uint8List secret;
  Uint8List iv;

  ChachaCipher(String aeadCipherName, {required this.secret, required this.iv});
  @override
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final secretKey = SecretKey(secret);
    final secretBox = await algorithm.encrypt(plain, secretKey: secretKey);

    return Uint8List.fromList(secretBox.cipherText);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List encrypted,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final secretKey = SecretKey(secret);
    final mac = encrypted.sublist(encrypted.length - 16);
    final secretBox = SecretBox(
      encrypted,
      nonce: [...iv, ...nonce],
      mac: Mac(mac),
    );

    print('nonce length: ${nonce.length}');
    // Decrypt
    final clearText = await algorithm.decrypt(secretBox, secretKey: secretKey);
    print('Cleartext: $clearText');
    return Uint8List.fromList(clearText);
  }
}

Future<void> main() async {
  final message = <int>[1, 2, 3];
  final algorithm = Chacha20.poly1305Aead();
  final secretKey = await algorithm.newSecretKey();

  // final secretKey = SecretKey(utf8.encode("my secret"));
  // Encrypt
  final secretBox = await algorithm.encrypt(message, secretKey: secretKey);
  print('Nonce: ${secretBox.nonce}');
  print('Ciphertext: ${secretBox.cipherText}');
  print('MAC: ${secretBox.mac.bytes}');

  // final remoteKey = Uint8List(0);

  final remoteKey = SecretKey(utf8.encode("my secret"));
  SecretBox(
    secretBox.cipherText,
    nonce: secretBox.nonce,
    mac: Mac(secretBox.mac.bytes),
  );

  // Decrypt
  final clearText = await algorithm.decrypt(secretBox, secretKey: remoteKey);
  print('Cleartext: $clearText');
}

Chacha20 Chacha20Algorithm() {
  return Chacha20.poly1305Aead();
}
