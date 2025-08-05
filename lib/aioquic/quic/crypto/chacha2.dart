//
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'crypto_pair2.dart';
import '../packet.dart';

class ChachaCipher extends AEAD {
  final algorithm = Chacha20.poly1305Aead();
  Uint8List secret;

  ChachaCipher(
    String aeadCipherName, {
    required this.secret,
    // required Uint8List iv,
  });

  @override
  // Future<SecretBox> encrypt(
  //   Uint8List plainText,
  //   Uint8List associatedData,
  //   Uint8List nonce,
  // ) async {
  //   final cipher = Chacha20.poly1305Aead();
  //   return cipher.encrypt(
  //     SecretBox(
  //       plainText,
  //       nonce: nonce,
  //       // associatedData: associatedData,
  //       mac: Mac(Uint8List(0)),
  //     ),
  //     secretKey: _key,aad: associatedData
  //   );
  // }
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final secretKey = SecretKey(secret);
    final secretBox = await algorithm.encrypt(
      plain,
      secretKey: secretKey,
      aad: associatedData,
      nonce: nonce,
    );

    return Uint8List.fromList(secretBox.cipherText);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List cipherText,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final cipher = Chacha20.poly1305Aead();
    final secretBox = SecretBox(
      cipherText.sublist(
        0,
        cipherText.length - Chacha20.poly1305Aead().macAlgorithm.macLength,
      ),
      nonce: nonce,
      // associatedData: associatedData,
      mac: Mac(
        cipherText.sublist(
          cipherText.length - Chacha20.poly1305Aead().macAlgorithm.macLength,
        ),
      ),
    );
    return Uint8List.fromList(
      await cipher.decrypt(
        secretBox,
        secretKey: SecretKey(secret),
        aad: associatedData,
      ),
    );
  }
}
