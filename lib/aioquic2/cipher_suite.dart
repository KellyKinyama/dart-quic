// Filename: cipher_suite.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart'; // For printing hex strings

const aeadNonceLength = 12;

class XorNonceAead {
  final Cipher _cipher;
  final SecretKeyData _secretKey;
  final Uint8List _nonceMask;

  XorNonceAead(this._cipher, this._secretKey, List<int> iv)
    : _nonceMask = Uint8List.fromList(iv);

  Future<Uint8List> seal(
    Uint8List plaintext,
    Uint8List nonce,
    Uint8List additionalData,
  ) async {
    final xoredNonce = _xorNonce(nonce, '[DEBUG ENCRYPT]');
    final secretBox = await _cipher.encrypt(
      plaintext,
      secretKey: _secretKey,
      nonce: xoredNonce,
      aad: additionalData,
    );
    return Uint8List.fromList([
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  Future<Uint8List> open(
    Uint8List ciphertextAndMac,
    Uint8List nonce,
    Uint8List additionalData,
  ) async {
    final overhead = 16;
    final ciphertext = ciphertextAndMac.sublist(
      0,
      ciphertextAndMac.length - overhead,
    );
    final mac = Mac(
      ciphertextAndMac.sublist(ciphertextAndMac.length - overhead),
    );

    final xoredNonce = _xorNonce(nonce, '[DEBUG DECRYPT]');
    final secretBoxWithNonce = SecretBox(
      ciphertext,
      nonce: xoredNonce,
      mac: mac,
    );

    final decrypted = await _cipher.decrypt(
      secretBoxWithNonce,
      secretKey: _secretKey,
      aad: additionalData,
    );
    return Uint8List.fromList(decrypted);
  }

  Uint8List _xorNonce(List<int> packetNumberNonce, String context) {
    final tempNonce = Uint8List.fromList(_nonceMask);
    for (int i = 0; i < 8; i++) {
      tempNonce[4 + i] ^= packetNumberNonce[i];
    }
    print('$context Nonce       : ${HEX.encode(tempNonce)}');
    return tempNonce;
  }
}

class CipherSuite {
  final int id;
  final HashAlgorithm hash;
  final int keyLen;
  final Cipher Function() aeadFactory;

  CipherSuite({
    required this.id,
    required this.hash,
    required this.keyLen,
    required this.aeadFactory,
  });

  int get ivLen => aeadNonceLength;

  static final Map<int, CipherSuite> _suites = {
    0x1301: CipherSuite(
      id: 0x1301,
      hash: Sha256(),
      keyLen: 16,
      aeadFactory: () => AesGcm.with128bits(),
    ),
    0x1303: CipherSuite(
      id: 0x1303,
      hash: Sha256(),
      keyLen: 32,
      aeadFactory: () => Chacha20.poly1305Aead(),
    ),
    0x1302: CipherSuite(
      id: 0x1302,
      hash: Sha384(),
      keyLen: 32,
      aeadFactory: () => AesGcm.with256bits(),
    ),
  };

  static CipherSuite getById(int id) {
    final suite = _suites[id];
    if (suite == null) throw ArgumentError('Unknown cipher suite: $id');
    return suite;
  }
}
