// Filename: cipher_suite.dart
import 'dart:typed_data';
// import 'package:pointycastle/stream/chacha20.dart' as stream_chacha20;
import 'package:cryptography/cryptography.dart';

const aeadNonceLength = 12;

// A wrapper around a Cipher instance to XOR the nonce before each operation.
class XorNonceAead {
  final Cipher _cipher;
  final Uint8List _nonceMask;

  XorNonceAead(this._cipher, Uint8List nonceMask)
    : _nonceMask = Uint8List.fromList(nonceMask) {
    if (nonceMask.length != aeadNonceLength) {
      throw ArgumentError('Invalid nonce mask length');
    }
  }

  int get nonceSize => 8; // 64-bit sequence number
  int get overhead => 16; // Standard for AES-GCM and ChaCha20-Poly1305

  Future<Uint8List> seal(
    Uint8List plaintext, {
    required Uint8List nonce,
    required Uint8List additionalData,
  }) async {
    final secretBox = await _cipher.encrypt(
      plaintext,
      secretKey: SecretKeyData([]), // Key is pre-set in the cipher instance
      nonce: _xorNonce(nonce),
      aad: additionalData,
    );
    return secretBox.concatenation();
  }

  Future<Uint8List> open(
    Uint8List ciphertext, {
    required Uint8List nonce,
    required Uint8List additionalData,
  }) async {
    final secretBox = SecretBox.fromConcatenation(
      ciphertext,
      nonceLength: 0, // The nonce is provided externally
      macLength: overhead,
    );
    return Uint8List.fromList(
      await _cipher.decrypt(
        secretBox,
        secretKey: SecretKeyData([]),
        // nonce: _xorNonce(nonce),
        aad: additionalData,
      ),
    );
  }

  List<int> _xorNonce(List<int> nonce) {
    final tempNonce = Uint8List.fromList(_nonceMask);
    for (int i = 0; i < nonce.length; i++) {
      tempNonce[4 + i] ^= nonce[i];
    }
    return tempNonce;
  }
}

class CipherSuite {
  final int id;
  final HashAlgorithm hash;
  final int keyLen;
  final Future<XorNonceAead> Function(SecretKey, Uint8List) aeadFactory;

  CipherSuite({
    required this.id,
    required this.hash,
    required this.keyLen,
    required this.aeadFactory,
  });

  int get ivLen => aeadNonceLength;

  static final Map<int, CipherSuite> _suites = {
    0x1301: CipherSuite(
      id: 0x1301, // TLS_AES_128_GCM_SHA256
      hash: Sha256(),
      keyLen: 16,
      aeadFactory: (key, nonceMask) async =>
          XorNonceAead(AesGcm.with128bits(), nonceMask),
    ),
    0x1303: CipherSuite(
      id: 0x1303, // TLS_CHACHA20_POLY1305_SHA256
      hash: Sha256(),
      keyLen: 32,
      aeadFactory: (key, nonceMask) async {
        return XorNonceAead(Chacha20.poly1305Aead(), nonceMask);
        // XorNonceAead(Chacha20.poly1305Aead().poly1305Aead(secretKey: key), nonceMask);
      },
    ),
    0x1302: CipherSuite(
      id: 0x1302, // TLS_AES_256_GCM_SHA384
      hash: Sha384(),
      keyLen: 32,
      aeadFactory: (key, nonceMask) async =>
          XorNonceAead(AesGcm.with256bits(), nonceMask),
    ),
  };

  static CipherSuite getById(int id) {
    final suite = _suites[id];
    if (suite == null) {
      throw ArgumentError('Unknown cipher suite: $id');
    }
    return suite;
  }
}

Future<void> main() async {
  final message = <int>[1, 2, 3];

  final algorithm = Chacha20.poly1305Aead();
  final algorithm2 = Chacha20.poly1305Aead();
  final secretKey = await algorithm.newSecretKey();
  final nonce = Uint16List.fromList([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

  // Encrypt
  final secretBox = await algorithm.encrypt(
    message,
    secretKey: secretKey,
    nonce: nonce,
  );
  print('Nonce: ${secretBox.nonce}');
  print('Ciphertext: ${secretBox.cipherText}');
  print('MAC: ${secretBox.mac.bytes}');

  final secretBox2 = SecretBox(
    secretBox.cipherText,
    nonce: nonce,
    mac: Mac(secretBox.mac.bytes),
  );

  // Decrypt
  final clearText = await algorithm2.decrypt(secretBox2, secretKey: secretKey);
  print('Cleartext: $clearText');
}
