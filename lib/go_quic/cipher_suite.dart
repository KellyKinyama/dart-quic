// lib/cipher_suite.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import 'ciphers/aes_gcm.dart';
// import 'package:pointycastle/api.dart';
// import 'package:pointycastlease_aead_cipher.dart'

const aeadNonceLength = 12;

/// A cipher suite implementation, mirroring Go's crypto/tls.
class CipherSuite {
  final int id;
  final Digest Function() hash;
  final int keyLen;
  final XorNonceAEAD Function({
    required Uint8List key,
    required Uint8List nonceMask,
  })
  aead;

  CipherSuite({
    required this.id,
    required this.hash,
    required this.keyLen,
    required this.aead,
  });

  int get ivLen => aeadNonceLength;

  @override
  String toString() {
    // TODO: implement toString
    switch (id) {
      case 0x1301:
        return "CipherSuite{ TLS_AES_128_GCM_SHA256}";
      case 0x1302:
        return "CipherSuite{ TLS_AES_256_GCM_SHA384}";
      case 0x1303:
        return "CipherSuite{ TLS_CHACHA20_POLY1305_SHA256}";
      default:
        throw Exception('unknown cipher suite: $id');
    }
  }
}

CipherSuite getCipherSuite(int id) {
  switch (id) {
    case 0x1301: // tls.TLS_AES_128_GCM_SHA256
      return CipherSuite(
        id: 0x1301,
        hash: () => SHA256Digest(),
        keyLen: 16,
        aead: aeadAESGCMTLS13,
      );
    // case 0x1302: // tls.TLS_AES_256_GCM_SHA384
    //   return CipherSuite(
    //     id: 0x1302,
    //     hash: () => SHA384Digest(),
    //     keyLen: 32,
    //     aead: aeadAESGCMTLS13,
    // );
    // case 0x1303: // tls.TLS_CHACHA20_POLY1305_SHA256
    //   return CipherSuite(
    //     id: 0x1303,
    //     hash: () => SHA256Digest(),
    //     keyLen: 32,
    //     aead: aeadChaCha20Poly1305,
    //   );
    default:
      throw Exception('unknown cipher suite: $id');
  }
}

// XorNonceAEAD aeadAESGCMTLS13({
//   required Uint8List key,
//   required Uint8List nonceMask,
// }) {
//   final aes = AESEngine();
//   aes.init(true, KeyParameter(key));
//   final aead = GCMBlockCipher(aes);
//   // aead.macSize;
//   return XorNonceAEAD(aead, key, nonceMask);
// }

// XorNonceAEAD aeadChaCha20Poly1305({
//   required Uint8List key,
//   required Uint8List nonceMask,
// }) {
//   final aead = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
//   return XorNonceAEAD(aead, key, nonceMask);
// }

XorNonceAEAD aeadAESGCMTLS13({
  required Uint8List key,
  required Uint8List nonceMask,
}) {
  final aes = AESEngine();
  final aead = GCMBlockCipher(aes);
  aead.init(
    true,
    AEADParameters(KeyParameter(key), 128, Uint8List(12), Uint8List(0)),
  );
  return XorNonceAEAD(aead, key, nonceMask); // Pass the key here
}

XorNonceAEAD aeadChaCha20Poly1305({
  required Uint8List key,
  required Uint8List nonceMask,
}) {
  final aead = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
  return XorNonceAEAD(aead, key, nonceMask); // Pass the key here
}

/// Wraps an AEAD by XORing a fixed pattern into the nonce.
class XorNonceAEAD {
  final Uint8List _nonceMask;
  final dynamic _aead;
  final Uint8List key; // Add a key field

  XorNonceAEAD(this._aead, this.key, Uint8List nonceMask)
    : _nonceMask = Uint8List.fromList(nonceMask);

  int get nonceSize => 8; // 64-bit sequence number
  int get overhead {
    if (_aead is GCMBlockCipher) {
      return (_aead as GCMBlockCipher).macSize; // ~/
      // 8; // GCMBlockCipher has macSize getter (in bits)
    } else if (_aead is ChaCha20Poly1305) {
      return 16; // Poly1305 has a fixed MAC size of 16 bytes
    }
    throw Exception('Unknown AEAD type');
  }

  // Uint8List seal(
  //   Uint8List nonce,
  //   Uint8List plaintext,
  //   Uint8List additionalData,
  // ) {
  //   final iv = _prepareNonce(nonce);
  //   _aead.init(
  //     true,
  //     AEADParameters(
  //       KeyParameter(Uint8List(0)),
  //       overhead * 8,
  //       iv,
  //       additionalData,
  //     ),
  //   );
  //   final output = Uint8List(_aead.getOutputSize(plaintext.length));
  //   final len = _aead.processBytes(plaintext, 0, plaintext.length, output, 0);
  //   _aead.doFinal(output, len);
  //   return output;
  // }

  // Uint8List open(
  //   Uint8List nonce,
  //   Uint8List ciphertext,
  //   Uint8List additionalData,
  // ) {
  //   final iv = _prepareNonce(nonce);
  //   _aead.init(
  //     false,
  //     AEADParameters(
  //       KeyParameter(Uint8List(0)),
  //       overhead * 8,
  //       iv,
  //       additionalData,
  //     ),
  //   );
  //   final output = Uint8List(_aead.getOutputSize(ciphertext.length));
  //   try {
  //     final len = _aead.processBytes(
  //       ciphertext,
  //       0,
  //       ciphertext.length,
  //       output,
  //       0,
  //     );
  //     _aead.doFinal(output, len);
  //     return output;
  //   } catch (e) {
  //     throw Exception('Failed to open AEAD');
  //   }
  // }

  Uint8List seal(
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List additionalData,
  ) {
    print("Called XorNonceAEAD: seal: nonce: $nonce");
    final iv = _prepareNonce(nonce);

    // print("Overheade: ${overhead * 8}");
    // print("encryption Key: $key");
    // _aead.init(
    //   true,

    //   // Use the correct key and macSize
    //   AEADParameters(
    //     KeyParameter(key),
    //     overhead * 8, // macSize is in bits
    //     iv,
    //     additionalData,
    //   ),
    //   // AEADParameters(KeyParameter(_key), _aead.macSize, iv, additionalData),
    // );

    return encrypt(key, plaintext, iv, additionalData);
    // final output = Uint8List(_aead.getOutputSize(plaintext.length));
    // final len = _aead.processBytes(plaintext, 0, plaintext.length, output, 0);
    // _aead.doFinal(output, len);
    // return output;
  }

  Uint8List open(
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List additionalData,
  ) {
    final iv = _prepareNonce(nonce);

    // print("decryption Key: $key");
    // _aead.init(
    //   false,
    //   // Use the correct key and macSize
    //   AEADParameters(
    //     KeyParameter(key),
    //     overhead * 8, // macSize is in bits
    //     iv,
    //     additionalData,
    //   ),
    // );

    return decrypt(key, ciphertext, iv, additionalData);
    // final output = Uint8List(_aead.getOutputSize(ciphertext.length));
    // try {
    //   final len = _aead.processBytes(
    //     ciphertext,
    //     0,
    //     ciphertext.length,
    //     output,
    //     0,
    //   );
    //   _aead.doFinal(output, len);
    //   return output;
    // } catch (e) {
    //   throw Exception('Failed to open AEAD');
    // }
  }

  Uint8List _prepareNonce(Uint8List nonce) {
    print("Called XorNonceAEAD: _prepareNonce: nonce: $nonce");
    final iv = Uint8List.fromList(_nonceMask);
    for (var i = 0; i < nonce.length; i++) {
      iv[4 + i] ^= nonce[i];
    }
    return iv;
  }
}
