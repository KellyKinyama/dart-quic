// lib/cipher_suite.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

const aeadNonceLength = 12;

/// A cipher suite implementation, mirroring Go's crypto/tls.
class CipherSuite {
  final int id;
  final Digest Function() hash;
  final int keyLen;
  final XorNonceAEAD Function(Uint8List key, Uint8List nonceMask) aead;

  CipherSuite({
    required this.id,
    required this.hash,
    required this.keyLen,
    required this.aead,
  });

  int get ivLen => aeadNonceLength;
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
    case 0x1302: // tls.TLS_AES_256_GCM_SHA384
      return CipherSuite(
        id: 0x1302,
        hash: () => SHA384Digest(),
        keyLen: 32,
        aead: aeadAESGCMTLS13,
      );
    case 0x1303: // tls.TLS_CHACHA20_POLY1305_SHA256
      return CipherSuite(
        id: 0x1303,
        hash: () => SHA256Digest(),
        keyLen: 32,
        aead: aeadChaCha20Poly1305,
      );
    default:
      throw Exception('unknown cipher suite: $id');
  }
}

XorNonceAEAD aeadAESGCMTLS13(Uint8List key, Uint8List nonceMask) {
  final aes = AESEngine();
  final aead = GCMBlockCipher(aes);
  return XorNonceAEAD(aead, nonceMask);
}

XorNonceAEAD aeadChaCha20Poly1305(Uint8List key, Uint8List nonceMask) {
  final aead = ChaCha20Poly1305(key: key);
  return XorNonceAEAD(aead, nonceMask);
}

/// Wraps an AEAD by XORing a fixed pattern into the nonce.
class XorNonceAEAD {
  final Uint8List _nonceMask;
  final AEADCipher _aead;

  XorNonceAEAD(this._aead, Uint8List nonceMask)
      : _nonceMask = Uint8List.fromList(nonceMask);

  int get nonceSize => 8; // 64-bit sequence number
  int get overhead => _aead.macSize;

  Uint8List seal(Uint8List nonce, Uint8List plaintext, Uint8List additionalData) {
    final iv = _prepareNonce(nonce);
    _aead.init(true, AEADParameters(KeyParameter(Uint8List(0)), overhead * 8, iv, additionalData));
    final output = Uint8List(_aead.getOutputSize(plaintext.length));
    final len = _aead.processBytes(plaintext, 0, plaintext.length, output, 0);
    _aead.doFinal(output, len);
    return output;
  }

  Uint8List open(Uint8List nonce, Uint8List ciphertext, Uint8List additionalData) {
    final iv = _prepareNonce(nonce);
    _aead.init(false, AEADParameters(KeyParameter(Uint8List(0)), overhead * 8, iv, additionalData));
    final output = Uint8List(_aead.getOutputSize(ciphertext.length));
    try {
      final len = _aead.processBytes(ciphertext, 0, ciphertext.length, output, 0);
      _aead.doFinal(output, len);
      return output;
    } catch (e) {
      throw Exception('Failed to open AEAD');
    }
  }

  Uint8List _prepareNonce(Uint8List nonce) {
    final iv = Uint8List.fromList(_nonceMask);
    for (var i = 0; i < nonce.length; i++) {
      iv[4 + i] ^= nonce[i];
    }
    return iv;
  }
}