import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'protocol.dart';
// import 'package:pointycastle/src/impl/base_aead_block_cipher.dart.';
// import 'package:pointycastle/base_aead_block_cipher.dart.';

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
  aeadFactory;

  CipherSuite({
    required this.id,
    required this.hash,
    required this.keyLen,
    required this.aeadFactory,
  });

  int get ivLen => aeadNonceLength;

  @override
  String toString() {
    switch (id) {
      case 0x1301:
        return "CipherSuite{TLS_AES_128_GCM_SHA256}";
      case 0x1302:
        return "CipherSuite{TLS_AES_256_GCM_SHA384}";
      case 0x1303:
        return "CipherSuite{TLS_CHACHA20_POLY1305_SHA256}";
      default:
        return "CipherSuite{Unknown}";
    }
  }
}

/// Retrieves a CipherSuite definition by its TLS identifier.
CipherSuite getCipherSuite(int id) {
  switch (id) {
    case 0x1301: // tls.TLS_AES_128_GCM_SHA256
      return CipherSuite(
        id: 0x1301,
        hash: () => SHA256Digest(),
        keyLen: 16,
        aeadFactory: XorNonceAEAD.aesGcm,
      );
    default:
      throw Exception('Unsupported cipher suite: $id');
  }
}

/// Wraps an AEAD cipher to implement the nonce XORing required by QUIC.
class XorNonceAEAD {
  final GCMBlockCipher _aead;
  final Uint8List _key;
  final Uint8List _nonceMask;

  XorNonceAEAD(this._aead, this._key, Uint8List nonceMask)
    : _nonceMask = Uint8List.fromList(nonceMask);

  /// Factory for creating an AES-GCM AEAD cipher.
  static XorNonceAEAD aesGcm({
    required Uint8List key,
    required Uint8List nonceMask,
  }) {
    return XorNonceAEAD(GCMBlockCipher(AESEngine()), key, nonceMask);
  }

  int get overhead => _aead.macSize;

  /// **Reimplementation**: Correctly uses `pointycastle` to encrypt data.
  Uint8List seal(
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List additionalData,
  ) {
    final iv = _prepareNonce(nonce);
    final params = AEADParameters(
      KeyParameter(_key),
      overhead * 8,
      iv,
      additionalData,
    );
    _aead.init(true, params); // true for encryption
    return _aead.process(plaintext);
  }

  /// **Reimplementation**: Correctly uses `pointycastle` to decrypt data.
  Uint8List open(
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List additionalData,
  ) {
    final iv = _prepareNonce(nonce);
    final params = AEADParameters(
      KeyParameter(_key),
      overhead * 8,
      iv,
      additionalData,
    );
    _aead.init(false, params); // false for decryption
    try {
      return _aead.process(ciphertext);
      // } on InvalidCipherText {
      // Catching the specific error from pointycastle for authentication failure.
      // throw DecryptionFailedException('AEAD authentication failed.');
    } catch (e) {
      throw DecryptionFailedException('AEAD open failed: $e');
    }
  }

  /// Prepares the full nonce by XORing the packet number with the IV mask.
  Uint8List _prepareNonce(Uint8List nonce) {
    final iv = Uint8List.fromList(_nonceMask);
    // The packet number is encoded as a big-endian integer.
    // The nonce must be left-padded with zeros to match the IV length.
    final offset = iv.length - nonce.length;
    for (var i = 0; i < nonce.length; i++) {
      iv[offset + i] ^= nonce[i];
    }
    return iv;
  }
}
