// lib/src/types.dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/hkdf.dart';
import 'package:pointycastle/modes/gcm.dart';
import 'package:pointycastle/stream/chacha20.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart'; // Needed for ECBBlockCipher
import 'package:pointycastle/stream/chacha20.dart';
import 'package:pointycastle/macs/poly1305.dart';
import 'package:pointycastle/paddings/pkcs7.dart'; // For ECB padding if needed, though not directly for HP
import 'package:pointycastle/block/ecb.dart'; // For ECB

import 'package:quic_tls_analysis/src/constants.dart';
import 'package:quic_tls_analysis/src/utils.dart'; // For createHkdfLabelInfo

// Abstract interfaces (remain the same)
abstract class AEADAlgorithm {
  int get keyLength;
  int get ivLength;
  int get tagLength;

  Uint8List encrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List plaintext,
  );
  Uint8List? decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List ciphertextWithTag,
  );
}

abstract class KDFAlgorithm {
  Uint8List hkdfExpandLabel(
    Uint8List secret,
    String label,
    Uint8List context,
    int length,
  );
  Uint8List hkdfExtract(Uint8List salt, Uint8List ikm);
  int get hashLength;
}

// PointyCastle KDF Implementation
class PointyCastleKDFAlgorithm implements KDFAlgorithm {
  final Digest _digest;

  PointyCastleKDFAlgorithm(this._digest);

  @override
  int get hashLength => _digest.digestSize;

  @override
  Uint8List hkdfExpandLabel(
    Uint8List secret,
    String label,
    Uint8List context,
    int length,
  ) {
    final Hkdf hkdf = Hkdf(_digest);
    hkdf.init(
      HkdfParameters(
        secret,
        Uint8List(0), // No salt used for Expand part
        createHkdfLabelInfo(length, label, context),
      ),
    );
    return hkdf.deriveKey(length);
  }

  @override
  Uint8List hkdfExtract(Uint8List salt, Uint8List ikm) {
    final Hkdf hkdf = Hkdf(_digest);
    hkdf.init(
      HkdfParameters(
        ikm,
        salt,
        Uint8List(0), // No info for Extract part
      ),
    );
    return hkdf.extractKey();
  }
}

// PointyCastle AEAD Implementations
class PointyCastleAESGCM implements AEADAlgorithm {
  final int _keyLength;
  final int _ivLength = QuicConstants.aeadIvLength; // Fixed 12 bytes for GCM
  final int _tagLength = 16; // Fixed 16 bytes for GCM

  PointyCastleAESGCM(this._keyLength);

  @override
  int get keyLength => _keyLength;
  @override
  int get ivLength => _ivLength;
  @override
  int get tagLength => _tagLength;

  @override
  Uint8List encrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List plaintext,
  ) {
    final GCMBlockCipher cipher = GCMBlockCipher(AESEngine());
    cipher.init(
      true,
      AEADParameters(
        KeyParameter(key),
        tagLength * 8, // Tag length in bits
        nonce,
        associatedData,
      ),
    );
    final Uint8List ciphertext = Uint8List(
      cipher.getOutputSize(plaintext.length),
    );
    int offset = cipher.processBytes(
      plaintext,
      0,
      plaintext.length,
      ciphertext,
      0,
    );
    cipher.doFinal(ciphertext, offset);
    return ciphertext;
  }

  @override
  Uint8List? decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List ciphertextWithTag,
  ) {
    final GCMBlockCipher cipher = GCMBlockCipher(AESEngine());
    try {
      cipher.init(
        false,
        AEADParameters(
          KeyParameter(key),
          tagLength * 8, // Tag length in bits
          nonce,
          associatedData,
        ),
      );
      final Uint8List plaintext = Uint8List(
        cipher.getOutputSize(ciphertextWithTag.length),
      );
      int offset = cipher.processBytes(
        ciphertextWithTag,
        0,
        ciphertextWithTag.length,
        plaintext,
        0,
      );
      cipher.doFinal(plaintext, offset);
      return plaintext;
    } on ArgumentError catch (e) {
      if (e.message.contains('mac check failed')) {
        return null; // Tag verification failed
      }
      rethrow;
    } catch (e) {
      return null; // Other decryption errors
    }
  }
}

class PointyCastleChaCha20Poly1305 implements AEADAlgorithm {
  final int _keyLength =
      QuicConstants.chacha20Poly1305KeyLength; // Fixed 32 bytes
  final int _ivLength =
      QuicConstants.aeadIvLength; // Fixed 12 bytes for ChaCha20-Poly1305
  final int _tagLength = 16; // Fixed 16 bytes for Poly1305

  @override
  int get keyLength => _keyLength;
  @override
  int get ivLength => _ivLength;
  @override
  int get tagLength => _tagLength;

  @override
  Uint8List encrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List plaintext,
  ) {
    final ChaCha20Poly1305Engine cipher = ChaCha20Poly1305Engine();
    cipher.init(
      true,
      AEADParameters(KeyParameter(key), _tagLength * 8, nonce, associatedData),
    );

    final Uint8List output = Uint8List(cipher.getOutputSize(plaintext.length));
    int offset = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
    cipher.doFinal(output, offset);
    return output;
  }

  @override
  Uint8List? decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List ciphertextWithTag,
  ) {
    final ChaCha20Poly1305Engine cipher = ChaCha20Poly1305Engine();
    try {
      cipher.init(
        false,
        AEADParameters(
          KeyParameter(key),
          _tagLength * 8,
          nonce,
          associatedData,
        ),
      );
      final Uint8List output = Uint8List(
        cipher.getOutputSize(ciphertextWithTag.length),
      );
      int offset = cipher.processBytes(
        ciphertextWithTag,
        0,
        ciphertextWithTag.length,
        output,
        0,
      );
      cipher.doFinal(output, offset);
      return output;
    } on ArgumentError catch (e) {
      if (e.message.contains('mac check failed')) {
        return null; // Tag verification failed
      }
      rethrow;
    } catch (e) {
      return null; // Other decryption errors
    }
  }
}

// Global instances for convenience, matching RFC specifications for QUIC
final KDFAlgorithm quicKdfSHA256 = PointyCastleKDFAlgorithm(SHA256Digest());
final AEADAlgorithm aes128Gcm = PointyCastleAESGCM(
  QuicConstants.aes128GcmKeyLength,
);
final AEADAlgorithm chacha20Poly1305 = PointyCastleChaCha20Poly1305();

// Helper functions for header protection (now using PointyCastle)
Uint8List aesEcbEncrypt(Uint8List key, Uint8List data) {
  final ECBBlockCipher cipher = ECBBlockCipher(AESEngine());
  cipher.init(true, KeyParameter(key)); // true for encryption
  final Uint8List output = Uint8List(data.length);
  cipher.processBlock(data, 0, output, 0); // ECB processes a single block
  return output;
}

Uint8List chacha20Encrypt(
  Uint8List key,
  Uint8List counter,
  Uint8List nonce,
  Uint8List plaintext,
) {
  // ChaCha20 in header protection uses a fixed 4-byte counter and 12-byte nonce
  // The first 4 bytes of the HP sample are used as the counter, and the remaining 12 bytes as the nonce.
  // The key is the HP key. Plaintext is 5 zero bytes.
  final ChaCha20Engine cipher = ChaCha20Engine();
  // PointyCastle's ChaCha20 requires an IV of 12 bytes.
  // The counter is provided as part of the parameters.
  cipher.init(
    true,
    ParametersWithIV(
      KeyParameter(key),
      Uint8List.fromList([...counter, ...nonce]),
    ),
  );

  final Uint8List output = Uint8List(plaintext.length);
  cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
  return output;
}
