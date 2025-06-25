// lib/src/enums.dart
import 'dart:typed_data';

enum EncryptionLevel { initial, zeroRtt, handshake, oneRtt }

// lib/src/errors.dart
class QuicError implements Exception {
  final int code;
  final String message;
  QuicError(this.code, this.message);

  @override
  String toString() => 'QuicError(0x${code.toRadixString(16)}): $message';

  // Mapping for TLS alerts (RFC 9001, Section 4.8)
  static const int tlsAlertBase = 0x0100;
  static QuicError fromTlsAlert(int alertDescription) {
    return QuicError(
      tlsAlertBase + alertDescription,
      'TLS Alert: $alertDescription',
    );
  }

  static const int protocolViolation = 0x01; // Example common error code
}

// lib/src/constants.dart
class QuicConstants {
  static const int maxPacketNumberLength = 4; // Bytes
  static const int headerProtectionSampleLength = 16; // Bytes
  static const int aes128GcmKeyLength = 16; // bytes
  static const int aes256GcmKeyLength = 32; // bytes
  static const int chacha20Poly1305KeyLength = 32; // bytes
  static const int aeadIvLength = 12; // bytes (for GCM and ChaCha20-Poly1305)

  // Initial Salt (RFC 9001, Section 5.2)
  static const List<int> initialSalt = [
    0x38,
    0x76,
    0x2c,
    0xf7,
    0xf5,
    0x59,
    0x34,
    0xb3,
    0x4d,
    0x17,
    0x9a,
    0xe6,
    0xa4,
    0xc8,
    0x0c,
    0xad,
    0xcc,
    0xbb,
    0x7f,
    0x0a,
  ];

  // Retry Key and Nonce (RFC 9001, Section 5.8)
  static const List<int> retryKey = [
    0xbe,
    0x0c,
    0x69,
    0x0b,
    0x9f,
    0x66,
    0x57,
    0x5a,
    0x1d,
    0x76,
    0x6b,
    0x54,
    0xe3,
    0x68,
    0xc8,
    0x4e,
  ];
  static const List<int> retryNonce = [
    0x46,
    0x15,
    0x99,
    0xd3,
    0x5d,
    0x63,
    0x2b,
    0xf2,
    0x23,
    0x98,
    0x25,
    0xbb,
  ];

  // TLS Alert descriptions (subset for example)
  static const int handshakeFailure = 40;
  static const int protocolVersion = 70;
  static const int internalError = 80;
}

// lib/src/types.dart
// Placeholder for AEAD and KDF algorithm representation
abstract class AEADAlgorithm {
  int get keyLength;
  int get ivLength;
  int get tagLength; // Typically 16 bytes for GCM/ChaCha20-Poly1305

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
  int get hashLength; // e.g., 32 for SHA-256
}

// Concrete placeholder AEAD/KDF implementations (NOT CRYPTOGRAPHICALLY SECURE)
class MockAEADAlgorithm implements AEADAlgorithm {
  final int _keyLength;
  final int _ivLength;
  final int _tagLength;

  MockAEADAlgorithm(this._keyLength, this._ivLength, this._tagLength);

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
    // In a real implementation, use a secure AEAD (e.g., AES-GCM, ChaCha20-Poly1305)
    // This is a placeholder for demonstration.
    var encrypted = Uint8List(plaintext.length + tagLength);
    for (int i = 0; i < plaintext.length; i++) {
      encrypted[i] = plaintext[i] ^ key[i % key.length]; // Simple XOR for demo
    }
    // Append a mock tag
    for (int i = 0; i < tagLength; i++) {
      encrypted[plaintext.length + i] = i.toUnsigned(8);
    }
    return encrypted;
  }

  @override
  Uint8List? decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List associatedData,
    Uint8List ciphertextWithTag,
  ) {
    // In a real implementation, use a secure AEAD decrypt and verify tag
    if (ciphertextWithTag.length < tagLength) return null; // Too short for tag

    var plaintext = Uint8List(ciphertextWithTag.length - tagLength);
    for (int i = 0; i < plaintext.length; i++) {
      plaintext[i] =
          ciphertextWithTag[i] ^ key[i % key.length]; // Simple XOR for demo
    }
    // Mock tag verification - in real AEAD this is integrated
    var receivedTag = ciphertextWithTag.sublist(plaintext.length);
    var expectedTag = Uint8List(tagLength);
    for (int i = 0; i < tagLength; i++) {
      expectedTag[i] = i.toUnsigned(8);
    }
    if (listEquals(receivedTag, expectedTag)) {
      return plaintext;
    }
    return null; // Tag mismatch
  }

  // Simple list equality check for Uint8List
  bool listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class MockKDFAlgorithm implements KDFAlgorithm {
  final int _hashLength;

  MockKDFAlgorithm(this._hashLength);

  @override
  int get hashLength => _hashLength;

  @override
  Uint8List hkdfExpandLabel(
    Uint8List secret,
    String label,
    Uint8List context,
    int length,
  ) {
    // In a real implementation, use a secure HKDF-Expand-Label
    // This is a placeholder for demonstration.
    var output = Uint8List(length);
    final labelBytes = Uint8List.fromList(label.codeUnits);
    for (int i = 0; i < length; i++) {
      output[i] =
          (secret[i % secret.length] ^
                  labelBytes[i % labelBytes.length] ^
                  (context.isNotEmpty ? context[i % context.length] : 0))
              .toUnsigned(8);
    }
    return output;
  }

  @override
  Uint8List hkdfExtract(Uint8List salt, Uint8List ikm) {
    // In a real implementation, use a secure HKDF-Extract
    // This is a placeholder for demonstration.
    var output = Uint8List(hashLength);
    for (int i = 0; i < hashLength; i++) {
      output[i] = (salt[i % salt.length] ^ ikm[i % ikm.length]).toUnsigned(8);
    }
    return output;
  }
}

// Mock implementations for specific algorithms
final AEADAlgorithm aes128Gcm = MockAEADAlgorithm(
  QuicConstants.aes128GcmKeyLength,
  QuicConstants.aeadIvLength,
  16,
);
final KDFAlgorithm sha256Kdf = MockKDFAlgorithm(
  32,
); // For Initial packets and SHA256 ciphersuite
// Add other AEAD and KDF algorithms as needed (e.g., AES-256-GCM, ChaCha20-Poly1305, SHA384)

// Helper for Variable-Length Integer Encoding/Decoding (simplified)
class VarInt {
  static int decode(Uint8List bytes, int offset) {
    if (bytes.isEmpty || offset >= bytes.length) return -1; // Indicate error

    int firstByte = bytes[offset];
    int length = 1 << (firstByte >> 6); // 1, 2, 4, or 8 bytes

    if (offset + length > bytes.length) return -1; // Not enough bytes

    int value = firstByte & (0x3F >> (8 - length * 2)); // Mask out length bits
    for (int i = 1; i < length; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return value;
  }

  static Uint8List encode(int value) {
    if (value < 64) {
      return Uint8List.fromList([value]);
    } else if (value < 16384) {
      return Uint8List.fromList([(value >> 8) | 0x40, value & 0xFF]);
    } else if (value < 1073741824) {
      return Uint8List.fromList([
        (value >> 24) | 0x80,
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
      ]);
    } else if (value < 4611686018427387904) {
      // 2^62
      return Uint8List.fromList([
        (value >> 56) | 0xC0,
        (value >> 48) & 0xFF,
        (value >> 40) & 0xFF,
        (value >> 32) & 0xFF,
        (value >> 24) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
      ]);
    } else {
      throw ArgumentError('Value too large for Variable-Length Integer');
    }
  }
}
