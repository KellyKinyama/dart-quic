// crypto.dart (NEW)
import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/modes/gcm.dart';
import 'package:pointycastle/block/chacha20.dart';
import 'package:pointycastle/macs/poly1305.dart';
import 'package:pointycastle/stream/chacha20.dart' as stream_chacha20;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';

import 'auxiliary.dart'; // Contains Aead interface, Role, EncryptionLevel, etc.

// MissingKeysException.java
class MissingKeysException extends QuicRuntimeException {
  MissingKeysException(String message) : super(message);
}

// BaseAeadImpl.java
abstract class BaseAeadImpl implements Aead {
  @override
  Uint8List createHeaderProtectionMask(Uint8List sample) {
    // This method is abstract in the Java BaseAeadImpl and implemented by subclasses.
    // In Java, `cipher.processBlock` is used, implying a block cipher operating on `sample`.
    // In Pointy Castle, header protection is usually derived via a separate sub-key and a block cipher.
    // For AES-GCM, this involves a specific PRF, for ChaCha20, it involves ChaCha20 with a fixed counter.
    throw UnimplementedError('createHeaderProtectionMask must be implemented by concrete AEAD classes.');
  }
}

// Aes128Gcm.java
class Aes128Gcm extends BaseAeadImpl {
  final int _keySize = 16; // 128 bits
  final int _nonceSize = 12; // 96 bits (standard for GCM)
  final int _tagSize = 16; // Authentication tag size

  @override
  int getKeySize() => _keySize;

  @override
  int getNonceSize() => _nonceSize;

  @override
  Uint8List createHeaderProtectionMask(Uint8List sample) {
    // From RFC 9001, Section 5.4.1. This is not AEAD encrypt/decrypt.
    // It's a key derivation followed by a block cipher operation.
    // The sample is encrypted using the HP key (derived from packet protection key).
    // The first 16 bytes of the output are the mask.
    // For AES-128, the HP key is 16 bytes.
    // This assumes `sample` is 16 bytes.

    // A real implementation needs the HP key, which is usually derived from the AEAD key.
    // For simplicity here, let's assume `createHeaderProtectionMask`
    // is called with a specific HP key.
    // For now, using a placeholder cipher setup for HP mask generation.
    final aesBlockCipher = AESEngine();
    aesBlockCipher.init(true, KeyParameter(Uint8List(16))); // Placeholder HP key
    final mask = Uint8List(16);
    aesBlockCipher.processBlock(sample, 0, mask, 0); // Encrypt the sample
    return mask;
  }

  @override
  Uint8List encrypt(Uint8List key, Uint8List iv, Uint8List plaintext, Uint8List? additionalData) {
    final gcm = GCMBlockCipher(AESEngine());
    final params = AEADParameters(
      KeyParameter(key),
      _tagSize * 8, // Tag size in bits
      iv,
      additionalData,
    );
    gcm.init(true, params); // True for encryption

    final cipherText = gcm.process(plaintext);
    return cipherText;
  }

  @override
  Uint8List decrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List? additionalData) {
    final gcm = GCMBlockCipher(AESEngine());
    final params = AEADParameters(
      KeyParameter(key),
      _tagSize * 8,
      iv,
      additionalData,
    );
    gcm.init(false, params); // False for decryption

    try {
      final decryptedText = gcm.process(ciphertext);
      return decryptedText;
    } on ArgumentError catch (e) {
      if (e.message.contains('mac mismatch')) {
        throw DecryptionException('AEAD authentication tag mismatch.');
      }
      rethrow;
    }
  }
}

// Aes256Gcm.java (Similar to Aes128Gcm but with 256-bit key)
class Aes256Gcm extends BaseAeadImpl {
  final int _keySize = 32; // 256 bits
  final int _nonceSize = 12;
  final int _tagSize = 16;

  @override
  int getKeySize() => _keySize;

  @override
  int getNonceSize() => _nonceSize;

  @override
  Uint8List createHeaderProtectionMask(Uint8List sample) {
    // Similar HP derivation logic as AES-128, but with 256-bit key if applicable.
    final aesBlockCipher = AESEngine();
    aesBlockCipher.init(true, KeyParameter(Uint8List(32))); // Placeholder HP key for AES-256
    final mask = Uint8List(16);
    aesBlockCipher.processBlock(sample, 0, mask, 0);
    return mask;
  }

  @override
  Uint8List encrypt(Uint8List key, Uint8List iv, Uint8List plaintext, Uint8List? additionalData) {
    final gcm = GCMBlockCipher(AESEngine());
    final params = AEADParameters(
      KeyParameter(key),
      _tagSize * 8,
      iv,
      additionalData,
    );
    gcm.init(true, params);
    final cipherText = gcm.process(plaintext);
    return cipherText;
  }

  @override
  Uint8List decrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List? additionalData) {
    final gcm = GCMBlockCipher(AESEngine());
    final params = AEADParameters(
      KeyParameter(key),
      _tagSize * 8,
      iv,
      additionalData,
    );
    gcm.init(false, params);
    try {
      final decryptedText = gcm.process(ciphertext);
      return decryptedText;
    } on ArgumentError catch (e) {
      if (e.message.contains('mac mismatch')) {
        throw DecryptionException('AEAD authentication tag mismatch.');
      }
      rethrow;
    }
  }
}

// ChaCha20.java (Note: The Java file likely refers to ChaCha20-Poly1305 AEAD, not just ChaCha20 stream cipher)
class ChaCha20 extends BaseAeadImpl {
  final int _keySize = 32; // 256 bits
  final int _nonceSize = 12; // 96 bits
  final int _tagSize = 16;

  @override
  int getKeySize() => _keySize;

  @override
  int getNonceSize() => _nonceSize;

  @override
  Uint8List createHeaderProtectionMask(Uint8List sample) {
    // For ChaCha20, header protection uses a separate ChaCha20 instance with a fixed counter.
    // The HP key is derived. The `sample` is the input for the cipher.
    // The mask is the output of the cipher.
    // This assumes `sample` is 16 bytes for the mask.
    // A proper HP key derived from the AEAD key should be used.
    final chacha20Engine = stream_chacha20.ChaCha20Engine();
    // Placeholder HP key (e.g., derived from the actual AEAD key).
    // The IV for header protection is typically 0 for ChaCha20-Poly1305.
    final params = KeyParameter(Uint8List(32)); // 256-bit key
    final ivParams = ParametersWithIV(params, Uint8List(8)); // 64-bit IV for stream cipher (PointyCastle ChaCha20)

    chacha20Engine.init(true, ivParams); // `true` for encryption (or just process)
    final mask = Uint8List(16);
    chacha20Engine.processBytes(sample, 0, 16, mask, 0); // Encrypt the sample to get the mask
    return mask;
  }

  @override
  Uint8List encrypt(Uint8List key, Uint8List iv, Uint8List plaintext, Uint8List? additionalData) {
    final poly1305 = Poly1305();
    final chacha20 = stream_chacha20.ChaCha20Engine();

    final paramsWithIv = ParametersWithIV(KeyParameter(key), iv);
    final chacha20Poly1305Params = AEADParameters(
      KeyParameter(key),
      _tagSize * 8, // Tag size in bits
      iv,
      additionalData,
    );

    // Pointy Castle's ChaCha20-Poly1305 is not a direct AEAD cipher.
    // It's implemented by combining ChaCha20 stream cipher and Poly1305 MAC.
    // The process is:
    // 1. Generate Poly1305 key using ChaCha20 with block 0 and specific key/IV.
    // 2. Encrypt plaintext using ChaCha20 starting from block 1.
    // 3. Compute Poly1305 tag over AAD || ciphertext.
    // This is more complex than direct GCM usage.

    // Using the combined AEAD approach for ChaCha20-Poly1305 if available.
    // Pointy Castle doesn't have a direct ChaCha20Poly1305 AEAD class.
    // This will require manual implementation of the RFC 7539 (ChaCha20-Poly1305) AEAD construction.
    // This is a simplification and will need to be refined for true RFC 7539 compliance.

    // Placeholder for actual ChaCha20-Poly1305 construction.
    // For demonstration, let's treat it as a direct AEAD interface, but
    // a proper implementation would build on `stream_chacha20.ChaCha20Engine` and `Poly1305`.
    // This is significantly more involved than just wrapping `GCMBlockCipher`.

    throw UnimplementedError('ChaCha20-Poly1305 encryption not fully implemented with PointyCastle AEAD interface yet. '
                             'Requires manual RFC 7539 construction.');
  }

  @override
  Uint8List decrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List? additionalData) {
    // Similar to encrypt, requires manual RFC 7539 construction.
    throw UnimplementedError('ChaCha20-Poly1305 decryption not fully implemented with PointyCastle AEAD interface yet. '
                             'Requires manual RFC 7539 construction.');
  }
}

// ConnectionSecrets.java
class ConnectionSecrets {
  final Logger _log;
  final Role _role;
  final Version _version;

  Uint8List? _initialSecret;
  Uint8List? _clientInitialTrafficSecret;
  Uint8List? _serverInitialTrafficSecret;

  Uint8List? _handshakeSecret;
  Uint8List? _clientHandshakeTrafficSecret;
  Uint8List? _serverHandshakeTrafficSecret;

  Uint8List? _clientApplicationTrafficSecret;
  Uint8List? _serverApplicationTrafficSecret;

  Aead? _initialAead;
  Aead? _handshakeAead;
  Aead? _zeroRttAead; // Assuming derived from application secrets eventually
  Aead? _oneRttClientAead;
  Aead? _oneRttServerAead;
  Aead? _oneRttClientAeadNext; // For key updates
  Aead? _oneRttServerAeadNext; // For key updates

  ConnectionSecrets(this._log, this._role, this._version);

  // Initial Secrets (RFC 9001, Section 5.1)
  void generateInitialSecrets(Uint8List initialSalt, Uint8List destinationConnectionId) {
    _log.debug("Generating initial secrets...");

    // Initial secret derived from initial salt and DCID.
    final digest = SHA256Digest(); // QUIC v1 uses SHA256 for initial secrets
    _initialSecret = Hkdf.deriveKey(digest, destinationConnectionId, digest.byteLength, salt: initialSalt);
    _log.debug("Initial secret: ${_initialSecret?.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}");

    _clientInitialTrafficSecret = deriveTrafficSecret(_initialSecret!, "client in");
    _serverInitialTrafficSecret = deriveTrafficSecret(_initialSecret!, "server in");

    _log.debug("Client Initial Traffic Secret: ${_clientInitialTrafficSecret?.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}");
    _log.debug("Server Initial Traffic Secret: ${_serverInitialTrafficSecret?.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}");

    // Instantiate AEADs for Initial encryption level
    _initialAead = Aes128Gcm(); // Initial packets use AES-128-GCM
  }

  // Handshake Secrets (RFC 9001, Section 5.1)
  void generateHandshakeSecrets(Uint8List handshakeSecret) {
    _log.debug("Generating handshake secrets...");
    _handshakeSecret = handshakeSecret; // This comes from TLS Handshake

    _clientHandshakeTrafficSecret = deriveTrafficSecret(_handshakeSecret!, "client hs");
    _serverHandshakeTrafficSecret = deriveTrafficSecret(_handshakeSecret!, "server hs");

    _log.debug("Client Handshake Traffic Secret: ${_clientHandshakeTrafficSecret?.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}");
    _log.debug("Server Handshake Traffic Secret: ${_serverHandshakeTrafficSecret?.map((b) => b.toRadixString(16).padLeft(2, '0')).join('')}");

    // Instantiate AEADs for Handshake encryption level
    _handshakeAead = Aes128Gcm(); // Handshake packets use AES-128-GCM (for v1)
  }

  // Application Secrets (RFC 9001, Section 5.2)
  void generateApplicationSecrets(Uint8List masterSecret, bool isZeroRtt) {
    _log.debug("Generating application secrets (0-RTT/1-RTT)...");

    // Client/Server Application Traffic Secrets
    _clientApplicationTrafficSecret = deriveTrafficSecret(masterSecret, "client ap in");
    _serverApplicationTrafficSecret = deriveTrafficSecret(masterSecret, "server ap in");

    // Instantiate AEADs for Application encryption level
    // Assuming AES-128-GCM for now, but this should be negotiated via TLS.
    // Key phase 0 AEADs
    _oneRttClientAead = Aes128Gcm();
    _oneRttServerAead = Aes128Gcm();

    if (isZeroRtt) {
      _zeroRttAead = Aes128Gcm(); // 0-RTT uses specific keys derived from client_early_traffic_secret
    }
  }

  // Helper for deriving traffic secrets as per RFC 9001, Section 5.1
  Uint8List deriveTrafficSecret(Uint8List secret, String label) {
    return Hkdf.deriveKey(
      SHA256Digest(), // Or SHA512Digest depending on negotiated cipher suite
      secret,
      32, // Length of derived secret (e.g., 32 for SHA256, 64 for SHA512)
      info: utf8.encode(label),
    );
  }

  // Retrieve AEAD instances
  Aead getAead(EncryptionLevel level) {
    switch (level) {
      case EncryptionLevel.initial:
        return _initialAead ?? (throw MissingKeysException("Initial AEAD not available"));
      case EncryptionLevel.handshake:
        return _handshakeAead ?? (throw MissingKeysException("Handshake AEAD not available"));
      case EncryptionLevel.zeroRtt:
        return _zeroRttAead ?? (throw MissingKeysException("0-RTT AEAD not available"));
      case EncryptionLevel.oneRtt:
        // Return client or server AEAD based on role and current key phase
        return (_role == Role.client ? _oneRttClientAead : _oneRttServerAead)
               ?? (throw MissingKeysException("1-RTT AEAD not available"));
    }
  }

  // Retrieve packet protection key for a given encryption level and role
  Uint8List getPacketProtectionKey(EncryptionLevel level, Role forRole) {
    Uint8List? secret;
    switch (level) {
      case EncryptionLevel.initial:
        secret = (forRole == Role.client) ? _clientInitialTrafficSecret : _serverInitialTrafficSecret;
        break;
      case EncryptionLevel.handshake:
        secret = (forRole == Role.client) ? _clientHandshakeTrafficSecret : _serverHandshakeTrafficSecret;
        break;
      case EncryptionLevel.zeroRtt:
        secret = (forRole == Role.client) ? _clientApplicationTrafficSecret : null; // 0-RTT only applies to client for sending
        break;
      case EncryptionLevel.oneRtt:
        secret = (forRole == Role.client) ? _clientApplicationTrafficSecret : _serverApplicationTrafficSecret;
        break;
    }
    if (secret == null) {
      throw MissingKeysException("Packet protection key not available for $level and $forRole");
    }
    // Derive packet protection key from traffic secret.
    // The actual key derivation label and length depend on the AEAD cipher suite.
    // Assuming 16 bytes for AES-128 for now.
    return Hkdf.deriveKey(SHA256Digest(), secret, 16, info: utf8.encode("quic hp")); // Use appropriate digest
  }

  // Retrieve packet protection IV for a given encryption level and role
  Uint8List getPacketProtectionIv(EncryptionLevel level, Role forRole) {
    Uint8List? secret;
    switch (level) {
      case EncryptionLevel.initial:
        secret = (forRole == Role.client) ? _clientInitialTrafficSecret : _serverInitialTrafficSecret;
        break;
      case EncryptionLevel.handshake:
        secret = (forRole == Role.client) ? _clientHandshakeTrafficSecret : _serverHandshakeTrafficSecret;
        break;
      case EncryptionLevel.zeroRtt:
        secret = (forRole == Role.client) ? _clientApplicationTrafficSecret : null;
        break;
      case EncryptionLevel.oneRtt:
        secret = (forRole == Role.client) ? _clientApplicationTrafficSecret : _serverApplicationTrafficSecret;
        break;
    }
    if (secret == null) {
      throw MissingKeysException("Packet protection IV secret not available for $level and $forRole");
    }
    // Derive packet protection IV from traffic secret.
    // IV length (nonce size) depends on AEAD. For AES-GCM, it's 12 bytes.
    return Hkdf.deriveKey(SHA256Digest(), secret, 12, info: utf8.encode("quic iv"));
  }
}