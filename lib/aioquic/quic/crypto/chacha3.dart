import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Abstract class definition for an AEAD cipher.
abstract class AEAD {
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  );
  Future<Uint8List> decrypt(
    Uint8List encrypted,
    Uint8List associatedData,
    Uint8List nonce,
  );
}

class ChachaCipher implements AEAD {
  final algorithm = Chacha20.poly1305Aead();
  final SecretKey secretKey;
  Uint8List iv;

  /// The cipher should be initialized with the SecretKey directly.
  ChachaCipher({required this.secretKey, required this.iv});

  /// Encrypts plaintext using the given associated data and nonce.
  ///
  /// In QUIC:
  /// - `plain`: The unencrypted QUIC frame(s).
  /// - `associatedData`: The authenticated but unencrypted packet header.
  /// - `nonce`: The 12-byte nonce constructed from the IV and the packet number.
  @override
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final secretBox = await algorithm.encrypt(
      plain,
      secretKey: secretKey,
      nonce: nonce,
      aad: associatedData, // Associated data is critical for authentication
    );

    // The final encrypted payload is the ciphertext followed by the 16-byte MAC (tag).
    return Uint8List.fromList([
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  /// Decrypts a QUIC packet's payload.
  ///
  /// In QUIC:
  /// - `encryptedPayload`: The raw payload from the packet (ciphertext + auth tag).
  /// - `associatedData`: The authenticated but unencrypted packet header.
  /// - `nonce`: The 12-byte nonce reconstructed from the IV and packet number.
  @override
  Future<Uint8List> decrypt(
    Uint8List encryptedPayload,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    if (encryptedPayload.length < 16) {
      throw ArgumentError(
        'Encrypted payload is too short to contain a MAC tag.',
      );
    }

    // The MAC is the last 16 bytes of the payload.
    final int ciphertextLength = encryptedPayload.length - 16;
    final ciphertext = encryptedPayload.sublist(0, ciphertextLength);
    final mac = Mac(encryptedPayload.sublist(ciphertextLength));

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);

    // The `decrypt` function requires the same AAD to verify the integrity of the packet.
    // The library will throw an exception if the MAC is invalid.
    final clearText = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: associatedData,
    );
    return Uint8List.fromList(clearText);
  }
}

class AesGcm256Cipher implements AEAD {
  final algorithm = AesGcm.with256bits();
  final SecretKey secretKey;
  Uint8List iv;

  /// The cipher should be initialized with the SecretKey directly.
  AesGcm256Cipher({required this.secretKey, required this.iv});

  /// Encrypts plaintext using the given associated data and nonce.
  ///
  /// In QUIC:
  /// - `plain`: The unencrypted QUIC frame(s).
  /// - `associatedData`: The authenticated but unencrypted packet header.
  /// - `nonce`: The 12-byte nonce constructed from the IV and the packet number.
  @override
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final secretBox = await algorithm.encrypt(
      plain,
      secretKey: secretKey,
      nonce: nonce,
      aad: associatedData, // Associated data is critical for authentication
    );

    // The final encrypted payload is the ciphertext followed by the 16-byte MAC (tag).
    return Uint8List.fromList([
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  /// Decrypts a QUIC packet's payload.
  ///
  /// In QUIC:
  /// - `encryptedPayload`: The raw payload from the packet (ciphertext + auth tag).
  /// - `associatedData`: The authenticated but unencrypted packet header.
  /// - `nonce`: The 12-byte nonce reconstructed from the IV and packet number.
  @override
  Future<Uint8List> decrypt(
    Uint8List encryptedPayload,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    if (encryptedPayload.length < 16) {
      throw ArgumentError(
        'Encrypted payload is too short to contain a MAC tag.',
      );
    }

    // The MAC is the last 16 bytes of the payload.
    final int ciphertextLength = encryptedPayload.length - 16;
    final ciphertext = encryptedPayload.sublist(0, ciphertextLength);
    final mac = Mac(encryptedPayload.sublist(ciphertextLength));

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);

    // The `decrypt` function requires the same AAD to verify the integrity of the packet.
    // The library will throw an exception if the MAC is invalid.
    final clearText = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: associatedData,
    );
    return Uint8List.fromList(clearText);
  }
}

class AesGcm128Cipher implements AEAD {
  final algorithm = AesGcm.with128bits();
  final SecretKey secretKey;
  Uint8List iv;

  /// The cipher should be initialized with the SecretKey directly.
  AesGcm128Cipher({required this.secretKey, required this.iv});

  /// Encrypts plaintext using the given associated data and nonce.
  ///
  /// In QUIC:
  /// - `plain`: The unencrypted QUIC frame(s).
  /// - `associatedData`: The authenticated but unencrypted packet header.
  /// - `nonce`: The 12-byte nonce constructed from the IV and the packet number.
  @override
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    final secretBox = await algorithm.encrypt(
      plain,
      secretKey: secretKey,
      nonce: nonce,
      aad: associatedData, // Associated data is critical for authentication
    );

    // The final encrypted payload is the ciphertext followed by the 16-byte MAC (tag).
    return Uint8List.fromList([
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  /// Decrypts a QUIC packet's payload.
  ///
  /// In QUIC:
  /// - `encryptedPayload`: The raw payload from the packet (ciphertext + auth tag).
  /// - `associatedData`: The authenticated but unencrypted packet header.
  /// - `nonce`: The 12-byte nonce reconstructed from the IV and packet number.
  @override
  Future<Uint8List> decrypt(
    Uint8List encryptedPayload,
    Uint8List associatedData,
    Uint8List nonce,
  ) async {
    if (encryptedPayload.length < 16) {
      throw ArgumentError(
        'Encrypted payload is too short to contain a MAC tag.',
      );
    }

    // The MAC is the last 16 bytes of the payload.
    final int ciphertextLength = encryptedPayload.length - 16;
    final ciphertext = encryptedPayload.sublist(0, ciphertextLength);
    final mac = Mac(encryptedPayload.sublist(ciphertextLength));

    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);

    // The `decrypt` function requires the same AAD to verify the integrity of the packet.
    // The library will throw an exception if the MAC is invalid.
    final clearText = await algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: associatedData,
    );
    return Uint8List.fromList(clearText);
  }
}
