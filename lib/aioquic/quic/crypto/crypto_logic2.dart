import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart';

import 'chacha3.dart';

class CryptoError implements Exception {
  final String message;
  CryptoError(this.message);
  @override
  String toString() => 'CryptoError: $message';
}

/// Provides Authenticated Encryption with Associated Data (AEAD) functions.
class Aead {
  final ChachaCipher _cipher;
  final Uint8List _key;
  final Uint8List _iv;
  final int _tagLength;

  Aead(String cipherName, this._key, this._iv)
    : _cipher = ChachaCipher(secretKey: SecretKey(_key), iv: _iv),
      _tagLength = 16;

  // static AEADCipher _createCipher(String cipherName) {
  //   switch (cipherName) {
  //     case 'aes-128-gcm':
  //       return GCMBlockCipher(AESEngine());
  //     case 'aes-256-gcm':
  //       return GCMBlockCipher(AESEngine());
  //     case 'chacha20-poly1305':
  //       return ChaCha20Poly1305(macSize: 16);
  //     default:
  //       throw ArgumentError('Unsupported cipher: $cipherName');
  //   }
  // }

  Uint8List _createNonce(int packetNumber) {
    final nonce = Uint8List.fromList(_iv);
    final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);
    for (var i = 0; i < 8; i++) {
      nonce[nonce.length - 8 + i] ^= pnBytes.getUint8(i);
    }
    return nonce;
  }

  // Uint8List decrypt(
  //   Uint8List data,
  //   Uint8List associatedData,
  //   int packetNumber,
  // ) {
  //   final nonce = _createNonce(packetNumber);
  //   _cipher.init(
  //     false,
  //     AEADParameters(KeyParameter(_key), _tagLength * 8, nonce, associatedData),
  //   );

  //   final input = data;
  //   try {
  //     final output = _cipher.process(input);
  //     return output;
  //   } catch (e) {
  //     throw CryptoError('Payload decryption failed');
  //   }
  // }

  // Uint8List encrypt(
  //   Uint8List data,
  //   Uint8List associatedData,
  //   int packetNumber,
  // ) {
  //   final nonce = _createNonce(packetNumber);
  //   _cipher.init(
  //     true,
  //     AEADParameters(KeyParameter(_key), _tagLength * 8, nonce, associatedData),
  //   );

  //   return _cipher.process(data);
  // }
}

/// Provides QUIC Header Protection.
class HeaderProtection {
  final ChachaCipher _cipher;
  final Uint8List _key;
  final bool _isChaCha20;

  HeaderProtection(String cipherName, this._key)
    : _cipher = ChachaCipher(secretKey: SecretKey(_key), iv: Uint8List(0)),
      _isChaCha20 = cipherName == 'chacha20' {
    // _cipher.init(true, KeyParameter(_key));
  }

  // static BlockCipher _createCipher(String cipherName) {
  //   switch (cipherName) {
  //     case 'aes-128-ecb':
  //     case 'aes-256-ecb':
  //       return ECBBlockCipher(AESEngine());
  //     case 'chacha20':
  //       // PointyCastle ChaCha20 needs to be used carefully for this.
  //       // We emulate the OpenSSL behavior of encrypting a block of zeros.
  //       return ChaChaEngine();
  //     default:
  //       throw ArgumentError(
  //         'Unsupported header protection cipher: $cipherName',
  //       );
  //   }
  // }

  // Uint8List _createMask(Uint8List sample) {
  //   if (_isChaCha20) {
  //     final chacha = _cipher as ChachaCipher;
  //     // The sample is the nonce for ChaCha20 header protection.
  //     // The key was set in the constructor.
  //     chacha.init(true, ParametersWithIV(KeyParameter(_key), sample));
  //     final mask = Uint8List(5);
  //     chacha.processBytes(Uint8List(5), 0, 5, mask, 0);
  //     return mask;
  //   } else {
  //     final mask = Uint8List(_cipher.blockSize);
  //     _cipher.processBlock(sample, 0, mask, 0);
  //     return mask;
  //   }
  // }
  Future<Uint8List> _createMask(Uint8List sample) async {
    final nonce = Uint8List.fromList(sample.sublist(4, 16));
    final keyStream = await _cipher.encrypt(
      Uint8List(5),
      Uint8List(0), // associatedData is empty for header protection
      // secretKey: _secretKey,
      nonce,
    );
    return Uint8List.fromList(keyStream);
  }

  Future<Uint8List> apply(Uint8List header, Uint8List payload) async {
    final pnLength = (header[0] & 0x03) + 1;
    final sample = payload.sublist(4 - pnLength, 4 - pnLength + 16);
    final mask = await _createMask(sample);

    final protectedPacket = Uint8List.fromList(header)..addAll(payload);

    // Apply mask to first byte
    if ((protectedPacket[0] & 0x80) != 0) {
      // Long Header
      protectedPacket[0] ^= mask[0] & 0x0f;
    } else {
      // Short Header
      protectedPacket[0] ^= mask[0] & 0x1f;
    }

    // Apply mask to packet number
    final pnOffset = header.length - pnLength;
    for (var i = 0; i < pnLength; i++) {
      protectedPacket[pnOffset + i] ^= mask[1 + i];
    }
    return protectedPacket;
  }

  Future<(Uint8List, int)> remove(Uint8List packet, int encryptedOffset) async {
    final sample = packet.sublist(
      encryptedOffset + 4,
      encryptedOffset + 4 + 16,
    );
    final mask = await _createMask(sample);

    final plainHeader = packet.sublist(0, encryptedOffset);

    // Remove mask from first byte
    if ((plainHeader[0] & 0x80) != 0) {
      // Long Header
      plainHeader[0] ^= mask[0] & 0x0f;
    } else {
      // Short Header
      plainHeader[0] ^= mask[0] & 0x1f;
    }

    final pnLength = (plainHeader[0] & 0x03) + 1;
    final pnOffset = plainHeader.length - pnLength;

    // Temporarily copy the encrypted PN to the plain header buffer to decrypt it in place.
    plainHeader.setRange(
      pnOffset,
      pnOffset + pnLength,
      packet.sublist(encryptedOffset, encryptedOffset + pnLength),
    );

    // Remove mask from packet number
    int truncatedPn = 0;
    for (var i = 0; i < pnLength; ++i) {
      plainHeader[pnOffset + i] ^= mask[1 + i];
      truncatedPn = (truncatedPn << 8) | plainHeader[pnOffset + i];
    }

    return (plainHeader, truncatedPn);
  }
}
