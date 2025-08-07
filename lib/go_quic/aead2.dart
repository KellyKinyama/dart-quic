// lib/aead.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import 'protocol.dart';

/// Abstract class for a QUIC AEAD cipher.
abstract class QuicAEAD {
  final SecretKey secretKey;
  final Uint8List iv;

  QuicAEAD({required this.secretKey, required this.iv});

  Future<Uint8List> encrypt(Uint8List plain, Uint8List ad, PacketNumber pn);
  Future<Uint8List> decrypt(Uint8List encrypted, Uint8List ad, PacketNumber pn);
  int get overhead;
}

/// Creates the final 12-byte nonce by XORing the IV with the packet number.
Uint8List _createNonce(Uint8List iv, PacketNumber pn) {
  final nonce = Uint8List.fromList(iv);
  final pnBytes = ByteData(8)..setUint64(0, pn, Endian.big);
  for (var i = 0; i < 8; i++) {
    nonce[4 + i] ^= pnBytes.getUint8(i);
  }
  return nonce;
}

// Below are the implementations that wrap the algorithms from your file.

class AesGcm128QuicAEAD extends QuicAEAD {
  final _algo = AesGcm.with128bits();
  @override
  int get overhead => 16;

  AesGcm128QuicAEAD({required super.secretKey, required super.iv});

  @override
  Future<Uint8List> encrypt(Uint8List plain, Uint8List ad, PacketNumber pn) async {
    final nonce = _createNonce(iv, pn);
    final secretBox = await _algo.encrypt(plain, secretKey: secretKey, nonce: nonce, aad: ad);
    return Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
  }

  @override
  Future<Uint8List> decrypt(Uint8List encrypted, Uint8List ad, PacketNumber pn) async {
    final nonce = _createNonce(iv, pn);
    final ciphertext = encrypted.sublist(0, encrypted.length - overhead);
    final mac = Mac(encrypted.sublist(encrypted.length - overhead));
    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
    final clearText = await _algo.decrypt(secretBox, secretKey: secretKey, aad: ad);
    return Uint8List.fromList(clearText);
  }
}

class AesGcm256QuicAEAD extends QuicAEAD {
  final _algo = AesGcm.with256bits();
  @override
  int get overhead => 16;
  
  AesGcm256QuicAEAD({required super.secretKey, required super.iv});

  @override
  Future<Uint8List> encrypt(Uint8List plain, Uint8List ad, PacketNumber pn) async {
    final nonce = _createNonce(iv, pn);
    final secretBox = await _algo.encrypt(plain, secretKey: secretKey, nonce: nonce, aad: ad);
    return Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
  }

  @override
  Future<Uint8List> decrypt(Uint8List encrypted, Uint8List ad, PacketNumber pn) async {
    final nonce = _createNonce(iv, pn);
    final ciphertext = encrypted.sublist(0, encrypted.length - overhead);
    final mac = Mac(encrypted.sublist(encrypted.length - overhead));
    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
    final clearText = await _algo.decrypt(secretBox, secretKey: secretKey, aad: ad);
    return Uint8List.fromList(clearText);
  }
}

class Chacha20QuicAEAD extends QuicAEAD {
  final _algo = Chacha20.poly1305Aead();
  @override
  int get overhead => 16;

  Chacha20QuicAEAD({required super.secretKey, required super.iv});
  
  @override
  Future<Uint8List> encrypt(Uint8List plain, Uint8List ad, PacketNumber pn) async {
    final nonce = _createNonce(iv, pn);
    final secretBox = await _algo.encrypt(plain, secretKey: secretKey, nonce: nonce, aad: ad);
    return Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
  }

  @override
  Future<Uint8List> decrypt(Uint8List encrypted, Uint8List ad, PacketNumber pn) async {
    final nonce = _createNonce(iv, pn);
    final ciphertext = encrypted.sublist(0, encrypted.length - overhead);
    final mac = Mac(encrypted.sublist(encrypted.length - overhead));
    final secretBox = SecretBox(ciphertext, nonce: nonce, mac: mac);
    final clearText = await _algo.decrypt(secretBox, secretKey: secretKey, aad: ad);
    return Uint8List.fromList(clearText);
  }
}