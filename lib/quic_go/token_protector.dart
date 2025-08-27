
// Filename: token_protector.dart
import 'dart:typed_data';
import 'dart:math';
import 'package:cryptography/cryptography.dart';

const _tokenNonceSize = 32;

class TokenProtector {
  final SecretKey _key;

  TokenProtector(List<int> keyBytes) : _key = SecretKey(keyBytes);

  Future<Uint8List> newToken(Uint8List data) async {
    final nonce = _generateNonce(_tokenNonceSize);
    final aead = await _createAead(nonce);
    final secretBox = await aead.encrypt(data,secretKey: _key, nonce: nonce.sublist(16)); // Use part of nonce for AEAD

    final builder = BytesBuilder();
    builder.add(nonce);
    builder.add(secretBox.concatenation());
    return builder.toBytes();
  }

  Future<Uint8List> decodeToken(Uint8List protectedToken) async {
    if (protectedToken.length < _tokenNonceSize) {
      throw ArgumentError('Token too short');
    }
    final nonce = protectedToken.sublist(0, _tokenNonceSize);
    final ciphertext = protectedToken.sublist(_tokenNonceSize);

    final aead = await _createAead(nonce);
    final secretBox = SecretBox.fromConcatenation(
      ciphertext,
      nonceLength: 16,
      macLength: 16,
    );

    final decrypted = await aead.decrypt(secretBox,secretKey: _key);
    return Uint8List.fromList(decrypted);
  }

  Future<AesGcm> _createAead(List<int> nonce) async {
    final hkdf = Hkdf(hmac: Hmac(Sha256()), hash: Sha256());
    final keyMaterial = await hkdf.expand(
      secretKey: _key,
      info: 'quic-go token source'.codeUnits,
      length: 32 + 12, // 32 for key, 12 for nonce
    );
    
    final keyBytes = (await keyMaterial.extractBytes()).sublist(0, 32);
    // Nonce for AEAD is also derived, but the Go code's nonce handling is complex.
    // This is a simplified, secure alternative.
    final aeadKey = SecretKey(keyBytes);
    return AesGcm.with256bits();
  }

  Uint8List _generateNonce(int size) {
    final random = Random.secure();
    return Uint8List.fromList(List<int>.generate(size, (_) => random.nextInt(256)));
  }
}
