// lib/header_protector.dart
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart' as pc;

import 'cipher_suite.dart';
import 'hkdf.dart';
import 'protocol.dart';

abstract class HeaderProtector {
  Future<void> encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes);
  Future<void> decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes);
}

// ... other code remains the same ...

class ChaChaHeaderProtector implements HeaderProtector {
  final Uint8List _key;
  final bool _isLongHeader;
  final _algo = ChaCha20(macAlgorithm: MacAlgorithm.empty);

  ChaChaHeaderProtector(this._key, this._isLongHeader);

  static Future<ChaChaHeaderProtector> create(
    CipherSuite suite, Uint8List trafficSecret, bool isLongHeader, Version v
  ) async {
    final hpKey = await hkdfExpandLabel(Hmac(sha256), trafficSecret, Uint8List(0), hkdfHeaderProtectionLabel(v), suite.keyLen);
    return ChaChaHeaderProtector(hpKey, isLongHeader);
  }
  
  @override
  Future<void> apply(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes) async {
    if (sample.length != 16) throw Exception('invalid sample size');
    
    final nonce = sample.sublist(4);
    final keyStream = await _algo.encrypt(
      Uint8List(5), // We only need 5 bytes of the key stream
      secretKey: SecretKey(_key),
      nonce: nonce,
      // The counter is encoded in the first 4 bytes of the sample
      initialCounter: ByteData.sublistView(sample).getUint32(0, Endian.little),
    );

    firstByte[0] ^= keyStream[0] & (_isLongHeader ? 0x0f : 0x1f);
    for (var i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= keyStream[i + 1];
    }
  }
}