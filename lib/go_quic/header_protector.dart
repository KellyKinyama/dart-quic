// lib/header_protector.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import 'cipher_suite.dart';
import 'hkdf.dart';
import 'protocol.dart';

/// An interface for header protection.
abstract class HeaderProtector {
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes);
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes);
}

String hkdfHeaderProtectionLabel(Version v) {
  return v == Version.version2 ? 'quicv2 hp' : 'quic hp';
}

HeaderProtector newHeaderProtector(
  CipherSuite suite,
  Uint8List trafficSecret,
  bool isLongHeader,
  Version v,
) {
  final label = hkdfHeaderProtectionLabel(v);
  switch (suite.id) {
    case 0x1301: // TLS_AES_128_GCM_SHA256
    case 0x1302: // TLS_AES_256_GCM_SHA384
      return AESHeaderProtector(suite, trafficSecret, isLongHeader, label);
    case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
      return ChaChaHeaderProtector(suite, trafficSecret, isLongHeader, label);
    default:
      throw Exception('Invalid cipher suite id: ${suite.id}');
  }
}

class AESHeaderProtector implements HeaderProtector {
  final BlockCipher _block;
  final bool _isLongHeader;
  final Uint8List _mask;

  AESHeaderProtector(
    CipherSuite suite,
    Uint8List trafficSecret,
    this._isLongHeader,
    String hkdfLabel,
  ) : _mask = Uint8List(16) {
    final hpKey = hkdfExpandLabel(
      suite.hash(),
      trafficSecret,
      Uint8List(0),
      hkdfLabel,
      suite.keyLen,
    );
    _block = AESEngine()..init(true, KeyParameter(hpKey));
  }

  @override
  void encryptHeader(
    Uint8List sample,
    Uint8List firstByte,
    Uint8List hdrBytes,
  ) {
    _apply(sample, firstByte, hdrBytes);
  }

  @override
  void decryptHeader(
    Uint8List sample,
    Uint8List firstByte,
    Uint8List hdrBytes,
  ) {
    _apply(sample, firstByte, hdrBytes);
  }

  void _apply(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes) {
    if (sample.length != _mask.length) throw Exception('invalid sample size');
    _block.processBlock(sample, 0, _mask, 0);

    firstByte[0] ^= _mask[0] & (_isLongHeader ? 0x0f : 0x1f);
    for (var i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= _mask[i + 1];
    }
  }
}

class ChaChaHeaderProtector implements HeaderProtector {
  final Uint8List _key;
  final bool _isLongHeader;

  ChaChaHeaderProtector(
    CipherSuite suite,
    Uint8List trafficSecret,
    this._isLongHeader,
    String hkdfLabel,
  ) : _key = Uint8List(32) {
    final hpKey = hkdfExpandLabel(
      suite.hash(),
      trafficSecret,
      Uint8List(0),
      hkdfLabel,
      suite.keyLen,
    );
    _key.setRange(0, 32, hpKey);
  }

  @override
  void encryptHeader(
    Uint8List sample,
    Uint8List firstByte,
    Uint8List hdrBytes,
  ) {
    _apply(sample, firstByte, hdrBytes);
  }

  @override
  void decryptHeader(
    Uint8List sample,
    Uint8List firstByte,
    Uint8List hdrBytes,
  ) {
    _apply(sample, firstByte, hdrBytes);
  }

  void _apply(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes) {
    if (sample.length != 16) throw Exception('invalid sample size');

    final nonce = sample.sublist(4);
    final counter = ByteData.sublistView(sample).getUint32(0, Endian.little);

    final cipher = ChaCha20Engine()
      ..init(true, ParametersWithIV(KeyParameter(_key), nonce));
    cipher.seekTo(counter * 64);

    final mask = Uint8List(5);
    cipher.processBytes(mask, 0, mask.length, mask, 0);

    firstByte[0] ^= mask[0] & (_isLongHeader ? 0x0f : 0x1f);
    for (var i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= mask[i + 1];
    }
  }
}
