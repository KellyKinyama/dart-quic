import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import 'cipher_suite.dart';
import 'hkdf.dart';
import 'protocol.dart';

abstract class HeaderProtector {
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes);
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes);
}

String _hkdfHeaderProtectionLabel(Version v) {
  return v == Version.version2 ? 'quicv2 hp' : 'quic hp';
}

HeaderProtector newHeaderProtector(
  CipherSuite suite,
  Uint8List trafficSecret,
  bool isLongHeader,
  Version v,
) {
  final label = _hkdfHeaderProtectionLabel(v);
  switch (suite.id) {
    case 0x1301: // TLS_AES_128_GCM_SHA256
      return AESHeaderProtector(suite, trafficSecret, isLongHeader, label);
    default:
      throw Exception('Invalid cipher suite id: ${suite.id}');
  }
}

class AESHeaderProtector implements HeaderProtector {
  late final GCMBlockCipher _block;
  final bool _isLongHeader;
  final Uint8List _mask;
  late Uint8List hpKey;

  AESHeaderProtector(
    CipherSuite suite,
    Uint8List trafficSecret,
    this._isLongHeader,
    String hkdfLabel,
  ) : _mask = Uint8List(16) {
    hpKey = hkdfExpandLabel(
      trafficSecret,
      Uint8List(0),
      hkdfLabel,
      suite.keyLen,
    );

    _block = GCMBlockCipher(AESEngine())..init(true, KeyParameter(hpKey));
  }

  @override
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    _apply(sample, firstByte, pnBytes);
  }

  @override
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    _apply(sample, firstByte, pnBytes);
  }

  void _apply(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    if (sample.length != _mask.length) throw Exception('invalid sample size');

    final int aeadAuthTagLen =
        16; // Defined in protectionprofiles.go for AES_128_GCM
    final params = AEADParameters(
      KeyParameter(hpKey),
      aeadAuthTagLen * 8,
      sample,
      Uint8List(0),
    );

    _block = GCMBlockCipher(AESEngine())..init(true, params);
    _block.processBlock(sample, 0, _mask, 0);

    firstByte[0] ^= _mask[0] & (_isLongHeader ? 0x0f : 0x1f);
    for (var i = 0; i < pnBytes.length; i++) {
      pnBytes[i] ^= _mask[i + 1];
    }
  }
}
