import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

import 'cipher_suite.dart';
import 'hkdf.dart';
import 'protocol.dart';

/// An interface for header protection.
abstract class HeaderProtector {
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes);
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List hdrBytes);
  Uint8List get mask;
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
  late BlockCipher _block;
  final bool _isLongHeader;
  final Uint8List _mask;

  AESHeaderProtector(
    CipherSuite suite,
    Uint8List trafficSecret,
    this._isLongHeader,
    String hkdfLabel,
  ) : _mask = Uint8List(16) {
    final hpKey = hkdfExpandLabel(
      trafficSecret,
      Uint8List(0),
      hkdfLabel,
      suite.keyLen,
    );
    _block = AESEngine()..init(true, KeyParameter(hpKey));
  }

  @override
  Uint8List get mask => _mask;

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
    _block.processBlock(sample, 0, _mask, 0);

    firstByte[0] ^= _mask[0] & (_isLongHeader ? 0x0f : 0x1f);
    for (var i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= _mask[i + 1];
    }
  }
}

class ChaChaHeaderProtector implements HeaderProtector {
  final Uint8List _hpKey;
  final bool _isLongHeader;
  final Uint8List _mask = Uint8List(5);

  @override
  Uint8List get mask => _mask;

  ChaChaHeaderProtector(
    CipherSuite suite,
    Uint8List trafficSecret,
    this._isLongHeader,
    String hkdfLabel,
  ) : _hpKey = Uint8List(32) {
    final hpKey = hkdfExpandLabel(
      trafficSecret,
      Uint8List(0),
      hkdfLabel,
      suite.keyLen,
    );
    _hpKey.setRange(0, suite.keyLen, hpKey);
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

    // QUIC RFC 9001 Section 5.4.3:
    // Counter = sample[0..3]
    // Nonce = sample[4..15]
    final counterBytes = sample.sublist(0, 4);
    final nonce = sample.sublist(4, 16); // Exactly 12 bytes

    // PointyCastle FIX:
    // Use ChaCha7539Engine instead of ChaCha20Engine.
    // ChaCha7539Engine is the IETF version that accepts 12-byte IVs.
    final engine = ChaCha7539Engine();

    engine.init(true, ParametersWithIV(KeyParameter(_hpKey), nonce));

    // QUIC requires the engine to start at the block defined by the counter.
    // In ChaCha20, the counter is 32-bits (4 bytes) at the start of the sample.
    final counter = ByteData.sublistView(
      counterBytes,
    ).getUint32(0, Endian.little);

    // We generate a 5-byte mask.
    // Because we initialized the engine with the 12-byte nonce,
    // we need to set the internal block counter.
    // If your PointyCastle version doesn't support seek/skip,
    // we process the bytes directly.
    final zeroInput = Uint8List(5);
    final mask = Uint8List(5);

    // Note: If the engine doesn't account for the 'counter' via init,
    // you would normally need to skip (counter * 64) bytes.
    // However, in QUIC HP, the sample is used to *become* the nonce/counter for 1 block.
    engine.processBytes(zeroInput, 0, 5, mask, 0);

    // XOR the first byte
    firstByte[0] ^= mask[0] & (_isLongHeader ? 0x0f : 0x1f);

    // XOR the packet number bytes
    for (var i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= mask[i + 1];
    }
  }
}
