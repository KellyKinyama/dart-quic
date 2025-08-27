// Filename: header_protector.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:cryptography/cryptography.dart';

import 'cipher_suite.dart';
import 'hkdf.dart';

abstract class HeaderProtector {
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List hdrBytes);
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List hdrBytes);
}

class AesHeaderProtector implements HeaderProtector {
  final pc.BlockCipher _block;
  final bool _isLongHeader;
  final Uint8List _mask;

  AesHeaderProtector(this._block, this._isLongHeader) : _mask = Uint8List(16);

  static Future<HeaderProtector> create(
    CipherSuite suite,
    List<int> trafficSecret,
    bool isLongHeader,
  ) async {
    final hpKeyBytes = await hkdfExpandLabel(
      suite.hash,
      trafficSecret,
      [],
      'quic hp',
      suite.keyLen,
    );
    final block = pc.AESEngine()..init(true, pc.KeyParameter(hpKeyBytes));
    return AesHeaderProtector(block, isLongHeader);
  }

  void _apply(Uint8List sample, ByteData firstByte, Uint8List hdrBytes) {
    if (sample.length != 16) {
      throw ArgumentError('Invalid sample size for AES Header Protection');
    }
    _block.processBlock(sample, 0, _mask, 0);

    if (_isLongHeader) {
      firstByte.setUint8(0, firstByte.getUint8(0) ^ (_mask[0] & 0x0f));
    } else {
      firstByte.setUint8(0, firstByte.getUint8(0) ^ (_mask[0] & 0x1f));
    }

    for (int i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= _mask[i + 1];
    }
  }

  @override
  void encryptHeader(
    Uint8List sample,
    ByteData firstByte,
    Uint8List hdrBytes,
  ) => _apply(sample, firstByte, hdrBytes);

  @override
  void decryptHeader(
    Uint8List sample,
    ByteData firstByte,
    Uint8List hdrBytes,
  ) => _apply(sample, firstByte, hdrBytes);
}

class ChaChaHeaderProtector implements HeaderProtector {
  final Uint8List _key;
  final bool _isLongHeader;
  final Uint8List _mask = Uint8List(5);

  ChaChaHeaderProtector(this._key, this._isLongHeader);

  static Future<HeaderProtector> create(
    CipherSuite suite,
    List<int> trafficSecret,
    bool isLongHeader,
  ) async {
    final hpKey = await hkdfExpandLabel(
      suite.hash,
      trafficSecret,
      [],
      'quic hp',
      suite.keyLen,
    );
    return ChaChaHeaderProtector(hpKey, isLongHeader);
  }

  void _apply(Uint8List sample, ByteData firstByte, Uint8List hdrBytes) {
    if (sample.length != 16) {
      throw ArgumentError('Invalid sample size for ChaCha20 Header Protection');
    }

    final nonce = sample.sublist(4);
    final counter = ByteData.sublistView(sample).getUint32(0, Endian.little);

    final cipher = pc.ChaCha7539Engine.fromRounds(counter)
      ..init(
        true,
        pc.ParametersWithIV<pc.KeyParameter>(pc.KeyParameter(_key), nonce),
      );

    // (cipher as pc.ChaCha7539Engine).from(counter);

    final zeros = Uint8List(5);
    cipher.processBytes(zeros, 0, 5, _mask, 0);

    if (_isLongHeader) {
      firstByte.setUint8(0, firstByte.getUint8(0) ^ (_mask[0] & 0x0f));
    } else {
      firstByte.setUint8(0, firstByte.getUint8(0) ^ (_mask[0] & 0x1f));
    }

    for (int i = 0; i < hdrBytes.length; i++) {
      hdrBytes[i] ^= _mask[i + 1];
    }
  }

  @override
  void encryptHeader(
    Uint8List sample,
    ByteData firstByte,
    Uint8List hdrBytes,
  ) => _apply(sample, firstByte, hdrBytes);

  @override
  void decryptHeader(
    Uint8List sample,
    ByteData firstByte,
    Uint8List hdrBytes,
  ) => _apply(sample, firstByte, hdrBytes);
}
