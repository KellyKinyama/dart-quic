// Filename: header_protector.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:hex/hex.dart'; // For printing hex strings
import 'cipher_suite.dart';

abstract class HeaderProtector {
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
}

class AesHeaderProtector implements HeaderProtector {
  final pc.BlockCipher _blockCipher;
  final bool _isLongHeader;
  final Uint8List _mask;

  AesHeaderProtector(this._blockCipher, this._isLongHeader)
    : _mask = Uint8List(16);

  static Future<HeaderProtector> create(
    CipherSuite suite,
    List<int> hpKey,
    bool isLongHeader,
  ) async {
    final blockCipher = pc.AESEngine()
      ..init(true, pc.KeyParameter(Uint8List.fromList(hpKey)));
    return AesHeaderProtector(blockCipher, isLongHeader);
  }

  void apply(
    Uint8List sample,
    ByteData firstByte,
    Uint8List pnBytes,
    String context,
  ) {
    print('$context HP Sample    : ${HEX.encode(sample)}');
    if (sample.length != 16) {
      throw ArgumentError('Invalid sample size for AES Header Protection');
    }
    _blockCipher.processBlock(sample, 0, _mask, 0);
    print('$context HP Mask      : ${HEX.encode(_mask)}');

    final maskBit = _isLongHeader ? 0x0f : 0x1f;
    firstByte.setUint8(0, firstByte.getUint8(0) ^ (_mask[0] & maskBit));

    for (int i = 0; i < pnBytes.length; i++) {
      pnBytes[i] ^= _mask[i + 1];
    }
  }

  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) =>
      apply(sample, firstByte, pnBytes, '[DEBUG ENCRYPT]');

  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) =>
      apply(sample, firstByte, pnBytes, '[DEBUG DECRYPT]');
}

// ChaChaHeaderProtector is omitted for brevity but should be updated similarly if used.
class ChaChaHeaderProtector implements HeaderProtector {
  // ...
  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {}
  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {}
}
