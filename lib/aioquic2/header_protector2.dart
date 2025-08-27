// Filename: header_protector.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:hex/hex.dart';
import 'cipher_suite.dart';

abstract class HeaderProtector {
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
}

class AesHeaderProtector implements HeaderProtector {
  // Store the key, not the stateful cipher instance.
  final Uint8List _hpKey;
  final bool _isLongHeader;

  AesHeaderProtector(List<int> hpKey, this._isLongHeader)
    : _hpKey = Uint8List.fromList(hpKey);

  static Future<HeaderProtector> create(
    CipherSuite suite,
    List<int> hpKey,
    bool isLongHeader,
  ) async {
    return AesHeaderProtector(hpKey, isLongHeader);
  }

  void _apply(
    Uint8List sample,
    ByteData firstByte,
    Uint8List pnBytes,
    String context,
  ) {
    // Create a new AESEngine instance for every operation to ensure it is stateless.
    final blockCipher = pc.AESEngine()..init(true, pc.KeyParameter(_hpKey));
    final mask = Uint8List(16);

    print('$context HP Sample    : ${HEX.encode(sample)}');
    if (sample.length != 16) {
      throw ArgumentError('Invalid sample size for AES Header Protection');
    }
    blockCipher.processBlock(sample, 0, mask, 0);
    print('$context HP Mask      : ${HEX.encode(mask)}');

    final maskBit = _isLongHeader ? 0x0f : 0x1f;
    firstByte.setUint8(0, firstByte.getUint8(0) ^ (mask[0] & maskBit));

    for (int i = 0; i < pnBytes.length; i++) {
      pnBytes[i] ^= mask[i + 1];
    }
  }

  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) =>
      _apply(sample, firstByte, pnBytes, '[DEBUG ENCRYPT]');

  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) =>
      _apply(sample, firstByte, pnBytes, '[DEBUG DECRYPT]');
}

// ChaChaHeaderProtector should be updated similarly if used.
class ChaChaHeaderProtector implements HeaderProtector {
  // ... implementation ...
  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {}
  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {}
}
