// Filename: header_protector.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:hex/hex.dart'; // Required for printing hex strings
import 'cipher_suite.dart';

/// An interface for QUIC Header Protection.
abstract class HeaderProtector {
  /// Encrypts the header's first byte and packet number.
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);

  /// Decrypts the header's first byte and packet number.
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
}

/// An implementation of QUIC Header Protection using AES-ECB.
class AesHeaderProtector implements HeaderProtector {
  final pc.BlockCipher _blockCipher;
  final bool _isLongHeader;
  final Uint8List _mask;

  AesHeaderProtector(this._blockCipher, this._isLongHeader)
    : _mask = Uint8List(16);

  /// Creates and initializes an AesHeaderProtector with the given key.
  static Future<HeaderProtector> create(
    CipherSuite suite,
    List<int> hpKey,
    bool isLongHeader,
  ) async {
    final blockCipher = pc.AESEngine()
      ..init(true, pc.KeyParameter(Uint8List.fromList(hpKey)));
    return AesHeaderProtector(blockCipher, isLongHeader);
  }

  /// Applies the header protection mask to the given header bytes.
  void _applyMask(
    Uint8List sample,
    ByteData firstByte,
    Uint8List pnBytes,
    String context,
  ) {
    if (sample.length != 16) {
      throw ArgumentError(
        'Invalid sample size for AES Header Protection. Must be 16 bytes.',
      );
    }

    // --- Start of Debugging Lines ---
    print('$context HP Sample    : ${HEX.encode(sample)}');
    // --- End of Debugging Lines ---

    // Generate the mask by encrypting the sample with the hpKey.
    _blockCipher.processBlock(sample, 0, _mask, 0);

    // --- Start of Debugging Lines ---
    print('$context HP Mask      : ${HEX.encode(_mask)}');
    // --- End of Debugging Lines ---

    // Determine which bits of the first byte to protect based on header type.
    final maskBit = _isLongHeader ? 0x0f : 0x1f;
    firstByte.setUint8(0, firstByte.getUint8(0) ^ (_mask[0] & maskBit));

    // Protect the packet number bytes.
    for (int i = 0; i < pnBytes.length; i++) {
      pnBytes[i] ^= _mask[i + 1];
    }
  }

  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) =>
      _applyMask(sample, firstByte, pnBytes, '[DEBUG ENCRYPT]');

  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) =>
      _applyMask(sample, firstByte, pnBytes, '[DEBUG DECRYPT]');
}

/// A ChaCha20-based header protector (implementation can be added if needed).
class ChaChaHeaderProtector implements HeaderProtector {
  // This class can be fully implemented if support for ChaCha20 cipher suites is required.
  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {
    throw UnimplementedError("ChaChaHeaderProtector is not yet implemented.");
  }

  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {
    throw UnimplementedError("ChaChaHeaderProtector is not yet implemented.");
  }
}
