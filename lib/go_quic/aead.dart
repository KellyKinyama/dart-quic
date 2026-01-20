// lib/aead.dart
import 'dart:math';
import 'dart:typed_data';

import 'cipher_suite.dart';
import 'header_protector2.dart';
import 'protocol.dart' as protocol;
import 'protocol.dart';

abstract class _LongHeaderSealer {
  Uint8List seal(Uint8List message, PacketNumber pn, Uint8List ad);
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes);
  int get overhead;
}

abstract class _LongHeaderOpener {
  PacketNumber decodePacketNumber(PacketNumber wirePN, int wirePNLen);
  Uint8List open(Uint8List cipherText, PacketNumber pn, Uint8List ad);
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes);
}

class LongHeaderSealer implements _LongHeaderSealer {
  final XorNonceAEAD _aead;
  final HeaderProtector _headerProtector;
  final ByteData _nonceBuf = ByteData(8);

  LongHeaderSealer(this._aead, this._headerProtector);

  @override
  int get overhead => _aead.overhead;

  @override
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    _headerProtector.encryptHeader(sample, firstByte, pnBytes);
  }

  @override
  Uint8List seal(Uint8List message, int pn, Uint8List ad) {
    // print("Called LongHeaderSealer: seal: pn: $pn");
    _nonceBuf.setUint64(0, pn, Endian.big);
    final generatedNonce = _nonceBuf.buffer.asUint8List();

    // print("nonce: $generatedNonce");
    // print("aead: $ad");

    return _aead.seal(generatedNonce, message, ad);
  }
}

class LongHeaderOpener implements _LongHeaderOpener {
  final XorNonceAEAD _aead;
  final HeaderProtector _headerProtector;
  PacketNumber _highestRcvdPN = 0;
  final ByteData _nonceBuf = ByteData(8);

  LongHeaderOpener(this._aead, this._headerProtector);

  get mask => _headerProtector.mask;

  @override
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    _headerProtector.decryptHeader(sample, firstByte, pnBytes);
  }

  @override
  PacketNumber decodePacketNumber(PacketNumber wirePN, int wirePNLen) {
    return protocol.decodePacketNumber(wirePNLen, _highestRcvdPN, wirePN);
  }

  @override
  Uint8List open(Uint8List cipherText, int pn, Uint8List ad) {
    _nonceBuf.setUint64(0, pn, Endian.big);

    final generatedNonce = _nonceBuf.buffer.asUint8List();
    // print("nonce: $generatedNonce");
    // print("aead: $ad");
    try {
      final decrypted = _aead.open(generatedNonce, cipherText, ad);
      _highestRcvdPN = max(_highestRcvdPN, pn);
      return decrypted;
    } catch (e, st) {
      print('\nError: $e, Stack trace: $st');
      throw Errors.decryptionFailed;
    }
  }
}
