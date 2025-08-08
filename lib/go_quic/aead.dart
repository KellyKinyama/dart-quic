// lib/aead.dart
import 'dart:math';
import 'dart:typed_data';

import 'cipher_suite.dart';
import 'header_protector.dart';
import 'protocol.dart';

abstract class _LongHeaderSealer {
  Uint8List seal(Uint8List dst, Uint8List src, PacketNumber pn, Uint8List ad);
  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes);
  int get overhead;
}

abstract class _LongHeaderOpener {
  PacketNumber decodePacketNumber(PacketNumber wirePN, int wirePNLen);
  Uint8List open(Uint8List dst, Uint8List src, PacketNumber pn, Uint8List ad);
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
  Uint8List seal(Uint8List dst, Uint8List src, int pn, Uint8List ad) {
    _nonceBuf.setUint64(0, pn, Endian.big);
    return _aead.seal(_nonceBuf.buffer.asUint8List(), src, ad);
  }
}

class LongHeaderOpener implements _LongHeaderOpener {
  final XorNonceAEAD _aead;
  final HeaderProtector _headerProtector;
  PacketNumber _highestRcvdPN = 0;
  final ByteData _nonceBuf = ByteData(8);

  LongHeaderOpener(this._aead, this._headerProtector);

  @override
  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    _headerProtector.decryptHeader(sample, firstByte, pnBytes);
  }

  @override
  PacketNumber decodePacketNumber(PacketNumber wirePN, int wirePNLen) {
    return decodePacketNumber(wirePNLen, _highestRcvdPN);
  }

  @override
  Uint8List open(Uint8List dst, Uint8List src, int pn, Uint8List ad) {
    _nonceBuf.setUint64(0, pn, Endian.big);
    try {
      final decrypted = _aead.open(_nonceBuf.buffer.asUint8List(), src, ad);
      _highestRcvdPN = max(_highestRcvdPN, pn);
      return decrypted;
    } catch (e) {
      throw Errors.decryptionFailed;
    }
  }
}
