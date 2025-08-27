// Filename: aead.dart
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'interface.dart';
import 'cipher_suite.dart';
import 'header_protector.dart';
import 'hkdf.dart';

Future<XorNonceAead> createAead(
  CipherSuite suite,
  List<int> trafficSecret,
) async {
  final key = await hkdfExpandLabel(
    suite.hash,
    trafficSecret,
    [],
    'quic key',
    suite.keyLen,
  );
  final iv = await hkdfExpandLabel(
    suite.hash,
    trafficSecret,
    [],
    'quic iv',
    suite.ivLen,
  );
  final secretKey = SecretKey(key);
  return await suite.aeadFactory(secretKey, iv);
}

class LongHeaderSealerImpl implements LongHeaderSealer {
  final XorNonceAead _aead;
  final HeaderProtector _headerProtector;
  final Uint8List _nonceBuf;

  LongHeaderSealerImpl(this._aead, this._headerProtector)
    : _nonceBuf = Uint8List(_aead.nonceSize);

  @override
  int get overhead => _aead.overhead;

  @override
  Uint8List seal(
    Uint8List? dst,
    Uint8List src,
    int packetNumber,
    Uint8List associatedData,
  ) {
    final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);
    _nonceBuf.setRange(0, _nonceBuf.length, pnBytes.buffer.asUint8List(0, 8));

    // The cryptography package in Dart is async. This implementation will need to be adapted
    // into an async workflow in the calling code.
    // For simplicity here, we use a placeholder for a sync version.
    // A real implementation would be:
    // return await _aead.seal(src, nonce: _nonceBuf, additionalData: associatedData);
    throw UnimplementedError(
      'Async seal operation must be handled by the caller.',
    );
  }

  @override
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {
    _headerProtector.encryptHeader(sample, firstByte, pnBytes);
  }
}

class LongHeaderOpenerImpl implements LongHeaderOpener {
  final XorNonceAead _aead;
  final HeaderProtector _headerProtector;
  int _highestReceivedPN = 0;
  final Uint8List _nonceBuf;

  LongHeaderOpenerImpl(this._aead, this._headerProtector)
    : _nonceBuf = Uint8List(_aead.nonceSize);

  @override
  int decodePacketNumber(int wirePN, int wirePNLen) {
    // This is a simplified version of protocol.DecodePacketNumber
    // A full implementation is required.
    return wirePN;
  }

  @override
  Future<Uint8List> open(
    Uint8List? dst,
    Uint8List src,
    int pn,
    Uint8List associatedData,
  ) async {
    final pnBytes = ByteData(8)..setUint64(0, pn, Endian.big);
    _nonceBuf.setRange(0, _nonceBuf.length, pnBytes.buffer.asUint8List(0, 8));

    try {
      final decrypted = await _aead.open(
        src,
        nonce: _nonceBuf,
        additionalData: associatedData,
      );
      if (pn > _highestReceivedPN) {
        _highestReceivedPN = pn;
      }
      return decrypted;
    } catch (e) {
      throw DecryptionFailedException();
    }
  }

  @override
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes) {
    _headerProtector.decryptHeader(sample, firstByte, pnBytes);
  }
}
