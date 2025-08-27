import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import 'cipher_suite.dart';
import 'header_protector.dart';

/// Encapsulates the logic for sealing (encrypting) a QUIC packet payload and header.
class LongHeaderSealer {
  final XorNonceAEAD aead;
  final HeaderProtector headerProtector;

  LongHeaderSealer(this.aead, this.headerProtector);

  Uint8List seal(Uint8List msg, int packetNumber, Uint8List ad) {
    final pnBytes = _encodePacketNumber(packetNumber);
    return aead.seal(pnBytes, msg, ad);
  }

  void encryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    headerProtector.encryptHeader(sample, firstByte, pnBytes);
  }

  int get overhead => aead.overhead;
}

/// Encapsulates the logic for opening (decrypting) a QUIC packet payload and header.
class LongHeaderOpener {
  final XorNonceAEAD aead;
  final HeaderProtector headerProtector;

  LongHeaderOpener(this.aead, this.headerProtector);

  Uint8List open(Uint8List encrypted, int packetNumber, Uint8List ad) {
    final pnBytes = _encodePacketNumber(packetNumber);
    return aead.open(pnBytes, encrypted, ad);
  }

  void decryptHeader(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    headerProtector.decryptHeader(sample, firstByte, pnBytes);
  }
}

/// Encodes an integer packet number into a 4-byte big-endian representation.
Uint8List _encodePacketNumber(int packetNumber) {
  final data = ByteData(4);
  data.setUint32(0, packetNumber, Endian.big);
  return data.buffer.asUint8List();
}