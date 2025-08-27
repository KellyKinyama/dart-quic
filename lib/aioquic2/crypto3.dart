// Filename: crypto.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'cipher_suite.dart';
import 'header_protector.dart';
import 'hkdf2.dart';
import 'interface.dart';

class CryptoContext {
  XorNonceAead? aead;
  HeaderProtector? hp;

  Future<void> setup({
    required CipherSuite suite,
    required List<int> secret,
    required bool isLongHeader,
  }) async {
    final key = await hkdfExpandLabel(
      suite.hash,
      secret,
      [],
      'quic key',
      suite.keyLen,
    );
    final iv = await hkdfExpandLabel(
      suite.hash,
      secret,
      [],
      'quic iv',
      suite.ivLen,
    );
    final hpKey = await hkdfExpandLabel(
      suite.hash,
      secret,
      [],
      'quic hp',
      suite.keyLen,
    );

    final secretKey = SecretKeyData(key);
    final aeadCipher = suite.aeadFactory();
    this.aead = XorNonceAead(aeadCipher, secretKey, iv);
    this.hp = await AesHeaderProtector.create(suite, hpKey, isLongHeader);
  }

  Future<Uint8List> encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) async {
    final protectedPayload = await aead!.seal(
      plainPayload,
      _packetNumberToNonce(packetNumber),
      plainHeader,
    );
    final pnLength = (plainHeader[0] & 0x03) + 1;
    final sampleOffset = 4 - pnLength;
    final sample = protectedPayload.sublist(sampleOffset, sampleOffset + 16);
    final protectedHeader = Uint8List.fromList(plainHeader);
    await hp!.apply(
      ByteData.sublistView(protectedHeader),
      protectedHeader.sublist(protectedHeader.length - pnLength),
      sample,
    );
    return Uint8List.fromList([...protectedHeader, ...protectedPayload]);
  }

  Future<(Uint8List, Uint8List, int)> decryptPacket(
    Uint8List packet,
    int pnOffset,
    int expectedPn,
  ) async {
    final headerToDeprotect = packet.sublist(0, pnOffset + 4);
    final sample = packet.sublist(pnOffset + 4, pnOffset + 20);
    final firstByteView = ByteData.sublistView(headerToDeprotect);
    final pnBytesView = headerToDeprotect.sublist(pnOffset);
    await hp!.apply(firstByteView, pnBytesView, sample);

    final pnLength = (firstByteView.getUint8(0) & 0x03) + 1;
    final plainHeader = headerToDeprotect.sublist(0, pnOffset + pnLength);
    final protectedPayload = packet.sublist(pnOffset + pnLength);

    int truncatedPn = 0;
    for (int i = 0; i < pnLength; i++) {
      truncatedPn = (truncatedPn << 8) | pnBytesView[i];
    }
    final packetNumber = _decodePacketNumber(
      truncatedPn,
      pnLength * 8,
      expectedPn,
    );
    final plainPayload = await aead!.open(
      protectedPayload,
      _packetNumberToNonce(packetNumber),
      plainHeader,
    );

    return (plainHeader, plainPayload, packetNumber);
  }

  Uint8List _packetNumberToNonce(int n) {
    final byteData = ByteData(8)..setUint64(0, n, Endian.big);
    return byteData.buffer.asUint8List();
  }

  int _decodePacketNumber(int truncated, int numBits, int expected) {
    final window = 1 << numBits;
    final halfWindow = window ~/ 2;
    final candidate = (expected & ~(window - 1)) | truncated;
    if (candidate <= expected - halfWindow) return candidate + window;
    if (candidate > expected + halfWindow) return candidate - window;
    return candidate;
  }
}

class CryptoPair {
  final send = CryptoContext();
  final recv = CryptoContext();

  Future<void> setupInitial({
    required Uint8List cid,
    required bool isClient,
  }) async {
    final salt = Uint8List.fromList([
      0x38,
      0x76,
      0x2c,
      0xf7,
      0xf5,
      0x59,
      0x34,
      0xb3,
      0x4d,
      0x17,
      0x9a,
      0xe6,
      0xa4,
      0xc8,
      0x0c,
      0xad,
      0xcc,
      0xbb,
      0x7f,
      0x0a,
    ]);

    final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
    final prk = await hkdf.deriveKey(
      secretKey: SecretKeyData(cid),
      nonce: salt,
    );
    final initialSecretBytes = await prk.extractBytes();

    final clientSecret = await hkdfExpandLabel(
      Sha256(),
      initialSecretBytes,
      [],
      'client in',
      32,
    );
    final serverSecret = await hkdfExpandLabel(
      Sha256(),
      initialSecretBytes,
      [],
      'server in',
      32,
    );

    final sendSecret = isClient ? clientSecret : serverSecret;
    final recvSecret = isClient ? serverSecret : clientSecret;

    await send.setup(
      suite: CipherSuite.getById(0x1301),
      secret: sendSecret,
      isLongHeader: true,
    );
    await recv.setup(
      suite: CipherSuite.getById(0x1301),
      secret: recvSecret,
      isLongHeader: true,
    );
  }
}
