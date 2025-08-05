//
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';

import '../../buffer.dart';
import '../enums.dart';
import '../packet.dart';
import 'chacha2.dart';
import 'hkdf.dart';

typedef Callback = void Function(String trigger);

void noCallback(String trigger) {}

const PACKET_NUMBER_LENGTH_MAX = 4;
final INITIAL_SALT_VERSION_1 = hex.decode(
  "38762cf7f55934b34d179ae6a4c80cadccbb7f0a",
);
const SAMPLE_SIZE = 16;
const CHACHA20_KEY_SIZE = 32;

// enum CipherSuite {
//   AES_128_GCM_SHA256(0x1301),
//   AES_256_GCM_SHA384(0x1302),
//   CHACHA20_POLY1305_SHA256(0x1303),
//   EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF);

//   final int value;
//   const CipherSuite(this.value);
// }

const INITIAL_CIPHER_SUITE = CipherSuite.CHACHA20_POLY1305_SHA256;

abstract class AEAD {
  Future<Uint8List> encrypt({
    required Uint8List plain,
    required Uint8List associatedData,
    required Uint8List nonce,
  });

  Future<Uint8List> decrypt({
    required Uint8List encrypted,
    required Uint8List associatedData,
    required Uint8List nonce,
  });
}

abstract class HeaderProtection {
  Future<Uint8List> apply(Uint8List header, Uint8List encryptedPayload);
  Future<Uint8List> unapply(Uint8List header, Uint8List encryptedPayload);
}

class HeaderProtectionChaCha20 extends HeaderProtection {
  final ChachaCipher _cipher;
  final SecretKey _secretKey;

  HeaderProtectionChaCha20({required Uint8List key})
    : _cipher = ChachaCipher("chacha20", secret: key),
      _secretKey = SecretKey(key);

  @override
  Future<Uint8List> apply(Uint8List header, Uint8List encryptedPayload) async {
    final (pnLength, pnOffset) = _getPacketNumberDetails(header);
    final sample = _getSample(encryptedPayload, pnLength);
    final mask = await _getMask(sample);
    return _applyMask(header, mask, pnLength, pnOffset);
  }

  @override
  Future<Uint8List> unapply(
    Uint8List header,
    Uint8List encryptedPayload,
  ) async {
    final (pnLength, pnOffset) = _getPacketNumberDetails(header);
    final sample = _getSample(encryptedPayload, pnLength);
    final mask = await _getMask(sample);
    return _applyMask(header, mask, pnLength, pnOffset);
  }

  (int, int) _getPacketNumberDetails(Uint8List header) {
    final pnLength = (header[0] & 0x03) + 1;
    final pnOffset = header.length - pnLength;
    return (pnLength, pnOffset);
  }

  Uint8List _getSample(Uint8List encryptedPayload, int pnLength) {
    final sampleOffset = 4 - pnLength;
    if (encryptedPayload.length < sampleOffset + SAMPLE_SIZE) {
      throw Exception('Payload is too short for header protection');
    }
    return encryptedPayload.sublist(sampleOffset, sampleOffset + SAMPLE_SIZE);
  }

  Future<Uint8List> _getMask(Uint8List sample) async {
    final nonce = Uint8List.fromList(sample.sublist(4, 16));
    final keyStream = await _cipher.encrypt(
      Uint8List(5),
      Uint8List(0), // associatedData is empty for header protection
      // secretKey: _secretKey,
      nonce,
    );
    return Uint8List.fromList(keyStream);
  }

  Uint8List _applyMask(
    Uint8List header,
    Uint8List mask,
    int pnLength,
    int pnOffset,
  ) {
    final maskedHeader = Uint8List.fromList(header);
    maskedHeader[0] ^= isLongHeader(maskedHeader[0])
        ? (mask[0] & 0x0F)
        : (mask[0] & 0x1F);
    for (var i = 0; i < pnLength; ++i) {
      maskedHeader[pnOffset + i] ^= mask[1 + i];
    }
    return maskedHeader;
  }
}

class CryptoContext {
  ChachaCipher? aead;
  CipherSuite? cipherSuite;
  HeaderProtection? hp;
  int keyPhase;
  Uint8List? secret;
  int? version;
  final Callback setupCb;
  final Callback teardownCb;
  Uint8List? iv;

  CryptoContext({
    this.keyPhase = 0,
    this.setupCb = noCallback,
    this.teardownCb = noCallback,
  });

  Future<(Uint8List, Uint8List, int)> decryptPacket({
    required Uint8List packet,
    required int encryptedOffset,
    required int expectedPacketNumber,
  }) async {
    if (aead == null) {
      throw Exception('Decryption key is not available');
    }

    final (unprotectedHeader, pnLength, pnTruncated) = await unprotectHeader(
      packet: packet,
      encryptedOffset: encryptedOffset,
    );

    final firstByte = unprotectedHeader[0];
    final packetNumber = decodePacketNumber(
      pnTruncated,
      pnLength * 8,
      expectedPacketNumber,
    );

    var crypto = this;
    if (!isLongHeader(firstByte)) {
      final keyPhase = (firstByte & 4) >> 2;
      if (keyPhase != this.keyPhase) {
        crypto = nextKeyPhase(this);
      }
    }

    final nonce = _createNonce(packetNumber);
    final payload = await crypto.aead!.decrypt(
      packet.sublist(unprotectedHeader.length),
      unprotectedHeader,
      nonce,
    );

    return (unprotectedHeader, payload, packetNumber);
  }

  Future<Uint8List> encryptPacket({
    required Uint8List plainHeader,
    required Uint8List plainPayload,
    required int packetNumber,
  }) async {
    if (!isValid()) {
      throw Exception('Encryption key is not available');
    }

    final nonce = _createNonce(packetNumber);
    final protectedPayload = await aead!.encrypt(
      plainPayload,
      plainHeader,
      nonce,
    );

    return await hp!.apply(plainHeader, protectedPayload);
  }

  Uint8List _createNonce(int packetNumber) {
    if (iv == null) {
      throw Exception('IV is not available');
    }

    Buffer buffer = Buffer(capacity: 4);
    buffer.pushUintVar(packetNumber);
    return Uint8List.fromList([...iv!, ...buffer.data]);
  }

  bool isValid() => aead != null;

  void setup({
    required CipherSuite cipherSuite,
    required Uint8List secret,
    required int version,
  }) {
    final (key, iv, hpKey) = derive_key_iv_hp(
      cipherSuite: cipherSuite,
      secret: secret,
      version: version,
    );
    this.aead = ChachaCipher("chacha20", secret: key);
    this.cipherSuite = cipherSuite;
    this.hp = HeaderProtectionChaCha20(key: hpKey);
    this.iv = iv;
    this.secret = secret;
    this.version = version;
    setupCb("tls");
  }

  void teardown() {
    aead = null;
    cipherSuite = null;
    hp = null;
    secret = null;
    teardownCb("tls");
  }

  Future<(Uint8List, int, int)> unprotectHeader({
    required Uint8List packet,
    required int encryptedOffset,
  }) async {
    // This is a simplified function and may need refinement.
    final header = packet.sublist(0, encryptedOffset);
    final pnOffset = header.length - 4; // Placeholder
    final protectedHeader = await hp!.unapply(
      header.sublist(0, pnOffset + 4),
      packet.sublist(encryptedOffset),
    );
    final pnLength = (protectedHeader[0] & 0x03) + 1;
    final pnTruncated = 0;
    return (protectedHeader, pnLength, pnTruncated);
  }
}

class CryptoPair {
  int aeadTagSize = 16;
  CryptoContext recv;
  CryptoContext send;
  bool _updateKeyRequested = false;

  CryptoPair({required this.recv, required this.send});

  factory CryptoPair.forClient({
    required Uint8List clientConnectionId,
    required Uint8List serverConnectionId,
    required QuicProtocolVersion version,
  }) {
    final initialSecret = hkdfExtract(
      Uint8List.fromList(INITIAL_SALT_VERSION_1),
      salt: Uint8List.fromList(serverConnectionId),
    );
    final clientSecret = hkdf_expand_label(
      initialSecret,
      utf8.encode('client in'),
      Uint8List(0),
      CHACHA20_KEY_SIZE,
    );
    final serverSecret = hkdf_expand_label(
      initialSecret,
      utf8.encode('server in'),
      Uint8List(0),
      CHACHA20_KEY_SIZE,
    );

    final recv = CryptoContext();
    recv.setup(
      cipherSuite: INITIAL_CIPHER_SUITE,
      secret: serverSecret,
      version: version.value,
    );
    final send = CryptoContext();
    send.setup(
      cipherSuite: INITIAL_CIPHER_SUITE,
      secret: clientSecret,
      version: version.value,
    );

    return CryptoPair(recv: recv, send: send);
  }

  factory CryptoPair.forServer({
    required Uint8List clientConnectionId,
    required Uint8List serverConnectionId,
    required QuicProtocolVersion version,
  }) {
    final initialSecret = hkdfExtract(
      Uint8List.fromList(INITIAL_SALT_VERSION_1),
      salt: Uint8List.fromList(serverConnectionId),
    );
    final clientSecret = hkdf_expand_label(
      initialSecret,
      utf8.encode('client in'),
      Uint8List(0),
      CHACHA20_KEY_SIZE,
    );
    final serverSecret = hkdf_expand_label(
      initialSecret,
      utf8.encode('server in'),
      Uint8List(0),
      CHACHA20_KEY_SIZE,
    );

    final recv = CryptoContext();
    recv.setup(
      cipherSuite: INITIAL_CIPHER_SUITE,
      secret: clientSecret,
      version: version.value,
    );
    final send = CryptoContext();
    send.setup(
      cipherSuite: INITIAL_CIPHER_SUITE,
      secret: serverSecret,
      version: version.value,
    );

    return CryptoPair(recv: recv, send: send);
  }

  Future<Uint8List> decryptPacket({
    required Uint8List packet,
    required int encryptedOffset,
    required int expectedPacketNumber,
  }) async {
    final (result, _, _) = await recv.decryptPacket(
      packet: packet,
      encryptedOffset: encryptedOffset,
      expectedPacketNumber: expectedPacketNumber,
    );
    return result;
  }

  Future<Uint8List> encryptPacket({
    required Uint8List plainHeader,
    required Uint8List plainPayload,
    required int packetNumber,
  }) async {
    return await send.encryptPacket(
      plainHeader: plainHeader,
      plainPayload: plainPayload,
      packetNumber: packetNumber,
    );
  }

  void _updateKey(String trigger) {
    applyKeyPhase(recv, nextKeyPhase(recv));
    applyKeyPhase(send, nextKeyPhase(send));
    _updateKeyRequested = false;
  }

  void applyKeyPhase(CryptoContext self, CryptoContext crypto) {
    self.aead = crypto.aead;
    self.keyPhase = crypto.keyPhase;
    self.secret = crypto.secret;
    self.iv = crypto.iv;
    self.hp = crypto.hp;
    self.cipherSuite = crypto.cipherSuite;
    self.version = crypto.version;
    self.setupCb("local_update");
  }

  void updateKey() {
    _updateKey("local_update");
  }

  int get keyPhase {
    if (_updateKeyRequested) {
      return 1 - recv.keyPhase;
    }
    return recv.keyPhase;
  }
}

CryptoContext nextKeyPhase(CryptoContext self) {
  final crypto = CryptoContext(keyPhase: self.keyPhase == 0 ? 1 : 0);
  crypto.setup(
    cipherSuite: self.cipherSuite!,
    secret: hkdf_expand_label(
      self.secret!,
      utf8.encode('quic ku'),
      Uint8List(0),
      CHACHA20_KEY_SIZE,
    ),
    version: self.version!,
  );
  return crypto;
}
