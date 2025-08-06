//
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';

import '../../buffer2.dart';
import '../enums.dart';
import '../packet.dart';
// import 'chacha2.dart';
import 'chacha3.dart';
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

// abstract class AEAD {
//   Future<Uint8List> encrypt({
//     required Uint8List plain,
//     required Uint8List associatedData,
//     required Uint8List nonce,
//   });

//   Future<Uint8List> decrypt({
//     required Uint8List encrypted,
//     required Uint8List associatedData,
//     required Uint8List nonce,
//   });
// }

// abstract class HeaderProtection {
//   Future<Uint8List> apply(Uint8List header, Uint8List encryptedPayload);
//   Future<Uint8List> unapply(Uint8List header, Uint8List encryptedPayload);
// }

abstract class HeaderProtection {
  Future<Uint8List> apply(Uint8List header, Uint8List encryptedPayload);
  // This method will now unprotect the header and return the decoded truncated packet number.
  Future<(Uint8List, int)> unprotect(Uint8List packet, int encryptedOffset);
}

class HeaderProtectionChaCha20 extends HeaderProtection {
  final AEAD _cipher;
  final SecretKey _secretKey;
  Uint8List iv;

  HeaderProtectionChaCha20({required Uint8List key, required this.iv})
    : _cipher = ChachaCipher(secretKey: SecretKey(key), iv: iv),
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

  // ✅ CORRECT
  @override
  Future<(Uint8List, int)> unprotect(
    Uint8List packet,
    int encryptedOffset,
  ) async {
    final header = packet.sublist(0, encryptedOffset);
    final payload = packet.sublist(encryptedOffset);

    // The sample for header protection is taken from the first 16 bytes
    // of the payload, starting 4 bytes after the packet number begins.
    // We provisionally assume a 4-byte PN, so the sample is at payload[4:20].
    final sampleOffset = 4;
    if (payload.length < sampleOffset + SAMPLE_SIZE) {
      throw Exception('Payload too short for header protection sample');
    }
    final sample = payload.sublist(sampleOffset, sampleOffset + SAMPLE_SIZE);
    final mask = await _getMask(sample);

    // 1. Unprotect the first byte to find the real packet number length
    final unprotectedHeader = Uint8List.fromList(header); // Make a mutable copy
    if (isLongHeader(unprotectedHeader[0])) {
      unprotectedHeader[0] ^= mask[0] & 0x0F;
    } else {
      unprotectedHeader[0] ^= mask[0] & 0x1F;
    }

    // 2. Now get the actual packet number length
    final pnLength = (unprotectedHeader[0] & 0x03) + 1;
    if (payload.length < pnLength) {
      throw Exception('Payload too short for packet number');
    }

    // 3. Unprotect and decode the packet number
    int truncatedPn = 0;
    for (var i = 0; i < pnLength; ++i) {
      final unprotectedByte = payload[i] ^ mask[1 + i];
      truncatedPn = (truncatedPn << 8) | unprotectedByte;
    }

    return (unprotectedHeader, truncatedPn);
  }
}

class CryptoContext {
  AEAD? _aead;
  CipherSuite? _cipherSuite;
  HeaderProtection? _hp;
  int keyPhase;
  Uint8List? _secret;
  int? _version;
  final Callback setupCb;
  final Callback teardownCb;
  Uint8List? iv;

  CryptoContext({
    this.keyPhase = 0,
    this.setupCb = noCallback,
    this.teardownCb = noCallback,
  });

  // Future<(Uint8List, Uint8List, int)> decryptPacket({
  //   required Uint8List packet,
  //   required int encryptedOffset,
  //   required int expectedPacketNumber,
  // }) async {
  //   if (_aead == null) {
  //     throw Exception('Decryption key is not available');
  //   }

  //   final (unprotectedHeader, pnLength, pnTruncated) = await unprotectHeader(
  //     packet: packet,
  //     encryptedOffset: encryptedOffset,
  //   );

  //   final firstByte = unprotectedHeader[0];
  //   final packetNumber = decodePacketNumber(
  //     pnTruncated,
  //     pnLength * 8,
  //     expectedPacketNumber,
  //   );

  //   var crypto = this;
  //   if (!isLongHeader(firstByte)) {
  //     final keyPhase = (firstByte & 4) >> 2;
  //     if (keyPhase != this.keyPhase) {
  //       crypto = nextKeyPhase(this);
  //     }
  //   }

  //   final nonce = _createNonce(packetNumber);
  //   final payload = await crypto._aead!.decrypt(
  //     packet.sublist(unprotectedHeader.length),
  //     unprotectedHeader,
  //     nonce,
  //   );

  //   return (unprotectedHeader, payload, packetNumber);
  // }

  // ✅ CORRECT
  Future<(Uint8List, Uint8List, int)> decryptPacket({
    required Uint8List packet,
    required int encryptedOffset,
    required int expectedPacketNumber,
  }) async {
    if (_aead == null || _hp == null) {
      throw Exception('Decryption key is not available');
    }

    // 1. Unprotect header and extract truncated packet number
    final (unprotectedHeader, truncatedPn) = await _hp!.unprotect(
      packet,
      encryptedOffset,
    );

    // 2. Decode the full packet number from the truncated value
    final pnLength = (unprotectedHeader[0] & 0x03) + 1;
    final packetNumber = decodePacketNumber(
      truncatedPn,
      pnLength * 8,
      expectedPacketNumber,
    );

    // 3. Handle key phase for 1-RTT packets
    var crypto = this;
    if (!isLongHeader(unprotectedHeader[0])) {
      final keyPhase = (unprotectedHeader[0] & 4) >> 2;
      if (keyPhase != this.keyPhase) {
        crypto = nextKeyPhase(this);
      }
    }

    // 4. Create the correct nonce
    final nonce = crypto._createNonce(packetNumber);

    // 5. Decrypt the payload (ciphertext starts AFTER the packet number)
    final ciphertextOffset = encryptedOffset + pnLength;
    final ciphertext = packet.sublist(ciphertextOffset);

    final payload = await crypto._aead!.decrypt(
      ciphertext,
      unprotectedHeader, // Associated Data is the unprotected header
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
    final protectedPayload = await _aead!.encrypt(
      plainPayload,
      plainHeader,
      nonce,
    );

    return await _hp!.apply(plainHeader, protectedPayload);
  }

  // Uint8List _createNonce(int packetNumber) {
  //   if (iv == null) {
  //     throw Exception('IV is not available');
  //   }

  //   Buffer buffer = Buffer(capacity: 4);
  //   buffer.pushUintVar(packetNumber);
  //   return Uint8List.fromList([...iv!, ...buffer.data]);
  // }

  Uint8List _createNonce(int packetNumber) {
    if (iv == null) {
      throw Exception('IV is not available');
    }
    // Make a mutable copy of the 12-byte IV
    final nonce = Uint8List.fromList(iv!);

    final pnBytes = ByteData(8)..setUint64(0, packetNumber, Endian.big);

    // ✅ CONFIRM THIS XOR LOGIC IS PRESENT
    for (var i = 0; i < 8; i++) {
      nonce[nonce.length - 8 + i] ^= pnBytes.getUint8(i);
    }

    // This must return the 12-byte nonce
    return nonce;
  }

  bool isValid() => _aead != null;

  void setup({
    required CipherSuite cipherSuite,
    required secret,
    required int version,
  }) {
    _cipherSuite = cipherSuite;
    final (key, iv, hpKey) = derive_key_iv_hp(
      cipherSuite: cipherSuite,
      secret: secret,
      version: version,
    );

    switch (cipherSuite) {
      case CipherSuite.AES_256_GCM_SHA384:
        {
          _aead = AesGcm256Cipher(secretKey: SecretKey(key), iv: iv);
        }
      case CipherSuite.CHACHA20_POLY1305_SHA256:
        {
          _aead = ChachaCipher(secretKey: SecretKey(key), iv: iv);
        }
      default:
        {
          _aead = AesGcm128Cipher(secretKey: SecretKey(key), iv: iv);
        }
    }

    _hp = HeaderProtectionChaCha20(key: hpKey, iv: iv);
    this.iv = iv;
    _secret = secret;
    _version = version;
    setupCb("tls");
  }

  void teardown() {
    _aead = null;
    _cipherSuite = null;
    _hp = null;
    _secret = null;
    teardownCb("tls");
  }

  // Future<(Uint8List, int, int)> unprotectHeader({
  //   required Uint8List packet,
  //   required int encryptedOffset,
  // }) async {
  //   // This is a simplified function and may need refinement.
  //   print("encrypted offset: $encryptedOffset");
  //   final header = packet.sublist(0, encryptedOffset);
  //   final pnOffset = header.length - 4; // Placeholder
  //   final protectedHeader = await _hp!.unapply(
  //     header.sublist(0, pnOffset + 4),
  //     packet.sublist(encryptedOffset),
  //   );
  //   final pnLength = (protectedHeader[0] & 0x03) + 1;
  //   final pnTruncated = 0;
  //   return (protectedHeader, pnLength, pnTruncated);
  // }
}

class CryptoPair {
  int aeadTagSize = 16;
  CryptoContext recv;
  CryptoContext send;
  bool _updateKeyRequested = false;

  // CryptoPair({required this.recv, required this.send});

  CryptoPair({
    Callback recvSetupCb = noCallback,
    Callback recvTeardownCb = noCallback,
    Callback sendSetupCb = noCallback,
    Callback sendTeardownCb = noCallback,
  }) : recv = CryptoContext(setupCb: recvSetupCb, teardownCb: recvTeardownCb),
       send = CryptoContext(setupCb: sendSetupCb, teardownCb: sendTeardownCb);

  // factory CryptoPair.forClient({
  //   required Uint8List clientConnectionId,
  //   required Uint8List serverConnectionId,
  //   required QuicProtocolVersion version,
  // }) {
  //   final initialSecret = hkdfExtract(
  //     Uint8List.fromList(INITIAL_SALT_VERSION_1),
  //     salt: Uint8List.fromList(serverConnectionId),
  //   );
  //   final clientSecret = hkdf_expand_label(
  //     initialSecret,
  //     utf8.encode('client in'),
  //     Uint8List(0),
  //     CHACHA20_KEY_SIZE,
  //   );
  //   final serverSecret = hkdf_expand_label(
  //     initialSecret,
  //     utf8.encode('server in'),
  //     Uint8List(0),
  //     CHACHA20_KEY_SIZE,
  //   );

  //   final recv = CryptoContext();
  //   recv.setup(
  //     cipherSuite: INITIAL_CIPHER_SUITE,
  //     secret: serverSecret,
  //     version: version.value,
  //   );
  //   final send = CryptoContext();
  //   send.setup(
  //     cipherSuite: INITIAL_CIPHER_SUITE,
  //     secret: clientSecret,
  //     version: version.value,
  //   );

  //   return CryptoPair(recv: recv, send: send);
  // }

  // factory CryptoPair.forServer({
  //   required Uint8List clientConnectionId,
  //   required Uint8List serverConnectionId,
  //   required QuicProtocolVersion version,
  // }) {
  //   final initialSecret = hkdfExtract(
  //     Uint8List.fromList(INITIAL_SALT_VERSION_1),
  //     salt: Uint8List.fromList(serverConnectionId),
  //   );
  //   final clientSecret = hkdf_expand_label(
  //     initialSecret,
  //     utf8.encode('client in'),
  //     Uint8List(0),
  //     CHACHA20_KEY_SIZE,
  //   );
  //   final serverSecret = hkdf_expand_label(
  //     initialSecret,
  //     utf8.encode('server in'),
  //     Uint8List(0),
  //     CHACHA20_KEY_SIZE,
  //   );

  //   final recv = CryptoContext();
  //   recv.setup(
  //     cipherSuite: INITIAL_CIPHER_SUITE,
  //     secret: clientSecret,
  //     version: version.value,
  //   );
  //   final send = CryptoContext();
  //   send.setup(
  //     cipherSuite: INITIAL_CIPHER_SUITE,
  //     secret: serverSecret,
  //     version: version.value,
  //   );

  //   return CryptoPair(recv: recv, send: send);
  // }

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
    self._aead = crypto._aead;
    self.keyPhase = crypto.keyPhase;
    self._secret = crypto._secret;
    self.iv = crypto.iv;
    self._hp = crypto._hp;
    self._cipherSuite = crypto._cipherSuite;
    self._version = crypto._version;
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
    cipherSuite: self._cipherSuite!,
    secret: hkdf_expand_label(
      self._secret!,
      utf8.encode('quic ku'),
      Uint8List(0),
      CHACHA20_KEY_SIZE,
    ),
    version: self._version!,
  );
  return crypto;
}
