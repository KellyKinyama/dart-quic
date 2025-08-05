import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
// import 'package:dart_quic/aioquic/quic/crypto.dart';
// import 'package:dart_quic/aioquic/quic/crypto.dart';
import 'package:dart_quic/aioquic/quic/crypto/chacha.dart';

import '../../buffer.dart';
import '../enums.dart';
import '../packet.dart';
import 'hkdf.dart';

// Assuming these are external classes/functions from other parts of the library.
const PACKET_NUMBER_LENGTH_MAX = 4;

typedef Callback = void Function(String trigger);
void noCallback(String trigger) {}

// enum CipherSuite {
//   AES_128_GCM_SHA256(0x1301),
//   AES_256_GCM_SHA384(0x1302),
//   CHACHA20_POLY1305_SHA256(0x1303),
//   EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF);

//   final int value;
//   const CipherSuite(this.value);
// }

const CIPHER_SUITES = {
  CipherSuite.AES_128_GCM_SHA256: ("aes-128-ecb", "aes-128-gcm"),
  CipherSuite.AES_256_GCM_SHA384: ("aes-256-ecb", "aes-256-gcm"),
  CipherSuite.CHACHA20_POLY1305_SHA256: ("chacha20", "chacha20-poly1305"),
};

const INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256;
final INITIAL_SALT_VERSION_1 = utf8.encode(
  "38762cf7f55934b34d179ae6a4c80cadccbb7f0a",
);
final INITIAL_SALT_VERSION_2 = utf8.encode(
  "0dede3def700a6db819381be6e269dcbf9bd2ed9",
);
const SAMPLE_SIZE = 16;

abstract class AEAD {
  Future<Uint8List> encrypt(
    Uint8List plain,
    Uint8List associatedData,
    Uint8List nonce,
  );
  Future<Uint8List> decrypt(
    Uint8List encrypted,
    Uint8List associatedData,
    Uint8List nonce,
  );
}

/// A conceptual implementation of the HeaderProtection cryptographic object.
class HeaderProtection {
  final String _cipherName;
  final Uint8List _key;
  final bool _isChacha20;
  final Uint8List _mask = Uint8List(31);
  final Uint8List _zero = Uint8List(5);

  HeaderProtection({required String cipherName, required Uint8List key})
    : _cipherName = cipherName,
      _key = key,
      _isChacha20 = cipherName == 'chacha20' {
    // In a real-world scenario, we would initialize the cipher here.
  }

  Future<Uint8List> _maskHeader({required Uint8List sample}) async {
    // Conceptual implementation of `HeaderProtection_mask`
    // In a real implementation, this would use a cryptographic library.
    Uint8List mask;
    if (_isChacha20) {
      // This is a simplification; ChaCha20 uses a different key stream generation.
      final cipher = //Cipher('ChaCha20')..init(key: _key, nonce: sample);
      ChachaCipher(
        'ChaCha20',
        secret: _key,
        iv: sample,
      );

      print("Nonce length: ${sample.length}");

      mask = Uint8List.fromList(
        await cipher.encrypt(_zero, Uint8List(0), sample),
      ); //.then((
      //   encrypted,
      // ) {
      //   mask = Uint8List.fromList(encrypted.cipherText);
      // });
      // mask = cipher.process(_zero);
    } else {
      throw UnimplementedError("AES/ECB is not implemented");
      // final cipher = Cipher('AES/ECB')..init(key: _key);
      // mask = cipher.process(sample.sublist(0, sampleLength));
    }
    return mask;
  }

  Future<Uint8List> apply({
    required Uint8List header,
    required Uint8List payload,
  }) async {
    final pnLength = (header[0] & 0x03) + 1;
    final pnOffset = header.length - pnLength;
    final sample = payload.sublist(PACKET_NUMBER_LENGTH_MAX - pnLength);

    final mask = await _maskHeader(sample: sample);

    final buffer = Uint8List(header.length + payload.length);
    buffer.setAll(0, header);
    buffer.setAll(header.length, payload);

    if ((buffer[0] & 0x80) != 0) {
      buffer[0] ^= mask[0] & 0x0F;
    } else {
      buffer[0] ^= mask[0] & 0x1F;
    }

    for (var i = 0; i < pnLength; ++i) {
      buffer[pnOffset + i] ^= mask[1 + i];
    }
    return buffer;
  }

  Future<(Uint8List, int, int)> remove({
    required Uint8List packet,
    required int pnOffset,
  }) async {
    final sample = packet.sublist(pnOffset + PACKET_NUMBER_LENGTH_MAX);

    final mask = await _maskHeader(sample: sample);

    final buffer = Uint8List(pnOffset + PACKET_NUMBER_LENGTH_MAX);
    buffer.setAll(0, packet.sublist(0, pnOffset + PACKET_NUMBER_LENGTH_MAX));

    if ((buffer[0] & 0x80) != 0) {
      buffer[0] ^= mask[0] & 0x0F;
    } else {
      buffer[0] ^= mask[0] & 0x1F;
    }

    final pnLength = (buffer[0] & 0x03) + 1;
    var pnTruncated = 0;
    for (var i = 0; i < pnLength; ++i) {
      buffer[pnOffset + i] ^= mask[1 + i];
      pnTruncated |= buffer[pnOffset + i] << (8 * (pnLength - 1 - i));
    }

    return (buffer.sublist(0, pnOffset + pnLength), pnLength, pnTruncated);
  }
}

class CryptoContext {
  AEAD? aead;
  CipherSuite? cipherSuite;
  HeaderProtection? hp;
  int keyPhase;
  Uint8List? secret;
  int? version;
  final Callback setupCb;
  final Callback teardownCb;

  CryptoContext({
    this.keyPhase = 0,
    this.setupCb = noCallback,
    this.teardownCb = noCallback,
  });

  Future<(Uint8List, Uint8List, int, bool)> decryptPacket(
    Uint8List packet,
    int encryptedOffset,
    int expectedPacketNumber,
  ) async {
    if (aead == null) {
      throw Exception("Decryption key is not available");
    }

    final (plainHeader, packetNumberBytes, pnTruncated) = await hp!.remove(
      packet: packet,
      pnOffset: encryptedOffset,
    );
    // final plainHeader = headerProtection.item1;
    // final packetNumberBytes = headerProtection.item2;
    final firstByte = plainHeader[0];

    final pnLength = (firstByte & 0x03) + 1;
    final packetNumber = decodePacketNumber(
      packetNumberBytes,
      pnLength * 8,
      expectedPacketNumber,
    );

    var crypto = this;
    var updateKey = false;
    if (!isLongHeader(firstByte)) {
      final keyPhase = (firstByte & 4) >> 2;
      if (keyPhase != this.keyPhase) {
        crypto = nextKeyPhase(this);
        updateKey = true;
      }
    }

    final pnBuffer = Buffer(capacity: 12);

    pnBuffer.pushUintVar(packetNumber);
    final payload = await crypto.aead!.decrypt(
      packet.sublist(plainHeader.length),
      plainHeader,
      pnBuffer.data,
    );

    return (plainHeader, payload, packetNumber, updateKey);
  }

  Future<Uint8List> encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) async {
    if (!isValid()) {
      throw Exception("Encryption key is not available");
    }

    final pnBuffer = Buffer(capacity: 12);

    pnBuffer.pushUintVar(packetNumber);

    final protectedPayload = await aead!.encrypt(
      plainPayload,
      plainHeader,
      pnBuffer.data,
    );

    return await hp!.apply(header: plainHeader, payload: protectedPayload);
  }

  bool isValid() => aead != null;

  void setup({
    required CipherSuite cipherSuite,
    required Uint8List secret,
    required int version,
  }) {
    final (hpCipherName, aeadCipherName) = CIPHER_SUITES[cipherSuite]!;

    final (key, iv, hp) = derive_key_iv_hp(
      cipherSuite: cipherSuite,
      secret: secret,
      version: version,
    );
    this.aead = ChachaCipher(aeadCipherName, secret: key, iv: iv);
    this.cipherSuite = cipherSuite;
    this.hp = HeaderProtection(cipherName: hpCipherName, key: hp);
    this.secret = secret;
    this.version = version;

    print("Receive iv length: ${iv.lengthInBytes}");

    setupCb("tls");
  }

  void teardown() {
    aead = null;
    cipherSuite = null;
    hp = null;
    secret = null;

    teardownCb("tls");
  }
}

class CryptoPair {
  int aeadTagSize = 16;
  CryptoContext recv;
  CryptoContext send;
  bool _updateKeyRequested = false;

  CryptoPair({
    Callback recvSetupCb = noCallback,
    Callback recvTeardownCb = noCallback,
    Callback sendSetupCb = noCallback,
    Callback sendTeardownCb = noCallback,
  }) : recv = CryptoContext(setupCb: recvSetupCb, teardownCb: recvTeardownCb),
       send = CryptoContext(setupCb: sendSetupCb, teardownCb: sendTeardownCb);

  Future<(Uint8List, Uint8List, int)> decrypt_packet({
    required Uint8List packet,
    required int encrypted_offset,
    required expected_packet_number,
  }) async {
    final (plain_header, payload, packet_number, update_key) = await recv
        .decryptPacket(packet, encrypted_offset, expected_packet_number);
    if (update_key) {
      _update_key("remote_update");
    }
    return (plain_header, payload, packet_number);
  }

  void _update_key(String trigger) {
    applyKeyPhase(recv, nextKeyPhase(recv), trigger: trigger);
    applyKeyPhase(send, nextKeyPhase(send), trigger: trigger);
    _updateKeyRequested = false;
  }

  void applyKeyPhase(
    CryptoContext self,
    CryptoContext crypto, {
    required String trigger,
  }) {
    self.aead = crypto.aead;
    self.keyPhase = crypto.keyPhase;
    self.secret = crypto.secret;

    self.setupCb(trigger);
  }

  // def encrypt_packet(
  //     self, plain_header: bytes, plain_payload: bytes, packet_number: int
  // ) -> bytes:
  //     if self._update_key_requested:
  //         self._update_key("local_update")
  //     return self.send.encrypt_packet(plain_header, plain_payload, packet_number)
}

CryptoContext nextKeyPhase(CryptoContext self) {
  // final algorithm = sha256;
  final crypto = CryptoContext(keyPhase: self.keyPhase == 0 ? 1 : 0);
  crypto.setup(
    cipherSuite: self.cipherSuite!,
    secret: hkdf_expand_label(
      // algorithm,
      self.secret!,
      Uint8List.fromList([113, 117, 105, 99, 32, 107, 117]), // "quic ku"
      Uint8List(0),
      // algorithm.blockSize,
      32,
    ),
    version: self.version!,
  );
  return crypto;
}
