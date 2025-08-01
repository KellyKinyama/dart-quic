import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'packet.dart';
import '../tls.dart';

// Assuming these are external classes/functions from other parts of the library.
abstract class AEAD {
  Uint8List encrypt(Uint8List plain, Uint8List associatedData, int nonce);
  Uint8List decrypt(Uint8List encrypted, Uint8List associatedData, int nonce);
}

abstract class HeaderProtection {
  Uint8List apply(Uint8List header, Uint8List payload);
  Tuple<Uint8List, Uint8List> remove(Uint8List packet, int offset);
}

class CryptoError implements Exception {}

class CryptoErrorHeaderProtection implements CryptoError {}

class CryptoErrorDecryptionFailed implements CryptoError {}

class KeyUnavailableError implements CryptoError {
  final String message;
  KeyUnavailableError(this.message);
  String toString() => "KeyUnavailableError: $message";
}

// Placeholder implementations for crypto functions
Uint8List hkdfExtract(Hash algorithm, Uint8List salt, Uint8List ikm) {
  // Mock implementation
  return Uint8List(algorithm.blockSize);
}

Uint8List hkdfExpandLabel(
  Hash algorithm,
  Uint8List secret,
  Uint8List label,
  Uint8List context,
  int length,
) {
  // Mock implementation
  return Uint8List(length);
}

// Assuming these are defined elsewhere
class QuicProtocolVersion {
  static const int VERSION_1 = 1;
  static const int VERSION_2 = 2;
}

Uint8List decodePacketNumber(
  int packetNumber,
  int pnBits,
  int expectedPacketNumber,
) {
  // Mock implementation
  return Uint8List(0);
}

bool isLongHeader(int firstByte) {
  return (firstByte & 0x80) == 0x80;
}

// End of assumed external classes/functions

const Map<CipherSuite, Tuple<Uint8List, Uint8List>> CIPHER_SUITES = {
  CipherSuite.AES_128_GCM_SHA256: Tuple(
    Uint8List.fromList([97, 101, 115, 45, 49, 50, 56, 45, 101, 99, 98]),
    Uint8List.fromList([97, 101, 115, 45, 49, 50, 56, 45, 103, 99, 109]),
  ), // "aes-128-ecb", "aes-128-gcm"
  CipherSuite.AES_256_GCM_SHA384: Tuple(
    Uint8List.fromList([97, 101, 115, 45, 50, 53, 54, 45, 101, 99, 98]),
    Uint8List.fromList([97, 101, 115, 45, 50, 53, 54, 45, 103, 99, 109]),
  ), // "aes-256-ecb", "aes-256-gcm"
  CipherSuite.CHACHA20_POLY1305_SHA256: Tuple(
    Uint8List.fromList([99, 104, 97, 99, 104, 97, 50, 48]),
    Uint8List.fromList([
      99,
      104,
      97,
      99,
      104,
      97,
      50,
      48,
      45,
      112,
      111,
      108,
      121,
      49,
      51,
      48,
      53,
    ]),
  ), // "chacha20", "chacha20-poly1305"
};
const INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256;
final Uint8List INITIAL_SALT_VERSION_1 = Uint8List.fromList(
  hex.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
);
final Uint8List INITIAL_SALT_VERSION_2 = Uint8List.fromList(
  hex.decode("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
);
const int SAMPLE_SIZE = 16;

typedef Callback = void Function(String trigger);

void noCallback(String trigger) {}

Uint8List cipherSuiteHash(CipherSuite cipherSuite) {
  // Mock implementation
  return Uint8List(0);
}

Tuple<Uint8List, Uint8List, Uint8List> deriveKeyIvHp({
  required CipherSuite cipherSuite,
  required Uint8List secret,
  required int version,
}) {
  final algorithm = sha256; // Placeholder, assuming sha256 for now
  int keySize;
  if (cipherSuite == CipherSuite.AES_256_GCM_SHA384 ||
      cipherSuite == CipherSuite.CHACHA20_POLY1305_SHA256) {
    keySize = 32;
  } else {
    keySize = 16;
  }
  if (version == QuicProtocolVersion.VERSION_2) {
    return Tuple(
      hkdfExpandLabel(
        algorithm,
        secret,
        Uint8List.fromList([113, 117, 105, 99, 118, 50, 32, 107, 101, 121]),
        Uint8List(0),
        keySize,
      ), // "quicv2 key"
      hkdfExpandLabel(
        algorithm,
        secret,
        Uint8List.fromList([113, 117, 105, 99, 118, 50, 32, 105, 118]),
        Uint8List(0),
        12,
      ), // "quicv2 iv"
      hkdfExpandLabel(
        algorithm,
        secret,
        Uint8List.fromList([113, 117, 105, 99, 118, 50, 32, 104, 112]),
        Uint8List(0),
        keySize,
      ), // "quicv2 hp"
    );
  } else {
    return Tuple(
      hkdfExpandLabel(
        algorithm,
        secret,
        Uint8List.fromList([113, 117, 105, 99, 32, 107, 101, 121]),
        Uint8List(0),
        keySize,
      ), // "quic key"
      hkdfExpandLabel(
        algorithm,
        secret,
        Uint8List.fromList([113, 117, 105, 99, 32, 105, 118]),
        Uint8List(0),
        12,
      ), // "quic iv"
      hkdfExpandLabel(
        algorithm,
        secret,
        Uint8List.fromList([113, 117, 105, 99, 32, 104, 112]),
        Uint8List(0),
        keySize,
      ), // "quic hp"
    );
  }
}

class CryptoContext {
  AEAD? aead;
  CipherSuite? cipherSuite;
  HeaderProtection? hp;
  int keyPhase;
  Uint8List? secret;
  int? version;
  final Callback _setupCb;
  final Callback _teardownCb;

  CryptoContext({
    this.keyPhase = 0,
    this.setupCb = noCallback,
    this.teardownCb = noCallback,
  }) : _setupCb = setupCb,
       _teardownCb = teardownCb;

  Tuple<Uint8List, Uint8List, int, bool> decryptPacket(
    Uint8List packet,
    int encryptedOffset,
    int expectedPacketNumber,
  ) {
    if (aead == null) {
      throw KeyUnavailableError("Decryption key is not available");
    }

    final headerProtection = hp!.remove(packet, encryptedOffset);
    final plainHeader = headerProtection.item1;
    final packetNumberBytes = headerProtection.item2;
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

    final payload = crypto.aead!.decrypt(
      packet.sublist(plainHeader.length),
      plainHeader,
      packetNumber,
    );

    return Tuple(plainHeader, payload, packetNumber, updateKey);
  }

  Uint8List encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) {
    if (!isValid()) {
      throw KeyUnavailableError("Encryption key is not available");
    }

    final protectedPayload = aead!.encrypt(
      plainPayload,
      plainHeader,
      packetNumber,
    );

    return hp!.apply(plainHeader, protectedPayload);
  }

  bool isValid() => aead != null;

  void setup({
    required CipherSuite cipherSuite,
    required Uint8List secret,
    required int version,
  }) {
    final hpCipherName, aeadCipherName = CIPHER_SUITES[cipherSuite];

    final keys = deriveKeyIvHp(
      cipherSuite: cipherSuite,
      secret: secret,
      version: version,
    );
    this.aead = AEAD(aeadCipherName, keys.item1, keys.item2);
    this.cipherSuite = cipherSuite;
    this.hp = HeaderProtection(hpCipherName, keys.item3);
    this.secret = secret;
    this.version = version;

    _setupCb("tls");
  }

  void teardown() {
    aead = null;
    cipherSuite = null;
    hp = null;
    secret = null;

    _teardownCb("tls");
  }
}

void applyKeyPhase(
  CryptoContext self,
  CryptoContext crypto, {
  required String trigger,
}) {
  self.aead = crypto.aead;
  self.keyPhase = crypto.keyPhase;
  self.secret = crypto.secret;

  self._setupCb(trigger);
}

CryptoContext nextKeyPhase(CryptoContext self) {
  final algorithm = sha256;
  final crypto = CryptoContext(keyPhase: self.keyPhase == 0 ? 1 : 0);
  crypto.setup(
    cipherSuite: self.cipherSuite!,
    secret: hkdfExpandLabel(
      algorithm,
      self.secret!,
      Uint8List.fromList([113, 117, 105, 99, 32, 107, 117]), // "quic ku"
      Uint8List(0),
      algorithm.blockSize,
    ),
    version: self.version!,
  );
  return crypto;
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

  Tuple<Uint8List, Uint8List, int> decryptPacket(
    Uint8List packet,
    int encryptedOffset,
    int expectedPacketNumber,
  ) {
    final result = recv.decryptPacket(
      packet,
      encryptedOffset,
      expectedPacketNumber,
    );
    final plainHeader = result.item1;
    final payload = result.item2;
    final packetNumber = result.item3;
    final updateKey = result.item4;
    if (updateKey) {
      _updateKey("remote_update");
    }
    return Tuple(plainHeader, payload, packetNumber);
  }

  Uint8List encryptPacket(
    Uint8List plainHeader,
    Uint8List plainPayload,
    int packetNumber,
  ) {
    if (_updateKeyRequested) {
      _updateKey("local_update");
    }
    return send.encryptPacket(plainHeader, plainPayload, packetNumber);
  }

  void setupInitial(Uint8List cid, bool isClient, int version) {
    Uint8List recvLabel, sendLabel;
    if (isClient) {
      recvLabel = Uint8List.fromList([
        115,
        101,
        114,
        118,
        101,
        114,
        32,
        105,
        110,
      ]); // "server in"
      sendLabel = Uint8List.fromList([
        99,
        108,
        105,
        101,
        110,
        116,
        32,
        105,
        110,
      ]); // "client in"
    } else {
      recvLabel = Uint8List.fromList([
        99,
        108,
        105,
        101,
        110,
        116,
        32,
        105,
        110,
      ]); // "client in"
      sendLabel = Uint8List.fromList([
        115,
        101,
        114,
        118,
        101,
        114,
        32,
        105,
        110,
      ]); // "server in"
    }

    final initialSalt = version == QuicProtocolVersion.VERSION_2
        ? INITIAL_SALT_VERSION_2
        : INITIAL_SALT_VERSION_1;

    final algorithm = sha256;
    final initialSecret = hkdfExtract(algorithm, initialSalt, cid);
    recv.setup(
      cipherSuite: INITIAL_CIPHER_SUITE,
      secret: hkdfExpandLabel(
        algorithm,
        initialSecret,
        recvLabel,
        Uint8List(0),
        algorithm.blockSize,
      ),
      version: version,
    );
    send.setup(
      cipherSuite: INITIAL_CIPHER_SUITE,
      secret: hkdfExpandLabel(
        algorithm,
        initialSecret,
        sendLabel,
        Uint8List(0),
        algorithm.blockSize,
      ),
      version: version,
    );
  }

  void teardown() {
    recv.teardown();
    send.teardown();
  }

  void updateKey() {
    _updateKeyRequested = true;
  }

  int get keyPhase {
    if (_updateKeyRequested) {
      return recv.keyPhase == 0 ? 1 : 0;
    } else {
      return recv.keyPhase;
    }
  }

  void _updateKey(String trigger) {
    applyKeyPhase(recv, nextKeyPhase(recv), trigger: trigger);
    applyKeyPhase(send, nextKeyPhase(send), trigger: trigger);
    _updateKeyRequested = false;
  }
}
