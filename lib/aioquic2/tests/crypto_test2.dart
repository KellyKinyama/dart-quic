import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:collection/collection.dart';

// import '../crypto2.dart';
import '../hkdf2.dart';
import '../packet.dart';

// class CipherSuite(IntEnum):
const AES_128_GCM_SHA256 = 0x1301;
const AES_256_GCM_SHA384 = 0x1302;
const CHACHA20_POLY1305_SHA256 = 0x1303;
const EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

const INITIAL_CIPHER_SUITE = AES_128_GCM_SHA256;
const PROTOCOL_VERSION = QuicProtocolVersion.version1;

void test_derive_key_iv_hp() {
  // https://datatracker.ietf.org/doc/html/rfc9001#appendix-A.1

  // client
  final secret = Uint8List.fromList(
    HEX.decode(
      "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
    ),
  );
  var (key, iv, hp) = deriveKeyIvHp(
    cipherSuite: INITIAL_CIPHER_SUITE,
    secret: secret,
    version: PROTOCOL_VERSION,
  );
  if (!DeepCollectionEquality().equals(
    key,
    HEX.decode("1f369613dd76d5467730efcbe3b1a22d"),
  )) {
    print("Got key: $key, length: ${key.length}");
    print(
      "Expected:    ${HEX.decode("1f369613dd76d5467730efcbe3b1a22d")}, length: ${HEX.decode("1f369613dd76d5467730efcbe3b1a22d").length}",
    );
    throw Exception("mismatch");
  }
  if (!DeepCollectionEquality().equals(
    iv,
    HEX.decode("fa044b2f42a3fd3b46fb255c"),
  )) {
    throw Exception("mismatch");
  }
  if (!DeepCollectionEquality().equals(
    hp,
    HEX.decode("9f50449e04a0e810283a1e9933adedd2"),
  )) {
    print("Got iv: $hp, length: ${hp.length}");
    print(
      "Expected:    ${HEX.decode("9f50449e04a0e810283a1e9933adedd2")}, length: ${HEX.decode("9f50449e04a0e810283a1e9933adedd2").length}",
    );
    throw Exception("mismatch");
  }
  //         // server
  //         secret = HEX.decode(
  //             "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
  //         );
  //         (key, iv, hp) = deriveKeyIvHp(
  //             cipher_suite=INITIAL_CIPHER_SUITE,
  //             secret=secret,
  //             version=PROTOCOL_VERSION,
  //         )
  //         self.assertEqual(key, binascii.unhexlify("cf3a5331653c364c88f0f379b6067e37"))
  //         self.assertEqual(iv, binascii.unhexlify("0ac1493ca1905853b0bba03e"))
  //         self.assertEqual(hp, binascii.unhexlify("c206b8d9b9f0f37644430b490eeaa314"))
  // }
}

void main() {
  test_derive_key_iv_hp();
}
