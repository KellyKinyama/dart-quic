// lib/initial_aead.dart
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'aead.dart'; // This would contain the sealer/opener logic
import 'cipher_suite.dart';
import 'header_protector.dart';
import 'hkdf.dart';
import 'protocol.dart';

final quicSaltV1 = Uint8List.fromList([
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
final quicSaltV2 = Uint8List.fromList([
  0x0d,
  0xed,
  0xe3,
  0xde,
  0xf7,
  0x00,
  0xa6,
  0xdb,
  0x81,
  0x93,
  0x81,
  0xbe,
  0x6e,
  0x26,
  0x9d,
  0xcb,
  0xf9,
  0xbd,
  0x2e,
  0xd9,
]);

const hkdfLabelKeyV1 = 'quic key';
const hkdfLabelKeyV2 = 'quicv2 key';
const hkdfLabelIVV1 = 'quic iv';
const hkdfLabelIVV2 = 'quicv2 iv';

Uint8List getSalt(Version v) => v == Version.version2 ? quicSaltV2 : quicSaltV1;

final initialSuite = getCipherSuite(0x1301);

Future<(LongHeaderSealer, LongHeaderOpener)> newInitialAEAD(
  ConnectionID connID,
  Perspective pers,
  Version v,
) async {
  final (clientSecret, serverSecret) = await computeSecrets(connID, v);

  final Uint8List mySecret, otherSecret;

  final (myKey, myIV) = await computeInitialKeyAndIV(mySecret, v);
  final (otherKey, otherIV) = await computeInitialKeyAndIV(otherSecret, v);

  final mySecretKey = myKey;
  final otherSecretKey = otherKey;

  final encrypter = initialSuite.aead(key: mySecretKey, nonceMask: myIV);
  final decrypter = initialSuite.aead(key: otherSecretKey, nonceMask: otherIV);

  final myHeaderProtector = await newHeaderProtector(
    initialSuite,
    mySecret,
    true,
    v,
  );
  final otherHeaderProtector = await newHeaderProtector(
    initialSuite,
    otherSecret,
    true,
    v,
  );

  return (
    LongHeaderSealer(encrypter, myHeaderProtector),
    LongHeaderOpener(decrypter, otherHeaderProtector),
  );
}

Future<(Uint8List, Uint8List)> computeSecrets(
  ConnectionID connID,
  Version v,
) async {
  final hmac = Hmac.sha256();
  final initialSecret = await hmac.calculateMac(
    secretKey: SecretKey(connID),
    nonce: getSalt(v),
  );

  final clientSecret = await hkdfExpandLabel(
    hmac,
    connID,
    Uint8List(0),
    'client in',
    32,
  );
  final serverSecret = await hkdfExpandLabel(
    hmac,
    connID,
    Uint8List(0),
    'server in',
    32,
  );
  return (clientSecret, serverSecret);
}

Future<(Uint8List, Uint8List)> computeInitialKeyAndIV(
  Uint8List secret,
  Version v,
) async {
  final hmac = Hmac(sha256);
  final prk = await hmac.importKey(key: secret);
  final keyLabel = v == Version.version2 ? hkdfLabelKeyV2 : hkdfLabelKeyV1;
  final ivLabel = v == Version.version2 ? hkdfLabelIVV2 : hkdfLabelIVV1;

  final key = await hkdfExpandLabel(hmac, secret, Uint8List(0), keyLabel, 16);
  final iv = await hkdfExpandLabel(hmac, secret, Uint8List(0), ivLabel, 12);
  return (key, iv);
}
