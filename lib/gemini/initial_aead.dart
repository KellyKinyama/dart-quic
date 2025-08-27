// lib/initial_aead.dart
import 'dart:typed_data';
// import 'package:pointycastle/export.dart';

import 'aead2.dart';
import 'cipher_suite.dart';
import 'header_protector.dart';
import 'hkdf.dart';
import 'prf.dart';
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

final initialSuite = getCipherSuite(0x1301); // TLS_AES_128_GCM_SHA256

(LongHeaderSealer, LongHeaderOpener) newInitialAEAD(
  ConnectionID connID,
  Perspective pers,
  Version v,
) {
  final (clientSecret, serverSecret) = computeSecrets(connID, v);
  final Uint8List mySecret, otherSecret;
  if (pers == Perspective.client) {
    mySecret = clientSecret;
    otherSecret = serverSecret;
  } else {
    mySecret = serverSecret;
    otherSecret = clientSecret;
  }

  final (myKey, myIV) = computeInitialKeyAndIV(mySecret, v);
  final (otherKey, otherIV) = computeInitialKeyAndIV(otherSecret, v);

  final encrypter = initialSuite.aead(key: myKey, nonceMask: myIV);
  final decrypter = initialSuite.aead(key: otherKey, nonceMask: otherIV);

  final sealer = LongHeaderSealer(
    encrypter,
    newHeaderProtector(initialSuite, mySecret, true, v),
  );
  final opener = LongHeaderOpener(
    decrypter,
    newHeaderProtector(initialSuite, otherSecret, true, v),
  );
  return (sealer, opener);
}

// (Uint8List, Uint8List) computeSecrets(ConnectionID connID, Version v) {
//   final initialSecret = connID;
//   final clientSecret = hkdfExpandLabel(
//     // SHA256Digest(),
//     initialSecret,
//     Uint8List(0),
//     'client in',
//     32,
//   );
//   final serverSecret = hkdfExpandLabel(
//     // SHA256Digest(),
//     initialSecret,
//     Uint8List(0),
//     'server in',
//     32,
//   );
//   return (clientSecret, serverSecret);
// }

(Uint8List, Uint8List) computeSecrets(ConnectionID connID, Version v) {
  // Step 1: CORRECTLY call hkdfExtract from your prf.dart file.
  final initialSecret = hkdfExtract(connID, salt: getSalt(v));

  // Step 2: The rest of the function can now use this correct initialSecret.
  final clientSecret = hkdfExpandLabel(
    initialSecret,
    Uint8List(0),
    'client in',
    32,
  );
  final serverSecret = hkdfExpandLabel(
    initialSecret,
    Uint8List(0),
    'server in',
    32,
  );
  return (clientSecret, serverSecret);
}

(Uint8List, Uint8List) computeInitialKeyAndIV(Uint8List secret, Version v) {
  final keyLabel = v == Version.version2 ? hkdfLabelKeyV2 : hkdfLabelKeyV1;
  final ivLabel = v == Version.version2 ? hkdfLabelIVV2 : hkdfLabelIVV1;

  final key = hkdfExpandLabel(
    // SHA256Digest(),
    secret,
    Uint8List(0),
    keyLabel,
    16,
  );
  final iv = hkdfExpandLabel(secret, Uint8List(0), ivLabel, 12);
  return (key, iv);
}
