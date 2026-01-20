// lib/initial_aead.dart
import 'dart:convert';
import 'dart:typed_data';
// import 'package:pointycastle/export.dart';

import 'package:hex/hex.dart';

import 'aead.dart';
import 'cipher_suite.dart';
import 'hash.dart';
import 'header_protector2.dart';
import 'hkdf.dart';
// import 'prf.dart';
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

(LongHeaderSealer, LongHeaderOpener) fromHandshakeSecrets(
  // ConnectionID connID,
  Perspective pers,
  Version v, {
  required Uint8List clientHelloBytes,
  required Uint8List serverHelloBytes,
}) {
  final hello_hash = createHash(
    Uint8List.fromList([...clientHelloBytes, ...serverHelloBytes]),
  );
  print("Handshake hash: ${HEX.encode(hello_hash)}");
  print(
    "Expected:       ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b",
  );

  final shared_secret = Uint8List.fromList(
    HEX.decode(
      "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624",
    ),
  );
  // final zero_keyDecoded = Uint8List.fromList(
  //   HEX.decode(
  //     "0000000000000000000000000000000000000000000000000000000000000000",
  //   ),
  // );
  final zero_key = Uint8List(32);

  final early_secret = hkdfExtract(zero_key, salt: Uint8List(2));
  final empty_hash = createHash(Uint8List(0));
  final derived_secret = hkdfExpandLabel(
    early_secret,
    empty_hash,
    "derived",
    32,
  );

  final handshake_secret = hkdfExtract(shared_secret, salt: derived_secret);
  final csecret = hkdfExpandLabel(
    handshake_secret,
    hello_hash,
    "c hs traffic",
    32,
  );
  final ssecret = hkdfExpandLabel(
    handshake_secret,
    hello_hash,
    "s hs traffic",
    32,
  );
  final client_handshake_key = hkdfExpandLabel(
    csecret,
    utf8.encode(""),
    "quic key",
    16,
  );
  final server_handshake_key = hkdfExpandLabel(
    ssecret,
    utf8.encode(""),
    "quic key",
    16,
  );
  final client_handshake_iv = hkdfExpandLabel(
    csecret,
    utf8.encode(""),
    "quic iv",
    12,
  );
  final server_handshake_iv = hkdfExpandLabel(
    ssecret,
    utf8.encode(""),
    "quic iv",
    12,
  );
  // final client_handshake_hp = hkdfExpandLabel(
  //   csecret,
  //   utf8.encode(""),
  //   "quic hp",
  //   16,
  // );
  // final server_handshake_hp = hkdfExpandLabel(
  //   ssecret,
  //   utf8.encode(""),
  //   "quic hp",
  //   16,
  // );
  // final (clientSecret, serverSecret) = computeSecrets(connID, v);
  final Uint8List mySecret, otherSecret;
  final Uint8List myKey, myIV;
  final Uint8List otherKey, otherIV;
  if (pers == Perspective.client) {
    mySecret = csecret;
    otherSecret = ssecret;

    myKey = client_handshake_key;
    myIV = client_handshake_iv;

    otherKey = server_handshake_key;
    otherIV = server_handshake_iv;
  } else {
    mySecret = ssecret;
    otherSecret = csecret;

    otherKey = client_handshake_key;
    otherIV = client_handshake_iv;

    myKey = server_handshake_key;
    myIV = server_handshake_iv;
  }

  final encrypter = initialSuite.aead(key: myKey, nonceMask: myIV);
  final decrypter = initialSuite.aead(key: otherKey, nonceMask: otherIV);
  print("Pers: $pers");
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

(Uint8List, Uint8List) computeSecrets(ConnectionID connID, Version v) {
  final initialSecret = hkdfExtract(connID, salt: getSalt(v));

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

// (Uint8List, Uint8List) computeSecrets(ConnectionID connID, Version v) {
//   // Step 1: CORRECTLY call hkdfExtract from your prf.dart file.
//   final initialSecret = hkdfExtract(connID, salt: getSalt(v));

//   // Step 2: The rest of the function can now use this correct initialSecret.
//   final clientSecret = hkdfExpandLabel(
//     initialSecret,
//     Uint8List(0),
//     'client in',
//     32,
//   );
//   final serverSecret = hkdfExpandLabel(
//     initialSecret,
//     Uint8List(0),
//     'server in',
//     32,
//   );
//   return (clientSecret, serverSecret);
// }

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
