import 'dart:typed_data';
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

final initialSuite = 0x1301; // TLS_AES_128_GCM_SHA256

(Uint8List, Uint8List) computeSecrets(ConnectionID connID, Version v) {
  final initialSecret = hkdfExtract(connID, salt: getSalt(v));

  final clientSecret = hkdfExpandLabel(
    secret: initialSecret,
    context: Uint8List(0),
    label: 'client in',
    length: 32,
  );
  final serverSecret = hkdfExpandLabel(
    secret: initialSecret,
    context: Uint8List(0),
    label: 'server in',
    length: 32,
  );
  return (clientSecret, serverSecret);
}

(Uint8List, Uint8List) computeInitialKeyAndIV(Uint8List secret, Version v) {
  final keyLabel = v == Version.version2 ? hkdfLabelKeyV2 : hkdfLabelKeyV1;
  final ivLabel = v == Version.version2 ? hkdfLabelIVV2 : hkdfLabelIVV1;

  final key = hkdfExpandLabel(
    // SHA256Digest(),
    secret: secret,
    context: Uint8List(0),
    label: keyLabel,
    length: 16,
  );
  final iv = hkdfExpandLabel(
    secret: secret,
    context: Uint8List(0),
    label: ivLabel,
    length: 12,
  );
  return (key, iv);
}

(
  ({({Uint8List key, Uint8List nonceMask}) aead, Uint8List hp}),
  ({({Uint8List key, Uint8List nonceMask}) aead, Uint8List hp}),
)
newInitialAEAD(ConnectionID connID, Perspective pers, Version v) {
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

  final encrypter = (key: myKey, nonceMask: myIV);
  final decrypter = (key: otherKey, nonceMask: otherIV);

  final sealer = (
    aead: encrypter,
    hp: newHeaderProtector(initialSuite, mySecret, true, v),
  );
  final opener = (
    aead: decrypter,
    hp: newHeaderProtector(initialSuite, otherSecret, true, v),
  );
  return (sealer, opener);
}

String hkdfHeaderProtectionLabel(Version v) {
  return v == Version.version2 ? 'quicv2 hp' : 'quic hp';
}

Uint8List newHeaderProtector(
  int suite,
  Uint8List trafficSecret,
  bool isLongHeader,
  Version v,
) {
  final label = hkdfHeaderProtectionLabel(v);

  switch (suite) {
    case 0x1301: // TLS_AES_128_GCM_SHA256
    case 0x1302: // TLS_AES_256_GCM_SHA384
      return hkdfExpandLabel(
        // suite.hash(),
        secret: trafficSecret,
        context: Uint8List(0),
        label: label,
        length: 16,
      );
    case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
      return hkdfExpandLabel(
        // suite.hash(),
        secret: trafficSecret,
        context: Uint8List(0),
        label: label,
        length: 32,
      );
    default:
      throw Exception('Invalid cipher suite id: ${suite}');
  }
}
