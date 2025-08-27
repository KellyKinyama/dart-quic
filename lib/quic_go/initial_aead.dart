// Filename: initial_aead.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dart_quic/go_quic/prf.dart';

import 'hkdf.dart';
import 'interface.dart';
import 'aead.dart';

// QUIC v1 Salt from RFC 9001
final _quicSaltV1 = Uint8List.fromList([
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

class InitialSecrets {
  final Uint8List clientSecret;
  final Uint8List serverSecret;
  InitialSecrets(this.clientSecret, this.serverSecret);
}

Future<InitialSecrets> computeSecrets(Uint8List connId) async {
  // final h = Hmac(Sha256());
  // final h=hmacSha256(connId, data)
  final prk = hmacSha256(connId);
  final initialSecretKey = //await Hkdf(hmac: h, ).deriveKey(secretKey: prk, nonce: _quicSaltV1);
  hkdfExpand(
    prk,
    _quicSaltV1,
    outputLength,
  );
  final clientSecret = await hkdfExpandLabel(
    Sha256(),
    initialSecretKey,
    [],
    'client in',
    32,
  );
  final serverSecret = await hkdfExpandLabel(
    Sha256(),
    initialSecretKey,
    [],
    'server in',
    32,
  );

  return InitialSecrets(clientSecret, serverSecret);
}

Future<void> newInitialAead(Uint8List connId, bool isClient) async {
  // This function would create the sealer and opener using the secrets
  // and the aead.dart implementation.
  // It is left as a placeholder for the full application logic.
}
