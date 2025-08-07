// lib/initial_aead.dart
import 'package:cryptography/cryptography.dart';

import 'aead_manager.dart'; // This would contain the sealer/opener logic
import 'cipher_suite.dart';
import 'header_protector.dart';
import 'hkdf.dart';
import 'protocol.dart';

// ... salts and labels remain the same ...

final initialSuite = getCipherSuite(0x1301);

Future<(LongHeaderSealer, LongHeaderOpener)> newInitialAEAD(
    ConnectionID connID, Perspective pers, Version v) async {
  final (clientSecret, serverSecret) = await computeSecrets(connID, v);
  
  // ... logic to select mySecret/otherSecret ...

  final (myKey, myIV) = await computeInitialKeyAndIV(mySecret, v);
  final (otherKey, otherIV) = await computeInitialKeyAndIV(otherSecret, v);
  
  final mySecretKey = SecretKey(myKey);
  final otherSecretKey = SecretKey(otherKey);

  final encrypter = initialSuite.aead(secretKey: mySecretKey, iv: myIV);
  final decrypter = initialSuite.aead(secretKey: otherSecretKey, iv: otherIV);

  final myHeaderProtector = await newHeaderProtector(initialSuite, mySecret, true, v);
  final otherHeaderProtector = await newHeaderProtector(initialSuite, otherSecret, true, v);

  return (
    LongHeaderSealer(encrypter, myHeaderProtector),
    LongHeaderOpener(decrypter, otherHeaderProtector),
  );
}

Future<(Uint8List, Uint8List)> computeSecrets(ConnectionID connID, Version v) async {
  final hmac = Hmac(sha256);
  final initialSecret = await hmac.importKey(key: getSalt(v));
  
  final clientSecret = await hkdfExpandLabel(hmac, connID, Uint8List(0), 'client in', 32);
  final serverSecret = await hkdfExpandLabel(hmac, connID, Uint8List(0), 'server in', 32);
  return (clientSecret, serverSecret);
}

Future<(Uint8List, Uint8List)> computeInitialKeyAndIV(Uint8List secret, Version v) async {
  final hmac = Hmac(sha256);
  final prk = await hmac.importKey(key: secret);
  final keyLabel = v == Version.version2 ? hkdfLabelKeyV2 : hkdfLabelKeyV1;
  final ivLabel = v == Version.version2 ? hkdfLabelIVV2 : hkdfLabelIVV1;
  
  final key = await hkdfExpandLabel(hmac, secret, Uint8List(0), keyLabel, 16);
  final iv = await hkdfExpandLabel(hmac, secret, Uint8List(0), ivLabel, 12);
  return (key, iv);
}