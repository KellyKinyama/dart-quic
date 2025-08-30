// Filename: hkdf_example.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';
import '../hkdf.dart'; // Your hkdf.dart file
import '../prf.dart'; // Your prf.dart file

void main() {
  print('--- Running HKDF Example ---');

  // This example uses test vectors from RFC 9001, Appendix A.1.

  // 1. The initial secret is derived via HKDF-Extract(salt, connectionId).
  //    This is the PRK (Pseudo-Random Key) that will be expanded.
  final initialSecret = Uint8List.fromList(
    HEX.decode(
      '7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44',
    ),
  );
  print('Using Initial Secret (PRK): ${HEX.encode(initialSecret)}');

  // 2. Use hkdfExpandLabel to derive the client's initial traffic secret.
  final clientSecret = hkdfExpandLabel(
    initialSecret,
    Uint8List(0), // The context is an empty hash for initial secrets
    'client in',
    32, // The desired length in bytes (for SHA-256)
  );

  print('Derived Client Secret:    ${HEX.encode(clientSecret)}');

  // 3. Compare with the known correct value from the RFC.
  final expectedClientSecret = Uint8List.fromList(
    HEX.decode(
      'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea',
    ),
  );
  print('Expected Client Secret:   ${HEX.encode(expectedClientSecret)}');

  if (!DeepCollectionEquality().equals(clientSecret, expectedClientSecret)) {
    throw Exception('Derived client secret does not match the expected value!');
  }

  print('\n✅ HKDF-Expand-Label test passed!');
  print('\n--- HKDF Example Finished ---');
}
