import 'dart:typed_data';

import 'hkdf.dart';
// Assuming Hkdf class from previous snippets.

class QuicKeyDerivation {
  static const String keyLabel = "quic key";
  static const String ivLabel = "quic iv";
  static const String hpLabel = "quic hp";

  static final Uint8List quicInitialSaltV1 = Uint8List.fromList([
    0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef, 0xcf, 0x80,
    0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0
  ]);

  // A hypothetical new salt for a future QUIC version, emphasizing key diversity.
  static final Uint8List quicInitialSaltV2 = Uint8List.fromList([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
    0xDD, 0xEE, 0xFF, 0x00, 0x1A, 0x2B, 0x3C, 0x4D
  ]);

  static Uint8List deriveKey(
      Uint8List secret, String label, int length, int hashLength) {
    return Hkdf.expandLabel(secret, label, Uint8List(0), length);
  }

  static Map<String, Uint8List> deriveInitialSecrets(
      Uint8List salt, Uint8List clientDstConnectionId, int hashLength) {
    final Uint8List initialSecret = Hkdf.extract(salt, clientDstConnectionId);
    final Uint8List clientInitialSecret = Hkdf.expandLabel(initialSecret, "client in", Uint8List(0), hashLength);
    final Uint8List serverInitialSecret = Hkdf.expandLabel(initialSecret, "server in", Uint8List(0), hashLength);
    return {
      'client_initial_secret': clientInitialSecret,
      'server_initial_secret': serverInitialSecret,
    };
  }
}

// void main() {
//   // Example: Key Diversity
//   final Uint8List clientConnectionId = Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD]);
//   final int hashLength = 32;

//   print('**Key Diversity Example**');
//   print('--- QUIC Version 1 Initial Secrets ---');
//   final Map<String, Uint8List> v1Secrets = QuicKeyDerivation.deriveInitialSecrets(
//       QuicKeyDerivation.quicInitialSaltV1, clientConnectionId, hashLength);
//   print('Client Initial Secret (V1): ${v1Secrets['client_initial_secret']?.toHexString()}');
//   print('Server Initial Secret (V1): ${v1Secrets['server_initial_secret']?.toHexString()}');

//   print('\n--- QUIC Version 2 Initial Secrets (Hypothetical New Salt) ---');
//   final Map<String, Uint8List> v2Secrets = QuicKeyDerivation.deriveInitialSecrets(
//       QuicKeyDerivation.quicInitialSaltV2, clientConnectionId, hashLength);
//   print('Client Initial Secret (V2): ${v2Secrets['client_initial_secret']?.toHexString()}');
//   print('Server Initial Secret (V2): ${v2Secrets['server_initial_secret']?.toHexString()}\n');
// }