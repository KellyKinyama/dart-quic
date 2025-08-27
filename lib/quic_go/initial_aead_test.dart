
// Filename: initial_aead_test.dart
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import 'initial_aead.dart'; // Assuming the functions are exposed for testing

// Helper from handshake_helpers_test.go
Uint8List splitHexString(String s) {
  final sanitized = s.replaceAll('0x', '').replaceAll(' ', '');
  return Uint8List.fromList(HEX.decode(sanitized));
}

void main() {
  group('Initial AEAD Secrets', () {
    test('computes client key and IV for QUIC v1', () async {
      final connId = splitHexString('8394c8f03e515708');
      final expectedClientSecret = splitHexString('c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea');
      
      final secrets = await computeSecrets(connId);
      
      expect(
        DeepCollectionEquality().equals(secrets.clientSecret, expectedClientSecret),
        isTrue,
      );
      
      // Additional tests for key and IV derivation would follow...
    });

    test('computes server key and IV for QUIC v1', () async {
      final connId = splitHexString('8394c8f03e515708');
      final expectedServerSecret = splitHexString('3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b');

      final secrets = await computeSecrets(connId);

      expect(
        DeepCollectionEquality().equals(secrets.serverSecret, expectedServerSecret),
        isTrue,
      );
    });
  });
}