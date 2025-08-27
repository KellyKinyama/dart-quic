// test/initial_aead_test.dart
import 'dart:typed_data';

import 'package:test/test.dart';
import 'protocol.dart';
import 'initial_aead.dart';
// import 'aead.dart';

void main() {
  final connID = splitHexString('0x8394c8f03e515708');

  group('Initial AEAD Key and IV Derivation', () {
    group('Client', () {
      final tests = [
        {
          'name': 'QUIC v1',
          'version': Version.version1,
          'expectedClientSecret': splitHexString(
            'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea',
          ),
          'expectedKey': splitHexString('1f369613dd76d5467730efcbe3b1a22d'),
          'expectedIV': splitHexString('fa044b2f42a3fd3b46fb255c'),
        },
        {
          'name': 'QUIC v2',
          'version': Version.version2,
          'expectedClientSecret': splitHexString(
            '14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b',
          ),
          'expectedKey': splitHexString('8b1a0bc121284290a29e0971b5cd045d'),
          'expectedIV': splitHexString('91f73e2351d8fa91660e909f'),
        },
      ];

      for (final tt in tests) {
        test(tt['name'] as String, () {
          final version = tt['version'] as Version;
          final (clientSecret, _) = computeSecrets(connID, version);
          expect(clientSecret, equals(tt['expectedClientSecret']));

          final (key, iv) = computeInitialKeyAndIV(clientSecret, version);
          expect(key, equals(tt['expectedKey']));
          expect(iv, equals(tt['expectedIV']));
        });
      }
    });

    group('Server', () {
      final tests = [
        {
          'name': 'QUIC v1',
          'version': Version.version1,
          'expectedServerSecret': splitHexString(
            '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b',
          ),
          'expectedKey': splitHexString('cf3a5331653c364c88f0f379b6067e37'),
          'expectedIV': splitHexString('0ac1493ca1905853b0bba03e'),
        },
        {
          'name': 'QUIC v2',
          'version': Version.version2,
          'expectedServerSecret': splitHexString(
            '0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1',
          ),
          'expectedKey': splitHexString('82db637861d55e1d011f19ea71d5d2a7'),
          'expectedIV': splitHexString('dd13c276499c0249d3310652'),
        },
      ];

      for (final tt in tests) {
        test(tt['name'] as String, () {
          final version = tt['version'] as Version;
          final (_, serverSecret) = computeSecrets(connID, version);
          expect(serverSecret, equals(tt['expectedServerSecret']));

          final (key, iv) = computeInitialKeyAndIV(serverSecret, version);
          expect(key, equals(tt['expectedKey']));
          expect(iv, equals(tt['expectedIV']));
        });
      }
    });
  });

  group('Initial AEAD Sealing and Opening', () {
    for (final ver in Version.values) {
      test('seals and opens successfully for $ver', () {
        final cid = splitHexString('1234567890abcdef');
        final (clientSealer, clientOpener) = newInitialAEAD(
          cid,
          Perspective.client,
          ver,
        );
        final (serverSealer, serverOpener) = newInitialAEAD(
          cid,
          Perspective.server,
          ver,
        );

        final clientMessage = clientSealer.seal(
          // Uint8List(0),
          Uint8List.fromList('foobar'.codeUnits),
          42,
          Uint8List.fromList('aad'.codeUnits),
        );
        final openedClientMessage = serverOpener.open(
          // Uint8List(0),
          clientMessage,
          42,
          Uint8List.fromList('aad'.codeUnits),
        );
        expect(
          openedClientMessage,
          equals(Uint8List.fromList('foobar'.codeUnits)),
        );

        final serverMessage = serverSealer.seal(
          // Uint8List(0),
          Uint8List.fromList('raboof'.codeUnits),
          99,
          Uint8List.fromList('daa'.codeUnits),
        );
        final openedServerMessage = clientOpener.open(
          // Uint8List(0),
          serverMessage,
          99,
          Uint8List.fromList('daa'.codeUnits),
        );
        expect(
          openedServerMessage,
          equals(Uint8List.fromList('raboof'.codeUnits)),
        );
      });

      test('fails with different connection IDs for $ver', () {
        final c1 = splitHexString('0000000000000001');
        final c2 = splitHexString('0000000000000002');
        final (clientSealer, _) = newInitialAEAD(c1, Perspective.client, ver);
        final (_, serverOpener) = newInitialAEAD(c2, Perspective.server, ver);

        final clientMessage = clientSealer.seal(
          // Uint8List(0),
          Uint8List.fromList('foobar'.codeUnits),
          42,
          Uint8List.fromList('aad'.codeUnits),
        );
        expect(
          () => serverOpener.open(
            // Uint8List(0),
            clientMessage,
            42,
            Uint8List.fromList('aad'.codeUnits),
          ),
          throwsA(equals(Errors.decryptionFailed)),
        );
      });
    }
  });
}
