// test/aead_test.dart
import 'dart:typed_data';
import 'dart:math';

// import 'package:test/test.dart';
import 'protocol.dart';
import 'aead.dart';
import 'cipher_suite.dart';
import 'header_protector2.dart';

// Helper to create a sealer and opener for tests
(LongHeaderSealer, LongHeaderOpener) getSealerAndOpener(
  CipherSuite cs,
  Version v,
) {
  final rand = Random.secure();
  final key = Uint8List.fromList(
    List.generate(cs.keyLen, (_) => rand.nextInt(256)),
  );
  final hpKey = Uint8List.fromList(
    List.generate(cs.keyLen, (_) => rand.nextInt(256)),
  );
  final iv = Uint8List.fromList(
    List.generate(cs.ivLen, (_) => rand.nextInt(256)),
  );

  final aead = cs.aead(key: key, nonceMask: iv);
  final headerProtector = newHeaderProtector(cs, hpKey, true, v);

  return (
    LongHeaderSealer(aead, headerProtector),
    LongHeaderOpener(aead, headerProtector),
  );
}

void main() {
  for (final v in Version.values) {
    for (final csId in [
      0x1301, // 0x1302,
      0x1303,
    ]) {
      // group('AEAD for QUIC $v / CipherSuite $csId', () {
      final cs = getCipherSuite(csId);

      // test('encrypts and decrypts a message', () {
      var (sealer, opener) = getSealerAndOpener(cs, v);
      final msg = Uint8List.fromList(
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.'
            .codeUnits,
      );
      final ad = Uint8List.fromList('Donec in velit neque.'.codeUnits);

      final encrypted = sealer.seal(msg, 0x1337, ad);
      final opened = opener.open(encrypted, 0x1337, ad);

      // expect(opened, equals(msg));
      print("Got:      $opened");
      print("Expected: $msg");

      // Test with incorrect AD
      // expect(
      //   () =>
      // opener.open(encrypted, 0x1337, Uint8List.fromList('wrong ad'.codeUnits));
      // ,
      //   throwsA(isA<Exception>()),
      // );

      // Test with incorrect packet number
      // expect(
      //   () =>
      // opener.open(encrypted, 0x42, ad);
      //   throwsA(isA<Exception>()),
      // );
      // });

      // test('encrypts and decrypts header', () {
      (sealer, opener) = getSealerAndOpener(cs, v);
      final rand = Random.secure();

      for (var i = 0; i < 20; i++) {
        final sample = Uint8List.fromList(
          List.generate(16, (_) => rand.nextInt(256)),
        );

        // Header contains: [Flags, ConnectionID (8 bytes), PacketNumber (4 bytes)]
        final header = Uint8List.fromList([
          0xb5,
          1,
          2,
          3,
          4,
          5,
          6,
          7,
          8,
          0xde,
          0xad,
          0xbe,
          0xef,
        ]);
        final originalHeader = Uint8List.fromList(header);

        // In Dart, sublist creates a COPY.
        // --- REPLACE OLD SUBLIST CODE WITH THIS ---
        final firstByteView = Uint8List.view(
          header.buffer,
          header.offsetInBytes,
          1,
        );
        final pnBytesView = Uint8List.view(
          header.buffer,
          header.offsetInBytes + 9,
          4,
        );

        // --- ENCRYPT ---
        sealer.encryptHeader(sample, firstByteView, pnBytesView);

        // Update the original header array with the encrypted pieces for printing
        header[0] = firstByteView[0];
        header.setRange(9, 13, pnBytesView);

        print('--- Run $i ---');
        print(
          'Original:  ${originalHeader.map((b) => b.toRadixString(16).padLeft(2, '0')).toList()}',
        );
        print(
          'Protected: ${header.map((b) => b.toRadixString(16).padLeft(2, '0')).toList()}',
        );

        // --- DECRYPT ---
        opener.decryptHeader(sample, firstByteView, pnBytesView);

        // Update the array again to show decrypted state
        header[0] = firstByteView[0];
        header.setRange(9, 13, pnBytesView);

        print(
          'Decrypted: ${header.map((b) => b.toRadixString(16).padLeft(2, '0')).toList()}',
        );

        bool success = true;
        for (int j = 0; j < header.length; j++) {
          if (header[j] != originalHeader[j]) success = false;
        }
        print('Status:    ${success ? "✅ SUCCESS" : "❌ FAILED"}');
        print('');
      }
      // });
      // });
    }
  }
}
