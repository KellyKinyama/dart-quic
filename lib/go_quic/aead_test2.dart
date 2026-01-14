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
      final (sealer, opener) = getSealerAndOpener(cs, v);
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
      // final (sealer, opener) = getSealerAndOpener(cs, v);
      // final rand = Random.secure();

      // for (var i = 0; i < 20; i++) {
      //   final sample = Uint8List.fromList(
      //     List.generate(16, (_) => rand.nextInt(256)),
      //   );
      //   final header = Uint8List.fromList([
      //     0xb5,
      //     1,
      //     2,
      //     3,
      //     4,
      //     5,
      //     6,
      //     7,
      //     8,
      //     0xde,
      //     0xad,
      //     0xbe,
      //     0xef,
      //   ]);
      //   final originalHeader = Uint8List.fromList(header);

      //   final firstByte = header.sublist(0, 1);
      //   final pnBytes = header.sublist(9, 13);

      //   sealer.encryptHeader(sample, firstByte, pnBytes);

      //   expect(header.sublist(1, 9), equals(originalHeader.sublist(1, 9)));
      //   expect(pnBytes, isNot(equals(originalHeader.sublist(9, 13))));

      //   opener.decryptHeader(sample, firstByte, pnBytes);
      //   expect(header, equals(originalHeader));
      // }
      // });
      // });
    }
  }
}
