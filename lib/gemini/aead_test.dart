import 'dart:typed_data';
import 'dart:math';

import 'package:test/test.dart';
import 'protocol.dart';
import 'aead.dart';
import 'cipher_suite.dart';
import 'header_protector.dart';

/// Helper to create a sealer and opener for tests
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

  final aead = cs.aeadFactory(key: key, nonceMask: iv);
  final headerProtector = newHeaderProtector(cs, hpKey, true, v);

  return (
    LongHeaderSealer(aead, headerProtector),
    LongHeaderOpener(aead, headerProtector),
  );
}

void main() {
  for (final v in Version.values) {
    group('AEAD for QUIC $v / TLS_AES_128_GCM_SHA256', () {
      final cs = getCipherSuite(0x1301);

      test('encrypts and decrypts a message payload', () {
        final (sealer, opener) = getSealerAndOpener(cs, v);
        final msg = Uint8List.fromList('Hello, QUIC world!'.codeUnits);
        final ad = Uint8List.fromList('Associated Data'.codeUnits);
        const packetNumber = 0x1A2B3C4D;

        final encrypted = sealer.seal(msg, packetNumber, ad);
        final opened = opener.open(encrypted, packetNumber, ad);

        expect(opened, equals(msg));
      });

      test('fails decryption with incorrect Associated Data', () {
        final (sealer, opener) = getSealerAndOpener(cs, v);
        final msg = Uint8List.fromList('Test message'.codeUnits);
        final ad = Uint8List.fromList('Correct AD'.codeUnits);
        final wrongAd = Uint8List.fromList('Wrong AD'.codeUnits);
        const packetNumber = 12345;

        final encrypted = sealer.seal(msg, packetNumber, ad);

        expect(
          () => opener.open(encrypted, packetNumber, wrongAd),
          throwsA(isA<DecryptionFailedException>()),
        );
      });

      test('fails decryption with incorrect packet number', () {
        final (sealer, opener) = getSealerAndOpener(cs, v);
        final msg = Uint8List.fromList('Another test'.codeUnits);
        final ad = Uint8List.fromList('Some AD'.codeUnits);
        const packetNumber = 9876;
        const wrongPacketNumber = 6789;

        final encrypted = sealer.seal(msg, packetNumber, ad);

        expect(
          () => opener.open(encrypted, wrongPacketNumber, ad),
          throwsA(isA<DecryptionFailedException>()),
        );
      });

      test('encrypts and decrypts header bytes', () {
        final (sealer, opener) = getSealerAndOpener(cs, v);
        final rand = Random.secure();

        final sample = Uint8List.fromList(
          List.generate(16, (_) => rand.nextInt(256)),
        );
        final header = Uint8List.fromList([
          0xc3, // Long Header type with 4-byte PN
          0x01, 0x02, 0x03, 0x04, // Version
          0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // SCID
          0x00, // Token Length
          0x04, 0x00, // Length
          0x1A, 0x2B, 0x3C, 0x4D, // Packet Number
        ]);
        final originalHeader = Uint8List.fromList(header);

        final firstByte = header.sublist(0, 1);
        final pnBytes = header.sublist(
          header.length - 4,
        ); // Last 4 bytes are PN

        // Encrypt the header
        sealer.encryptHeader(sample, firstByte, pnBytes);

        // Assert that the header is actually changed
        expect(firstByte[0], isNot(originalHeader[0]));
        expect(
          pnBytes,
          isNot(originalHeader.sublist(originalHeader.length - 4)),
        );

        // Decrypt the header
        opener.decryptHeader(sample, firstByte, pnBytes);

        // Assert that it's restored to its original state
        expect(header, equals(originalHeader));
      });
    });
  }
}
