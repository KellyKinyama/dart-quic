import 'dart:typed_data';
import '../protocol.dart';
import '../aead.dart';
import '../cipher_suite.dart';
import '../header_protector.dart';
import 'dart:math';

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

void encryptsAndDecryptsMessage() {
  print("encryptsAndDecryptsMessage...");
  final csId = 0x1301;
  final v = Version.version1;
  final cs = getCipherSuite(csId);
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
  print("");

  try {
    // Test with incorrect AD
    print("Test with incorrect AD");
    opener.open(encrypted, 0x1337, Uint8List.fromList('wrong ad'.codeUnits));
  } catch (e, st) {
    print("Error: $e, Stack trace: $st");
  }

  try {
    print("Test with incorrect packet number");
    opener.open(encrypted, 0x42, ad);
  } catch (e, st) {
    print("Error: $e, Stack trace: $st");
  }
}

void encryptsAndDecryptsHeader() {
  print("encryptsAndDecryptsHeader...");
  final csId = 0x1301;
  final v = Version.version1;
  final cs = getCipherSuite(csId);
  final (sealer, opener) = getSealerAndOpener(cs, v);
  final rand = Random.secure();

  // for (var i = 0; i < 20; i++) {
  final sample = Uint8List.fromList(
    List.generate(16, (_) => rand.nextInt(256)),
  );
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

  final firstByte = header.sublist(0, 1);
  final pnBytes = header.sublist(9, 13);

  print("Initial tHeader:        $header");
  print("Initial originalHeader: $originalHeader");

  sealer.encryptHeader(sample, firstByte, pnBytes);

  // expect(header.sublist(1, 9), equals(originalHeader.sublist(1, 9)));
  print("Got Header:      ${header.sublist(1, 9)}");
  print("Expected Header: ${originalHeader.sublist(1, 9)}");
  print("");

  // expect(pnBytes, isNot(equals(originalHeader.sublist(9, 13))));
  print("Got:  pnBytes     $pnBytes");
  print("Not Expected pnBytes: ${originalHeader.sublist(9, 13)}");
  print("");

  opener.decryptHeader(sample, firstByte, pnBytes);
  // expect(header, equals(originalHeader));
  print("Got decryptHeader:       $header");
  print("Expected decryptHeader:  $originalHeader");
  print("");
  print("Initial tHeader:        $header");
  print("Initial originalHeader: $originalHeader");
  print("");
  print("Got:  pnBytes     $pnBytes");
  print("Expected pnBytes: ${originalHeader.sublist(9, 13)}");
  print("");
  // }
}

void main() {
  // encryptsAndDecryptsMessage();
  encryptsAndDecryptsHeader();
}
