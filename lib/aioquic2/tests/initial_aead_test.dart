// Filename: test/initial_aead_test.dart
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';
import '../crypto2.dart';
import '../prf.dart';
import '../hkdf.dart';
import '../interface.dart'; // Import for DecryptionFailedException

// Helper to decode hex strings from the test vectors
Uint8List _splitHexString(String s) {
  return Uint8List.fromList(HEX.decode(s.replaceAll(' ', '')));
}

void main() {
  final eq = DeepCollectionEquality().equals;

  group('Initial AEAD Secrets', () {
    final connId = _splitHexString("8394c8f03e515708");
    final saltV1 = _splitHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    test('computes client secrets for QUIC v1', () {
      final expectedClientSecret = _splitHexString(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
      );
      final expectedKey = _splitHexString("1f369613dd76d5467730efcbe3b1a22d");
      final expectedIV = _splitHexString("fa044b2f42a3fd3b46fb255c");

      final initialSecret = hkdfExtract(connId, salt: saltV1);
      final clientSecret = hkdfExpandLabel(
        initialSecret,
        Uint8List(0),
        'client in',
        32,
      );
      expect(eq(clientSecret, expectedClientSecret), isTrue);

      final key = hkdfExpandLabel(clientSecret, Uint8List(0), 'quic key', 16);
      final iv = hkdfExpandLabel(clientSecret, Uint8List(0), 'quic iv', 12);
      expect(eq(key, expectedKey), isTrue);
      expect(eq(iv, expectedIV), isTrue);
    });

    test('computes server secrets for QUIC v1', () {
      final expectedServerSecret = _splitHexString(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
      );
      final expectedKey = _splitHexString("cf3a5331653c364c88f0f379b6067e37");
      final expectedIV = _splitHexString("0ac1493ca1905853b0bba03e");

      final initialSecret = hkdfExtract(connId, salt: saltV1);
      final serverSecret = hkdfExpandLabel(
        initialSecret,
        Uint8List(0),
        'server in',
        32,
      );
      expect(eq(serverSecret, expectedServerSecret), isTrue);

      final key = hkdfExpandLabel(serverSecret, Uint8List(0), 'quic key', 16);
      final iv = hkdfExpandLabel(serverSecret, Uint8List(0), 'quic iv', 12);
      expect(eq(key, expectedKey), isTrue);
      expect(eq(iv, expectedIV), isTrue);
    });
  });

  group('Initial Packet Protection', () {
    test('seals and opens packets correctly', () async {
      final connectionId = Uint8List.fromList([
        0x12,
        0x34,
        0x56,
        0x78,
        0x90,
        0xab,
        0xcd,
        0xef,
      ]);
      final clientPair = CryptoPair();
      await clientPair.setupInitial(cid: connectionId, isClient: true);
      final serverPair = CryptoPair();
      await serverPair.setupInitial(cid: connectionId, isClient: false);

      final plainPayload = Uint8List.fromList('foobar'.codeUnits);
      // FIX: Use a realistic header that is long enough to contain a packet number.
      final plainHeader = Uint8List.fromList([0xc3, 0, 0, 0, 1, 0, 0, 0, 42]);
      final packetNumber = 42;
      final pnOffset = plainHeader.length - 4; // 9 - 4 = 5

      // Client seals, Server opens
      final encryptedPacket = await clientPair.send.encryptPacket(
        plainHeader,
        plainPayload,
        packetNumber,
      );
      final (decryptedHeader, decryptedPayload, decryptedPn) = await serverPair
          .recv
          .decryptPacket(encryptedPacket, pnOffset, packetNumber - 1);

      expect(eq(decryptedPayload, plainPayload), isTrue);
      expect(decryptedPn, packetNumber);
    });

    test('fails to open with different connection IDs', () async {
      final c1 = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 1]);
      final c2 = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 2]);

      final clientPair = CryptoPair();
      await clientPair.setupInitial(cid: c1, isClient: true);
      final serverPair = CryptoPair();
      await serverPair.setupInitial(cid: c2, isClient: false);

      final plainPayload = Uint8List.fromList('foobar'.codeUnits);
      final plainHeader = Uint8List.fromList([0xc3, 0, 0, 0, 1, 0, 0, 0, 42]);
      final packetNumber = 42;
      final pnOffset = plainHeader.length - 4;

      final encryptedPacket = await clientPair.send.encryptPacket(
        plainHeader,
        plainPayload,
        packetNumber,
      );

      // FIX: Expect a cryptographic error (DecryptionFailedException), not just any Exception.
      expect(
        () => serverPair.recv.decryptPacket(
          encryptedPacket,
          pnOffset,
          packetNumber - 1,
        ),
        throwsA(isA<DecryptionFailedException>()),
      );
    });
  });
}
