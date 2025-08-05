//
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';

import 'crypto_pair3.dart';
// import '../packet.dart';
import '../enums.dart';

void main() {
  test('CryptoPair roundtrip with key updates', () async {
    // Helper function to simulate packet creation
    Uint8List createPacket({required int keyPhase, required int packetNumber}) {
      final header = Uint8List.fromList(hex.decode("4200bff4"));
      final payload = Uint8List.fromList(hex.decode("01"));
      return Uint8List.fromList([...header, ...payload]);
    }

    // Initialize two CryptoPair instances
    final clientConnectionId = Uint8List.fromList(
      hex.decode("088394c8f03e5157"),
    );
    final serverConnectionId = Uint8List.fromList(hex.decode("00000000"));

    final pair1 = CryptoPair.forClient(
      clientConnectionId: clientConnectionId,
      serverConnectionId: serverConnectionId,
      version: QuicProtocolVersion.VERSION_1,
    );

    final pair2 = CryptoPair.forServer(
      clientConnectionId: clientConnectionId,
      serverConnectionId: serverConnectionId,
      version: QuicProtocolVersion.VERSION_1,
    );

    // Helper function to simulate sending and receiving
    Future<void> send(
      CryptoPair sender,
      CryptoPair receiver,
      int packetNumber,
    ) async {
      final plainHeader = createPacket(
        keyPhase: sender.keyPhase,
        packetNumber: packetNumber,
      );
      final plainPayload = Uint8List.fromList(utf8.encode('Hello, QUIC!'));

      final encryptedPacket = await sender.encryptPacket(
        plainHeader: plainHeader,
        plainPayload: plainPayload,
        packetNumber: packetNumber,
      );

      // final (recovHeader, recovPayload, recovPacketNumber) = await receiver
      //     .decryptPacket(
      //       packet: encryptedPacket,
      //       encryptedOffset: plainHeader.length,
      //       expectedPacketNumber: packetNumber,
      //     );

      final recovHeader = await receiver.decryptPacket(
        packet: encryptedPacket,
        encryptedOffset: plainHeader.length,
        expectedPacketNumber: packetNumber,
      );

      expect(recovHeader, plainHeader);
      // expect(recovPayload, plainPayload);
      // expect(recovPacketNumber, packetNumber);
    }

    // Initial roundtrip
    await send(pair1, pair2, 0);
    await send(pair2, pair1, 0);

    expect(pair1.keyPhase, 0);
    expect(pair2.keyPhase, 0);

    // Pair 1 key update
    pair1.updateKey();

    // Roundtrip after key update on pair 1
    await send(pair1, pair2, 1);
    await send(pair2, pair1, 1);

    expect(pair1.keyPhase, 1);
    expect(pair2.keyPhase, 1);

    // Pair 2 key update
    pair2.updateKey();

    // Roundtrip after key update on pair 2
    await send(pair2, pair1, 2);
    await send(pair1, pair2, 2);

    expect(pair1.keyPhase, 0);
    expect(pair2.keyPhase, 0);
  });
}
