// bin/main.dart
import 'dart:async';
import 'dart:typed_data';

import 'connection.dart';
import 'enums.dart';
import 'tls_stack.dart';

void main() async {
  print('Starting QUIC TLS Integration Simulation...');

  // Create mock TLS stacks for client and server
  final clientTls = MockQuicTlsStack(true);
  final serverTls = MockQuicTlsStack(false);

  // Create QUIC connections
  final clientConnection = QuicConnection(true, clientTls);
  final serverConnection = QuicConnection(false, serverTls);

  // Simulate network communication
  // This is a very simplified model: direct send/receive, no loss, no reordering.
  // A real network simulator would be much more complex.
  Timer? clientSendTimer;
  Timer? serverSendTimer;

  // --- Client initiates handshake ---
  clientConnection.start();

  // Simulate Client Initial packet being sent
  Uint8List? clientInitialPacket = clientTls.getBytesToSend(
    EncryptionLevel.initial,
  );
  if (clientInitialPacket != null) {
    print('\n--- Client sending Initial packet to Server ---');
    // Simulate packet protection for Initial
    var clientKeys = clientConnection.keyManager.getSendKeys(
      EncryptionLevel.initial,
    );
    // Hardcoding header details for initial packet for demo based on mock data
    // Client Initial: Type 0x00, Version 1, DCID len 8, SCID len 8, Token Len 0, Payload Length
    Uint8List clientRawHeader = Uint8List.fromList([
      0xC0 |
          ((clientConnection.sendPacketNumber % 4) +
              1), // First byte + PN length
      0x00, 0x00, 0x00, 0x01, // Version
      clientConnection.localConnectionId.length, // DCID Len
      ...clientConnection
          .localConnectionId, // Client's DCID (becomes server's DCID)
      clientConnection.peerConnectionId.length, // SCID Len (Client's SCID)
      ...clientConnection.peerConnectionId,
      ...VarInt.encode(0), // Token Length
      ...VarInt.encode(
        clientInitialPacket.length + clientKeys!.aead.tagLength,
      ), // Payload Length
    ]);
    int clientPnOffset =
        clientRawHeader.length -
        VarInt.encode(
          clientInitialPacket.length + clientKeys.aead.tagLength,
        ).length; // Simplified

    // Increment client's PN before protecting for accurate nonce calculation
    int currentClientPn = clientConnection.sendPacketNumber++;

    Uint8List protectedClientInitial = clientConnection.packetProtector.protect(
      rawHeader: clientRawHeader,
      payload: clientInitialPacket,
      keys: clientKeys,
      packetNumber: currentClientPn,
      longHeader: true,
      pnOffset: clientPnOffset,
      pnLength: VarInt.encode(currentClientPn).length, // Actual PN length
    );
    print('Client Initial Packet Size: ${protectedClientInitial.length}');
    serverConnection.receiveUdpDatagram(protectedClientInitial);
  }

  // Allow some time for server to process and respond
  await Future.delayed(Duration(milliseconds: 100));

  // --- Server sends its flight ---
  // Server will have derived Initial keys and generated ServerHello/Handshake messages.
  Uint8List? serverHandshakePacket = serverTls.getBytesToSend(
    EncryptionLevel.initial,
  );
  if (serverHandshakePacket != null) {
    print('\n--- Server sending Initial/Handshake packet to Client ---');
    var serverKeys = serverConnection.keyManager.getSendKeys(
      EncryptionLevel.initial,
    ); // Should be server's initial send keys

    Uint8List serverRawHeader = Uint8List.fromList([
      0xC0 |
          ((serverConnection.sendPacketNumber % 4) +
              1), // First byte + PN length
      0x00, 0x00, 0x00, 0x01, // Version
      serverConnection
          .localConnectionId
          .length, // Server's DCID (client's original SCID)
      ...serverConnection.localConnectionId,
      serverConnection
          .peerConnectionId
          .length, // Server's SCID (client's original DCID)
      ...serverConnection.peerConnectionId,
      ...VarInt.encode(0), // Token Length
      ...VarInt.encode(
        serverHandshakePacket.length + serverKeys!.aead.tagLength,
      ), // Payload Length
    ]);
    int serverPnOffset =
        serverRawHeader.length -
        VarInt.encode(
          serverHandshakePacket.length + serverKeys.aead.tagLength,
        ).length; // Simplified

    int currentServerPn = serverConnection.sendPacketNumber++;
    Uint8List protectedServerHandshake = serverConnection.packetProtector
        .protect(
          rawHeader: serverRawHeader,
          payload: serverHandshakePacket,
          keys: serverKeys,
          packetNumber: currentServerPn,
          longHeader: true,
          pnOffset: serverPnOffset,
          pnLength: VarInt.encode(currentServerPn).length,
        );
    print('Server Handshake Packet Size: ${protectedServerHandshake.length}');
    clientConnection.receiveUdpDatagram(protectedServerHandshake);
  }

  // Allow client to process and send its Finished message
  await Future.delayed(Duration(milliseconds: 100));

  // --- Client sends its Finished message (Handshake packet) ---
  Uint8List? clientFinishedPacket = clientTls.getBytesToSend(
    EncryptionLevel.handshake,
  );
  if (clientFinishedPacket != null) {
    print('\n--- Client sending Handshake (Finished) packet to Server ---');
    var clientHandshakeKeys = clientConnection.keyManager.getSendKeys(
      EncryptionLevel.handshake,
    );

    Uint8List clientRawHeader = Uint8List.fromList([
      0xC2 | ((clientConnection.sendPacketNumber % 4) + 1), // Handshake packet
      0x00, 0x00, 0x00, 0x01, // Version
      clientConnection.localConnectionId.length,
      ...clientConnection.localConnectionId,
      clientConnection.peerConnectionId.length,
      ...clientConnection.peerConnectionId,
      ...VarInt.encode(
        clientFinishedPacket.length + clientHandshakeKeys!.aead.tagLength,
      ), // Payload Length
    ]);
    int clientPnOffset =
        clientRawHeader.length -
        VarInt.encode(
          clientFinishedPacket.length + clientHandshakeKeys.aead.tagLength,
        ).length;

    int currentClientPn = clientConnection.sendPacketNumber++;
    Uint8List protectedClientFinished = clientConnection.packetProtector
        .protect(
          rawHeader: clientRawHeader,
          payload: clientFinishedPacket,
          keys: clientHandshakeKeys,
          packetNumber: currentClientPn,
          longHeader: true, // Handshake packets are long header
          pnOffset: clientPnOffset,
          pnLength: VarInt.encode(currentClientPn).length,
        );
    print('Client Finished Packet Size: ${protectedClientFinished.length}');
    serverConnection.receiveUdpDatagram(protectedClientFinished);
  }

  // Allow server to process and send HANDSHAKE_DONE and maybe 1-RTT application data
  await Future.delayed(Duration(milliseconds: 100));

  // --- Server sends HANDSHAKE_DONE and 1-RTT application data ---
  // Server will internally send HANDSHAKE_DONE.
  // Simulate server's 1-RTT app data being sent.
  serverConnection.sendApplicationData(
    EncryptionLevel.oneRtt,
  ); // This will trigger protection and print

  // Allow client to receive and send 1-RTT app data
  await Future.delayed(Duration(milliseconds: 100));

  clientConnection.sendApplicationData(EncryptionLevel.oneRtt);

  await Future.delayed(Duration(milliseconds: 500)); // Keep alive for a bit
  clientConnection.close();
  serverConnection.close();
}
