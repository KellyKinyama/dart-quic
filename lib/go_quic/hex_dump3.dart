// Your main file: hex_dump2.dart

import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:dart_quic/go_quic/quic_connection.dart';
import 'package:dart_quic/go_quic/protocol.dart';

// Mock packet data from a real handshake trace
// Packet 1: Server's Initial (contains ServerHello)
final serverInitialPacket = HEX.decode(
  'cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee',
);

// Packet 2: Server's Handshake (contains EncryptedExtensions, Cert, etc.)
final serverHandshakePacket = HEX.decode(
  'c2000000010008f067a5502a4262b500403500005d532535728b9505c24941913f380145ca033d59e39d372ce6662a4b8b68853612d1b3bff247900b971a82984714a1a05837cb1e485458eb48b612d381014e7105421b1065271882d40004ab497495b',
);

// Packet 3: Server's 1-RTT (contains HANDSHAKE_DONE and application data)
final serverOneRTTPacket = HEX.decode(
  '415f989f5b2b4429c4202c46f685f6756627055a409951a1',
);

void main() {
  // 1. Initialize the client's view of the connection
  final clientConnection = QuicConnection(
    initialDestinationCid: Uint8List.fromList(
      HEX.decode("f067a5502a4262b5"),
    ), // Server's SCID from the log
    perspective: Perspective.client,
  );

  // 2. Client receives and processes the server's Initial packet
  clientConnection.processPacket(Uint8List.fromList(serverInitialPacket));

  // 3. Client receives and processes the server's Handshake packet
  // The connection object will automatically use the newly derived Handshake keys.
  clientConnection.processPacket(Uint8List.fromList(serverHandshakePacket));

  // 4. Client receives and processes a 1-RTT packet
  // The connection object will use the final 1-RTT keys.
  clientConnection.processPacket(Uint8List.fromList(serverOneRTTPacket));
}
