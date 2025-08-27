// Filename: server.dart
import 'dart:io';
import 'dart:typed_data';
import 'configuration.dart';
import 'connection.dart';
import 'events.dart';

void main() async {
  // 1. Create a configuration for the server.
  final config = QuicConfiguration(
    isClient: false,
    alpnProtocols: ['echo'],
    // In a real application, you would load a certificate and private key.
    // certificate: ...,
    // privateKey: ...,
  );

  // 2. Bind a UDP socket.
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);
  print('Server listening on ${socket.address.address}:${socket.port}');

  final connections = <String, QuicConnection>{};

  // 3. Listen for incoming datagrams.
  await for (final event in socket) {
    if (event == RawSocketEvent.read) {
      final datagram = socket.receive();
      if (datagram == null) continue;

      final remoteAddress = '${datagram.address.address}:${datagram.port}';
      
      // 4. Find or create a connection for the remote address.
      var conn = connections[remoteAddress];
      if (conn == null) {
        print('New connection from $remoteAddress');
        conn = QuicConnection(configuration: config);
        connections[remoteAddress] = conn;
      }
      
      // 5. Process the incoming datagram.
      conn.receiveDatagram(datagram.data, DateTime.now().millisecondsSinceEpoch / 1000.0);
      
      // 6. Process connection events.
      QuicEvent? quicEvent;
      while ((quicEvent = conn.nextEvent()) != null) {
        if (quicEvent is StreamDataReceived) {
          print('Server received: ${String.fromCharCodes(quicEvent.data)} on stream ${quicEvent.streamId}');
          // Echo the data back.
          conn.sendStreamData(quicEvent.streamId, quicEvent.data, endStream: quicEvent.endStream);
        }
      }
      
      // 7. Send any outgoing datagrams.
      final (datagrams, _, _) = await conn.datagramsToSend(DateTime.now().millisecondsSinceEpoch / 1000.0);
      for (final packet in datagrams) {
        socket.send(packet, datagram.address, datagram.port);
      }
    }
  }
}