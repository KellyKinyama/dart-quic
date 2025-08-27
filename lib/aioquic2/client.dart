// Filename: client.dart
import 'dart:io';
import 'dart:typed_data';
import 'dart:async';
import 'configuration.dart';
import 'connection.dart';
import 'events.dart';

void main() async {
  // 1. Create a configuration for the client.
  final config = QuicConfiguration(isClient: true, alpnProtocols: ['echo']);

  final remoteAddress = InternetAddress('127.0.0.1');
  final remotePort = 4433;

  // 2. Create a QUIC connection.
  final conn = QuicConnection(configuration: config);

  // 3. Bind a UDP socket.
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print('Client bound to ${socket.address.address}:${socket.port}');

  // 4. Initiate the connection.
  conn.connect(
    serverName: remoteAddress.address,
    port: remotePort,
    now: DateTime.now().millisecondsSinceEpoch / 1000.0,
  );

  // 5. Send initial packets.
  var (datagrams, _, _) = await conn.datagramsToSend(
    DateTime.now().millisecondsSinceEpoch / 1000.0,
  );
  for (final packet in datagrams) {
    socket.send(packet, remoteAddress, remotePort);
  }

  // 6. Create a stream and send data.
  final streamId = conn.createStream();
  final message = Uint8List.fromList('hello from client'.codeUnits);
  conn.sendStreamData(streamId, message, endStream: true);
  print('Client sent: ${String.fromCharCodes(message)}');

  // 7. Start a timer to handle connection events and timers.
  Timer.periodic(Duration(milliseconds: 10), (timer) async {
    // Handle timers
    final timerAt = conn.getTimer();
    if (timerAt != null &&
        DateTime.now().millisecondsSinceEpoch / 1000.0 >= timerAt) {
      conn.handleTimer(DateTime.now().millisecondsSinceEpoch / 1000.0);
    }

    // Send outgoing packets
    var (datagrams, _, _) = await conn.datagramsToSend(
      DateTime.now().millisecondsSinceEpoch / 1000.0,
    );
    for (final packet in datagrams) {
      socket.send(packet, remoteAddress, remotePort);
    }
  });

  // 8. Listen for incoming data and events.
  await for (final event in socket) {
    if (event == RawSocketEvent.read) {
      final datagram = socket.receive();
      if (datagram == null) continue;

      conn.receiveDatagram(
        datagram.data,
        DateTime.now().millisecondsSinceEpoch / 1000.0,
      );

      QuicEvent? quicEvent;
      while ((quicEvent = conn.nextEvent()) != null) {
        if (quicEvent is StreamDataReceived) {
          print(
            'Client received: ${String.fromCharCodes(quicEvent.data)} on stream ${quicEvent.streamId}',
          );
          if (quicEvent.endStream) {
            print('Stream ${quicEvent.streamId} closed.');
            socket.close();
            exit(0);
          }
        }
      }
    }
  }
}
