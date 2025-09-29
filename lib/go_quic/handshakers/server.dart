import 'dart:io';

import '../cert_utils.dart';
import '../processor.dart';
// import '../tests/initial_packet_scenario.dart';
import 'handshake_context.dart';

class HandshakeManager {
  RawDatagramSocket serverSocket;

  late EcdsaCert serverEcCertificate;
  Map<String, HandshakeContext> clients = {};

  HandshakeManager(this.serverSocket) {
    serverEcCertificate = generateSelfSignedCertificate();
    listen();
  }

  void listen() {
    int msg = 0;
    serverSocket.listen((RawSocketEvent event) {
      if (event == RawSocketEvent.read) {
        Datagram? datagram = serverSocket.receive();
        if (datagram != null) {
          // final String response = String.fromCharCodes(datagram.data);
          print('Received data from ${datagram.address.host}:${datagram.port}');
          // print('${datagram.data}');
          unprotectAndParseInitialPacket(datagram.data);
          // if (msg > 2)
          // serverSocket.close(); // Close client after receiving response
          msg++;
        }
      }
    });

    // clientSocket.send(quicIntialPacket, InternetAddress("127.0.0.1"), 4242);
    // print('Sent: message to ${serverAddress.host}:$serverPort');
  }
}
