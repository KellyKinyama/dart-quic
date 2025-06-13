import 'dart:io';
import 'dart:typed_data';

void main() async {
  final InternetAddress serverAddress =
      InternetAddress.loopbackIPv4; // Or your server's IP
  final int serverPort = 4433; // Port your UDP server is listening on

  final RawDatagramSocket clientSocket = await RawDatagramSocket.bind(
    InternetAddress("127.0.0.1"),
    443,
  ); // Bind to any available port
  print('UDP Client started on port ${clientSocket.port}');

  // Send a message
  final String message = "Hello from Dart Client!";
  final Uint8List data = Uint8List.fromList(message.codeUnits);
  // clientSocket.send(data, serverAddress, serverPort);
  print('Sent: "$message" to ${serverAddress.host}:$serverPort');

  // Listen for a response
  clientSocket.listen((RawSocketEvent event) {
    if (event == RawSocketEvent.read) {
      Datagram? datagram = clientSocket.receive();
      if (datagram != null) {
        final String response = String.fromCharCodes(datagram.data);
        print(
          'Received response from ${datagram.address.host}:${datagram.port}: "$response"',
        );
        // clientSocket.close(); // Close client after receiving response
      }
    }
  });

  // Optional: Add a timeout to close the client if no response is received
  // Future.delayed(Duration(seconds: 5), () {
  //   if (!clientSocket.isClosed) {
  //     print('No response received within timeout. Closing client.');
  //     clientSocket.close();
  //   }
  // });
}
