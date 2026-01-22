import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

// Ensure these match your actual file names
import 'index.dart';

void main() async {
  // 1. Create the server instance using the QuicServerOptions class
  var server = createServer(
    QuicServerOptions(
      sniCallback: (String servername, Function callback) {
        print('Getting certificate for: $servername');

        try {
          // It is better to use readAsBytesSync for TLS credentials
          final key = File('certs/localhost.key').readAsBytesSync();
          final cert = File('certs/localhost.crt').readAsBytesSync();

          // Pass the credentials back via the callback
          callback(null, {'key': key, 'cert': cert});
        } catch (e) {
          print('Error loading certificates: $e');
          callback(e, null);
        }
      },
    ),
  );

  // 2. Handle WebTransport sessions
  server.on('webtransport', (session) {
    print('WebTransport session opened');

    // Define datagram handler
    session.onDatagram = (Uint8List data) {
      var message = utf8.decode(data);
      print('Datagram from client: $message');

      // Echo the data back
      session.send(data);
    };

    // Define close handler
    session.onClose = () {
      print('WebTransport session closed');
    };
  });

  // 3. Start listening on port 4433
  // Changed to '0.0.0.0' or '::' if you want to accept external connections
  await server.listen(4433, '127.0.0.1', () {
    print('QUIC server running on port 4433');
  });
}
