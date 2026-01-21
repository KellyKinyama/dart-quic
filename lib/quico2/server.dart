import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'index.dart';

void main() async {
  // 1. Create the server instance with the SNICallback
  var server = createServer({
    'SNICallback': (String servername, Function callback) {
      print('Getting certificate for: $servername');

      try {
        // Read certificate and key from files
        final key = File('certs/localhost.key').readAsStringSync();
        final cert = File('certs/localhost.crt').readAsStringSync();

        // Pass the credentials back via the callback
        callback(null, {'key': key, 'cert': cert});
      } catch (e) {
        callback(e, null);
      }
    },
  });

  // 2. Handle WebTransport sessions (Event-driven pattern)
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
  await server.listen(4433, '::', () {
    print('QUIC server running on port 4433');
  });
}
