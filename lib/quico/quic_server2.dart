import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

// Note: You must define or import the following external functions/classes:
// 1. QuicServer (Placeholder class structure is provided for context)
// 2. receivingUdpQuicPacket (The function ported in the previous step)

// Placeholder for the external connection handler function
// In a real Dart implementation, this would likely be part of the QuicServer class.
// For now, we match the structure provided by the JS to simplify the porting.
void receivingUdpQuicPacket(
  QuicServer server,
  String fromIp,
  int fromPort,
  Uint8List udpPacketData,
) {
  // Placeholder - actual implementation from previous response
}

/// Represents the QUIC server object, handling UDP sockets and connection management.
class QuicServer {
  // Internal properties
  RawDatagramSocket? _udp4;
  RawDatagramSocket? _udp6;
  int? _port;
  Timer? _timeoutTimer;

  // External-facing handlers and state
  Function? _handler; // For 'request' event
  Function? _webtransportHandler; // For 'webtransport' event
  final Function? sNICallback; // From options

  // Connection State Maps
  // Key: DCID in hex string (String), Value: QuicConnection object (dynamic)
  final Map<String, dynamic> connections = {};
  // Key: IP:Port string (String), Value: DCID in hex string (String)
  final Map<String, String> addressBinds = {};

  // Constructor
  QuicServer({required Map<String, dynamic> options, Function? handler})
    : _handler = handler,
      sNICallback = options['SNICallback'] as Function?;

  /// Starts listening for UDP packets on the specified port and host.
  ///
  /// The logic handles default values and the Node.js `dgram` setup
  /// for IPv4 and IPv6 sockets.
  Future<void> listen([
    int? port,
    dynamic host, // Can be String or Function (callback)
    Function? callback,
  ]) async {
    // 1. Handle optional arguments (JS style)
    if (host is Function) {
      callback = host;
      host = null;
    }
    String hostStr = (host as String?) ?? '::';
    _port = port ?? 443;

    // 2. Setup UDP4 Socket
    if (hostStr == '::' || hostStr.contains('.')) {
      String host4 = hostStr.contains('.') ? hostStr : '0.0.0.0';
      _udp4 = await RawDatagramSocket.bind(host4, _port!);
      _udp4!.listen(
        (RawSocketEvent event) {
          if (event == RawSocketEvent.read) {
            final Datagram? dg = _udp4!.receive();
            if (dg != null) {
              // Call the shared packet receiving function
              receivingUdpQuicPacket(
                this,
                dg.address.address,
                dg.port,
                dg.data,
              );
            }
          } else if (event == RawSocketEvent.closed) {
            // Handle close event
          }
        },
        onError: (err) {
          // console.error('UDP4 error:', err);
          // Note: Dart socket errors are handled via the onError listener
        },
      );
    }

    // 3. Setup UDP6 Socket
    String host6 = hostStr.contains(':') ? hostStr : '::';
    // Dart's RawDatagramSocket.bind handles IPv6 correctly, often
    // requiring `ipv6Only: true` to prevent IPv4 traffic on the IPv6 socket.
    _udp6 = await RawDatagramSocket.bind(
      host6,
      _port!,
      // We assume we want separate sockets for v4/v6 like the JS version.
      // `v6Only: true` is crucial to prevent the IPv6 socket from binding
      // to IPv4 traffic, mimicking the Node.js `ipv6Only: true` behavior.
      v6Only: true,
    );

    _udp6!.listen(
      (RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          final Datagram? dg = _udp6!.receive();
          if (dg != null) {
            // Call the shared packet receiving function
            receivingUdpQuicPacket(this, dg.address.address, dg.port, dg.data);
          }
        } else if (event == RawSocketEvent.closed) {
          // Handle close event
        }
      },
      onError: (err) {
        // console.error('UDP6 error:', err);
      },
    );

    // 4. Call the optional callback upon successful binding (after the second bind completes)
    if (callback != null) {
      callback();
    }
  }

  /// Registers event handlers (mimics Node.js EventEmitter `.on()`).
  void on(String event, Function cb) {
    switch (event) {
      case 'request':
        _handler = cb;
        break;
      case 'webtransport':
        _webtransportHandler = cb;
        break;
      case 'OCSPRequest':
      // Handlers for 'OCSPRequest', 'newSession', 'resumeSession' are placeholders
      // and would require specific Dart TLS/QUIC library integration.
      case 'newSession':
      case 'resumeSession':
        break;
      default:
        // Handle unknown event if necessary
        break;
    }
  }

  /// Closes both UDP sockets.
  void close() {
    _udp4?.close();
    _udp6?.close();
    _timeoutTimer?.cancel();
  }

  /// Sets a connection timeout (mimics Node.js `setTimeout`).
  void setTimeout(int ms, Function cb) {
    _timeoutTimer?.cancel(); // Cancel any existing timeout
    _timeoutTimer = Timer(Duration(milliseconds: ms), () {
      cb();
    });
  }
}

// --- Factory function to mirror the Node.js API ---

/// Factory function to create a new QuicServer instance.
QuicServer createServer(Map<String, dynamic> options, [Function? handler]) {
  return QuicServer(options: options, handler: handler);
}
