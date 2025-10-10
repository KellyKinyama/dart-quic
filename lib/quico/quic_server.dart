// --- Imports (Must be available in the Dart environment) ---
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

// Third-party package for hex encoding
import 'package:hex/hex.dart';

// Local project dependencies (ported from .js files)
import 'utils.dart'; // VarInt helpers, concatUint8Lists
import 'tls_crypto.dart'; // QUIC key derivation functions (Includes QUICKeys class)
import 'quic_packet.dart'; // Packet decryption classes and methods (Includes decryptQuicPacket)

// --- Mock/Placeholder Classes (Full implementation depends on other files) ---

class QUICSession {
  final Uint8List dcid;
  final String address;
  final int port;
  // State for keys, stream limits, largest PN, etc., would be managed here.

  QUICSession({required this.dcid, required this.address, required this.port});

  // Mock method to simulate processing decrypted frames
  void handleDecryptedPacket(Uint8List plaintext) {
    // In a full implementation, this calls the frame parser and stream handlers.
    print(
      'Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.',
    );
  }
}

// --- QUICServer Class (Port of index.js) ---

class QUICServer {
  // Dart equivalent of JS var self._QUIC_SESSIONS
  final Map<String, QUICSession> _quicSessions = {};

  // Dart equivalent of JS var self._udp4 / self._udp6
  RawDatagramSocket? _udp4;
  RawDatagramSocket? _udp6;

  int _port;
  String? _host;

  // Handlers (Dart equivalent of JS this._handler and this._webtransport_handler)
  void Function(QUICSession)? _handler;
  void Function(dynamic)? _webtransportHandler;

  QUICServer({int port = 0, String? host}) : _port = port, _host = host;

  // --- Core Packet Receiver (Port of receiving_udp_quic_packet) ---
  void _receivingQuicPacket(InternetAddress address, int port, Uint8List msg) {
    if (msg.isEmpty) return;

    final firstByte = msg[0];
    final isLongHeader = (firstByte & 0x80) != 0;

    Uint8List dcid;
    String dcidHex;

    // The complexity of QUIC headers requires careful parsing, especially for Long Headers.
    if (isLongHeader) {
      // Assuming a Long Header: Initial (0xC0-0xC3), R(4 bits) + V(4 bytes) + DCIDL(1 byte) + DCID
      if (msg.length < 7) {
        print('Packet too short for Long Header parsing');
        return;
      }

      final dcidLen = msg[6];
      if (dcidLen > 20 || dcidLen == 0) return; // Invalid length

      dcid = msg.sublist(7, 7 + dcidLen);
      dcidHex = HEX.encode(dcid);

      var quicSession = _quicSessions[dcidHex];

      if (quicSession == null) {
        // Handle new connection (Initial packet)
        if ((firstByte & 0xC0) == 0xC0) {
          final version = ByteData.view(
            msg.buffer,
            msg.offsetInBytes + 1,
            4,
          ).getUint32(0);

          try {
            // FIX: Destructure the record returned by quicDeriveInitSecrets
            final (_, initKeys) = quicDeriveInitSecrets(dcid, version, 'read');

            // Decrypt the Initial packet
            final decryptedPacket = decryptQuicPacket(
              msg,
              initKeys.key,
              initKeys.iv,
              initKeys.hp,
              dcid,
              0, // largestPn for Initial is 0
            );

            if (decryptedPacket != null && decryptedPacket.plaintext != null) {
              print(
                'Successfully decrypted Initial packet. Creating new session.',
              );
              // Session creation and initial handshake response logic goes here.
              quicSession = QUICSession(
                dcid: dcid,
                address: address.address,
                port: port,
              );
              _quicSessions[dcidHex] = quicSession;

              // Pass the plaintext frames to the session handler
              quicSession.handleDecryptedPacket(decryptedPacket.plaintext!);
            }
          } catch (e) {
            print('Error processing Initial packet: $e');
          }
        }
      } else {
        // For existing sessions receiving Handshake/0RTT Long Headers,
        // decryption is required here using the appropriate negotiated keys.
        // For now, we print a warning as the required session state is missing:
        print(
          'WARNING: Received Long Header for existing session. Decryption skipped (missing session key state).',
        );
      }
    } else {
      // Short Header (1RTT)
      // Needs to look up session using the DCID.

      // Placeholder DCID extraction (e.g., assuming first 8 bytes after Type)
      if (msg.length < 9) return;
      dcid = msg.sublist(1, 9);
      dcidHex = HEX.encode(dcid);

      var quicSession = _quicSessions[dcidHex];
      if (quicSession != null) {
        // FIX: Short Header (1RTT) packets must be decrypted.
        // In a real implementation, the session must provide the 1-RTT read keys and largest PN.
        try {
          // Placeholder keys - Replace with quicSession.oneRttReadKey, etc.
          // Note: These must match the cipher suite lengths (16/12/16 for AES-128-GCM)
          final mockKey = Uint8List(16);
          final mockIv = Uint8List(12);
          final mockHp = Uint8List(16);

          final decryptedPacket = decryptQuicPacket(
            msg,
            mockKey, // Session's current 1-RTT read key
            mockIv, // Session's current 1-RTT read IV
            mockHp, // Session's current 1-RTT read HP key
            dcid,
            0, // Replace with session's largestPn received
          );

          if (decryptedPacket != null && decryptedPacket.plaintext != null) {
            // Pass the plaintext frames to the session handler
            quicSession.handleDecryptedPacket(decryptedPacket.plaintext!);
          } else {
            print('Short Header decryption failed.');
          }
        } catch (e) {
          print('Error processing Short Header packet: $e');
        }
      }
    }
  }

  // --- Public Methods (Port of QUICServer.listen and QUICServer.on) ---

  /// Starts the QUIC server listening on UDP sockets.
  Future<void> listen(int port, String host, [Function? callback]) async {
    _port = port;
    _host = host;

    // 1. Setup IPv4 Socket (Port of JS self._udp4 setup)
    if (host == '::' || host.contains('.')) {
      final host4 = host.contains('.') ? host : InternetAddress.anyIPv4.address;
      try {
        _udp4 = await RawDatagramSocket.bind(host4, _port, reuseAddress: true);
        _udp4!.listen((RawSocketEvent event) {
          if (event == RawSocketEvent.read) {
            final datagram = _udp4!.receive();
            if (datagram != null) {
              _receivingQuicPacket(
                datagram.address,
                datagram.port,
                datagram.data,
              );
            }
          }
        });
        print('QUIC listening on udp4://$host4:$port');
      } on SocketException catch (e) {
        print('Error binding IPv4 socket: $e');
      }
    }

    // 2. Setup IPv6 Socket (Port of JS self._udp6 setup)
    if (host == '::' || host.contains(':')) {
      final host6 = host.contains(':') ? host : InternetAddress.anyIPv6.address;
      try {
        _udp6 = await RawDatagramSocket.bind(
          host6,
          _port,
          reuseAddress: true,
          // ipv6Only: true, // Corrected to explicitly set ipv6Only
        );
        _udp6!.listen((RawSocketEvent event) {
          if (event == RawSocketEvent.read) {
            final datagram = _udp6!.receive();
            if (datagram != null) {
              _receivingQuicPacket(
                datagram.address,
                datagram.port,
                datagram.data,
              );
            }
          }
        });
        print('QUIC listening on udp6://$host6:$port');
      } on SocketException catch (e) {
        print('Error binding IPv6 socket: $e');
      }
    }

    if (callback != null) {
      callback();
    }
  }

  /// Registers event handlers.
  void on(String event, Function cb) {
    if (event == 'request') {
      _handler = cb as void Function(QUICSession);
    } else if (event == 'webtransport') {
      // FIX: Explicitly cast the generic 'Function' to the expected type
      _webtransportHandler = cb as void Function(dynamic);
    }
  }

  /// Closes both UDP sockets.
  void close() {
    _udp4?.close();
    _udp6?.close();
    _quicSessions.clear();
    print('QUIC server closed.');
  }
}
