// Create this new file to manage the connection state.
import 'dart:typed_data';
import 'package:hex/hex.dart';

import 'aead.dart';
import 'cipher_suite.dart';
import 'header_protector.dart';
import 'hkdf.dart';
import 'initial_aead.dart';
import 'protocol.dart';
import 'quic_frame_parser.dart';

/// A mock TLS 1.3 state machine that produces the required secrets.
/// In a real implementation, this would be a full TLS stack.
class MockTls {
  // Secrets would be derived from a real TLS exchange.
  // For this example, we'll use hardcoded placeholder secrets.
  final clientHandshakeSecret = HEX.decode(
    'c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea',
  );
  final serverHandshakeSecret = HEX.decode(
    '3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b',
  );
  final clientAppSecret = HEX.decode(
    '9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b',
  );
  final serverAppSecret = HEX.decode(
    '9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b',
  );

  bool handshakeComplete = false;

  void processCryptoData(Uint8List data) {
    // In a real implementation, this feeds data into the TLS engine.
    // For our simulation, we'll just assume the server's Finished message
    // completes the handshake.
    print('TLS> Processing ${data.length} bytes of crypto data...');
    handshakeComplete = true; // Simulate handshake completion
  }
}

/// Manages the full state of a QUIC connection, including keys for all levels.
class QuicConnection {
  final Perspective perspective;
  final MockTls tls = MockTls();
  final CipherSuite cipherSuite = getCipherSuite(
    0x1301,
  ); // TLS_AES_128_GCM_SHA256

  // Key sets for each encryption level
  late final LongHeaderOpener initialOpener;
  LongHeaderOpener? handshakeOpener;
  LongHeaderOpener? oneRTTOpener;

  QuicConnection({
    required Uint8List initialDestinationCid,
    required this.perspective,
  }) {
    final (_, opener) = newInitialAEAD(
      initialDestinationCid,
      perspective,
      Version.version1,
    );
    initialOpener = opener;
  }

  /// Main entry point for processing an incoming packet.
  void processPacket(Uint8List packetBytes) {
    final firstByte = packetBytes[0];
    if ((firstByte & 0x80) == 0) {
      // Short Header (1-RTT)
      print('\n--- Processing 1-RTT Packet ---');
      _unprotectAndParse(packetBytes, 'OneRTT', oneRTTOpener);
    } else {
      // Long Header
      final packetType = (firstByte & 0x30) >> 4;
      if (packetType == 0) {
        // Initial
        print('\n--- Processing Initial Packet ---');
        _unprotectAndParse(packetBytes, 'Initial', initialOpener);
      } else if (packetType == 2) {
        // Handshake
        print('\n--- Processing Handshake Packet ---');
        _unprotectAndParse(packetBytes, 'Handshake', handshakeOpener);
      }
    }
  }

  /// Generic packet decryption and frame parsing logic.
  void _unprotectAndParse(
    Uint8List packetBytes,
    String level,
    LongHeaderOpener? opener,
  ) {
    if (opener == null) {
      print(
        '❌ ERROR: No keys available to decrypt $level packet. Packet dropped.',
      );
      return;
    }

    // NOTE: This is a simplified header parser for the example.
    // A real implementation would parse all header fields correctly.
    final headerLength = 21;
    final header = packetBytes.sublist(0, headerLength);
    final ciphertext = packetBytes.sublist(headerLength);
    final packetNumber = 0; // Simplified for this example.

    try {
      final plaintext = opener.open(ciphertext, packetNumber, header);
      print('✅ Packet decrypted successfully!');

      final parser = QuicFrameParser(encryptionLevel: level);
      final frames = parser.parse(plaintext);

      for (final frame in frames) {
        if (frame is CryptoFrame) {
          tls.processCryptoData(frame.messages.first.messageBody); // Simplified
          // After processing TLS data, check if we can derive new keys
          _updateKeys();
        }
      }
    } catch (e) {
      print('❌ ERROR: Failed to decrypt $level packet: $e');
    }
  }

  /// Derives and installs new keys as the handshake progresses.
  void _updateKeys() {
    // 1. Derive Handshake Keys if they aren't already available
    if (handshakeOpener == null) {
      print('🔑 Deriving Handshake Keys...');
      final secret = (perspective == Perspective.client)
          ? tls.serverHandshakeSecret
          : tls.clientHandshakeSecret;
      handshakeOpener = _createOpenerFromSecret(Uint8List.fromList(secret));
    }

    // 2. Derive 1-RTT Keys if the handshake is complete
    if (oneRTTOpener == null && tls.handshakeComplete) {
      print('🔑 Deriving 1-RTT Keys...');
      final secret = (perspective == Perspective.client)
          ? tls.serverAppSecret
          : tls.clientAppSecret;
      oneRTTOpener = _createOpenerFromSecret(Uint8List.fromList(secret));
      print('🤝 Handshake Complete!');
    }
  }

  /// Helper to create an AEAD opener from a TLS traffic secret.
  LongHeaderOpener _createOpenerFromSecret(Uint8List secret) {
    final key = hkdfExpandLabel(
      secret,
      Uint8List(0),
      'quic key',
      cipherSuite.keyLen,
    );
    final iv = hkdfExpandLabel(
      secret,
      Uint8List(0),
      'quic iv',
      cipherSuite.ivLen,
    );
    final hpKey = hkdfExpandLabel(
      secret,
      Uint8List(0),
      hkdfHeaderProtectionLabel(Version.version1),
      cipherSuite.keyLen,
    );

    final aead = cipherSuite.aead(key: key, nonceMask: iv);
    final headerProtector = newHeaderProtector(
      cipherSuite,
      hpKey,
      true,
      Version.version1,
    );
    return LongHeaderOpener(aead, headerProtector);
  }
}
