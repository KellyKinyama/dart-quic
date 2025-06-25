// lib/src/tls_stack.dart
import 'dart:typed_data';

import 'enums.dart';
import 'transport_parameters.dart';
import 'package:quic_tls_analysis/src/types.dart';

/// Abstract interface for the TLS 1.3 stack.
/// In a real QUIC implementation, this would be an FFI wrapper around
/// a native TLS library (e.g., BoringSSL) or a complex pure-Dart TLS 1.3 impl.
abstract class QuicTlsStack {
  final bool isClient;
  QuicTlsStack(this.isClient);

  /// Feeds received handshake data to the TLS stack.
  void processInput(Uint8List data, EncryptionLevel level);

  /// Requests handshake data from the TLS stack to be sent.
  /// Returns null if no data is available to send at the current level.
  Uint8List? getBytesToSend(EncryptionLevel level);

  /// Sets the local QUIC transport parameters to be sent in ClientHello/EncryptedExtensions.
  void setTransportParameters(QuicTransportParameters params);

  /// Gets the peer's negotiated transport parameters after handshake completion.
  /// Throws if handshake not complete or parameters not available.
  QuicTransportParameters getPeerTransportParameters();

  /// Called by TLS stack when new traffic secrets are available.
  /// (Simplified: a real TLS library would pass more specific secrets like early_secret, handshake_secret, master_secret)
  void Function(
    EncryptionLevel level,
    Uint8List clientTrafficSecret,
    Uint8List serverTrafficSecret,
    AEADAlgorithm negotiatedAead,
    KDFAlgorithm negotiatedKdf,
  )?
  onNewTrafficSecrets;

  /// Called by TLS stack when its handshake is complete (Finished sent and peer's Finished verified).
  void Function()? onHandshakeComplete;

  /// Called by TLS stack when a TLS alert is generated.
  void Function(int alertDescription)? onTlsAlert;

  /// Client-side: Signals if 0-RTT was accepted by the server.
  bool is0RttAccepted();

  /// Server-side: Determines if it's willing to accept 0-RTT.
  bool canAccept0Rtt();

  // Lifecycle methods for the TLS stack
  void startHandshake();
  void close();
}

// Mock TLS 1.3 Stack for demonstration purposes
class MockQuicTlsStack extends QuicTlsStack {
  MockQuicTlsStack(bool isClient) : super(isClient);

  // Internal state to simulate handshake
  int _currentInputOffset = 0;
  final List<Uint8List> _clientHandshakeMessages =
      []; // Simulates client's handshake messages
  final List<Uint8List> _serverHandshakeMessages =
      []; // Simulates server's handshake messages
  EncryptionLevel _currentSendLevel = EncryptionLevel.initial;
  EncryptionLevel _currentReceiveLevel = EncryptionLevel.initial;
  bool _handshakeDone = false;
  bool _0RttAccepted = false;
  QuicTransportParameters? _peerTransportParameters;

  @override
  void processInput(Uint8List data, EncryptionLevel level) {
    print('TLS Stack: Received ${data.length} bytes for $level');
    // Simulate TLS processing incoming data
    if (isClient) {
      _serverHandshakeMessages.add(data);
      // Simulate client reacting to server's messages
      if (level == EncryptionLevel.initial && data.length > 50) {
        // Assume serverhello is larger
        // Simulate Handshake keys being available
        _currentSendLevel = EncryptionLevel.handshake;
        _currentReceiveLevel = EncryptionLevel.handshake;
        onNewTrafficSecrets?.call(
          EncryptionLevel.handshake,
          Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
          Uint8List.fromList([0, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
          aes128Gcm,
          sha256Kdf,
        ); // Mock
        _0RttAccepted = true; // For demo purposes
        _peerTransportParameters = QuicTransportParameters(
          initialMaxData: 10000,
        ); // Mock peer TP
      }
      if (level == EncryptionLevel.handshake &&
          _serverHandshakeMessages.length >= 2) {
        // Assume Finished arrived
        _handshakeDone = true;
        onHandshakeComplete?.call();
        // Simulate 1-RTT keys being available
        _currentSendLevel = EncryptionLevel.oneRtt;
        _currentReceiveLevel = EncryptionLevel.oneRtt;
        onNewTrafficSecrets?.call(
          EncryptionLevel.oneRtt,
          Uint8List.fromList([11, 12, 13, 14, 15]),
          Uint8List.fromList([15, 14, 13, 12, 11]),
          aes128Gcm,
          sha256Kdf,
        ); // Mock
      }
    } else {
      // Server
      _clientHandshakeMessages.add(data);
      if (level == EncryptionLevel.initial && data.length > 50) {
        // ClientHello received
        // Simulate Handshake keys being available
        _currentSendLevel = EncryptionLevel.handshake;
        _currentReceiveLevel = EncryptionLevel.handshake;
        onNewTrafficSecrets?.call(
          EncryptionLevel.handshake,
          Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
          Uint8List.fromList([0, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
          aes128Gcm,
          sha256Kdf,
        ); // Mock
        _0RttAccepted = true; // For demo purposes
        _peerTransportParameters = QuicTransportParameters(
          initialMaxData: 10000,
        ); // Mock peer TP
      }
      if (level == EncryptionLevel.handshake &&
          _clientHandshakeMessages.length >= 2) {
        // Client Finished received
        _handshakeDone = true;
        onHandshakeComplete?.call();
        // Simulate 1-RTT keys being available
        _currentSendLevel = EncryptionLevel.oneRtt;
        _currentReceiveLevel = EncryptionLevel.oneRtt;
        onNewTrafficSecrets?.call(
          EncryptionLevel.oneRtt,
          Uint8List.fromList([11, 12, 13, 14, 15]),
          Uint8List.fromList([15, 14, 13, 12, 11]),
          aes128Gcm,
          sha256Kdf,
        ); // Mock
      }
    }
  }

  @override
  Uint8List? getBytesToSend(EncryptionLevel level) {
    if (level != _currentSendLevel) return null; // Only send from current level

    if (isClient) {
      if (level == EncryptionLevel.initial &&
          _clientHandshakeMessages.isEmpty) {
        // Simulate ClientHello
        return Uint8List.fromList(
          List.generate(100, (i) => i),
        ); // Mock ClientHello
      } else if (level == EncryptionLevel.handshake &&
          _serverHandshakeMessages.isNotEmpty &&
          !_handshakeDone) {
        // Simulate Client Finished
        return Uint8List.fromList(
          List.generate(50, (i) => i + 100),
        ); // Mock Client Finished
      }
    } else {
      // Server
      if (level == EncryptionLevel.initial &&
          _clientHandshakeMessages.isNotEmpty &&
          _serverHandshakeMessages.isEmpty) {
        // Simulate ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished
        return Uint8List.fromList(
          List.generate(200, (i) => i),
        ); // Mock Server Flight 1
      } else if (level == EncryptionLevel.handshake &&
          _clientHandshakeMessages.length >= 2 &&
          !_handshakeDone) {
        // No more handshake messages for server after its Finished
        return null;
      }
    }
    return null;
  }

  @override
  void setTransportParameters(QuicTransportParameters params) {
    print(
      'TLS Stack: Set local transport parameters: ${params.initialMaxData}',
    );
    // In a real TLS, this would configure the TLS `quic_transport_parameters` extension.
  }

  @override
  QuicTransportParameters getPeerTransportParameters() {
    if (_peerTransportParameters == null) {
      throw QuicError(
        QuicConstants.protocolViolation,
        'Peer transport parameters not available yet.',
      );
    }
    return _peerTransportParameters!;
  }

  @override
  void onHandshakeComplete() {
    print('TLS Stack: Handshake completed.');
  }

  @override
  void onHandshakeConfirmed() {
    print('TLS Stack: Handshake confirmed.');
  }

  @override
  void onTlsAlert(int alertDescription) {
    print('TLS Stack: TLS Alert: $alertDescription');
  }

  @override
  bool is0RttAccepted() => _0RttAccepted;

  @override
  bool canAccept0Rtt() => true; // Server always accepts 0-RTT in this mock

  @override
  void startHandshake() {
    print('TLS Stack: Handshake started.');
  }

  @override
  void close() {
    print('TLS Stack: Closed.');
  }
}
