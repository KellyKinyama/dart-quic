// lib/src/key_manager.dart
import 'dart:typed_data';

import 'enums.dart';
// import 'package:quic_tls_analysis/src/types.dart';

class QuicPacketProtectionKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hpKey; // Header Protection Key
  final AEADAlgorithm aead;
  final KDFAlgorithm kdf;

  QuicPacketProtectionKeys({
    required this.key,
    required this.iv,
    required this.hpKey,
    required this.aead,
    required this.kdf,
  });
}

// lib/src/key_manager.dart (continued)

class QuicKeyManager {
  // Map to store send/receive keys for each encryption level
  final Map<EncryptionLevel, QuicPacketProtectionKeys> _sendKeys = {};
  final Map<EncryptionLevel, QuicPacketProtectionKeys> _receiveKeys = {};

  // For Initial secrets, KDF is always SHA-256
  final KDFAlgorithm _initialKdf = sha256Kdf;

  void setSendKeys(EncryptionLevel level, QuicPacketProtectionKeys keys) {
    _sendKeys[level] = keys;
  }

  void setReceiveKeys(EncryptionLevel level, QuicPacketProtectionKeys keys) {
    _receiveKeys[level] = keys;
  }

  QuicPacketProtectionKeys? getSendKeys(EncryptionLevel level) =>
      _sendKeys[level];
  QuicPacketProtectionKeys? getReceiveKeys(EncryptionLevel level) =>
      _receiveKeys[level];

  /// Derives Initial secrets and packet protection keys (RFC 9001, Section 5.2).
  /// [clientDstConnectionId]: The Destination Connection ID from the client's first Initial packet.
  void deriveInitialKeys(Uint8List clientDstConnectionId) {
    final Uint8List initialSecret = _initialKdf.hkdfExtract(
      Uint8List.fromList(QuicConstants.initialSalt),
      clientDstConnectionId,
    );

    final Uint8List clientInitialSecret = _initialKdf.hkdfExpandLabel(
      initialSecret,
      "client in",
      Uint8List(0), // Zero-length context
      _initialKdf.hashLength,
    );

    final Uint8List serverInitialSecret = _initialKdf.hkdfExpandLabel(
      initialSecret,
      "server in",
      Uint8List(0), // Zero-length context
      _initialKdf.hashLength,
    );

    // Initial packets use AEAD_AES_128_GCM (RFC 9001, Section 5)
    final initialAead = aes128Gcm; // Or specific AES-128-GCM implementation

    // Derive client's send keys for Initial packets
    final clientInitialSendKeys = QuicPacketProtectionKeys(
      key: _initialKdf.hkdfExpandLabel(
        clientInitialSecret,
        "quic key",
        Uint8List(0),
        initialAead.keyLength,
      ),
      iv: _initialKdf.hkdfExpandLabel(
        clientInitialSecret,
        "quic iv",
        Uint8List(0),
        initialAead.ivLength,
      ),
      hpKey: _initialKdf.hkdfExpandLabel(
        clientInitialSecret,
        "quic hp",
        Uint8List(0),
        initialAead.keyLength,
      ),
      aead: initialAead,
      kdf: _initialKdf,
    );
    setSendKeys(EncryptionLevel.initial, clientInitialSendKeys);

    // Derive server's send keys for Initial packets (which client will receive)
    final serverInitialSendKeys = QuicPacketProtectionKeys(
      key: _initialKdf.hkdfExpandLabel(
        serverInitialSecret,
        "quic key",
        Uint8List(0),
        initialAead.keyLength,
      ),
      iv: _initialKdf.hkdfExpandLabel(
        serverInitialSecret,
        "quic iv",
        Uint8List(0),
        initialAead.ivLength,
      ),
      hpKey: _initialKdf.hkdfExpandLabel(
        serverInitialSecret,
        "quic hp",
        Uint8List(0),
        initialAead.keyLength,
      ),
      aead: initialAead,
      kdf: _initialKdf,
    );
    // For the client, these are its receive keys for Initial packets.
    setReceiveKeys(EncryptionLevel.initial, serverInitialSendKeys);
  }

  /// Derives and installs packet protection keys for non-Initial levels (Handshake, 0-RTT, 1-RTT).
  /// [trafficSecret]: The secret provided by TLS for this encryption level.
  /// [negotiatedAead]: The AEAD algorithm negotiated by TLS.
  /// [negotiatedKdf]: The KDF algorithm negotiated by TLS.
  /// [isClient]: True if this endpoint is the client.
  void installTrafficSecrets({
    required EncryptionLevel level,
    required Uint8List clientTrafficSecret,
    required Uint8List serverTrafficSecret,
    required AEADAlgorithm negotiatedAead,
    required KDFAlgorithm negotiatedKdf,
    required bool isClient,
  }) {
    // Derive send keys for this endpoint
    final mySendSecret = isClient ? clientTrafficSecret : serverTrafficSecret;
    final mySendKeys = QuicPacketProtectionKeys(
      key: negotiatedKdf.hkdfExpandLabel(
        mySendSecret,
        "quic key",
        Uint8List(0),
        negotiatedAead.keyLength,
      ),
      iv: negotiatedKdf.hkdfExpandLabel(
        mySendSecret,
        "quic iv",
        Uint8List(0),
        negotiatedAead.ivLength,
      ),
      hpKey: negotiatedKdf.hkdfExpandLabel(
        mySendSecret,
        "quic hp",
        Uint8List(0),
        negotiatedAead.keyLength,
      ),
      aead: negotiatedAead,
      kdf: negotiatedKdf,
    );
    setSendKeys(level, mySendKeys);

    // Derive receive keys for this endpoint
    final myReceiveSecret = isClient
        ? serverTrafficSecret
        : clientTrafficSecret;
    final myReceiveKeys = QuicPacketProtectionKeys(
      key: negotiatedKdf.hkdfExpandLabel(
        myReceiveSecret,
        "quic key",
        Uint8List(0),
        negotiatedAead.keyLength,
      ),
      iv: negotiatedKdf.hkdfExpandLabel(
        myReceiveSecret,
        "quic iv",
        Uint8List(0),
        negotiatedAead.ivLength,
      ),
      hpKey: negotiatedKdf.hkdfExpandLabel(
        myReceiveSecret,
        "quic hp",
        Uint8List(0),
        negotiatedAead.keyLength,
      ),
      aead: negotiatedAead,
      kdf: negotiatedKdf,
    );
    setReceiveKeys(level, myReceiveKeys);
  }

  /// Discards keys for a given encryption level. (RFC 9001, Section 4.9)
  /// Note: Actual discarding might be delayed.
  void discardKeys(EncryptionLevel level) {
    // In a real impl, might queue for later secure wiping
    _sendKeys.remove(level);
    _receiveKeys.remove(level);
    print('Keys for $level discarded.');
  }

  /// Logic for discarding Initial keys (RFC 9001, Section 4.9.1)
  void discardInitialKeys(bool isClient) {
    if (isClient) {
      // Client discards when it first sends a Handshake packet.
      // (This method would be called by the connection logic at that point)
      discardKeys(EncryptionLevel.initial);
    } else {
      // Server discards when it first successfully processes a Handshake packet.
      // (This method would be called by the connection logic at that point)
      discardKeys(EncryptionLevel.initial);
    }
  }

  /// Logic for discarding Handshake keys (RFC 9001, Section 4.9.2)
  void discardHandshakeKeys() {
    // Discard when TLS handshake is confirmed.
    discardKeys(EncryptionLevel.handshake);
  }

  /// Logic for discarding 0-RTT keys (RFC 9001, Section 4.9.3)
  void discardZeroRttKeys(bool isClient) {
    if (isClient) {
      // Client discards as soon as it installs 1-RTT keys.
      discardKeys(EncryptionLevel.zeroRtt);
    } else {
      // Server MAY discard after receiving a 1-RTT packet.
      // Can retain temporarily for reordered packets (e.g., 3x PTO).
      discardKeys(EncryptionLevel.zeroRtt); // Simplified: immediate discard
    }
  }
}
