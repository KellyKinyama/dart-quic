// Filename: interface.dart
import 'dart:async';
import 'dart:typed_data';
import 'package:meta/meta.dart';

// Represents the tls.ConnectionState and additional QUIC properties.
class ConnectionState {
  // This would contain fields from tls.ConnectionState if needed.
  final bool used0RTT;

  ConnectionState({required this.used0RTT});
}

// Represents transport parameters from a session ticket or peer.
class TransportParameters {
  // Dummy class for TransportParameters. A full implementation is needed.
}

/// Thrown when keys for a specific encryption level are not yet available.
class KeysNotYetAvailableException implements Exception {
  final String message = "CryptoSetup: keys at this encryption level not yet available";
  @override
  String toString() => message;
}

/// Thrown when keys for an encryption level have already been dropped.
class KeysDroppedException implements Exception {
  final String message = "CryptoSetup: keys were already dropped";
  @override
  String toString() => message;
}

/// Thrown when AEAD decryption fails.
class DecryptionFailedException implements Exception {
  final String message = "decryption failed";
  @override
  String toString() => message;
}

abstract class HeaderDecryptor {
  void decryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
}

abstract class LongHeaderOpener implements HeaderDecryptor {
  int decodePacketNumber(int wirePN, int wirePNLen);
  Future<Uint8List> open(Uint8List? dst, Uint8List src, int pn, Uint8List associatedData);
}

abstract class ShortHeaderOpener implements HeaderDecryptor {
  int decodePacketNumber(int wirePN, int wirePNLen);
  Future<Uint8List> open(Uint8List? dst, Uint8List src, DateTime rcvTime, int pn, int kp, Uint8List associatedData);
}

abstract class LongHeaderSealer {
  Uint8List seal(Uint8List? dst, Uint8List src, int packetNumber, Uint8List associatedData);
  void encryptHeader(Uint8List sample, ByteData firstByte, Uint8List pnBytes);
  int get overhead;
}

abstract class ShortHeaderSealer implements LongHeaderSealer {
  int get keyPhase;
}

enum EventKind {
  noEvent,
  writeInitialData,
  writeHandshakeData,
  receivedReadKeys,
  discard0RTTKeys,
  receivedTransportParameters,
  restoredTransportParameters,
  handshakeComplete,
}

class HandshakeEvent {
  final EventKind kind;
  final Uint8List? data;
  final TransportParameters? transportParameters;

  HandshakeEvent({
    required this.kind,
    this.data,
    this.transportParameters,
  });
}

abstract class CryptoSetup {
  Future<void> startHandshake();
  Future<void> close();
  void changeConnectionID(Uint8List newConnId);
  Future<Uint8List?> getSessionTicket();
  Future<void> handleMessage(Uint8List data, int encryptionLevel);
  HandshakeEvent nextEvent();
  Future<void> setLargest1RTTAcked(int pn);
  void discardInitialKeys();
  void setHandshakeConfirmed();
  ConnectionState connectionState();

  Future<LongHeaderOpener> getInitialOpener();
  Future<LongHeaderOpener> getHandshakeOpener();
  Future<LongHeaderOpener> get0RTTOpener();
  Future<ShortHeaderOpener> get1RTTOpener();

  Future<LongHeaderSealer> getInitialSealer();
  Future<LongHeaderSealer> getHandshakeSealer();
  Future<LongHeaderSealer> get0RTTSealer();
  Future<ShortHeaderSealer> get1RTTSealer();
}