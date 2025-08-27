// Filename: events.dart
import 'dart:typed_data';

/// Base class for all QUIC events.
abstract class QuicEvent {}

/// Fired when a new connection ID is issued by the peer.
class ConnectionIdIssued extends QuicEvent {
  final Uint8List connectionId;
  ConnectionIdIssued({required this.connectionId});
}

/// Fired when the peer retires one of our connection IDs.
class ConnectionIdRetired extends QuicEvent {
  final Uint8List connectionId;
  ConnectionIdRetired({required this.connectionId});
}

/// Fired when the QUIC connection is terminated.
class ConnectionTerminated extends QuicEvent {
  final int errorCode;
  final int? frameType;
  final String reasonPhrase;

  ConnectionTerminated({
    required this.errorCode,
    this.frameType,
    required this.reasonPhrase,
  });
}

/// Fired when a DATAGRAM frame is received.
class DatagramFrameReceived extends QuicEvent {
  final Uint8List data;
  DatagramFrameReceived({required this.data});
}

/// Fired when the TLS handshake completes successfully.
class HandshakeCompleted extends QuicEvent {
  final String? alpnProtocol;
  final bool sessionResumed;

  HandshakeCompleted({this.alpnProtocol, required this.sessionResumed});
}

/// Fired when a PING frame sent by the application is acknowledged.
class PingAcknowledged extends QuicEvent {
  final int uid;
  PingAcknowledged({required this.uid});
}

/// Fired when a STOP_SENDING frame is received from the peer.
class StopSendingReceived extends QuicEvent {
  final int streamId;
  final int errorCode;
  StopSendingReceived({required this.streamId, required this.errorCode});
}

/// Fired whenever data is received on a stream.
class StreamDataReceived extends QuicEvent {
  final int streamId;
  final Uint8List data;
  final bool endStream;

  StreamDataReceived({
    required this.streamId,
    required this.data,
    required this.endStream,
  });
}

/// Fired when the remote peer resets a stream.
class StreamReset extends QuicEvent {
  final int streamId;
  final int errorCode;
  StreamReset({required this.streamId, required this.errorCode});
}
