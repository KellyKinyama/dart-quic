// The following code is a Dart translation of the `events.py` Python module.
// This translation uses Dart's class and inheritance features to represent
// the event hierarchy and named constructors for creating event instances,
// which is a common pattern for data classes in Dart.

import 'dart:typed_data';

/// Base class for QUIC events.
abstract class QuicEvent {}

/// The `ConnectionIdIssued` event is fired when a new connection ID is issued.
class ConnectionIdIssued implements QuicEvent {
  final Uint8List connectionId;

  ConnectionIdIssued({required this.connectionId});
}

/// The `ConnectionIdRetired` event is fired when a connection ID is retired.
class ConnectionIdRetired implements QuicEvent {
  final Uint8List connectionId;

  ConnectionIdRetired({required this.connectionId});
}

/// The `ConnectionTerminated` event is fired when the QUIC connection is terminated.
class ConnectionTerminated implements QuicEvent {
  /// The error code which was specified when closing the connection.
  final int errorCode;

  /// The frame type which caused the connection to be closed, or `null`.
  final int? frameType;

  /// The human-readable reason for which the connection was closed.
  final String reasonPhrase;

  ConnectionTerminated({
    required this.errorCode,
    this.frameType,
    required this.reasonPhrase,
  });
}

/// The `DatagramFrameReceived` event is fired when a DATAGRAM frame is received.
class DatagramFrameReceived implements QuicEvent {
  /// The data which was received.
  final Uint8List data;

  DatagramFrameReceived({required this.data});
}

/// The `HandshakeCompleted` event is fired when the TLS handshake completes.
class HandshakeCompleted implements QuicEvent {
  /// The protocol which was negotiated using ALPN, or `null`.
  final String? alpnProtocol;

  /// Whether early (0-RTT) data was accepted by the remote peer.
  final bool earlyDataAccepted;

  /// Whether a TLS session was resumed.
  final bool sessionResumed;

  HandshakeCompleted({
    this.alpnProtocol,
    required this.earlyDataAccepted,
    required this.sessionResumed,
  });
}

/// The `PingAcknowledged` event is fired when a PING frame is acknowledged.
class PingAcknowledged implements QuicEvent {
  /// The unique ID of the PING.
  final int uid;

  PingAcknowledged({required this.uid});
}

/// The `ProtocolNegotiated` event is fired when ALPN negotiation completes.
class ProtocolNegotiated implements QuicEvent {
  /// The protocol which was negotiated using ALPN, or `null`.
  final String? alpnProtocol;

  ProtocolNegotiated({this.alpnProtocol});
}

/// The `StopSendingReceived` event is fired when the remote peer requests
/// stopping data transmission on a stream.
class StopSendingReceived implements QuicEvent {
  /// The error code that was sent from the peer.
  final int errorCode;

  /// The ID of the stream that the peer requested stopping data transmission.
  final int streamId;

  StopSendingReceived({required this.errorCode, required this.streamId});
}

/// The `StreamDataReceived` event is fired whenever data is received on a stream.
class StreamDataReceived implements QuicEvent {
  /// The data which was received.
  final Uint8List data;

  /// Whether the STREAM frame had the FIN bit set.
  final bool endStream;

  /// The ID of the stream the data was received for.
  final int streamId;

  StreamDataReceived({
    required this.data,
    required this.endStream,
    required this.streamId,
  });
}

/// The `StreamReset` event is fired when the remote peer resets a stream.
class StreamReset implements QuicEvent {
  /// The error code that triggered the reset.
  final int errorCode;

  /// The ID of the stream that was reset.
  final int streamId;

  StreamReset({required this.errorCode, required this.streamId});
}
