import 'dart:typed_data';

/// The H3Event class is the base class for all HTTP/3 events.
/// This class exists to allow for type-safe event handling.
class H3Event {
  const H3Event();
}

/// Headers type definition.
/// In Python, this is a List of Tuples of bytes.
/// In Dart, we can represent this as a List of Lists of Uint8List.
typedef Headers = List<List<Uint8List>>;

class DataReceived extends H3Event {
  /// The data which was received.
  final Uint8List data;

  /// The ID of the stream the data was received for.
  final int streamId;

  /// Whether the STREAM frame had the FIN bit set.
  final bool streamEnded;

  /// The Push ID or `null` if this is not a push.
  final int? pushId;

  const DataReceived({
    required this.data,
    required this.streamId,
    required this.streamEnded,
    this.pushId,
  });
}

class DatagramReceived extends H3Event {
  /// The data which was received.
  final Uint8List data;

  /// The ID of the stream the data was received for.
  final int streamId;

  const DatagramReceived({
    required this.data,
    required this.streamId,
  });
}

class HeadersReceived extends H3Event {
  /// The headers.
  final Headers headers;

  /// The ID of the stream the headers were received for.
  final int streamId;

  /// Whether the STREAM frame had the FIN bit set.
  final bool streamEnded;

  /// The Push ID or `null` if this is not a push.
  final int? pushId;

  const HeadersReceived({
    required this.headers,
    required this.streamId,
    required this.streamEnded,
    this.pushId,
  });
}

class PushPromiseReceived extends H3Event {
  /// The request headers.
  final Headers headers;

  /// The Push ID of the push promise.
  final int pushId;

  /// The Stream ID of the stream that the push is related to.
  final int streamId;

  const PushPromiseReceived({
    required this.headers,
    required this.pushId,
    required this.streamId,
  });
}

class WebTransportStreamDataReceived extends H3Event {
  /// The data which was received.
  final Uint8List data;

  /// The ID of the stream the data was received for.
  final int streamId;

  /// Whether the STREAM frame had the FIN bit set.
  final bool streamEnded;

  /// The ID of the session the data was received for.
  final int sessionId;

  const WebTransportStreamDataReceived({
    required this.data,
    required this.streamId,
    required this.streamEnded,
    required this.sessionId,
  });
}