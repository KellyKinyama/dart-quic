// ignore_for_file: unused_field, unused_local_variable

import 'dart:typed_data';
import '../h3/events.dart';
import 'package:http3/src/quic.dart';

// H0_ALPN is a List<String>
const List<String> h0Alpn = ['hq-interop'];

class H0Connection {
  final Map<int, Uint8List> _buffer = {};
  final Map<int, bool> _headersReceived = {};
  final bool _isClient;
  final QuicConnection _quic;

  H0Connection(this._quic) : _isClient = _quic.configuration.isClient;

  List<H3Event> handleEvent(QuicEvent event) {
    final httpEvents = <H3Event>[];

    if (event is StreamDataReceived && (event.streamId % 4) == 0) {
      final buffer = _buffer.remove(event.streamId) ?? Uint8List(0);
      final data = Uint8List.fromList(buffer.followedBy(event.data));

      if (!_headersReceived.containsKey(event.streamId)) {
        if (_isClient) {
          httpEvents.add(
            HeadersReceived(
              headers: [],
              streamEnded: false,
              streamId: event.streamId,
            ),
          );
        } else if (data.endsWith(Uint8List.fromList([13, 10])) ||
            event.endStream) {
          final dataString = String.fromCharCodes(data).trim();
          final parts = dataString.split(' ');
          final method = parts[0];
          final path = parts.sublist(1).join(' ');
          httpEvents.add(
            HeadersReceived(
              headers: [
                [
                  Uint8List.fromList(':method'.codeUnits),
                  Uint8List.fromList(method.codeUnits),
                ],
                [
                  Uint8List.fromList(':path'.codeUnits),
                  Uint8List.fromList(path.codeUnits),
                ],
              ],
              streamEnded: false,
              streamId: event.streamId,
            ),
          );
          _headersReceived[event.streamId] = true;
          _buffer[event.streamId] = Uint8List(0);
        } else {
          _buffer[event.streamId] = data;
          return httpEvents;
        }
      }

      httpEvents.add(
        DataReceived(
          data: data,
          streamEnded: event.endStream,
          streamId: event.streamId,
        ),
      );
    }
    return httpEvents;
  }

  void sendData(int streamId, Uint8List data, bool endStream) {
    _quic.sendStreamData(streamId, data, endStream: endStream);
  }

  void sendHeaders(int streamId, Headers headers, {bool endStream = false}) {
    Uint8List data;
    if (_isClient) {
      final headersMap = Map.fromEntries(
        headers.map((h) => MapEntry(String.fromCharCodes(h[0]), h[1])),
      );
      final method = headersMap[':method'];
      final path = headersMap[':path'];
      data = Uint8List.fromList(
        method!
            .followedBy(Uint8List.fromList(' '.codeUnits))
            .followedBy(path!)
            .followedBy(Uint8List.fromList('\r\n'.codeUnits)),
      );
    } else {
      data = Uint8List(0);
    }
    _quic.sendStreamData(streamId, data, endStream: endStream);
  }
}
