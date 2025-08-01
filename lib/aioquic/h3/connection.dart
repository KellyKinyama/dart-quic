// ignore_for_file: unused_field, unused_local_variable, lines_longer_than_80_chars

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:http3/src/quic.dart'; // Placeholder for QuicConnection
import 'package:http3/src/qpack.dart'; // Placeholder for QPACK
import 'package:logging/logging.dart';
import 'package:quiver_core/core.dart' show Optional;

final Logger logger = Logger('http3');

// Python's re.compile(b'[A-Z]')
final RegExp _uppercase = RegExp(r'[A-Z]');

// Constants from the C code
const int colon = 0x3A;
const int nul = 0x00;
const int lf = 0x0A;
const int cr = 0x0D;
const int sp = 0x20;
const int htab = 0x09;
const List<int> whitespace = [sp, htab];

// The `aioquic.buffer` library needs a conceptual implementation in Dart.
// This class mimics the behavior of `aioquic.buffer.Buffer`.
class Buffer {
  Uint8List _data;
  int _offset = 0;

  Buffer({Uint8List? data, int capacity = 0}) : _data = data ?? Uint8List(capacity);

  bool get eof => _offset >= _data.length;

  int pullUintVar() {
    int value = 0;
    int shift = 0;
    int firstByte = _data[_offset];
    int length = (firstByte >> 6) & 0x03;
    _offset++;
    if (length == 0) {
      value = firstByte;
    } else {
      value = firstByte & 0x3F;
      for (int i = 0; i < length; i++) {
        value = (value << 8) | _data[_offset];
        _offset++;
      }
    }
    return value;
  }

  void pushUintVar(int value) {
    if (value < 64) {
      _data.buffer.asByteData().setUint8(_offset, value);
      _offset += 1;
    } else if (value < 16384) {
      _data.buffer.asByteData().setUint16(_offset, value | 0x4000);
      _offset += 2;
    } else if (value < 1073741824) {
      _data.buffer.asByteData().setUint32(_offset, value | 0x80000000);
      _offset += 4;
    } else {
      // In a full implementation, this would handle 64-bit integers.
      throw UnsupportedError('64-bit variable-length integers are not implemented.');
    }
  }

  void pushBytes(Uint8List data) {
    _data.setAll(_offset, data);
    _offset += data.length;
  }

  Uint8List get data => _data.sublist(0, _offset);
  int tell() => _offset;
}

// H3_ALPN is a List<String>
const List<String> h3Alpn = ['h3'];

// RESERVED_SETTINGS is a Set<int>
const Set<int> reservedSettings = {0x0, 0x2, 0x3, 0x4, 0x5};

// H3_DATAGRAM_ERROR is an int constant (not an enum value)
const int h3DatagramError = 0x33;

enum ErrorCode {
  h3NoError(0x100),
  h3GeneralProtocolError(0x101),
  h3InternalError(0x102),
  h3StreamCreationError(0x103),
  h3ClosedCriticalStream(0x104),
  h3FrameUnexpected(0x105),
  h3FrameError(0x106),
  h3ExcessiveLoad(0x107),
  h3IdError(0x108),
  h3SettingsError(0x109),
  h3MissingSettings(0x10A),
  h3RequestRejected(0x10B),
  h3RequestCancelled(0x10C),
  h3RequestIncomplete(0x10D),
  h3MessageError(0x10E),
  h3ConnectError(0x10F),
  h3VersionFallback(0x110),
  qpackDecompressionFailed(0x200),
  qpackEncoderStreamError(0x201),
  qpackDecoderStreamError(0x202);

  final int value;
  const ErrorCode(this.value);
}

enum FrameType {
  data(0x0),
  headers(0x1),
  priority(0x2),
  cancelPush(0x3),
  settings(0x4),
  pushPromise(0x5),
  goaway(0x7),
  maxPushId(0xD),
  duplicatePush(0xE),
  webtransportStream(0x41);

  final int value;
  const FrameType(this.value);
}

enum HeadersState {
  initial,
  afterHeaders,
  afterTrailers,
}

enum Setting {
  qpackMaxTableCapacity(0x1),
  maxFieldSectionSize(0x6),
  qpackBlockedStreams(0x7),
  enableConnectProtocol(0x8),
  h3Datagram(0x33),
  enableWebtransport(0x2B603742),
  dummy(0x21);

  final int value;
  const Setting(this.value);
}

enum StreamType {
  control(0),
  push(1),
  qpackEncoder(2),
  qpackDecoder(3),
  webtransport(0x54);

  final int value;
  const StreamType(this.value);
}

class ProtocolError implements Exception {
  final ErrorCode errorCode;
  final String reasonPhrase;

  ProtocolError([this.reasonPhrase = "", this.errorCode = ErrorCode.h3GeneralProtocolError]);

  @override
  String toString() => 'ProtocolError: $reasonPhrase (Error Code: ${errorCode.value})';
}

class QpackDecompressionFailed extends ProtocolError {
  QpackDecompressionFailed() : super("", ErrorCode.qpackDecompressionFailed);
}

class QpackDecoderStreamError extends ProtocolError {
  QpackDecoderStreamError() : super("", ErrorCode.qpackDecoderStreamError);
}

class QpackEncoderStreamError extends ProtocolError {
  QpackEncoderStreamError() : super("", ErrorCode.qpackEncoderStreamError);
}

class ClosedCriticalStream extends ProtocolError {
  ClosedCriticalStream() : super("", ErrorCode.h3ClosedCriticalStream);
}

class DatagramError extends ProtocolError {
  DatagramError([String reason = '']) : super(reason, ErrorCode.h3DatagramError);
}

class FrameUnexpected extends ProtocolError {
  FrameUnexpected([String reason = '']) : super(reason, ErrorCode.h3FrameUnexpected);
}

class MessageError extends ProtocolError {
  MessageError([String reason = '']) : super(reason, ErrorCode.h3MessageError);
}

class MissingSettingsError extends ProtocolError {
  MissingSettingsError() : super("", ErrorCode.h3MissingSettings);
}

class SettingsError extends ProtocolError {
  SettingsError([String reason = '']) : super(reason, ErrorCode.h3SettingsError);
}

class StreamCreationError extends ProtocolError {
  StreamCreationError() : super("", ErrorCode.h3StreamCreationError);
}

Uint8List encodeFrame(int frameType, Uint8List frameData) {
  final frameLength = frameData.length;
  final buf = Buffer(capacity: frameLength + 2 * 8); // Max size for UINT_VAR
  buf.pushUintVar(frameType);
  buf.pushUintVar(frameLength);
  buf.pushBytes(frameData);
  return buf.data;
}

Uint8List encodeSettings(Map<int, int> settings) {
  final buf = Buffer(capacity: 1024);
  for (var entry in settings.entries) {
    buf.pushUintVar(entry.key);
    buf.pushUintVar(entry.value);
  }
  return buf.data;
}

int parseMaxPushId(Uint8List data) {
  final buf = Buffer(data: data);
  final maxPushId = buf.pullUintVar();
  if (!buf.eof) {
    throw Exception('Extra data after max_push_id');
  }
  return maxPushId;
}

Map<int, int> parseSettings(Uint8List data) {
  final buf = Buffer(data: data);
  final settings = <int, int>{};
  while (!buf.eof) {
    final setting = buf.pullUintVar();
    final value = buf.pullUintVar();
    if (reservedSettings.contains(setting)) {
      throw SettingsError('Setting identifier 0x${setting.toRadixString(16)} is reserved');
    }
    if (settings.containsKey(setting)) {
      throw SettingsError('Setting identifier 0x${setting.toRadixString(16)} is included twice');
    }
    settings[setting] = value;
  }
  return settings;
}

bool streamIsRequestResponse(int streamId) {
  return streamId % 4 == 0;
}

void validateHeaderName(Uint8List key) {
  final keyStr = utf8.decode(key, allowMalformed: true);
  for (final c in key) {
    if (c <= 0x20 || (c >= 0x41 && c <= 0x5A) || c >= 0x7F) {
      throw MessageError('Header "$keyStr" contains invalid characters');
    }
    if (c == colon && key.indexOf(c) != 0) {
      throw MessageError('Header "$keyStr" contains a non-initial colon');
    }
  }
}

void validateHeaderValue(Uint8List key, Uint8List value) {
  final keyStr = utf8.decode(key, allowMalformed: true);
  for (final c in value) {
    if (c == nul || c == lf || c == cr) {
      throw MessageError('Header "$keyStr" value has forbidden characters');
    }
  }
  if (value.isNotEmpty) {
    final first = value.first;
    if (whitespace.contains(first)) {
      throw MessageError('Header "$keyStr" value starts with whitespace');
    }
    if (value.length > 1) {
      final last = value.last;
      if (whitespace.contains(last)) {
        throw MessageError('Header "$keyStr" value ends with whitespace');
      }
    }
  }
}

// Re-defining the Python types for clarity, using Dart equivalents
typedef Headers = List<List<Uint8List>>;
typedef FrozenSet<T> = Set<T>;

void validateHeaders(
    Headers headers,
    FrozenSet<Uint8List> allowedPseudoHeaders,
    FrozenSet<Uint8List> requiredPseudoHeaders,
    {H3Stream? stream}) {
  bool afterPseudoHeaders = false;
  Uint8List? authority;
  Uint8List? path;
  Uint8List? scheme;
  final seenPseudoHeaders = <Uint8List>{};

  for (var header in headers) {
    final key = header[0];
    final value = header[1];
    validateHeaderName(key);
    validateHeaderValue(key, value);

    if (key.first == colon) {
      if (afterPseudoHeaders) {
        throw MessageError('Pseudo-header "$key" is not allowed after regular headers');
      }
      if (!allowedPseudoHeaders.contains(key)) {
        throw MessageError('Pseudo-header "$key" is not valid');
      }
      if (seenPseudoHeaders.contains(key)) {
        throw MessageError('Pseudo-header "$key" is included twice');
      }
      seenPseudoHeaders.add(key);

      if (utf8.decode(key) == ':authority') {
        authority = value;
      } else if (utf8.decode(key) == ':path') {
        path = value;
      } else if (utf8.decode(key) == ':scheme') {
        scheme = value;
      }
    } else {
      afterPseudoHeaders = true;
      if (utf8.decode(key) == 'content-length') {
        try {
          final contentLength = int.parse(utf8.decode(value));
          if (contentLength < 0) {
            throw ArgumentError();
          }
          if (stream != null) {
            stream.expectedContentLength = contentLength;
          }
        } on FormatException {
          throw MessageError('content-length is not a non-negative integer');
        } on ArgumentError {
          throw MessageError('content-length is not a non-negative integer');
        }
      } else if (utf8.decode(key) == 'transfer-encoding' && utf8.decode(value) != 'trailers') {
        throw MessageError('The only valid value for transfer-encoding is trailers');
      }
    }
  }

  final missing = requiredPseudoHeaders.difference(seenPseudoHeaders);
  if (missing.isNotEmpty) {
    throw MessageError('Pseudo-headers ${missing.map((e) => utf8.decode(e)).join(', ')} are missing');
  }

  if (scheme != null && [utf8.encode('http'), utf8.encode('https')].any((s) => s.containsAll(scheme))) {
    if (authority == null || authority.isEmpty) {
      throw MessageError('Pseudo-header \':authority\' cannot be empty');
    }
    if (path == null || path.isEmpty) {
      throw MessageError('Pseudo-header \':path\' cannot be empty');
    }
  }
}

void validatePushPromiseHeaders(Headers headers) {
  validateHeaders(
    headers,
    FrozenSet({
      utf8.encode(':method'),
      utf8.encode(':scheme'),
      utf8.encode(':authority'),
      utf8.encode(':path')
    }),
    FrozenSet({
      utf8.encode(':method'),
      utf8.encode(':scheme'),
      utf8.encode(':authority'),
      utf8.encode(':path')
    }),
  );
}

void validateRequestHeaders(Headers headers, {H3Stream? stream}) {
  validateHeaders(
    headers,
    FrozenSet({
      utf8.encode(':method'),
      utf8.encode(':scheme'),
      utf8.encode(':authority'),
      utf8.encode(':path'),
      utf8.encode(':protocol'),
    }),
    FrozenSet({utf8.encode(':method'), utf8.encode(':authority')}),
    stream: stream,
  );
}

void validateResponseHeaders(Headers headers, {H3Stream? stream}) {
  validateHeaders(
    headers,
    FrozenSet({utf8.encode(':status')}),
    FrozenSet({utf8.encode(':status')}),
    stream: stream,
  );
}

void validateTrailers(Headers headers) {
  validateHeaders(
    headers,
    FrozenSet(),
    FrozenSet(),
  );
}

class H3Stream {
  bool blocked = false;
  int? blockedFrameSize;
  Uint8List buffer = Uint8List(0);
  bool ended = false;
  int? frameSize;
  int? frameType;
  HeadersState headersRecvState = HeadersState.initial;
  HeadersState headersSendState = HeadersState.initial;
  int? pushId;
  int? sessionId;
  final int streamId;
  int? streamType;
  int? expectedContentLength;
  int contentLength = 0;

  H3Stream(this.streamId);
}

class H3Connection {
  final QuicConnection _quic;
  final bool _isClient;
  bool _isDone = false;

  final int _maxTableCapacity;
  final int _blockedStreams;
  final bool _enableWebtransport;

  // QPACK
  late final QpackDecoder _decoder;
  late final QpackEncoder _encoder;
  int _decoderBytesReceived = 0;
  int _decoderBytesSent = 0;
  int _encoderBytesReceived = 0;
  int _encoderBytesSent = 0;

  bool _settingsReceived = false;
  final Map<int, H3Stream> _stream = {};
  int? _maxPushId;
  int _nextPushId = 0;

  int? _localControlStreamId;
  int? _localDecoderStreamId;
  int? _localEncoderStreamId;

  int? _peerControlStreamId;
  int? _peerDecoderStreamId;
  int? _peerEncoderStreamId;
  Map<int, int>? _receivedSettings;
  Map<int, int>? _sentSettings;

  H3Connection({
    required this.quic,
    this.enableWebtransport = false,
  })  : _quic = quic,
        _isClient = quic.configuration.isClient,
        _maxTableCapacity = 4096,
        _blockedStreams = 16 {
    _decoder = QpackDecoder(_maxTableCapacity, _blockedStreams);
    _encoder = QpackEncoder();
    _maxPushId = _isClient ? 8 : null;
    _initConnection();
  }

  int createWebtransportStream({required int sessionId, bool isUnidirectional = false}) {
    if (isUnidirectional) {
      final streamId = _createUniStream(StreamType.webtransport);
      _quic.sendStreamData(streamId, encodeUintVar(sessionId));
      return streamId;
    } else {
      final streamId = _quic.getNextAvailableStreamId();
      _logStreamType(streamId: streamId, streamType: StreamType.webtransport.value);
      _quic.sendStreamData(
        streamId,
        encodeUintVar(FrameType.webtransportStream.value) + encodeUintVar(sessionId),
      );
      return streamId;
    }
  }

  List<H3Event> handleEvent(QuicEvent event) {
    if (_isDone) {
      return [];
    }

    try {
      if (event is StreamDataReceived) {
        final streamId = event.streamId;
        final stream = _getOrCreateStream(streamId);
        if (streamIsUnidirectional(streamId)) {
          return _receiveStreamDataUni(stream, event.data, event.endStream);
        } else {
          return _receiveRequestOrPushData(stream, event.data, event.endStream);
        }
      } else if (event is DatagramFrameReceived) {
        return _receiveDatagram(event.data);
      }
    } on ProtocolError catch (exc) {
      _isDone = true;
      _quic.close(errorCode: exc.errorCode, reasonPhrase: exc.reasonPhrase);
    }
    return [];
  }

  void sendDatagram({required int streamId, required Uint8List data}) {
    if (!streamIsRequestResponse(streamId)) {
      throw InvalidStreamTypeError('Datagrams can only be sent for client-initiated bidirectional streams');
    }
    _quic.sendDatagramFrame(encodeUintVar(streamId ~/ 4) + data);
  }

  int sendPushPromise({required int streamId, required Headers headers}) {
    assert(!_isClient, "Only servers may send a push promise.");

    if (!streamIsRequestResponse(streamId)) {
      throw InvalidStreamTypeError('Push promises can only be sent for client-initiated bidirectional streams');
    }

    if (_maxPushId == null || _nextPushId >= _maxPushId!) {
      throw NoAvailablePushIDError();
    }

    final pushId = _nextPushId;
    _nextPushId++;
    _quic.sendStreamData(
      streamId,
      encodeFrame(
        FrameType.pushPromise.value,
        encodeUintVar(pushId) + _encodeHeaders(streamId, headers),
      ),
    );

    final pushStreamId = _createUniStream(StreamType.push, pushId: pushId);
    _quic.sendStreamData(pushStreamId, encodeUintVar(pushId));

    return pushStreamId;
  }

  void sendData({required int streamId, required Uint8List data, required bool endStream}) {
    final stream = _getOrCreateStream(streamId);
    if (stream.headersSendState != HeadersState.afterHeaders) {
      throw FrameUnexpected('DATA frame is not allowed in this state');
    }

    _quic.sendStreamData(streamId, encodeFrame(FrameType.data.value, data), endStream);
  }

  void sendHeaders({required int streamId, required Headers headers, bool endStream = false}) {
    final stream = _getOrCreateStream(streamId);
    if (stream.headersSendState == HeadersState.afterTrailers) {
      throw FrameUnexpected('HEADERS frame is not allowed in this state');
    }

    final frameData = _encodeHeaders(streamId, headers);

    if (stream.headersSendState == HeadersState.initial) {
      stream.headersSendState = HeadersState.afterHeaders;
    } else {
      stream.headersSendState = HeadersState.afterTrailers;
    }
    _quic.sendStreamData(streamId, encodeFrame(FrameType.headers.value, frameData), endStream);
  }

  Map<int, int>? get receivedSettings => _receivedSettings;
  Map<int, int>? get sentSettings => _sentSettings;

  int _createUniStream(StreamType streamType, {int? pushId}) {
    final streamId = _quic.getNextAvailableStreamId(isUnidirectional: true);
    _logStreamType(streamId: streamId, streamType: streamType.value, pushId: pushId);
    _quic.sendStreamData(streamId, encodeUintVar(streamType.value));
    return streamId;
  }

  Headers _decodeHeaders(int streamId, Uint8List? frameData) {
    try {
      if (frameData == null) {
        // This is a conceptual call; the actual implementation would be different
        // and probably return an object with the headers.
        final result = _decoder.resumeHeader(streamId);
        _decoderBytesSent += result.decoder.length;
        _quic.sendStreamData(_localDecoderStreamId!, result.decoder);
        return result.headers;
      } else {
        final result = _decoder.feedHeader(streamId, frameData);
        _decoderBytesSent += result.decoder.length;
        _quic.sendStreamData(_localDecoderStreamId!, result.decoder);
        return result.headers;
      }
    } on DecompressionFailed {
      throw QpackDecompressionFailed();
    }
  }

  Uint8List _encodeHeaders(int streamId, Headers headers) {
    final result = _encoder.encode(streamId, headers);
    _encoderBytesSent += result.encoder.length;
    _quic.sendStreamData(_localEncoderStreamId!, result.encoder);
    return result.frameData;
  }

  H3Stream _getOrCreateStream(int streamId) {
    if (!_stream.containsKey(streamId)) {
      _stream[streamId] = H3Stream(streamId);
    }
    return _stream[streamId]!;
  }

  Map<int, int> _getLocalSettings() {
    final settings = <int, int>{
      Setting.qpackMaxTableCapacity.value: _maxTableCapacity,
      Setting.qpackBlockedStreams.value: _blockedStreams,
      Setting.enableConnectProtocol.value: 1,
      Setting.dummy.value: 1,
    };
    if (_enableWebtransport) {
      settings[Setting.h3Datagram.value] = 1;
      settings[Setting.enableWebtransport.value] = 1;
    }
    return settings;
  }

  void _handleControlFrame(int frameType, Uint8List frameData) {
    if (frameType != FrameType.settings.value && !_settingsReceived) {
      throw MissingSettingsError();
    }

    if (frameType == FrameType.settings.value) {
      if (_settingsReceived) {
        throw FrameUnexpected('SETTINGS have already been received');
      }
      final settings = parseSettings(frameData);
      _validateSettings(settings);
      _receivedSettings = settings;
      final encoder = _encoder.applySettings(
        maxTableCapacity: settings[Setting.qpackMaxTableCapacity.value] ?? 0,
        blockedStreams: settings[Setting.qpackBlockedStreams.value] ?? 0,
      );
      _quic.sendStreamData(_localEncoderStreamId!, encoder);
      _settingsReceived = true;
    } else if (frameType == FrameType.maxPushId.value) {
      if (!_isClient) {
        throw FrameUnexpected('Servers must not send MAX_PUSH_ID');
      }
      _maxPushId = parseMaxPushId(frameData);
    } else if ([
      FrameType.data.value,
      FrameType.headers.value,
      FrameType.pushPromise.value,
      FrameType.duplicatePush.value,
    ].contains(frameType)) {
      throw FrameUnexpected('Invalid frame type on control stream');
    }
  }

  void _checkContentLength(H3Stream stream) {
    if (stream.expectedContentLength != null &&
        stream.contentLength != stream.expectedContentLength) {
      throw MessageError('content-length does not match data size');
    }
  }

  List<H3Event> _handleRequestOrPushFrame(
    int frameType,
    Uint8List? frameData,
    H3Stream stream,
    bool streamEnded,
  ) {
    final httpEvents = <H3Event>[];

    if (frameType == FrameType.data.value) {
      if (stream.headersRecvState != HeadersState.afterHeaders) {
        throw FrameUnexpected('DATA frame is not allowed in this state');
      }

      if (frameData != null) {
        stream.contentLength += frameData.length;
      }
      if (streamEnded) {
        _checkContentLength(stream);
      }

      if (streamEnded || (frameData != null && frameData.isNotEmpty)) {
        httpEvents.add(
          DataReceived(
            data: frameData!,
            pushId: stream.pushId,
            streamEnded: streamEnded,
            streamId: stream.streamId,
          ),
        );
      }
    } else if (frameType == FrameType.headers.value) {
      if (stream.headersRecvState == HeadersState.afterTrailers) {
        throw FrameUnexpected('HEADERS frame is not allowed in this state');
      }

      final headers = _decodeHeaders(stream.streamId, frameData);

      if (stream.headersRecvState == HeadersState.initial) {
        if (_isClient) {
          validateResponseHeaders(headers, stream: stream);
        } else {
          validateRequestHeaders(headers, stream: stream);
        }
      } else {
        validateTrailers(headers);
      }

      if (streamEnded) {
        _checkContentLength(stream);
      }

      if (stream.headersRecvState == HeadersState.initial) {
        stream.headersRecvState = HeadersState.afterHeaders;
      } else {
        stream.headersRecvState = HeadersState.afterTrailers;
      }
      httpEvents.add(
        HeadersReceived(
          headers: headers,
          pushId: stream.pushId,
          streamId: stream.streamId,
          streamEnded: streamEnded,
        ),
      );
    } else if (frameType == FrameType.pushPromise.value && stream.pushId == null) {
      if (!_isClient) {
        throw FrameUnexpected('Clients must not send PUSH_PROMISE');
      }
      final frameBuf = Buffer(data: frameData);
      final pushId = frameBuf.pullUintVar();
      final headers = _decodeHeaders(stream.streamId, frameData!.sublist(frameBuf.tell()));

      validatePushPromiseHeaders(headers);

      httpEvents.add(
        PushPromiseReceived(
          headers: headers,
          pushId: pushId,
          streamId: stream.streamId,
        ),
      );
    } else if ([
      FrameType.priority.value,
      FrameType.cancelPush.value,
      FrameType.settings.value,
      FrameType.pushPromise.value,
      FrameType.goaway.value,
      FrameType.maxPushId.value,
      FrameType.duplicatePush.value,
    ].contains(frameType)) {
      throw FrameUnexpected(stream.pushId == null
          ? 'Invalid frame type on request stream'
          : 'Invalid frame type on push stream');
    }
    return httpEvents;
  }

  void _initConnection() {
    _localControlStreamId = _createUniStream(StreamType.control);
    _sentSettings = _getLocalSettings();
    _quic.sendStreamData(
      _localControlStreamId!,
      encodeFrame(FrameType.settings.value, encodeSettings(_sentSettings!)),
    );
    if (_isClient && _maxPushId != null) {
      _quic.sendStreamData(
        _localControlStreamId!,
        encodeFrame(FrameType.maxPushId.value, encodeUintVar(_maxPushId!)),
      );
    }
    _localEncoderStreamId = _createUniStream(StreamType.qpackEncoder);
    _localDecoderStreamId = _createUniStream(StreamType.qpackDecoder);
  }

  void _logStreamType({required int streamId, required int streamType, int? pushId}) {
    final typeName = {
      0: 'control',
      1: 'push',
      2: 'qpack_encoder',
      3: 'qpack_decoder',
      0x54: 'webtransport',
    }[streamType];
    logger.info('stream_type_set: new: $typeName, stream_id: $streamId, associated_push_id: $pushId');
  }

  List<H3Event> _receiveDatagram(Uint8List data) {
    final buf = Buffer(data: data);
    try {
      final quarterStreamId = buf.pullUintVar();
      return [
        DatagramReceived(data: data.sublist(buf.tell()), streamId: quarterStreamId * 4)
      ];
    } on BufferReadError {
      throw DatagramError('Could not parse quarter stream ID');
    }
  }

  List<H3Event> _receiveRequestOrPushData(H3Stream stream, Uint8List data, bool streamEnded) {
    final httpEvents = <H3Event>[];

    final oldBuffer = stream.buffer;
    stream.buffer = Uint8List(oldBuffer.length + data.length);
    stream.buffer.setAll(0, oldBuffer);
    stream.buffer.setAll(oldBuffer.length, data);

    if (streamEnded) {
      stream.ended = true;
    }
    if (stream.blocked) {
      return httpEvents;
    }

    if (stream.frameType == FrameType.webtransportStream.value && stream.sessionId != null) {
      httpEvents.add(
        WebTransportStreamDataReceived(
          data: stream.buffer,
          sessionId: stream.sessionId!,
          streamId: stream.streamId,
          streamEnded: streamEnded,
        ),
      );
      stream.buffer = Uint8List(0);
      return httpEvents;
    }

    // Continue the logic from the Python snippet.
    // The snippet was truncated, so this part is a conceptual continuation.
    // The code would loop to parse frames from the buffer.
    // The `_receiveRequestOrPushData` function in the original Python
    // would also handle parsing the frame type and length before calling
    // `_handleRequestOrPushFrame`.

    return httpEvents;
  }
}

// Placeholder classes to match the Python imports
class QuicConnection {
  final QuicConfiguration configuration;
  final QuicLoggerTrace? _quicLogger;

  QuicConnection(this.configuration, {QuicLoggerTrace? quicLogger}) : _quicLogger = quicLogger;

  int getNextAvailableStreamId({bool isUnidirectional = false}) => 0;
  void sendStreamData(int streamId, Uint8List data, [bool endStream = false]) {}
  void sendDatagramFrame(Uint8List data) {}
  void close({required ErrorCode errorCode, String? reasonPhrase}) {}
}

class QuicConfiguration {
  final bool isClient;
  QuicConfiguration(this.isClient);
}

class QuicEvent {}

class QuicLoggerTrace {}

class StreamDataReceived extends QuicEvent {
  final int streamId;
  final Uint8List data;
  final bool endStream;
  StreamDataReceived(this.streamId, this.data, this.endStream);
}

class DatagramFrameReceived extends QuicEvent {
  final Uint8List data;
  DatagramFrameReceived(this.data);
}

class H3Event {}

class DatagramReceived extends H3Event {
  final Uint8List data;
  final int streamId;
  DatagramReceived({required this.data, required this.streamId});
}

class DataReceived extends H3Event {
  final Uint8List data;
  final int? pushId;
  final bool streamEnded;
  final int streamId;
  DataReceived({
    required this.data,
    required this.pushId,
    required this.streamEnded,
    required this.streamId,
  });
}

class HeadersReceived extends H3Event {
  final Headers headers;
  final int? pushId;
  final int streamId;
  final bool streamEnded;
  HeadersReceived({
    required this.headers,
    required this.pushId,
    required this.streamId,
    required this.streamEnded,
  });
}

class PushPromiseReceived extends H3Event {
  final Headers headers;
  final int pushId;
  final int streamId;
  PushPromiseReceived({
    required this.headers,
    required this.pushId,
    required this.streamId,
  });
}

class WebTransportStreamDataReceived extends H3Event {
  final Uint8List data;
  final int sessionId;
  final int streamId;
  final bool streamEnded;
  WebTransportStreamDataReceived({
    required this.data,
    required this.sessionId,
    required this.streamId,
    required this.streamEnded,
  });
}

class InvalidStreamTypeError implements Exception {
  final String message;
  InvalidStreamTypeError(this.message);
}

class NoAvailablePushIDError implements Exception {}

class QpackDecoder {
  QpackDecoder(int maxTableCapacity, int blockedStreams);
  dynamic resumeHeader(int streamId) {}
  dynamic feedHeader(int streamId, Uint8List frameData) {}
}

class QpackEncoder {
  Uint8List encode(int streamId, Headers headers) => Uint8List(0);
  Uint8List applySettings({required int maxTableCapacity, required int blockedStreams}) => Uint8List(0);
}

class DecompressionFailed implements Exception {}

Uint8List encodeUintVar(int value) => Uint8List(0);
bool streamIsUnidirectional(int streamId) => false;