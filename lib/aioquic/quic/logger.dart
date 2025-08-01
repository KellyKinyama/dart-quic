// The following code is a Dart translation of the `logger.py` Python module.
// This translation adapts the original logic to Dart's class structure,
// type system, and standard library conventions. It uses Dart's `Uint8List`
// for byte data, `Map` for dictionaries, and `dart:convert` for JSON
// serialization. File I/O is handled using `dart:io`, and a helper
// function for hex dumping is included.

import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as path;
import 'package:quic_dart/quic/h3/events.dart';
import 'packet.dart';
import 'range_set.dart';

const Map<int, String> packetTypeNames = {
  QuicPacketType.initial: 'initial',
  QuicPacketType.handshake: 'handshake',
  QuicPacketType.zeroRtt: '0RTT',
  QuicPacketType.oneRtt: '1RTT',
  QuicPacketType.retry: 'retry',
  QuicPacketType.versionNegotiation: 'version_negotiation',
};

const String qlogVersion = '0.3';

/// Converts a Uint8List to its hexadecimal string representation.
String hexdump(Uint8List data) {
  return hex.encode(data);
}

/// A QUIC event trace.
///
/// Events are logged in the format defined by qlog.
///
/// See:
/// - https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-02
/// - https://datatracker.ietf.org/doc/html/draft-marx-quic-qlog-quic-events
/// - https://datatracker.ietf.org/doc/html/draft-marx-quic-qlog-h3-events
class QuicLoggerTrace {
  final Uint8List _odcid;
  final Queue<Map<String, dynamic>> _events = Queue<Map<String, dynamic>>();
  final Map<String, dynamic> _vantagePoint;

  QuicLoggerTrace({required bool isClient, required Uint8List odcid})
      : _odcid = odcid,
        _vantagePoint = {
          'name': 'aioquic',
          'type': isClient ? 'client' : 'server',
        };

  // QUIC

  Map<String, dynamic> encodeAckFrame(RangeSet ranges, double delay) {
    return {
      'ack_delay': encodeTime(delay),
      'acked_ranges': [
        [x.start, x.stop - 1] for x in ranges.ranges
      ],
      'frame_type': 'ack',
    };
  }

  Map<String, dynamic> encodeConnectionCloseFrame(
      int errorCode, int? frameType, String reasonPhrase) {
    final attrs = <String, dynamic>{
      'error_code': errorCode,
      'error_space': frameType == null ? 'application' : 'transport',
      'frame_type': 'connection_close',
      'raw_error_code': errorCode,
      'reason': reasonPhrase,
    };
    if (frameType != null) {
      attrs['trigger_frame_type'] = frameType;
    }
    return attrs;
  }

  Map<String, dynamic> encodeConnectionLimitFrame(int frameType, int maximum) {
    if (frameType == QuicFrameType.maxData) {
      return {'frame_type': 'max_data', 'maximum': maximum};
    } else {
      return {
        'frame_type': 'max_streams',
        'maximum': maximum,
        'stream_type': frameType == QuicFrameType.maxStreamsUni
            ? 'unidirectional'
            : 'bidirectional',
      };
    }
  }

  Map<String, dynamic> encodeCryptoFrame(QuicStreamFrame frame) {
    return {
      'frame_type': 'crypto',
      'length': frame.data.length,
      'offset': frame.offset,
    };
  }

  Map<String, dynamic> encodeDataBlockedFrame(int limit) {
    return {'frame_type': 'data_blocked', 'limit': limit};
  }

  Map<String, dynamic> encodeDatagramFrame(int length) {
    return {'frame_type': 'datagram', 'length': length};
  }

  Map<String, dynamic> encodeHandshakeDoneFrame() {
    return {'frame_type': 'handshake_done'};
  }

  Map<String, dynamic> encodeMaxStreamDataFrame(int maximum, int streamId) {
    return {
      'frame_type': 'max_stream_data',
      'maximum': maximum,
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeNewConnectionIdFrame(
    Uint8List connectionId,
    int retirePriorTo,
    int sequenceNumber,
    Uint8List statelessResetToken,
  ) {
    return {
      'connection_id': hexdump(connectionId),
      'frame_type': 'new_connection_id',
      'length': connectionId.length,
      'reset_token': hexdump(statelessResetToken),
      'retire_prior_to': retirePriorTo,
      'sequence_number': sequenceNumber,
    };
  }

  Map<String, dynamic> encodeNewTokenFrame(Uint8List token) {
    return {
      'frame_type': 'new_token',
      'length': token.length,
      'token': hexdump(token),
    };
  }

  Map<String, dynamic> encodePaddingFrame() {
    return {'frame_type': 'padding'};
  }

  Map<String, dynamic> encodePathChallengeFrame(Uint8List data) {
    return {'data': hexdump(data), 'frame_type': 'path_challenge'};
  }

  Map<String, dynamic> encodePathResponseFrame(Uint8List data) {
    return {'data': hexdump(data), 'frame_type': 'path_response'};
  }

  Map<String, dynamic> encodePingFrame() {
    return {'frame_type': 'ping'};
  }

  Map<String, dynamic> encodeResetStreamFrame(
      int errorCode, int finalSize, int streamId) {
    return {
      'error_code': errorCode,
      'final_size': finalSize,
      'frame_type': 'reset_stream',
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeRetireConnectionIdFrame(int sequenceNumber) {
    return {
      'frame_type': 'retire_connection_id',
      'sequence_number': sequenceNumber,
    };
  }

  Map<String, dynamic> encodeStreamDataBlockedFrame(int limit, int streamId) {
    return {
      'frame_type': 'stream_data_blocked',
      'limit': limit,
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeStopSendingFrame(int errorCode, int streamId) {
    return {
      'frame_type': 'stop_sending',
      'error_code': errorCode,
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeStreamFrame(QuicStreamFrame frame, int streamId) {
    return {
      'fin': frame.fin,
      'frame_type': 'stream',
      'length': frame.data.length,
      'offset': frame.offset,
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeStreamsBlockedFrame(
      bool isUnidirectional, int limit) {
    return {
      'frame_type': 'streams_blocked',
      'limit': limit,
      'stream_type': isUnidirectional ? 'unidirectional' : 'bidirectional',
    };
  }

  /// Convert a time to milliseconds.
  double encodeTime(double seconds) {
    return seconds * 1000;
  }

  Map<String, dynamic> encodeTransportParameters(
      String owner, QuicTransportParameters parameters) {
    final data = <String, dynamic>{'owner': owner};
    // Note: Dart does not have a direct equivalent to Python's __dict__ for
    // getting all instance variables. This conversion manually includes
    // all parameters defined in the QuicTransportParameters class.
    data['active_connection_id_limit'] = parameters.activeConnectionIdLimit;
    data['max_data'] = parameters.maxData;
    data['initial_max_data'] = parameters.initialMaxData;
    data['initial_max_stream_data_bidi_local'] =
        parameters.initialMaxStreamDataBidiLocal;
    data['initial_max_stream_data_bidi_remote'] =
        parameters.initialMaxStreamDataBidiRemote;
    data['initial_max_stream_data_uni'] = parameters.initialMaxStreamDataUni;
    data['initial_max_streams_bidi'] = parameters.initialMaxStreamsBidi;
    data['initial_max_streams_uni'] = parameters.initialMaxStreamsUni;
    data['idle_timeout'] = parameters.idleTimeout;
    data['max_packet_size'] = parameters.maxPacketSize;
    data['stateless_reset_token'] = parameters.statelessResetToken != null
        ? hexdump(parameters.statelessResetToken!)
        : null;
    data['disable_active_migration'] = parameters.disableActiveMigration;
    data['preferred_address'] = parameters.preferredAddress;
    return data;
  }

  String packetType(int packetType) {
    return packetTypeNames[packetType] ?? 'unknown';
  }

  // HTTP/3

  Map<String, dynamic> encodeHttp3DataFrame(int length, int streamId) {
    return {
      'frame': {'frame_type': 'data'},
      'length': length,
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeHttp3HeadersFrame(
      int length, Headers headers, int streamId) {
    return {
      'frame': {
        'frame_type': 'headers',
        'headers': _encodeHttp3Headers(headers),
      },
      'length': length,
      'stream_id': streamId,
    };
  }

  Map<String, dynamic> encodeHttp3PushPromiseFrame(
      int length, Headers headers, int pushId, int streamId) {
    return {
      'frame': {
        'frame_type': 'push_promise',
        'headers': _encodeHttp3Headers(headers),
        'push_id': pushId,
      },
      'length': length,
      'stream_id': streamId,
    };
  }

  List<Map<String, String>> _encodeHttp3Headers(Headers headers) {
    return headers
        .map((h) => {
              'name': utf8.decode(h.first),
              'value': utf8.decode(h.second),
            })
        .toList();
  }

  // CORE

  void logEvent({
    required String category,
    required String event,
    required Map<String, dynamic> data,
  }) {
    _events.add({
      'data': data,
      'name': '$category:$event',
      'time': encodeTime(DateTime.now().millisecondsSinceEpoch / 1000),
    });
  }

  /// Return the trace as a dictionary which can be written as JSON.
  Map<String, dynamic> toDict() {
    return {
      'common_fields': {
        'ODCID': hexdump(_odcid),
      },
      'events': _events.toList(),
      'vantage_point': _vantagePoint,
    };
  }
}

/// A QUIC event logger which stores traces in memory.
class QuicLogger {
  final List<QuicLoggerTrace> _traces = [];

  QuicLogger();

  QuicLoggerTrace startTrace({required bool isClient, required Uint8List odcid}) {
    final trace = QuicLoggerTrace(isClient: isClient, odcid: odcid);
    _traces.add(trace);
    return trace;
  }

  void endTrace(QuicLoggerTrace trace) {
    if (!_traces.contains(trace)) {
      throw ArgumentError('QuicLoggerTrace does not belong to QuicLogger');
    }
  }

  /// Return the traces as a dictionary which can be written as JSON.
  Map<String, dynamic> toDict() {
    return {
      'qlog_format': 'JSON',
      'qlog_version': qlogVersion,
      'traces': _traces.map((trace) => trace.toDict()).toList(),
    };
  }
}

/// A QUIC event logger which writes one trace per file.
class QuicFileLogger extends QuicLogger {
  final String path;

  QuicFileLogger(this.path) {
    if (!Directory(path).existsSync()) {
      throw ArgumentError("QUIC log output directory '$path' does not exist");
    }
  }

  @override
  void endTrace(QuicLoggerTrace trace) {
    final traceDict = trace.toDict();
    final tracePath = path.join(path, '${traceDict['common_fields']['ODCID']}.qlog');
    final loggerFile = File(tracePath);
    final jsonContent = jsonEncode({
      'qlog_format': 'JSON',
      'qlog_version': qlogVersion,
      'traces': [traceDict],
    });
    loggerFile.writeAsStringSync(jsonContent);
    _traces.remove(trace);
  }
}