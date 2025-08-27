// Filename: stream.dart
import 'dart:typed_data';
import 'dart:math';
import 'events.dart';
import 'packet.dart';
import 'range_set.dart';
import 'packet_builder.dart';

class FinalSizeError implements Exception {
  final String message;
  FinalSizeError(this.message);
}

class StreamFinishedError implements Exception {}

class QuicStreamReceiver {
  final int streamId;
  int highestOffset = 0;
  bool isFinished = false;
  bool stopPending = false;
  int? stopErrorCode;

  final BytesBuilder _buffer = BytesBuilder();
  int _bufferStart = 0;
  int? _finalSize;
  final RangeSet _ranges = RangeSet();

  QuicStreamReceiver(this.streamId);

  int get _bufferedBytes => _buffer.length;
  int startingOffset() => _bufferStart;

  StreamDataReceived? handleFrame(QuicStreamFrame frame) {
    int pos = frame.offset - _bufferStart;
    int count = frame.data.length;
    int frameEnd = frame.offset + count;

    if (_finalSize != null) {
      if (frameEnd > _finalSize!)
        throw FinalSizeError("Data received beyond final size");
      if (frame.fin && frameEnd != _finalSize)
        throw FinalSizeError("Cannot change final size");
    }
    if (frame.fin) _finalSize = frameEnd;
    if (frameEnd > highestOffset) highestOffset = frameEnd;

    // A more efficient buffer (e.g., a list of chunks) would avoid this copy.
    if (frame.data.isNotEmpty) {
      _ranges.add(frame.offset, frame.offset + frame.data.length);
      int gap = pos - _bufferedBytes;
      if (gap > 0) _buffer.add(List.filled(gap, 0));
      // Inefficient write for simplicity.
      var oldBytes = _buffer.toBytes();
      _buffer.clear();
      var newBytes = Uint8List(max(oldBytes.length, pos + count));
      newBytes.setRange(0, oldBytes.length, oldBytes);
      newBytes.setRange(pos, pos + count, frame.data);
      _buffer.add(newBytes);
    }

    final pulledData = _pullData();
    final endStream = (_finalSize != null && _bufferStart >= _finalSize!);
    if (endStream) isFinished = true;

    if (pulledData.isNotEmpty || endStream) {
      return StreamDataReceived(
        streamId: streamId,
        data: pulledData,
        endStream: endStream,
      );
    }
    return null;
  }

  StreamReset handleReset(int errorCode, int finalSize) {
    if (_finalSize != null && finalSize != _finalSize) {
      throw FinalSizeError('Cannot change final size');
    }
    _finalSize = finalSize;
    isFinished = true;
    return StreamReset(streamId: streamId, errorCode: errorCode);
  }

  Uint8List _pullData() {
    if (_ranges.isEmpty || _ranges.first.start != _bufferStart)
      return Uint8List(0);

    final r = _ranges.shift();
    final pos = r.end - r.start;
    final allBytes = _buffer.takeBytes();
    final data = allBytes.sublist(0, pos);
    if (allBytes.length > pos) {
      _buffer.add(allBytes.sublist(pos));
    }
    _bufferStart = r.end;
    return data;
  }
}

class QuicStreamSender {
  final int streamId;
  bool get bufferIsEmpty => _buffer.isEmpty && !_pendingEof;
  int highestOffset = 0;
  bool isFinished;
  bool resetPending = false;

  final RangeSet _acked = RangeSet();
  final BytesBuilder _buffer = BytesBuilder();
  int? _bufferFin;
  int _bufferStart = 0;
  int _bufferStop = 0;
  final RangeSet _pending = RangeSet();
  bool _pendingEof = false;
  int? _resetErrorCode;

  QuicStreamSender({required this.streamId, bool writable = true})
    : isFinished = !writable;

  QuicStreamFrame? getFrame(int maxSize, int maxOffset) {
    if (resetPending) return null;
    if (_pending.isEmpty) {
      if (_pendingEof) {
        _pendingEof = false;
        return QuicStreamFrame(
          data: Uint8List(0),
          fin: true,
          offset: _bufferFin!,
        );
      }
      return null;
    }

    final r = _pending.first;
    int start = r.start;
    int stop = min(r.end, start + maxSize);
    stop = min(stop, maxOffset);
    if (stop <= start) return null;

    final data = _buffer.toBytes().sublist(
      start - _bufferStart,
      stop - _bufferStart,
    );
    _pending.subtract(start, stop);

    if (stop > highestOffset) highestOffset = stop;

    return QuicStreamFrame(
      data: data,
      offset: start,
      fin: (_bufferFin != null && stop == _bufferFin && _pending.isEmpty),
    );
  }

  void write(Uint8List data, {bool endStream = false}) {
    if (_bufferFin != null) throw Exception("Cannot write after FIN");
    if (resetPending) throw Exception("Cannot write after reset");

    if (data.isNotEmpty) {
      _pending.add(_bufferStop, _bufferStop + data.length);
      _buffer.add(data);
      _bufferStop += data.length;
    }
    if (endStream) {
      _bufferFin = _bufferStop;
      _pendingEof = true;
    }
  }

  void onDataDelivery(
    QuicDeliveryState delivery,
    int start,
    int stop,
    bool fin,
  ) {
    if (resetPending) return;
    if (delivery == QuicDeliveryState.acked) {
      // Data and/or FIN was acknowledged
      if (stop > start) _acked.add(start, stop);
      if (fin && _bufferFin != null && _bufferStart == _bufferFin)
        isFinished = true;
    } else {
      // Lost
      // Reschedule data and/or FIN for retransmission
      if (stop > start) _pending.add(start, stop);
      if (fin) _pendingEof = true;
    }
  }
}

class QuicStream {
  final int streamId;
  final QuicStreamReceiver receiver;
  final QuicStreamSender sender;

  QuicStream({
    required this.streamId,
    bool isLocalInitiator = true,
    bool isUnidirectional = false,
  }) : receiver = QuicStreamReceiver(streamId),
       sender = QuicStreamSender(
         streamId: streamId,
         writable: !(isLocalInitiator == isUnidirectional),
       );

  bool get isFinished => receiver.isFinished && sender.isFinished;
}
