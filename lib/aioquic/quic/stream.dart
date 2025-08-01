import 'dart:typed_data';
import 'dart:collection';
import 'dart:math';

import 'events.dart' as events;
import 'packet.dart';
import 'packet_builder.dart';
import 'range_set.dart';

class FinalSizeError implements Exception {}

class StreamFinishedError implements Exception {}

class QuicStreamReceiver {
  int highestOffset; // the highest offset ever seen
  bool isFinished;
  bool stopPending;

  final BytesBuilder _buffer;
  int _bufferStart; // the offset for the start of the buffer
  int? _finalSize;
  final RangeSet _ranges;
  final int? _streamId;
  int? _stopErrorCode;

  QuicStreamReceiver({int? streamId, required bool readable})
    : highestOffset = 0,
      isFinished = !readable, // If not readable, it's finished by default
      stopPending = false,
      _buffer = BytesBuilder(),
      _bufferStart = 0,
      _ranges = RangeSet(),
      _streamId = streamId;

  QuicStopSendingFrame getStopFrame() {
    stopPending = false;
    return QuicStopSendingFrame(
      errorCode: _stopErrorCode ?? QuicErrorCode.NO_ERROR.value,
      streamId: _streamId!,
    );
  }

  int startingOffset() {
    return _bufferStart;
  }

  events.StreamDataReceived? handleFrame(QuicStreamFrame frame) {
    var pos = frame.offset - _bufferStart;
    var count = frame.data.length;
    var frameEnd = frame.offset + count;

    // we should receive no more data beyond FIN!
    if (_finalSize != null) {
      if (frameEnd > _finalSize!) {
        throw FinalSizeError("Data received beyond final size");
      } else if (frame.fin && frameEnd != _finalSize) {
        throw FinalSizeError("Cannot change final size");
      }
    }
    if (frame.fin) {
      _finalSize = frameEnd;
    }
    if (frameEnd > highestOffset) {
      highestOffset = frameEnd;
    }

    // fast path: new in-order chunk
    if (pos == 0 && count > 0 && _buffer.isEmpty) {
      _bufferStart += count;
      if (frame.fin) {
        isFinished = true;
      }
      return events.StreamDataReceived(
        data: frame.data,
        endStream: frame.fin,
        streamId: _streamId!,
      );
    }

    // discard duplicate data
    if (pos < 0) {
      frame = QuicStreamFrame(
        data: frame.data.sublist(-pos),
        offset: frame.offset - pos,
        fin: frame.fin,
      );
      pos = 0;
      count = frame.data.length;
      frameEnd = frame.offset + count;
    }

    // marked received range
    if (frameEnd > frame.offset) {
      _ranges.add(frame.offset, frameEnd);
    }

    // add new data
    final gap = pos - _buffer.length;
    if (gap > 0) {
      _buffer.add(Uint8List(gap));
    }
    _buffer.add(frame.data);

    // return data from the front of the buffer
    final data = _pullData();
    final endStream = _bufferStart == _finalSize;
    if (endStream) {
      isFinished = true;
    }
    if (data.isNotEmpty || endStream) {
      return events.StreamDataReceived(
        data: data,
        endStream: endStream,
        streamId: _streamId!,
      );
    } else {
      return null;
    }
  }

  events.StreamReset? handleReset({
    required int finalSize,
    int errorCode = 0, // QuicErrorCode.NO_ERROR.value
  }) {
    if (_finalSize != null && finalSize != _finalSize) {
      throw FinalSizeError("Cannot change final size");
    }

    _finalSize = finalSize;
    isFinished = true;
    return events.StreamReset(
      errorCode: errorCode,
      streamId: _streamId!,
      finalSize: finalSize,
    );
  }

  void onStopSendingDelivery(QuicDeliveryState delivery) {
    if (delivery != QuicDeliveryState.ACKED) {
      stopPending = true;
    }
  }

  void stop([int errorCode = 0]) {
    _stopErrorCode = errorCode;
    stopPending = true;
  }

  Uint8List _pullData() {
    bool hasDataToRead;
    try {
      hasDataToRead = _ranges.first.start == _bufferStart;
    } on StateError {
      hasDataToRead = false;
    }
    if (!hasDataToRead) {
      return Uint8List(0);
    }

    final r = _ranges.shift();
    final pos = r.end - r.start;
    final data = _buffer.toBytes().sublist(0, pos);
    _buffer.clear();
    _buffer.add(Uint8List.fromList(_buffer.toBytes().sublist(pos)));
    _bufferStart = r.end;
    return data;
  }
}

class QuicStreamSender {
  bool bufferIsEmpty;
  int highestOffset;
  bool isFinished;
  bool resetPending;

  final RangeSet _acked;
  bool _ackedFin;
  final BytesBuilder _buffer;
  int? _bufferFin;
  int _bufferStart; // the offset for the start of the buffer
  int _bufferStop; // the offset for the stop of the buffer
  final RangeSet _pending;
  bool _pendingEof;
  int? _resetErrorCode;
  final int? _streamId;

  QuicStreamSender({int? streamId, required bool writable})
    : bufferIsEmpty = true,
      highestOffset = 0,
      isFinished = !writable,
      resetPending = false,
      _acked = RangeSet(),
      _ackedFin = false,
      _buffer = BytesBuilder(),
      _bufferStart = 0,
      _bufferStop = 0,
      _pending = RangeSet(),
      _pendingEof = false,
      _streamId = streamId;

  int get nextOffset {
    try {
      return _pending.first.start;
    } on StateError {
      return _bufferStop;
    }
  }

  QuicStreamFrame? getFrame(int maxSize, {int? maxOffset}) {
    assert(_resetErrorCode == null, "cannot call getFrame() after reset()");

    Range? r;
    try {
      r = _pending.first;
    } on StateError {
      if (_pendingEof) {
        _pendingEof = false;
        return QuicStreamFrame(fin: true, offset: _bufferFin!);
      }
      bufferIsEmpty = true;
      return null;
    }

    var start = r.start;
    var stop = min(r.end, start + maxSize);
    if (maxOffset != null && stop > maxOffset) {
      stop = maxOffset;
    }
    if (stop <= start) {
      return null;
    }

    final frame = QuicStreamFrame(
      data: _buffer.toBytes().sublist(
        start - _bufferStart,
        stop - _bufferStart,
      ),
      offset: start,
    );
    _pending.subtract(start, stop);

    if (stop > highestOffset) {
      highestOffset = stop;
    }

    if (_bufferFin == stop) {
      frame.fin = true;
      _pendingEof = false;
    }

    return frame;
  }

  QuicResetStreamFrame getResetFrame() {
    resetPending = false;
    return QuicResetStreamFrame(
      errorCode: _resetErrorCode!,
      finalSize: highestOffset,
      streamId: _streamId!,
    );
  }

  void onDataDelivery(
    QuicDeliveryState delivery,
    int start,
    int stop,
    bool fin,
  ) {
    assert(
      !fin || stop == _bufferFin,
      "onDataDelivered() was called with inconsistent fin / stop",
    );

    if (_resetErrorCode != null) {
      return;
    }

    if (delivery == QuicDeliveryState.ACKED) {
      if (stop > start) {
        _acked.add(start, stop);
        try {
          final firstRange = _acked.first;
          if (firstRange.start == _bufferStart) {
            final size = firstRange.end - firstRange.start;
            _acked.shift();
            _bufferStart += size;
            _buffer.clear();
            _buffer.add(Uint8List.fromList(_buffer.toBytes().sublist(size)));
          }
        } on StateError {
          // No ranges in _acked
        }
      }

      if (fin) {
        _ackedFin = true;
      }

      if (_bufferStart == _bufferFin && _ackedFin) {
        isFinished = true;
      }
    } else {
      if (stop > start) {
        bufferIsEmpty = false;
        _pending.add(start, stop);
      }

      if (fin) {
        bufferIsEmpty = false;
        _pendingEof = true;
      }
    }
  }

  void onResetDelivery(QuicDeliveryState delivery) {
    if (delivery == QuicDeliveryState.ACKED) {
      isFinished = true;
    } else {
      resetPending = true;
    }
  }

  void reset(int errorCode) {
    assert(_resetErrorCode == null, "cannot call reset() more than once");
    _resetErrorCode = errorCode;
    resetPending = true;
    bufferIsEmpty = true;
  }

  void write(Uint8List data, {bool endStream = false}) {
    assert(_bufferFin == null, "cannot call write() after FIN");
    assert(_resetErrorCode == null, "cannot call write() after reset()");
    final size = data.length;

    if (size > 0) {
      bufferIsEmpty = false;
      _pending.add(_bufferStop, _bufferStop + size);
      _buffer.add(data);
      _bufferStop += size;
    }
    if (endStream) {
      bufferIsEmpty = false;
      _bufferFin = _bufferStop;
      _pendingEof = true;
    }
  }
}

class QuicStream {
  final int? streamId;
  final bool isClientInitiated;
  final bool isUnidirectional;
  final int maxStreamDataLocal;
  int maxStreamDataLocalSent;
  final int maxStreamDataRemote;
  final QuicStreamReceiver receiver;
  final QuicStreamSender sender;
  bool isBlocked;

  QuicStream({
    this.streamId,
    this.maxStreamDataLocal = 0,
    this.maxStreamDataRemote = 0,
    bool readable = true,
    bool writable = true,
  }) : isClientInitiated = (streamId ?? 0) % 2 == 0,
       isUnidirectional = (streamId ?? 0) % 4 >= 2,
       maxStreamDataLocalSent = maxStreamDataLocal,
       receiver = QuicStreamReceiver(streamId: streamId, readable: readable),
       sender = QuicStreamSender(streamId: streamId, writable: writable),
       isBlocked = false;

  bool get isFinished => receiver.isFinished && sender.isFinished;
}

int min(int a, int b) => a < b ? a : b;
int max(int a, int b) => a > b ? a : b;
