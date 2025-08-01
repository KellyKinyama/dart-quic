import 'dart:typed_data';
import '../buffer.dart';
import 'packet.dart';
import 'crypto.dart';
import '../tls.dart';

// Assuming QuicLoggerTrace is a class for logging
class QuicLoggerTrace {
  // A placeholder function to show how the original python code might be handled
  Map<String, dynamic> encodePaddingFrame() => {"frame_type": "padding"};
}

typedef QuicDeliveryHandler = void Function(List<dynamic> args);

enum QuicDeliveryState { ACKED, LOST }

class QuicSentPacket {
  final Epoch epoch;
  bool inFlight;
  bool isAckEliciting;
  final bool isCryptoPacket;
  final int packetNumber;
  final QuicPacketType packetType;
  final double? sentTime;
  int sentBytes;
  final List<Tuple<QuicDeliveryHandler, List<dynamic>>> deliveryHandlers;
  final List<Map<String, dynamic>> quicLoggerFrames;

  QuicSentPacket({
    required this.epoch,
    required this.inFlight,
    required this.isAckEliciting,
    required this.isCryptoPacket,
    required this.packetNumber,
    required this.packetType,
    this.sentTime,
    this.sentBytes = 0,
    List<Tuple<QuicDeliveryHandler, List<dynamic>>>? deliveryHandlers,
    List<Map<String, dynamic>>? quicLoggerFrames,
  }) : deliveryHandlers = deliveryHandlers ?? [],
       quicLoggerFrames = quicLoggerFrames ?? [];
}

class QuicPacketBuilderStop implements Exception {}

class QuicPacketBuilder {
  final Uint8List _hostCid;
  final bool _isClient;
  final Uint8List _peerCid;
  final Uint8List _peerToken;
  final QuicLoggerTrace? _quicLogger;
  final bool _spinBit;
  final int _version;

  int? maxFlightBytes;
  int? maxTotalBytes;
  List<Map<String, dynamic>>? quicLoggerFrames;

  // assembled datagrams and packets
  final List<Uint8List> _datagrams = [];
  int _datagramFlightBytes = 0;
  bool _datagramInit = true;
  bool _datagramNeedsPadding = false;
  final List<QuicSentPacket> _packets = [];
  int _flightBytes = 0;
  int _totalBytes = 0;

  // current packet
  int _headerSize = 0;
  QuicSentPacket? _packet;
  CryptoPair? _packetCrypto;
  int _packetNumber;
  int _packetStart = 0;
  QuicPacketType? _packetType;

  final Buffer _buffer;
  int _bufferCapacity;
  int _flightCapacity;

  QuicPacketBuilder({
    required Uint8List hostCid,
    required Uint8List peerCid,
    required int version,
    required bool isClient,
    required int maxDatagramSize,
    int packetNumber = 0,
    Uint8List peerToken = const Uint8List(0),
    QuicLoggerTrace? quicLogger,
    bool spinBit = false,
  }) : _hostCid = hostCid,
       _peerCid = peerCid,
       _version = version,
       _isClient = isClient,
       _packetNumber = packetNumber,
       _peerToken = peerToken,
       _quicLogger = quicLogger,
       _spinBit = spinBit,
       _buffer = Buffer(maxDatagramSize),
       _bufferCapacity = maxDatagramSize,
       _flightCapacity = maxDatagramSize;

  bool get packetIsEmpty {
    assert(_packet != null);
    final packetSize = _buffer.tell() - _packetStart;
    return packetSize <= _headerSize;
  }

  int get packetNumber => _packetNumber;

  int get remainingBufferSpace {
    if (_packetCrypto == null) return 0;
    return _bufferCapacity - _buffer.tell() - _packetCrypto!.aeadTagSize;
  }

  int get remainingFlightSpace {
    if (_packetCrypto == null) return 0;
    return _flightCapacity - _buffer.tell() - _packetCrypto!.aeadTagSize;
  }

  Tuple<List<Uint8List>, List<QuicSentPacket>> flush() {
    if (_packet != null) {
      _endPacket();
    }
    _flushCurrentDatagram();

    final datagrams = List<Uint8List>.from(_datagrams);
    final packets = List<QuicSentPacket>.from(_packets);
    _datagrams.clear();
    _packets.clear();
    return Tuple(datagrams, packets);
  }

  Buffer startFrame(
    int frameType, {
    int capacity = 1,
    QuicDeliveryHandler? handler,
    List<dynamic> handlerArgs = const [],
  }) {
    if (remainingBufferSpace < capacity ||
        (!NON_IN_FLIGHT_FRAME_TYPES.contains(QuicFrameType.values[frameType]) &&
            remainingFlightSpace < capacity)) {
      throw QuicPacketBuilderStop();
    }

    _buffer.pushUintVar(frameType);
    if (!NON_ACK_ELICITING_FRAME_TYPES.contains(
      QuicFrameType.values[frameType],
    )) {
      _packet!.isAckEliciting = true;
    }
    if (!NON_IN_FLIGHT_FRAME_TYPES.contains(QuicFrameType.values[frameType])) {
      _packet!.inFlight = true;
    }
    if (QuicFrameType.values[frameType] == QuicFrameType.CRYPTO) {
      _packet!.isCryptoPacket = true;
    }
    if (handler != null) {
      _packet!.deliveryHandlers.add(Tuple(handler, handlerArgs));
    }
    return _buffer;
  }

  void startPacket(QuicPacketType packetType, CryptoPair crypto) {
    assert(
      packetType == QuicPacketType.INITIAL ||
          packetType == QuicPacketType.HANDSHAKE ||
          packetType == QuicPacketType.ZERO_RTT ||
          packetType == QuicPacketType.ONE_RTT,
      "Invalid packet type",
    );
    final buf = _buffer;

    if (_packet != null) {
      _endPacket();
    }

    var packetStart = buf.tell();
    if (_bufferCapacity - packetStart < 128) {
      _flushCurrentDatagram();
      packetStart = 0;
    }

    if (_datagramInit) {
      if (maxTotalBytes != null) {
        final remainingTotalBytes = maxTotalBytes! - _totalBytes;
        if (remainingTotalBytes < _bufferCapacity) {
          _bufferCapacity = remainingTotalBytes;
        }
      }

      _flightCapacity = _bufferCapacity;
      if (maxFlightBytes != null) {
        final remainingFlightBytes = maxFlightBytes! - _flightBytes;
        if (remainingFlightBytes < _flightCapacity) {
          _flightCapacity = remainingFlightBytes;
        }
      }
      _datagramFlightBytes = 0;
      _datagramInit = false;
      _datagramNeedsPadding = false;
    }

    var headerSize;
    if (packetType != QuicPacketType.ONE_RTT) {
      headerSize = 11 + _peerCid.length + _hostCid.length;
      if (packetType == QuicPacketType.INITIAL) {
        final tokenLength = _peerToken.length;
        headerSize += sizeUintVar(tokenLength) + tokenLength;
      }
    } else {
      headerSize = 3 + _peerCid.length;
    }

    if (packetStart + headerSize >= _bufferCapacity) {
      throw QuicPacketBuilderStop();
    }

    late Epoch epoch;
    if (packetType == QuicPacketType.INITIAL) {
      epoch = Epoch.INITIAL;
    } else if (packetType == QuicPacketType.HANDSHAKE) {
      epoch = Epoch.HANDSHAKE;
    } else {
      epoch = Epoch.ONE_RTT;
    }

    _headerSize = headerSize;
    _packet = QuicSentPacket(
      epoch: epoch,
      inFlight: false,
      isAckEliciting: false,
      isCryptoPacket: false,
      packetNumber: _packetNumber,
      packetType: packetType,
    );
    _packetCrypto = crypto;
    _packetStart = packetStart;
    _packetType = packetType;
    quicLoggerFrames = _packet!.quicLoggerFrames;

    buf.seek(_packetStart + _headerSize);
  }

  void _endPacket() {
    final buf = _buffer;
    final packetSize = buf.tell() - _packetStart;
    if (packetSize > _headerSize) {
      var paddingSize =
          PACKET_NUMBER_MAX_SIZE -
          PACKET_NUMBER_SEND_SIZE +
          _headerSize -
          packetSize;

      if ((_isClient || _packet!.isAckEliciting) &&
          _packetType == QuicPacketType.INITIAL) {
        _datagramNeedsPadding = true;
      }

      if (_datagramNeedsPadding && _packetType == QuicPacketType.ONE_RTT) {
        if (remainingFlightSpace > paddingSize) {
          paddingSize = remainingFlightSpace;
        }
        _datagramNeedsPadding = false;
      }

      if (paddingSize > 0) {
        buf.pushBytes(Uint8List(paddingSize));
        packetSize += paddingSize;
        _packet!.inFlight = true;

        if (_quicLogger != null) {
          _packet!.quicLoggerFrames.add(_quicLogger!.encodePaddingFrame());
        }
      }

      if (_packetType != QuicPacketType.ONE_RTT) {
        final length =
            packetSize -
            _headerSize +
            PACKET_NUMBER_SEND_SIZE +
            _packetCrypto!.aeadTagSize;
        buf.seek(_packetStart);
        buf.pushUint8(
          encodeLongHeaderFirstByte(
            _version,
            _packetType!,
            PACKET_NUMBER_SEND_SIZE - 1,
          ),
        );
        buf.pushUint32(_version);
        buf.pushUint8(_peerCid.length);
        buf.pushBytes(_peerCid);
        buf.pushUint8(_hostCid.length);
        buf.pushBytes(_hostCid);
        if (_packetType == QuicPacketType.INITIAL) {
          buf.pushUintVar(_peerToken.length);
          buf.pushBytes(_peerToken);
        }
        buf.pushUint16(length | 0x4000);
        buf.pushUint16(_packetNumber & 0xFFFF);
      } else {
        buf.seek(_packetStart);
        buf.pushUint8(
          PACKET_FIXED_BIT |
              (_spinBit ? (1 << 5) : 0) |
              (_packetCrypto!.keyPhase << 2) |
              (PACKET_NUMBER_SEND_SIZE - 1),
        );
        buf.pushBytes(_peerCid);
        buf.pushUint16(_packetNumber & 0xFFFF);
      }

      final plain = buf.data.sublist(_packetStart, _packetStart + packetSize);
      buf.seek(_packetStart);
      buf.pushBytes(
        _packetCrypto!.encryptPacket(
          plain.sublist(0, _headerSize),
          plain.sublist(_headerSize, packetSize),
          _packetNumber,
        ),
      );
      _packet!.sentBytes = buf.tell() - _packetStart;
      _packets.add(_packet!);
      if (_packet!.inFlight) {
        _datagramFlightBytes += _packet!.sentBytes;
      }

      if (_packetType == QuicPacketType.ONE_RTT) {
        _flushCurrentDatagram();
      }

      _packetNumber++;
    } else {
      buf.seek(_packetStart);
    }

    _packet = null;
    quicLoggerFrames = null;
  }

  void _flushCurrentDatagram() {
    final datagramBytes = _buffer.tell();
    if (datagramBytes > 0) {
      if (_datagramNeedsPadding) {
        final extraBytes = _flightCapacity - _buffer.tell();
        if (extraBytes > 0) {
          _buffer.pushBytes(Uint8List(extraBytes));
          _datagramFlightBytes += extraBytes;
        }
      }

      _datagrams.add(Uint8List.fromList(_buffer.data));
      _flightBytes += _datagramFlightBytes;
      _totalBytes += datagramBytes;
      _datagramInit = true;
      _buffer.seek(0);
    }
  }
}
