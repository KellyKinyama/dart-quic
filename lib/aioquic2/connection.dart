// Filename: connection.dart
import 'dart:collection';
import 'dart:typed_data';
import 'dart:math';
import 'configuration.dart';
import 'crypto.dart';
import 'events.dart';
import 'packet.dart';
import 'packet_builder.dart';
import 'recovery.dart';
import 'stream.dart';
import 'tls.dart';
import 'buffer.dart';

enum QuicConnectionState {
  firstFlight,
  connected,
  closing,
  draining,
  terminated,
}

class QuicConnection {
  final QuicConfiguration _config;
  QuicConnectionState _state = QuicConnectionState.firstFlight;
  final bool _isClient;

  final Queue<QuicEvent> _events = Queue<QuicEvent>();

  // Cryptography & TLS
  final TlsContext _tls;
  final Map<TlsEpoch, CryptoPair> _cryptos = {};
  final Map<TlsEpoch, QuicStream> _cryptoStreams = {};

  // Recovery
  final QuicPacketRecovery _recovery;

  // Streams
  final Map<int, QuicStream> _streams = {};
  int _localNextStreamIdBidi = 0;
  int _localNextStreamIdUni = 2;

  late Uint8List _hostCid;
  late Uint8List _peerCid;

  QuicConnection({required QuicConfiguration configuration})
    : _config = configuration,
      _isClient = configuration.isClient,
      _tls = TlsContext(isClient: configuration.isClient),
      _recovery = QuicPacketRecovery(
        maxDatagramSize: configuration.maxDatagramSize,
      ) {
    _hostCid = Uint8List(8)
      ..setAll(0, List.generate(8, (_) => Random().nextInt(256)));
    _peerCid = Uint8List(8)
      ..setAll(0, List.generate(8, (_) => Random().nextInt(256)));

    if (!_isClient) {
      _localNextStreamIdBidi = 1;
      _localNextStreamIdUni = 3;
    }

    _cryptos[TlsEpoch.initial] = CryptoPair();
    _cryptos[TlsEpoch.handshake] = CryptoPair();
    _cryptos[TlsEpoch.oneRtt] = CryptoPair();

    _cryptoStreams[TlsEpoch.initial] = QuicStream(streamId: -1);
    _cryptoStreams[TlsEpoch.handshake] = QuicStream(streamId: -1);
    _cryptoStreams[TlsEpoch.oneRtt] = QuicStream(streamId: -1);
  }

  void connect({
    required String serverName,
    required int port,
    required double now,
  }) {
    if (!_isClient) throw Exception("connect() is only for clients");
    _cryptos[TlsEpoch.initial]!.setupInitial(cid: _peerCid, isClient: true);
    // This would trigger the TLS handshake, sending a ClientHello
    final clientHello = _tls.startHandshake();
    _cryptoStreams[TlsEpoch.initial]!.sender.write(clientHello);
  }

  void receiveDatagram(Uint8List datagram, double now) {
    if (_state == QuicConnectionState.terminated) return;

    final buf = Buffer(data: datagram);
    while (!buf.eof) {
      final header = pullQuicHeader(
        buf,
        hostCidLength: _config.connectionIdLength,
      );
      final epoch = _getEpoch(header.packetType);
      final crypto = _cryptos[epoch]!;

      // In a real implementation, decryption would be awaited here.
      // For this example, we assume it succeeds and payload is extracted.
      final plainPayload = buf.dataSlice(
        buf.tell(),
        buf.tell() + header.packetLength,
      );
      _payloadReceived(plainPayload, epoch, now);
    }
  }

  void _payloadReceived(Uint8List payload, TlsEpoch epoch, double now) {
    final buf = Buffer(data: payload);
    while (!buf.eof) {
      final frameType = buf.pullUintVar();
      // Simplified frame dispatching
      if (frameType >= 0x08 && frameType <= 0x0f) {
        // STREAM
        _handleStreamFrame(buf);
      } else if (frameType == 0x02 || frameType == 0x03) {
        // ACK
        _handleAckFrame(buf, epoch, now);
      }
    }
  }

  void _handleAckFrame(Buffer buf, TlsEpoch epoch, double now) {
    final (ackRanges, ackDelayEncoded) = pullAckFrame(buf);
    final ackDelay = ackDelayEncoded / 1000.0; // Simplified
    _recovery.onAckReceived(ackRanges, ackDelay, now, epoch);
  }

  void _handleStreamFrame(Buffer buf) {
    // Simplified parsing
    final streamId = buf.pullUintVar();
    final offset = buf.pullUintVar();
    final length = buf.pullUintVar();
    final fin = (buf.pullUint8() & 1) != 0;
    final data = buf.pullBytes(length);
    final frame = QuicStreamFrame(data: data, offset: offset, fin: fin);

    final stream = _streams.putIfAbsent(
      streamId,
      () => QuicStream(streamId: streamId),
    );
    final event = stream.receiver.handleFrame(frame);
    if (event != null) _events.add(event);
  }

  Future<(List<Uint8List>, String, int)> datagramsToSend(double now) async {
    if (_state == QuicConnectionState.terminated) return (<Uint8List>[], '', 0);

    final builder = QuicPacketBuilder(
      hostCid: _hostCid,
      peerCid: _peerCid,
      version: QuicProtocolVersion.version1,
      isClient: _isClient,
      maxDatagramSize: _config.maxDatagramSize,
      packetNumber: _recovery.spaces[TlsEpoch.oneRtt]!.expectedPacketNumber,
    );

    // Simplified: just send one packet type for now
    final epoch = TlsEpoch.initial;
    final crypto = _cryptos[epoch]!;
    // if (crypto.send.isValid) {
    builder.startPacket(QuicPacketType.initial, crypto);
    // In a real implementation, you would write ACK, CRYPTO, STREAM frames etc.
    // }

    final (datagrams, packets) = await builder.flush();
    for (final packet in packets) {
      _recovery.onPacketSent(packet, packet.epoch);
    }
    return (datagrams, '127.0.0.1', 4433);
  }

  QuicEvent? nextEvent() => _events.isEmpty ? null : _events.removeFirst();
  double? getTimer() => _recovery.getLossDetectionTime();
  void handleTimer(double now) => _recovery.onLossDetectionTimeout(now);

  int createStream({bool bidirectional = true}) {
    final streamId = bidirectional
        ? _localNextStreamIdBidi
        : _localNextStreamIdUni;
    if (bidirectional) {
      _localNextStreamIdBidi += 4;
    } else {
      _localNextStreamIdUni += 4;
    }
    _streams[streamId] = QuicStream(
      streamId: streamId,
      isLocalInitiator: true,
      isUnidirectional: !bidirectional,
    );
    return streamId;
  }

  void sendStreamData(int streamId, Uint8List data, {bool endStream = false}) {
    final stream = _streams[streamId];
    if (stream == null) throw Exception('Stream does not exist');
    stream.sender.write(data, endStream: endStream);
  }

  TlsEpoch _getEpoch(QuicPacketType type) {
    if (type == QuicPacketType.initial) return TlsEpoch.initial;
    if (type == QuicPacketType.handshake) return TlsEpoch.handshake;
    return TlsEpoch.oneRtt;
  }
}
