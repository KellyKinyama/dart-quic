// Filename: packet_builder.dart
import 'dart:typed_data';
import 'buffer.dart';
import 'crypto.dart';
import 'packet.dart';
import 'tls.dart';

enum QuicDeliveryState { acked, lost }

class QuicSentPacket {
  final TlsEpoch epoch;
  final bool inFlight;
  bool isAckEliciting;
  final bool isCryptoPacket;
  final int packetNumber;
  final QuicPacketType packetType;
  double? sentTime;
  int sentBytes = 0;

  QuicSentPacket({
    required this.epoch,
    required this.packetNumber,
    required this.packetType,
    this.inFlight = false,
    this.isAckEliciting = false,
    this.isCryptoPacket = false,
  });
}

class QuicPacketBuilder {
  final Uint8List hostCid;
  final Uint8List peerCid;
  final int version;
  final bool isClient;
  final int maxDatagramSize;
  int packetNumber;
  final Uint8List _peerToken;

  final List<Uint8List> _datagrams = [];
  final List<QuicSentPacket> _packets = [];

  QuicSentPacket? _packet;
  CryptoPair? _packetCrypto;
  int _packetStart = 0;
  int _headerSize = 0;

  // FIX: Initialize the buffer directly here.
  final Buffer _buffer;

  // THIS IS THE CORRECTED CONSTRUCTOR
  // It uses modern Dart syntax to initialize all fields directly in the
  // parameter list, which resolves the constant evaluation ambiguity.
  QuicPacketBuilder({
    required this.hostCid,
    required this.peerCid,
    required this.version,
    required this.isClient,
    required this.maxDatagramSize,
    this.packetNumber = 0,
    List<int> peerToken = const [],
  }) : _peerToken = Uint8List.fromList(peerToken),
       _buffer = Buffer(capacity: maxDatagramSize);

  void startPacket(QuicPacketType packetType, CryptoPair crypto) {
    if (_packet != null) {
      throw Exception(
        'Cannot start a new packet before the previous one is flushed.',
      );
    }

    TlsEpoch epoch;
    if (packetType == QuicPacketType.initial) {
      epoch = TlsEpoch.initial;
      _headerSize =
          1 +
          4 +
          1 +
          peerCid.length +
          1 +
          hostCid.length +
          2 +
          _peerToken.length +
          2;
    } else if (packetType == QuicPacketType.handshake) {
      epoch = TlsEpoch.handshake;
      _headerSize = 1 + 4 + 1 + peerCid.length + 1 + hostCid.length + 2;
    } else {
      epoch = TlsEpoch.oneRtt;
      _headerSize = 1 + peerCid.length + 2;
    }

    _packet = QuicSentPacket(
      epoch: epoch,
      packetNumber: packetNumber,
      packetType: packetType,
    );
    _packetCrypto = crypto;
    _packetStart = _buffer.tell();

    _buffer.seek(_packetStart + _headerSize); // Reserve space for header
  }

  Future<(List<Uint8List>, List<QuicSentPacket>)> flush() async {
    if (_packet != null) await _endPacket();

    if (_buffer.length > 0) {
      _datagrams.add(_buffer.data);
    }

    final result = (_datagrams.toList(), _packets.toList());
    _datagrams.clear();
    _packets.clear();
    _buffer.seek(0);
    return result;
  }

  Future<void> _endPacket() async {
    if (_packet == null) return;

    final payloadLength = _buffer.tell() - _packetStart - _headerSize;
    if (payloadLength == 0) {
      _buffer.seek(_packetStart); // Cancel empty packet
      _packet = null;
      return;
    }

    final packetSize = _headerSize + payloadLength;
    final plainHeaderAndPayload = _buffer.dataSlice(
      _packetStart,
      _packetStart + packetSize,
    );

    // Encrypt the packet
    final encryptedPacket = await _packetCrypto!.send.encryptPacket(
      plainHeaderAndPayload.sublist(0, _headerSize),
      plainHeaderAndPayload.sublist(_headerSize),
      packetNumber,
    );

    // Overwrite plain data with encrypted data
    _buffer.seek(_packetStart);
    _buffer.pushBytes(encryptedPacket);

    _packet!.sentBytes = encryptedPacket.length;
    _packets.add(_packet!);
    packetNumber++;
    _packet = null;
  }
}
