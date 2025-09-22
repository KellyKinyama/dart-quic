// Create a new file: lib/go_quic/quic_header.dart

import 'dart:typed_data';
import 'package:dart_quic/go_quic/buffer.dart';

class QuicHeader {
  final int packetType; // 0 for Initial, 2 for Handshake, etc.
  final Uint8List destinationCid;
  final Uint8List sourceCid;
  final int pnOffset;
  final int payloadLength;
  final int headerLength;

  QuicHeader({
    required this.packetType,
    required this.destinationCid,
    required this.sourceCid,
    required this.pnOffset,
    required this.payloadLength,
    required this.headerLength,
  });
}

/// Parses the Long Header of an Initial or Handshake packet.
QuicHeader pullQuicLongHeader(Buffer buffer) {
  final initialOffset = buffer.tell();

  final firstByte = buffer.pullUint8();
  final packetType = (firstByte & 0x30) >> 4;

  buffer.pullUint32(); // Skip Version

  final dcid = buffer.pullVector(1);
  final scid = buffer.pullVector(1);

  if (packetType == 0) {
    // Initial Packet has a Token
    buffer.pullVarInt(); // Skips Token (pullVector(0) reads a var-int length)
  }

  final payloadLength = buffer.pullVarInt();
  final pnOffset = buffer.tell();
  final headerLength = pnOffset - initialOffset;

  return QuicHeader(
    packetType: packetType,
    destinationCid: dcid,
    sourceCid: scid,
    pnOffset: pnOffset,
    payloadLength: payloadLength,
    headerLength: headerLength,
  );
}
