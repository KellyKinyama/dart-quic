// lib/go_quic/quic_header.dart

import 'dart:typed_data';
import 'buffer.dart';

/// Represents the parsed data from a QUIC packet header.
class QuicHeader {
  final int packetType;
  final Uint8List destinationCid;
  final Uint8List sourceCid;
  final int pnOffset;
  final int payloadLength;
  final int headerLength;
  final int? tokenLength; // Optional token length for Initial packets.
  final int?
  parsedPayloadLengthFieldBytes; // The byte size of the varint payload length.

  QuicHeader({
    required this.packetType,
    required this.destinationCid,
    required this.sourceCid,
    required this.pnOffset,
    required this.payloadLength,
    required this.headerLength,
    this.tokenLength,
    this.parsedPayloadLengthFieldBytes,
  });

  /// Extracts the header protection sample from the raw packet bytes.
  ///
  /// The sample is a fixed-size portion of the ciphertext used to
  /// encrypt/decrypt the header's packet number.
  ///
  /// - [packetBytes]: The full UDP datagram containing the QUIC packet.
  /// - [sampleLength]: The required length of the sample, typically 16 bytes.
  Uint8List getSample(Uint8List packetBytes, int sampleLength) {
    // The sample offset is calculated from the start of the packet number field.
    // Per RFC 9001, we always assume the packet number is 4 bytes long for this calculation
    // to simplify decryption, regardless of its actual encoded length.
    const assumedPnLength = 4;
    final sampleOffset = pnOffset + assumedPnLength;

    // Ensure the packet is long enough to contain a full sample.
    if (packetBytes.length < sampleOffset + sampleLength) {
      throw Exception(
        'Packet is too short to extract a complete header protection sample.',
      );
    }

    return Uint8List.view(
      packetBytes.buffer,
      packetBytes.offsetInBytes + sampleOffset,
      sampleLength,
    );
  }
}

/// Parses the Long Header of an Initial or Handshake packet from a buffer.
QuicHeader pullQuicLongHeader(Buffer buffer) {
  final initialOffset = buffer.tell();

  final firstByte = buffer.pullUint8();
  // Bits 4 and 5 (00110000) determine the long packet type.
  final packetType = (firstByte & 0x30) >> 4;

  buffer.pullUint32(); // Skip Version

  final dcid = buffer.pullVector(1);
  final scid = buffer.pullVector(1);

  int? tokenLength;
  if (packetType == 0) {
    // Initial Packet
    tokenLength = buffer.pullVarInt();
    buffer.pullBytes(tokenLength); // Skip the token itself
  }

  final payloadLengthFieldOffset = buffer.tell();
  final payloadLength = buffer.pullVarInt();
  final payloadLengthFieldBytes = buffer.tell() - payloadLengthFieldOffset;

  final pnOffset = buffer.tell();
  final headerLength = pnOffset - initialOffset;

  return QuicHeader(
    packetType: packetType,
    destinationCid: dcid,
    sourceCid: scid,
    pnOffset: pnOffset,
    payloadLength: payloadLength,
    headerLength: headerLength,
    tokenLength: tokenLength,
    parsedPayloadLengthFieldBytes: payloadLengthFieldBytes,
  );
}
