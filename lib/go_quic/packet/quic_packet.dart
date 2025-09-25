import 'dart:typed_data';

import '../buffer.dart';

/// The base class for all parsed QUIC packets.
abstract class QuicPacket {
  /// The raw byte view of the entire packet.
  final Uint8List raw;

  const QuicPacket({required this.raw});
}

/// Represents a QUIC packet with a Short Header (1-RTT).
class ShortHeaderPacket extends QuicPacket {
  const ShortHeaderPacket({required super.raw});
}

/// The base class for all QUIC packets with a Long Header.
abstract class LongHeaderPacket extends QuicPacket {
  final int version;
  final Uint8List destinationConnectionId;
  final Uint8List sourceConnectionId;

  const LongHeaderPacket({
    required this.version,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    required super.raw,
  });
}

/// Represents a Version Negotiation packet.
class VersionNegotiationPacket extends LongHeaderPacket {
  final List<int> supportedVersions;

  const VersionNegotiationPacket({
    required super.version,
    required super.destinationConnectionId,
    required super.sourceConnectionId,
    required this.supportedVersions,
    required super.raw,
  });
}

/// Represents an Initial packet.
class InitialPacket extends LongHeaderPacket {
  final Uint8List token;
  final int payloadLength;

  const InitialPacket({
    required super.version,
    required super.destinationConnectionId,
    required super.sourceConnectionId,
    required this.token,
    required this.payloadLength,
    required super.raw,
  });
}

/// Represents a Retry packet.
class RetryPacket extends LongHeaderPacket {
  final Uint8List originalDestinationConnectionId;

  const RetryPacket({
    required super.version,
    required super.destinationConnectionId,
    required super.sourceConnectionId,
    required this.originalDestinationConnectionId,
    required super.raw,
  });
}

/// Represents a Handshake packet.
class HandshakePacket extends LongHeaderPacket {
  final int payloadLength;

  const HandshakePacket({
    required super.version,
    required super.destinationConnectionId,
    required super.sourceConnectionId,
    required this.payloadLength,
    required super.raw,
  });
}

/// Represents a 0-RTT packet.
class ZeroRttPacket extends LongHeaderPacket {
  final int payloadLength;

  const ZeroRttPacket({
    required super.version,
    required super.destinationConnectionId,
    required super.sourceConnectionId,
    required this.payloadLength,
    required super.raw,
  });
}

/// Parses a single QUIC packet from the buffer's current position.
/// Returns null if the packet is malformed or the buffer is too small.
QuicPacket? parseQuicPacket(Buffer buffer) {
  final startOffset = buffer.readOffset;
  final firstByte = buffer.pullUint8();
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    final version = buffer.pullUint32();
    final dcidLen = buffer.pullUint8();
    final dcid = buffer.pullBytes(dcidLen);
    final scidLen = buffer.pullUint8();
    final scid = buffer.pullBytes(scidLen);

    // Version Negotiation Packet has a special format
    if (version == 0) {
      final supportedVersions = <int>[];
      while (!buffer.eof) {
        supportedVersions.add(buffer.pullUint32());
      }
      final raw = buffer.data.sublist(startOffset, buffer.readOffset);
      return VersionNegotiationPacket(
        version: version,
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        supportedVersions: supportedVersions,
        raw: raw,
      );
    }

    final packetTypeBits = (firstByte & 0x30) >> 4;
    switch (packetTypeBits) {
      case 0: // Initial
        final tokenLen = buffer.pullVarInt();
        final token = buffer.pullBytes(tokenLen);
        final payloadLen = buffer.pullVarInt();
        // Move reader to the end of the packet's payload
        buffer.pullBytes(payloadLen);
        final raw = buffer.data.sublist(startOffset, buffer.readOffset);
        return InitialPacket(
          version: version,
          destinationConnectionId: dcid,
          sourceConnectionId: scid,
          token: token,
          payloadLength: payloadLen,
          raw: raw,
        );
      case 1: // 0-RTT
        final payloadLen = buffer.pullVarInt();
        buffer.pullBytes(payloadLen);
        final raw = buffer.data.sublist(startOffset, buffer.readOffset);
        return ZeroRttPacket(
          version: version,
          destinationConnectionId: dcid,
          sourceConnectionId: scid,
          payloadLength: payloadLen,
          raw: raw,
        );
      case 2: // Handshake
        final payloadLen = buffer.pullVarInt();
        buffer.pullBytes(payloadLen);
        final raw = buffer.data.sublist(startOffset, buffer.readOffset);
        return HandshakePacket(
          version: version,
          destinationConnectionId: dcid,
          sourceConnectionId: scid,
          payloadLength: payloadLen,
          raw: raw,
        );
      case 3: // Retry
        // The rest of the packet is the ODIC
        final odcid = buffer.pullBytes(buffer.remaining);
        final raw = buffer.data.sublist(startOffset, buffer.readOffset);
        return RetryPacket(
          version: version,
          destinationConnectionId: dcid,
          sourceConnectionId: scid,
          originalDestinationConnectionId: odcid,
          raw: raw,
        );
    }
  } else {
    // Short Header Packet (1-RTT)
    // The header itself is not fully parsed here, only identified.
    // The payload consumes the rest of the buffer.
    buffer.position(offset: startOffset + buffer.remaining);
    final raw = buffer.data.sublist(startOffset, buffer.readOffset);
    return ShortHeaderPacket(raw: raw);
  }
  return null;
}

/// Parses a full datagram which may contain multiple coalesced packets.
List<QuicPacket> parseQuicDatagrams(Uint8List data) {
  final buffer = Buffer(data: data);
  final packets = <QuicPacket>[];

  try {
    while (!buffer.eof) {
      final packet = parseQuicPacket(buffer);
      if (packet != null) {
        packets.add(packet);
      } else {
        // Stop if a packet is malformed
        break;
      }
    }
  } catch (e) {
    // A BufferReadError indicates a malformed datagram.
    print('Error parsing datagram: $e');
  }

  return packets;
}

/// Helper function to convert a hex string to a Uint8List.
Uint8List hexToBytes(String hex) {
  final bytes = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

void main() {
  // This is the hex representation of a coalesced Initial + Handshake packet
  // from RFC 9000, Appendix A.2.
  final String serverResponseHex =
      'c30000000108f06170706c65730008d834535426b30fcf'
      'c20100000075000040350200005a0600409a0300ff00'
      '01000028000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      '00000000000000000000000000000000000000000000'
      'e20000000108d834535426b30fcf0008f06170706c6573'
      '00404802000044060040400500401804004004070008'
      '000100020002020003020000000a00080006001d0017'
      '0018000b00020100';
  // ADD THIS LINE to check the raw string length
  print(
    'Verification: Hex string character count is ${serverResponseHex.length}',
  );

  final datagramBytes = hexToBytes(serverResponseHex);

  print('--- Parsing QUIC Datagram (${datagramBytes.length} bytes) ---');

  final List<QuicPacket> packets = parseQuicDatagrams(datagramBytes);

  print('Parsed ${packets.length} packets:');
  for (int i = 0; i < packets.length; i++) {
    final packet = packets[i];
    print('\n[Packet ${i + 1}]');

    if (packet is InitialPacket) {
      print('  Type: InitialPacket');
      print('  Version: 0x${packet.version.toRadixString(16)}');
      print('  DCID: ${packet.destinationConnectionId}');
      print('  SCID: ${packet.sourceConnectionId}');
      print('  Token Length: ${packet.token.length}');
      print('  Payload Length: ${packet.payloadLength}');
      print('  Total Raw Length: ${packet.raw.length}');
    } else if (packet is HandshakePacket) {
      print('  Type: HandshakePacket');
      print('  Version: 0x${packet.version.toRadixString(16)}');
      print('  DCID: ${packet.destinationConnectionId}');
      print('  SCID: ${packet.sourceConnectionId}');
      print('  Payload Length: ${packet.payloadLength}');
      print('  Total Raw Length: ${packet.raw.length}');
    } else if (packet is ShortHeaderPacket) {
      print('  Type: ShortHeaderPacket (1-RTT)');
      print('  Total Raw Length: ${packet.raw.length}');
    } else {
      print('  Type: ${packet.runtimeType}');
    }
  }
}
