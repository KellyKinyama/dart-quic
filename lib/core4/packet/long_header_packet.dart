// LongHeaderPacket.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import 'quic_packet.dart'; // Import base QuicPacket

// Import concrete packet types for type determination
import 'initial_packet.dart';
import 'handshake_packet.dart';
import 'retry_packet.dart';
import 'zero_rtt_packet.dart';
import 'version_negotiation_packet.dart';

abstract class LongHeaderPacket extends QuicPacket {
  static const int V1_INITIAL_TYPE = 0x00; // Type bits 00
  static const int V1_HANDSHAKE_TYPE = 0x02; // Type bits 10
  static const int V1_ZERO_RTT_TYPE = 0x01; // Type bits 01
  static const int V1_RETRY_TYPE = 0x03; // Type bits 11

  // For QUIC Version 2 (draft-ietf-quic-v2-01) - types are shifted
  static const int V2_INITIAL_TYPE = 0x01; // Type bits 01
  static const int V2_HANDSHAKE_TYPE = 0x03; // Type bits 11
  static const int V2_ZERO_RTT_TYPE = 0x02; // Type bits 10
  static const int V2_RETRY_TYPE = 0x00; // Type bits 00

  Uint8List? sourceConnectionId;
  int? packetLength; // The Length field (Variable-Length Integer)

  LongHeaderPacket(Version quicVersion) : super() {
    this.quicVersion = quicVersion;
  }

  static bool isLongHeaderPacket(int firstByte) {
    return (firstByte & 0x80) == 0x80; // Fixed bit is 1
  }

  static Type determineType(int firstByte, Version version) {
    int type = (firstByte & 0x30) >> 4; // Extract the 2-bit packet type (bits 4 and 5)

    if (version == Version.QUIC_VERSION_1) {
      if (type == V1_INITIAL_TYPE) {
        return InitialPacket;
      } else if (type == V1_HANDSHAKE_TYPE) {
        return HandshakePacket;
      } else if (type == V1_RETRY_TYPE) {
        return RetryPacket;
      } else if (type == V1_ZERO_RTT_TYPE) {
        return ZeroRttPacket;
      }
    } else if (version == Version.QUIC_VERSION_2) { // Assuming V2 handling
      if (type == V2_INITIAL_TYPE) {
        return InitialPacket;
      } else if (type == V2_HANDSHAKE_TYPE) {
        return HandshakePacket;
      } else if (type == V2_RETRY_TYPE) {
        return RetryPacket;
      } else if (type == V2_ZERO_RTT_TYPE) {
        return ZeroRttPacket;
      }
    }
    throw InvalidPacketException("Unknown long header packet type: $type for version $version");
  }

  @override
  void parseHeader(Uint8List rawPacketData, int currentOffset, int firstByte, VersionHolder quicVersionHolder) {
    // This method parses the common fields of a Long Header Packet:
    // Version, DCID Length, DCID, SCID Length, SCID.
    // The 'Length' field and subsequent Packet Number are handled by specific subclasses.

    final ByteData byteData = rawPacketData.buffer.asByteData(rawPacketData.offsetInBytes);
    int offset = currentOffset;

    // Version field (4 bytes)
    if (rawPacketData.length - offset < 4) {
      throw InvalidPacketException("Buffer too short for Long Header Version");
    }
    quicVersion = Version(byteData.getUint32(offset));
    offset += 4;
    quicVersionHolder.version = quicVersion; // Update the shared version holder

    // Destination Connection ID Length (1 byte)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException("Buffer too short for DCID Length");
    }
    int dcidLength = byteData.getUint8(offset);
    offset += 1;

    // Destination Connection ID (variable length)
    if (rawPacketData.length - offset < dcidLength) {
      throw InvalidPacketException("Buffer too short for DCID (length $dcidLength)");
    }
    destinationConnectionId = Uint8List.sublistView(rawPacketData, offset, offset + dcidLength);
    offset += dcidLength;

    // Source Connection ID Length (1 byte)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException("Buffer too short for SCID Length");
    }
    int scidLength = byteData.getUint8(offset);
    offset += 1;

    // Source Connection ID (variable length)
    if (rawPacketData.length - offset < scidLength) {
      throw InvalidPacketException("Buffer too short for SCID (length $scidLength)");
    }
    sourceConnectionId = Uint8List.sublistView(rawPacketData, offset, offset + scidLength);
    offset += scidLength;

    // The currentOffset in the ByteBuffer needs to be updated.
    // Since `rawPacketData` is a Uint8List view, we return the new offset
    // so `PacketParser` can manage the main buffer.
    // In Dart, you typically manage offsets explicitly with `Uint8List.sublistView`.
    // I'll adjust PacketParser to pass the remaining buffer.
  }

  @override
  ByteBuffer createBufferForSend(Aead aead, EncryptionLevel encryptionLevel, int largestPacketNumber, Logger logger) {
    throw UnimplementedError('createBufferForSend for LongHeaderPacket not yet implemented');
  }
}