// VersionNegotiationPacket.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import 'quic_packet.dart'; // Import base QuicPacket

class VersionNegotiationPacket extends QuicPacket {
  List<Version> supportedVersions = [];

  VersionNegotiationPacket(Version quicVersion) : super() {
    this.quicVersion = quicVersion;
  }

  @override
  void parseHeader(
    Uint8List rawPacketData,
    int currentOffset,
    int firstByte,
    VersionHolder quicVersionHolder,
  ) {
    // Version Negotiation Packet Header:
    // First byte (fixed bit 1, packet type bits ignored),
    // Version (0x00000000),
    // Destination Connection ID Length, DCID,
    // Source Connection ID Length, SCID.
    // The remainder of the packet is a list of supported versions.

    final ByteData byteData = rawPacketData.buffer.asByteData(
      rawPacketData.offsetInBytes,
    );
    int offset = currentOffset;

    // Version field (4 bytes) - must be 0x00000000 for VN packets.
    if (rawPacketData.length - offset < 4) {
      throw InvalidPacketException(
        "Buffer too short for Version Negotiation Packet Version",
      );
    }
    quicVersion = Version(byteData.getUint32(offset));
    offset += 4;
    quicVersionHolder.version = quicVersion;

    if (quicVersion != Version.QUIC_RESERVED_VERSION) {
      throw InvalidPacketException(
        "Version field in Version Negotiation Packet must be 0x00000000.",
      );
    }

    // Destination Connection ID Length (1 byte)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException("Buffer too short for DCID Length");
    }
    int dcidLength = byteData.getUint8(offset);
    offset += 1;

    // Destination Connection ID (variable length)
    if (rawPacketData.length - offset < dcidLength) {
      throw InvalidPacketException(
        "Buffer too short for DCID (length $dcidLength)",
      );
    }
    destinationConnectionId = Uint8List.sublistView(
      rawPacketData,
      offset,
      offset + dcidLength,
    );
    offset += dcidLength;

    // Source Connection ID Length (1 byte)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException("Buffer too short for SCID Length");
    }
    int scidLength = byteData.getUint8(offset);
    offset += 1;

    // Source Connection ID (variable length)
    if (rawPacketData.length - offset < scidLength) {
      throw InvalidPacketException(
        "Buffer too short for SCID (length $scidLength)",
      );
    }
    sourceConnectionId = Uint8List.sublistView(
      rawPacketData,
      offset,
      offset + scidLength,
    );
    offset += scidLength;

    // The remainder of the packet contains the list of supported versions (multiples of 4 bytes)
    if ((rawPacketData.length - offset) % 4 != 0) {
      throw InvalidPacketException(
        "Version Negotiation Packet payload length is not a multiple of 4.",
      );
    }

    while (rawPacketData.length - offset > 0) {
      supportedVersions.add(Version(byteData.getUint32(offset)));
      offset += 4;
    }
  }

  @override
  ByteBuffer createBufferForSend(
    Aead aead,
    EncryptionLevel encryptionLevel,
    int largestPacketNumber,
    Logger logger,
  ) {
    throw UnimplementedError(
      'createBufferForSend for VersionNegotiationPacket not yet implemented',
    );
  }
}
