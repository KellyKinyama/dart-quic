// ShortHeaderPacket.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import 'quic_packet.dart'; // Import base QuicPacket

class ShortHeaderPacket extends QuicPacket {
  int keyPhaseBit = 0; // 0 or 1, extracted from the first byte

  ShortHeaderPacket(Version quicVersion) : super() {
    this.quicVersion = quicVersion;
  }

  // Constructor for creating a packet to send
  ShortHeaderPacket.forSending(
    Version quicVersion,
    Uint8List destinationConnectionId,
    QuicFrame frame,
  ) : super() {
    this.quicVersion = quicVersion;
    this.destinationConnectionId = destinationConnectionId;
    this.frames.add(frame);
  }

  static bool isShortHeaderPacket(int firstByte) {
    return (firstByte & 0x80) == 0x00; // Fixed bit is 0 for short header
  }

  @override
  void parseHeader(
    Uint8List rawPacketData,
    int currentOffset,
    int firstByte,
    VersionHolder quicVersionHolder,
  ) {
    // Short header packets implicitly use the negotiated version for the connection.
    quicVersion = quicVersionHolder.version;

    // Extract the Key Phase (K) bit from the first byte (bit 2, 0-indexed from right)
    // First byte structure: 0 1 S R R K K P P
    // K bit is (firstByte >> 2) & 0x01
    keyPhaseBit = (firstByte >> 2) & 0x01;

    // For short header packets, the Destination Connection ID (DCID) length is not
    // explicitly encoded in the header. It must be known from the connection context.
    // The `PacketParser` is responsible for reading the DCID based on the `cidLength`
    // it was initialized with and setting `destinationConnectionId` on the packet
    // before calling this `parseHeader` method.
    // Therefore, this `parseHeader` method for ShortHeaderPacket assumes `rawPacketData`
    // is already positioned *after* the DCID, and `currentOffset` points to the start of PN.
    if (destinationConnectionId == null) {
      throw StateError(
        "Destination Connection ID must be set for Short Header Packet parsing before parseHeader.",
      );
    }
    // No explicit DCID parsing here; it's handled by PacketParser.
    // `currentOffset` is now at the start of the Packet Number.
  }

  @override
  ByteBuffer createBufferForSend(
    Aead aead,
    EncryptionLevel encryptionLevel,
    int largestPacketNumber,
    Logger logger,
  ) {
    throw UnimplementedError(
      'createBufferForSend for ShortHeaderPacket not yet implemented',
    );
  }
}
