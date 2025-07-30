// HandshakePacket.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import 'long_header_packet.dart'; // Import base LongHeaderPacket

class HandshakePacket extends LongHeaderPacket {
  late int _headerEndOffset;

  HandshakePacket(Version quicVersion) : super(quicVersion);

  static bool isHandshake(int type, Version version) {
    if (version == Version.QUIC_VERSION_1) {
      return type == LongHeaderPacket.V1_HANDSHAKE_TYPE;
    } else if (version == Version.QUIC_VERSION_2) {
      return type == LongHeaderPacket.V2_HANDSHAKE_TYPE;
    }
    return false;
  }

  @override
  void parseHeader(
    Uint8List rawPacketData,
    int currentOffset,
    int firstByte,
    VersionHolder quicVersionHolder,
  ) {
    super.parseHeader(
      rawPacketData,
      currentOffset,
      firstByte,
      quicVersionHolder,
    );

    // After super.parseHeader, calculate the current offset explicitly.
    int offset = 1; // After first byte
    offset += 4; // Version
    offset +=
        (rawPacketData.buffer.asByteData(offset, 1).getUint8(0) +
        1); // DCID length + DCID
    offset +=
        (rawPacketData.buffer.asByteData(offset, 1).getUint8(0) +
        1); // SCID length + SCID

    // Packet Length (Variable-Length Integer)
    if (rawPacketData.length - offset < 1) {
      // Length (Variable-Length Integer)
      throw InvalidPacketException(
        "Buffer too short for HandshakePacket Packet Length (VLI)",
      );
    }
    final tempBufferForVLI = rawPacketData.buffer.asByteBuffer(offset);
    packetLength = VariableLengthInteger.decode(tempBufferForVLI);
    offset = rawPacketData.length - tempBufferForVLI.remaining;

    _headerEndOffset = offset;
  }

  @override
  ByteBuffer createBufferForSend(
    Aead aead,
    EncryptionLevel encryptionLevel,
    int largestPacketNumber,
    Logger logger,
  ) {
    throw UnimplementedError(
      'createBufferForSend for HandshakePacket not yet implemented',
    );
  }

  int getHeaderEndOffset() => _headerEndOffset;
}
