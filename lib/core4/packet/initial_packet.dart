// InitialPacket.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import 'long_header_packet.dart'; // Import base LongHeaderPacket

class InitialPacket extends LongHeaderPacket {
  Uint8List? token;
  int? tokenLength;
  late int
  _headerEndOffset; // To mark where the header ends (before PN and payload)

  InitialPacket(Version quicVersion) : super(quicVersion);

  static bool isInitialType(int type, Version version) {
    if (version == Version.QUIC_VERSION_1) {
      return type == LongHeaderPacket.V1_INITIAL_TYPE;
    } else if (version == Version.QUIC_VERSION_2) {
      return type == LongHeaderPacket.V2_INITIAL_TYPE;
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
    // First, parse the common Long Header fields up to SCID using the superclass.
    super.parseHeader(
      rawPacketData,
      currentOffset,
      firstByte,
      quicVersionHolder,
    );

    // After super.parseHeader, the `currentOffset` that the superclass would have
    // advanced is implicitly the end of the SCID. We need to manually calculate it here.
    // We start from the position *after* the initial byte.
    int offset = 1; // Start after the first byte
    offset += 4; // Version
    offset +=
        (rawPacketData.buffer.asByteData(offset, 1).getUint8(0) +
        1); // DCID length + DCID
    offset +=
        (rawPacketData.buffer.asByteData(offset, 1).getUint8(0) +
        1); // SCID length + SCID

    final ByteData byteData = rawPacketData.buffer.asByteData(
      rawPacketData.offsetInBytes,
    );

    // Token Length (Variable-Length Integer)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException(
        "Buffer too short for InitialPacket Token Length (VLI)",
      );
    }
    // Need to create a temporary ByteBuffer view for VariableLengthInteger.decode
    final tempBufferForVLI = rawPacketData.buffer.asByteBuffer(offset);
    tokenLength = VariableLengthInteger.decode(tempBufferForVLI);
    offset =
        rawPacketData.length -
        tempBufferForVLI.remaining; // Update offset based on VLI consumption

    // Token (variable length)
    if (tokenLength! > 0) {
      if (rawPacketData.length - offset < tokenLength!) {
        throw InvalidPacketException(
          "Buffer too short for InitialPacket Token (length $tokenLength)",
        );
      }
      token = Uint8List.sublistView(
        rawPacketData,
        offset,
        offset + tokenLength!,
      );
      offset += tokenLength!;
    }

    // Packet Length (Variable-Length Integer)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException(
        "Buffer too short for InitialPacket Packet Length (VLI)",
      );
    }
    final tempBufferForVLI2 = rawPacketData.buffer.asByteBuffer(offset);
    packetLength = VariableLengthInteger.decode(tempBufferForVLI2);
    offset =
        rawPacketData.length -
        tempBufferForVLI2.remaining; // Update offset based on VLI consumption

    _headerEndOffset =
        offset; // Store the offset where the header ends and PN/payload begin.
  }

  @override
  ByteBuffer createBufferForSend(
    Aead aead,
    EncryptionLevel encryptionLevel,
    int largestPacketNumber,
    Logger logger,
  ) {
    throw UnimplementedError(
      'createBufferForSend for InitialPacket not yet implemented',
    );
  }

  // Helper to get the offset to the packet number and payload for this packet type.
  int getHeaderEndOffset() => _headerEndOffset;
}
