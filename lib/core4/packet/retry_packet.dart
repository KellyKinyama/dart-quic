// RetryPacket.dart (UPDATED)
import 'dart:typed_data';
import 'dart:convert'; // For utf8 encoding of "QUIC"
import 'auxiliary.dart'; // Import auxiliary classes
import 'quic_packet.dart'; // Import base QuicPacket
import '../crypto/crypto.dart'; // Import actual AEAD implementations

class RetryPacket extends QuicPacket {
  static const int V1_TYPE = 0x03; // Type bits 11
  static const int V2_TYPE = 0x00; // Type bits 00

  static const int RETRY_INTEGRITY_TAG_LENGTH = 16;

  // Secret keys for Retry Integrity Tag calculation (from RFCs)
  static final Uint8List SECRET_KEY_V1 = Uint8List.fromList([
    0xbe,
    0x0c,
    0x69,
    0x0b,
    0x9f,
    0x66,
    0x57,
    0x5a,
    0x1d,
    0x76,
    0x6b,
    0x54,
    0xe3,
    0x68,
    0xc8,
    0x4e,
  ]);
  static final Uint8List SECRET_KEY_V2 = Uint8List.fromList([
    0xcc,
    0xce,
    0x18,
    0x7e,
    0xd0,
    0x9a,
    0x09,
    0xd0,
    0x57,
    0x28,
    0x15,
    0x5a,
    0x6c,
    0xb9,
    0x6b,
    0xe1,
  ]);

  Uint8List?
  originalDestinationConnectionId; // This is the SCID in the Retry Packet, but is the ODID
  Uint8List? retryToken;
  Uint8List? retryIntegrityTag;
  int? firstByteRaw; // Store the original first byte for AAD calculation

  RetryPacket(Version quicVersion) : super() {
    this.quicVersion = quicVersion;
  }

  static bool isRetry(int type, Version version) {
    if (version == Version.QUIC_VERSION_1) {
      return type == V1_TYPE;
    } else if (version == Version.QUIC_VERSION_2) {
      return type == V2_TYPE;
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
    firstByteRaw = firstByte; // Store for integrity tag calculation

    final ByteData byteData = rawPacketData.buffer.asByteData(
      rawPacketData.offsetInBytes,
    );
    int offset = currentOffset;

    // Version field (4 bytes) - must be 0x00000000 for VN packets.
    if (rawPacketData.length - offset < 4) {
      throw InvalidPacketException("Buffer too short for Retry Packet Version");
    }
    quicVersion = Version(byteData.getUint32(offset));
    offset += 4;
    quicVersionHolder.version = quicVersion;

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
    // For Retry packets, this is the Original Destination Connection ID (ODCID)
    if (rawPacketData.length - offset < 1) {
      throw InvalidPacketException("Buffer too short for SCID (ODCID) Length");
    }
    int scidLength = byteData.getUint8(offset);
    offset += 1;

    // Original Destination Connection ID (variable length)
    if (rawPacketData.length - offset < scidLength) {
      throw InvalidPacketException(
        "Buffer too short for SCID (ODCID) (length $scidLength)",
      );
    }
    originalDestinationConnectionId = Uint8List.sublistView(
      rawPacketData,
      offset,
      offset + scidLength,
    );
    offset += scidLength;

    // The rest of the packet is the Retry Token followed by the Retry Integrity Tag.
    // The Retry Integrity Tag is fixed at 16 bytes.
    if (rawPacketData.length - offset < RETRY_INTEGRITY_TAG_LENGTH) {
      throw InvalidPacketException("Buffer too short for Retry Integrity Tag");
    }

    int tokenLength =
        (rawPacketData.length - offset) - RETRY_INTEGRITY_TAG_LENGTH;
    if (tokenLength < 0) {
      throw InvalidPacketException(
        "Invalid Retry Packet length: token length negative",
      );
    }

    retryToken = Uint8List.sublistView(
      rawPacketData,
      offset,
      offset + tokenLength,
    );
    offset += tokenLength;

    retryIntegrityTag = Uint8List.sublistView(
      rawPacketData,
      offset,
      offset + RETRY_INTEGRITY_TAG_LENGTH,
    );
    offset += RETRY_INTEGRITY_TAG_LENGTH;

    // Validate the Retry Integrity Tag
    // The AAD for the Retry Integrity Tag is the original packet (excluding the tag)
    // prefixed by the string "QUIC" (in ASCII).
    // Reconstructing this requires access to the original raw bytes of the header and token.
    Uint8List pseudoPacket = _buildRetryPseudoPacket(
      rawPacketData.sublist(0, offset),
      firstByte,
    );
    Uint8List expectedTag = _calculateRetryIntegrityTag(
      pseudoPacket,
      quicVersion!,
    );

    if (!listEquals(retryIntegrityTag!, expectedTag)) {
      throw InvalidPacketException("Retry Integrity Tag validation failed");
    }
  }

  // Reconstructs the pseudo-packet for Retry Integrity Tag calculation.
  // `packetBytesUpToTag` is the raw bytes of the packet from start up to (but not including) the tag.
  Uint8List _buildRetryPseudoPacket(
    Uint8List packetBytesUpToTag,
    int initialByte,
  ) {
    // This must precisely match the bytes that were fed into the AEAD for tag generation.
    // It's "QUIC" (ASCII) + the entire Retry packet header and token, excluding the tag itself.
    final List<int> pseudoPacketBytes = [];
    pseudoPacketBytes.addAll(utf8.encode("QUIC")); // Prefix "QUIC"
    pseudoPacketBytes.addAll(packetBytesUpToTag);

    return Uint8List.fromList(pseudoPacketBytes);
  }

  // Calculates the expected Retry Integrity Tag.
  Uint8List _calculateRetryIntegrityTag(
    Uint8List pseudoPacket,
    Version version,
  ) {
    Uint8List key = (version == Version.QUIC_VERSION_1)
        ? SECRET_KEY_V1
        : SECRET_KEY_V2;
    Uint8List iv = Uint8List(12); // All zeros IV as per RFC 9001, Section 5.8
    Aead aead =
        Aes128Gcm(); // Use AES-128-GCM for Retry integrity tag (as per RFC)

    // The AEAD encryption function is used with empty plaintext and `pseudoPacket` as AAD
    // to generate the authentication tag.
    return aead.encrypt(key, iv, Uint8List(0), additionalData: pseudoPacket);
  }

  @override
  ByteBuffer createBufferForSend(
    Aead aead,
    EncryptionLevel encryptionLevel,
    int largestPacketNumber,
    Logger logger,
  ) {
    throw UnimplementedError(
      'createBufferForSend for RetryPacket not yet implemented',
    );
  }
}
