// QuicPacket.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import '../crypto/crypto.dart'; // Import crypto classes

abstract class QuicPacket {
  static const int MAX_PACKET_SIZE = 1500;

  Version? quicVersion;
  int packetNumber = -1;
  List<QuicFrame> frames = [];
  int packetSize = -1;
  Uint8List? destinationConnectionId;
  bool isProbe = false;

  QuicPacket();

  static int computePacketNumberSize(int packetNumber) {
    if (packetNumber <= 0xff) {
      return 1;
    } else if (packetNumber <= 0xffff) {
      return 2;
    } else if (packetNumber <= 0xffffff) {
      return 3;
    } else {
      return 4;
    }
  }

  static Uint8List encodePacketNumber(int packetNumber) {
    if (packetNumber < 0) {
      throw ArgumentError('Packet number cannot be negative');
    }
    if (packetNumber <= 0xff) {
      return Uint8List.fromList([packetNumber]);
    } else if (packetNumber <= 0xffff) {
      return Uint8List.fromList([
        (packetNumber >> 8) & 0xff,
        packetNumber & 0xff,
      ]);
    } else if (packetNumber <= 0xffffff) {
      return Uint8List.fromList([
        (packetNumber >> 16) & 0xff,
        (packetNumber >> 8) & 0xff,
        packetNumber & 0xff,
      ]);
    } else if (packetNumber <= 0xffffffff) { // Dart int handles 64-bit, so this is equivalent to Java's long for 4 bytes
      return Uint8List.fromList([
        (packetNumber >> 24) & 0xff,
        (packetNumber >> 16) & 0xff,
        (packetNumber >> 8) & 0xff,
        packetNumber & 0xff,
      ]);
    } else {
      throw NotYetImplementedException("Cannot encode packet number > 4 bytes");
    }
  }

  static int decodePacketNumber(Uint8List encodedPn, int largestPacketNumber) {
    // This is a simplified example based on RFC 9000, Section 17.1 "Packet Number Encoding".
    // A full implementation requires more robust handling of the packet number space.
    if (encodedPn.isEmpty || encodedPn.length > 4) {
      throw InvalidPacketException("Invalid encoded packet number length");
    }

    int pn = 0;
    for (int i = 0; i < encodedPn.length; i++) {
      pn = (pn << 8) | encodedPn[i];
    }

    // Adjust candidate PN to be closest to the next expected packet number.
    // This logic is simplified; a full implementation would need to consider a more robust windowing.
    int expectedPn = largestPacketNumber + 1;
    int window = 1 << (encodedPn.length * 8);
    int candidatePn = pn;

    if (candidatePn < expectedPn - window / 2 && expectedPn > window / 2) {
      candidatePn += window;
    } else if (candidatePn > expectedPn + window / 2 && expectedPn < (1 << 62) - window / 2) { // Using 62-bit for reasonable range
      candidatePn -= window;
    }

    return candidatePn;
  }

  /// Updates the given flags byte to encode the packet number length.
  static int encodePacketNumberLength(int flags, int packetNumber) {
    if (packetNumber <= 0xff) {
      return flags;
    } else if (packetNumber <= 0xffff) {
      return (flags | 0x01);
    } else if (packetNumber <= 0xffffff) {
      return (flags | 0x02);
    } else if (packetNumber <= 0xffffffff) {
      return (flags | 0x03);
    } else {
      throw NotYetImplementedException("Cannot encode packet number > 4 bytes");
    }
  }

  // Method to create the header protection mask using the provided AEAD
  Uint8List createHeaderProtectionMask(Uint8List sample, Aead aead) {
    return aead.createHeaderProtectionMask(sample);
  }

  // Method to be overridden by subclasses to update their internal flags
  // after header protection is removed.
  void setUnprotectedHeader(int flags) {
    // Default implementation does nothing; subclasses will use this.
  }

  // Parses the packet number and payload, including header protection and packet protection.
  void parsePacketNumberAndPayload(Uint8List packetBytes, int firstByte, int offsetToPnAndPayload, int payloadLengthIncludingPn,
      Aead aead, Uint8List ppKey, Uint8List ppIv, int largestPacketNumber, Logger log) throws Exception {

    // `packetBytes` is the full raw packet data.
    // `offsetToPnAndPayload` is the index within `packetBytes` where the protected PN and payload start.
    // `payloadLengthIncludingPn` is the total length of protected PN and payload.

    // Header Protection Removal (RFC 9001, Section 5.4.1)
    // Sample 16 bytes from the packet ciphertext starting after the protected fields.
    // Assumed Packet Number length is 4 bytes for sampling.

    int sampleStart = offsetToPnAndPayload + 4; // Assuming 4 bytes for PN for sampling
    if (packetBytes.length - sampleStart < 16) {
      throw InvalidPacketException("Packet too short for header protection sample (16 bytes)");
    }
    Uint8List sample = Uint8List.sublistView(packetBytes, sampleStart, sampleStart + 16);

    Uint8List mask = createHeaderProtectionMask(sample, aead);

    // Apply mask to the first byte's protected bits
    int decryptedFlags;
    if ((firstByte & 0x80) == 0x80) { // Long header: lowest 4 bits of first byte masked
      decryptedFlags = (firstByte ^ (mask[0] & 0x0f));
    } else { // Short header: lowest 5 bits of first byte masked
      decryptedFlags = (firstByte ^ (mask[0] & 0x1f));
    }

    setUnprotectedHeader(decryptedFlags); // Update the packet's internal flags based on decrypted header

    // Determine actual packet number length from decrypted flags (PN length is 2 lowest bits + 1)
    int protectedPacketNumberLength = (decryptedFlags & 0x03) + 1;

    // Extract protected packet number bytes from the original packetBytes
    if (offsetToPnAndPayload + protectedPacketNumberLength > packetBytes.length) {
      throw InvalidPacketException("Buffer underflow for protected packet number after header protection");
    }
    Uint8List protectedPacketNumberBytes = Uint8List.sublistView(packetBytes, offsetToPnAndPayload, offsetToPnAndPayload + protectedPacketNumberLength);

    // Apply mask to packet number bytes
    Uint8List unprotectedPacketNumberBytes = Uint8List(protectedPacketNumberLength);
    for (int i = 0; i < protectedPacketNumberLength; i++) {
      unprotectedPacketNumberBytes[i] = protectedPacketNumberBytes[i] ^ mask[i + 1];
    }

    packetNumber = decodePacketNumber(unprotectedPacketNumberBytes, largestPacketNumber);
    log.debug("Packet number: $packetNumber");

    // The rest is the protected payload (ciphertext + authentication tag).
    // The `payloadLengthIncludingPn` is the length of protected PN + encrypted payload.
    int encryptedPayloadOffset = offsetToPnAndPayload + protectedPacketNumberLength;
    int encryptedPayloadLength = payloadLengthIncludingPn - protectedPacketNumberLength;

    if (encryptedPayloadOffset + encryptedPayloadLength > packetBytes.length) {
      throw InvalidPacketException("Buffer too short for encrypted payload.");
    }

    Uint8List encryptedPayload = Uint8List.sublistView(packetBytes, encryptedPayloadOffset, encryptedPayloadOffset + encryptedPayloadLength);

    // Construct Associated Data (AAD) for AEAD decryption.
    // AAD includes the entire header *before* header protection is applied.
    // This means the initial byte, version (for long header), connection IDs,
    // and the *original, protected* packet number bytes.
    Uint8List associatedData = buildAssociatedData(packetBytes.sublist(0, encryptedPayloadOffset), unprotectedPacketNumberBytes);

    try {
      Uint8List decryptedPayload = aead.decrypt(ppKey, ppIv, encryptedPayload, additionalData: associatedData);
      parseFrames(decryptedPayload); // Parse frames from the decrypted payload

    } on DecryptionException catch (e) {
      log.error("Packet decryption failed: ${e.message}");
      throw e;
    }
  }

  // Placeholder for building associated data for AEAD.
  // `headerBeforePn` is the part of the header *before* the protected packet number bytes.
  // `unprotectedPnBytes` are the bytes of the packet number AFTER header protection is removed.
  Uint8List buildAssociatedData(Uint8List headerBeforePn, Uint8List unprotectedPnBytes) {
    // This is simplified. The AAD in QUIC is the raw bytes of the packet header
    // *before* header protection, concatenated with the *unprotected* (decrypted)
    // packet number bytes.
    // The `headerBeforePn` would contain the initial byte, version, connection IDs,
    // token (for Initial), and length field (for Long Header packets).
    // Then the unprotected packet number bytes are appended.
    final List<int> aadBytes = [];
    aadBytes.addAll(headerBeforePn);
    aadBytes.addAll(unprotectedPnBytes); // These are the bytes that were actually protected for AEAD

    return Uint8List.fromList(aadBytes);
  }


  // Abstract method to parse QUIC frames from the decrypted payload.
  void parseFrames(Uint8List decryptedPayload) {
    // In a real implementation, you would loop through decryptedPayload,
    // parse each frame type, and add to `frames` list.
    if (decryptedPayload.isNotEmpty) {
      // For demonstration, just add a dummy PaddingFrame if there's content.
      frames.add(PaddingFrame()); // Placeholder for actual frame parsing
    }
  }

  // Abstract method to be implemented by subclasses to parse their specific headers
  // Now takes `rawPacketData` and `currentOffset` to allow flexible parsing.
  void parseHeader(Uint8List rawPacketData, int currentOffset, int firstByte, VersionHolder quicVersionHolder);

  // Abstract method to create a buffer for sending this packet.
  ByteBuffer createBufferForSend(Aead aead, EncryptionLevel encryptionLevel, int largestPacketNumber, Logger logger);
}