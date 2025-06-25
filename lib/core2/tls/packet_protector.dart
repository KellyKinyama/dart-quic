// lib/src/packet_protector.dart
import 'dart:typed_data';
import 'enums.dart';
import 'key_manager.dart';

class QuicPacketProtector {
  /// Creates the AEAD nonce from IV and packet number. (RFC 9001, Section 5.3)
  Uint8List _createAeadNonce(Uint8List iv, int packetNumber) {
    // Nonce is IV XORed with left-padded packet number (62 bits)
    final pnBytes = Uint8List(iv.length);
    for (int i = 0; i < 8 && i < iv.length; i++) {
      // Packet number is up to 62 bits, so max 8 bytes
      pnBytes[iv.length - 1 - i] = (packetNumber >> (8 * i)).toUnsigned(8);
    }
    return xorBytes(iv, pnBytes);
  }

  /// Generic header protection mask generation based on AEAD type.
  Uint8List _generateHeaderProtectionMask(
    Uint8List hpKey,
    Uint8List sample,
    AEADAlgorithm aead,
  ) {
    if (aead is MockAEADAlgorithm &&
        aead.keyLength == QuicConstants.aes128GcmKeyLength) {
      // Placeholder for AES-ECB (RFC 9001, Section 5.4.3)
      // In a real impl, use a proper AES-ECB function
      return _aesEcbEncrypt(hpKey, sample);
    } else if (aead is MockAEADAlgorithm &&
        aead.keyLength == QuicConstants.chacha20Poly1305KeyLength) {
      // Placeholder for ChaCha20 (RFC 9001, Section 5.4.4)
      final counter = sample.sublist(0, 4);
      final nonce = sample.sublist(4, 16);
      return _chacha20Encrypt(
        hpKey,
        counter,
        nonce,
        Uint8List(5),
      ); // Encrypt 5 zero bytes
    } else {
      throw UnimplementedError('Header protection not defined for AEAD: $aead');
    }
  }

  // --- Placeholder for actual cryptographic operations ---
  // In a real implementation, these would use a secure crypto library.

  // Mock AES-ECB for header protection (NOT SECURE)
  Uint8List _aesEcbEncrypt(Uint8List key, Uint8List data) {
    var output = Uint8List(data.length);
    for (int i = 0; i < data.length; i++) {
      output[i] = data[i] ^ key[i % key.length]; // Simple XOR for demo
    }
    return output;
  }

  // Mock ChaCha20 for header protection (NOT SECURE)
  Uint8List _chacha20Encrypt(
    Uint8List key,
    Uint8List counter,
    Uint8List nonce,
    Uint8List plaintext,
  ) {
    var output = Uint8List(plaintext.length);
    for (int i = 0; i < plaintext.length; i++) {
      output[i] = plaintext[i] ^ key[i % key.length]; // Simple XOR for demo
    }
    return output;
  }
  // --- End Placeholder ---

  /// Protects a QUIC packet.
  /// [rawHeader]: The header bytes before header protection.
  /// [payload]: The packet payload (frames).
  /// [keys]: Packet protection keys for the current encryption level.
  /// [packetNumber]: The full packet number.
  /// [longHeader]: True if it's a long header packet.
  /// [pnOffset]: The offset where the Packet Number field starts in rawHeader.
  /// Returns the protected packet (header + ciphertext).
  Uint8List protect({
    required Uint8List rawHeader,
    required Uint8List payload,
    required QuicPacketProtectionKeys keys,
    required int packetNumber,
    required bool longHeader,
    required int pnOffset, // Start of Packet Number field in rawHeader
    required int pnLength, // Encoded length of Packet Number in header
  }) {
    // 1. AEAD Encryption (RFC 9001, Section 5.3)
    final nonce = _createAeadNonce(keys.iv, packetNumber);
    final associatedData =
        rawHeader; // Full header as AD before header protection
    final ciphertextWithTag = keys.aead.encrypt(
      keys.key,
      nonce,
      associatedData,
      payload,
    );

    final protectedPacket = Uint8List.fromList([
      ...rawHeader,
      ...ciphertextWithTag,
    ]);

    // 2. Header Protection (RFC 9001, Section 5.4)
    // Sample ciphertext for header protection mask
    final int sampleOffset =
        pnOffset +
        QuicConstants.maxPacketNumberLength; // Assumes 4-byte PN for sampling
    if (sampleOffset + QuicConstants.headerProtectionSampleLength >
        protectedPacket.length) {
      // This packet needs to be padded to allow for sampling.
      // In a real implementation, padding frames would be added to the payload
      // before AEAD encryption to meet this requirement.
      // For now, we'll just throw if not enough data.
      throw QuicError(
        QuicConstants.protocolViolation,
        'Packet too short for header protection sample.',
      );
    }
    final sample = protectedPacket.sublist(
      sampleOffset,
      sampleOffset + QuicConstants.headerProtectionSampleLength,
    );

    final mask = _generateHeaderProtectionMask(keys.hpKey, sample, keys.aead);

    // Apply mask to protected header fields
    final maskedHeader = Uint8List.fromList(rawHeader);
    if (longHeader) {
      // Long header: 4 bits masked
      maskedHeader[0] ^= (mask[0] & 0x0F);
    } else {
      // Short header: 5 bits masked (including Key Phase)
      maskedHeader[0] ^= (mask[0] & 0x1F);
    }

    // Mask packet number field
    for (int i = 0; i < pnLength; i++) {
      maskedHeader[pnOffset + i] ^= mask[1 + i];
    }

    // Reconstruct the final packet
    return Uint8List.fromList([...maskedHeader, ...ciphertextWithTag]);
  }

  /// Generic header protection mask generation based on AEAD type.
  Uint8List _generateHeaderProtectionMask(
    Uint8List hpKey,
    Uint8List sample,
    AEADAlgorithm aead,
  ) {
    // RFC 9001, Section 5.4.1. Header Protection Mask
    // Sample is always 16 bytes.
    if (aead is PointyCastleAESGCM) {
      // For AES-GCM (used by Initial), use AES-ECB
      // The sample is the input to AES-ECB
      // The mask is the first 5 bytes of the AES-ECB output.
      return aesEcbEncrypt(
        hpKey,
        sample,
      ); // This now calls the pointycastle based fn
    } else if (aead is PointyCastleChaCha20Poly1305) {
      // For ChaCha20-Poly1305, use ChaCha20
      // The sample is used to derive counter and nonce for ChaCha20
      final counter = sample.sublist(0, 4);
      final nonce = sample.sublist(4, 16);
      // ChaCha20 encrypts 5 zero bytes to produce the mask.
      return chacha20Encrypt(
        hpKey,
        counter,
        nonce,
        Uint8List(5),
      ); // This now calls the pointycastle based fn
    } else {
      throw UnimplementedError(
        'Header protection not defined for AEAD: ${aead.runtimeType}',
      );
    }
  }

  /// Unprotects a QUIC packet.
  /// [packetData]: The raw incoming packet bytes.
  /// [keys]: Packet protection keys for the expected encryption level.
  /// [isLongHeader]: True if the packet is a long header packet.
  /// [headerLength]: The length of the entire header *before* payload.
  /// [pnOffset]: The offset where the Packet Number field is expected to start in the header.
  /// [truncatedPacketNumber]: The truncated packet number from the received packet.
  /// [expectedPnLength]: The expected encoded length of the packet number.
  /// Returns the unprotected payload (frames) and the full packet number, or null if decryption fails.
  Map<String, dynamic>? unprotect({
    required Uint8List packetData,
    required QuicPacketProtectionKeys keys,
    required bool isLongHeader,
    required int headerLength, // Header length including masked PN
    required int pnOffset, // Offset of the PN field in the header
  }) {
    // 1. Remove Header Protection (RFC 9001, Section 5.4)
    final maskedHeader = packetData.sublist(0, headerLength);
    final ciphertextWithTag = packetData.sublist(headerLength);

    final int sampleOffset =
        pnOffset +
        QuicConstants.maxPacketNumberLength; // Assumes 4-byte PN for sampling
    if (sampleOffset + QuicConstants.headerProtectionSampleLength >
        packetData.length) {
      // Packet too short for header protection sample
      return null; // Discard (RFC 9001, Section 5.4.2)
    }
    final sample = packetData.sublist(
      sampleOffset,
      sampleOffset + QuicConstants.headerProtectionSampleLength,
    );

    final mask = _generateHeaderProtectionMask(keys.hpKey, sample, keys.aead);

    final unmaskedHeader = Uint8List.fromList(maskedHeader);
    if (isLongHeader) {
      unmaskedHeader[0] ^= (mask[0] & 0x0F);
    } else {
      unmaskedHeader[0] ^= (mask[0] & 0x1F);
    }

    // Determine pn_length from unmasked header byte
    final int pnLength =
        (unmaskedHeader[0] & 0x03) +
        1; // Assuming pn_length bits are LSBs (bits 0 and 1)

    // Re-mask to extract packet number
    for (int i = 0; i < pnLength; i++) {
      unmaskedHeader[pnOffset + i] ^= mask[1 + i];
    }

    // Extract truncated packet number
    int truncatedPacketNumber = 0;
    for (int i = 0; i < pnLength; i++) {
      truncatedPacketNumber =
          (truncatedPacketNumber << 8) | unmaskedHeader[pnOffset + i];
    }

    // Placeholder: Reconstruct full packet number from truncated (requires connection context)
    // In a real implementation, this involves tracking largest received PN for the PN space.
    final int fullPacketNumber = _reconstructPacketNumber(
      truncatedPacketNumber,
      pnLength,
    ); // Placeholder

    // 2. AEAD Decryption (RFC 9001, Section 5.3)
    final nonce = _createAeadNonce(keys.iv, fullPacketNumber);
    // Associated Data is the header *after* header protection removed, but *before* AEAD decrypt
    // This is the header that was used as AD during encryption, so it includes the unmasked PN
    final associatedData = unmaskedHeader;

    final decryptedPayload = keys.aead.decrypt(
      keys.key,
      nonce,
      associatedData,
      ciphertextWithTag,
    );

    if (decryptedPayload == null) {
      // AEAD decryption or tag verification failed.
      return null; // Discard packet.
    }

    return {
      'payload': decryptedPayload,
      'packet_number': fullPacketNumber,
      'unmasked_header': unmaskedHeader,
      'pn_length': pnLength,
    };
  }

  // Placeholder for reconstructing full packet number (RFC 9000, Section 17.1)
  // This needs the largest received packet number for the current PN space
  int _reconstructPacketNumber(int truncatedPn, int pnLength) {
    // This is a simplified stub. A real implementation is more complex.
    // It involves comparing `truncatedPn` to `largest_received_pn` and selecting the candidate `full_pn`
    // that is closest to `largest_received_pn`.
    final int pnBitLength = pnLength * 8;
    final int candidatePn = truncatedPn; // Simplistic
    return candidatePn;
  }

  /// Validates the Retry Integrity Tag. (RFC 9001, Section 5.8)
  /// [retryPacket]: The full received Retry packet.
  /// [originalDcId]: The Destination Connection ID from the client's Initial packet
  ///                 that this Retry packet is a response to.
  /// Returns true if the tag is valid, false otherwise.
  bool validateRetryIntegrity(Uint8List retryPacket, Uint8List originalDcId) {
    final int tagLength = aes128Gcm.tagLength;
    if (retryPacket.length < tagLength) return false;

    final Uint8List receivedTag = retryPacket.sublist(
      retryPacket.length - tagLength,
    );
    final Uint8List retryPseudoPacket = _buildRetryPseudoPacket(
      retryPacket.sublist(0, retryPacket.length - tagLength),
      originalDcId,
    );

    // Fixed key and nonce for Retry integrity
    final Uint8List key = Uint8List.fromList(QuicConstants.retryKey);
    final Uint8List nonce = Uint8List.fromList(QuicConstants.retryNonce);

    // Plaintext for AEAD is empty for Retry tag calculation
    final Uint8List emptyPlaintext = Uint8List(0);

    // Encrypt to get the expected tag
    final Uint8List expectedCiphertextWithTag = aes128Gcm.encrypt(
      key,
      nonce,
      retryPseudoPacket,
      emptyPlaintext,
    );
    final Uint8List expectedTag = expectedCiphertextWithTag.sublist(
      expectedCiphertextWithTag.length - tagLength,
    );

    return listEquals(receivedTag, expectedTag);
  }

  /// Builds the Retry Pseudo-Packet for integrity calculation. (RFC 9001, Section 5.8, Figure 8)
  Uint8List _buildRetryPseudoPacket(
    Uint8List retryPacketWithoutTag,
    Uint8List originalDcId,
  ) {
    final builder = BytesBuilder();
    builder.addByte(originalDcId.length); // ODCID Length
    builder.add(originalDcId); // Original Destination Connection ID
    builder.add(retryPacketWithoutTag); // Remaining Retry Packet fields
    return builder.takeBytes();
  }

  bool listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

// lib/src/utils.dart (Helper for XOR operation)
Uint8List xorBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    throw ArgumentError(
      'Input Uint8Lists must have the same length for XOR operation.',
    );
  }
  final result = Uint8List(a.length);
  for (int i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}
