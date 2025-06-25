import 'dart:typed_data';
import 'dart:math';

/// Handles encoding and decoding of QUIC Packet Numbers.
///
/// See RFC 9000, Section 17.1.
///
/// Note: This implementation assumes header protection is already applied/removed
/// for encoding/decoding the raw packet number bytes.
class QuicPacketNumber {
  /// Encodes a packet number into its byte representation.
  ///
  /// The `largestAckedPn` is used to determine the minimum number of bits
  /// required for truncation, according to RFC 9000, Section 17.1.
  ///
  /// Returns a [Uint8List] representing the encoded packet number.
  /// The length of the returned list will be 1, 2, 3, or 4 bytes.
  static Uint8List encode(int packetNumber, int largestAckedPn) {
    if (packetNumber < 0) {
      throw ArgumentError('Packet number must be non-negative.');
    }

    // Calculate the minimum number of bits needed for encoding based on RFC.
    // "size able to represent more than twice as large a range as the difference
    // between the largest acknowledged packet number and the packet number being sent."
    // And "at least one bit more than the base-2 logarithm of the number of contiguous unacknowledged packet numbers"

    int pnDelta = (packetNumber - largestAckedPn).abs();
    int minBitsNeeded;

    if (pnDelta == 0) {
        minBitsNeeded = 1; // Smallest possible number of bits for a single value.
    } else {
        // Logarithm base 2 of 2 * delta. Add 1 for the "at least one bit more" rule.
        minBitsNeeded = (log(2 * pnDelta) / log(2)).ceil() + 1;
    }

    int bytesNeeded;
    if (minBitsNeeded <= 8) {
      bytesNeeded = 1;
    } else if (minBitsNeeded <= 16) {
      bytesNeeded = 2;
    } else if (minBitsNeeded <= 24) {
      bytesNeeded = 3;
    } else {
      bytesNeeded = 4; // Max 4 bytes for PN in header
    }

    // Ensure the packetNumber fits into the chosen number of bytes.
    // If it doesn't, we might need more bytes, but the RFC limits PN in header to 4 bytes.
    // For simplicity, we just mask it to the chosen size.
    int maskedPacketNumber = packetNumber & ((1 << (bytesNeeded * 8)) - 1);

    final buffer = Uint8List(bytesNeeded);
    final byteData = ByteData.view(buffer.buffer);

    switch (bytesNeeded) {
      case 1:
        byteData.setUint8(0, maskedPacketNumber);
        break;
      case 2:
        byteData.setUint16(0, maskedPacketNumber, Endian.big);
        break;
      case 3:
        // No direct setUint24, do it manually
        buffer[0] = (maskedPacketNumber >> 16) & 0xFF;
        buffer[1] = (maskedPacketNumber >> 8) & 0xFF;
        buffer[2] = maskedPacketNumber & 0xFF;
        break;
      case 4:
        byteData.setUint32(0, maskedPacketNumber, Endian.big);
        break;
    }
    return buffer;
  }

  /// Decodes a packet number from its truncated byte representation.
  ///
  /// `encodedPn` is the raw bytes of the encoded packet number (after header protection removal).
  /// `pnLengthBits` is the value from the Packet Number Length field (0-3),
  /// which determines the actual length of `encodedPn` (bytes = `pnLengthBits + 1`).
  /// `largestReceivedPn` is the largest packet number received in a successfully
  /// authenticated packet within the same packet number space.
  ///
  /// Returns the reconstructed full packet number.
  static int decode(Uint8List encodedPn, int pnLengthBits, int largestReceivedPn) {
    final int pnBytes = pnLengthBits + 1;
    if (encodedPn.length < pnBytes) {
      throw ArgumentError('Encoded packet number bytes are shorter than declared length ($pnBytes bytes). Actual: ${encodedPn.length}');
    }

    int receivedPnValue;
    final ByteData byteData = ByteData.view(encodedPn.buffer, encodedPn.offsetInBytes);

    switch (pnBytes) {
      case 1:
        receivedPnValue = byteData.getUint8(0);
        break;
      case 2:
        receivedPnValue = byteData.getUint16(0, Endian.big);
        break;
      case 3:
        // No direct getUint24
        receivedPnValue = (byteData.getUint8(0) << 16) |
                          (byteData.getUint8(1) << 8) |
                          byteData.getUint8(2);
        break;
      case 4:
        receivedPnValue = byteData.getUint32(0, Endian.big);
        break;
      default:
        throw ArgumentError('Invalid packet number length: $pnBytes bytes.');
    }

    // Reconstruction logic from RFC 9000, Appendix A.3
    final int pnWindow = 1 << (pnBytes * 8); // e.g., 256 for 1 byte PN, 65536 for 2 bytes
    final int halfPnWindow = pnWindow ~/ 2;

    // Calculate candidate_pn by masking out the lower bits of largestReceivedPn
    // and combining with the received truncated packet number.
    // `~ (pnWindow - 1)` creates a mask like `...FF00` for 1-byte PN, `...FF0000` for 2-byte PN.
    int candidatePn = (largestReceivedPn & ~(pnWindow - 1)) | receivedPnValue;

    // Adjust candidate_pn to be closest to largestReceivedPn + 1
    // If candidate_pn is too small (meaning it's from the next window after wrapping around)
    if (candidatePn < largestReceivedPn + 1 - halfPnWindow) {
      candidatePn += pnWindow;
    }
    // If candidate_pn is too large (meaning it's from the previous window before wrapping around)
    // The `candidatePn >= pnWindow` part ensures we don't subtract if `candidatePn` itself is very small
    // (e.g., received 0x01, largest_acked 0xFE, window 0x100)
    else if (candidatePn > largestReceivedPn + 1 + halfPnWindow && candidatePn >= pnWindow) {
      candidatePn -= pnWindow;
    }

    return candidatePn;
  }
}