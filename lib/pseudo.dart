import 'dart:math' as math;
import 'dart:typed_data';

int readVarint(Uint8List data) {
  // The length of variable-length integers is encoded in the
  // first two bits of the first byte.
  ByteData bd = ByteData.sublistView(data);
  int offset = 0;
  int v = bd.getUint8(offset);
  final prefix = v >> 6;
  final length = 1 << prefix;

  // Once the length is known, remove these bits and read any
  // remaining bytes.
  v = v & 0x3f;
  for (int i = 0; i < length; i++) {
    offset++;
    v = (v << 8) + bd.getUint8(offset);
  }
  return v;
}

// A.2. Sample Packet Number Encoding Algorithm
// The pseudocode in Figure 46 shows how an implementation can select an appropriate size for packet number encodings.

// The EncodePacketNumber function takes two arguments:

// full_pn is the full packet number of the packet being sent.
// largest_acked is the largest packet number that has been acknowledged by the peer in the current packet number space, if any.
encodePacketNumber(int fullPn, int? largestAcked) {
  int numUnacked;
  // The number of bits must be at least one more
  // than the base-2 logarithm of the number of contiguous
  // unacknowledged packet numbers, including the new packet.
  if (largestAcked == null) {
    numUnacked = fullPn + 1;
  } else {
    numUnacked = fullPn - largestAcked;
  }

  final minBits = math.log(numUnacked) + 1;
  final numBytes = (minBits / 8).toInt().ceil();

  // Encode the integer value and truncate to
  // the num_bytes least significant bytes.

  return encode(fullPn, numBytes);
}

Uint8List encode(int fullPn, int numBytes) {
  final data = Uint8List(numBytes);
  if (numBytes == 4) {
    ByteData.sublistView(data).setUint32(0, fullPn);
  } else if (numBytes == 2) {
    ByteData.sublistView(data).setUint16(0, fullPn);
  } else if (numBytes == 1) {
    ByteData.sublistView(data).setUint8(0, fullPn);
  } else if (numBytes == 3) {
    throw UnimplementedError("legnth encoding of $numBytes is not implemented");
    ByteData.sublistView(data).setUint8(0, fullPn);
  }
  return data;
}

// A.3. Sample Packet Number Decoding Algorithm
// The pseudocode in Figure 47 includes an example algorithm for decoding packet numbers after header protection has been removed.

// The DecodePacketNumber function takes three arguments:

// largest_pn is the largest packet number that has been successfully processed in the current packet number space.
// truncated_pn is the value of the Packet Number field.
// pn_nbits is the number of bits in the Packet Number field (8, 16, 24, or 32).
decodePacketNumber(int largestPn, int truncatedPn, int pnNbits) {
  final expectedPn = largestPn + 1;
  final pnWin = 1 << pnNbits;
  final pnHwin = pnWin / 2;
  final pnMask = pnWin - 1;
  // The incoming packet number should be greater than
  // expected_pn - pn_hwin and less than or equal to
  // expected_pn + pn_hwin
  //
  // This means we cannot just strip the trailing bits from
  // expected_pn and add the truncated_pn because that might
  // yield a value outside the window.
  //
  // The following code calculates a candidate value and
  // makes sure it's within the packet number window.
  // Note the extra checks to prevent overflow and underflow.
  final candidatePn = (expectedPn & ~pnMask) | truncatedPn;
  if (candidatePn <= expectedPn - pnHwin && candidatePn < (1 << 62) - pnWin) {
    return candidatePn + pnWin;
  }
  if (candidatePn > expectedPn + pnHwin && candidatePn >= pnWin) {
    return candidatePn - pnWin;
  }
  return candidatePn;
}
