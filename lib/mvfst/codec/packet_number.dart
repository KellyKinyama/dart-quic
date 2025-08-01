// Imports are not needed for these basic integer operations.

/// Represents a QUIC packet number.
typedef PacketNum = int;

/// A simple class to hold the result of encoding a packet number.
class PacketNumEncodingResult {
  final PacketNum result;
  // This is the packet number length in bytes.
  final int length;

  const PacketNumEncodingResult({
    required this.result,
    required this.length,
  });

  @override
  String toString() => 'PacketNumEncodingResult(result: $result, length: $length)';
}

/// A helper function to find the index of the most significant bit.
/// Similar to C++ `folly::findLastSet`. Returns 0 for input 0.
int _findLastSet(int n) {
  if (n == 0) return 0;
  int bit = 0;
  while ((1 << bit) <= n) {
    bit++;
  }
  return bit;
}

/// Encodes a packet number based on the largest acknowledged packet number.
PacketNumEncodingResult encodePacketNumber({
  required PacketNum packetNum,
  required PacketNum largestAckedPacketNum,
}) {
  final int twiceDistance = (packetNum - largestAckedPacketNum) * 2;
  // The number of bits we need to mask all set bits in twiceDistance.
  // This is 1 + floor(log2(x)).
  final int lengthInBits = _findLastSet(twiceDistance);
  // Round up to bytes
  final int lengthInBytes = lengthInBits == 0 ? 1 : (lengthInBits + 7) >> 3;

  assert(lengthInBytes <= 4,
      'Impossible to encode PacketNum=$packetNum, largestAcked=$largestAckedPacketNum');
  
  // The original C++ code has a DCHECK_NE(lengthInBytes, 8), but Dart's int
  // is 64-bit, so this logic needs to be adapted.
  // In C++, the mask is a 64-bit int. In Dart, we can just compute it directly.
  
  // `(1 << (lengthInBytes * 8)) - 1` computes a mask of all 1s.
  // E.g., for lengthInBytes=1, it's `(1 << 8) - 1` = 255 (0xFF).
  final int mask = (1 << (lengthInBytes * 8)) - 1;
  
  return PacketNumEncodingResult(
    result: packetNum & mask,
    length: lengthInBytes,
  );
}

/// Decodes a packet number.
PacketNum decodePacketNumber({
  required int encodedPacketNum,
  required int packetNumBytes,
  required PacketNum expectedNextPacketNum,
}) {
  assert(packetNumBytes <= 4);

  final int packetNumBits = 8 * packetNumBytes;
  final int packetNumWin = 1 << packetNumBits;
  final int packetNumHalfWin = packetNumWin >> 1;
  final int mask = packetNumWin - 1;
  
  final int candidate = (expectedNextPacketNum & ~mask) | encodedPacketNum;

  // The C++ `1ULL << 62` is a large 64-bit number. We can use a direct literal
  // or a constant since Dart's `int` is 64-bit.
  const int maxPossiblePacketNum = 1 << 62;

  if (expectedNextPacketNum > packetNumHalfWin &&
      candidate <= expectedNextPacketNum - packetNumHalfWin &&
      candidate < maxPossiblePacketNum - packetNumWin) {
    return candidate + packetNumWin;
  }
  
  if (candidate > expectedNextPacketNum + packetNumHalfWin &&
      candidate >= packetNumWin) {
    return candidate - packetNumWin;
  }
  
  return candidate;
}