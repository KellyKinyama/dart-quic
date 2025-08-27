// package protocol

// A PacketNumber in QUIC
typedef PacketNumber = int;

// InvalidPacketNumber is a packet number that is never sent.
// In QUIC, 0 is a valid packet number.
const PacketNumber InvalidPacketNumber = -1;

// PacketNumberLen is the length of the packet number in bytes
typedef PacketNumberLen = int;

// const (
// PacketNumberLen1 is a packet number length of 1 byte
const PacketNumberLen PacketNumberLen1 = 1;
// PacketNumberLen2 is a packet number length of 2 bytes
const PacketNumberLen PacketNumberLen2 = 2;
// PacketNumberLen3 is a packet number length of 3 bytes
const PacketNumberLen PacketNumberLen3 = 3;
// PacketNumberLen4 is a packet number length of 4 bytes
const PacketNumberLen PacketNumberLen4 = 4;
// )

// // DecodePacketNumber calculates the packet number based its length and the last seen packet number
// // This function is taken from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3.
PacketNumber decodePacketNumber(
  PacketNumberLen length,
  PacketNumber largest,
  PacketNumber truncated,
) {
  PacketNumber expected = largest + 1;
  PacketNumber win = (1 << (length * 8));
  final hwin = win / 2;
  final mask = win - 1;

  int xorMask = mask;
  xorMask = xorMask ^ mask;
  final candidate = (expected & xorMask) | truncated;
  if (candidate <= expected - hwin && candidate < 1 << 62 - win) {
    return candidate + win;
  }
  if (candidate > expected + hwin && candidate >= win) {
    return candidate - win;
  }
  return candidate;
}

// PacketNumberLengthForHeader gets the length of the packet number for the header
// it never chooses a PacketNumberLen of 1 byte, since this is too short under certain circumstances
PacketNumberLen packetNumberLengthForHeader(
  PacketNumber pn,
  PacketNumber largestAcked,
) {
  PacketNumber numUnacked;
  if (largestAcked == InvalidPacketNumber) {
    numUnacked = pn + 1;
  } else {
    numUnacked = pn - largestAcked;
  }
  if (numUnacked < 1 << (16 - 1)) {
    return PacketNumberLen2;
  }
  if (numUnacked < 1 << (24 - 1)) {
    return PacketNumberLen3;
  }
  return PacketNumberLen4;
}
