import 'dart:typed_data';

// From packet.h
const int cxplatVersionSaltLength = 20;
const int quicVersionRetryIntegritySecretLength = 32;

// The HKDF labels are defined as strings in the C file.
class QuicHkdfLabels {
  final String key;
  final String iv;
  final String hp;
  final String ku;

  const QuicHkdfLabels(
      {required this.key,
      required this.iv,
      required this.hp,
      required this.ku});
}

class QuicVersionInfo {
  final int number; // In network byte order.
  final Uint8List salt;
  final Uint8List retryIntegritySecret;
  final QuicHkdfLabels hkdfLabels;

  const QuicVersionInfo({
    required this.number,
    required this.salt,
    required this.retryIntegritySecret,
    required this.hkdfLabels,
  });
}

// The list of supported QUIC versions.
// Converted from the `packet.c` file.
final List<QuicVersionInfo> quicSupportedVersionList = [
  QuicVersionInfo(
    number: 0x00000002, // QUIC_VERSION_2
    salt: Uint8List.fromList([
      0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
      0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
    ]),
    retryIntegritySecret: Uint8List.fromList([
      0x34, 0x25, 0xc2, 0x0c, 0xf8, 0x87, 0x79, 0xdf, 0x2f, 0xf7, 0x1e, 0x8a,
      0xbf, 0xa7, 0x82, 0x49, 0x89, 0x1e, 0x76, 0x3b, 0xbe, 0xd2, 0xf1, 0x3c,
      0x04, 0x83, 0x43, 0xd3, 0x48, 0xc0, 0x60, 0xe2
    ]),
    hkdfLabels: const QuicHkdfLabels(
        key: "quicv2 key", iv: "quicv2 iv", hp: "quicv2 hp", ku: "quicv2 ku"),
  ),
  QuicVersionInfo(
    number: 0x00000001, // QUIC_VERSION_1
    salt: Uint8List.fromList([
      0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    ]),
    retryIntegritySecret: Uint8List.fromList([
      0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21, 0x50, 0x6b,
      0xcc, 0x02, 0x81, 0x4c, 0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce,
      0x87, 0x6e, 0xca, 0x87, 0x6e, 0x6f, 0xca, 0x8e
    ]),
    hkdfLabels: const QuicHkdfLabels(
        key: "quic key", iv: "quic iv", hp: "quic hp", ku: "quic ku"),
  ),
  // QUIC_VERSION_DRAFT_29 and QUIC_VERSION_MS_1 have the same salt and secret.
  QuicVersionInfo(
    number: 0x0000001d, // QUIC_VERSION_DRAFT_29
    salt: Uint8List.fromList([
      0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
      0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    ]),
    retryIntegritySecret: Uint8List.fromList([
      0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2,
      0x07, 0xd8, 0x0d, 0xf2, 0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42,
      0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c
    ]),
    hkdfLabels: const QuicHkdfLabels(
        key: "quic key", iv: "quic iv", hp: "quic hp", ku: "quic ku"),
  ),
  QuicVersionInfo(
    number: 0xfaceb00e, // QUIC_VERSION_MS_1
    salt: Uint8List.fromList([
      0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
      0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    ]),
    retryIntegritySecret: Uint8List.fromList([
      0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2,
      0x07, 0xd8, 0x0d, 0xf2, 0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42,
      0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c
    ]),
    hkdfLabels: const QuicHkdfLabels(
        key: "quic key", iv: "quic iv", hp: "quic hp", ku: "quic ku"),
  ),
];

// Prefixes used in packet logging.
const List<List<String>> packetLogPrefix = [
  ['C', 'S'],
  ['T', 'R'],
];

// Replaces the `QUIC_HEADER_INVARIANT` union with an interface and two classes.
abstract class QuicHeaderInvariant {
  bool get isLongHeader;
  int get variant;
}

class QuicLongHeader implements QuicHeaderInvariant {
  final int variant;
  @override
  final bool isLongHeader = true;
  final int version;
  final int destCidLength;

  const QuicLongHeader({
    required this.variant,
    required this.version,
    required this.destCidLength,
  });
}

class QuicShortHeader implements QuicHeaderInvariant {
  final int variant;
  @override
  final bool isLongHeader = false;

  const QuicShortHeader({required this.variant});
}

const int minInvLongHdrLength = 5;
const int minInvShortHdrLength = 1;

class QuicVersionNegotiationPacket {
  final bool isLongHeader;
  final int unused; // 7 bits
  final int version;
  final int destCidLength;
  // Dynamic arrays for DestCid, SourceCid, and SupportedVersions are not
  // represented directly in a Dart class but would be part of a byte buffer.

  const QuicVersionNegotiationPacket({
    required this.isLongHeader,
    required this.unused,
    required this.version,
    required this.destCidLength,
  });
}

enum QuicLongHeaderTypeV1 {
  initial,
  rtt0Protected,
  handshake,
  retry,
}

enum QuicLongHeaderTypeV2 {
  retry,
  initial,
  rtt0Protected,
  handshake,
}

class QuicLongHeaderV1 {
  final int pnLength; // 2 bits
  final int reserved; // 2 bits
  final int type; // 2 bits
  final int fixedBit; // 1 bit
  final bool isLongHeader; // 1 bit
  final int version;
  final int destCidLength;

  const QuicLongHeaderV1({
    required this.pnLength,
    required this.reserved,
    required this.type,
    required this.fixedBit,
    required this.isLongHeader,
    required this.version,
    required this.destCidLength,
  });
}

const int minLongHeaderLengthV1 = 1 + 4 + 1 + 1 + 4;

class QuicRetryPacketV1 {
  final int unused; // 4 bits
  final int type; // 2 bits
  final int fixedBit; // 1 bit
  final bool isLongHeader; // 1 bit
  final int version;
  final int destCidLength;
  // CIDs, Token, and Integrity Field are variable length.
}

const int minRetryHeaderLengthV1 = 1 + 1;
const int quicRetryIntegrityTagLengthV1 = 16;

class QuicShortHeaderV1 {
  final int pnLength; // 2 bits
  final int keyPhase; // 1 bit
  final int reserved; // 2 bits
  final int spinBit; // 1 bit
  final int fixedBit; // 1 bit
  final bool isLongHeader; // 1 bit
  // DestCid and PacketNumber are variable length.
}

const int minShortHeaderLengthV1 = 1 + 4; // DestCid with max length is not included.

// This is an example of a function signature conversion. The implementation is omitted.
// `BOOLEAN QuicPacketIsHandshake(...)` becomes:
bool quicPacketIsHandshake(QuicHeaderInvariant packet) {
  if (!packet.isLongHeader) {
    return false;
  }
  final longHeader = packet as QuicLongHeader;
  switch (longHeader.version) {
    // Assuming QUIC_VERSION_1, QUIC_VERSION_DRAFT_29, and QUIC_VERSION_MS_1
    // are constants defined elsewhere.
    // The C code has a switch statement, so we replicate the logic.
    // ...
  }
  return true;
}

// Function signature conversion
// `QuicPktNumEncode`
void quicPktNumEncode(
    int packetNumber, int packetNumberLength, Uint8List buffer) {
  // Implementation omitted.
}

// `QuicPktNumDecode`
int quicPktNumDecode(int packetNumberLength, Uint8List buffer) {
  // Implementation omitted.
  return 0;
}

// `QuicPktNumDecompress`
int quicPktNumDecompress(
    int expectedPacketNumber, int compressedPacketNumber, int bytes) {
  // Implementation omitted.
  return 0;
}

// `QuicPacketEncodeLongHeaderV1`
int quicPacketEncodeLongHeaderV1({
  required int version,
  required int packetType,
  required bool fixedBit,
  required Uint8List destCidData,
  required int destCidLength,
  required Uint8List sourceCidData,
  required int sourceCidLength,
  required int tokenLength,
  Uint8List? token,
  required int packetNumber,
  required int bufferLength,
  required Uint8List buffer,
}) {
  // Implementation omitted.
  return 0;
}

// `QuicPacketEncodeShortHeaderV1`
int quicPacketEncodeShortHeaderV1({
  required Uint8List destCidData,
  required int destCidLength,
  required int packetNumber,
  required int packetNumberLength,
  required bool spinBit,
  required bool keyPhase,
  required bool fixedBit,
  required int bufferLength,
  required Uint8List buffer,
}) {
  // Implementation omitted.
  return 0;
}

// Logging functions are replaced with simple print statements or would use a
// dedicated logging framework.
void quicPacketLogDrop(String reason) {
  print("Packet dropped. Reason: $reason");
}