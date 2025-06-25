import 'dart:typed_data';
import 'quic_variable_length_integer.dart';
import 'quic_packet_number.dart';
import 'quic_long_header_packet.dart';

void main() {
  // --- Test QuicVariableLengthInteger ---
  print('--- Testing QuicVariableLengthInteger ---');
  testVlq(0, 1);
  testVlq(63, 1); // Max 1-byte
  testVlq(64, 2); // Min 2-byte
  testVlq(16383, 2); // Max 2-byte
  testVlq(16384, 4); // Min 4-byte
  testVlq(1073741823, 4); // Max 4-byte
  testVlq(1073741824, 8); // Min 8-byte
  testVlq(4611686018427387903, 8); // Max 62-bit (QUIC max)

  try {
    QuicVariableLengthInteger.encode(-1);
  } catch (e) {
    print(
      'Encoding negative: ${e.runtimeType}: ${e.toString().split('\n').first}',
    );
  }
  try {
    QuicVariableLengthInteger.encode(4611686018427387904); // Exceeds 62 bits
  } catch (e) {
    print(
      'Encoding too large: ${e.runtimeType}: ${e.toString().split('\n').first}',
    );
  }

  print('\n--- Testing QuicPacketNumber ---');
  testPacketNumberEncodingDecoding(0, 0); // initial
  testPacketNumberEncodingDecoding(1, 0); // after 0
  testPacketNumberEncodingDecoding(
    100,
    90,
  ); // Large jump, pn=100, largest_acked=90
  testPacketNumberEncodingDecoding(
    105,
    100,
  ); // Small delta, pn=105, largest_acked=100
  testPacketNumberEncodingDecoding(256, 0); // force 2 bytes
  testPacketNumberEncodingDecoding(65535, 0); // force 2 bytes
  testPacketNumberEncodingDecoding(65536, 0); // force 3 bytes
  testPacketNumberEncodingDecoding(1000000, 0); // force 3 bytes
  testPacketNumberEncodingDecoding(16777215, 0); // force 3 bytes
  testPacketNumberEncodingDecoding(16777216, 0); // force 4 bytes
  testPacketNumberEncodingDecoding(0xFFFFFFFF, 0); // Max 4-byte PN

  // Simulate a packet arriving out of order (more common scenario for decoding)
  print('\n--- Testing QuicPacketNumber (OOD) ---');
  int largestReceivedPn = 1000;
  Uint8List encodedPnSmall = QuicPacketNumber.encode(
    1005,
    largestReceivedPn,
  ); // Encoded assuming largest is 1000
  int pnLengthBitsSmall = encodedPnSmall.length - 1;
  // Simulate largest_received_pn being higher when this old packet arrives
  int decodedPnOOD1 = QuicPacketNumber.decode(
    encodedPnSmall,
    pnLengthBitsSmall,
    largestReceivedPn + 200,
  );
  print(
    'Encoded PN 1005 from largest 1000: ${encodedPnSmall.map((e) => e.toRadixString(16).padLeft(2, '0')).join()} (Len: ${encodedPnSmall.length})',
  );
  print(
    'Decoded PN 1005 (largest received 1200): $decodedPnOOD1',
  ); // Should recover 1005
  assert(decodedPnOOD1 == 1005, 'PN OOD 1 mismatch');

  largestReceivedPn = 100000;
  Uint8List encodedPnLarge = QuicPacketNumber.encode(100005, largestReceivedPn);
  int pnLengthBitsLarge = encodedPnLarge.length - 1;
  // Simulate largest_received_pn being higher when this old packet arrives
  int decodedPnOOD2 = QuicPacketNumber.decode(
    encodedPnLarge,
    pnLengthBitsLarge,
    largestReceivedPn + 5000,
  );
  print(
    'Encoded PN 100005 from largest 100000: ${encodedPnLarge.map((e) => e.toRadixString(16).padLeft(2, '0')).join()} (Len: ${encodedPnLarge.length})',
  );
  print(
    'Decoded PN 100005 (largest received 105000): $decodedPnOOD2',
  ); // Should recover 100005
  assert(decodedPnOOD2 == 100005, 'PN OOD 2 mismatch');

  // --- Test LongHeaderPacket ---
  print('\n--- Testing LongHeaderPacket (Encoding & Decoding) ---');

  // Example: Initial Packet (common type for Long Header)
  // Header: 1100xxxx
  // First byte: 0xC0 (Header Form: 1, Fixed Bit: 1, Type: Initial)
  // Type-Specific Bits: Reserved (00), PN Length (00) -> 0x00 for 1-byte PN
  // So, first byte = 0xC0 | 0x00 = 0xC0

  final Uint8List destCid = Uint8List.fromList([
    0x83,
    0x94,
    0xc1,
    0x6e,
    0x3a,
    0x7c,
    0x01,
    0x1a,
  ]); // 8 bytes
  final Uint8List srcCid = Uint8List.fromList([
    0x1a,
    0x2b,
    0x3c,
    0x4d,
    0x5e,
    0x6f,
    0x70,
    0x81,
  ]); // 8 bytes
  final Uint8List dummyPayload = Uint8List.fromList(
    List.generate(30, (i) => i),
  ); // 30 bytes of payload
  final int packetNumber = 5; // Example Packet Number

  // Encode the packet number raw bytes
  final Uint8List encodedPacketNumber = QuicPacketNumber.encode(
    packetNumber,
    0,
  ); // largest_acked_pn=0 for initial
  final int pnLengthBits =
      encodedPacketNumber.length - 1; // 0 for 1 byte, 1 for 2 bytes, etc.

  // Calculate the 'Length' field: PN bytes + Payload bytes
  final int totalLength = encodedPacketNumber.length + dummyPayload.length;

  final LongHeaderPacket initialPacket = LongHeaderPacket(
    fixedBit: true,
    identifiedType: QuicLongHeaderType.initial, // Use the new enum
    isVersionNegotiation: false,
    version: 0x00000001, // QUIC Version 1
    destinationConnectionId: destCid,
    sourceConnectionId: srcCid,
    length: totalLength,
    packetNumberRaw: encodedPacketNumber,
    packetPayload: dummyPayload,
    reservedBits:
        0, // Explicitly set for construction (will be part of first byte's typeSpecificBits)
    packetNumberLengthBits: pnLengthBits, // Explicitly set for construction
    decodedPacketNumber:
        packetNumber, // Will be derived during parse, just for internal consistency
  );

  final Uint8List serializedPacket = initialPacket.toBytes();
  print(
    '\n--- Serialized Initial Packet (${serializedPacket.length} bytes) ---',
  );
  printBytes(serializedPacket);

  // --- Parse the serialized packet ---
  print('\n--- Parsing Serialized Packet ---');
  try {
    final LongHeaderPacket parsedPacket = LongHeaderPacket.parse(
      serializedPacket,
    );
    print(parsedPacket);

    // Verify some fields
    print('Verification:');
    print('Parsed Fixed Bit: ${parsedPacket.fixedBit}');
    print('Parsed Identified Type: ${parsedPacket.identifiedType}');
    print('Parsed Version: 0x${parsedPacket.version.toRadixString(16)}');
    print(
      'Parsed Dest CID: ${parsedPacket.destinationConnectionId.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}',
    );
    print(
      'Parsed Src CID: ${parsedPacket.sourceConnectionId.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')}',
    );
    print('Parsed PN Length Bits: ${parsedPacket.packetNumberLengthBits}');
    print(
      'Parsed Raw PN: ${parsedPacket.packetNumberRaw?.map((e) => e.toRadixString(16).padLeft(2, '0')).join(' ')}',
    );
    print('Parsed Decoded PN: ${parsedPacket.decodedPacketNumber}');
    print('Parsed Length: ${parsedPacket.length}');
    print('Parsed Payload Length: ${parsedPacket.packetPayload?.length}');

    assert(parsedPacket.fixedBit == initialPacket.fixedBit);
    assert(parsedPacket.identifiedType == initialPacket.identifiedType);
    assert(parsedPacket.version == initialPacket.version);
    assert(
      ListEquality().equals(
        parsedPacket.destinationConnectionId,
        initialPacket.destinationConnectionId,
      ),
    );
    assert(
      ListEquality().equals(
        parsedPacket.sourceConnectionId,
        initialPacket.sourceConnectionId,
      ),
    );
    assert(parsedPacket.length == initialPacket.length);
    assert(
      ListEquality().equals(
        parsedPacket.packetNumberRaw!,
        initialPacket.packetNumberRaw!,
      ),
    );
    assert(
      ListEquality().equals(
        parsedPacket.packetPayload!,
        initialPacket.packetPayload!,
      ),
    );
    print('Parsing and comparison successful!');
  } catch (e) {
    print('Error parsing packet: $e');
  }

  // --- Testing Version Negotiation Packet ---
  print(
    '\n--- Testing Version Negotiation Packet (Simplified Encoding/Decoding) ---',
  );

  // Version Negotiation has:
  // Header Form (1) = 1 (0x80)
  // Fixed Bit (1) = 0 (no 0x40)
  // Type-Specific Bits (6) = 0 (0x3F) (for VN, these are unused and MUST be 0)
  // So, first byte is 0x80.
  // Version (32) = 0x00000000 (special value)
  // Followed by CIDs, then Supported Versions (32-bit each)

  final int vnVersion = 0x00000000; // Special version for VN
  final Uint8List vnDestCid = Uint8List.fromList([
    0xaa,
    0xbb,
    0xcc,
    0xdd,
  ]); // 4 bytes
  final Uint8List vnSrcCid = Uint8List.fromList([
    0xee,
    0xff,
    0x11,
    0x22,
  ]); // 4 bytes
  final Uint8List supportedVersions = Uint8List.fromList([
    0x00, 0x00, 0x00, 0x01, // QUIC Version 1
    0x00, 0x00, 0x00, 0x02, // QUIC Version 2 (hypothetical)
  ]);

  final LongHeaderPacket vnPacket = LongHeaderPacket(
    fixedBit: false, // Fixed bit is 0 for VN
    identifiedType: QuicLongHeaderType.versionNegotiation,
    isVersionNegotiation: true,
    version: vnVersion,
    destinationConnectionId: vnDestCid,
    sourceConnectionId: vnSrcCid,
    typeSpecificPayload: supportedVersions, // This is the 'payload' for VN
    // No PN, Length, PacketPayload fields for VN
  );

  final Uint8List serializedVnPacket = vnPacket.toBytes();
  print(
    '\n--- Serialized Version Negotiation Packet (${serializedVnPacket.length} bytes) ---',
  );
  printBytes(serializedVnPacket);

  try {
    final LongHeaderPacket parsedVnPacket = LongHeaderPacket.parse(
      serializedVnPacket,
    );
    print(parsedVnPacket);
    assert(parsedVnPacket.isVersionNegotiation == true);
    assert(parsedVnPacket.fixedBit == false); // VN fixed bit is 0
    assert(parsedVnPacket.version == 0x00000000); // VN version is 0
    assert(
      ListEquality().equals(parsedVnPacket.destinationConnectionId, vnDestCid),
    );
    assert(ListEquality().equals(parsedVnPacket.sourceConnectionId, vnSrcCid));
    assert(
      ListEquality().equals(
        parsedVnPacket.typeSpecificPayload!,
        supportedVersions,
      ),
    ); // Check the payload
    print('Parsed VN Packet successfully and verified payload!');
  } catch (e) {
    print('Error parsing VN packet: $e');
  }
}

// Helper to print bytes in hex format
void printBytes(Uint8List bytes) {
  StringBuffer sb = StringBuffer();
  for (int i = 0; i < bytes.length; i++) {
    sb.write(bytes[i].toRadixString(16).padLeft(2, '0'));
    if ((i + 1) % 16 == 0) {
      sb.writeln(); // Newline every 16 bytes
    } else if ((i + 1) % 8 == 0) {
      sb.write('  '); // Double space every 8 bytes
    } else {
      sb.write(' ');
    }
  }
  print(sb.toString().trim());
}

void testVlq(int value, int expectedLength) {
  final encoded = QuicVariableLengthInteger.encode(value);
  final decoded = QuicVariableLengthInteger.decode(encoded);
  print(
    'Value: $value, Encoded: ${encoded.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')} (Len: ${encoded.length}), Decoded: ${decoded.key}, Bytes Consumed: ${decoded.value}',
  );
  assert(
    encoded.length == expectedLength,
    'Length mismatch for $value. Expected $expectedLength, got ${encoded.length}',
  );
  assert(
    decoded.key == value,
    'Value mismatch for $value. Decoded ${decoded.key}',
  );
  assert(
    decoded.value == expectedLength,
    'Bytes consumed mismatch for $value. Expected $expectedLength, got ${decoded.value}',
  );
}

void testPacketNumberEncodingDecoding(int pn, int largestAckedPn) {
  final encoded = QuicPacketNumber.encode(pn, largestAckedPn);
  final pnLengthBits =
      encoded.length - 1; // Simulate getting length from first byte
  final decoded = QuicPacketNumber.decode(
    encoded,
    pnLengthBits,
    largestAckedPn,
  );
  print(
    'PN: $pn, LargestAcked: $largestAckedPn, Encoded: ${encoded.map((e) => e.toRadixString(16).padLeft(2, '0')).join('')} (Len: ${encoded.length}), Decoded: $decoded',
  );
  assert(decoded == pn, 'Packet number mismatch for $pn. Decoded $decoded');
}

// Simple list equality checker for Uint8List
class ListEquality {
  bool equals<T>(List<T>? a, List<T>? b) {
    if (a == b) return true; // Handles both null or same instance
    if (a == null || b == null) return false; // One is null, other isn't
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
