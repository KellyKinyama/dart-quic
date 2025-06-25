import 'dart:typed_data';
import 'quic_variable_length_integer.dart';
import 'quic_packet_number.dart';
import 'quic_long_header_packet2.dart';

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

  // Initial Packet Test
  print('\n--- Testing Initial Packet ---');
  final Uint8List initialDestCid = Uint8List.fromList([
    0x83,
    0x94,
    0xc1,
    0x6e,
    0x3a,
    0x7c,
    0x01,
    0x1a,
  ]);
  final Uint8List initialSrcCid = Uint8List.fromList([
    0x1a,
    0x2b,
    0x3c,
    0x4d,
    0x5e,
    0x6f,
    0x70,
    0x81,
  ]);
  final Uint8List initialPayload = Uint8List.fromList(
    List.generate(30, (i) => i),
  ); // 30 bytes
  final int initialPn = 5;
  final Uint8List initialEncodedPn = QuicPacketNumber.encode(
    initialPn,
    0,
  ); // PN encoded for a client initial
  final int initialPnLengthBits = initialEncodedPn.length - 1;
  final Uint8List initialToken = Uint8List(
    0,
  ); // Server MUST send 0-length token in Initial
  final int initialPacketLength =
      initialEncodedPn.length +
      initialPayload.length; // Length field covers PN + Payload

  final LongHeaderPacket initialPacket = LongHeaderPacket(
    fixedBit: true,
    identifiedType: QuicLongHeaderType.initial,
    isVersionNegotiation: false,
    version: 0x00000001,
    destinationConnectionId: initialDestCid,
    sourceConnectionId: initialSrcCid,
    tokenLength: initialToken.length,
    token: initialToken,
    length: initialPacketLength,
    packetNumberRaw: initialEncodedPn,
    packetPayload: initialPayload,
    reservedBits: 0,
    packetNumberLengthBits: initialPnLengthBits,
    decodedPacketNumber: initialPn,
  );

  final Uint8List serializedInitialPacket = initialPacket.toBytes();
  print(
    '\n--- Serialized Initial Packet (${serializedInitialPacket.length} bytes) ---',
  );
  printBytes(serializedInitialPacket);

  print('\n--- Parsing Serialized Initial Packet ---');
  try {
    final LongHeaderPacket parsedInitialPacket = LongHeaderPacket.parse(
      serializedInitialPacket,
    );
    print(parsedInitialPacket);
    assert(parsedInitialPacket.identifiedType == QuicLongHeaderType.initial);
    assert(parsedInitialPacket.isVersionNegotiation == false);
    assert(parsedInitialPacket.tokenLength == initialToken.length);
    assert(ListEquality().equals(parsedInitialPacket.token, initialToken));
    assert(parsedInitialPacket.length == initialPacketLength);
    assert(parsedInitialPacket.decodedPacketNumber == initialPn);
    assert(
      ListEquality().equals(parsedInitialPacket.packetPayload, initialPayload),
    );
    print('Initial Packet parsing and comparison successful!');
  } catch (e) {
    print('Error parsing Initial packet: $e');
  }

  // 0-RTT Packet Test
  print('\n--- Testing 0-RTT Packet ---');
  final Uint8List zeroRttDestCid = Uint8List.fromList([
    0xaa,
    0xbb,
    0xcc,
    0xdd,
    0xee,
    0xff,
  ]);
  final Uint8List zeroRttSrcCid = Uint8List.fromList([
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
  ]);
  final Uint8List zeroRttPayload = Uint8List.fromList([
    0x01,
    0x02,
    0x03,
    0x04,
  ]); // Small payload
  final int zeroRttPn = 100;
  final Uint8List zeroRttEncodedPn = QuicPacketNumber.encode(
    zeroRttPn,
    0,
  ); // PN encoded
  final int zeroRttPnLengthBits = zeroRttEncodedPn.length - 1;
  final int zeroRttPacketLength =
      zeroRttEncodedPn.length + zeroRttPayload.length;

  final LongHeaderPacket zeroRttPacket = LongHeaderPacket(
    fixedBit: true,
    identifiedType: QuicLongHeaderType.zeroRtt,
    isVersionNegotiation: false,
    version: 0x00000001,
    destinationConnectionId: zeroRttDestCid,
    sourceConnectionId: zeroRttSrcCid,
    length: zeroRttPacketLength,
    packetNumberRaw: zeroRttEncodedPn,
    packetPayload: zeroRttPayload,
    reservedBits: 0,
    packetNumberLengthBits: zeroRttPnLengthBits,
    decodedPacketNumber: zeroRttPn,
  );

  final Uint8List serializedZeroRttPacket = zeroRttPacket.toBytes();
  print(
    '\n--- Serialized 0-RTT Packet (${serializedZeroRttPacket.length} bytes) ---',
  );
  printBytes(serializedZeroRttPacket);

  print('\n--- Parsing Serialized 0-RTT Packet ---');
  try {
    final LongHeaderPacket parsedZeroRttPacket = LongHeaderPacket.parse(
      serializedZeroRttPacket,
    );
    print(parsedZeroRttPacket);
    assert(parsedZeroRttPacket.identifiedType == QuicLongHeaderType.zeroRtt);
    assert(parsedZeroRttPacket.isVersionNegotiation == false);
    assert(parsedZeroRttPacket.token == null); // 0-RTT has no token
    assert(parsedZeroRttPacket.length == zeroRttPacketLength);
    assert(parsedZeroRttPacket.decodedPacketNumber == zeroRttPn);
    assert(
      ListEquality().equals(parsedZeroRttPacket.packetPayload, zeroRttPayload),
    );
    print('0-RTT Packet parsing and comparison successful!');
  } catch (e) {
    print('Error parsing 0-RTT packet: $e');
  }

  // Handshake Packet Test
  print('\n--- Testing Handshake Packet ---');
  final Uint8List handshakeDestCid = Uint8List.fromList([
    0x12,
    0x34,
    0x56,
    0x78,
  ]);
  final Uint8List handshakeSrcCid = Uint8List.fromList([
    0x9a,
    0xbc,
    0xde,
    0xf0,
  ]);
  final Uint8List handshakePayload = Uint8List.fromList([
    0xaa,
    0xbb,
    0xcc,
  ]); // Small payload
  final int handshakePn =
      0; // Handshake packets have their own PN space, often starts at 0
  final Uint8List handshakeEncodedPn = QuicPacketNumber.encode(
    handshakePn,
    -1,
  ); // -1 as largest_acked for new space
  final int handshakePnLengthBits = handshakeEncodedPn.length - 1;
  final int handshakePacketLength =
      handshakeEncodedPn.length + handshakePayload.length;

  final LongHeaderPacket handshakePacket = LongHeaderPacket(
    fixedBit: true,
    identifiedType: QuicLongHeaderType.handshake,
    isVersionNegotiation: false,
    version: 0x00000001,
    destinationConnectionId: handshakeDestCid,
    sourceConnectionId: handshakeSrcCid,
    length: handshakePacketLength,
    packetNumberRaw: handshakeEncodedPn,
    packetPayload: handshakePayload,
    reservedBits: 0,
    packetNumberLengthBits: handshakePnLengthBits,
    decodedPacketNumber: handshakePn,
  );

  final Uint8List serializedHandshakePacket = handshakePacket.toBytes();
  print(
    '\n--- Serialized Handshake Packet (${serializedHandshakePacket.length} bytes) ---',
  );
  printBytes(serializedHandshakePacket);

  print('\n--- Parsing Serialized Handshake Packet ---');
  try {
    final LongHeaderPacket parsedHandshakePacket = LongHeaderPacket.parse(
      serializedHandshakePacket,
    );
    print(parsedHandshakePacket);
    assert(
      parsedHandshakePacket.identifiedType == QuicLongHeaderType.handshake,
    );
    assert(parsedHandshakePacket.isVersionNegotiation == false);
    assert(parsedHandshakePacket.token == null); // Handshake has no token
    assert(parsedHandshakePacket.length == handshakePacketLength);
    assert(parsedHandshakePacket.decodedPacketNumber == handshakePn);
    assert(
      ListEquality().equals(
        parsedHandshakePacket.packetPayload,
        handshakePayload,
      ),
    );
    print('Handshake Packet parsing and comparison successful!');
  } catch (e) {
    print('Error parsing Handshake packet: $e');
  }

  // Retry Packet Test
  print('\n--- Testing Retry Packet ---');
  final Uint8List retryDestCid = Uint8List.fromList([
    0x1a,
    0x2b,
    0x3c,
    0x4d,
    0x5e,
    0x6f,
    0x70,
    0x81,
  ]);
  final Uint8List retrySrcCid = Uint8List.fromList([0x83, 0x94, 0xc1, 0x6e]);
  final Uint8List retryToken = Uint8List.fromList([
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
  ]); // 8-byte token
  final Uint8List retryIntegrityTag = Uint8List.fromList(
    List.generate(16, (i) => i + 0x10),
  ); // 16-byte tag

  final LongHeaderPacket retryPacket = LongHeaderPacket(
    fixedBit: true, // RFC says Fixed Bit = 1 for Retry in Figure 18.
    // Though 17.2.5 says "Unused (4)" and "set to an arbitrary value...SHOULD set ...0x40 to 1".
    // Sticking to Fixed Bit = 1.
    identifiedType: QuicLongHeaderType.retry,
    isVersionNegotiation: false,
    version: 0x00000001,
    destinationConnectionId: retryDestCid,
    sourceConnectionId: retrySrcCid,
    retryToken: retryToken,
    retryIntegrityTag: retryIntegrityTag,
    // No PN, Length, Payload fields for Retry
  );

  final Uint8List serializedRetryPacket = retryPacket.toBytes();
  print(
    '\n--- Serialized Retry Packet (${serializedRetryPacket.length} bytes) ---',
  );
  printBytes(serializedRetryPacket);

  print('\n--- Parsing Serialized Retry Packet ---');
  try {
    final LongHeaderPacket parsedRetryPacket = LongHeaderPacket.parse(
      serializedRetryPacket,
    );
    print(parsedRetryPacket);
    assert(parsedRetryPacket.identifiedType == QuicLongHeaderType.retry);
    assert(parsedRetryPacket.isVersionNegotiation == false);
    assert(parsedRetryPacket.length == null); // Retry has no length field
    assert(parsedRetryPacket.packetNumberRaw == null); // Retry has no PN
    assert(ListEquality().equals(parsedRetryPacket.retryToken, retryToken));
    assert(
      ListEquality().equals(
        parsedRetryPacket.retryIntegrityTag,
        retryIntegrityTag,
      ),
    );
    print('Retry Packet parsing and comparison successful!');
  } catch (e) {
    print('Error parsing Retry packet: $e');
  }

  // Version Negotiation Packet Test (re-run to ensure consistency after updates)
  print(
    '\n--- Testing Version Negotiation Packet (Simplified Encoding/Decoding) ---',
  );
  final int vnVersion = 0x00000000;
  final Uint8List vnDestCid = Uint8List.fromList([0xaa, 0xbb, 0xcc, 0xdd]);
  final Uint8List vnSrcCid = Uint8List.fromList([0xee, 0xff, 0x11, 0x22]);
  final Uint8List supportedVersions = Uint8List.fromList([
    0x00, 0x00, 0x00, 0x01, // v1
    0x00, 0x00, 0x00, 0x02, // v2 (hypothetical)
  ]);

  final LongHeaderPacket vnPacket = LongHeaderPacket(
    fixedBit: false, // Fixed bit is 0 for VN
    identifiedType: QuicLongHeaderType.versionNegotiation,
    isVersionNegotiation: true,
    version: vnVersion,
    destinationConnectionId: vnDestCid,
    sourceConnectionId: vnSrcCid,
    supportedVersions: supportedVersions, // This is the 'payload' for VN
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
    assert(parsedVnPacket.fixedBit == false);
    assert(parsedVnPacket.version == 0x00000000);
    assert(
      ListEquality().equals(parsedVnPacket.destinationConnectionId, vnDestCid),
    );
    assert(ListEquality().equals(parsedVnPacket.sourceConnectionId, vnSrcCid));
    assert(
      ListEquality().equals(
        parsedVnPacket.supportedVersions!,
        supportedVersions,
      ),
    );
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
