// main.dart (add to existing main.dart)
// ... existing imports ...
import 'dart:typed_data';

import 'quic_transport_parameters.dart'; // New import

import 'quic_variable_length_integer.dart';

import 'quic_packet_number.dart';

// Add a simple ListEquality helper if not already present
class ListEquality {
  bool equals<T>(List<T>? a, List<T>? b) {
    if (a == b) return true;
    if (a == null || b == null) return false;
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

// ... main function ...
void main() {
  // ... (previous test calls) ...

  // --- Test Transport Parameters ---
  print('\n--- Testing QUIC Transport Parameters ---');

  // Test Case 1: Integer parameters
  print('\n--- Test Case 1: Integer Parameters ---');
  final QuicTransportParameters tp1 = QuicTransportParameters();
  tp1.setInteger(QuicTransportParameterId.maxIdleTimeout, 30000); // 30 seconds
  tp1.setInteger(QuicTransportParameterId.initialMaxData, 1048576); // 1 MB
  tp1.setInteger(QuicTransportParameterId.maxUdpPayloadSize, 1500); // MTU
  tp1.setInteger(QuicTransportParameterId.activeConnectionIdLimit, 10);
  tp1.setInteger(QuicTransportParameterId.maxAckDelay, 100); // 100ms

  final Uint8List serializedTp1 = tp1.toBytes();
  print('\nSerialized TP1 (${serializedTp1.length} bytes):');
  printBytes(serializedTp1);

  final QuicTransportParameters parsedTp1 = QuicTransportParameters.parse(
    serializedTp1,
  );
  print('\nParsed TP1:');
  print(parsedTp1);

  assert(
    parsedTp1.getInteger(QuicTransportParameterId.maxIdleTimeout) == 30000,
    'TP1 maxIdleTimeout mismatch',
  );
  assert(
    parsedTp1.getInteger(QuicTransportParameterId.initialMaxData) == 1048576,
    'TP1 initialMaxData mismatch',
  );
  assert(
    parsedTp1.getInteger(QuicTransportParameterId.maxUdpPayloadSize) == 1500,
    'TP1 maxUdpPayloadSize mismatch',
  );
  assert(
    parsedTp1.getInteger(QuicTransportParameterId.activeConnectionIdLimit) ==
        10,
    'TP1 activeConnectionIdLimit mismatch',
  );
  assert(
    parsedTp1.getInteger(QuicTransportParameterId.maxAckDelay) == 100,
    'TP1 maxAckDelay mismatch',
  );
  print('Test Case 1 (Integer Parameters) successful!');

  // Test Case 2: Fixed-length and Zero-length parameters
  print('\n--- Test Case 2: Fixed-length and Zero-length Parameters ---');
  final QuicTransportParameters tp2 = QuicTransportParameters();
  final Uint8List srt = Uint8List.fromList(
    List.generate(16, (i) => i + 100),
  ); // Sample 16-byte token
  tp2.setBytes(QuicTransportParameterId.statelessResetToken, srt);
  tp2.setDisableActiveMigration(); // Zero-length parameter

  final Uint8List serializedTp2 = tp2.toBytes();
  print('\nSerialized TP2 (${serializedTp2.length} bytes):');
  printBytes(serializedTp2);

  final QuicTransportParameters parsedTp2 = QuicTransportParameters.parse(
    serializedTp2,
  );
  print('\nParsed TP2:');
  print(parsedTp2);

  assert(
    ListEquality().equals(
      parsedTp2.getBytes(QuicTransportParameterId.statelessResetToken),
      srt,
    ),
    'TP2 statelessResetToken mismatch',
  );
  assert(
    parsedTp2.isDisableActiveMigration,
    'TP2 disableActiveMigration mismatch',
  );
  assert(
    parsedTp2
        .getBytes(QuicTransportParameterId.disableActiveMigration)!
        .isEmpty,
    'TP2 disableActiveMigration length mismatch',
  );
  print('Test Case 2 (Fixed/Zero-length Parameters) successful!');

  // Test Case 3: Preferred Address
  print('\n--- Test Case 3: Preferred Address Parameter ---');
  final PreferredAddress prefAddr = PreferredAddress(
    ipv4Address: Uint8List.fromList([192, 0, 2, 1]),
    ipv4Port: 4433,
    ipv6Address: Uint8List.fromList([
      0x20,
      0x01,
      0xdb,
      0x80,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
    ]),
    ipv6Port: 8080,
    connectionId: Uint8List.fromList([
      0x12,
      0x34,
      0x56,
      0x78,
      0x90,
    ]), // 5-byte CID
    statelessResetToken: Uint8List.fromList(List.generate(16, (i) => i + 0xaa)),
  );

  final QuicTransportParameters tp3 = QuicTransportParameters();
  tp3.setPreferredAddress(prefAddr);

  final Uint8List serializedTp3 = tp3.toBytes();
  print('\nSerialized TP3 (${serializedTp3.length} bytes):');
  printBytes(serializedTp3);

  final QuicTransportParameters parsedTp3 = QuicTransportParameters.parse(
    serializedTp3,
  );
  print('\nParsed TP3:');
  print(parsedTp3);

  final PreferredAddress? parsedPrefAddr = parsedTp3.getPreferredAddress();
  assert(parsedPrefAddr != null, 'TP3 PreferredAddress is null');
  assert(
    ListEquality().equals(parsedPrefAddr!.ipv4Address, prefAddr.ipv4Address),
    'TP3 PA IPv4 mismatch',
  );
  assert(
    parsedPrefAddr!.ipv4Port == prefAddr.ipv4Port,
    'TP3 PA IPv4 port mismatch',
  );
  assert(
    ListEquality().equals(parsedPrefAddr!.ipv6Address, prefAddr.ipv6Address),
    'TP3 PA IPv6 mismatch',
  );
  assert(
    parsedPrefAddr!.ipv6Port == prefAddr.ipv6Port,
    'TP3 PA IPv6 port mismatch',
  );
  assert(
    ListEquality().equals(parsedPrefAddr!.connectionId, prefAddr.connectionId),
    'TP3 PA Conn ID mismatch',
  );
  assert(
    ListEquality().equals(
      parsedPrefAddr!.statelessResetToken,
      prefAddr.statelessResetToken,
    ),
    'TP3 PA SRT mismatch',
  );
  print('Test Case 3 (Preferred Address) successful!');

  // Test Case 4: Mixed parameters including a reserved one
  print('\n--- Test Case 4: Mixed Parameters with Reserved ---');
  final QuicTransportParameters tp4 = QuicTransportParameters();
  tp4.setInteger(QuicTransportParameterId.initialMaxStreamsBidi, 100);
  tp4.setInteger(QuicTransportParameterId.ackDelayExponent, 5); // Default is 3
  // Add a reserved parameter: 31 * N + 27. Let N=1, so ID = 31+27 = 58 (0x3A)
  // tp4.setBytes(
  //   QuicTransportParameterId.fromValue(0x3A),
  //   Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]),
  // );

  final Uint8List serializedTp4 = tp4.toBytes();
  print('\nSerialized TP4 (${serializedTp4.length} bytes):');
  printBytes(serializedTp4);

  final QuicTransportParameters parsedTp4 = QuicTransportParameters.parse(
    serializedTp4,
  );
  print('\nParsed TP4:');
  print(parsedTp4);

  assert(
    parsedTp4.getInteger(QuicTransportParameterId.initialMaxStreamsBidi) == 100,
    'TP4 initialMaxStreamsBidi mismatch',
  );
  assert(
    parsedTp4.getInteger(QuicTransportParameterId.ackDelayExponent) == 5,
    'TP4 ackDelayExponent mismatch',
  );
  // Check that the reserved parameter was captured in _unknownParameters map
  assert(
    parsedTp4.unknownParameters.containsKey(0x3A),
    'TP4 should contain reserved parameter 0x3A',
  );
  assert(
    ListEquality().equals(
      parsedTp4.unknownParameters[0x3A],
      Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]),
    ),
    'TP4 reserved parameter value mismatch',
  );
  print('Test Case 4 (Mixed & Reserved Parameters) successful!');

  // Test Case 5: Parsing invalid PreferredAddress
  print('\n--- Test Case 5: Parsing Invalid PreferredAddress ---');
  // Manually craft a malformed preferred_address transport parameter value.
  // The structure is ID (VLQ) + Length (VLQ) + Value (bytes)
  // preferred_address ID is 0x0d.

  final List<int> malformedTpBytes = [];
  // Add Preferred Address ID (0x0d)
  malformedTpBytes.addAll(
    QuicVariableLengthInteger.encode(
      QuicTransportParameterId.preferredAddress.value,
    ),
  );

  // Add a LENGTH for the malformed value. Let's make it seem like there are more bytes than there actually are,
  // or too few for a valid PreferredAddress structure.
  // A valid PreferredAddress is min 42 bytes. Let's send less.
  final Uint8List malformedPrefAddrValue = Uint8List.fromList([
    0x00, 0x00, 0x00, 0x01, // IPv4 (4)
    0x11, 0x22, // IPv4 Port (2)
    // Intentionally incomplete data to simulate malformed packet
    // This value is only 6 bytes, much less than the required 42.
  ]);
  malformedTpBytes.addAll(
    QuicVariableLengthInteger.encode(malformedPrefAddrValue.length),
  ); // Length of the malformed value
  malformedTpBytes.addAll(malformedPrefAddrValue); // The malformed value itself

  final Uint8List rawMalformedTp = Uint8List.fromList(malformedTpBytes);

  print(
    '\nRaw Malformed TP for PreferredAddress (${rawMalformedTp.length} bytes):',
  );
  printBytes(rawMalformedTp);

  try {
    // Parse the entire transport parameters sequence containing the malformed preferred_address
    final QuicTransportParameters parsedTp5 = QuicTransportParameters.parse(
      rawMalformedTp,
    );
    print('\nParsed TP5:');
    print(
      parsedTp5,
    ); // This will show the raw malformed value if it was successfully read by parse()

    // Now, attempt to get the PreferredAddress object, which should trigger the parsing error inside getPreferredAddress()
    final PreferredAddress? invalidPrefAddr = parsedTp5.getPreferredAddress();
    print(
      'Attempted to parse invalid PreferredAddress from TP: $invalidPrefAddr',
    );

    assert(
      invalidPrefAddr == null,
      'Invalid PreferredAddress should result in null from getter',
    );
    print(
      'Test Case 5 (Parsing Invalid PreferredAddress) successful (getter returned null as expected)!',
    );
  } catch (e) {
    // Note: QuicTransportParameters.parse() might throw if the overall structure (ID, Length) is messed up.
    // PreferredAddress.parse() (called by getPreferredAddress) throws if its *value* is malformed.
    print('Test Case 5: Unexpected exception caught: $e');
    assert(
      false,
      'Expected graceful handling by returning null, not an exception during parsing of the value.',
    );
  }
}

// ... (existing helper functions like printBytes, testVlq, testPacketNumberEncodingDecoding) ...
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
