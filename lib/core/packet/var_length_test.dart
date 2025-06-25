// main.dart
import 'dart:typed_data';
import 'var_length.dart'; // Import the VarInt class from its file

/// Helper function to convert a hex string to Uint8List
Uint8List hexToBytes(String hexString) {
  final bytes = <int>[];
  for (int i = 0; i < hexString.length; i += 2) {
    final hexPair = hexString.substring(i, i + 2);
    bytes.add(int.parse(hexPair, radix: 16));
  }
  return Uint8List.fromList(bytes);
}

void main() {
  print('--- VarInt Decoding Examples ---');

  // Example 1: Eight-byte sequence
  String hex1 = 'c2197c5eff14e88c';
  Uint8List bytes1 = hexToBytes(hex1);
  Map<String, int> result1 = VarInt.read(bytes1, 0);
  print('Decoding 0x$hex1:');
  print('  Value: ${result1['value']} (Expected: 151288809941952652)');
  print('  Bytes Read: ${result1['bytesRead']}');
  print('');

  // Example 2: Four-byte sequence
  String hex2 = '9d7f3e7d';
  Uint8List bytes2 = hexToBytes(hex2);
  Map<String, int> result2 = VarInt.read(bytes2, 0);
  print('Decoding 0x$hex2:');
  print('  Value: ${result2['value']} (Expected: 494878333)');
  print('  Bytes Read: ${result2['bytesRead']}');
  print('');

  // Example 3: Two-byte sequence
  String hex3 = '7bbd';
  Uint8List bytes3 = hexToBytes(hex3);
  Map<String, int> result3 = VarInt.read(bytes3, 0);
  print('Decoding 0x$hex3:');
  print('  Value: ${result3['value']} (Expected: 15293)');
  print('  Bytes Read: ${result3['bytesRead']}');
  print('');

  // Example 4: Single byte sequence
  String hex4 = '25';
  Uint8List bytes4 = hexToBytes(hex4);
  Map<String, int> result4 = VarInt.read(bytes4, 0);
  print('Decoding 0x$hex4:');
  print('  Value: ${result4['value']} (Expected: 37)');
  print('  Bytes Read: ${result4['bytesRead']}');
  print('');

  // Example 5: Two-byte sequence that also decodes to 37 (shortest encoding rule)
  String hex5 = '4025';
  Uint8List bytes5 = hexToBytes(hex5);
  Map<String, int> result5 = VarInt.read(bytes5, 0);
  print('Decoding 0x$hex5 (should also be 37):');
  print('  Value: ${result5['value']} (Expected: 37)');
  print('  Bytes Read: ${result5['bytesRead']}');
  print('');

  print('--- VarInt Encoding Examples ---');

  // Example 1: Value that fits in 1 byte
  int val1 = 37;
  Uint8List encoded1 = VarInt.write(val1);
  print(
    'Encoding $val1: 0x${encoded1.map((b) => b.toRadixString(16).padLeft(2, '0')).join()} (Expected: 0x25)',
  );
  print('');

  // Example 2: Value that fits in 2 bytes
  int val2 = 15293;
  Uint8List encoded2 = VarInt.write(val2);
  print(
    'Encoding $val2: 0x${encoded2.map((b) => b.toRadixString(16).padLeft(2, '0')).join()} (Expected: 0x7bbd)',
  );
  print('');

  // Example 3: Value that fits in 4 bytes
  int val3 = 494878333;
  Uint8List encoded3 = VarInt.write(val3);
  print(
    'Encoding $val3: 0x${encoded3.map((b) => b.toRadixString(16).padLeft(2, '0')).join()} (Expected: 0x9d7f3e7d)',
  );
  print('');

  // Example 4: Value that fits in 8 bytes
  int val4 = 151288809941952652;
  Uint8List encoded4 = VarInt.write(val4);
  print(
    'Encoding $val4: 0x${encoded4.map((b) => b.toRadixString(16).padLeft(2, '0')).join()} (Expected: 0xc2197c5eff14e88c)',
  );
  print('');
}
