// Filename: lib/aes_test_alt.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:collection/collection.dart'; // Required for ListEquality

Future<void> main() async {
  print('--- Running Minimal AES Test with package:cryptography ---');

  // Values from RFC 9001, Appendix A.2 and A.3
  final hpKeyBytes = HEX.decode('437b9aec36be423400cdd115d9db3241');
  final sample = Uint8List.fromList(
    HEX.decode('d1b1c98dd7689fb8ec11d242b123dc9b'),
  );
  final expectedMask = Uint8List.fromList(
    HEX.decode('8255b4d32060a82352865d142c2d766'),
  );

  print('Using HP Key : ${HEX.encode(hpKeyBytes)}');
  print('Using Sample : ${HEX.encode(sample)}');
  print('Expected Mask: ${HEX.encode(expectedMask)}');

crypto.AesCbc.with128bits(macAlgorithm: macAlgorithm)
  // Set up the algorithm and key using the library prefix
  final algorithm = crypto.AesEcb(macAlgorithm: crypto.MacAlgorithm.empty);
  final secretKey = crypto.SecretKey(hpKeyBytes);

  // Perform encryption
  final secretBox = await algorithm.encrypt(sample, secretKey: secretKey);
  final generatedMask = Uint8List.fromList(secretBox.cipherText);

  print('Generated Mask: ${HEX.encode(generatedMask)}');
  print('');

  // Use a reliable method to compare the two byte lists
  bool success = const ListEquality().equals(generatedMask, expectedMask);

  if (success) {
    print('✅ Test PASSED: The generated mask is correct!');
  } else {
    print('❌ Test FAILED: The generated mask is incorrect.');
  }
}
