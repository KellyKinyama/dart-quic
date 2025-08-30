// Filename: lib/aes_test.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart' as pc;

void main() {
  print('--- Running Minimal AES Header Protection Test ---');

  // Values from RFC 9001, Appendix A.2 and A.3
  final hpKey = Uint8List.fromList(
    HEX.decode('437b9aec36be423400cdd115d9db3241'),
  );

  final sample = Uint8List.fromList(
    HEX.decode('d1b1c98dd7689fb8ec11d242b123dc9b'),
  );

  final expectedMask = Uint8List.fromList(
    HEX.decode('8255b4d32060a842352865d142c2d766'),
  );

  print('Using HP Key : ${HEX.encode(hpKey)}');
  print('Using Sample : ${HEX.encode(sample)}');
  print('Expected Mask: ${HEX.encode(expectedMask)}');

  // Initialize the AES cipher
  final blockCipher = pc.AESEngine()..init(true, pc.KeyParameter(hpKey));

  // Create a buffer for the output mask
  final generatedMask = Uint8List(16);

  // Perform the AES-ECB encryption
  blockCipher.processBlock(sample, 0, generatedMask, 0);

  print('Generated Mask: ${HEX.encode(generatedMask)}');
  print('');

  // Compare the result
  bool success = true;
  for (int i = 0; i < expectedMask.length; i++) {
    if (generatedMask[i] != expectedMask[i]) {
      success = false;
      break;
    }
  }

  if (success) {
    print('✅ Test PASSED: The generated mask is correct!');
  } else {
    print('❌ Test FAILED: The generated mask is incorrect.');
  }
}
