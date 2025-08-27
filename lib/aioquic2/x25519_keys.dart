// Filename: x25519_keys.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:hex/hex.dart';

// Helper to decode hex strings from the tutorial.
Uint8List hexToBytes(String hexString) {
  return Uint8List.fromList(HEX.decode(hexString.replaceAll(' ', '')));
}

Future<void> main() async {
  print('--- Step 1: Client Ephemeral Key Generation ---');

  // As per the tutorial, a fixed private key is used for reproducibility.
  final privateKeyBytes = hexToBytes('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
  final expectedPublicKey = hexToBytes('358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254');

  final algorithm = X25519();
  final simpleKeyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
  final simplePublicKey = await simpleKeyPair.extractPublicKey();

  print('Private Key: ${HEX.encode(privateKeyBytes)}');
  print('Public Key : ${HEX.encode(simplePublicKey.bytes)}');

  // Verify the generated public key matches the tutorial's expected value.
  assert(HEX.encode(simplePublicKey.bytes) == HEX.encode(expectedPublicKey));

  print('\n✅ Public key matches the tutorial value.');
  print('\n--- Key Generation Finished ---');
}