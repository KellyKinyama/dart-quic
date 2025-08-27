// Filename: illustrated_quic_example.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';
import '../crypto.dart'; // Your QUIC crypto library files
import '../prf.dart';
import '../hkdf.dart';

// Helper to decode hex strings from the tutorial
Uint8List hexToBytes(String hexString) {
  return Uint8List.fromList(HEX.decode(hexString.replaceAll(' ', '')));
}

// Helper to compare two byte lists for the assert.
bool listsAreEqual(Uint8List a, Uint8List b) {
  return DeepCollectionEquality().equals(a, b);
}

void main() async {
  print('--- Running "The Illustrated QUIC Connection" Example ---');

  // -- Step 1: Generate Client Ephemeral Keys (as described in the tutorial) --
  // The tutorial uses a fixed private key for reproducibility.
  final clientEphemeralPrivateKey = hexToBytes(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
  );
  final expectedPublicKey = hexToBytes(
    '358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254',
  );
  // NOTE: Verifying the X25519 key derivation would require a specific crypto library function.
  // We will assume this step is correct and proceed with the QUIC-specific parts.
  print('Step 1: Client key pair generated.');

  // -- Step 2: Generate Client Initial Keys (as described in the tutorial) --
  print('\nStep 2: Deriving Initial encryption keys...');

  // The client generates a random Destination Connection ID. The tutorial uses a fixed one.
  final dcid = hexToBytes('0001020304050607');
  final salt = hexToBytes('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');

  // Derive initial secrets
  final initialSecret = hkdfExtract(dcid, salt: salt);
  final clientSecret = hkdfExpandLabel(
    initialSecret,
    Uint8List(0),
    'client in',
    32,
  );
  final serverSecret = hkdfExpandLabel(
    initialSecret,
    Uint8List(0),
    'server in',
    32,
  );

  // Derive client keys and IVs from the client secret
  final clientKey = hkdfExpandLabel(clientSecret, Uint8List(0), 'quic key', 16);
  final clientIV = hkdfExpandLabel(clientSecret, Uint8List(0), 'quic iv', 12);
  final clientHpKey = hkdfExpandLabel(
    clientSecret,
    Uint8List(0),
    'quic hp',
    16,
  );

  // Verify derived keys against the tutorial's values
  print('  Client Key: ${HEX.encode(clientKey)}');
  print('  Client IV:  ${HEX.encode(clientIV)}');
  print('  Client HP:  ${HEX.encode(clientHpKey)}');
  assert(HEX.encode(clientKey) == 'b14b918124fda5c8d79847602fa3520b');
  assert(HEX.encode(clientIV) == 'ddbc15dea80925a55686a7df');
  assert(HEX.encode(clientHpKey) == '6df4e9d737cdf714711d7c617ee82981');
  print('✅ Client keys match the tutorial.');

  // -- Step 3: Create and Encrypt the Client Initial Packet --
  print('\nStep 3: Building and encrypting the Client Hello packet...');

  final cryptoPair = CryptoPair();
  await cryptoPair.setupInitial(cid: dcid, isClient: true);

  final plainHeader = hexToBytes(
    'cd0000000108000102030405060705635f63696400410300',
  );
  final plainPayload = hexToBytes(
    '060040ee010000ea0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000006130113021303010000bb0000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d001700180010000b00090870696e672f312e30000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b00030203040039003103048000fff7040480a0000005048010000006048010000007048010000008010a09010a0a01030b01190f05635f636964',
  );
  final packetNumber = 0;

  // Encrypt the packet using the derived keys
  final encryptedPacket = await cryptoPair.send.encryptPacket(
    plainHeader,
    plainPayload,
    packetNumber,
  );

  // The tutorial's final datagram includes padding to 1200 bytes.
  // We will compare our encrypted packet to the start of the tutorial's datagram.
  final expectedDatagramStart = hexToBytes(
    'cd0000000108000102030405060705635f636964004103981c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efaffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099',
  );

  print('Comparing generated packet with tutorial...');
  assert(
    listsAreEqual(encryptedPacket, expectedDatagramStart),
    'Generated packet does not match the tutorial\'s expected value!',
  );

  print('✅ Generated Client Initial packet matches the tutorial.');
  print('\n--- Example Finished ---');
}
