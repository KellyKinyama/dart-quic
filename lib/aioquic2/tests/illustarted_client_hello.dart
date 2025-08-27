// Filename: illustrated_client_hello.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';
import '../crypto.dart';
import '../prf.dart';
import '../hkdf.dart';

// Helper to decode hex strings from the tutorial.
Uint8List hexToBytes(String s) {
  return Uint8List.fromList(
    HEX.decode(s.replaceAll(' ', '').replaceAll('\n', '')),
  );
}

// Helper for asserting byte list equality.
bool listsAreEqual(Uint8List a, Uint8List b) {
  return DeepCollectionEquality().equals(a, b);
}

void main() async {
  print('--- Running "Illustrated QUIC" Client Hello Example ---');

  // --- Step 1: Derive Initial Keys ---
  print('\n[1] Deriving Initial Keys...');

  // Values from the tutorial
  final dcid = hexToBytes('0001020304050607');
  final salt = hexToBytes('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');

  // Expected values from the tutorial
  final expectedClientKey = hexToBytes('b14b918124fda5c8d79847602fa3520b');
  final expectedClientIV = hexToBytes('ddbc15dea80925a55686a7df');
  final expectedClientHpKey = hexToBytes('6df4e9d737cdf714711d7c617ee82981');

  // Perform the key derivation
  final initialSecret = hkdfExtract(dcid, salt: salt);
  final clientSecret = hkdfExpandLabel(
    initialSecret,
    Uint8List(0),
    'client in',
    32,
  );
  final clientKey = hkdfExpandLabel(clientSecret, Uint8List(0), 'quic key', 16);
  final clientIV = hkdfExpandLabel(clientSecret, Uint8List(0), 'quic iv', 12);
  final clientHpKey = hkdfExpandLabel(
    clientSecret,
    Uint8List(0),
    'quic hp',
    16,
  );

  // Verify the derived keys match the tutorial's values
  assert(listsAreEqual(clientKey, expectedClientKey));
  assert(listsAreEqual(clientIV, expectedClientIV));
  assert(listsAreEqual(clientHpKey, expectedClientHpKey));
  print('✅ All client-side initial keys derived correctly.');

  // --- Step 2: Build and Encrypt the Packet ---
  print('\n[2] Building and Encrypting Packet...');

  // Create a CryptoPair which internally derives the same keys.
  final cryptoPair = CryptoPair();
  await cryptoPair.setupInitial(cid: dcid, isClient: true);

  // Plaintext header and payload from the tutorial.
  // Note: The packet number is part of the header.
  final plainHeader = hexToBytes(
    'cd0000000108000102030405060705635f63696400410300',
  );
  final plainPayload = hexToBytes(
    '060040ee010000ea0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000006130113021303010000bb0000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d001700180010000b00090870696e672f312e30000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b00030203040039003103048000fff7040480a0000005048010000006048010000007048010000008010a09010a0a01030b01190f05635f636964',
  );
  final packetNumber = 0;

  // Encrypt the packet.
  final encryptedPacket = await cryptoPair.send.encryptPacket(
    plainHeader,
    plainPayload,
    packetNumber,
  );

  // --- Step 3: Verify the Result ---
  print('\n[3] Verifying Result...');

  // This is the expected final encrypted packet from the tutorial.
  final expectedPacket = hexToBytes(
    'cd0000000108000102030405060705635f636964004103981c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efaffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099',
  );

  assert(
    listsAreEqual(encryptedPacket, expectedPacket),
    'Generated packet does not match the tutorial\'s expected value!',
  );

  print('✅ Generated Client Initial packet matches the tutorial.');
  print('\n--- Example Finished ---');
}
