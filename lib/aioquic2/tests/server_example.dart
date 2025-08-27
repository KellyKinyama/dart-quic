// Filename: server_example.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';
import '../crypto.dart';
import '../packet.dart';

// Helper to decode hex strings from the tutorial, removing spaces and newlines.
Uint8List hexToBytes(String hexString) {
  return Uint8List.fromList(
    HEX.decode(hexString.replaceAll(' ', '').replaceAll('\n', '')),
  );
}

// Helper to compare two byte lists for the assert.
bool listsAreEqual(Uint8List a, Uint8List b) {
  return DeepCollectionEquality().equals(a, b);
}

void main() async {
  print('--- Running QUIC Server Response Example ---');

  // -- Step 1: Receive the Client's Initial Packet --
  // This is UDP Datagram 1 from the tutorial.
  final clientInitialDatagram = hexToBytes(
    'cd0000000108000102030405060705635f636964004103981c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efaffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099',
  );

  // The server extracts the Destination Connection ID from the header.
  // In the tutorial, this is the client's "initial_random".
  final clientDestConnId = hexToBytes('0001020304050607');
  print(
    'Step 1: Received Client Initial Packet. DCID: ${HEX.encode(clientDestConnId)}',
  );

  // -- Step 2: Server Derives Initial Keys --
  // The server performs the *exact same* key derivation as the client,
  // using the DCID from the packet it received.
  print('\nStep 2: Deriving Initial keys from Client DCID...');
  final serverCryptoPair = CryptoPair();
  await serverCryptoPair.setupInitial(cid: clientDestConnId, isClient: false);
  print('✅ Server keys derived successfully.');

  // -- Step 3: Server Decrypts the Client Packet --
  print('\nStep 3: Decrypting Client Hello packet...');
  try {
    final expectedPlainPayload = hexToBytes(
      '060040ee010000ea0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000006130113021303010000bb0000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d001700180010000b00090870696e672f312e30000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b00030203040039003103048000fff7040480a0000005048010000006048010000007048010000008010a09010a0a01030b01190f05635f636964',
    );

    // The Packet Number Offset in the Client Initial packet is 22 bytes.
    final (plainHeader, plainPayload, packetNum) = await serverCryptoPair.recv
        .decryptPacket(clientInitialDatagram, 22, 0);

    assert(
      listsAreEqual(plainPayload, expectedPlainPayload),
      'Decrypted payload mismatch!',
    );
    print('✅ Client packet decrypted successfully.');
  } catch (e, st) {
    print('❌ Decrypt Test FAILED: $e');
    print(st);
  }

  // -- Step 4: Server Creates and Encrypts its Response Packet --
  print('\nStep 4: Building and encrypting the Server Hello packet...');

  // These are the plaintext parts of the server's response from the tutorial.
  final serverPlainHeader = hexToBytes(
    'cd0000000105635f63696405735f63696400407500',
  );
  final serverPlainPayload = hexToBytes(
    '020000560303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f00130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304',
  );
  final serverPacketNumber = 0;

  // This is the expected final encrypted packet from the tutorial.
  final expectedServerPacket = hexToBytes(
    'cd0000000105635f63696405735f6369640040753a836855d5d9c823d07c616882ca770279249864b556e51632257e2d8ab1fd0dc04b18b9203fb919d8ef5a33f378a627db674d3c7fce6ca5bb3e8cf90109cbb955665fc1a4b93d05f6eb83252f6631bcadc7402c10f65c52ed15b4429c9f64d84d64fa406cf0b517a926d62a54a9294136b143b033',
  );

  // Encrypt the packet using the server's send keys.
  final encryptedServerPacket = await serverCryptoPair.send.encryptPacket(
    serverPlainHeader,
    serverPlainPayload,
    serverPacketNumber,
  );

  assert(
    listsAreEqual(encryptedServerPacket, expectedServerPacket),
    'Generated server packet does not match the tutorial\'s expected value!',
  );

  print('✅ Generated Server Initial packet matches the tutorial.');
  print('\n--- Server Response Example Finished ---');
}
