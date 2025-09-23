// main test file: hex_dump2.dart
import 'dart:typed_data';
import 'dart:math';

import 'package:hex/hex.dart';

import 'aead.dart';
import 'header_protector.dart';
import 'payload_parser_final.dart';
import 'protocol.dart';
import 'initial_aead.dart';
import 'quic_frame_parser.dart';
import 'buffer.dart';
import 'quic_header2.dart'; // Import the new header file

void unprotectAndParseServerInitialPacket(Uint8List packetBytes) {
  print('\n--- Parsing Server Initial Packet ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = Buffer(data: mutablePacket);

  // 1. Parse the header to get structured data and offsets.
  final header = pullQuicLongHeader(buffer);

  print('DEBUG: Parsed DCID (Hex): ${HEX.encode(header.destinationCid)}');
  print('DEBUG: Parsed SCID (Hex): ${HEX.encode(header.sourceCid)}');
  print('DEBUG: Packet Number starts at offset: ${header.pnOffset}');

  final (_, opener) = newInitialAEAD(
    header.destinationCid, // Use the DCID from the header
    Perspective.client,
    Version.version1,
  );

  // 2. Use the new method to extract the sample.
  final sample = header.getSample(mutablePacket, 16);
  print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

  // Views for in-place decryption
  final firstByteView = Uint8List.view(mutablePacket.buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(
    mutablePacket.buffer,
    header.pnOffset,
    4,
  ); // Max PN length

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  print('DEBUG: Decoded Packet Number on the wire: $wirePn');

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = header.pnOffset + pnLength;
  final associatedData = Uint8List.view(mutablePacket.buffer, 0, payloadOffset);
  final ciphertext = Uint8List.view(
    mutablePacket.buffer,
    payloadOffset,
    header.payloadLength, // Use the parsed payload length
  );

  print('DEBUG: Final Payload Ciphertext Length: ${ciphertext.length}');

  try {
    final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
    print('✅ **Payload decrypted successfully!**');
    final parser = QuicFrameParser(encryptionLevel: 'Initial');
    final List<QuicFrame> frames = parser.parse(plaintext);
    for (final frame in frames) {
      if (frame is CryptoFrame) {
        print('Found Crypto frame with TLS data.');
      } else if (frame is AckFrame) {
        print('Found ACK frame, largest acked: ${frame.largestAcked}');
      }
    }
  } catch (e) {
    print('\n❌ ERROR: Decryption failed.');
    print('Exception: $e');
  }
}

Uint8List testServersInitial() {
  final connID = Uint8List.fromList(
    HEX.decode("0001020304050607"),
  ); //0001020304050607

  // name:           "QUIC v1",
  final version = Version.version1;
  final header = splitHexString("c00000000105635f63696405735f63696400407500");
  final data = serverInitialData;
  final expectedSample = splitHexString("d5d9c823d07c616882ca770279249864");
  final expectedHdr = splitHexString(
    "cd0000000105635f63696405735f6369640040753a",
  );
  final expectedPacket = serverInitial;

  // parsePayload(data);

  // {
  // 	name:           "QUIC v2",
  // 	version:        protocol.Version2,
  // 	header:         splitHexString(t, "d16b3343cf0008f067a5502a4262b50040750001"),
  // 	data:           splitHexString(t, "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
  // 	expectedSample: splitHexString(t, "6f05d8a4398c47089698baeea26b91eb"),
  // 	expectedHdr:    splitHexString(t, "dc6b3343cf0008f067a5502a4262b5004075d92f"),
  // 	expectedPacket: splitHexString(t, "dc6b3343cf0008f067a5502a4262b500 4075d92faaf16f05d8a4398c47089698 baeea26b91eb761d9b89237bbf872630 17915358230035f7fd3945d88965cf17 f9af6e16886c61bfc703106fbaf3cb4c fa52382dd16a393e42757507698075b2 c984c707f0a0812d8cd5a6881eaf21ce da98f4bd23f6fe1a3e2c43edd9ce7ca8 4bed8521e2e140"),
  // },

  print("connID: ${HEX.encode(connID)}");
  // 1. Create client sealer
  final (sealer, _) = newInitialAEAD(connID, Perspective.server, version);

  // 3. Seal the payload
  final sealed = sealer.seal(data, 0, header);

  // 4. Extract and verify the sample used for header protection
  // Note: this test vector uses a simplified sample location (first 16 bytes).
  final sample = sealed.sublist(3, 3 + 16);
  // _expectEquals(sample, expectedSample, 'Client Packet Sample');

  print('Server Packet Sample');
  print("Got:      ${HEX.encode(sample)}");
  print("Expected: ${HEX.encode(expectedSample)}");
  print("");

  // 5. Encrypt the header and verify its protected parts
  final protectedHeader = Uint8List.fromList(header);
  final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
  final pnView = Uint8List.view(
    protectedHeader.buffer,
    protectedHeader.length - 1,
    1,
  );
  sealer.encryptHeader(sample, firstByteView, pnView);

  print('Protected header');
  print("Got:      $protectedHeader");
  print("Expected: $expectedHdr");
  print("");

  // 6. Assemble and verify the final, full packet
  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealed);

  //  _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
  print('Final Client Packet');
  print("Got:      ${HEX.encode(finalPacket.toBytes().sublist(0, 32))}");
  print("Expected: ${HEX.encode(expectedPacket.sublist(0, 32))}");
  print("");

  return finalPacket.toBytes();
}

// ... (rest of your file, like testServersInitial, main, etc.)
// No changes are needed for testServersInitial() as it constructs a packet.
// The main function will now call the updated unprotectAndParseServerInitialPacket.

void main() {
  // unprotectAndParseInitialPacket(clientInitial); // This function would need similar updates.
  unprotectAndParseServerInitialPacket(testServersInitial());
}

// (Keep your existing functions like testServersInitial and your hex data variables)
// ...
final serverInitial = Uint8List.fromList([
  0xcd,
  0x00,
  0x00,
  0x00,
  0x01,
  0x05,
  0x63,
  0x5f,
  0x63,
  0x69,
  0x64,
  0x05,
  0x73,
  0x5f,
  0x63,
  0x69,
  0x64,
  0x00,
  0x40,
  0x75,
  0x3a,
  0x83,
  0x68,
  0x55,
  0xd5,
  0xd9,
  0xc8,
  0x23,
  0xd0,
  0x7c,
  0x61,
  0x68,
  0x82,
  0xca,
  0x77,
  0x02,
  0x79,
  0x24,
  0x98,
  0x64,
  0xb5,
  0x56,
  0xe5,
  0x16,
  0x32,
  0x25,
  0x7e,
  0x2d,
  0x8a,
  0xb1,
  0xfd,
  0x0d,
  0xc0,
  0x4b,
  0x18,
  0xb9,
  0x20,
  0x3f,
  0xb9,
  0x19,
  0xd8,
  0xef,
  0x5a,
  0x33,
  0xf3,
  0x78,
  0xa6,
  0x27,
  0xdb,
  0x67,
  0x4d,
  0x3c,
  0x7f,
  0xce,
  0x6c,
  0xa5,
  0xbb,
  0x3e,
  0x8c,
  0xf9,
  0x01,
  0x09,
  0xcb,
  0xb9,
  0x55,
  0x66,
  0x5f,
  0xc1,
  0xa4,
  0xb9,
  0x3d,
  0x05,
  0xf6,
  0xeb,
  0x83,
  0x25,
  0x2f,
  0x66,
  0x31,
  0xbc,
  0xad,
  0xc7,
  0x40,
  0x2c,
  0x10,
  0xf6,
  0x5c,
  0x52,
  0xed,
  0x15,
  0xb4,
  0x42,
  0x9c,
  0x9f,
  0x64,
  0xd8,
  0x4d,
  0x64,
  0xfa,
  0x40,
  0x6c,
  0xf0,
  0xb5,
  0x17,
  0xa9,
  0x26,
  0xd6,
  0x2a,
  0x54,
  0xa9,
  0x29,
  0x41,
  0x36,
  0xb1,
  0x43,
  0xb0,
  0x33,
]);
final serverInitialData = Uint8List.fromList([
  0x02,
  0x00,
  0x42,
  0x40,
  0x00,
  0x00,
  0x06,
  0x00,
  0x40,
  0x5a,
  0x02,
  0x00,
  0x00,
  0x56,
  0x03,
  0x03,
  0x70,
  0x71,
  0x72,
  0x73,
  0x74,
  0x75,
  0x76,
  0x77,
  0x78,
  0x79,
  0x7a,
  0x7b,
  0x7c,
  0x7d,
  0x7e,
  0x7f,
  0x80,
  0x81,
  0x82,
  0x83,
  0x84,
  0x85,
  0x86,
  0x87,
  0x88,
  0x89,
  0x8a,
  0x8b,
  0x8c,
  0x8d,
  0x8e,
  0x8f,
  0x00,
  0x13,
  0x01,
  0x00,
  0x00,
  0x2e,
  0x00,
  0x33,
  0x00,
  0x24,
  0x00,
  0x1d,
  0x00,
  0x20,
  0x9f,
  0xd7,
  0xad,
  0x6d,
  0xcf,
  0xf4,
  0x29,
  0x8d,
  0xd3,
  0xf9,
  0x6d,
  0x5b,
  0x1b,
  0x2a,
  0xf9,
  0x10,
  0xa0,
  0x53,
  0x5b,
  0x14,
  0x88,
  0xd7,
  0xf8,
  0xfa,
  0xbb,
  0x34,
  0x9a,
  0x98,
  0x28,
  0x80,
  0xb6,
  0x15,
  0x00,
  0x2b,
  0x00,
  0x02,
  0x03,
  0x04,
]);
