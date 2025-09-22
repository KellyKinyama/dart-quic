// In your main file (e.g., hex_dump2.dart)
// Make sure to import the new file:
import 'dart:convert';
import 'dart:typed_data';

import 'buffer.dart';
import 'hash.dart';
import 'hkdf.dart';
import 'quic_header.dart';
import 'dart:math';

import 'package:hex/hex.dart';

import 'aead.dart';
import 'header_protector.dart';
import 'payload_parser_final.dart';
// import 'payload_parser9.dart';
import 'protocol.dart';
import 'initial_aead.dart';
import 'quic_frame_parser.dart';

/// Unprotects and parses a QUIC packet with a long header (e.g., Initial, Handshake).
///
/// Takes the raw [packetBytes] and the correct [opener] containing the keys
/// for the packet's encryption level.
void unprotectAndParseLongHeaderPacket(
  Uint8List packetBytes,
  LongHeaderOpener opener,
  String packetDescription, // For clear logging, e.g., "Client Initial ACK"
) {
  print('\n--- Parsing $packetDescription Packet ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = Buffer(data: mutablePacket);

  try {
    // 1. Use the robust header parser to correctly read all fields.
    final header = pullQuicLongHeader(buffer);
    print('DEBUG: Parsed Packet Type: ${header.packetType}');
    print('DEBUG: Packet Number starts at offset: ${header.pnOffset}');

    // 2. Perform header protection using the correct sample offset.
    if (mutablePacket.length < header.pnOffset + 4 + 16) {
      throw Exception('Packet is too short for header protection sample');
    }
    final sample = Uint8List.view(
      mutablePacket.buffer,
      header.pnOffset + 4,
      16,
    );
    final firstByteView = Uint8List.view(mutablePacket.buffer, 0, 1);

    // Pass a 4-byte view for the packet number. The decryptor will determine the actual length.
    final protectedPnBytesView = Uint8List.view(
      mutablePacket.buffer,
      header.pnOffset,
      4,
    );

    opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

    // 3. Decode the now-unprotected packet number.
    final pnLength = (firstByteView[0] & 0x03) + 1;
    int wirePn = 0;
    for (int i = 0; i < pnLength; i++) {
      wirePn = (wirePn << 8) | protectedPnBytesView[i];
    }
    print('DEBUG: Decoded Packet Number on the wire: $wirePn');

    final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);

    // 4. Slice the associated data and ciphertext using the parsed header values.
    final payloadOffset = header.pnOffset + pnLength;
    final associatedData = Uint8List.view(
      mutablePacket.buffer,
      0,
      payloadOffset,
    );
    final ciphertext = Uint8List.view(
      mutablePacket.buffer,
      payloadOffset,
      header.payloadLength - pnLength,
    );

    // 5. Decrypt the payload.
    final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
    print('✅ **Payload decrypted successfully!**');

    // 6. Parse the plaintext frames.
    final encryptionLevel = (header.packetType == 0) ? 'Initial' : 'Handshake';
    final parser = QuicFrameParser(encryptionLevel: encryptionLevel);
    final frames = parser.parse(plaintext);

    // 7. Process the frames.
    for (final frame in frames) {
      if (frame is CryptoFrame) {
        print('Found TLS messages: ${frame.messages}');
      } else if (frame is AckFrame) {
        print('Peer acknowledged up to packet ${frame.largestAcked}');
      }
    }
  } catch (e, s) {
    print('\n❌ ERROR: Failed to unprotect or parse packet.');
    print('Exception: $e');
    print('Stack trace:\n$s');
  }
}

// Corrected main function
void main() {
  final hello_hash = createHash(Uint8List.fromList([...ch, ...sh]));
  print("Handshake hash: ${HEX.encode(hello_hash)}");
  print(
    "Expected:       ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b",
  );

  final shared_secret = Uint8List.fromList(
    HEX.decode(
      "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624",
    ),
  );
  // final zero_keyDecoded = Uint8List.fromList(
  //   HEX.decode(
  //     "0000000000000000000000000000000000000000000000000000000000000000",
  //   ),
  // );
  final zero_key = Uint8List(32);

  final early_secret = hkdfExtract(zero_key, salt: Uint8List(2));
  final empty_hash = createHash(Uint8List(0));
  final derived_secret = hkdfExpandLabel(
    early_secret,
    empty_hash,
    "derived",
    32,
  );

  final handshake_secret = hkdfExtract(shared_secret, salt: derived_secret);
  final csecret = hkdfExpandLabel(
    handshake_secret,
    hello_hash,
    "c hs traffic",
    32,
  );
  final ssecret = hkdfExpandLabel(
    handshake_secret,
    hello_hash,
    "s hs traffic",
    32,
  );
  final client_handshake_key = hkdfExpandLabel(
    csecret,
    utf8.encode(""),
    "quic key",
    16,
  );
  final server_handshake_key = hkdfExpandLabel(
    ssecret,
    utf8.encode(""),
    "quic key",
    16,
  );
  final client_handshake_iv = hkdfExpandLabel(
    csecret,
    utf8.encode(""),
    "quic iv",
    12,
  );
  final server_handshake_iv = hkdfExpandLabel(
    ssecret,
    utf8.encode(""),
    "quic iv",
    12,
  );
  final client_handshake_hp = hkdfExpandLabel(
    csecret,
    utf8.encode(""),
    "quic hp",
    16,
  );
  final server_handshake_hp = hkdfExpandLabel(
    ssecret,
    utf8.encode(""),
    "quic hp",
    16,
  );

  // print("");
  // print("Keys:");
  // print("client_handshake_key: ${HEX.encode(client_handshake_key)}");
  // print("Expected:             30a7e816f6a1e1b3434cf39cf4b415e7");
  // print("client_handshake_iv: ${HEX.encode(client_handshake_iv)}");
  // print("Expected:             11e70a5d1361795d2bb04465");

  // print("server_handshake_key: ${HEX.encode(server_handshake_key)}");
  // print("Expected:             17abbf0a788f96c6986964660414e7ec");
  // print("server_handshake_iv: ${HEX.encode(server_handshake_iv)}");
  // print("Expected:             09597a2ea3b04c00487e71f3");

  // print("server_handshake_hp: ${HEX.encode(server_handshake_hp)}");
  // print("Expected:             2a18061c396c2828582b41b0910ed536");

  // ... (All your key derivation logic for `csecret` is correct) ...
  // final hello_hash = createHash(Uint8List.fromList([...ch, ...sh]));
  // // ... etc ...
  // final csecret = hkdfExpandLabel(handshake_secret, hello_hash, "c hs traffic", 32);

  // // --- Create the HANDSHAKE opener using the keys you derived ---
  // final client_handshake_key = hkdfExpandLabel(csecret, Uint8List(0), "quic key", 16);
  // final client_handshake_iv = hkdfExpandLabel(csecret, Uint8List(0), "quic iv", 12);
  // final client_handshake_hp_secret = hkdfExpandLabel(csecret, Uint8List(0), "quic hp", 16);

  final handshakeDecrypter = initialSuite.aead(
    key: client_handshake_key,
    nonceMask: client_handshake_iv,
  );

  final handshakeOpener = LongHeaderOpener(
    handshakeDecrypter,
    newHeaderProtector(initialSuite, csecret, true, Version.version1),
  );

  // This is a client HANDSHAKE packet (not Initial)
  final clientHandshakePacket = Uint8List.fromList([
    0xcf,
    0x00,
    0x00,
    0x00,
    0x01,
    0x05,
    0x73,
    0x5f,
    0x63,
    0x69,
    0x64,
    0x05,
    0x63,
    0x5f,
    0x63,
    0x69,
    0x64,
    0x00,
    0x40,
    0x17,
    0x56,
    0x6e,
    0x1f,
    0x98,
    0xed,
    0x1f,
    0x7b,
    0x05,
    0x55,
    0xcd,
    0xb7,
    0x83,
    0xfb,
    0xdf,
    0x5b,
    0x52,
    0x72,
    0x4b,
    0x7d,
    0x29,
    0xf0,
    0xaf,
    0xe3,
  ]);

  // Use the new generic function with the HANDSHAKE opener
  unprotectAndParseLongHeaderPacket(
    clientHandshakePacket,
    handshakeOpener,
    'Handshake',
  );
}

final ch = Uint8List.fromList([
  0x01,
  0x00,
  0x00,
  0xea,
  0x03,
  0x03,
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x08,
  0x09,
  0x0a,
  0x0b,
  0x0c,
  0x0d,
  0x0e,
  0x0f,
  0x10,
  0x11,
  0x12,
  0x13,
  0x14,
  0x15,
  0x16,
  0x17,
  0x18,
  0x19,
  0x1a,
  0x1b,
  0x1c,
  0x1d,
  0x1e,
  0x1f,
  0x00,
  0x00,
  0x06,
  0x13,
  0x01,
  0x13,
  0x02,
  0x13,
  0x03,
  0x01,
  0x00,
  0x00,
  0xbb,
  0x00,
  0x00,
  0x00,
  0x18,
  0x00,
  0x16,
  0x00,
  0x00,
  0x13,
  0x65,
  0x78,
  0x61,
  0x6d,
  0x70,
  0x6c,
  0x65,
  0x2e,
  0x75,
  0x6c,
  0x66,
  0x68,
  0x65,
  0x69,
  0x6d,
  0x2e,
  0x6e,
  0x65,
  0x74,
  0x00,
  0x0a,
  0x00,
  0x08,
  0x00,
  0x06,
  0x00,
  0x1d,
  0x00,
  0x17,
  0x00,
  0x18,
  0x00,
  0x10,
  0x00,
  0x0b,
  0x00,
  0x09,
  0x08,
  0x70,
  0x69,
  0x6e,
  0x67,
  0x2f,
  0x31,
  0x2e,
  0x30,
  0x00,
  0x0d,
  0x00,
  0x14,
  0x00,
  0x12,
  0x04,
  0x03,
  0x08,
  0x04,
  0x04,
  0x01,
  0x05,
  0x03,
  0x08,
  0x05,
  0x05,
  0x01,
  0x08,
  0x06,
  0x06,
  0x01,
  0x02,
  0x01,
  0x00,
  0x33,
  0x00,
  0x26,
  0x00,
  0x24,
  0x00,
  0x1d,
  0x00,
  0x20,
  0x35,
  0x80,
  0x72,
  0xd6,
  0x36,
  0x58,
  0x80,
  0xd1,
  0xae,
  0xea,
  0x32,
  0x9a,
  0xdf,
  0x91,
  0x21,
  0x38,
  0x38,
  0x51,
  0xed,
  0x21,
  0xa2,
  0x8e,
  0x3b,
  0x75,
  0xe9,
  0x65,
  0xd0,
  0xd2,
  0xcd,
  0x16,
  0x62,
  0x54,
  0x00,
  0x2d,
  0x00,
  0x02,
  0x01,
  0x01,
  0x00,
  0x2b,
  0x00,
  0x03,
  0x02,
  0x03,
  0x04,
  0x00,
  0x39,
  0x00,
  0x31,
  0x03,
  0x04,
  0x80,
  0x00,
  0xff,
  0xf7,
  0x04,
  0x04,
  0x80,
  0xa0,
  0x00,
  0x00,
  0x05,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x06,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x07,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x08,
  0x01,
  0x0a,
  0x09,
  0x01,
  0x0a,
  0x0a,
  0x01,
  0x03,
  0x0b,
  0x01,
  0x19,
  0x0f,
  0x05,
  0x63,
  0x5f,
  0x63,
  0x69,
  0x64,
]);

final sh = Uint8List.fromList([
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
