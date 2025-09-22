import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';

import 'package:dart_quic/go_quic/hash.dart';
// import 'package:dart_quic/go_quic/tests/generate_and_parse.dart';
import 'package:dart_quic/go_quic/hkdf.dart';
import 'package:dart_quic/go_quic/protocol.dart';
import 'package:hex/hex.dart';

import '../aead.dart';
import '../buffer.dart';
// import '../hkdf.dart';
// import '../handshake/client_hello.dart';
import '../header_protector.dart';
import '../protocol.dart';
import '../initial_aead.dart';
import '../quic_frame_parser.dart';

/// Verifies the entire client-side sealing and protection process against a known packet vector.
Uint8List testClientInitialProtection() {
  print('\n--- Running Test: Client Initial Packet Protection Vector ---');

  final header = splitHexString("c00000000105735f63696405635f63696400401701");
  final data = splitHexString("0200200000");
  final expectedSample = splitHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
  final expectedHdrFirstByte = 0xcf;
  final expectedHdrPnBytes = splitHexString("56");
  final expectedPacket = splitHexString(
    "cf0000000105735f63696405635f636964004017566e1f98ed1f7b0555cdb783fbdf5b52724b7d29f0afe3",
  );

  // 1. Create client sealer
  final (sealer, opener) = fromHandshakeSecrets(
    // connID,
    // scid,
    Perspective.client,
    Version.version1,
    clientHelloBytes: ch,
    serverHelloBytes: sh,
  );
  // 2. Pad data to the required minimum length for an Initial packet
  final paddedDataBuilder = BytesBuilder()..add(data);

  final paddedData = paddedDataBuilder.toBytes();

  // 3. Seal the payload
  final sealed = sealer.seal(paddedData, 1, header);

  // 4. Extract and verify the sample used for header protection
  // Note: this test vector uses a simplified sample location (first 16 bytes).
  final sample = sealed.sublist(1, 1 + 16);
  // _expectEquals(sample, expectedSample, 'Client Packet Sample');

  print('Client Packet Sample');
  print("Got:      $sample");
  print("Expected: $expectedSample");
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

  print('Protected First Byte');
  print("Got:      ${protectedHeader[0]}");
  print("Expected: $expectedHdrFirstByte");
  print("");

  print('Protected Packet Number');
  print("Got:      $pnView");
  print("Expected: $expectedHdrPnBytes");
  print("");

  // 6. Assemble and verify the final, full packet
  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealed);

  // _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
  // print('Final Client Packet');
  print("Got:      ${finalPacket.toBytes()}");
  print("Expected: $expectedPacket");
  print("");

  return finalPacket.toBytes();
}

void unprotectAndParseClientHandsakePacket(
  Uint8List packetBytes,
  LongHeaderOpener opener,
) {
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
  // final connID = Uint8List.fromList(
  //   HEX.decode("0001020304050607"),
  // ); //0001020304050607

  final header = Uint8List.fromList(
    HEX.decode("c00000000105735f63696405635f63696400401701"),
  );

  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version

  // DEBUG: Print initial state
  print('DEBUG: Starting offset: $offset');

  final dcidLen = mutablePacket[offset];
  offset += 1;
  final dcid = Uint8List.view(buffer, offset, dcidLen);
  offset += dcidLen;
  // DEBUG: Verify the most critical piece of info: the DCID
  print('DEBUG: Parsed DCID Length: $dcidLen');
  print('DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}');
  print('DEBUG: Offset after DCID: $offset');
  print("");

  // Skip SCID and Token
  final scidLen = mutablePacket[offset];
  offset += 1;
  final scid = mutablePacket.sublist(offset, offset + scidLen);
  print('DEBUG: Parsed SCID Length: $scidLen');
  print('DEBUG: Parsed SCID (Hex): ${HEX.encode(scid)}');
  print('DEBUG: Offset after SCID: $offset');
  offset += scidLen;
  offset += 1;
  print('DEBUG: Offset after skipping SCID & Token Len: $offset');

  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;
  // DEBUG: Verify the parsed length
  print('DEBUG: Parsed Length Field (Decimal): $lengthField');
  print('DEBUG: Packet Number starts at offset: $pnOffset');

  final sampleOffset = 4;
  final sample = Uint8List.view(buffer, pnOffset + sampleOffset, 16);

  final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 1);
  print("protectedPnBytesView: ${HEX.encode(protectedPnBytesView.sublist(0))}");
  print(
    "Header check:   ${HEX.encode(mutablePacket.sublist(0, pnOffset + 1))}",
  );
  // final protectedPnBytesView = Uint8List.view(
  //   Uint8List.fromList([0xb7]).buffer,
  //   0,
  //   1,
  // );

  // DEBUG: Show what's being used for header decryption
  print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

  // final sampled = sampleData.sublist(sampleOffset, sampleOffset + 16);
  // // 5. Encrypt the header and verify its protected parts
  // final protectedHeader = Uint8List.fromList(header);
  // const len = 1;
  // final firstByteViewToProtect = Uint8List.view(protectedHeader.buffer, 0, len);
  // final pnView = Uint8List.view(
  //   protectedHeader.buffer,
  //   protectedHeader.length - len,
  //   len,
  // );

  // sealer.encryptHeader(sampled, firstByteViewToProtect, pnView);
  // print("Protecetd Header:   ${HEX.encode(protectedHeader)}");
  // print("Expected:           ${HEX.encode(expectedHdr)}");
  print("");
  // throw UnimplementedError("thrown intentionally");
  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);
  print("Header:   ${HEX.encode(mutablePacket.sublist(0, pnOffset + 1))}");
  print("Expected: c00000000105735f63696405635f63696400401701");

  final pnLength = (firstByteView[0] & 0x03) + 1;
  print("pnLength: $pnLength");
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  // DEBUG: Verify packet number details
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  print('DEBUG: Decoded Packet Number on the wire: $wirePn');

  print(
    "again Header:   ${HEX.encode(mutablePacket.sublist(0, pnOffset + 1))}",
  );
  print("Expected:       c00000000105735f63696405635f63696400401701");

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final associatedData = Uint8List.view(buffer, 0, payloadOffset);

  // print("header: ${HEX.encode(mutablePacket.sublist(0, payloadOffset))}");

  // This is the line from your code that is causing the error
  final ciphertext = Uint8List.view(
    buffer,
    payloadOffset,
    lengthField - pnLength,
  );

  // DEBUG: CRITICAL CHECK - Inspect the slices right before decryption
  print('DEBUG: Payload starts at offset: $payloadOffset');
  print(
    'DEBUG: Associated Data (Hex): ${HEX.encode(associatedData.sublist(0, min(16, associatedData.length)))}...',
  );
  print('DEBUG: Ciphertext Length: ${ciphertext.length}');
  print(
    'DEBUG: Ciphertext (Hex): ...${HEX.encode(ciphertext.sublist(max(0, ciphertext.length - 16)))}',
  );

  try {
    final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
    print('✅ **Payload decrypted successfully!**');
    print(
      '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...',
    );
    // parsePayload(plaintext);

    // 1. Instantiate the parser with the correct encryption level
    final parser = QuicFrameParser(
      encryptionLevel: 'Initial',
    ); // Or 'Handshake', etc.

    // 2. Call the parse method
    final List<QuicFrame> frames = parser.parse(plaintext);

    // 3. You now have a structured list of frames to work with
    for (final frame in frames) {
      if (frame is CryptoFrame) {
        // Handle the TLS messages found inside
        print('Found TLS messages: ${frame.messages}');
      } else if (frame is AckFrame) {
        // Handle ACK logic
        print('Peer acknowledged up to packet ${frame.largestAcked}');
      }
    }
  } catch (e, s) {
    print('\n❌ ERROR: Decryption failed as expected.');
    print('Exception: $e');
    print('Stack trace:\n$s');
  }
}

void main() {
  // final chBuffer = Buffer(data: ch);
  // final chMsgType = chBuffer.pullUint8();
  // // print("msgType: $msgType");
  // final chLength = chBuffer.pullUint24();
  // final clientHelloBody = chBuffer.pullBytes(chLength);

  // final shBuffer = Buffer(data: sh);
  // final msgType2 = shBuffer.pullUint8();
  // // print("msgType: $msgType");
  // final shLength = shBuffer.pullUint24();
  // final serverHelloBody = shBuffer.pullBytes(shLength);

  // final clientHello = ClientHello.fromBytes(Buffer(data: recv_data));
  // print("certificateVerify: $certificateVerify");
  // final hash = createHash(
  //   Uint8List.fromList([...clientHelloBody, ...serverHelloBody]),
  // );
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

  final decrypter = initialSuite.aead(
    key: client_handshake_key,
    nonceMask: client_handshake_iv,
  );

  final opener = LongHeaderOpener(
    decrypter,
    newHeaderProtector(initialSuite, csecret, true, Version.version1),
  );
  // testClientInitialProtection();
  unprotectAndParseClientHandsakePacket(clientIntialBytes, opener);
}

final clientIntialBytes = Uint8List.fromList([
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
