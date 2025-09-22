import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

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

// Uint8List testServersInitial() {
//   final connID = Uint8List.fromList(
//     HEX.decode("0001020304050607"),
//   ); //0001020304050607

//   // name:           "QUIC v1",
//   final version = Version.version1;
//   final header = splitHexString("e0 00 00 00 01 05 63 5f 63 69 64 05 73 5f 63 69 64 44 14 00");
//   final data = serverInitialData;
//   final expectedSample = splitHexString("d5d9c823d07c616882ca770279249864");
//   final expectedHdr = splitHexString(
//     "ed 00 00 00 01 05 63 5f 63 69 64 05 73 5f 63 69 64 44 14 b7",
//   );
//   final expectedPacket = serverInitial;

//   // parsePayload(data);

//   // {
//   // 	name:           "QUIC v2",
//   // 	version:        protocol.Version2,
//   // 	header:         splitHexString(t, "d16b3343cf0008f067a5502a4262b50040750001"),
//   // 	data:           splitHexString(t, "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
//   // 	expectedSample: splitHexString(t, "6f05d8a4398c47089698baeea26b91eb"),
//   // 	expectedHdr:    splitHexString(t, "dc6b3343cf0008f067a5502a4262b5004075d92f"),
//   // 	expectedPacket: splitHexString(t, "dc6b3343cf0008f067a5502a4262b500 4075d92faaf16f05d8a4398c47089698 baeea26b91eb761d9b89237bbf872630 17915358230035f7fd3945d88965cf17 f9af6e16886c61bfc703106fbaf3cb4c fa52382dd16a393e42757507698075b2 c984c707f0a0812d8cd5a6881eaf21ce da98f4bd23f6fe1a3e2c43edd9ce7ca8 4bed8521e2e140"),
//   // },

//   print("connID: ${HEX.encode(connID)}");
//   // 1. Create client sealer
//   final (sealer, _) = newInitialAEAD(connID, Perspective.server, version);

//   // 3. Seal the payload
//   final sealed = sealer.seal(data, 0, header);

//   // 4. Extract and verify the sample used for header protection
//   // Note: this test vector uses a simplified sample location (first 16 bytes).
//   final sample = sealed.sublist(3, 3 + 16);
//   // _expectEquals(sample, expectedSample, 'Client Packet Sample');

//   print('Server Packet Sample');
//   print("Got:      ${HEX.encode(sample)}");
//   print("Expected: ${HEX.encode(expectedSample)}");
//   print("");

//   // 5. Encrypt the header and verify its protected parts
//   final protectedHeader = Uint8List.fromList(header);
//   final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
//   final pnView = Uint8List.view(
//     protectedHeader.buffer,
//     protectedHeader.length - 1,
//     1,
//   );
//   sealer.encryptHeader(sample, firstByteView, pnView);

//   print('Protected header');
//   print("Got:      $protectedHeader");
//   print("Expected: $expectedHdr");
//   print("");

//   // 6. Assemble and verify the final, full packet
//   final finalPacket = BytesBuilder()
//     ..add(protectedHeader)
//     ..add(sealed);

//   //  _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
//   print('Final Client Packet');
//   print("Got:      ${HEX.encode(finalPacket.toBytes().sublist(0, 32))}");
//   print("Expected: ${HEX.encode(expectedPacket.sublist(0, 32))}");
//   print("");

//   return finalPacket.toBytes();
// }

void unprotectAndParseServerHandsakePacket(
  Uint8List packetBytes,
  LongHeaderOpener opener,
) {
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
  // final connID = Uint8List.fromList(
  //   HEX.decode("0001020304050607"),
  // ); //0001020304050607

  final sampleData = Uint8List.fromList(
    HEX.decode(
      "dd73ae296209dff2d02d3d50af692176dd4d509fe8cb1b46e45b09364d815fa7a5748e21",
    ),
  );
  final header = Uint8List.fromList(
    HEX.decode("e00000000105635f63696405735f636964441400"),
  );

  final expectedHdr = Uint8List.fromList(
    HEX.decode("ed0000000105635f63696405735f6369644414b7"),
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
  // offset += 1;
  print('DEBUG: Offset after skipping SCID & Token Len: $offset');

  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;
  // DEBUG: Verify the parsed length
  print('DEBUG: Parsed Length Field (Decimal): $lengthField');
  print('DEBUG: Packet Number starts at offset: $pnOffset');

  // final (sealer, opener) = fromHandshakeSecrets(
  //   // connID,
  //   // scid,
  //   Perspective.client,
  //   Version.version1,
  //   clientHelloBytes: ch,
  //   serverHelloBytes: sh,
  // );
  final sampleOffset = 4;
  final sample = Uint8List.view(buffer, pnOffset + sampleOffset, 16);

  print("Sampled:    ${HEX.encode(sample.sublist(0))}");
  print(
    "SampleData: ${HEX.encode(sampleData.sublist(sampleOffset, sampleOffset + 16))}",
  );
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
  print("Expected: e00000000105635f63696405735f636964441400");

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
  print("Expected:       e00000000105635f63696405735f636964441400");

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

// void unprotectAndParseServerHandsakePacket(
//   Uint8List packetBytes,
//   LongHeaderOpener opener,
// ) {
//   print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
//   final mutablePacket = Uint8List.fromList(packetBytes);
//   final buffer = mutablePacket.buffer;
//   int offset = 1 + 4; // Skip first byte and version

//   // DEBUG: Print initial state
//   print('DEBUG: Starting offset: $offset');

//   final dcidLen = mutablePacket[offset];
//   offset += 1;
//   final dcid = Uint8List.view(buffer, offset, dcidLen);
//   offset += dcidLen;
//   // DEBUG: Verify the most critical piece of info: the DCID
//   print('DEBUG: Parsed DCID Length: $dcidLen');
//   print('DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}');
//   print('DEBUG: Offset after DCID: $offset');

//   // Skip SCID and Token
//   offset += 1 + mutablePacket[offset];
//   offset += 1;
//   print('DEBUG: Offset after skipping SCID & Token Len: $offset');

//   final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
//   offset += 2;
//   final pnOffset = offset;
//   // DEBUG: Verify the parsed length
//   print('DEBUG: Parsed Length Field (Decimal): $lengthField');
//   print('DEBUG: Packet Number starts at offset: $pnOffset');

//   // final (_, opener) = newInitialAEAD(
//   //   dcid,
//   //   Perspective.server,
//   //   Version.version1,
//   // );

//   final sample = Uint8List.view(buffer, pnOffset + 3, 16);
//   final firstByteView = Uint8List.view(buffer, 0, 1);
//   final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 1);
//   print("Header: ${HEX.encode(mutablePacket.sublist(0, pnOffset))}");
//   // print("protectedPnBytesView: ${HEX.encode(protectedPnBytesView)}");
//   // DEBUG: Show what's being used for header decryption
//   // print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

//   opener.decryptHeader(sample, firstByteView, protectedPnBytesView);
//   print("Decrypted header: ${HEX.encode(mutablePacket.sublist(0, pnOffset))}");
//   print("Expected: e00000000105635f63696405735f636964441400");
//   final pnLength = (firstByteView[0] & 0x03) + 1;
//   int wirePn = 0;
//   for (int i = 0; i < pnLength; i++) {
//     wirePn = (wirePn << 8) | protectedPnBytesView[i];
//   }
//   // DEBUG: Verify packet number details
//   print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
//   print('DEBUG: Decoded Packet Number on the wire: $wirePn');

//   final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
//   final payloadOffset = pnOffset + pnLength;
//   final associatedData = Uint8List.view(buffer, 0, payloadOffset);

//   // This is the line from your code that is causing the error
//   final ciphertext = Uint8List.view(
//     buffer,
//     payloadOffset,
//     lengthField - pnLength,
//   );

//   // DEBUG: CRITICAL CHECK - Inspect the slices right before decryption
//   print('DEBUG: Payload starts at offset: $payloadOffset');
//   print('DEBUG: Associated Data Length: ${associatedData.length}');
//   print(
//     'DEBUG: Associated Data (Hex): ${HEX.encode(associatedData.sublist(0, min(16, associatedData.length)))}...',
//   );
//   print('DEBUG: Ciphertext Length: ${ciphertext.length}');
//   print(
//     'DEBUG: Ciphertext (Hex): ...${HEX.encode(ciphertext.sublist(max(0, ciphertext.length - 16)))}',
//   );

//   try {
//     final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
//     print('✅ **Payload decrypted successfully!**');
//     print(
//       '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...',
//     );
//   } catch (e, s) {
//     print('\n❌ ERROR: Decryption failed as expected.');
//     print('Exception: $e');
//     print('Stack trace:\n$s');
//   }
// }

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
    key: server_handshake_key,
    nonceMask: server_handshake_iv,
  );

  final opener = LongHeaderOpener(
    decrypter,
    newHeaderProtector(initialSuite, ssecret, true, Version.version1),
  );

  unprotectAndParseServerHandsakePacket(handshakeBytes, opener);
}

// hello_hash=ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b
// shared_secret=df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624
// zero_key=0000000000000000000000000000000000000000000000000000000000000000
// early_secret=$(./hkdf extract 00 $zero_key)
// empty_hash=$(openssl sha256 < /dev/null | sed -e 's/.* //')
// derived_secret=$(./hkdf expandlabel $early_secret "derived" $empty_hash 32)
// handshake_secret=$(./hkdf extract $derived_secret $shared_secret)
// csecret=$(./hkdf expandlabel $handshake_secret "c hs traffic" $hello_hash 32)
// ssecret=$(./hkdf expandlabel $handshake_secret "s hs traffic" $hello_hash 32)
// client_handshake_key=$(./hkdf expandlabel $csecret "quic key" "" 16)
// server_handshake_key=$(./hkdf expandlabel $ssecret "quic key" "" 16)
// client_handshake_iv=$(./hkdf expandlabel $csecret "quic iv" "" 12)
// server_handshake_iv=$(./hkdf expandlabel $ssecret "quic iv" "" 12)
// client_handshake_hp=$(./hkdf expandlabel $csecret "quic hp" "" 16)
// server_handshake_hp=$(./hkdf expandlabel $ssecret "quic hp" "" 16)
// echo ckey: $client_handshake_key
// echo civ: $client_handshake_iv
// echo chp: $client_handshake_hp
// echo skey: $server_handshake_key
// echo siv: $server_handshake_iv
// echo shp: $server_handshake_hp
// ckey: 30a7e816f6a1e1b3434cf39cf4b415e7
// civ: 11e70a5d1361795d2bb04465
// chp: 84b3c21cacaf9f54c885e9a506459079
// skey: 17abbf0a788f96c6986964660414e7ec
// siv: 09597a2ea3b04c00487e71f3
// shp: 2a18061c396c2828582b41b0910ed536
// early_secret = HKDF-Extract(salt=00, key=00...)
// empty_hash = SHA256("")
// derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 32)
// handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
// client_secret = HKDF-Expand-Label(key: handshake_secret, label: "c hs traffic", ctx: hello_hash, len: 32)
// server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 32)
// client_key = HKDF-Expand-Label(key: client_secret, label: "quic key", ctx: "", len: 16)
// server_key = HKDF-Expand-Label(key: server_secret, label: "quic key", ctx: "", len: 16)
// client_iv = HKDF-Expand-Label(key: client_secret, label: "quic iv", ctx: "", len: 12)
// server_iv = HKDF-Expand-Label(key: server_secret, label: "quic iv", ctx: "", len: 12)

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

final handshakeBytes = Uint8List.fromList([
  0xed,
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
  0x44,
  0x14,
  0xb7,
  0xdd,
  0x73,
  0xae,
  0x29,
  0x62,
  0x09,
  0xdf,
  0xf2,
  0xd0,
  0x2d,
  0x3d,
  0x50,
  0xaf,
  0x69,
  0x21,
  0x76,
  0xdd,
  0x4d,
  0x50,
  0x9f,
  0xe8,
  0xcb,
  0x1b,
  0x46,
  0xe4,
  0x5b,
  0x09,
  0x36,
  0x4d,
  0x81,
  0x5f,
  0xa7,
  0xa5,
  0x74,
  0x8e,
  0x21,
  0x80,
  0xda,
  0xd2,
  0xb7,
  0xb6,
  0x68,
  0xca,
  0xb8,
  0x6f,
  0xbd,
  0xc2,
  0x98,
  0x8c,
  0x45,
  0xcb,
  0xb8,
  0x51,
  0xdd,
  0xcf,
  0x16,
  0x01,
  0xb7,
  0x80,
  0xd7,
  0x48,
  0xb9,
  0xee,
  0x64,
  0x1e,
  0xbc,
  0xbe,
  0x20,
  0x12,
  0x6e,
  0x32,
  0x26,
  0x7e,
  0x66,
  0x4d,
  0x2f,
  0x37,
  0xcf,
  0x53,
  0xb7,
  0x53,
  0xd1,
  0x24,
  0x71,
  0x7c,
  0x2e,
  0x13,
  0xc4,
  0x8a,
  0x09,
  0xe3,
  0x42,
  0x8b,
  0x11,
  0xdc,
  0x73,
  0xba,
  0xeb,
  0xd4,
  0x98,
  0xe8,
  0xca,
  0xf5,
  0xbe,
  0xce,
  0xfe,
  0xa7,
  0x60,
  0xd0,
  0xe7,
  0xa5,
  0xcd,
  0xb7,
  0x6b,
  0x52,
  0xbc,
  0xb1,
  0x92,
  0x29,
  0x97,
  0x3e,
  0x5d,
  0x09,
  0xaa,
  0x05,
  0x5e,
  0x9c,
  0x97,
  0x18,
  0xdc,
  0x58,
  0x14,
  0x54,
  0x77,
  0x5c,
  0x58,
  0xec,
  0xdd,
  0x5e,
  0xe7,
  0xe7,
  0x72,
  0x78,
  0xf5,
  0x60,
  0x10,
  0x70,
  0x40,
  0x41,
  0x62,
  0xa7,
  0x9e,
  0xe8,
  0xc5,
  0x96,
  0x45,
  0xd6,
  0xca,
  0x24,
  0xa2,
  0x00,
  0x18,
  0x6a,
  0xe9,
  0x9c,
  0xe4,
  0x7e,
  0xac,
  0xe1,
  0xcf,
  0xc9,
  0x52,
  0x7b,
  0x24,
  0xae,
  0x8b,
  0xc6,
  0xcc,
  0xdb,
  0xac,
  0xb7,
  0x9b,
  0x81,
  0xc9,
  0x1a,
  0x26,
  0x95,
  0x47,
  0x07,
  0xba,
  0x35,
  0xcb,
  0xa0,
  0xca,
  0xe9,
  0xaf,
  0xf4,
  0x18,
  0xc6,
  0xe0,
  0x8d,
  0xa6,
  0x50,
  0x61,
  0x63,
  0xa3,
  0x9f,
  0x19,
  0xb6,
  0x76,
  0xa6,
  0x6a,
  0xc1,
  0x74,
  0xe3,
  0x29,
  0x5f,
  0x1a,
  0xb9,
  0xea,
  0x73,
  0x83,
  0xa9,
  0xc2,
  0x85,
  0xd7,
  0x3e,
  0x95,
  0x75,
  0x8d,
  0xc9,
  0xbd,
  0x8d,
  0xa9,
  0x07,
  0x34,
  0xa9,
  0xfe,
  0xdf,
  0xd7,
  0xe1,
  0xf7,
  0x4d,
  0x2b,
  0x69,
  0xc7,
  0x0b,
  0xf7,
  0x39,
  0xa4,
  0x8c,
  0x5a,
  0x5d,
  0x0a,
  0xfa,
  0x0b,
  0xfa,
  0x16,
  0x03,
  0x47,
  0x1b,
  0x0c,
  0x61,
  0xa9,
  0xca,
  0xde,
  0x12,
  0x0b,
  0x39,
  0x86,
  0xa6,
  0xce,
  0x02,
  0x95,
  0xbe,
  0x82,
  0x28,
  0xc6,
  0x92,
  0x70,
  0x13,
  0xb0,
  0x6d,
  0xa5,
  0x8d,
  0x31,
  0x99,
  0x62,
  0x31,
  0xb9,
  0xe3,
  0x15,
  0x0b,
  0xb5,
  0x82,
  0x70,
  0x96,
  0x0e,
  0x61,
  0xcb,
  0xc6,
  0x69,
  0x8a,
  0x2f,
  0x13,
  0x79,
  0xa2,
  0x25,
  0x84,
  0x65,
  0xda,
  0x73,
  0x25,
  0xb3,
  0x49,
  0xc6,
  0xcd,
  0x55,
  0xd1,
  0x05,
  0xfd,
  0x54,
  0x85,
  0xfd,
  0x0a,
  0xc7,
  0x9a,
  0x1d,
  0xf1,
  0xdb,
  0xba,
  0x7f,
  0x85,
  0xb4,
  0x9b,
  0x72,
  0x36,
  0x5b,
  0xfa,
  0xb9,
  0xd5,
  0x78,
  0xe0,
  0x1d,
  0xcb,
  0xff,
  0x85,
  0x15,
  0xa6,
  0x32,
  0xfd,
  0x70,
  0x01,
  0x38,
  0x2e,
  0xd9,
  0x0f,
  0x6c,
  0xdc,
  0xb1,
  0x7d,
  0xb9,
  0x9a,
  0x33,
  0xfa,
  0x11,
  0x81,
  0xf6,
  0xf6,
  0x1a,
  0x89,
  0xe7,
  0x83,
  0xcf,
  0xb0,
  0x42,
  0xfc,
  0x0f,
  0x2f,
  0x67,
  0xcd,
  0xb6,
  0x0e,
  0x89,
  0xf2,
  0x63,
  0x88,
  0x56,
  0x81,
  0xae,
  0x64,
  0x5a,
  0x1c,
  0x7a,
  0xb1,
  0x59,
  0x0e,
  0xb2,
  0xf8,
  0x46,
  0x9f,
  0x46,
  0x0f,
  0x04,
  0xe0,
  0x9f,
  0xea,
  0x2a,
  0x3a,
  0x41,
  0x1b,
  0x49,
  0x86,
  0x63,
  0x01,
  0x0b,
  0x3c,
  0x38,
  0x2a,
  0x3f,
  0x25,
  0x83,
  0x7c,
  0x2c,
  0x70,
  0x86,
  0xaf,
  0x5a,
  0x9a,
  0xd2,
  0x90,
  0xcf,
  0x3c,
  0xcf,
  0x1a,
  0xc6,
  0xeb,
  0x0f,
  0x44,
  0x55,
  0x35,
  0xe8,
  0xb0,
  0x0a,
  0x55,
  0x7c,
  0x87,
  0xa5,
  0x3d,
  0x93,
  0x07,
  0x14,
  0x62,
  0xa0,
  0xbc,
  0x22,
  0x61,
  0x4e,
  0x5c,
  0x3a,
  0xe0,
  0x84,
  0x17,
  0xb7,
  0x20,
  0xa7,
  0x36,
  0xc1,
  0xad,
  0x48,
  0xea,
  0x37,
  0x75,
  0xcd,
  0x0f,
  0x00,
  0x9f,
  0x0c,
  0x57,
  0x50,
  0x0e,
  0x0b,
  0xb2,
  0xe7,
  0xe9,
  0xc5,
  0x3f,
  0x83,
  0x69,
  0x9a,
  0x47,
  0xe5,
  0xf1,
  0x3b,
  0xb2,
  0x07,
  0x72,
  0xab,
  0x23,
  0x50,
  0x64,
  0x24,
  0xb7,
  0x6f,
  0x6e,
  0xf9,
  0x6a,
  0x61,
  0xc9,
  0x17,
  0x22,
  0x6e,
  0x6e,
  0x04,
  0x8d,
  0xe6,
  0xf8,
  0x24,
  0x26,
  0xca,
  0x63,
  0xea,
  0xbf,
  0x3b,
  0x59,
  0x43,
  0xaf,
  0x0b,
  0x5f,
  0x0d,
  0x12,
  0x3d,
  0x9a,
  0xf0,
  0x45,
  0xbb,
  0x35,
  0x7c,
  0xad,
  0xbd,
  0x10,
  0x92,
  0xad,
  0x0a,
  0x1d,
  0x75,
  0x51,
  0x16,
  0x2a,
  0x3b,
  0x4b,
  0x48,
  0x6c,
  0x27,
  0x1e,
  0x00,
  0x24,
  0x4b,
  0x23,
  0xd8,
  0xad,
  0xec,
  0x81,
  0xc9,
  0x2e,
  0x31,
  0x23,
  0x9c,
  0x75,
  0xaf,
  0x41,
  0xcb,
  0x07,
  0x98,
  0x08,
  0x57,
  0x1b,
  0x48,
  0xac,
  0xb5,
  0x07,
  0x33,
  0x3f,
  0xfb,
  0xf1,
  0xa4,
  0x86,
  0xd8,
  0x05,
  0x3e,
  0xdc,
  0xc8,
  0x62,
  0xb6,
  0xa9,
  0xbf,
  0xd3,
  0x6a,
  0x09,
  0xcd,
  0xdb,
  0xa3,
  0x29,
  0x1b,
  0x9b,
  0x8b,
  0xa1,
  0x58,
  0x49,
  0x34,
  0x59,
  0x80,
  0x5c,
  0xe2,
  0x41,
  0xda,
  0xf5,
  0xc1,
  0x30,
  0x85,
  0x99,
  0xfc,
  0x0e,
  0x6e,
  0x6e,
  0xa7,
  0x10,
  0x30,
  0x33,
  0xb2,
  0x94,
  0xcc,
  0x7a,
  0x5f,
  0xdb,
  0x2d,
  0x46,
  0x54,
  0xf1,
  0xd4,
  0x40,
  0x78,
  0x25,
  0xeb,
  0xc3,
  0x75,
  0xab,
  0xdf,
  0xb2,
  0xcc,
  0xa1,
  0xab,
  0xf5,
  0xa2,
  0x41,
  0x34,
  0x3d,
  0xec,
  0x3b,
  0x16,
  0x5d,
  0x32,
  0x0a,
  0xf8,
  0x4b,
  0xc1,
  0xfa,
  0x21,
  0x11,
  0x2e,
  0xfd,
  0xb9,
  0xd4,
  0x5c,
  0x6c,
  0xfc,
  0x7b,
  0x8a,
  0x64,
  0x42,
  0xff,
  0x59,
  0x3d,
  0x09,
  0x21,
  0x93,
  0x36,
  0xfa,
  0x07,
  0x56,
  0xd9,
  0xe4,
  0x5b,
  0xab,
  0x4f,
  0xa6,
  0x33,
  0x94,
  0xa2,
  0xa8,
  0x80,
  0x3d,
  0xf4,
  0x67,
  0x8e,
  0x79,
  0x21,
  0x6f,
  0xdf,
  0x13,
  0x1f,
  0x55,
  0x82,
  0x2f,
  0x9e,
  0xad,
  0x69,
  0x4a,
  0xb7,
  0x5e,
  0xe2,
  0x54,
  0x96,
  0xe6,
  0xb7,
  0x8c,
  0x3b,
  0x09,
  0x04,
  0x66,
  0x58,
  0xe2,
  0xc4,
  0x27,
  0xdd,
  0xc4,
  0x53,
  0x8a,
  0xf8,
  0xde,
  0x2a,
  0xcb,
  0x81,
  0x39,
  0x8b,
  0x74,
  0x82,
  0x83,
  0x37,
  0xf2,
  0x69,
  0xcb,
  0x03,
  0x1d,
  0x99,
  0x7a,
  0x5c,
  0xf6,
  0x3e,
  0x11,
  0xab,
  0x05,
  0x0a,
  0xa8,
  0xae,
  0xe1,
  0xf0,
  0x79,
  0x62,
  0xdd,
  0xd7,
  0x51,
  0x5a,
  0xb6,
  0x0e,
  0x19,
  0x2e,
  0x40,
  0x3c,
  0x30,
  0x03,
  0x11,
  0xe9,
  0xe4,
  0xb9,
  0xb7,
  0x0f,
  0x16,
  0x15,
  0x02,
  0x9d,
  0x07,
  0xfe,
  0x1c,
  0x23,
  0x19,
  0x39,
  0x02,
  0x71,
  0x49,
  0xf4,
  0xfd,
  0x29,
  0x72,
  0x02,
  0x3a,
  0x55,
  0xde,
  0x29,
  0x35,
  0x65,
  0x05,
  0xfb,
  0xe7,
  0x49,
  0x90,
  0x8c,
  0x62,
  0xaa,
  0x33,
  0xeb,
  0x25,
  0x9a,
  0x39,
  0x9b,
  0xf7,
  0x11,
  0xb9,
  0x2b,
  0x61,
  0x6c,
  0xb7,
  0x48,
  0xde,
  0x73,
  0xc8,
  0xbf,
  0xad,
  0xd5,
  0xd4,
  0x3e,
  0x2d,
  0xae,
  0x91,
  0x6a,
  0x7b,
  0xa0,
  0xdb,
  0x61,
  0xdf,
  0xcd,
  0x6f,
  0xaf,
  0x95,
  0x76,
  0x08,
  0x26,
  0x2b,
  0x68,
  0x34,
  0xe3,
  0x31,
  0x85,
  0xb8,
  0xd5,
  0x59,
  0x8f,
  0x87,
  0xe6,
  0x99,
  0x2a,
  0xac,
  0xf5,
  0x76,
  0x96,
  0xad,
  0xd5,
  0x55,
  0x8a,
  0x7d,
  0x96,
  0x94,
  0x38,
  0x1f,
  0x5d,
  0x7d,
  0x65,
  0x9d,
  0xa2,
  0xde,
  0x95,
  0x1b,
  0x60,
  0x74,
  0x78,
  0xf6,
  0x1d,
  0xa2,
  0x08,
  0xa2,
  0x4a,
  0x07,
  0xba,
  0x8d,
  0xa0,
  0x02,
  0x58,
  0xfa,
  0x7f,
  0x2f,
  0xe1,
  0x0d,
  0xef,
  0x61,
  0x83,
  0x26,
  0x7f,
  0x5d,
  0x38,
  0xe0,
  0x4c,
  0x94,
  0x23,
  0x00,
  0xb9,
  0xc8,
  0x74,
  0xe8,
  0x98,
  0x3c,
  0x1b,
  0xe1,
  0x4e,
  0x16,
  0x08,
  0xff,
  0xdc,
  0xa6,
  0x7d,
  0x7e,
  0x45,
  0x13,
  0xcc,
  0x0c,
  0xb9,
  0xca,
  0xb8,
  0x1d,
  0x63,
  0x19,
  0xdd,
  0x10,
  0x74,
  0xb2,
  0x17,
  0xe5,
  0x19,
  0x54,
  0x65,
  0x13,
  0x1e,
  0x06,
  0xdd,
  0x0b,
  0xaf,
  0xab,
  0xa8,
  0x4e,
  0xb5,
  0x2c,
  0x22,
  0xa4,
  0xa8,
  0xc6,
  0x12,
  0xa4,
  0x05,
  0xfe,
  0x6c,
  0x87,
  0x42,
  0x32,
  0xe4,
  0xa9,
  0x34,
  0x61,
  0x1b,
  0xc7,
  0x3c,
  0x56,
  0xfe,
  0x70,
  0xb2,
  0xcb,
  0x7a,
  0x59,
  0x6c,
  0x1f,
  0x53,
  0xc7,
  0x29,
  0xb6,
  0x64,
  0x3c,
  0xbd,
  0x70,
  0xd5,
  0x30,
  0xfe,
  0x31,
  0x96,
  0x06,
  0x9f,
  0xc0,
  0x07,
  0x8e,
  0x89,
  0xfb,
  0xb7,
  0x0d,
  0xc1,
  0xb3,
  0x8a,
  0xb4,
  0xe1,
  0x77,
  0x0c,
  0x8f,
  0xfb,
  0x53,
  0x31,
  0x6d,
  0x67,
  0x3a,
  0x32,
  0xb8,
  0x92,
  0x59,
  0xb5,
  0xd3,
  0x3e,
  0x94,
  0xad,
]);
