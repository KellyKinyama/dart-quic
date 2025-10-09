import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'frames/frame_parser.dart';
import 'handshakers/handshake_context.dart';
import 'initial_aead.dart';
import 'payload_parser_final.dart';
import 'protocol.dart';

void unprotectAndParseInitialPacket(Uint8List packetBytes, {HandshakeContext? hc}) {
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
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

  // Skip SCID and Token
  offset += 1 + mutablePacket[offset];
  offset += 1;
  print('DEBUG: Offset after skipping SCID & Token Len: $offset');

  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;
  // DEBUG: Verify the parsed length
  print('DEBUG: Parsed Length Field (Decimal): $lengthField');
  print('DEBUG: Packet Number starts at offset: $pnOffset');

  final (_, opener) = newInitialAEAD(
    dcid,
    Perspective.server,
    Version.version1,
  );

  final sample = Uint8List.view(buffer, pnOffset + 4, 16);
  final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 2);

  // DEBUG: Show what's being used for header decryption
  print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  // DEBUG: Verify packet number details
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  print('DEBUG: Decoded Packet Number on the wire: $wirePn');

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final associatedData = Uint8List.view(buffer, 0, payloadOffset);

  // This is the line from your code that is causing the error
  final ciphertext = Uint8List.view(
    buffer,
    payloadOffset,
    lengthField - pnLength,
  );

  // DEBUG: CRITICAL CHECK - Inspect the slices right before decryption
  print('DEBUG: Payload starts at offset: $payloadOffset');
  print('DEBUG: Associated Data Length: ${associatedData.length}');
  print(
    'DEBUG: Associated Data (Hex): ${HEX.encode(associatedData.sublist(0, min(16, associatedData.length)))}...',
  );
  print('DEBUG: Ciphertext Length: ${ciphertext.length}');
  print(
    'DEBUG: Ciphertext (Hex): ...${HEX.encode(ciphertext.sublist(max(0, ciphertext.length - 16)))}',
  );

  // try {
  final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
  print('✅ **Payload decrypted successfully!**');
  print(
    '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...',
  );
  final decodedFrames = parseQuicFrames(plaintext, hc:hc);
  print('Decoded ${decodedFrames.length} frames:');

  // parsePayload(plaintext);
  // } catch (e, s) {
  //   print('\n❌ ERROR: Decryption failed as expected.');
  //   print('Exception: $e');
  //   print('Stack trace:\n$s');
  // }
}
