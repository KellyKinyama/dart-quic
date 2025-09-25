import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'aead.dart';
import 'buffer.dart';
import 'initial_aead.dart';
import 'protocol.dart';

const PACKET_LONG_HEADER = 0x80;
const packetFixedBit = 0x40;
const connectionIdMaxSize = 20;

enum QuicPacketType {
  initial,
  zeroRtt,
  handshake,
  retry,
  versionNegotiation,
  oneRtt,
}

const Map<int, QuicPacketType> packetLongTypeDecodeVersion1 = {
  0: QuicPacketType.initial,
  1: QuicPacketType.zeroRtt,
  2: QuicPacketType.handshake,
  3: QuicPacketType.retry,
};

void parseQuicPacket(
  Uint8List packetBytes,
  Perspective perspective, {
  LongHeaderOpener? opener, // Optional opener for pre-computed keys
  int packNumLength = 4,
}) {
  final Buffer buf = Buffer(data: packetBytes);
  final firstByteView = Uint8List.view(packetBytes.buffer, 0, 1);
  final firstByte = buf.pullUint8();

  if ((firstByte & PACKET_LONG_HEADER) == 0) {
    print("✅ Detected Short Header (1-RTT) packet.");
    // TODO: Implement Short Header parsing and decryption here.
    return;
  }

  // --- Long Header Parsing ---
  final version = buf.pullUint32();
  if (version == 0x00000000) {
    print("✅ Detected Version Negotiation packet.");
    // TODO: Implement Version Negotiation parsing.
    return;
  }

  final dcidLen = buf.pullUint8();
  final dcid = buf.pullBytes(dcidLen);
  final scidLen = buf.pullUint8();
  buf.pullBytes(scidLen); // We only need the dcid for Initial keys

  final longType = (firstByte & 0x30) >> 4;
  final packetType = packetLongTypeDecodeVersion1[longType];

  if (packetType == null) {
    throw Exception("Unknown long packet type: $longType");
  }
  print("✅ Detected Long Header Packet Type: $packetType");

  // --- Type-Specific Field Parsing (The only part that differs) ---
  switch (packetType) {
    case QuicPacketType.initial:
      // Initial packets contain a Token. This is the path your working code uses.
      final tokenLen = buf.pullVarInt();
      buf.pullBytes(tokenLen);
      break;

    case QuicPacketType.handshake:
    case QuicPacketType.zeroRtt:
      // Handshake and 0-RTT packets DO NOT have a Token. We do nothing here.
      break;

    case QuicPacketType.retry:
      print("✅ Parsed Retry Packet.");
      // Retry packets have a different structure and no encrypted payload.
      return;

    default:
      throw Exception("Unsupported packet type for decryption: $packetType");
  }

  // --- Header Unprotection and Payload Decryption (Common Logic) ---
  // The following logic is the exact implementation that you confirmed works.

  final payloadFieldLength = buf.pullVarInt();
  final pnOffset = buf.tell();

  // --- NEW LOGIC: Use provided opener or derive a new one ---
  final LongHeaderOpener finalOpener;
  if (opener != null) {
    print("info: Using provided opener for Handshake keys.");
    finalOpener = opener;
  } else {
    print("info: No opener provided, deriving Initial keys.");
    final (_, derivedOpener) = newInitialAEAD(
      dcid,
      perspective,
      Version.fromValue(version),
    );
    finalOpener = derivedOpener;
  }
  // --- END NEW LOGIC ---

  final sampleOffset = pnOffset + 4;

  if (packetBytes.length < sampleOffset + 16) {
    throw Exception("Packet too short for header protection sample.");
  }

  final sample = Uint8List.view(packetBytes.buffer, sampleOffset, 16);
  final protectedPnBytesView = Uint8List.view(
    packetBytes.buffer,
    pnOffset,
    packNumLength,
  );

  // NOTE: This is a critical point. For a real connection, you must select the keys
  // based on the encryption level (Initial, Handshake, 1-RTT).
  // This example correctly uses Initial keys for an Initial packet.
  // final (_, opener) = newInitialAEAD(dcid, perspective, Version.version1);

  finalOpener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }

  final fullPacketNumber = finalOpener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final ciphertextLength = payloadFieldLength - pnLength;
  final associatedData = Uint8List.view(packetBytes.buffer, 0, payloadOffset);
  final ciphertext = Uint8List.view(
    packetBytes.buffer,
    payloadOffset,
    ciphertextLength,
  );

  try {
    final plaintext = finalOpener.open(
      ciphertext,
      fullPacketNumber,
      associatedData,
    );
    print('✅ **Payload decrypted successfully!**');
    print(
      '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, min(32, plaintext.length)))}"...',
    );
  } catch (e) {
    print('\n❌ ERROR: Decryption failed.');
    print('Exception: $e');
  }
}
