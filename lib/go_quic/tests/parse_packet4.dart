import 'dart:math';
import 'dart:typed_data';
import 'package:hex/hex.dart';

import '../initial_aead.dart';
import '../payload_parser9.dart';
import '../protocol.dart';

// #############################################################################
// ## SECTION 1: CRYPTOGRAPHIC AND UTILITY HELPERS
// #############################################################################

/// A robust buffer to read data sequentially from a Uint8List.
class Buffer {
  final ByteData _byteData;
  int _readOffset = 0;
  int get length => _byteData.lengthInBytes;
  bool get eof => _readOffset >= length;
  int get remaining => length - _readOffset;

  Buffer({required Uint8List data})
    : _byteData = data.buffer.asByteData(
        data.offsetInBytes,
        data.lengthInBytes,
      );

  int pullUint8() {
    final v = _byteData.getUint8(_readOffset);
    _readOffset += 1;
    return v;
  }

  int pullUint16() {
    final v = _byteData.getUint16(_readOffset);
    _readOffset += 2;
    return v;
  }

  int pullUint24() {
    final h = pullUint8();
    final l = pullUint16();
    return (h << 16) | l;
  }

  Uint8List pullBytes(int len) {
    if (_readOffset + len > length) throw Exception('Buffer underflow');
    final b = _byteData.buffer.asUint8List(
      _byteData.offsetInBytes + _readOffset,
      len,
    );
    _readOffset += len;
    return b;
  }

  Uint8List pullVector(int lenBytes) {
    int vecLen;
    if (lenBytes == 1) {
      vecLen = pullUint8();
    } else if (lenBytes == 2)
      vecLen = pullUint16();
    else
      throw ArgumentError('Vector length must be 1 or 2 bytes');
    return pullBytes(vecLen);
  }

  int pullVarInt() {
    final firstByte = _byteData.getUint8(_readOffset);
    final prefix = firstByte >> 6;
    final len = 1 << prefix;
    if (_readOffset + len > length) {
      throw Exception('VarInt read would overflow buffer');
    }
    int val = firstByte & 0x3F;
    for (int i = 1; i < len; i++) {
      val = (val << 8) | _byteData.getUint8(_readOffset + i);
    }
    _readOffset += len;
    return val;
  }
}

void parseQuicPayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = Buffer(data: plaintextPayload);
  try {
    while (!buffer.eof) {
      if (buffer._byteData.getUint8(buffer._readOffset) == 0) {
        buffer.pullUint8();
        continue; // PADDING
      }
      final frameType = buffer.pullVarInt();
      switch (frameType) {
        case 0x06: // CRYPTO Frame
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
          final cryptoData = buffer.pullBytes(length);
          final tlsMessages = parseTlsMessages(cryptoData);
          final frame = CryptoFrame(offset, length, tlsMessages);
          print('✅ Parsed QUIC Frame: $frame');
          break;
        default:
          print(
            'ℹ️ Skipping unknown frame type 0x${frameType.toRadixString(16)}',
          );
          return;
      }
    }
  } catch (e, st) {
    print('\n🛑 An error occurred during payload parsing: $e');
    print(st);
  }
}

// #############################################################################
// ## SECTION 4: MAIN PARSING WORKFLOW
// #############################################################################

// void unprotectAndParseInitialPacket(Uint8List packetBytes) {
//   print('\n--- Parsing QUIC Initial Packet ---');
//   final buffer = Buffer(data: packetBytes);

//   // 1. Parse the header fields
//   final firstByte = buffer.pullUint8();
//   if ((firstByte & 0x80) == 0) throw Exception('Not a long header packet');

//   buffer.pullBytes(4); // Skip version

//   final dcidLen = buffer.pullUint8();
//   final dcid = buffer.pullBytes(dcidLen);
//   print("Destination Connection ID: ${HEX.encode(dcid)}");

//   final scidLen = buffer.pullUint8();
//   buffer.pullBytes(scidLen); // Skip SCID

//   final tokenLen = buffer.pullVarInt();
//   buffer.pullBytes(tokenLen); // Skip Token

//   final lengthField = buffer.pullVarInt();
//   final pnOffset = buffer._readOffset;

//   // Create a mutable copy of the header for in-place decryption
//   final headerToDecrypt = Uint8List.fromList(
//     packetBytes.sublist(0, pnOffset + 4),
//   );

//   // 2. Remove Header Protection
//   final (_, opener) = newInitialAEAD(dcid);
//   final payloadToSample = Uint8List.view(
//     packetBytes.buffer,
//     packetBytes.offsetInBytes + pnOffset + 4,
//   );
//   opener.decryptHeader(headerToDecrypt, payloadToSample);

//   // 3. Decode the Packet Number
//   final pnLength = (headerToDecrypt[0] & 0x03) + 1;
//   int wirePn = 0;
//   for (int i = 0; i < pnLength; i++) {
//     wirePn = (wirePn << 8) | headerToDecrypt[pnOffset + i];
//   }
//   final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
//   print("Decoded Packet Number: $fullPacketNumber (length: $pnLength bytes)");

//   // 4. Decrypt the Payload
//   final payloadOffset = pnOffset + pnLength;
//   final associatedData = Uint8List.view(packetBytes.buffer, 0, payloadOffset);
//   final ciphertext = Uint8List.view(
//     packetBytes.buffer,
//     payloadOffset,
//     lengthField - pnLength,
//   );

//   final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
//   print('✅ **Payload decrypted successfully!** (${plaintext.length} bytes)');

//   // 5. Parse the inner QUIC frames and TLS messages
//   parseQuicPayload(plaintext);
// }

void unprotectAndParseInitialPacket(Uint8List packetBytes) {
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version
  // final quicHeader = pullQuicHeader(Buffer(data: quicIntialPacket));
  // print("Packet number length: ${quicHeader.p}")

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
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 1);

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

  try {
    final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
    print('✅ **Payload decrypted successfully!**');
    print(
      '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...',
    );
    parseQuicPayload(plaintext);
  } catch (e, s) {
    print('\n❌ ERROR: Decryption failed as expected.');
    print('Exception: $e');
    print('Stack trace:\n$s');
  }
}

void main() {
  // The sample QUIC Initial Packet you provided
  final quicInitialPacket = Uint8List.fromList([
    0xcd,
    0x00,
    0x00,
    0x00,
    0x01,
    0x08,
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x05,
    0x63,
    0x5f,
    0x63,
    0x69,
    0x64,
    0x00,
    0x41,
    0x03,
    0x98,
    0x1c,
    0x36,
    0xa7,
    0xed,
    0x78,
    0x71,
    0x6b,
    0xe9,
    0x71,
    0x1b,
    0xa4,
    0x98,
    0xb7,
    0xed,
    0x86,
    0x84,
    0x43,
    0xbb,
    0x2e,
    0x0c,
    0x51,
    0x4d,
    0x4d,
    0x84,
    0x8e,
    0xad,
    0xcc,
    0x7a,
    0x00,
    0xd2,
    0x5c,
    0xe9,
    0xf9,
    0xaf,
    0xa4,
    0x83,
    0x97,
    0x80,
    0x88,
    0xde,
    0x83,
    0x6b,
    0xe6,
    0x8c,
    0x0b,
    0x32,
    0xa2,
    0x45,
    0x95,
    0xd7,
    0x81,
    0x3e,
    0xa5,
    0x41,
    0x4a,
    0x91,
    0x99,
    0x32,
    0x9a,
    0x6d,
    0x9f,
    0x7f,
    0x76,
    0x0d,
    0xd8,
    0xbb,
    0x24,
    0x9b,
    0xf3,
    0xf5,
    0x3d,
    0x9a,
    0x77,
    0xfb,
    0xb7,
    0xb3,
    0x95,
    0xb8,
    0xd6,
    0x6d,
    0x78,
    0x79,
    0xa5,
    0x1f,
    0xe5,
    0x9e,
    0xf9,
    0x60,
    0x1f,
    0x79,
    0x99,
    0x8e,
    0xb3,
    0x56,
    0x8e,
    0x1f,
    0xdc,
    0x78,
    0x9f,
    0x64,
    0x0a,
    0xca,
    0xb3,
    0x85,
    0x8a,
    0x82,
    0xef,
    0x29,
    0x30,
    0xfa,
    0x5c,
    0xe1,
    0x4b,
    0x5b,
    0x9e,
    0xa0,
    0xbd,
    0xb2,
    0x9f,
    0x45,
    0x72,
    0xda,
    0x85,
    0xaa,
    0x3d,
    0xef,
    0x39,
    0xb7,
    0xef,
    0xaf,
    0xff,
    0xa0,
    0x74,
    0xb9,
    0x26,
    0x70,
    0x70,
    0xd5,
    0x0b,
    0x5d,
    0x07,
    0x84,
    0x2e,
    0x49,
    0xbb,
    0xa3,
    0xbc,
    0x78,
    0x7f,
    0xf2,
    0x95,
    0xd6,
    0xae,
    0x3b,
    0x51,
    0x43,
    0x05,
    0xf1,
    0x02,
    0xaf,
    0xe5,
    0xa0,
    0x47,
    0xb3,
    0xfb,
    0x4c,
    0x99,
    0xeb,
    0x92,
    0xa2,
    0x74,
    0xd2,
    0x44,
    0xd6,
    0x04,
    0x92,
    0xc0,
    0xe2,
    0xe6,
    0xe2,
    0x12,
    0xce,
    0xf0,
    0xf9,
    0xe3,
    0xf6,
    0x2e,
    0xfd,
    0x09,
    0x55,
    0xe7,
    0x1c,
    0x76,
    0x8a,
    0xa6,
    0xbb,
    0x3c,
    0xd8,
    0x0b,
    0xbb,
    0x37,
    0x55,
    0xc8,
    0xb7,
    0xeb,
    0xee,
    0x32,
    0x71,
    0x2f,
    0x40,
    0xf2,
    0x24,
    0x51,
    0x19,
    0x48,
    0x70,
    0x21,
    0xb4,
    0xb8,
    0x4e,
    0x15,
    0x65,
    0xe3,
    0xca,
    0x31,
    0x96,
    0x7a,
    0xc8,
    0x60,
    0x4d,
    0x40,
    0x32,
    0x17,
    0x0d,
    0xec,
    0x28,
    0x0a,
    0xee,
    0xfa,
    0x09,
    0x5d,
    0x08,
    0xb3,
    0xb7,
    0x24,
    0x1e,
    0xf6,
    0x64,
    0x6a,
    0x6c,
    0x86,
    0xe5,
    0xc6,
    0x2c,
    0xe0,
    0x8b,
    0xe0,
    0x99,
  ]);

  // Make sure you have pointycastle in your pubspec.yaml:
  // dependencies:
  //   pointycastle: ^3.0.0
  unprotectAndParseInitialPacket(quicInitialPacket);
}

// Helper Maps for readable output
const Map<int, String> _handshakeTypeMap = {1: 'ClientHello'};
const Map<int, String> _extensionTypesMap = {
  // Add common extensions if needed for detailed ClientHello parsing
};
