import 'dart:typed_data';
import 'package:test/test.dart';

import '../flow_control/frame.dart';
import '../flow_control/quic_ack_frame.dart';
import '../packet/quic_packet_header.dart';
import '../stream/quic_stream_frame.dart';
// Import your QUIC header and frame classes
// import 'path/to/quic_packet_header.dart';
// import 'path/to/quic_frame.dart';

void main() {
  group('QUIC Packet Parsing from Trace Examples', () {
    test('Client Initial Packet Header (Listing 14)', () {
      // Manually construct the byte array based on Listing 14
      // Header Form (1) = 1 (most significant bit)
      // Fixed Bit (1) = 1
      // Long Packet Type (2) = 00 (Initial)
      // Type-Specific Bits (4) = 0000
      // Combined first byte: 0b11000000 = 0xC0
      final List<int> initialHeaderBytes = [
        0xC0, // Header Form, Fixed Bit, Long Packet Type, Type-Specific Bits
        0xFF, 0x00, 0x00, 0x1D, // Version (0xff00001d)
        0x08, // Destination Connection ID Length (8)
        0x61,
        0x14,
        0xCA,
        0x6E,
        0xCB,
        0xE4,
        0x83,
        0xBB, // Destination Connection ID
        0x08, // Source Connection ID Length (8)
        0xC9, 0xF5, 0x4D, 0x3C, 0x29, 0x82, 0x96, 0xB9, // Source Connection ID
        0x00, // Token Length (i) = 0 (VarInt encoding for 0)
        0x40, 0x04, 0xC2, // Length (i) = 1226 (VarInt encoding of 0x04C2)
        // VarInt 1226: 0x4000 | 0x04C2 = 0x44C2 (Oops, 1226 is not 0x4C2. It's 0x4C2 = 1218. The listed length is 1226. Let's re-calculate VarInt 1226:
        // 1226 is 0x4CA. For 2-byte varint, it starts with 01. So 0100 1100 1010 = 0x4CA.
        // This means the VarInt is (0x4000 | 0x04CA) = 0x44CA
        // Let's recheck length of 1226 in listing. Length is 1226. 1226 in hex is 0x4CA.
        // 2-byte varint for 0x4CA is `01` prepended to the 14 bits. `01 00 1100 1010` = `0x44CA`.
        // The example `0x40, 0x04, 0xC2` is a 3-byte varint. 0x40 means 2-byte, but then 0x04C2 means 3-byte.
        // This looks like an error in the provided listing's byte representation for length.
        // Let's assume the value 1226 (0x4CA) is correct and infer its correct VarInt: 0x44, 0xCA.
        // Or if 0x40, 0x04, 0xC2 is correct, then it's a 4-byte varint (0x40 is prefix) where actual value is 0x04C2.
        // The text says "Length (i) = 1226".
        // If it's a 2-byte varint: 0x40 | 1226 = 0x44CA
        // If it's a 4-byte varint: 0x80 | 1226 = 0x840004CA
        // If it's an 8-byte varint: 0xC0 | 1226 = 0xC0000000000004CA
        // The example's `Length (i) = 1226` and its byte representation `0x40, 0x04, 0xC2` seems to be an error in the original document
        // regarding how `Length (i)` is represented as bytes.
        // 0x40 usually implies 2-byte length, and 0x04C2 is > 2 bytes.
        // Let's assume the value 1226 is correct. A two-byte varint for 1226 (0x4CA) would be 0x44CA.
        // So, `0x44, 0xCA`. If the example's bytes are critical, then the value 1226 is wrong.
        // Let's proceed assuming the value 1226 (0x4CA) is correct and the text's bytes are possibly a typo/simplified example.
        // VarInt encoding of 1226 (0x4CA) is `0x44ca` (two bytes).
        // So the bytes would be `0x44, 0xCA`.

        // Let's assume the bytes for Length are what the text provides, and the value might be slightly off.
        // If `0x40, 0x04, 0xC2` were a VarInt, it implies `0x40` is prefix for length, then `0x04C2` as data.
        // A VarInt that starts with 0x40 indicates 2 bytes. A VarInt that is 3 bytes long would start with 0x80.
        // This is a discrepancy. I will generate test data based on the *values* provided in the text and
        // use a correct VarInt encoder.

        // Corrected VarInt for 1226 (0x4CA): 0x44CA (2 bytes)
        // If the example is using a 4-byte VarInt (starting 0x80): 0x800004CA.
        // The text says (i) meaning varint, so it *should* be 0x44CA.
        // Given the example `Length (i) = 1226`, the *bytes* are likely `0x44, 0xCA`.
        0x44, 0xCA, // Length (i) = 1226
        0x00, // Packet Number (8..32) = 0 (encoded as 1 byte due to PNL in header)
        // Packet Payload (CRYPTO frame would follow)
      ];

      // For the sake of this example, let's assume `QuicLongHeader.parse` exists.
      // In reality, Packet Number Length (PNL) is encoded in Type-Specific Bits.
      // Listing 14 shows `Type-Specific Bits (4) = 0000`. This means Packet Number Length is 1 byte (00).
      // So, Packet Number (8..32) = 0, encoded as 1 byte.
      final QuicLongHeader header = QuicLongHeader.parse(
        Uint8List.fromList(initialHeaderBytes),
      );

      expect(header.headerForm, 1);
      expect(header.fixedBit, 1);
      expect(header.longPacketType, 0); // Initial
      expect(header.version, 0xff00001d);
      expect(header.destConnectionIdLength, 8);
      expect(header.destConnectionId, 0x6114ca6ecbe483bb);
      expect(header.srcConnectionIdLength, 8);
      expect(header.srcConnectionId, 0xc9f54d3c298296b9);
      expect(header.tokenLength, 0);
      expect(header.length, 1226);
      // Packet Number itself is part of the payload, not header in this simplified struct
      // The PNL for 0000 indicates 1 byte packet number.
      // expect(header.packetNumberLength, 1); // This would be part of Type-Specific Bits interpretation
    });

    test('Client CRYPTO Frame (Listing 15)', () {
      final List<int> cryptoFrameBytes = [
        0x06, // Type (i) = 0x06 (VarInt for 6)
        0x00, // Offset (i) = 0 (VarInt for 0)
        0x40,
        0xF5, // Length (i) = 245 (VarInt for 245) - 245 is 0xF5. VarInt for 0xF5 is 0x40F5.
        // Crypto Data (first few bytes of ClientHello)
        // For a test, you might use dummy data or actual ClientHello bytes if available
        ...List.generate(245, (index) => index % 256), // Placeholder data
      ];

      final QuicCryptoFrame cryptoFrame = QuicCryptoFrame.parse(
        Uint8List.fromList(cryptoFrameBytes),
        0,
      );

      expect(cryptoFrame.type, 0x06);
      expect(cryptoFrame.offset, 0);
      expect(cryptoFrame.length, 245);
      expect(cryptoFrame.cryptoData.length, 245);
    });

    test('Server ACK Frame (Listing 17)', () {
      final List<int> ackFrameBytes = [
        0x02, // Type (i) = 0x02
        0x00, // Largest Acknowledged (i) = 0
        0x00, // ACK Delay (i) = 0
        0x00, // ACK Range Count (i) = 0
        0x00, // First ACK Range (i) = 0
      ];

      final QuicAckFrame ackFrame = QuicAckFrame.parse(
        Uint8List.fromList(ackFrameBytes),
        0,
      );

      expect(ackFrame.type, 0x02);
      expect(ackFrame.largestAcknowledged, 0);
      expect(ackFrame.ackDelay, 0);
      expect(ackFrame.ackRangeCount, 0);
      expect(ackFrame.firstAckRange, 0);
      expect(ackFrame.ackRanges, isEmpty);
    });

    test('Client STREAM Frame (Listing 19)', () {
      // Type (i) = 0b00001011 = 0x0B
      // This type indicates: Offset present (bit 3=1), Length present (bit 2=1), FIN=1 (bit 0=1).
      final List<int> streamFrameBytes = [
        0x0B, // Type (i)
        0x08, // Stream ID = 8 (VarInt for 8)
        0x00, // Offset = 0 (VarInt for 0)
        0x11, // Length = 17 (VarInt for 17)
        ...('GET /index.html\r\n'.codeUnits), // Stream Data
      ];

      final QuicStreamFrame streamFrame = QuicStreamFrame.parse(
        Uint8List.fromList(streamFrameBytes),
        0,
      );

      expect(streamFrame.type, 0x0B);
      expect(streamFrame.streamId, 8);
      expect(streamFrame.offset, 0);
      expect(streamFrame.length, 17);
      expect(
        String.fromCharCodes(streamFrame.streamData),
        'GET /index.html\r\n',
      );
      expect(streamFrame.isFinSet, isTrue); // FIN bit is set
    });

    test('Server STREAM Frame (Listing 20)', () {
      // Type (i) = 0b00001111 = 0x0F
      // This type indicates: Offset present (bit 3=1), Length present (bit 2=1), FIN=1 (bit 0=1).
      final List<int> streamFrameBytes = [
        0x0F, // Type (i)
        0x08, // Stream ID = 8 (VarInt for 8)
        0x00, // Offset = 0 (VarInt for 0)
        0x41,
        0xCF, // Length = 462 (VarInt for 462, 0x1CE. VarInt for 0x1CE is 0x41CE. Corrected example's bytes)
        // 462 is 0x1CE. A 2-byte varint for 0x1CE is 01_00011100_1110 = 0x41CE.
        // So, `0x41, 0xCE`. The example's `0x40, 0x04, 0xC2` for length is again erroneous.
        ...List.generate(462, (index) => index % 256), // Dummy HTML data
      ];

      final QuicStreamFrame streamFrame = QuicStreamFrame.parse(
        Uint8List.fromList(streamFrameBytes),
        0,
      );

      expect(streamFrame.type, 0x0F);
      expect(streamFrame.streamId, 8);
      expect(streamFrame.offset, 0);
      expect(streamFrame.length, 462);
      expect(streamFrame.isFinSet, isTrue);
    });
  });
}

// Dummy QuicLongHeader class for testing
class QuicLongHeader {
  final int headerForm;
  final int fixedBit;
  final int longPacketType;
  final int version;
  final int destConnectionIdLength;
  final int destConnectionId;
  final int srcConnectionIdLength;
  final int srcConnectionId;
  final int tokenLength;
  final int length;

  QuicLongHeader({
    required this.headerForm,
    required this.fixedBit,
    required this.longPacketType,
    required this.version,
    required this.destConnectionIdLength,
    required this.destConnectionId,
    required this.srcConnectionIdLength,
    required this.srcConnectionId,
    required this.tokenLength,
    required this.length,
  });

  factory QuicLongHeader.parse(Uint8List data) {
    // Simplified parsing for illustration, assuming fixed sizes for CID for now.
    // In reality, this would use VarInt.
    int offset = 0;
    final int firstByte = data[offset++];
    final headerForm = (firstByte >> 7) & 0x01;
    final fixedBit = (firstByte >> 6) & 0x01;
    final longPacketType = (firstByte >> 4) & 0x03;
    // Type-Specific bits (bits 0-3) also encode Packet Number Length (PNL) for Initial packets.
    // For Long Packet Type 00 (Initial), 0b00 implies 1 byte PNL.
    // This is a simplification; full parsing would extract PNL from first byte.

    final version = ByteData.view(data.buffer, offset, 4).getUint32(0);
    offset += 4;

    final destCidLen = data[offset++];
    final destCid = ByteData.view(data.buffer, offset, destCidLen).getUint64(0);
    offset += destCidLen;

    final srcCidLen = data[offset++];
    final srcCid = ByteData.view(data.buffer, offset, srcCidLen).getUint64(0);
    offset += srcCidLen;

    // Token Length is a VarInt
    final tokenLength = VarInt.read(data, offset);
    offset += VarInt.getLength(tokenLength);
    // Skip Token data
    offset += tokenLength;

    // Length is a VarInt
    final length = VarInt.read(data, offset);
    offset += VarInt.getLength(length);

    return QuicLongHeader(
      headerForm: headerForm,
      fixedBit: fixedBit,
      longPacketType: longPacketType,
      version: version,
      destConnectionIdLength: destCidLen,
      destConnectionId: destCid,
      srcConnectionIdLength: srcCidLen,
      srcConnectionId: srcCid,
      tokenLength: tokenLength,
      length: length,
    );
  }
}



// (Add VarInt helper here or import it)
