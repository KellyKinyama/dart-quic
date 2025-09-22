// QUIC Payload Parser
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'buffer.dart';
import 'frames/crypto_frame.dart';
import 'handshake/handshake.dart';

void parsePayload(Uint8List plaintextPayload) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = Buffer(data: plaintextPayload);
  int frameCount = 0;

  try {
    while (!buffer.eof) {
      if (buffer.byteData.getUint8(buffer.readOffset) == 0) {
        buffer.pullUint8(); // Consume PADDING byte and loop again
        continue;
      }

      final frameType = buffer.pullVarInt();
      frameCount++;
      switch (frameType) {
        // --- FIX IS HERE ---
        case 0x02: // ACK Frame
        case 0x03: // ACK Frame with ECN
          print(
            '✅ Parsed Frame $frameCount: ACK Frame (type: 0x${frameType.toRadixString(16)}) - Skipping',
          );

          buffer.pullVarInt(); // 1. Largest Acknowledged
          buffer.pullVarInt(); // 2. ACK Delay
          final ackRangeCount = buffer.pullVarInt(); // 3. ACK Range Count
          buffer.pullVarInt(); // 4. First ACK Range

          // 5. Loop through all the ACK Ranges and discard them
          for (var i = 0; i < ackRangeCount; i++) {
            buffer.pullVarInt(); // Skip Gap
            buffer.pullVarInt(); // Skip ACK Range Length
          }

          // 6. If the frame has ECN counts, read and discard them too
          if (frameType == 0x03) {
            buffer.pullVarInt(); // Skip ECT(0) Count
            buffer.pullVarInt(); // Skip ECT(1) Count
            buffer.pullVarInt(); // Skip ECN-CE Count
          }
          break; // Continue to the next frame
        // --- END OF FIX --- the next frame

        case 0x06: // CRYPTO Frame
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
          final cryptoData = buffer.pullBytes(length);
          // Now, parse the TLS messages inside the crypto data
          final tlsMessages = parseTlsMessages(cryptoData);
          if (tlsMessages.isEmpty) throw Exception("Empty tls messages");
          final frame = CryptoFrame(offset, length, tlsMessages);
          print('✅ Parsed Frame $frameCount: $frame');
          // Print details of the first TLS message found
          if (frame.messages.isNotEmpty) {
            print(frame.messages.first);
          }
          break;
        default:
          print(
            '⚠️ Parsed Frame $frameCount: Skipping unknown frame type: 0x${frameType.toRadixString(16)}',
          );
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
        // return; // Stop on unknown frames for safety
      }
    }
  } catch (e, st) {
    print('\n🛑 An error occurred during parsing: $e');
    print(st);
  }
  print('\n🎉 Payload parsing complete.');
}

// #############################################################################
// ## SECTION 4: DEMONSTRATION
// #############################################################################

void main() {
  // This is the full, decrypted payload from RFC 9001, Appendix A.2
  // It contains one CRYPTO frame followed by PADDING frames.
  final rfcInitialPayload =
      (BytesBuilder()
            ..add(
              HEX.decode(
                '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
                '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
                '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
                '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
                'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
                '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
                '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
                '75300901100f088394c8f03e51570806048000ffff',
              ),
            )
            ..add(Uint8List(1162 - 242))) // 242 is the crypto frame size
          .toBytes();

  parsePayload(rfcInitialPayload);
}
