import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../buffer.dart';

import 'dart:typed_data';

import '../handshake/handshake.dart';
import 'frames.dart';

// Add other frame classes as needed...

/// Parses a byte buffer and decodes it into a list of QUIC frames.
List<QuicFrame> parseQuicFrames(Uint8List data) {
  final buffer = Buffer(data: data);
  final frames = <QuicFrame>[];

  // The try-catch block gracefully handles any buffer read errors.
  // If the packet is malformed, we stop parsing and return what we have.
  try {
    while (!buffer.eof) {
      final type = buffer.pullUint8();

      // PADDING frames are simply ignored after being read.
      if (type == 0x00) {
        continue;
      }
      // STREAM frames (0x08 to 0x0f)
      else if (type >= 0x08 && type <= 0x0f) {
        final hasOff = (type & 0x04) != 0;
        final hasLen = (type & 0x02) != 0;
        final fin = (type & 0x01) != 0;

        final id = buffer.pullVarInt();
        final offset = hasOff ? buffer.pullVarInt() : 0;

        // If length is not present, the data extends to the end of the packet.
        final len = hasLen ? buffer.pullVarInt() : buffer.remaining;
        final data = buffer.pullBytes(len);

        frames.add(StreamFrame(id: id, offset: offset, fin: fin, data: data));
      }
      // ACK frames (0x02, 0x03)
      else if (type == 0x02 || type == 0x03) {
        final hasEcn = (type & 0x01) != 0;
        final largest = buffer.pullVarInt();
        final delay = buffer.pullVarInt();
        final rangeCount = buffer.pullVarInt();
        final firstRange = buffer.pullVarInt();

        final ranges = <AckRange>[];
        for (var i = 0; i < rangeCount; i++) {
          final gap = buffer.pullVarInt();
          final len = buffer.pullVarInt();
          ranges.add(AckRange(gap: gap, length: len));
        }

        EcnCounts? ecn;
        if (hasEcn) {
          final ect0 = buffer.pullVarInt();
          final ect1 = buffer.pullVarInt();
          final ce = buffer.pullVarInt();
          ecn = EcnCounts(ect0: ect0, ect1: ect1, ce: ce);
        }

        frames.add(
          AckFrame(
            largest: largest,
            delay: delay,
            firstRange: firstRange,
            ranges: ranges,
            ecn: ecn,
          ),
        );
      }
      // All other frame types
      else {
        switch (type) {
          case 0x01: // PING
            frames.add(const PingFrame());
            break;

          case 0x04: // RESET_STREAM
            final id = buffer.pullVarInt();
            final error = buffer.pullUint16();
            final finalSize = buffer.pullVarInt();
            frames.add(
              ResetStreamFrame(id: id, error: error, finalSize: finalSize),
            );
            break;

          case 0x05: // STOP_SENDING
            final id = buffer.pullVarInt();
            final error = buffer.pullUint16();
            frames.add(StopSendingFrame(id: id, error: error));
            break;

          case 0x06: // CRYPTO
            final offset = buffer.pullVarInt();
            print("Crypto Offset: $offset");
            final len = buffer.pullVarInt();
            final cryptoData = buffer.pullBytes(len);
            // final tlsMessages = parseTlsMessages(cryptoData);
            // print('✅ Parsed tls Messages $tlsMessages');
            frames.add(CryptoFrame(offset: offset, data: cryptoData));

            List<CryptoFrame> cryptoFrames = [];
            for (final frame in frames) {
              if (frame.runtimeType == CryptoFrame) {
                cryptoFrames.add(frame as CryptoFrame);
              }
            }

            // cryptoFrames.reduce((value, element) {
            //   value as CryptoFrame;
            //   element as CryptoFrame;
            //   return CryptoFrame(
            //     offset: value.offset,
            //     data: Uint8List.fromList([...value.data, ...element.data]),
            //   );
            // });

            // final cryptoFrame = cryptoFrames.first as CryptoFrame;
            // try {
            final tlsMessages = parseTlsMessages(cryptoFrames);
            print('✅ Parsed tls Messages $tlsMessages');
            // } catch (e) {
            //   print(e);
            // }
            break;

          case 0x07: // NEW_TOKEN
            final len = buffer.pullVarInt();
            final token = buffer.pullBytes(len);
            frames.add(NewTokenFrame(token: token));
            break;

          case 0x10: // MAX_DATA
            final max = buffer.pullVarInt();
            frames.add(MaxDataFrame(max: max));
            break;

          case 0x11: // MAX_STREAM_DATA
            final id = buffer.pullVarInt();
            final max = buffer.pullVarInt();
            frames.add(MaxStreamDataFrame(id: id, max: max));
            break;

          case 0x12: // MAX_STREAMS (Bidi)
          case 0x13: // MAX_STREAMS (Uni)
            final max = buffer.pullVarInt();
            frames.add(MaxStreamsFrame(max: max, isBidi: type == 0x12));
            break;

          case 0x18: // NEW_CONNECTION_ID
            final seq = buffer.pullVarInt();
            final retire = buffer.pullVarInt();
            final len = buffer.pullUint8();
            final connId = buffer.pullBytes(len);
            final token = buffer.pullBytes(
              16,
            ); // Stateless Reset Token is always 16 bytes
            frames.add(
              NewConnectionIdFrame(
                seq: seq,
                retire: retire,
                connId: connId,
                token: token,
              ),
            );
            break;

          case 0x19: // RETIRE_CONNECTION_ID
            final seq = buffer.pullVarInt();
            frames.add(RetireConnectionIdFrame(seq: seq));
            break;

          case 0x1a: // PATH_CHALLENGE
          case 0x1b: // PATH_RESPONSE
            final data = buffer.pullBytes(8);
            if (type == 0x1a) {
              frames.add(PathChallengeFrame(data: data));
            } else {
              frames.add(PathResponseFrame(data: data));
            }
            break;

          case 0x1c: // CONNECTION_CLOSE (QUIC)
          case 0x1d: // CONNECTION_CLOSE (Application)
            final isApplication = type == 0x1d;
            final error = buffer.pullUint16();
            final frameType = isApplication ? 0 : buffer.pullVarInt();
            final reasonLen = buffer.pullVarInt();
            final reasonBytes = buffer.pullBytes(reasonLen);
            final reason = utf8.decode(reasonBytes);
            frames.add(
              ConnectionCloseFrame(
                error: error,
                isApplication: isApplication,
                frameType: frameType,
                reason: reason,
              ),
            );
            break;

          case 0x1e: // HANDSHAKE_DONE
            frames.add(const HandshakeDoneFrame());
            break;

          default:
            // Unknown frame type, stop parsing to avoid errors.
            // You could also add an 'UnknownFrame' type to the list if needed.
            // print('Encountered unknown frame type: 0x${type.toRadixString(16)}');
            return frames;
        }
      }
    }
  } catch (e) {
    // A BufferReadError likely means the packet was malformed or truncated.
    print('Error parsing frames: $e');
  }

  return frames;
}

/// Encodes a list of QUIC frames into a single byte buffer.
Uint8List encodeQuicFrames(List<QuicFrame> frames) {
  // Create a single buffer to write all frames into.
  // This is highly efficient as it avoids multiple allocations.
  final buffer = Buffer(data: Uint8List(0));

  for (final frame in frames) {
    // Use a switch on the object's runtimeType for clean, type-safe handling.
    switch (frame.runtimeType) {
      case PaddingFrame:
        final f = frame as PaddingFrame;
        // A new Uint8List is zero-filled by default.
        buffer.pushBytes(Uint8List(f.length));
        break;

      case PingFrame:
        buffer.pushUint8(0x01);
        break;

      case AckFrame:
        final f = frame as AckFrame;
        final hasEcn = f.ecn != null;
        buffer.pushUint8(hasEcn ? 0x03 : 0x02); // Type byte
        buffer.pushUintVar(f.largest);
        buffer.pushUintVar(f.delay);
        buffer.pushUintVar(f.ranges.length);
        buffer.pushUintVar(f.firstRange);

        for (final range in f.ranges) {
          buffer.pushUintVar(range.gap);
          buffer.pushUintVar(range.length);
        }

        if (hasEcn) {
          buffer.pushUintVar(f.ecn!.ect0);
          buffer.pushUintVar(f.ecn!.ect1);
          buffer.pushUintVar(f.ecn!.ce);
        }
        break;

      case ResetStreamFrame:
        final f = frame as ResetStreamFrame;
        buffer.pushUint8(0x04);
        buffer.pushUintVar(f.id);
        buffer.pushUint16(f.error); // Pushing a 16-bit error code
        buffer.pushUintVar(f.finalSize);
        break;

      case StopSendingFrame:
        final f = frame as StopSendingFrame;
        buffer.pushUint8(0x05);
        buffer.pushUintVar(f.id);
        buffer.pushUint16(f.error);
        break;

      case CryptoFrame:
        final f = frame as CryptoFrame;
        buffer.pushUint8(0x06);
        buffer.pushUintVar(f.offset);
        buffer.pushUintVar(f.data.length);
        buffer.pushBytes(f.data);
        break;

      case NewTokenFrame:
        final f = frame as NewTokenFrame;
        buffer.pushUint8(0x07);
        buffer.pushUintVar(f.token.length);
        buffer.pushBytes(f.token);
        break;

      case StreamFrame:
        final f = frame as StreamFrame;
        var typeByte = 0x08;
        final hasOffset = f.offset > 0;
        final hasLen = f.data.isNotEmpty;

        if (hasOffset) typeByte |= 0x04; // OFF bit
        if (hasLen) typeByte |= 0x02; // LEN bit
        if (f.fin) typeByte |= 0x01; // FIN bit

        buffer.pushUint8(typeByte);
        buffer.pushUintVar(f.id);
        if (hasOffset) {
          buffer.pushUintVar(f.offset);
        }
        if (hasLen) {
          buffer.pushUintVar(f.data.length);
          buffer.pushBytes(f.data);
        }
        break;

      case MaxDataFrame:
        final f = frame as MaxDataFrame;
        buffer.pushUint8(0x10);
        buffer.pushUintVar(f.max);
        break;

      case MaxStreamDataFrame:
        final f = frame as MaxStreamDataFrame;
        buffer.pushUint8(0x11);
        buffer.pushUintVar(f.id);
        buffer.pushUintVar(f.max);
        break;

      case MaxStreamsFrame:
        final f = frame as MaxStreamsFrame;
        buffer.pushUint8(f.isBidi ? 0x12 : 0x13);
        buffer.pushUintVar(f.max);
        break;

      case NewConnectionIdFrame:
        final f = frame as NewConnectionIdFrame;
        buffer.pushUint8(0x18);
        buffer.pushUintVar(f.seq);
        buffer.pushUintVar(f.retire);
        buffer.pushUint8(f.connId.length); // Length is a single byte
        buffer.pushBytes(f.connId);
        buffer.pushBytes(f.token); // Stateless Reset Token is 16 bytes
        break;

      case RetireConnectionIdFrame:
        final f = frame as RetireConnectionIdFrame;
        buffer.pushUint8(0x19);
        buffer.pushUintVar(f.seq);
        break;

      case PathChallengeFrame:
        final f = frame as PathChallengeFrame;
        buffer.pushUint8(0x1a);
        buffer.pushBytes(f.data); // Data is 8 bytes
        break;

      case PathResponseFrame:
        final f = frame as PathResponseFrame;
        buffer.pushUint8(0x1b);
        buffer.pushBytes(f.data); // Data is 8 bytes
        break;

      case ConnectionCloseFrame:
        final f = frame as ConnectionCloseFrame;
        buffer.pushUint8(f.isApplication ? 0x1d : 0x1c);
        buffer.pushUint16(f.error);
        if (!f.isApplication) {
          buffer.pushUintVar(f.frameType);
        }
        final reasonBytes = utf8.encode(f.reason);
        buffer.pushUintVar(reasonBytes.length);
        buffer.pushBytes(reasonBytes);
        break;

      case HandshakeDoneFrame:
        buffer.pushUint8(0x1e);
        break;

      default:
        // Optionally handle unknown frame types
        print('Unsupported frame type: ${frame.runtimeType}');
        break;
    }
  }

  // Return the underlying Uint8List containing all the encoded data.
  return buffer.toBytes();
}

void main() {
  // 1. Create a list of frames to encode.
  // final framesToEncode = <QuicFrame>[
  //   PingFrame(),
  //   StreamFrame(
  //     id: 2,
  //     offset: 1024,
  //     fin: true,
  //     data: Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]),
  //   ),
  //   MaxDataFrame(max: 987654),
  // ];

  // // 2. Encode the frames into a byte buffer.
  // final encodedData = encodeQuicFrames(framesToEncode);
  // print('Encoded ${encodedData.length} bytes.');

  // 3. Parse the bytes back into frame objects.
  final decodedFrames = parseQuicFrames(payload);
  print('Decoded ${decodedFrames.length} frames:');

  // 4. Verify the results.
  for (final frame in decodedFrames) {
    print('- Decoded frame of type: ${frame.runtimeType}');
    print("Frame: $frame");
    if (frame is StreamFrame) {
      print(
        '  Stream ID: ${frame.id}, Fin: ${frame.fin}, Data Length: ${frame.data.length}',
      );
    }
  }

  final encodedData = encodeQuicFrames(decodedFrames);
  print('Encoded  ${HEX.encode(encodedData)} bytes.');
  print('Expected ${HEX.encode(payload)} bytes.');
}

Uint8List payload = Uint8List.fromList([
  0x06,
  0x00,
  0x40,
  0xee,
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
