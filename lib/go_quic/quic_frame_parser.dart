import 'dart:typed_data';
import 'buffer.dart';
import 'handshake/handshake.dart';

//############################################################################
//## SECTION 1: QUIC FRAME DATA CLASSES
//############################################################################

/// Abstract base class for all parsed QUIC frames.
abstract class QuicFrame {
  final int type;
  QuicFrame(this.type);
}

/// Represents a PADDING frame (type 0x00). It has no content.
class PaddingFrame extends QuicFrame {
  PaddingFrame() : super(0x00);
  @override
  String toString() => 'PaddingFrame';
}

/// Represents a PING frame (type 0x01). It has no content.
class PingFrame extends QuicFrame {
  PingFrame() : super(0x01);
  @override
  String toString() => 'PingFrame';
}

/// Represents an ACK frame (types 0x02, 0x03).
class AckFrame extends QuicFrame {
  final int largestAcked;
  final int ackDelay;
  final int ackRangeCount;
  // Additional fields for a full implementation can be added here.

  AckFrame(int type, this.largestAcked, this.ackDelay, this.ackRangeCount)
    : super(type);

  @override
  String toString() =>
      'AckFrame(type: 0x${type.toRadixString(16)}, largestAcked: $largestAcked, rangeCount: $ackRangeCount)';
}

/// Represents a CRYPTO frame (type 0x06).
class CryptoFrame extends QuicFrame {
  final int offset;
  final int length;
  final List<TlsHandshakeMessage> messages;

  CryptoFrame(this.offset, this.length, this.messages) : super(0x06);

  @override
  String toString() {
    final messageTypes = messages.map((m) => m.typeName).join(', ');
    return 'CryptoFrame(offset: $offset, length: $length, messages: [$messageTypes])';
  }
}

//############################################################################
//## SECTION 2: THE QUIC FRAME PARSER
//############################################################################

/// A stateful parser for a sequence of QUIC frames within a packet's payload.
class QuicFrameParser {
  /// The encryption level of the packet being parsed.
  /// Valid values: 'Initial', 'Handshake', 'ZeroRTT', 'OneRTT'.
  final String encryptionLevel;

  QuicFrameParser({required this.encryptionLevel});

  /// Parses a plaintext QUIC payload into a list of QuicFrame objects.
  List<QuicFrame> parse(Uint8List plaintextPayload) {
    print('--- Parsing Plaintext QUIC Frames (Level: $encryptionLevel) ---');
    final buffer = Buffer(data: plaintextPayload);
    final frames = <QuicFrame>[];

    while (!buffer.eof) {
      // Per RFC 9000, Section 19.1, PADDING frames are just the byte 0x00.
      // We can peek at the byte to handle them efficiently.
      if (buffer.byteData.getUint8(buffer.readOffset) == 0x00) {
        buffer.pullUint8(); // Consume the PADDING byte
        frames.add(PaddingFrame());
        continue;
      }

      final frameType = buffer.pullVarInt();
      QuicFrame? parsedFrame;

      switch (frameType) {
        case 0x01: // PING
          parsedFrame = PingFrame();
          break;

        case 0x02: // ACK Frame
        case 0x03: // ACK Frame with ECN
          parsedFrame = _parseAckFrame(buffer, frameType);
          break;

        case 0x06: // CRYPTO Frame
          parsedFrame = _parseCryptoFrame(buffer);
          break;

        default:
          throw Exception(
            'Parsing stopped at unsupported frame type: 0x${frameType.toRadixString(16)}',
          );
      }

      // Validate that the frame is allowed at this encryption level
      if (!_isFrameAllowed(parsedFrame, encryptionLevel)) {
        throw Exception(
          '${parsedFrame.runtimeType} is not allowed at encryption level $encryptionLevel',
        );
      }

      frames.add(parsedFrame);
      print('✅ Parsed Frame: $parsedFrame');
    }
    return frames;
  }

  /// Parses the fields of an ACK frame.
  AckFrame _parseAckFrame(Buffer buffer, int frameType) {
    final largestAcked = buffer.pullVarInt();
    final ackDelay = buffer.pullVarInt();
    final ackRangeCount = buffer.pullVarInt();
    buffer.pullVarInt(); // First ACK Range

    for (var i = 0; i < ackRangeCount; i++) {
      buffer.pullVarInt(); // Gap
      buffer.pullVarInt(); // ACK Range Length
    }

    if (frameType == 0x03) {
      buffer.pullVarInt(); // ECT(0) Count
      buffer.pullVarInt(); // ECT(1) Count
      buffer.pullVarInt(); // ECN-CE Count
    }
    return AckFrame(frameType, largestAcked, ackDelay, ackRangeCount);
  }

  /// Parses the fields of a CRYPTO frame.
  CryptoFrame _parseCryptoFrame(Buffer buffer) {
    final offset = buffer.pullVarInt();
    final length = buffer.pullVarInt();
    final cryptoData = buffer.pullBytes(length);

    final tlsMessages = parseTlsMessages(cryptoData);
    if (tlsMessages.isEmpty) {
      throw Exception("No TLS messages found inside CRYPTO frame");
    }
    return CryptoFrame(offset, length, tlsMessages);
  }

  /// Checks if a frame is allowed at a specific encryption level.
  /// Based on RFC 9000, Section 12.5.
  bool _isFrameAllowed(QuicFrame frame, String encryptionLevel) {
    if (encryptionLevel == 'OneRTT') {
      return true; // All frames are allowed in 1-RTT packets.
    }
    if (encryptionLevel == 'Initial' || encryptionLevel == 'Handshake') {
      return frame is CryptoFrame || frame is AckFrame || frame is PingFrame;
      // A full implementation would also allow CONNECTION_CLOSE (type 0x1c).
    }
    // Add other levels like ZeroRTT if needed
    return false;
  }
}
