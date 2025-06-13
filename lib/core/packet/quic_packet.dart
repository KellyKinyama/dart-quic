// Conceptual snippet within a QuicPacket
import 'dart:typed_data';

import '../flow_control/frame.dart';
import '../stream/quic_stream_frame.dart';
import 'quic_packet_header.dart';

// class QuicPacket {
//   QuicPacketHeader header;
//   List<dynamic>
//   frames; // This list would hold various frame objects, including QuicStreamFrame

//   QuicPacket(this.header, this.frames);
//   factory QuicPacket.fromBytes(
//     Uint8List rawBytes, {
//     int? shortHeaderDestConnectionIdLength,
//   }) {
//     int offset = 0;
//     QuicPacketHeader header = QuicPacketHeader.parse(
//       rawBytes,
//       shortHeaderDestConnectionIdLength: shortHeaderDestConnectionIdLength,
//     );
//     // After parsing header, the remaining bytes are frames
//     offset += header
//         .toBytes()
//         .length; // Get length of parsed header (this would be more complex with varints)

//     Uint8List frameData = rawBytes.sublist(offset);
//     List<dynamic> frames = _parseFrames(
//       frameData,
//     ); // Call a function to parse individual frames
//     return QuicPacket(header, frames);
//   }

//   static List<dynamic> _parseFrames(Uint8List data) {
//     final List<dynamic> parsedFrames = [];
//     int offset = 0;
//     while (offset < data.length) {
//       // Logic to determine frame type from first byte/varint of the frame
//       // For this example, assuming all are STREAM frames for simplicity.
//       // In reality, you'd read the frame type and dispatch to appropriate parser.
//       try {
//         final streamFrame = QuicStreamFrame.parse(data, offset);
//         parsedFrames.add(streamFrame);
//         offset += streamFrame
//             .toBytes()
//             .length; // Advance offset by frame's total length
//       } catch (e) {
//         print('Error parsing frame: $e');
//         break; // Stop if a malformed frame is encountered
//       }
//     }
//     return parsedFrames;
//   }

//   bool get isAckEliciting {
//     // List of non-ack-eliciting frame types
//     const Set<int> nonAckElicitingTypes = {
//       0x02, // ACK
//       0x03, // ACK with ECN
//       0x01, // PADDING (usually) - check QUIC spec for exact rules
//       0x1C, // CONNECTION_CLOSE (with Error Code) - This frame can be ack-eliciting depending on context,
//       // but the text specifically states if a packet *only* contains CC, it's non-eliciting.
//       // For simplicity here, we'll follow the text's direct example.
//     };
//     return !nonAckElicitingTypes.contains(this);
//   }

//   // ... other methods
// }
class QuicPacket {
  final QuicPacketHeader header;
  final List<QuicFrame> frames;
  final int packetNumber; // The actual packet number, not just the encoded length bits
  final int timeSent; // Timestamp when this packet was sent (for RTT calculation)
  bool acknowledged = false;
  bool inFlight = false; // Whether it's currently considered in-flight

  QuicPacket({
    required this.header,
    required this.frames,
    required this.packetNumber,
    required this.timeSent,
  });

  // Determines if this packet requires an ACK from the receiver
  bool get isAckEliciting {
    return frames.any((frame) => frame.type.isAckEliciting);
  }

  // Example of how to parse frames within a packet
  static List<QuicFrame> parseFrames(Uint8List payloadData) {
    final List<QuicFrame> parsedFrames = [];
    int offset = 0;
    while (offset < payloadData.length) {
      try {
        final frame = QuicFrame.parse(payloadData, offset);
        parsedFrames.add(frame);
        // Advance offset by the actual length of the parsed frame
        offset += frame.toBytes().length; // This is a simplification; need actual frame length calculation
      } catch (e) {
        print('Error parsing frame: $e');
        // Handle malformed frame, potentially discard remaining data in packet
        break;
      }
    }
    return parsedFrames;
  }
}