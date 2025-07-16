import 'dart:typed_data';

enum QuicFrameType {
  padding(0x00),
  stream(0x08), // Base type for STREAM frame
  // Other frame types...
  ;

  final int typeCode;
  const QuicFrameType(this.typeCode);
}

// Represents a QUIC STREAM frame with its raw type byte.
class QuicStreamFrame {
  final int rawTypeByte; // The actual first byte of the frame, includes flags
  final Uint8List data; // The payload data of the stream

  QuicStreamFrame(this.rawTypeByte, this.data);

  // Checks if the STREAM frame is empty and does not have the FIN bit set.
  bool isStreamFrameEmptyWithoutFin() {
    final bool hasFinBit = (rawTypeByte & 0x01) == 0x01; // Assuming FIN is LSB
    final int streamDataLength = data.length;
    return !hasFinBit && streamDataLength == 0;
  }
}

class QuicPacketProcessor {
  void processFrame(QuicStreamFrame frame) {
    if (frame.isStreamFrameEmptyWithoutFin()) {
      print('**Peer Denial of Service Example**');
      print('PROTOCOL VIOLATION: Received empty STREAM frame without FIN bit set. Discarding.');
      // In a real system, this would lead to a connection error.
      return;
    }
    print('Processing STREAM frame with data length: ${frame.data.length}');
  }
}

void main() {
  final QuicPacketProcessor processor = QuicPacketProcessor();

  // Example of a valid STREAM frame (even if empty, it has FIN bit)
  final QuicStreamFrame validStreamFin = QuicStreamFrame(0x09, Uint8List(0)); // 0x09 could mean STREAM with FIN
  processor.processFrame(validStreamFin);

  // Example of an invalid STREAM frame (empty, no FIN bit)
  final QuicStreamFrame invalidStreamEmptyNoFin = QuicStreamFrame(0x08, Uint8List(0)); // 0x08 could mean STREAM without FIN
  processor.processFrame(invalidStreamEmptyNoFin);

  // Example of a valid STREAM frame with data
  final QuicStreamFrame validStreamWithData = QuicStreamFrame(0x08, Uint8List.fromList([0x01, 0x02, 0x03]));
  processor.processFrame(validStreamWithData);
  print('');
}