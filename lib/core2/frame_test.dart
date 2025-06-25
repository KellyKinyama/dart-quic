// main.dart (add to existing main.dart)
// ... existing imports ...
import 'dart:typed_data';

import 'frames/quic_frame_types.dart';
import 'frames/quic_frame_parser.dart'; // New import

// ... ListEquality class (if not already there) ...

void main() {
  // ... (previous test calls for VLQ, Transport Parameters) ...

  // --- Test QUIC Frames ---
  print('\n--- Testing QUIC Frames ---');

  // Test Case F1: PADDING and PING frames
  print('\n--- Test Case F1: PADDING and PING ---');
  final PaddingFrame padding1 = PaddingFrame();
  final PingFrame ping1 = PingFrame();
  final HandshakeDoneFrame hsDone1 = HandshakeDoneFrame();

  final List<QuicFrame> simpleFrames = [padding1, ping1, hsDone1];
  final Uint8List encodedSimpleFrames = QuicFrameParser.encodeFrames(
    simpleFrames,
  );
  print('Encoded Simple Frames (${encodedSimpleFrames.length} bytes):');
  printBytes(encodedSimpleFrames);

  final List<QuicFrame> parsedSimpleFrames = QuicFrameParser.parseFrames(
    encodedSimpleFrames,
  );
  assert(
    parsedSimpleFrames.length == 3,
    'F1: Expected 3 frames, got ${parsedSimpleFrames.length}',
  );
  assert(
    parsedSimpleFrames[0] is PaddingFrame,
    'F1: First frame not PaddingFrame',
  );
  assert(parsedSimpleFrames[1] is PingFrame, 'F1: Second frame not PingFrame');
  assert(
    parsedSimpleFrames[2] is HandshakeDoneFrame,
    'F1: Third frame not HandshakeDoneFrame',
  );
  print('Test Case F1 (PADDING, PING, HANDSHAKE_DONE) successful!');

  // Test Case F2: MAX_DATA and DATA_BLOCKED frames
  print('\n--- Test Case F2: MAX_DATA and DATA_BLOCKED ---');
  final MaxDataFrame maxData1 = MaxDataFrame(1000000); // 1MB
  final DataBlockedFrame dataBlocked1 = DataBlockedFrame(999999);

  final List<QuicFrame> flowControlFrames = [maxData1, dataBlocked1];
  final Uint8List encodedFlowControlFrames = QuicFrameParser.encodeFrames(
    flowControlFrames,
  );
  print(
    'Encoded Flow Control Frames (${encodedFlowControlFrames.length} bytes):',
  );
  printBytes(encodedFlowControlFrames);

  final List<QuicFrame> parsedFlowControlFrames = QuicFrameParser.parseFrames(
    encodedFlowControlFrames,
  );
  assert(
    parsedFlowControlFrames.length == 2,
    'F2: Expected 2 frames, got ${parsedFlowControlFrames.length}',
  );
  assert(
    parsedFlowControlFrames[0] is MaxDataFrame,
    'F2: First frame not MaxDataFrame',
  );
  assert(
    (parsedFlowControlFrames[0] as MaxDataFrame).maximumData == 1000000,
    'F2: MaxData value mismatch',
  );
  assert(
    parsedFlowControlFrames[1] is DataBlockedFrame,
    'F2: Second frame not DataBlockedFrame',
  );
  assert(
    (parsedFlowControlFrames[1] as DataBlockedFrame).maximumData == 999999,
    'F2: DataBlocked value mismatch',
  );
  print('Test Case F2 (MAX_DATA, DATA_BLOCKED) successful!');

  // Test Case F3: MAX_STREAM_DATA, STREAM_DATA_BLOCKED, STOP_SENDING, RESET_STREAM
  print('\n--- Test Case F3: Stream-Related Frames ---');
  final MaxStreamDataFrame maxStreamData1 = MaxStreamDataFrame(0x04, 50000);
  final StreamDataBlockedFrame streamDataBlocked1 = StreamDataBlockedFrame(
    0x08,
    49999,
  );
  final StopSendingFrame stopSending1 = StopSendingFrame(
    0x0C,
    0x01,
  ); // Stream 0x0C, App Error 0x01
  final ResetStreamFrame resetStream1 = ResetStreamFrame(0x10, 0x02, 12345);

  final List<QuicFrame> streamFrames = [
    maxStreamData1,
    streamDataBlocked1,
    stopSending1,
    resetStream1,
  ];
  final Uint8List encodedStreamFrames = QuicFrameParser.encodeFrames(
    streamFrames,
  );
  print('Encoded Stream Frames (${encodedStreamFrames.length} bytes):');
  printBytes(encodedStreamFrames);

  final List<QuicFrame> parsedStreamFrames = QuicFrameParser.parseFrames(
    encodedStreamFrames,
  );
  assert(
    parsedStreamFrames.length == 4,
    'F3: Expected 4 frames, got ${parsedStreamFrames.length}',
  );
  assert(
    (parsedStreamFrames[0] as MaxStreamDataFrame).streamId == 0x04,
    'F3: MaxStreamData streamId mismatch',
  );
  assert(
    (parsedStreamFrames[1] as StreamDataBlockedFrame).maximumStreamData ==
        49999,
    'F3: StreamDataBlocked data mismatch',
  );
  assert(
    (parsedStreamFrames[2] as StopSendingFrame).applicationProtocolErrorCode ==
        0x01,
    'F3: StopSending error code mismatch',
  );
  assert(
    (parsedStreamFrames[3] as ResetStreamFrame).finalSize == 12345,
    'F3: ResetStream final size mismatch',
  );
  print('Test Case F3 (Stream-Related Frames) successful!');

  // Test Case F4: ACK Frame (no ECN, single range)
  print('\n--- Test Case F4: ACK Frame (No ECN) ---');
  final AckFrame ack1 = AckFrame(
    rawType: 0x02,
    largestAcknowledged: 100,
    ackDelay:
        125, // 125 * 2^3 = 1000 microseconds (1ms) if ack_delay_exponent is 3
    firstAckRange: 5, // Acknowledges 95-100 (100 - 5 = 95)
    ackRanges: [], // No additional ranges
  );

  final Uint8List encodedAck1 = QuicFrameParser.encodeFrames([ack1]);
  print('Encoded ACK Frame 1 (${encodedAck1.length} bytes):');
  printBytes(encodedAck1);

  final List<QuicFrame> parsedAck1List = QuicFrameParser.parseFrames(
    encodedAck1,
  );
  assert(
    parsedAck1List.length == 1 && parsedAck1List[0] is AckFrame,
    'F4: Expected 1 ACK frame',
  );
  final AckFrame parsedAck1 = parsedAck1List[0] as AckFrame;
  assert(parsedAck1.rawType == 0x02, 'F4: ACK rawType mismatch');
  assert(
    parsedAck1.largestAcknowledged == 100,
    'F4: ACK largestAcknowledged mismatch',
  );
  assert(parsedAck1.ackDelay == 125, 'F4: ACK ackDelay mismatch');
  assert(parsedAck1.firstAckRange == 5, 'F4: ACK firstAckRange mismatch');
  assert(parsedAck1.ackRanges.isEmpty, 'F4: ACK ackRanges not empty');
  assert(
    parsedAck1.ecnCounts == null,
    'F4: ACK ECN counts present unexpectedly',
  );
  print('Test Case F4 (ACK Frame No ECN) successful!');

  // Test Case F5: ACK Frame (with ECN, multiple ranges)
  print('\n--- Test Case F5: ACK Frame (With ECN & Multiple Ranges) ---');
  final AckFrame ack2 = AckFrame(
    rawType: 0x03,
    largestAcknowledged: 200,
    ackDelay: 2000, // 2000 * 2^3 = 16000 microseconds (16ms)
    firstAckRange: 0, // Acknowledges only 200
    ackRanges: [
      AckRange(
        gap: 2,
        ackRangeLength: 1,
      ), // Gaps are 1 higher than value: gap of 3 unacked packets
      // previous_smallest (200) - gap (2+1) - 2 = 200-3-2 = 195.
      // 195 - 1 = 194. Range 194-195. (length 2)
      AckRange(gap: 5, ackRangeLength: 3), // gap of 6 unacked packets
      // previous_smallest (194) - gap (5+1) - 2 = 194-6-2 = 186.
      // 186 - 3 = 183. Range 183-186. (length 4)
    ],
    ecnCounts: EcnCounts(ect0Count: 10, ect1Count: 5, ecnCeCount: 2),
  );

  final Uint8List encodedAck2 = QuicFrameParser.encodeFrames([ack2]);
  print('Encoded ACK Frame 2 (${encodedAck2.length} bytes):');
  printBytes(encodedAck2);

  final List<QuicFrame> parsedAck2List = QuicFrameParser.parseFrames(
    encodedAck2,
  );
  assert(
    parsedAck2List.length == 1 && parsedAck2List[0] is AckFrame,
    'F5: Expected 1 ACK frame',
  );
  final AckFrame parsedAck2 = parsedAck2List[0] as AckFrame;
  assert(parsedAck2.rawType == 0x03, 'F5: ACK rawType mismatch');
  assert(
    parsedAck2.largestAcknowledged == 200,
    'F5: ACK largestAcknowledged mismatch',
  );
  assert(parsedAck2.ackDelay == 2000, 'F5: ACK ackDelay mismatch');
  assert(parsedAck2.firstAckRange == 0, 'F5: ACK firstAckRange mismatch');
  assert(parsedAck2.ackRanges.length == 2, 'F5: ACK ackRanges length mismatch');
  assert(
    parsedAck2.ackRanges[0].gap == 2 &&
        parsedAck2.ackRanges[0].ackRangeLength == 1,
    'F5: ACK Range 0 mismatch',
  );
  assert(
    parsedAck2.ackRanges[1].gap == 5 &&
        parsedAck2.ackRanges[1].ackRangeLength == 3,
    'F5: ACK Range 1 mismatch',
  );
  assert(parsedAck2.hasEcn, 'F5: ACK ECN not present');
  assert(
    parsedAck2.ecnCounts!.ect0Count == 10 &&
        parsedAck2.ecnCounts!.ect1Count == 5 &&
        parsedAck2.ecnCounts!.ecnCeCount == 2,
    'F5: ECN counts mismatch',
  );
  print('Test Case F5 (ACK Frame With ECN & Multiple Ranges) successful!');

  // Test Case F6: Invalid Frame Data (e.g., truncated frame)
  print('\n--- Test Case F6: Invalid Frame Data (Truncated) ---');
  final Uint8List truncatedMaxData = Uint8List.fromList([
    0x10, // MAX_DATA type
    0x40, // Partial VLQ for Maximum Data (should be 0x40 XX, but only 0x40 is there)
  ]);
  try {
    QuicFrameParser.parseFrames(truncatedMaxData);
    assert(
      false,
      'F6: Expected FormatException for truncated frame, but no exception was thrown.',
    );
  } on FormatException catch (e) {
    print('F6: Successfully caught expected exception for truncated frame: $e');
  } catch (e) {
    assert(false, 'F6: Caught unexpected exception type: $e');
  }
  print('Test Case F6 (Invalid Frame Data) successful!');

  // Test Case F7: Unimplemented Frame Type
  print('\n--- Test Case F7: Unimplemented Frame Type ---');
  final Uint8List unimplementedFrameBytes = Uint8List.fromList([
    0x06, // CRYPTO Frame (currently unimplemented in our classes)
    0x00, // Offset (0)
    0x01, // Length (1)
    0xAA, // Crypto Data
  ]);
  try {
    QuicFrameParser.parseFrames(unimplementedFrameBytes);
    assert(
      false,
      'F7: Expected UnimplementedError for unimplemented frame, but no exception was thrown.',
    );
  } on UnimplementedError catch (e) {
    print(
      'F7: Successfully caught expected exception for unimplemented frame: $e',
    );
  } catch (e) {
    assert(false, 'F7: Caught unexpected exception type: $e');
  }
  print('Test Case F7 (Unimplemented Frame Type) successful!');
}

// Helper to print bytes in hex format
void printBytes(Uint8List bytes) {
  StringBuffer sb = StringBuffer();
  for (int i = 0; i < bytes.length; i++) {
    sb.write(bytes[i].toRadixString(16).padLeft(2, '0'));
    if ((i + 1) % 16 == 0) {
      sb.writeln(); // Newline every 16 bytes
    } else if ((i + 1) % 8 == 0) {
      sb.write('  '); // Double space every 8 bytes
    } else {
      sb.write(' ');
    }
  }
  print(sb.toString().trim());
}
