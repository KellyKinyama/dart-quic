import 'dart:typed_data';

import '../packet/quic_packet_header.dart';
import 'frame.dart';
// Assume VarInt helper from previous steps is available
// import 'path/to/varint_helper.dart';

// Definition for a single ACK Range
class QuicAckRange {
  final int gap; // Varint: number of unacknowledged packets since previous acknowledged range
  final int ackRangeLength; // Varint: number of consecutive acknowledged packets

  QuicAckRange({required this.gap, required this.ackRangeLength});

  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(gap));
    builder.add(VarInt.write(ackRangeLength));
    return builder.toBytes();
  }

  @override
  String toString() => 'Gap: $gap, Length: $ackRangeLength';
}

// Definition for ECN Counts (optional in ACK frame)
class QuicEcnCounts {
  final int ect0Count; // Varint
  final int ect1Count; // Varint
  final int ecnCeCount; // Varint

  QuicEcnCounts({required this.ect0Count, required this.ect1Count, required this.ecnCeCount});

  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(ect0Count));
    builder.add(VarInt.write(ect1Count));
    builder.add(VarInt.write(ecnCeCount));
    return builder.toBytes();
  }

  @override
  String toString() => 'ECT0: $ect0Count, ECT1: $ect1Count, ECN-CE: $ecnCeCount';
}

class QuicAckFrame extends QuicFrame {
  // Types: 0x02 (regular), 0x03 (with ECN)
  final int largestAcknowledged; // Varint
  final int ackDelay; // Varint (microseconds)
  final int ackRangeCount; // Varint
  final int firstAckRange; // Varint
  final List<QuicAckRange> ackRanges; // List of ACK Range objects
  final QuicEcnCounts? ecnCounts; // Optional ECN counts

  QuicAckFrame({
    required int type,
    required this.largestAcknowledged,
    required this.ackDelay,
    required this.ackRangeCount,
    required this.firstAckRange,
    required this.ackRanges,
    this.ecnCounts,
  }) : super(type) {
    if ((type == 0x03 && ecnCounts == null) || (type == 0x02 && ecnCounts != null)) {
      throw ArgumentError('ACK frame type mismatch with ECN counts presence.');
    }
    if (ackRanges.length != ackRangeCount) {
      throw ArgumentError('ACK Range Count does not match actual ACK ranges provided.');
    }
  }

  factory QuicAckFrame.parse(Uint8List data, int offset) {
    int currentOffset = offset;

    final type = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(type);
    if (type != 0x02 && type != 0x03) throw FormatException('Invalid frame type for ACK Frame.');

    final largestAcknowledged = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(largestAcknowledged);

    final ackDelay = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(ackDelay);

    final ackRangeCount = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(ackRangeCount);

    final firstAckRange = VarInt.read(data, currentOffset);
    currentOffset += VarInt.getLength(firstAckRange);

    final List<QuicAckRange> ackRanges = [];
    for (int i = 0; i < ackRangeCount; i++) {
      final gap = VarInt.read(data, currentOffset);
      currentOffset += VarInt.getLength(gap);
      final ackRangeLength = VarInt.read(data, currentOffset);
      currentOffset += VarInt.getLength(ackRangeLength);
      ackRanges.add(QuicAckRange(gap: gap, ackRangeLength: ackRangeLength));
    }

    QuicEcnCounts? ecnCounts;
    if (type == 0x03) { // If ECN type, parse ECN Counts
      final ect0Count = VarInt.read(data, currentOffset);
      currentOffset += VarInt.getLength(ect0Count);
      final ect1Count = VarInt.read(data, currentOffset);
      currentOffset += VarInt.getLength(ect1Count);
      final ecnCeCount = VarInt.read(data, currentOffset);
      currentOffset += VarInt.getLength(ecnCeCount);
      ecnCounts = QuicEcnCounts(ect0Count: ect0Count, ect1Count: ect1Count, ecnCeCount: ecnCeCount);
    }

    return QuicAckFrame(
      type: type,
      largestAcknowledged: largestAcknowledged,
      ackDelay: ackDelay,
      ackRangeCount: ackRangeCount,
      firstAckRange: firstAckRange,
      ackRanges: ackRanges,
      ecnCounts: ecnCounts,
    );
  }

  @override
  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.add(VarInt.write(type));
    builder.add(VarInt.write(largestAcknowledged));
    builder.add(VarInt.write(ackDelay));
    builder.add(VarInt.write(ackRangeCount));
    builder.add(VarInt.write(firstAckRange));
    for (var range in ackRanges) {
      builder.add(range.toBytes());
    }
    if (ecnCounts != null) {
      builder.add(ecnCounts!.toBytes());
    }
    return builder.toBytes();
  }

  @override
  String toString() {
    String ackRangesStr = ackRanges.map((r) => '[${r.toString()}]').join(', ');
    String ecnStr = ecnCounts != null ? ', ECN: ${ecnCounts.toString()}' : '';
    return 'AckFrame(Type: 0x${type.toRadixString(16)}, Largest Ack: $largestAcknowledged, Ack Delay: $ackDelay us, First Ack Range: $firstAckRange, Ranges: [$ackRangesStr]$ecnStr)';
  }
}