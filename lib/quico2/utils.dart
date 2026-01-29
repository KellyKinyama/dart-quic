import 'dart:typed_data';

import 'buffer.dart';
import 'quic_frame.dart';

dynamic buildAckFrameFromPackets(
  List<int>? packets,
  dynamic ecnStats,
  int? ackDelay,
) {
  if (packets == null || packets.isEmpty) return null;

  // Sort descending: [10, 9, 8, 5, 4]
  List<int> sorted = List.from(packets)..sort((a, b) => b.compareTo(a));

  List<Map<String, int>> ranges = [];
  int rangeStart = sorted[0];
  int rangeEnd = rangeStart;
  int lastPn = rangeStart;

  for (int i = 1; i < sorted.length; i++) {
    int pn = sorted[i];
    if (pn == lastPn - 1) {
      lastPn = pn;
    } else {
      ranges.add({'start': lastPn, 'end': rangeEnd});
      rangeEnd = pn;
      lastPn = pn;
    }
  }
  ranges.add({'start': lastPn, 'end': rangeEnd});

  int firstRange = ranges[0]['end']! - ranges[0]['start']!;
  List<Map<String, int>> ackRanges = [];

  for (int i = 1; i < ranges.length; i++) {
    int gap = ranges[i - 1]['start']! - ranges[i]['end']! - 1;
    int length = ranges[i]['end']! - ranges[i]['start']!;
    ackRanges.add({'gap': gap, 'length': length});
  }

  Map<String, dynamic> frame = {
    'type': 'ack',
    'largest': sorted[0],
    'delay': ackDelay ?? 0,
    'firstRange': firstRange,
    'ranges': ackRanges,
  };

  if (ecnStats != null) {
    frame['ecn'] = {
      'ect0': ecnStats['ect0'] ?? 0,
      'ect1': ecnStats['ect1'] ?? 0,
      'ce': ecnStats['ce'] ?? 0,
    };
  }

  return frame;
}

/// Serializes an ACK frame object into bytes using the Buffer class.
Uint8List serialize_ack_frame(dynamic ack) {
  final buf = Buffer();

  // 1. Type Byte
  // 0x02 = ACK, 0x03 = ACK + ECN
  bool hasEcn = ack['ecn'] != null;
  buf.pushUint8(hasEcn ? 0x03 : 0x02);

  // 2. Largest Acknowledged (VarInt)
  buf.pushUintVar(ack['largest']);

  // 3. ACK Delay (VarInt)
  // Note: This is usually scaled by the ack_delay_exponent
  buf.pushUintVar(ack['delay']);

  // 4. ACK Range Count (VarInt)
  // This is the number of Gap/Length pairs (the 'ranges' list)
  List<dynamic> additionalRanges = ack['ranges'] ?? [];
  buf.pushUintVar(additionalRanges.length);

  // 5. First ACK Range (VarInt)
  // Number of packets preceding the largest acknowledged
  buf.pushUintVar(ack['firstRange']);

  // 6. Additional ACK Ranges (Gaps and Lengths)
  for (var range in additionalRanges) {
    buf.pushUintVar(range['gap']);
    buf.pushUintVar(range['length']);
  }

  // 7. ECN Counts (Optional)
  if (hasEcn) {
    final ecn = ack['ecn'];
    buf.pushUintVar(ecn['ect0'] ?? 0);
    buf.pushUintVar(ecn['ect1'] ?? 0);
    buf.pushUintVar(ecn['ce'] ?? 0);
  }

  return buf.toBytes();
}

/// Encodes an integer into a QUIC VarInt (Uint8List).
Uint8List writeVarInt(dynamic value) {
  // Convert to int if it's a BigInt that fits, or handle as num
  int val;
  if (value is BigInt) {
    val = value.toInt();
  } else {
    val = value;
  }

  if (val < 0x40) {
    // 1 byte, prefix 00
    return Uint8List.fromList([val]);
  }

  if (val < 0x4000) {
    // 2 bytes, prefix 01
    return Uint8List.fromList([0x40 | (val >> 8), val & 0xff]);
  }

  if (val < 0x40000000) {
    // 4 bytes, prefix 10
    return Uint8List.fromList([
      0x80 | (val >> 24),
      (val >> 16) & 0xff,
      (val >> 8) & 0xff,
      val & 0xff,
    ]);
  }

  // Handle 8-byte integers (up to 64-bit)
  // Using BigInt for safety with very large numbers
  BigInt bigVal = BigInt.from(val);
  BigInt mask8 = BigInt.from(0xff);

  return Uint8List.fromList([
    0xC0 | ((bigVal >> 56).toInt() & 0x3f),
    ((bigVal >> 48) & mask8).toInt(),
    ((bigVal >> 40) & mask8).toInt(),
    ((bigVal >> 32) & mask8).toInt(),
    ((bigVal >> 24) & mask8).toInt(),
    ((bigVal >> 16) & mask8).toInt(),
    ((bigVal >> 8) & mask8).toInt(),
    (bigVal & mask8).toInt(),
  ]);
}

/// Decodes a QUIC VarInt from a buffer at a specific offset.
Map<String, dynamic>? readVarInt(Uint8List array, int offset) {
  if (offset >= array.length) return null;

  final int first = array[offset];
  final int prefix = first >> 6;

  if (prefix == 0x00) {
    return {'value': first & 0x3f, 'byteLength': 1};
  }

  if (prefix == 0x01) {
    if (offset + 1 >= array.length) return null;
    final int value = ((first & 0x3f) << 8) | array[offset + 1];
    return {'value': value, 'byteLength': 2};
  }

  if (prefix == 0x02) {
    // Binary 10
    if (offset + 3 >= array.length) return null;
    final int value =
        (((first & 0x3f) << 24) |
                (array[offset + 1] << 16) |
                (array[offset + 2] << 8) |
                array[offset + 3])
            .toUnsigned(32);
    return {'value': value, 'byteLength': 4};
  }

  if (prefix == 0x03) {
    // Binary 11
    if (offset + 7 >= array.length) return null;

    // Use BigInt to prevent overflow on 32-bit systems or JS-compiled Dart
    BigInt hi = BigInt.from(
      (((first & 0x3f) << 24) |
              (array[offset + 1] << 16) |
              (array[offset + 2] << 8) |
              array[offset + 3])
          .toUnsigned(32),
    );

    BigInt lo = BigInt.from(
      ((array[offset + 4] << 24) |
              (array[offset + 5] << 16) |
              (array[offset + 6] << 8) |
              (array[offset + 7]))
          .toUnsigned(32),
    );

    BigInt full = (hi << 32) | lo;

    return {'value': full.isValidInt ? full.toInt() : full, 'byteLength': 8};
  }

  return null;
}

typedef EcnStats = ({int ect0, int ect1, int ce});

/// Builds a type-safe AckFrame from a flat list of PN ranges [start, end, start, end].
AckFrame? build_ack_info_from_ranges(
  List<int> flatRanges,
  EcnStats? ecnStats,
  int? ackDelay,
) {
  if (flatRanges.isEmpty) return null;
  if (flatRanges.length % 2 != 0) {
    throw ArgumentError("flatRanges must be in [from, to, ...] pairs");
  }

  // 1. Create mutable list of range records
  var ranges = <({int start, int end})>[];
  for (var i = 0; i < flatRanges.length; i += 2) {
    int from = flatRanges[i];
    int to = flatRanges[i + 1];
    if (to < from)
      throw ArgumentError("Range end ($to) must be >= start ($from)");
    ranges.add((start: from, end: to));
  }

  // 2. Sort ranges from highest end to lowest (Required for QUIC ACK encoding)
  ranges.sort((a, b) => b.end.compareTo(a.end));

  // 3. Merge overlapping or adjacent ranges
  var merged = <({int start, int end})>[];
  merged.add(ranges[0]);

  for (var i = 1; i < ranges.length; i++) {
    var last = merged.last;
    var curr = ranges[i];

    if (curr.end >= last.start - 1) {
      // Overlap or adjacency detected: merge them
      int newStart = curr.start < last.start ? curr.start : last.start;
      merged[merged.length - 1] = (start: newStart, end: last.end);
    } else {
      merged.add(curr);
    }
  }

  // 4. Construct AckFrame properties according to RFC 9000
  int largest = merged[0].end;
  int firstRange = largest - merged[0].start;
  var ackRanges = <AckRange>[];

  for (var i = 1; i < merged.length; i++) {
    // Gap: number of packets between ranges minus 1
    int gap = merged[i - 1].start - merged[i].end - 1;
    int length = merged[i].end - merged[i].start;

    if (gap < 0) continue;
    ackRanges.add(AckRange(gap, length));
  }

  return AckFrame(
    data: Uint8List(0),
    largest: largest,
    delay: ackDelay ?? 0,
    firstRange: firstRange,
    ranges: ackRanges,
    ecn: ecnStats != null
        ? {'ect0': ecnStats.ect0, 'ect1': ecnStats.ect1, 'ce': ecnStats.ce}
        : null,
  );
}

/// Converts an AckFrame back into a flat list of integers [start, end, ...]
/// for easier internal tracking.
List<int> quic_acked_info_to_ranges(AckFrame ackFrame) {
  final List<int> flatRanges = [];

  int rangeEnd = ackFrame.largest;
  int rangeStart = rangeEnd - ackFrame.firstRange;

  flatRanges.addAll([rangeStart, rangeEnd]);

  for (final r in ackFrame.ranges) {
    // Move backwards through the gaps
    rangeEnd = rangeStart - 1 - r.gap;
    rangeStart = rangeEnd - r.length;

    if (rangeStart < 0) break;
    flatRanges.addAll([rangeStart, rangeEnd]);
  }

  return flatRanges;
}
