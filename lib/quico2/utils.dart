import 'dart:typed_data';

import 'buffer.dart';

dynamic buildAckFrameFromPackets(List<int>? packets, dynamic ecnStats, int? ackDelay) {
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
    'ranges': ackRanges
  };

  if (ecnStats != null) {
    frame['ecn'] = {
      'ect0': ecnStats['ect0'] ?? 0,
      'ect1': ecnStats['ect1'] ?? 0,
      'ce': ecnStats['ce'] ?? 0
    };
  }

  return frame;
}

dynamic build_ack_info_from_ranges(List<int>? flatRanges, dynamic ecnStats, int? ackDelay) {
  if (flatRanges == null || flatRanges.isEmpty) return null;
  if (flatRanges.length % 2 != 0) throw Exception("flatRanges must be in [from, to, ...] pairs");

  List<Map<String, int>> ranges = [];
  for (int i = 0; i < flatRanges.length; i += 2) {
    int from = flatRanges[i];
    int to = flatRanges[i + 1];
    if (to < from) throw Exception("Range end must be >= start");
    ranges.add({'start': from, 'end': to});
  }

  // Sort ranges from highest to lowest end
  ranges.sort((a, b) => b['end']!.compareTo(a['end']!));

  // Merge overlapping or adjacent ranges
  List<Map<String, int>> merged = [ranges[0]];
  for (int i = 1; i < ranges.length; i++) {
    var last = merged.last;
    var curr = ranges[i];
    if (curr['end']! >= last['start']! - 1) {
      last['start'] = (last['start']! < curr['start']!) ? last['start']! : curr['start']!;
    } else {
      merged.add(curr);
    }
  }

  int largest = merged[0]['end']!;
  int firstRange = largest - merged[0]['start']!;
  List<Map<String, int>> ackRanges = [];

  for (int i = 1; i < merged.length; i++) {
    int gap = merged[i - 1]['start']! - merged[i]['end']! - 1;
    int length = merged[i]['end']! - merged[i]['start']!;
    ackRanges.add({'gap': gap, 'length': length});
  }

  return {
    'type': 'ack',
    'largest': largest,
    'delay': ackDelay ?? 0,
    'firstRange': firstRange,
    'ranges': ackRanges,
    'ecn': ecnStats != null ? {
      'ect0': ecnStats['ect0'] ?? 0,
      'ect1': ecnStats['ect1'] ?? 0,
      'ce': ecnStats['ce'] ?? 0
    } : null
  };
}

List<int> quic_acked_info_to_ranges(dynamic ackFrame) {
  List<int> flatRanges = [];

  if (ackFrame == null || ackFrame['type'] != 'ack') return flatRanges;

  int largest = ackFrame['largest'];
  int firstRange = ackFrame['firstRange'];

  // First range: [largest - firstRange, largest]
  int rangeEnd = largest;
  int rangeStart = rangeEnd - firstRange;
  flatRanges.add(rangeStart);
  flatRanges.add(rangeEnd);

  // Subsequent ranges
  List<dynamic> ranges = ackFrame['ranges'] ?? [];
  for (var r in ranges) {
    int gap = r['gap'];
    int length = r['length'];

    // Move backward through the gap
    rangeEnd = rangeStart - 1 - gap;
    rangeStart = rangeEnd - length;

    flatRanges.add(rangeStart);
    flatRanges.add(rangeEnd);
  }

  return flatRanges;
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