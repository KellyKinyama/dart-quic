// Filename: test/rangeset_test.dart
import 'package:test/test.dart';
import '../range_set.dart'; // Adjust import path as needed

// Helper to compare a RangeSet to a list of Dart Ranges for easy testing.
Matcher equalsRanges(List<Range> ranges) {
  return predicate<RangeSet>((rangeset) {
    if (rangeset.length != ranges.length) return false;
    for (int i = 0; i < ranges.length; i++) {
      if (rangeset[i].start != ranges[i].start ||
          rangeset[i].end != ranges[i].end) {
        return false;
      }
    }
    return true;
  }, 'matches ranges $ranges');
}

void main() {
  group('RangeSetTest', () {
    test('add single merge', () {
      final rangeset = RangeSet();
      rangeset.add(0, 1);
      rangeset.add(2, 3);
      expect(rangeset, equalsRanges([Range(0, 1), Range(2, 3)]));

      rangeset.add(1, 2);
      expect(rangeset, equalsRanges([Range(0, 3)]));
    });

    test('add range overlap', () {
      final rangeset = RangeSet();
      rangeset.add(0, 2);
      rangeset.add(3, 5);
      expect(rangeset, equalsRanges([Range(0, 2), Range(3, 5)]));

      rangeset.add(1, 4);
      expect(rangeset, equalsRanges([Range(0, 5)]));
    });

    test('subtract split', () {
      final rangeset = RangeSet();
      rangeset.add(0, 10);
      rangeset.subtract(2, 5);
      expect(rangeset, equalsRanges([Range(0, 2), Range(5, 10)]));
    });

    test('contains', () {
      final rangeset = RangeSet();
      rangeset.add(0, 1);
      rangeset.add(3, 6);
      expect(rangeset.contains(0), isTrue);
      expect(rangeset.contains(1), isFalse);
      expect(rangeset.contains(2), isFalse);
      expect(rangeset.contains(5), isTrue);
      expect(rangeset.contains(6), isFalse);
    });

    test('shift', () {
      final rangeset = RangeSet();
      rangeset.add(1, 2);
      rangeset.add(3, 4);
      final r = rangeset.shift();
      expect(r.start, 1);
      expect(r.end, 2);
      expect(rangeset, equalsRanges([Range(3, 4)]));
    });
  });
}
