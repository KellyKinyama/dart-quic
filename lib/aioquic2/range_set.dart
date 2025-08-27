// Filename: rangeset.dart
import 'dart:math';

class IntRange {
  final int start; // inclusive
  final int end; // exclusive

  IntRange(this.start, this.end);

  @override
  String toString() => '[$start, $end)';
}

class RangeSet {
  final List<IntRange> _ranges = [];

  bool get isEmpty => _ranges.isEmpty;
  int get length => _ranges.length;
  IntRange operator [](int index) => _ranges[index];
  IntRange get first => _ranges.first;
  IntRange get last => _ranges.last;

  bool contains(int value) {
    for (final r in _ranges) {
      if (value >= r.start && value < r.end) {
        return true;
      }
    }
    return false;
  }

  void add(int start, int end) {
    if (end <= start) return;

    for (int i = 0; i < _ranges.length; i++) {
      var r = _ranges[i];

      // Insert before current range
      if (end < r.start) {
        _ranges.insert(i, IntRange(start, end));
        return;
      }

      // Skip if after current range
      if (start > r.end) continue;

      // Merge with current and subsequent ranges
      start = min(start, r.start);
      end = max(end, r.end);

      while (i < _ranges.length - 1 && _ranges[i + 1].start <= end) {
        end = max(_ranges[i + 1].end, end);
        _ranges.removeAt(i + 1);
      }
      _ranges[i] = IntRange(start, end);
      return;
    }

    // Append at the end
    _ranges.add(IntRange(start, end));
  }

  IntRange shift() {
    return _ranges.removeAt(0);
  }

  void subtract(int start, int end) {
    if (end <= start) return;

    int i = 0;
    while (i < _ranges.length) {
      var r = _ranges[i];

      if (end <= r.start) return;
      if (start >= r.end) {
        i++;
        continue;
      }

      // The range to subtract completely covers the current range
      if (start <= r.start && end >= r.end) {
        _ranges.removeAt(i);
        continue;
      }

      // The range to subtract splits the current range
      if (start > r.start && end < r.end) {
        _ranges[i] = IntRange(r.start, start);
        _ranges.insert(i + 1, IntRange(end, r.end));
        i += 2;
        continue;
      }

      // The range to subtract touches the start
      if (start <= r.start && end < r.end) {
        _ranges[i] = IntRange(end, r.end);
      }
      // The range to subtract touches the end
      else if (start > r.start && end >= r.end) {
        _ranges[i] = IntRange(r.start, start);
      }
      i++;
    }
  }

  @override
  String toString() =>
      'RangeSet(${_ranges.map((r) => r.toString()).join(", ")})';
}
