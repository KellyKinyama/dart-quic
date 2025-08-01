import 'dart:collection';

/// A class representing a non-overlapping, sorted set of integer ranges.
class RangeSet with IterableMixin<Range> {
  final List<Range> _ranges = [];

  RangeSet([Iterable<Range>? ranges]) {
    if (ranges != null) {
      for (final r in ranges) {
        assert(r.step == 1);
        add(r.start, r.end);
      }
    }
  }

  void add(int start, [int? stop]) {
    final end = stop ?? start + 1;
    assert(end > start);

    for (var i = 0; i < _ranges.length; i++) {
      final r = _ranges[i];

      // The added range is entirely before the current item, insert here.
      if (end < r.start) {
        _ranges.insert(i, Range(start, end));
        return;
      }

      // The added range is entirely after the current item, keep looking.
      if (start >= r.end) {
        continue;
      }

      // The added range touches the current item, merge it.
      start = min(start, r.start);
      var newEnd = max(end, r.end);
      while (i < _ranges.length - 1 && _ranges[i + 1].start <= newEnd) {
        newEnd = max(_ranges[i + 1].end, newEnd);
        _ranges.removeAt(i + 1);
      }
      _ranges[i] = Range(start, newEnd);
      return;
    }

    // The added range is entirely after all existing items, append it.
    _ranges.add(Range(start, end));
  }

  Range bounds() {
    if (_ranges.isEmpty) {
      throw StateError("Cannot get bounds of an empty RangeSet");
    }
    return Range(_ranges.first.start, _ranges.last.end);
  }

  Range shift() {
    if (_ranges.isEmpty) {
      throw StateError("Cannot shift from an empty RangeSet");
    }
    return _ranges.removeAt(0);
  }

  void subtract(int start, int end) {
    assert(end > start);

    var i = 0;
    while (i < _ranges.length) {
      final r = _ranges[i];

      // The removed range is entirely before the current item, stop here.
      if (end <= r.start) {
        return;
      }

      // The removed range is entirely after the current item, keep looking.
      if (start >= r.end) {
        i++;
        continue;
      }

      // The removed range completely covers the current item, remove it.
      if (start <= r.start && end >= r.end) {
        _ranges.removeAt(i);
        continue;
      }

      // The removed range touches the current item.
      if (start > r.start) {
        _ranges[i] = Range(r.start, start);
        if (end < r.end) {
          _ranges.insert(i + 1, Range(end, r.end));
        }
      } else {
        _ranges[i] = Range(end, r.end);
      }

      i++;
    }
  }

  // IterableMixin overrides
  @override
  Iterator<Range> get iterator => _ranges.iterator;

  // Custom getters/methods to mimic Python's Sequence protocol
  int get length => _ranges.length;
  Range operator [](int index) => _ranges[index];
  bool contains(int value) {
    for (final r in _ranges) {
      if (r.contains(value)) {
        return true;
      }
    }
    return false;
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! RangeSet) return false;
    return other._ranges.length == _ranges.length &&
        _ranges.every((range) => other._ranges.contains(range));
  }

  @override
  int get hashCode => Object.hashAll(_ranges);

  @override
  String toString() {
    return "RangeSet($_ranges)";
  }
}

/// A simple class to represent an integer range, similar to Python's range.
class Range {
  final int start;
  final int end;
  final int step;

  Range(this.start, this.end, [this.step = 1]) {
    if (step != 1) {
      throw UnsupportedError('Only step=1 is supported for now');
    }
    if (end < start) {
      throw ArgumentError('End must be greater than or equal to start');
    }
  }

  bool contains(int value) {
    return value >= start && value < end;
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is Range &&
        other.start == start &&
        other.end == end &&
        other.step == step;
  }

  @override
  int get hashCode => Object.hash(start, end, step);

  @override
  String toString() {
    return "range($start, $end, $step)";
  }
}

int min(int a, int b) => a < b ? a : b;
int max(int a, int b) => a > b ? a : b;
