import 'dart:math';

// A simple class to represent a range, since Dart doesn't have a built-in one.
class IntRange {
  final int start;
  final int end; // Exclusive

  IntRange(this.start, this.end) {
    if (start >= end) {
      throw ArgumentError('start must be less than end');
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is IntRange &&
          runtimeType == other.runtimeType &&
          start == other.start &&
          end == other.end;

  @override
  int get hashCode => start.hashCode ^ end.hashCode;
  
  @override
  String toString() => '[$start, $end)';
}

class RangeSet {
  final List<IntRange> _ranges = [];

  List<IntRange> get ranges => List.unmodifiable(_ranges);
  bool get isEmpty => _ranges.isEmpty;
  int get length => _ranges.length;
  
  IntRange operator [](int index) => _ranges[index];

  void add(int start, [int? end]) {
    end ??= start + 1;
    if (end <= start) return;

    for (var i = 0; i < _ranges.length; i++) {
      var r = _ranges[i];

      // The new range is entirely before the current range, insert here.
      if (end < r.start) {
        _ranges.insert(i, IntRange(start, end));
        return;
      }

      // The new range is entirely after the current range, continue.
      if (start > r.end) {
        continue;
      }
      
      // Merge with the current range.
      start = min(start, r.start);
      end = max(end, r.end);

      // Continue merging with subsequent overlapping ranges.
      var j = i + 1;
      while (j < _ranges.length && _ranges[j].start <= end!) {
        end = max(end, _ranges[j].end);
        j++;
      }
      
      // Remove the old merged ranges and insert the new combined one.
      _ranges.replaceRange(i, j, [IntRange(start, end)]);
      return;
    }
    
    // The new range is after all existing ranges.
    _ranges.add(IntRange(start, end));
  }
  
  void subtract(int start, int end) {
    if(end <= start) return;

    var i = 0;
    while(i < _ranges.length) {
      final r = _ranges[i];

      if(end <= r.start) return;
      if(start >= r.end) {
        i++;
        continue;
      }

      // The subtracted range completely covers the current one.
      if(start <= r.start && end >= r.end) {
        _ranges.removeAt(i);
        continue;
      }

      // The subtracted range splits the current one.
      if(start > r.start && end < r.end) {
        _ranges[i] = IntRange(r.start, start);
        _ranges.insert(i + 1, IntRange(end, r.end));
        i++;
      } 
      // The subtracted range truncates the start of the current one.
      else if(start <= r.start && end < r.end) {
        _ranges[i] = IntRange(end, r.end);
      } 
      // The subtracted range truncates the end of the current one.
      else if(start > r.start && end >= r.end) {
        _ranges[i] = IntRange(r.start, start);
      }
      i++;
    }
  }

  bool contains(int value) {
    for (final r in _ranges) {
      if (value >= r.start && value < r.end) {
        return true;
      }
    }
    return false;
  }

  @override
  String toString() => 'RangeSet(${_ranges.toString()})';
}