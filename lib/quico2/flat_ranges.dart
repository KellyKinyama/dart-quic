import 'dart:math';

class FlatRanges {
  /// Clips [subtractRanges] against [baseRanges], effectively returning
  /// only parts of [subtractRanges] that exist within [baseRanges].
  static List<int> subtract_clip(
    List<int> baseRanges,
    List<int> subtractRanges,
  ) {
    List<int> result = [];
    for (int i = 0; i < subtractRanges.length; i += 2) {
      int from = subtractRanges[i];
      int to = subtractRanges[i + 1];
      List<int> clipped = [from, to];
      remove(clipped, baseRanges);
      for (int j = 0; j < clipped.length; j += 2) {
        result.addAll([clipped[j], clipped[j + 1]]);
      }
    }
    return result;
  }

  /// Merges overlapping or adjacent ranges into a single continuous list.
  static List<int> merge(List<int> flatRanges) {
    List<int> result = [];
    for (int i = 0; i < flatRanges.length; i += 2) {
      int from = flatRanges[i];
      int to = flatRanges[i + 1];
      if (result.isEmpty) {
        result.addAll([from, to]);
      } else {
        int lastTo = result.last;
        if (from <= lastTo) {
          result[result.length - 1] = max(lastTo, to);
        } else {
          result.addAll([from, to]);
        }
      }
    }
    return result;
  }

  /// Inverts ranges within a boundary to find gaps (unknown data).
  static List<int> invert(List<int> ranges, int fullStart, int fullEnd) {
    List<int> result = [];
    int last = fullStart;

    for (int i = 0; i < ranges.length; i += 2) {
      int from = ranges[i];
      if (from > last) result.addAll([last, from]);
      last = max(last, ranges[i + 1]);
    }

    if (last < fullEnd) result.addAll([last, fullEnd]);
    return result;
  }

  /// Removes [removeRanges] from the provided [ranges] list (mutates the list).
  static bool remove(List<int> ranges, List<int> removeRanges) {
    List<int> result = [];
    int i = 0, j = 0;
    bool changed = false;

    while (i < ranges.length && j < removeRanges.length) {
      int aFrom = ranges[i], aTo = ranges[i + 1];
      int bFrom = removeRanges[j], bTo = removeRanges[j + 1];

      if (aFrom == aTo) aTo = aFrom + 1;
      if (bFrom == bTo) bTo = bFrom + 1;

      if (aTo <= bFrom) {
        result.addAll([aFrom, aTo]);
        i += 2;
      } else if (aFrom >= bTo) {
        j += 2;
      } else {
        if (aFrom < bFrom) result.addAll([aFrom, bFrom]);
        if (aTo > bTo) result.addAll([bTo, aTo]);
        changed = true;
        i += 2;
      }
    }

    while (i < ranges.length) {
      int aFrom = ranges[i], aTo = ranges[i + 1];
      if (aFrom == aTo) aTo = aFrom + 1;
      result.addAll([aFrom, aTo]);
      i += 2;
    }

    if (result.length != ranges.length) changed = true;

    // In Dart, we update the existing list to match the result
    ranges.clear();
    ranges.addAll(result);

    return changed;
  }

  /// Adds [newRanges] to [ranges], merging them (mutates the list).
  static bool add(List<int> ranges, List<int> newRanges) {
    bool changed = false;
    List<List<int>> all = [];

    for (int i = 0; i < ranges.length; i += 2) {
      all.add([ranges[i], ranges[i + 1]]);
    }
    for (int i = 0; i < newRanges.length; i += 2) {
      all.add([newRanges[i], newRanges[i + 1]]);
    }

    all.sort((a, b) => a[0].compareTo(b[0]));

    List<int> merged = [];
    for (var range in all) {
      int from = range[0];
      int to = range[1];
      if (merged.isEmpty) {
        merged.addAll([from, to]);
      } else {
        int lastTo = merged.last;
        if (from <= lastTo + 1) {
          // +1 for adjacent merging
          if (to > lastTo) {
            merged[merged.length - 1] = to;
            changed = true;
          }
        } else {
          merged.addAll([from, to]);
          changed = true;
        }
      }
    }

    if (merged.length != ranges.length) changed = true;

    ranges.clear();
    ranges.addAll(merged);

    return changed;
  }

  /// Calculates total bytes covered by these ranges.
  static int length(List<int> ranges) {
    int total = 0;
    for (int i = 0; i < ranges.length; i += 2) {
      total += (ranges[i + 1] - ranges[i]);
    }
    return total;
  }

  /// Identifies ranges that are neither in "Have" nor "Not Have".
  static List<int> unknow(
    List<int> have,
    List<int> notHave,
    int start,
    int end,
  ) {
    List<int> combined = List.from(have)..addAll(notHave);
    return invert(merge(combined), start, end);
  }
}
