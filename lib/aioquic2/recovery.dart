// Filename: recovery.dart
import 'dart:math';
import 'packet_builder.dart';
import 'range_set.dart';
import 'tls.dart';

// --- Constants ---
const kPacketThreshold = 3;
const kTimeThreshold = 9 / 8;
const kGranularity = 0.001; // 1 millisecond
const kInitialRtt = 0.1; // 100 milliseconds

class QuicPacketSpace {
  double? ackAt;
  final RangeSet ackQueue = RangeSet();
  bool discarded = false;
  int expectedPacketNumber = 0;
  int largestReceivedPacket = -1;
  double? largestReceivedTime;

  int ackElicitingInFlight = 0;
  int largestAckedPacket = -1;
  double? lossTime;
  final Map<int, QuicSentPacket> sentPackets = {};
}

class QuicPacketRecovery {
  final Map<TlsEpoch, QuicPacketSpace> spaces = {
    TlsEpoch.initial: QuicPacketSpace(),
    TlsEpoch.handshake: QuicPacketSpace(),
    TlsEpoch.oneRtt: QuicPacketSpace(),
  };

  double _rttSmoothed = kInitialRtt;
  double _rttVariance = kInitialRtt / 2;
  double _rttLatest = 0.0;
  double _rttMin = double.infinity;
  bool _rttInitialized = false;

  int _ptoCount = 0;
  double _timeOfLastAckElicitingPacket = 0;

  // Congestion Control (Reno)
  int bytesInFlight = 0;
  late int _congestionWindow;
  final int _maxDatagramSize;

  QuicPacketRecovery({required int maxDatagramSize})
    : _maxDatagramSize = maxDatagramSize,
      _congestionWindow = 10 * maxDatagramSize; // Initial window

  int get congestionWindow => _congestionWindow;

  double getProbeTimeout() {
    if (!_rttInitialized) return 2 * kInitialRtt;
    return _rttSmoothed + max(4 * _rttVariance, kGranularity);
  }

  double? getLossDetectionTime() {
    double? earliestLossTime;
    for (final space in spaces.values) {
      if (!space.discarded && space.lossTime != null) {
        if (earliestLossTime == null || space.lossTime! < earliestLossTime) {
          earliestLossTime = space.lossTime;
        }
      }
    }
    if (earliestLossTime != null) return earliestLossTime;

    if (bytesInFlight > 0) {
      final timeout = getProbeTimeout() * (1 << _ptoCount);
      return _timeOfLastAckElicitingPacket + timeout;
    }
    return null;
  }

  void onPacketSent(QuicSentPacket packet, TlsEpoch epoch) {
    final space = spaces[epoch]!;
    packet.sentTime = DateTime.now().millisecondsSinceEpoch / 1000.0;
    space.sentPackets[packet.packetNumber] = packet;
    if (packet.inFlight) {
      bytesInFlight += packet.sentBytes;
      if (packet.isAckEliciting) {
        _timeOfLastAckElicitingPacket = packet.sentTime!;
      }
    }
  }

  void onAckReceived(
    RangeSet ackRangeset,
    double ackDelay,
    double now,
    TlsEpoch epoch,
  ) {
    final space = spaces[epoch]!;
    int largestAcked = ackRangeset.last.end - 1;
    if (largestAcked > space.largestAckedPacket) {
      space.largestAckedPacket = largestAcked;
    }

    List<int> newlyAckedNumbers = [];
    QuicSentPacket? latestAckedPacket;
    for (final pn in space.sentPackets.keys.toList()..sort()) {
      if (pn > largestAcked) break;
      if (ackRangeset.contains(pn)) {
        newlyAckedNumbers.add(pn);
        latestAckedPacket = space.sentPackets[pn];
      }
    }

    if (newlyAckedNumbers.isEmpty) return;

    if (latestAckedPacket != null && latestAckedPacket.isAckEliciting) {
      _rttLatest = now - latestAckedPacket.sentTime!;
      if (_rttLatest < _rttMin) _rttMin = _rttLatest;

      if (!_rttInitialized) {
        _rttInitialized = true;
        _rttVariance = _rttLatest / 2;
        _rttSmoothed = _rttLatest;
      } else {
        _rttVariance =
            (3 / 4 * _rttVariance) +
            (1 / 4 * (_rttSmoothed - _rttLatest).abs());
        _rttSmoothed = (7 / 8 * _rttSmoothed) + (1 / 8 * _rttLatest);
      }
    }

    for (final pn in newlyAckedNumbers) {
      final packet = space.sentPackets.remove(pn)!;
      if (packet.inFlight) {
        bytesInFlight -= packet.sentBytes;
        // Reno: On ACK, increase window by 1 MSS per RTT (simplified)
        _congestionWindow +=
            (_maxDatagramSize * _maxDatagramSize) ~/ _congestionWindow;
      }
    }

    detectLoss(now, space);
    _ptoCount = 0;
  }

  void onLossDetectionTimeout(double now) {
    double? earliestLossTime;
    QuicPacketSpace? lossSpace;
    for (final space in spaces.values) {
      if (!space.discarded && space.lossTime != null) {
        if (earliestLossTime == null || space.lossTime! < earliestLossTime) {
          earliestLossTime = space.lossTime!;
          lossSpace = space;
        }
      }
    }

    if (lossSpace != null) {
      detectLoss(now, lossSpace);
    } else {
      // PTO fired
      _ptoCount++;
    }
  }

  void detectLoss(double now, QuicPacketSpace space) {
    final lossDelay = kTimeThreshold * max(_rttLatest, _rttSmoothed);
    final packetThreshold = space.largestAckedPacket - kPacketThreshold;
    final timeThreshold = now - lossDelay;

    List<QuicSentPacket> lostPackets = [];
    space.lossTime = null;

    for (final packet in space.sentPackets.values) {
      if (packet.packetNumber > space.largestAckedPacket) continue;

      if (packet.packetNumber <= packetThreshold ||
          packet.sentTime! <= timeThreshold) {
        lostPackets.add(packet);
      } else {
        final packetLossTime = packet.sentTime! + lossDelay;
        if (space.lossTime == null || packetLossTime < space.lossTime!) {
          space.lossTime = packetLossTime;
        }
      }
    }

    if (lostPackets.isNotEmpty) {
      for (final packet in lostPackets) {
        space.sentPackets.remove(packet.packetNumber);
        if (packet.inFlight) bytesInFlight -= packet.sentBytes;
      }
      // Reno: On loss, halve the congestion window
      _congestionWindow = max(
        (_congestionWindow / 2).floor(),
        2 * _maxDatagramSize,
      );
    }
  }
}
