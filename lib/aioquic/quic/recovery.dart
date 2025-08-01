// The following code is a Dart translation of the `recovery.py` Python module.
// This translation adapts the original logic to Dart's class structure and type system.
// It uses Dart's `math` library for `math.inf` and assumes the existence of
// corresponding QUIC-related classes and functions from the converted modules.

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:quic_dart/quic/congestion/base.dart';
import 'package:quic_dart/quic/congestion/cubic.dart';
import 'package:quic_dart/quic/congestion/reno.dart';
import 'logger.dart';
import 'packet_builder.dart';
import 'range_set.dart';

// loss detection
const int kPacketThreshold = 3;
const double kTimeThreshold = 9 / 8;
const double kMicroSecond = 0.000001;
const double kSecond = 1.0;

class QuicPacketSpace {
  double? ackAt;
  RangeSet ackQueue = RangeSet();
  bool discarded = false;
  int expectedPacketNumber = 0;
  int largestReceivedPacket = -1;
  double? largestReceivedTime;

  // sent packets and loss
  int ackElicitingInFlight = 0;
  int largestAckedPacket = 0;
  double? lossTime;
  Map<int, QuicSentPacket> sentPackets = {};
}

class QuicPacketPacer {
  final int _maxDatagramSize;
  double bucketMax = 0.0;
  double bucketTime = 0.0;
  double evaluationTime = 0.0;
  double? packetTime;

  QuicPacketPacer({required int maxDatagramSize})
    : _maxDatagramSize = maxDatagramSize;

  double? nextSendTime(double now) {
    if (packetTime != null) {
      updateBucket(now: now);
      if (bucketTime <= 0) {
        return now + packetTime!;
      }
    }
    return null;
  }

  void updateAfterSend(double now) {
    if (packetTime != null) {
      updateBucket(now: now);
      if (bucketTime < packetTime!) {
        bucketTime = 0.0;
      } else {
        bucketTime -= packetTime!;
      }
    }
  }

  void updateBucket({required double now}) {
    if (now > evaluationTime) {
      bucketTime = math.min(bucketTime + (now - evaluationTime), bucketMax);
      evaluationTime = now;
    }
  }

  void updateRate({
    required int congestionWindow,
    required double smoothedRtt,
  }) {
    final pacingRate = congestionWindow / math.max(smoothedRtt, kMicroSecond);
    packetTime = math.max(
      kMicroSecond,
      math.min(_maxDatagramSize / pacingRate, kSecond),
    );

    bucketMax =
        (math.max(
          2 * _maxDatagramSize,
          math.min(congestionWindow ~/ 4, 16 * _maxDatagramSize),
        ) /
        pacingRate);
    if (bucketTime > bucketMax) {
      bucketTime = bucketMax;
    }
  }
}

class QuicPacketRecovery {
  /// Packet loss and congestion controller.
  final double maxAckDelay = 0.025;
  final bool peerCompletedAddressValidation;
  final List<QuicPacketSpace> spaces = [];

  // callbacks
  final Logger? _logger;
  final QuicLoggerTrace? _quicLogger;
  final Function _sendProbe;

  // loss detection
  int _ptoCount = 0;
  final double _rttInitial;
  bool _rttInitialized = false;
  double _rttLatest = 0.0;
  double _rttMin = math.pow(2, 63).toDouble(); // Dart's equivalent of math.inf
  double _rttSmoothed = 0.0;
  double _rttVariance = 0.0;
  double _timeOfLastSentAckElicitingPacket = 0.0;

  // congestion control
  late final CongestionControl _cc;
  late final QuicPacketPacer _pacer;

  QuicPacketRecovery({
    required String congestionControlAlgorithm,
    required double initialRtt,
    required int maxDatagramSize,
    required this.peerCompletedAddressValidation,
    required Function sendProbe,
    Logger? logger,
    QuicLoggerTrace? quicLogger,
  }) : _rttInitial = initialRtt,
       _logger = logger,
       _quicLogger = quicLogger,
       _sendProbe = sendProbe {
    _cc = createCongestionControl(
      congestionControlAlgorithm,
      maxDatagramSize: maxDatagramSize,
    );
    _pacer = QuicPacketPacer(maxDatagramSize: maxDatagramSize);
  }

  int get bytesInFlight => _cc.bytesInFlight;

  int get congestionWindow => _cc.congestionWindow;

  void discardSpace(QuicPacketSpace space) {
    assert(spaces.contains(space));

    _cc.onPacketsExpired(
      packets: space.sentPackets.values.where((x) => x.inFlight),
    );
    space.sentPackets.clear();

    space.ackAt = null;
    space.ackElicitingInFlight = 0;
    space.lossTime = null;

    // reset PTO count
    _ptoCount = 0;

    if (_quicLogger != null) {
      _logMetricsUpdated();
    }
  }

  double? getLossDetectionTime() {
    // loss timer
    final lossSpace = _getLossSpace();
    if (lossSpace != null) {
      return lossSpace.lossTime;
    }

    // packet timer
    if (!peerCompletedAddressValidation ||
        spaces
                .map((space) => space.ackElicitingInFlight)
                .reduce((a, b) => a + b) >
            0) {
      final timeout = getProbeTimeout() * math.pow(2, _ptoCount);
      return _timeOfLastSentAckElicitingPacket + timeout;
    }

    return null;
  }

  double getProbeTimeout() {
    if (!_rttInitialized) {
      return 2 * _rttInitial;
    }
    return _rttSmoothed +
        math.max(4 * _rttVariance, kGranularity) +
        maxAckDelay;
  }

  void onAckReceived({
    required RangeSet ackRangeset,
    required double ackDelay,
    required double now,
    required QuicPacketSpace space,
  }) {
    /// Update metrics as the result of an ACK being received.
    bool isAckEliciting = false;
    final largestAcked = ackRangeset.bounds!.stop - 1;
    int? largestNewlyAcked;
    double? largestSentTime;

    if (largestAcked > space.largestAckedPacket) {
      space.largestAckedPacket = largestAcked;
    }

    final packetNumbers = space.sentPackets.keys.toList()..sort();
    for (final packetNumber in packetNumbers) {
      if (packetNumber > largestAcked) {
        break;
      }
      if (ackRangeset.contains(packetNumber)) {
        final packet = space.sentPackets.remove(packetNumber)!;
        if (packet.isAckEliciting) {
          isAckEliciting = true;
          space.ackElicitingInFlight--;
        }
        if (packet.inFlight) {
          _cc.onPacketAcked(packet: packet, now: now);
        }
        largestNewlyAcked = packetNumber;
        largestSentTime = packet.sentTime;

        // trigger callbacks
        for (final handler in packet.deliveryHandlers) {
          handler.first(QuicDeliveryState.acked, handler.second);
        }
      }
    }

    // nothing to do if there are no newly acked packets
    if (largestNewlyAcked == null) {
      return;
    }

    if (largestAcked == largestNewlyAcked && isAckEliciting) {
      var latestRtt = now - largestSentTime!;
      final logRtt = true;

      // limit ACK delay to max_ack_delay
      ackDelay = math.min(ackDelay, maxAckDelay);

      // update RTT estimate, which cannot be < 1 ms
      _rttLatest = math.max(latestRtt, 0.001);
      if (_rttLatest < _rttMin) {
        _rttMin = _rttLatest;
      }
      if (_rttLatest > _rttMin + ackDelay) {
        _rttLatest -= ackDelay;
      }

      if (!_rttInitialized) {
        _rttInitialized = true;
        _rttVariance = latestRtt / 2;
        _rttSmoothed = latestRtt;
      } else {
        _rttVariance =
            3 / 4 * _rttVariance +
            1 / 4 * (math.min(_rttMin, _rttLatest) - _rttLatest).abs();
        _rttSmoothed = 7 / 8 * _rttSmoothed + 1 / 8 * _rttLatest;
      }

      // inform congestion controller
      _cc.onRttMeasurement(now: now, rtt: latestRtt);
      _pacer.updateRate(
        congestionWindow: _cc.congestionWindow,
        smoothedRtt: _rttSmoothed,
      );

      if (_quicLogger != null) {
        _logMetricsUpdated(logRtt: logRtt);
      }
    }

    _detectLoss(now: now, space: space);

    // reset PTO count
    _ptoCount = 0;

    if (_quicLogger != null) {
      _logMetricsUpdated();
    }
  }

  void onLossDetectionTimeout({required double now}) {
    final lossSpace = _getLossSpace();
    if (lossSpace != null) {
      _detectLoss(now: now, space: lossSpace);
    } else {
      _ptoCount++;
      rescheduleData(now: now);
    }
  }

  void onPacketSent({
    required QuicSentPacket packet,
    required QuicPacketSpace space,
  }) {
    space.sentPackets[packet.packetNumber] = packet;

    if (packet.isAckEliciting) {
      space.ackElicitingInFlight++;
    }
    if (packet.inFlight) {
      if (packet.isAckEliciting) {
        _timeOfLastSentAckElicitingPacket = packet.sentTime;
      }

      // add packet to bytes in flight
      _cc.onPacketSent(packet: packet);

      if (_quicLogger != null) {
        _logMetricsUpdated();
      }
    }
  }

  void rescheduleData({required double now}) {
    /// Schedule some data for retransmission.
    bool cryptoScheduled = false;
    for (final space in spaces) {
      final packets = space.sentPackets.values
          .where((i) => i.isCryptoPacket)
          .toList();
      if (packets.isNotEmpty) {
        _onPacketsLost(now: now, packets: packets, space: space);
        cryptoScheduled = true;
      }
    }
    if (cryptoScheduled && _logger != null) {
      _logger!.info("Scheduled CRYPTO data for retransmission");
    }

    // ensure an ACK-eliciting packet is sent
    _sendProbe();
  }

  void _detectLoss({required double now, required QuicPacketSpace space}) {
    /// Check whether any packets should be declared lost.
    final lossDelay =
        kTimeThreshold *
        (_rttInitialized ? math.max(_rttLatest, _rttSmoothed) : _rttInitial);
    final packetThreshold = space.largestAckedPacket - kPacketThreshold;
    final timeThreshold = now - lossDelay;

    final lostPackets = <QuicSentPacket>[];
    space.lossTime = null;
    final sentPacketNumbers = space.sentPackets.keys.toList()..sort();
    for (final packetNumber in sentPacketNumbers) {
      final packet = space.sentPackets[packetNumber]!;
      if (packetNumber > space.largestAckedPacket) {
        break;
      }

      if (packetNumber <= packetThreshold || packet.sentTime <= timeThreshold) {
        lostPackets.add(packet);
      } else {
        final packetLossTime = packet.sentTime + lossDelay;
        if (space.lossTime == null || space.lossTime! > packetLossTime) {
          space.lossTime = packetLossTime;
        }
      }
    }

    _onPacketsLost(now: now, packets: lostPackets, space: space);
  }

  QuicPacketSpace? _getLossSpace() {
    QuicPacketSpace? lossSpace;
    for (final space in spaces) {
      if (space.lossTime != null &&
          (lossSpace == null || space.lossTime! < lossSpace.lossTime!)) {
        lossSpace = space;
      }
    }
    return lossSpace;
  }

  void _logMetricsUpdated({bool logRtt = false}) {
    final data = _cc.getLogData();

    if (logRtt) {
      data.addAll({
        'latest_rtt': _quicLogger!.encodeTime(_rttLatest),
        'min_rtt': _quicLogger!.encodeTime(_rttMin),
        'smoothed_rtt': _quicLogger!.encodeTime(_rttSmoothed),
        'rtt_variance': _quicLogger!.encodeTime(_rttVariance),
      });
    }

    _quicLogger!.logEvent(
      category: 'recovery',
      event: 'metrics_updated',
      data: data,
    );
  }

  void _onPacketsLost({
    required double now,
    required Iterable<QuicSentPacket> packets,
    required QuicPacketSpace space,
  }) {
    final lostPacketsCc = <QuicSentPacket>[];
    for (final packet in packets) {
      space.sentPackets.remove(packet.packetNumber);

      if (packet.inFlight) {
        lostPacketsCc.add(packet);
      }

      if (packet.isAckEliciting) {
        space.ackElicitingInFlight--;
      }

      if (_quicLogger != null) {
        _quicLogger!.logEvent(
          category: 'recovery',
          event: 'packet_lost',
          data: {
            'type': _quicLogger!.packetType(packet.packetType),
            'packet_number': packet.packetNumber,
          },
        );
        _logMetricsUpdated();
      }

      // trigger callbacks
      for (final handler in packet.deliveryHandlers) {
        handler.first(QuicDeliveryState.lost, handler.second);
      }
    }

    // inform congestion controller
    if (lostPacketsCc.isNotEmpty) {
      _cc.onPacketsLost(now: now, packets: lostPacketsCc);
      _pacer.updateRate(
        congestionWindow: _cc.congestionWindow,
        smoothedRtt: _rttSmoothed,
      );
      if (_quicLogger != null) {
        _logMetricsUpdated();
      }
    }
  }
}
