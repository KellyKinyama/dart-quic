import 'dart:typed_data';

/// Abstract base class for all QUIC packets.
///
/// Contains fields common to both Long Header and Short Header packets.
abstract class QuicPacket {
  /// True if it's a long header, false for short header.
  bool get isLongHeader;

  /// The Destination Connection ID.
  /// Length is variable and implicit for Short Headers.
  Uint8List get destinationConnectionId;
}
