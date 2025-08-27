// Filename: logger.dart

/// Abstract base class for a QUIC logger.
///
/// An implementation of this class can be passed to the [QuicConfiguration]
/// to receive detailed events for debugging and tracing.
abstract class QuicLogger {
  void startTrace({required bool isClient, required List<int> odcid});
  void endTrace();
  // In a full implementation, you would add methods to log specific
  // event types, like `logPacketSent`, `logPacketReceived`, etc.
}