// CryptoStream.dart (NEW)
import 'dart:typed_data';

// This enum corresponds to Java's ProtectionKeysType
enum ProtectionKeysType {
  initial,
  handshake,
  zeroRtt,
  oneRttClient,
  oneRttServer,
}

class CryptoStream {
  // Map to store offsets for different crypto streams (e.g., initial, handshake, 1-RTT)
  // Each key corresponds to a ProtectionKeysType.
  final Map<ProtectionKeysType, int> _offsets;

  CryptoStream() : _offsets = {};

  // Get the current offset for a given crypto stream type
  int getOffset(ProtectionKeysType type) {
    return _offsets[type] ?? 0;
  }

  // Advance the offset for a given crypto stream type by a certain amount
  void advanceOffset(ProtectionKeysType type, int amount) {
    if (amount < 0) {
      throw ArgumentError("Amount to advance cannot be negative.");
    }
    _offsets[type] = (_offsets[type] ?? 0) + amount;
  }

  // Set the offset for a given crypto stream type to a specific value
  void setOffset(ProtectionKeysType type, int newOffset) {
    if (newOffset < 0) {
      throw ArgumentError("Offset cannot be negative.");
    }
    _offsets[type] = newOffset;
  }
}