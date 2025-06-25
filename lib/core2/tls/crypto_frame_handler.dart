// lib/src/crypto_frame_handler.dart
import 'dart:collection';
import 'dart:typed_data';

import 'enums.dart';
import 'package:quic_tls_analysis/src/errors.dart';
import 'package:quic_tls_analysis/src/tls_stack.dart';
import 'package:quic_tls_analysis/src/types.dart';

// Represents a CRYPTO frame
class CryptoFrame {
  final int offset;
  final int length;
  final Uint8List data;

  CryptoFrame(this.offset, this.length, this.data);

  Uint8List toBytes() {
    final builder = BytesBuilder();
    builder.addByte(0x06); // CRYPTO frame type
    builder.add(VarInt.encode(offset));
    builder.add(VarInt.encode(length));
    builder.add(data);
    return builder.takeBytes();
  }

  static CryptoFrame? fromBytes(Uint8List bytes, int offset) {
    try {
      int type = VarInt.decode(bytes, offset);
      int currentOffset = offset + VarInt.encode(type).length;
      if (type != 0x06) return null; // Not a CRYPTO frame

      int frameOffset = VarInt.decode(bytes, currentOffset);
      currentOffset += VarInt.encode(frameOffset).length;

      int frameLength = VarInt.decode(bytes, currentOffset);
      currentOffset += VarInt.encode(frameLength).length;

      if (currentOffset + frameLength > bytes.length) return null; // Incomplete frame

      final data = bytes.sublist(currentOffset, currentOffset + frameLength);
      return CryptoFrame(frameOffset, frameLength, data);
    } catch (e) {
      print('Error parsing CRYPTO frame: $e');
      return null;
    }
  }
}

class CryptoFrameHandler {
  final QuicTlsStack _tlsStack;
  final bool _isClient;

  // Buffers for incoming CRYPTO frame data, per encryption level
  final Map<EncryptionLevel, SplayTreeMap<int, Uint8List>> _receiveBuffers = {};
  final Map<EncryptionLevel, int> _expectedReceiveOffsets = {};

  // For outgoing CRYPTO frame data, per encryption level
  final Map<EncryptionLevel, int> _sendOffsets = {};


  EncryptionLevel _currentReceiveLevel = EncryptionLevel.initial; // Tracks TLS's current expected receive level

  CryptoFrameHandler(this._tlsStack, this._isClient);

  /// Sets the TLS stack's current expected receive encryption level.
  void setCurrentReceiveLevel(EncryptionLevel level) {
    _currentReceiveLevel = level;
    _receiveBuffers.putIfAbsent(level, () => SplayTreeMap());
    _expectedReceiveOffsets.putIfAbsent(level, () => 0);

    // RFC 9001, Section 4.1.3: If TLS provides keys for a higher encryption level,
    // if there is data from a previous encryption level that TLS has not consumed,
    // this MUST be treated as a connection error.
    _receiveBuffers.forEach((lvl, buffer) {
      if (lvl.index < level.index && buffer.isNotEmpty && _expectedReceiveOffsets[lvl]! < _getHighestOffset(lvl)) {
        throw QuicError(QuicConstants.protocolViolation,
            'Unconsumed CRYPTO data from previous encryption level ($lvl) when moving to $level.');
      }
    });
  }

  int _getHighestOffset(EncryptionLevel level) {
    var buffer = _receiveBuffers[level];
    if (buffer == null || buffer.isEmpty) return 0;
    var lastEntry = buffer.entries.last;
    return lastEntry.key + lastEntry.value.length;
  }

  /// Adds received CRYPTO frame data to the buffer. (RFC 9001, Section 4.1.3)
  void addReceivedData(CryptoFrame frame, EncryptionLevel level) {
    _receiveBuffers.putIfAbsent(level, () => SplayTreeMap());
    final buffer = _receiveBuffers[level]!;

    // Check for violations for previously installed levels
    if (level.index < _currentReceiveLevel.index) {
      if (frame.offset > _expectedReceiveOffsets[level]!) {
        throw QuicError(QuicConstants.protocolViolation,
            'CRYPTO frame from older encryption level ($level) extends past previously received data. Offset: ${frame.offset}, Expected: ${_expectedReceiveOffsets[level]}');
      }
    }

    buffer[frame.offset] = frame.data;

    // If it's the current receive level, try to deliver to TLS
    if (level == _currentReceiveLevel) {
      _deliverDataToTls(level);
    }
    // If it's a new encryption level, save for later (already done by adding to buffer)
    // No specific action needed here; _currentReceiveLevel will be updated later by connection logic
  }

  /// Attempts to deliver contiguous buffered data to TLS.
  void _deliverDataToTls(EncryptionLevel level) {
    final buffer = _receiveBuffers[level]!;
    int currentExpectedOffset = _expectedReceiveOffsets[level]!;
    final BytesBuilder contiguousData = BytesBuilder();

    // Collect contiguous data
    while (buffer.containsKey(currentExpectedOffset)) {
      final dataChunk = buffer.remove(currentExpectedOffset)!;
      contiguousData.add(dataChunk);
      currentExpectedOffset += dataChunk.length;
    }

    if (contiguousData.isNotEmpty) {
      _tlsStack.processInput(contiguousData.takeBytes(), level);
      _expectedReceiveOffsets[level] = currentExpectedOffset;
      // After providing new data, request new handshake bytes from TLS.
      // This will be handled by the QuicConnection orchestrator.
    }
  }

  /// Gets CRYPTO frames to send for a specific encryption level.
  /// This method requests data from the TLS stack and packages it into frames.
  List<CryptoFrame> getFramesToSend(EncryptionLevel level) {
    _sendOffsets.putIfAbsent(level, () => 0);
    final int currentSendOffset = _sendOffsets[level]!;

    // Request handshake bytes from TLS
    final Uint8List? handshakeBytes = _tlsStack.getBytesToSend(level);
    if (handshakeBytes == null || handshakeBytes.isEmpty) {
      return []; // No data from TLS
    }

    // Create a single CRYPTO frame for simplicity. In a real impl, might fragment based on MTU.
    final frame = CryptoFrame(currentSendOffset, handshakeBytes.length, handshakeBytes);
    _sendOffsets[level] = currentSendOffset + handshakeBytes.length; // Update offset for next send
    return [frame];
  }
}