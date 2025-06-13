import 'frame.dart';
import 'tx_params.dart';

class QuicFlowControlManager {
  // Connection-level
  int _localConnectionMaxData; // Max data *we* can receive
  int _remoteConnectionMaxData; // Max data *remote* can receive (set by remote's MAX_DATA frame)
  int _connectionDataSent = 0; // Total application data bytes sent
  int _connectionDataReceived = 0; // Total application data bytes received

  // Stream creation limits
  int _localMaxStreamsBidi;
  int _localMaxStreamsUni;
  int _remoteMaxStreamsBidi;
  int _remoteMaxStreamsUni;
  int _activeStreamsBidi = 0;
  int _activeStreamsUni = 0;

  // Per-stream limits (would need a map per stream ID)
  // Map<int, int> _localStreamMaxData = {}; // Max data *we* can receive on a stream
  // Map<int, int> _remoteStreamMaxData = {}; // Max data *remote* can receive on a stream
  // Map<int, int> _streamDataSent = {};
  // Map<int, int> _streamDataReceived = {};

  Function(QuicFrame) _sendFrameCallback; // Callback to send a frame

  QuicFlowControlManager(QuicTransportParameters initialParams, this._sendFrameCallback)
      : _localConnectionMaxData = initialParams.initialMaxData,
        _remoteConnectionMaxData = 0, // This is updated by the remote's first MAX_DATA (or its initial_max_data)
        _localMaxStreamsBidi = initialParams.initialMaxStreamsBidi,
        _localMaxStreamsUni = initialParams.initialMaxStreamsUni,
        _remoteMaxStreamsBidi = 0,
        _remoteMaxStreamsUni = 0;


  // --- Methods for Sender Side (what we are allowed to send) ---

  void onRemoteMaxDataFrame(int maxData) {
    _remoteConnectionMaxData = maxData;
    // Log or react if we were previously blocked.
    // If _connectionDataSent is now < _remoteConnectionMaxData, we are unblocked.
  }

  void onRemoteMaxStreamsFrame(int type, int maxStreams) {
    if (type == 0x06) {
      _remoteMaxStreamsBidi = maxStreams;
    } else {
      _remoteMaxStreamsUni = maxStreams;
    }
    // React if we were blocked from creating streams.
  }

  void onRemoteMaxStreamDataFrame(int streamId, int maxStreamData) {
    // _remoteStreamMaxData[streamId] = maxStreamData;
    // React if this specific stream was blocked.
  }

  bool canSendStreamData(int streamId, int length) {
    // Check connection-level limit
    if (_connectionDataSent + length > _remoteConnectionMaxData) {
      _sendFrameCallback(QuicDataBlockedFrame(connectionLimit: _remoteConnectionMaxData));
      return false; // Blocked at connection level
    }

    // Check per-stream limit (conceptual)
    // if (_streamDataSent[streamId]! + length > _remoteStreamMaxData[streamId]!) {
    //   _sendFrameCallback(QuicStreamDataBlockedFrame(streamId: streamId, streamDataLimit: _remoteStreamMaxData[streamId]!));
    //   return false; // Blocked at stream level
    // }

    return true; // Can send
  }

  void onStreamDataSent(int streamId, int length) {
    _connectionDataSent += length;
    // _streamDataSent[streamId] = (_streamDataSent[streamId] ?? 0) + length;
  }

  bool canCreateStream(bool isBidirectional) {
    if (isBidirectional) {
      if (_activeStreamsBidi >= _remoteMaxStreamsBidi) {
        _sendFrameCallback(QuicStreamsBlockedFrame.bidi(streamLimit: _remoteMaxStreamsBidi));
        return false;
      }
    } else {
      if (_activeStreamsUni >= _remoteMaxStreamsUni) {
        _sendFrameCallback(QuicStreamsBlockedFrame.uni(streamLimit: _remoteMaxStreamsUni));
        return false;
      }
    }
    return true;
  }

  void onStreamCreated(bool isBidirectional) {
    if (isBidirectional) {
      _activeStreamsBidi++;
    } else {
      _activeStreamsUni++;
    }
  }


  // --- Methods for Receiver Side (what we are expecting to receive) ---

  void onStreamDataReceived(int streamId, int offset, int length) {
    _connectionDataReceived += length;
    // _streamDataReceived[streamId] = (_streamDataReceived[streamId] ?? 0) + length;

    // Proactive flow control: send MAX_DATA/MAX_STREAM_DATA before limits are hit
    if (_connectionDataReceived + (0.5 * _localConnectionMaxData) > _localConnectionMaxData) {
      // Example: If we've received 50% of our capacity, extend it
      _localConnectionMaxData += 10000; // Extend by some amount
      _sendFrameCallback(QuicMaxDataFrame(maximumData: _localConnectionMaxData));
    }
    // Similar logic for per-stream data limits
  }

  void onDataBlockedFrame(int limit) {
    // Remote host is blocked by *our* connection limit.
    // This is a strong signal to increase _localConnectionMaxData and send MAX_DATA.
    _localConnectionMaxData += 20000; // React to blocking
    _sendFrameCallback(QuicMaxDataFrame(maximumData: _localConnectionMaxData));
  }

  void onStreamDataBlockedFrame(int streamId, int limit) {
    // Remote host is blocked by *our* per-stream limit on 'streamId'.
    // Increase _localStreamMaxData[streamId] and send MAX_STREAM_DATA.
  }

  void onStreamsBlockedFrame(int type, int limit) {
    // Remote host is blocked by *our* stream creation limit.
    // Increase _localMaxStreamsBidi/_localMaxStreamsUni and send MAX_STREAMS.
  }

  // Periodic check to send blocked frames if we are indeed blocked (as per the note)
  void periodicallyCheckBlockedStatus() {
    if (_connectionDataSent >= _remoteConnectionMaxData) {
      _sendFrameCallback(QuicDataBlockedFrame(connectionLimit: _remoteConnectionMaxData));
    }
    // Similar checks for stream data and stream creation limits
  }
}