// Part of a hypothetical QuicConnection class
class QuicStreamManager {
  int _clientBidirectionalStreamId = 0; // 00
  int _clientUnidirectionalStreamId = 2; // 10
  int _serverBidirectionalStreamId = 1; // 01
  int _serverUnidirectionalStreamId = 3; // 11

  int getNextClientBidirectionalStreamId() {
    final id = _clientBidirectionalStreamId;
    _clientBidirectionalStreamId += 4; // Increment by 4 to maintain '00' suffix
    return id;
  }

  int getNextClientUnidirectionalStreamId() {
    final id = _clientUnidirectionalStreamId;
    _clientUnidirectionalStreamId += 4; // Increment by 4 to maintain '10' suffix
    return id;
  }

  // ... similar for server-initiated streams if acting as a server
}