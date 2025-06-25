// lib/src/transport_parameters.dart
import 'dart:typed_data';

class QuicTransportParameters {
  int initialMaxData;
  int maxPacketSize;
  // ... other parameters like max_streams_bidi, idle_timeout, etc.

  QuicTransportParameters({
    this.initialMaxData = 0,
    this.maxPacketSize = 1200,
    // ...
  });

  // Example serialization/deserialization (simplified)
  Uint8List toBytes() {
    var buffer = BytesBuilder();
    buffer.add(VarInt.encode(initialMaxData));
    buffer.add(VarInt.encode(maxPacketSize));
    return buffer.takeBytes();
  }

  static QuicTransportParameters fromBytes(Uint8List bytes) {
    // In a real impl, this would parse the TLV structure of transport parameters
    var params = QuicTransportParameters();
    // Simplified parsing
    int offset = 0;
    var maxData = VarInt.decode(bytes, offset);
    if (maxData != -1) {
      params.initialMaxData = maxData;
      offset += VarInt.encode(maxData).length;
    }
    var pktSize = VarInt.decode(bytes, offset);
    if (pktSize != -1) {
      params.maxPacketSize = pktSize;
    }
    return params;
  }
}