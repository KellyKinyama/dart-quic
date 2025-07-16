import 'dart:typed_data';

/// Represents a generic TLS Extension.
class TlsExtension {
  final int type; // ExtensionType
  final Uint8List data; // extension_data

  TlsExtension(this.type, this.data);

  Uint8List toBytes() {
    final ByteData buffer = ByteData(4 + data.length);
    buffer.setUint16(0, type, Endian.big); // 2 bytes for type
    buffer.setUint16(2, data.length, Endian.big); // 2 bytes for length
    buffer.buffer.asUint8List().setRange(4, 4 + data.length, data);
    return buffer.buffer.asUint8List();
  }
}

/// Defines the ExtensionType for QUIC Transport Parameters.
class QuicExtensionType {
  static const int quicTransportParameters = 0xffa5; // 65535
}

/// Represents the QUIC Transport Parameters extension data.
/// The actual content (TransportParameters) would be a more complex structure
/// based on the QUIC version. For this example, it's just raw bytes.
class QuicTransportParametersExtension extends TlsExtension {
  QuicTransportParametersExtension(Uint8List transportParametersData)
      : super(QuicExtensionType.quicTransportParameters, transportParametersData);

  // You might add methods to parse or serialize the actual TransportParameters
  // based on the QUIC version.
  // For example:
  // List<TransportParameter> parseParameters() { ... }
}

void main() {
  // Example: Dummy transport parameters data
  // In a real scenario, this would be a TLV (Type-Length-Value) encoded structure
  // of various QUIC transport parameters like max_stream_data, idle_timeout, etc.
  final Uint8List dummyTransportParameters = Uint8List.fromList([
    0x00, 0x01, // Parameter ID: Max Stream Data
    0x00, 0x04, // Length: 4 bytes
    0x00, 0x01, 0x00, 0x00, // Value: 65536
    0x00, 0x04, // Parameter ID: Idle Timeout
    0x00, 0x02, // Length: 2 bytes
    0x00, 0x3C, // Value: 60 seconds
  ]);

  final QuicTransportParametersExtension quicTpExtension =
      QuicTransportParametersExtension(dummyTransportParameters);

  final Uint8List extensionBytes = quicTpExtension.toBytes();

  print('QUIC Transport Parameters Extension Type: 0x${quicTpExtension.type.toRadixString(16)}');
  print('QUIC Transport Parameters Extension Data (Hex): ${quicTpExtension.data.toHexString()}');
  print('Full Extension Bytes (Hex): ${extensionBytes.toHexString()}');

  // Simulate a check for non-QUIC context
  bool isQuicConnection = true; // Assume true for this example
  if (!isQuicConnection && quicTpExtension.type == QuicExtensionType.quicTransportParameters) {
    print('Error: Received QUIC transport parameters extension in a non-QUIC context.');
    // In a real implementation, this would trigger a fatal unsupported_extension alert.
  }
}

// Extension for easy hex printing (from previous snippets)
extension on Uint8List {
  String toHexString() {
    return map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}