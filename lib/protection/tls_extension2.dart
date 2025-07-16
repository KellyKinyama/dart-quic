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
class QuicTransportParametersExtension extends TlsExtension {
  QuicTransportParametersExtension(Uint8List transportParametersData)
      : super(QuicExtensionType.quicTransportParameters, transportParametersData);
}

void main() {
  // Example: Dummy transport parameters data
  final Uint8List dummyTransportParameters = Uint8List.fromList([
    0x00, 0x01, // Parameter ID: Max Stream Data
    0x00, 0x04, // Length: 4 bytes
    0x00, 0x01, 0x00, 0x00, // Value: 65536
  ]);

  final QuicTransportParametersExtension quicTpExtension =
      QuicTransportParametersExtension(dummyTransportParameters);

  print('**QUIC Transport Parameters Extension Example**');
  print('QUIC Transport Parameters Extension Type: 0x${quicTpExtension.type.toRadixString(16)}');
  print('QUIC Transport Parameters Extension Data (Hex): ${quicTpExtension.data.toHexString()}\n');
}