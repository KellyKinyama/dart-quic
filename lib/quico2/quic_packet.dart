import 'dart:typed_data';

enum QuicPacketType {
  initial(0),
  zeroRtt(1),
  handshake(2),
  retry(3),
  version_negotiation(256),
  oneRtt(257);

  const QuicPacketType(this.value);

  final int value;

  factory QuicPacketType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

enum QuicPacketForm { long, short }

class QuicPacket {
  QuicPacketForm? form;
  QuicPacketType? type;
  int? version;
  Uint8List? dcid;
  Uint8List? scid;
  Uint8List? originalDestinationConnectionId;
  int? totalLength;
  Uint8List? raw;
  Uint8List? token;
  List<int>? supportedVersions;

  QuicPacket({
    this.form,
    this.type,
    this.version,
    this.dcid,
    this.scid,
    this.originalDestinationConnectionId,
    this.totalLength,
    this.raw,
    this.supportedVersions,
    this.token,
  });

  /// Helper to convert bytes to a hex string for readability
  String _toHex(Uint8List? bytes) {
    if (bytes == null) return 'null';
    if (bytes.isEmpty) return 'empty';
    return bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join('')
        .toUpperCase();
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('QuicPacket {');
    buffer.writeln('  form: ${form?.name}');
    buffer.writeln('  type: ${type?.name}');
    buffer.writeln(
      '  version: ${version != null ? '0x' + version!.toRadixString(16) : 'null'}',
    );
    buffer.writeln('  dcid: ${_toHex(dcid)}');
    buffer.writeln('  scid: ${_toHex(scid)}');

    if (originalDestinationConnectionId != null) {
      buffer.writeln('  orig_dcid: ${_toHex(originalDestinationConnectionId)}');
    }

    if (token != null && token!.isNotEmpty) {
      buffer.writeln('  token: ${_toHex(token)}');
    }

    if (supportedVersions != null && supportedVersions!.isNotEmpty) {
      buffer.writeln(
        '  supportedVersions: ${supportedVersions!.map((v) => '0x' + v.toRadixString(16)).toList()}',
      );
    }

    buffer.writeln('  totalLength: $totalLength');
    buffer.writeln('  payloadSize: ${raw?.length ?? 0} bytes');
    buffer.write('}');

    return buffer.toString();
  }
}
