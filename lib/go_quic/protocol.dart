// lib/protocol.dart
import 'dart:typed_data';
import 'package:collection/collection.dart';

/// Represents a QUIC protocol version with its associated 32-bit integer value.
enum Version {
  /// Special value used for Version Negotiation packets.
  negotiation(0x00000000),

  /// IETF QUIC Version 1.
  version1(0x00000001),

  /// IETF QUIC Version 2.
  version2(0x6b3343cf),

  /// Represents an unsupported or unknown version.
  unknown(-1);

  /// The 32-bit integer value for the version.
  final int value;

  /// Constant constructor to associate the enum member with its integer value.
  const Version(this.value);

  /// Looks up a [Version] from its 32-bit integer representation.
  ///
  /// Returns [Version.unknown] if no matching version is found.
  static Version fromValue(int value) {
    // More efficient than iterating for a small, fixed number of enums.
    switch (value) {
      case 0x00000000:
        return negotiation;
      case 0x00000001:
        return version1;
      case 0x6b3343cf:
        return version2;
      default:
        return unknown;
    }
  }

  /// Returns the version as a 4-byte list.
  Uint8List toBytes() {
    final bytes = ByteData(4);
    bytes.setUint32(0, value);
    return bytes.buffer.asUint8List();
  }

  Uint8List encodeVersion() {
    return Uint8List.fromList([
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ]);
  }

  @override
  String toString() {
    return 'Version(name: $name, value: 0x${value.toRadixString(16).padLeft(8, '0')})';
  }
}

// Represents the perspective of the endpoint (client or server).
enum Perspective { client, server }

// A type alias for Connection ID for clarity.
typedef ConnectionID = Uint8List;

// A type alias for Packet Number.
typedef PacketNumber = int;

const packetNumberLen1 = 1;

class Errors {
  static final decryptionFailed = Exception('decryption failed');
}

// Helper to parse hex strings from tests into a Uint8List.
Uint8List splitHexString(String hex) {
  final cleanHex = hex.replaceAll(RegExp(r'\s|0x'), '');
  final bytes = <int>[];
  for (var i = 0; i < cleanHex.length; i += 2) {
    bytes.add(int.parse(cleanHex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

// Decodes a truncated packet number.
// https://www.rfc-editor.org/rfc/rfc9000.html#section-a.2
PacketNumber decodePacketNumber(
  int pnLen,
  PacketNumber largestPn,
  PacketNumber truncatedPn,
) {
  final pnNbits = pnLen * 8;
  final expectedPn = largestPn + 1;
  final pnWin = 1 << pnNbits;
  final pnHwin = pnWin ~/ 2;
  final pnMask = pnWin - 1;

  // The incoming packet number should be greater than expected_pn - pnHwin and
  // less than or equal to expected_pn + pnHwin
  final candidatePn = (expectedPn & ~pnMask) | truncatedPn;
  if (candidatePn <= expectedPn - pnHwin) {
    return candidatePn + pnWin;
  }
  if (candidatePn > expectedPn + pnHwin && candidatePn > pnWin) {
    return candidatePn - pnWin;
  }
  return candidatePn;
}

Function eq = const ListEquality().equals;
