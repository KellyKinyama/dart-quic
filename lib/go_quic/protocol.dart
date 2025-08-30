// lib/protocol.dart
import 'dart:typed_data';
import 'package:collection/collection.dart';

// Represents the QUIC protocol version.
enum Version { version1, version2 }

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
