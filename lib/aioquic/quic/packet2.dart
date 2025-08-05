import 'dart:io';
import 'dart:typed_data';
import 'dart:math';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

import '../buffer.dart';
import 'enums.dart';
import 'range_set.dart';

// Constants from packet.py
const int packetLongHeader = 0x80;
const int packetFixedBit = 0x40;
const int packetSpinBit = 0x20;
const int connectionIdMaxSize = 20;
const int packetNumberMaxSize = 4;
// ... other constants ...

enum QuicErrorCode {
  noError(0x0),
  internalError(0x1),
  // ... all other error codes
  cryptoError(0x100);

  final int value;
  const QuicErrorCode(this.value);
}

enum QuicPacketType {
  initial,
  zeroRtt,
  handshake,
  retry,
  versionNegotiation,
  oneRtt,
}

// enum QuicProtocolVersion {
//   negotiation(0),
//   version1(0x00000001),
//   version2(0x6B3343CF);

//   final int value;
//   const QuicProtocolVersion(this.value);
// }

// Data Classes
class QuicHeader {
  final int? version;
  final QuicPacketType packetType;
  final int packetLength;
  final Uint8List destinationCid;
  final Uint8List sourceCid;
  final Uint8List token;
  final Uint8List integrityTag;
  final List<int> supportedVersions;

  QuicHeader({
    this.version,
    required this.packetType,
    required this.packetLength,
    required this.destinationCid,
    required this.sourceCid,
    required this.token,
    required this.integrityTag,
    required this.supportedVersions,
  });
}

// ... other data classes like QuicTransportParameters, QuicPreferredAddress ...

// Helper functions
bool isLongHeader(int firstByte) => (firstByte & packetLongHeader) != 0;

int decodePacketNumber(int truncated, int numBytes, int expected) {
  final numBits = numBytes * 8;
  final window = 1 << numBits;
  final halfWindow = window >> 1;
  final candidate = (expected & ~(window - 1)) | truncated;

  if (candidate <= expected - halfWindow && candidate < ((1 << 62) - window)) {
    return candidate + window;
  } else if (candidate > expected + halfWindow && candidate >= window) {
    return candidate - window;
  } else {
    return candidate;
  }
}

// Main parsing function
QuicHeader pullQuicHeader(Buffer buf, {int? hostCidLength}) {
  final packetStart = buf.tell();
  int? version;
  var integrityTag = Uint8List(0);
  var supportedVersions = <int>[];
  var token = Uint8List(0);

  final firstByte = buf.pullUint8();

  if (isLongHeader(firstByte)) {
    // Long Header Packet
    version = buf.pullUint32();
    final destCidLen = buf.pullUint8();
    if (destCidLen > connectionIdMaxSize)
      throw ArgumentError('Destination CID too long');
    final destCid = Uint8List(destCidLen);
    buf.pullBytes(destCidLen, destCid);

    final srcCidLen = buf.pullUint8();
    if (srcCidLen > connectionIdMaxSize)
      throw ArgumentError('Source CID too long');
    final srcCid = Uint8List(srcCidLen);
    buf.pullBytes(srcCidLen, srcCid);

    if (version == QuicProtocolVersion.negotiation.value) {
      final packetType = QuicPacketType.versionNegotiation;
      while (!buf.eof()) {
        supportedVersions.add(buf.pullUint32());
      }
      final packetEnd = buf.tell();
      return QuicHeader(
        version: version,
        packetType: packetType,
        packetLength: packetEnd - packetStart,
        destinationCid: destCid,
        sourceCid: srcCid,
        token: token,
        integrityTag: integrityTag,
        supportedVersions: supportedVersions,
      );
    }
    // ... logic for other long header packet types (Initial, Handshake, etc.)
    // This is a very complex part of the original code and requires careful translation.
    // The following is a simplified placeholder.
    QuicPacketType packetType;
    final typeBits = (firstByte & 0x30) >> 4;
    // ... decode packet type based on version ...
    packetType = QuicPacketType.initial; // Placeholder

    // ... pull token, length, etc. based on packet type ...

    return QuicHeader(
      version: version,
      packetType: packetType, // Use the decoded type
      packetLength: 0, // Calculate this properly
      destinationCid: destCid,
      sourceCid: srcCid,
      token: token,
      integrityTag: integrityTag,
      supportedVersions: supportedVersions,
    );
  } else {
    // Short Header Packet
    if ((firstByte & packetFixedBit) == 0)
      throw ArgumentError('Packet fixed bit is zero');
    if (hostCidLength == null)
      throw ArgumentError('hostCidLength must be provided for short headers');

    final destCid = Uint8List(hostCidLength);
    buf.pullBytes(hostCidLength, destCid);

    final packetEnd = buf.capacity;

    return QuicHeader(
      packetType: QuicPacketType.oneRtt,
      packetLength: packetEnd - packetStart,
      destinationCid: destCid,
      sourceCid: Uint8List(0),
      token: Uint8List(0),
      integrityTag: Uint8List(0),
      supportedVersions: [],
    );
  }
}

// ... Additional classes and functions for frames, transport parameters, etc.
// would be translated here following the same pattern.

// Example: CipherSuite definitions needed by crypto.dart
// enum CipherSuite {
//   AES_128_GCM_SHA256,
//   AES_256_GCM_SHA384,
//   CHACHA20_POLY1305_SHA256,
// }

const Map<CipherSuite, (String, String)> cipherSuites = {
  CipherSuite.AES_128_GCM_SHA256: ('aes-128-ecb', 'aes-128-gcm'),
  CipherSuite.AES_256_GCM_SHA384: ('aes-256-ecb', 'aes-256-gcm'),
  CipherSuite.CHACHA20_POLY1305_SHA256: ('chacha20', 'chacha20-poly1305'),
};

final Map<CipherSuite, Hmac> cipherSuiteHash = {
  CipherSuite.AES_128_GCM_SHA256: Hmac.sha256(),
  CipherSuite.AES_256_GCM_SHA384: Hmac.sha384(),
  CipherSuite.CHACHA20_POLY1305_SHA256: Hmac.sha256(),
};
