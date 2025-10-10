import 'dart:typed_data';

// Local dependencies for cryptographic primitives and utilities
import 'hkdf.dart' as hkdf;
import 'utils.dart'; // For writeVarInt (if used, though usually not needed here)

// --- Constants ---

// QUIC v1 Initial Salt (38 76 20 f7 f6 f4 b6 3e 55 37 68 d1 fc e8 d5 23)
final Uint8List QUIC_V1_SALT = Uint8List.fromList([
  0x38,
  0x76,
  0x20,
  0xf7,
  0xf6,
  0xf4,
  0xb6,
  0x3e,
  0x55,
  0x37,
  0x68,
  0xd1,
  0xfc,
  0xe8,
  0xd5,
  0x23,
]);

// Cipher suite specific lengths for AES-128-GCM (used for Initial packets)
const int KEY_LENGTH = 16; // 128 bits
const int IV_LENGTH = 12; // 96 bits
const int HP_KEY_LENGTH = 16; // 128 bits
const int HASH_LENGTH = 32; // SHA-256 output length

// --- Data Structure for QUIC Keys ---

class QUICKeys {
  final Uint8List key; // Packet Protection Key
  final Uint8List iv;
  final Uint8List hp; // Header Protection Key

  QUICKeys({required this.key, required this.iv, required this.hp});
}

// --- Helper for QUIC HKDF Labels (RFC 9001, 5.2) ---

/// Constructs the Info parameter for HKDF-Expand as required by QUIC.
Uint8List _buildQuicHkdfLabel({
  required String label,
  required Uint8List context,
  required int length,
}) {
  final labelBytes = Uint8List.fromList('quic $label'.codeUnits);

  // Length (L, 2 bytes)
  final lenBytes = Uint8List(2);
  ByteData.view(lenBytes.buffer).setUint16(0, length, Endian.big);

  // Label (N)
  final labelLenBytes = Uint8List(1); // QUIC labels are typically < 256 bytes

  // Context Length (C, 1 byte)
  final contextLenBytes = Uint8List(1);
  contextLenBytes[0] = context.length;

  // Assembly: L || N || "quic " + Label || C || Context
  return concatUint8Lists([
    lenBytes,
    Uint8List.fromList([labelBytes.length]), // Length of the label string
    labelBytes,
    contextLenBytes,
    context,
  ]);
}

/// QUIC implementation of HKDF-Expand-Label (RFC 9001, 5.2).
Uint8List hkdfExpandLabel({
  required Uint8List secret, // The PRK
  required String label,
  required Uint8List context,
  required int outputLength,
}) {
  final info = _buildQuicHkdfLabel(
    label: label,
    context: context,
    length: outputLength,
  );

  return hkdf.hkdfExpand(prk: secret, info: info, outputLength: outputLength);
}

// --- Core Secret Derivation (Port of quic_derive_init_secrets) ---

/// Derives the necessary Initial Secrets and Keys for a QUIC connection.
///
/// QUIC uses a fixed salt and the Destination Connection ID to derive
/// the Initial Secrets.
///
/// [dcid]: The Destination Connection ID from the Initial packet.
/// [version]: The negotiated QUIC version (e.g., 0x00000001).
/// [direction]: 'read' (client_in for server) or 'write' (server_in for server).
(Uint8List secret, QUICKeys keys) quicDeriveInitSecrets(
  Uint8List dcid,
  int version,
  String direction,
) {
  // 1. Initial Secret (RFC 9001, 5.2)
  // HKDF-Extract(salt, IKM=DCID)
  final initialSecret = hkdf.hkdfExtract(dcid, salt: QUIC_V1_SALT);

  // 2. Traffic Secrets
  Uint8List trafficSecret;
  if (direction == 'read') {
    // Server reading Client Initial packets uses "client in" secret
    trafficSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: 'client in',
      context: Uint8List(0),
      outputLength: HASH_LENGTH,
    );
  } else if (direction == 'write') {
    // Server writing Server Initial packets uses "server in" secret
    trafficSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: 'server in',
      context: Uint8List(0),
      outputLength: HASH_LENGTH,
    );
  } else {
    throw ArgumentError(
      "Invalid direction '$direction'. Must be 'read' or 'write'.",
    );
  }

  // 3. Packet Protection Keys (RFC 9001, 5.3)
  final key = hkdfExpandLabel(
    secret: trafficSecret,
    label: 'quic key',
    context: Uint8List(0),
    outputLength: KEY_LENGTH,
  );

  final iv = hkdfExpandLabel(
    secret: trafficSecret,
    label: 'quic iv',
    context: Uint8List(0),
    outputLength: IV_LENGTH,
  );

  final hp = hkdfExpandLabel(
    secret: trafficSecret,
    label: 'quic hp',
    context: Uint8List(0),
    outputLength: HP_KEY_LENGTH,
  );

  // Return the traffic secret and the derived keys/IVs
  return (trafficSecret, QUICKeys(key: key, iv: iv, hp: hp));
}
