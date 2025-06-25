// lib/src/utils.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_derivators/hkdf.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha1.dart'; // For HMAC_SHA1 example if ever needed

/// Converts a hexadecimal string to a Uint8List.
Uint8List hexToBytes(String hex) {
  hex = hex.replaceAll(' ', ''); // Remove spaces
  if (hex.length % 2 != 0) {
    throw FormatException('Input hex string must have an even length.');
  }
  final List<int> bytes = [];
  for (int i = 0; i < hex.length; i += 2) {
    bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

/// Converts a Uint8List to a hexadecimal string.
String bytesToHex(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}

/// XORs two Uint8Lists.
Uint8List xorBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    throw ArgumentError(
      'Input Uint8Lists must have the same length for XOR operation.',
    );
  }
  final result = Uint8List(a.length);
  for (int i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/// Helper function to construct the 'info' parameter for HKDF-Expand-Label.
/// As defined in RFC 8446, Section 7.1, and applied in RFC 9001, Section 5.1.
Uint8List createHkdfLabelInfo(int length, String label, Uint8List context) {
  final BytesBuilder builder = BytesBuilder();

  // Length of output keying material (L, 2 bytes)
  builder.addByte((length >> 8) & 0xFF);
  builder.addByte(length & 0xFF);

  // Label length (label_len, 1 byte)
  final labelBytes = utf8.encode(
    'tls13 $label',
  ); // "tls13 " prefix for labels (RFC 8446)
  builder.addByte(labelBytes.length);

  // Label (label_len bytes)
  builder.add(labelBytes);

  // Context length (context_len, 1 byte)
  builder.addByte(context.length);

  // Context (context_len bytes)
  builder.add(context);

  return builder.takeBytes();
}

// Simple list equality check for Uint8List
bool listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
