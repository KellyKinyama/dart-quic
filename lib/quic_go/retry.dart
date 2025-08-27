
// Filename: retry.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

// Keys and nonces from RFC 9001 for Retry Packet Integrity
final _retryKeyV1 = SecretKey([
  0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
  0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
]);
final _retryNonceV1 = [
  0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
  0x23, 0x98, 0x25, 0xbb
];

Future<Uint8List> getRetryIntegrityTag(Uint8List retryPseudoPacket, Uint8List originalDestConnId) async {
  final aead = AesGcm.with128bits(secretKey: _retryKeyV1);
  final builder = BytesBuilder();
  builder.addByte(originalDestConnId.length);
  builder.add(originalDestConnId);
  builder.add(retryPseudoPacket);
  
  final secretBox = await aead.encrypt(
    [], // empty plaintext
    nonce: _retryNonceV1,
    aad: builder.toBytes(),
  );

  return secretBox.mac.bytes;
}
