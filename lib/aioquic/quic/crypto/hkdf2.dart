import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';

import '../enums.dart'; // Assuming this contains your enums
// import 'crypto_pair.dart'; // Assuming this contains INITIAL_CIPHER_SUITE etc.

/// Derives a secret using HKDF-Expand-Label as specified in TLS 1.3 / QUIC.
///
/// This is a helper that correctly builds the `info` structure for HKDF.
Future<Uint8List> hkdfExpandLabel({
  required Hkdf hkdf,
  required SecretKey secret,
  required String label,
  required List<int> context,
  required int outputLength,
}) async {
  // Construct the HkdfLabel structure as specified in RFC 8446 (TLS 1.3)
  final fullLabelBytes = utf8.encode('tls13 $label');

  final bb = BytesBuilder()
    ..add([(outputLength >> 8) & 0xFF, outputLength & 0xFF]) // 2-byte length
    ..add([fullLabelBytes.length, ...fullLabelBytes]) // 1-byte prefixed label
    ..add([context.length, ...context]) // 1-byte prefixed context
    ;

  final info = bb.toBytes();

  final output = await hkdf.deriveKey(secretKey: secret, nonce: info);
  return Uint8List.fromList(await output.extractBytes());
}

/// Derives the Key, IV, and Header Protection Key for a QUIC connection.
Future<(Uint8List, Uint8List, Uint8List)> deriveKeyIvHp({
  required CipherSuite cipherSuite,
  required Uint8List secretBytes,
  required int version,
}) async {
  // 1. Select the correct hash algorithm based on the cipher suite.
  final keySize =
      (cipherSuite == CipherSuite.AES_256_GCM_SHA384 ||
          cipherSuite == CipherSuite.CHACHA20_POLY1305_SHA256)
      ? 32
      : 16;
  final hashAlgorithm = (cipherSuite == CipherSuite.AES_256_GCM_SHA384)
      ? Hmac.sha384()
      : Hmac.sha256();
  final hkdf = Hkdf(hmac: hashAlgorithm, outputLength: keySize);
  final secret = SecretKey(secretBytes);

  // 2. Define key and IV sizes.

  final ivSize = 12;

  // 3. Define the label prefixes based on the QUIC version.
  final versionPrefix = (version == QuicProtocolVersion.VERSION_2.value)
      ? 'quicv2'
      : 'quic';

  // 4. Derive the key, iv, and header protection key in parallel.
  final results = await Future.wait([
    hkdfExpandLabel(
      hkdf: hkdf,
      secret: secret,
      label: '$versionPrefix key',
      context: [],
      outputLength: keySize,
    ),
    hkdfExpandLabel(
      hkdf: hkdf,
      secret: secret,
      label: '$versionPrefix iv',
      context: [],
      outputLength: ivSize,
    ),
    hkdfExpandLabel(
      hkdf: hkdf,
      secret: secret,
      label: '$versionPrefix hp',
      context: [],
      outputLength: keySize,
    ),
  ]);

  return (results[0], results[1], results[2]);
}

// Helper for HKDF-Extract
Future<SecretKey> hkdfExtract(Hkdf hkdf, List<int> salt, SecretKey ikm) async {
  return await hkdf.deriveKey(secretKey: ikm, nonce: salt);
}

/// import 'package:cryptography/cryptography.dart';
///
void main() async {
  final algorithm = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final secretKey = SecretKey([1, 2, 3]);
  final nonce = [4, 5, 6];
  final output = await algorithm.deriveKey(secretKey: secretKey, nonce: nonce);
}

// You would also use Hkdf for the initial secret extraction.
Future<SecretKey> extractInitialSecret(
  Uint8List cid, {
  required Uint8List salt,
}) async {
  final algorithm = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  // final hkdf = Hkdf(hmac: Hmac.sha256());
  // return await hkdf.extract(
  //     secretKey: SecretKey(cid),
  //     nonce: salt,
  // );

  final output = await algorithm.deriveKey(
    secretKey: SecretKey(cid),
    nonce: salt,
  );
  return output;
}
