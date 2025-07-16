import 'dart:convert';
import 'dart:typed_data';
// import 'package:pointycastle/export.dart'; // Using Pointy Castle for cryptographic primitives

import 'package:crypto/crypto.dart';

// Simplified HKDF implementation for demonstration purposes.
// In a production environment, use a battle-tested cryptography library.
class Hkdf {
  // static Uint8List extract(Uint8List salt, Uint8List ikm) {
  //   final Hmac hmac = Hmac(SHA256Digest(), salt);
  //   hmac.init(KeyParameter(salt));
  //   return hmac.process(ikm);
  // }

  /// HKDF-Extract using HMAC-SHA256
  static Uint8List extract(Uint8List salt, Uint8List ikm) {
    // salt ??= Uint8List(32); // Default salt = 32 zero bytes
    var hmac = Hmac(sha256, salt);
    return Uint8List.fromList(hmac.convert(ikm).bytes);
  }

  /// TLS 1.3 PRF using HKDF (HMAC-based Key Derivation Function)
  static Uint8List expandLabel(
    Uint8List secret,
    String label,
    Uint8List seed,
    int outputLength,
  ) {
    Uint8List info = Uint8List.fromList(utf8.encode(label) + seed);

    // Step 1: Extract
    Uint8List prk = hkdfExtract(secret);

    // Step 2: Expand
    return hkdfExpand(prk, info, outputLength);
  }

  /// HKDF-Extract using HMAC-SHA256
  static Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) {
    salt ??= Uint8List(32); // Default salt = 32 zero bytes
    var hmac = Hmac(sha256, salt);
    return Uint8List.fromList(hmac.convert(ikm).bytes);
  }

  /// HKDF-Expand using HMAC-SHA256
  static Uint8List hkdfExpand(Uint8List prk, Uint8List info, int outputLength) {
    List<int> output = [];
    Uint8List previousBlock = Uint8List(0);
    int counter = 1;

    while (output.length < outputLength) {
      var hmac = Hmac(sha256, prk);
      var data = Uint8List.fromList(previousBlock + info + [counter]);
      previousBlock = Uint8List.fromList(hmac.convert(data).bytes);

      output.addAll(previousBlock);
      counter++;
    }

    return Uint8List.fromList(output.sublist(0, outputLength));
  }
}

class QuicInitialSecrets {
  static final Uint8List initialSalt = Uint8List.fromList([
    0xef,
    0x4f,
    0xb0,
    0xab,
    0xb4,
    0x74,
    0x70,
    0xc4,
    0x1b,
    0xef,
    0xcf,
    0x80,
    0x31,
    0x33,
    0x4f,
    0xae,
    0x48,
    0x5e,
    0x09,
    0xa0,
  ]);

  static Map<String, Uint8List> deriveInitialSecrets(
    Uint8List clientDstConnectionId,
  ) {
    final Uint8List initialSecret = Hkdf.extract(
      initialSalt,
      clientDstConnectionId,
    );

    final int hashLength = 256;
    //SHA256Digest().byteLength;

    final Uint8List clientInitialSecret = Hkdf.expandLabel(
      initialSecret,
      "client in",
      Uint8List(0), // Empty context
      hashLength,
    );

    final Uint8List serverInitialSecret = Hkdf.expandLabel(
      initialSecret,
      "server in",
      Uint8List(0), // Empty context
      hashLength,
    );

    return {
      'client_initial_secret': clientInitialSecret,
      'server_initial_secret': serverInitialSecret,
    };
  }
}

void main() {
  // Example: Deriving initial secrets
  final Uint8List clientConnectionId = Uint8List.fromList([
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
  ]);
  final Map<String, Uint8List> secrets =
      QuicInitialSecrets.deriveInitialSecrets(clientConnectionId);

  print('**Initial Secrets Derivation Example**');
  print(
    'Client Initial Secret: ${secrets['client_initial_secret']?.toHexString()}',
  );
  print(
    'Server Initial Secret: ${secrets['server_initial_secret']?.toHexString()}\n',
  );
}

// Extension to easily print Uint8List as hex string
extension on Uint8List {
  String toHexString() {
    return map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}

String toHexString(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}
