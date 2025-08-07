// test/hkdf_test.dart
// Note: The original Go test used internal `crypto/tls` functions.
// This Dart version can't replicate that, so we focus on ensuring our
// `hkdfExpandLabel` runs without errors and produces deterministic output.
// A full test would require known test vectors from the RFCs.
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:test/test.dart';
import 'package:quic_crypto/hkdf.dart';

void main() {
  group('HKDF Expand Label', () {
    test('produces deterministic output', () {
      final secret = Uint8List.fromList('foobar'.codeUnits);
      final hash = SHA256Digest();
      final label = 'traffic upd';
      final context = Uint8List(0);
      final length = hash.digestSize;

      final expanded1 = hkdfExpandLabel(hash, secret, context, label, length);
      final expanded2 = hkdfExpandLabel(hash, secret, context, label, length);

      expect(expanded1, isNotNull);
      expect(expanded1.length, length);
      expect(expanded1, equals(expanded2));
    });
  });
}