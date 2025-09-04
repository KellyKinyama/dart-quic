// test/initial_aead_test.dart
import 'package:test/test.dart';
import '../protocol.dart';
import '../initial_aead.dart';

void main() {
  // ... (your existing 'Initial AEAD Key and IV Derivation' group)

  group('Key Derivation with Draft-21 Test Vector', () {
    // This test uses a DIFFERENT connection ID than your other tests.
    final connID = splitHexString('0xc654efd8a31b4792');

    // These expected values are taken directly from the draft-21 vector document.
    final expectedClientSecret = splitHexString(
      'f330763357e78ba3c948a5bbbe28aa2a386c10c7f432d897a77e2b244b030533',
    );
    final expectedKey = splitHexString('d4e43d2268f8e43bab1ca67a3680460f');
    final expectedIV = splitHexString('671f1c3d21de47ff018b113b');

    test('validates against the QUIC draft-21 client vector', () {
      final version = Version.version1; // Assuming draft-21 maps to your v1

      // This call is expected to FAIL because your computeSecrets function
      // is likely hardcoded for a different connID.
      final (clientSecret, _) = computeSecrets(connID, version);
      expect(
        clientSecret,
        equals(expectedClientSecret),
        reason:
            "This will fail if computeSecrets() is not a generic implementation.",
      );

      // These lines will not be reached if the test above fails.
      final (key, iv) = computeInitialKeyAndIV(clientSecret, version);
      expect(key, equals(expectedKey));
      expect(iv, equals(expectedIV));
    });
  });

  // ... (your existing 'Initial AEAD Sealing and Opening' group)
}
