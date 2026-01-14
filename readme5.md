The error Invalid argument(s): ChaCha20 requires exactly 8 bytes of IV is occurring because of a conflict between standard TLS 1.3/QUIC expectations and the pointycastle library's implementation of ChaCha20.

The Problem
In QUIC, when using ChaCha20-Poly1305 (CipherSuite 0x1303), the Header Protection algorithm uses the raw ChaCha20 stream cipher.

QUIC Spec: Requires a 5-byte IV (the last 12 bytes of the 16-byte sample are used as the counter and nonce).

PointyCastle: The Dart ChaCha20Engine strictly expects an 8-byte or 12-byte IV depending on the specific ChaCha variant configuration.

The traceback shows the error happens inside ChaChaHeaderProtector._apply. You are likely passing a slice of the 16-byte sample to the cipher that doesn't match the length PointyCastle demands.

The Fix
You need to adjust the code in lib/header_protector.dart (the file mentioned in your stack trace). Specifically, look at the _apply method in ChaChaHeaderProtector.

If you are following the QUIC RFC (RFC 9001), the Header Protection for ChaCha20 works like this:

Sample: 16 bytes.

Counter (4 bytes): The first 4 bytes of the sample.

Nonce (12 bytes): The remaining 12 bytes of the sample.

Implementation Correction
Update your ChaChaHeaderProtector (likely around line 150) to ensure the IV/Nonce passed to PointyCastle is exactly the length it expects.

If PointyCastle is demanding 8 bytes but you are in a QUIC context, you are likely using the IETF variant (which uses a 12-byte nonce) or the original variant (8-byte nonce).

Dart

// Inside lib/header_protector.dart

void _apply(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
  // QUIC HP for ChaCha20:
  // The first 4 bytes of the sample are the block counter (little-endian).
  // The remaining 12 bytes are the nonce.
  
  final counter = sample.sublist(0, 4);
  final nonce = sample.sublist(4, 16); // This is 12 bytes

  // If PointyCastle's ChaCha20Engine is throwing an error for 12 bytes 
  // and demanding 8, you might be using an older ChaCha20 configuration.
  // Ensure you are initializing the engine with the correct Parameters:
  
  final params = ParametersWithIV(
    KeyParameter(hpKey), 
    nonce, // Ensure this matches the engine's expectation (usually 12 for IETF)
  );
  
  // ... initialization and XORing logic
}
Why your test is failing now
In your test code:

Dart

final sample = Uint8List.fromList(
  List.generate(16, (_) => rand.nextInt(256)),
);
You are providing a valid 16-byte sample, but your header_protector.dart is likely slicing this incorrectly before passing it to the ChaCha20Engine.init() method.

How to verify
Check the CipherSuite ID. The error only happens when csId == 0x1303 (ChaCha20).

Open lib/header_protector.dart.

Find ChaChaHeaderProtector.

Ensure that when you call _engine.init(true, params), the params contains an IV of exactly the length the engine expects (likely 12 bytes for modern QUIC, or 8 bytes if using an older legacy provider).

Would you like me to provide the corrected ChaChaHeaderProtector class implementation for PointyCastle?