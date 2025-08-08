// main.dart

import 'dart:convert';
import 'dart:typed_data';

/// A pure Dart implementation of the SHA-256 cryptographic hash function.
/// This code is for educational and demonstrative purposes. For production
/// use, it is highly recommended to use the `package:crypto`.
class SHA256 {
  // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
  static const _h = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ];

  // Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
  static const _k = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
  ];

  /// Computes the SHA-256 hash for a given string message.
  static String hash(String message) {
    // 1. Pre-processing: Pad the message and convert to big-endian 32-bit words.
    final messageBytes = Uint8List.fromList(utf8.encode(message));
    final paddedMessage = _padMessage(messageBytes);
    final blockWords = _getBlocksAsWords(paddedMessage);

    // 2. Initialize hash values
    final h = Uint32List.fromList(_h);

    // 3. Process each 512-bit block
    for (final block in blockWords) {
      final w = _messageSchedule(block);

      var a = h[0],
          b = h[1],
          c = h[2],
          d = h[3],
          e = h[4],
          f = h[5],
          g = h[6],
          hVal = h[7];

      // 4. Main compression loop (64 rounds)
      for (var i = 0; i < 64; i++) {
        final S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        final ch = (e & f) ^ (~e & g);
        final temp1 = (hVal + S1 + ch + _k[i] + w[i]) & 0xFFFFFFFF;
        final S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        final maj = (a & b) ^ (a & c) ^ (b & c);
        final temp2 = (S0 + maj) & 0xFFFFFFFF;

        hVal = g;
        g = f;
        f = e;
        e = (d + temp1) & 0xFFFFFFFF;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) & 0xFFFFFFFF;
      }

      h[0] = (h[0] + a) & 0xFFFFFFFF;
      h[1] = (h[1] + b) & 0xFFFFFFFF;
      h[2] = (h[2] + c) & 0xFFFFFFFF;
      h[3] = (h[3] + d) & 0xFFFFFFFF;
      h[4] = (h[4] + e) & 0xFFFFFFFF;
      h[5] = (h[5] + f) & 0xFFFFFFFF;
      h[6] = (h[6] + g) & 0xFFFFFFFF;
      h[7] = (h[7] + hVal) & 0xFFFFFFFF;
    }

    // 5. Produce the final hash digest as a hexadecimal string.
    return h.map((val) => val.toRadixString(16).padLeft(8, '0')).join();
  }

  /// Right rotate a 32-bit integer.
  static int _rotr(int value, int shift) {
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF;
  }

  /// Pads the message to a multiple of 512 bits, with the last 64 bits
  /// reserved for the original message length.
  static Uint8List _padMessage(Uint8List messageBytes) {
    final originalLengthInBits = messageBytes.length * 8;

    // Calculate padding length in bits to make the total length 448 mod 512
    var paddingLengthInBits = 448 - (originalLengthInBits % 512);
    if (paddingLengthInBits <= 0) {
      paddingLengthInBits += 512;
    }

    final totalLengthInBits = originalLengthInBits + paddingLengthInBits + 64;
    final paddedBytes = Uint8List(totalLengthInBits ~/ 8);

    // Copy original message
    paddedBytes.setAll(0, messageBytes);

    // Append the '1' bit (0x80)
    paddedBytes[messageBytes.length] = 0x80;

    // Append the original message length as a 64-bit big-endian integer
    final lengthBytes = ByteData(8);
    lengthBytes.setUint64(0, originalLengthInBits, Endian.big);
    paddedBytes.setAll(
      paddedBytes.length - 8,
      lengthBytes.buffer.asUint8List(),
    );

    return paddedBytes;
  }

  /// Parses the padded message into 512-bit blocks of 32-bit words.
  static List<Uint32List> _getBlocksAsWords(Uint8List paddedMessage) {
    final blockCount = paddedMessage.lengthInBytes ~/ 64;
    final blocks = <Uint32List>[];

    for (var i = 0; i < blockCount; i++) {
      final block = Uint32List(16);
      final dataView = ByteData.sublistView(
        paddedMessage,
        i * 64,
        (i + 1) * 64,
      );
      for (var j = 0; j < 16; j++) {
        block[j] = dataView.getUint32(j * 4, Endian.big);
      }
      blocks.add(block);
    }
    return blocks;
  }

  /// Computes the message schedule for a single block.
  static Uint32List _messageSchedule(Uint32List block) {
    final w = Uint32List(64);
    w.setAll(0, block);

    for (var i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF;
    }

    return w;
  }
}

void main() {
  const message1 = "Hello, world!";
  const expectedHash1 =
      "d94b0a8c663a8a3f87532ac4dfc2f0f5b9d3324d45d31536b539c3e215456b3e";
  final actualHash1 = SHA256.hash(message1);
  print("Message: '$message1'");
  print("Actual Hash:   $actualHash1");
  print("Expected Hash: $expectedHash1");
  print("Match: ${actualHash1 == expectedHash1}\n");

  const message2 = "This is a test message for SHA-256.";
  const expectedHash2 =
      "6c8133534b1219b161f0e47085a666e4a2d8d64115147814b870e2815197f1f9";
  final actualHash2 = SHA256.hash(message2);
  print("Message: '$message2'");
  print("Actual Hash:   $actualHash2");
  print("Expected Hash: $expectedHash2");
  print("Match: ${actualHash2 == expectedHash2}\n");
}
