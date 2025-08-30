// Filename: aes_test_final_corrected.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';

// A self-contained, dependency-free implementation of AES-128 for a single block.
// Filename: aes_test_final_corrected.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:collection/collection.dart';

// A self-contained, dependency-free implementation of AES-128 for a single block.
// THIS IS THE FULLY CORRECTED CLASS
class PureAES {
  final List<Uint8List> _roundKeys;

  PureAES(Uint8List key) : _roundKeys = _keyExpansion(key);

  Uint8List encryptBlock(Uint8List plaintext) {
    var state = Uint8List.fromList(plaintext);

    _addRoundKey(state, _roundKeys[0]);

    for (int i = 1; i < 10; i++) {
      _subBytes(state);
      _shiftRows(state);
      _mixColumns(state);
      _addRoundKey(state, _roundKeys[i]);
    }

    _subBytes(state);
    _shiftRows(state);
    _addRoundKey(state, _roundKeys[10]);

    return state;
  }

  void _shiftRows(Uint8List state) {
    var temp;
    // Row 1, shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2, shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3, shift left by 3 (which is equivalent to a right shift of 1)
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
  }

  // --- THIS FUNCTION CONTAINS THE FIX ---
  int _gMul(int a, int b) {
    int p = 0;
    for (int i = 0; i < 8; i++) {
      if ((b & 1) != 0) {
        p ^= a;
      }
      var hiBitSet = (a & 0x80) != 0;
      a <<= 1;
      if (hiBitSet) {
        a ^= 0x1b;
      }
      a &= 0xff; // <<< THIS IS THE CRITICAL FIX
      b >>= 1;
    }
    return p;
  }

  void _mixColumns(Uint8List state) {
    for (int i = 0; i < 4; i++) {
      final c = i * 4;
      final s0 = state[c],
          s1 = state[c + 1],
          s2 = state[c + 2],
          s3 = state[c + 3];
      state[c] = _gMul(s0, 2) ^ _gMul(s1, 3) ^ s2 ^ s3;
      state[c + 1] = s0 ^ _gMul(s1, 2) ^ _gMul(s2, 3) ^ s3;
      state[c + 2] = s0 ^ s1 ^ _gMul(s2, 2) ^ _gMul(s3, 3);
      state[c + 3] = _gMul(s0, 3) ^ s1 ^ s2 ^ _gMul(s3, 2);
    }
  }

  void _addRoundKey(Uint8List state, Uint8List roundKey) {
    for (int i = 0; i < 16; i++) {
      state[i] ^= roundKey[i];
    }
  }

  void _subBytes(Uint8List state) {
    for (int i = 0; i < 16; i++) {
      state[i] = _sBox[state[i]];
    }
  }

  static List<Uint8List> _keyExpansion(Uint8List key) {
    final roundKeys = List<Uint8List>.generate(11, (_) => Uint8List(16));
    roundKeys[0] = Uint8List.fromList(key);
    for (int i = 1; i < 11; i++) {
      var temp = Uint8List.fromList(roundKeys[i - 1].sublist(12, 16));
      final first = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = first;
      for (int j = 0; j < 4; j++) temp[j] = _sBox[temp[j]];
      temp[0] ^= _rCon[i];
      for (int j = 0; j < 4; j++)
        roundKeys[i][j] = roundKeys[i - 1][j] ^ temp[j];
      for (int j = 4; j < 16; j++)
        roundKeys[i][j] = roundKeys[i - 1][j] ^ roundKeys[i][j - 4];
    }
    return roundKeys;
  }

  static final Uint8List _sBox = Uint8List.fromList([
    0x63,
    0x7c,
    0x77,
    0x7b,
    0xf2,
    0x6b,
    0x6f,
    0xc5,
    0x30,
    0x01,
    0x67,
    0x2b,
    0xfe,
    0xd7,
    0xab,
    0x76,
    0xca,
    0x82,
    0xc9,
    0x7d,
    0xfa,
    0x59,
    0x47,
    0xf0,
    0xad,
    0xd4,
    0xa2,
    0xaf,
    0x9c,
    0xa4,
    0x72,
    0xc0,
    0xb7,
    0xfd,
    0x93,
    0x26,
    0x36,
    0x3f,
    0xf7,
    0xcc,
    0x34,
    0xa5,
    0xe5,
    0xf1,
    0x71,
    0xd8,
    0x31,
    0x15,
    0x04,
    0xc7,
    0x23,
    0xc3,
    0x18,
    0x96,
    0x05,
    0x9a,
    0x07,
    0x12,
    0x80,
    0xe2,
    0xeb,
    0x27,
    0xb2,
    0x75,
    0x09,
    0x83,
    0x2c,
    0x1a,
    0x1b,
    0x6e,
    0x5a,
    0xa0,
    0x52,
    0x3b,
    0xd6,
    0xb3,
    0x29,
    0xe3,
    0x2f,
    0x84,
    0x53,
    0xd1,
    0x00,
    0xed,
    0x20,
    0xfc,
    0xb1,
    0x5b,
    0x6a,
    0xcb,
    0xbe,
    0x39,
    0x4a,
    0x4c,
    0x58,
    0xcf,
    0xd0,
    0xef,
    0xaa,
    0xfb,
    0x43,
    0x4d,
    0x33,
    0x85,
    0x45,
    0xf9,
    0x02,
    0x7f,
    0x50,
    0x3c,
    0x9f,
    0xa8,
    0x51,
    0xa3,
    0x40,
    0x8f,
    0x92,
    0x9d,
    0x38,
    0xf5,
    0xbc,
    0xb6,
    0xda,
    0x21,
    0x10,
    0xff,
    0xf3,
    0xd2,
    0xcd,
    0x0c,
    0x13,
    0xec,
    0x5f,
    0x97,
    0x44,
    0x17,
    0xc4,
    0xa7,
    0x7e,
    0x3d,
    0x64,
    0x5d,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4f,
    0xdc,
    0x22,
    0x2a,
    0x90,
    0x88,
    0x46,
    0xee,
    0xb8,
    0x14,
    0xde,
    0x5e,
    0x0b,
    0xdb,
    0xe0,
    0x32,
    0x3a,
    0x0a,
    0x49,
    0x06,
    0x24,
    0x5c,
    0xc2,
    0xd3,
    0xac,
    0x62,
    0x91,
    0x95,
    0xe4,
    0x79,
    0xe7,
    0xc8,
    0x37,
    0x6d,
    0x8d,
    0xd5,
    0x4e,
    0xa9,
    0x6c,
    0x56,
    0xf4,
    0xea,
    0x65,
    0x7a,
    0xae,
    0x08,
    0xba,
    0x78,
    0x25,
    0x2e,
    0x1c,
    0xa6,
    0xb4,
    0xc6,
    0xe8,
    0xdd,
    0x74,
    0x1f,
    0x4b,
    0xbd,
    0x8b,
    0x8a,
    0x70,
    0x3e,
    0xb5,
    0x66,
    0x48,
    0x03,
    0xf6,
    0x0e,
    0x61,
    0x35,
    0x57,
    0xb9,
    0x86,
    0xc1,
    0x1d,
    0x9e,
    0xe1,
    0xf8,
    0x98,
    0x11,
    0x69,
    0xd9,
    0x8e,
    0x94,
    0x9b,
    0x1e,
    0x87,
    0xe9,
    0xce,
    0x55,
    0x28,
    0xdf,
    0x8c,
    0xa1,
    0x89,
    0x0d,
    0xbf,
    0xe6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2d,
    0x0f,
    0xb0,
    0x54,
    0xbb,
    0x16,
  ]);
  static final Uint8List _rCon = Uint8List.fromList([
    0x8d,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1b,
    0x36,
  ]);
}

void main() {
  print('--- Running Final AES Test with Pure Dart Implementation ---');

  // Values from RFC 9001, Appendix A.2 and A.3
  final hpKeyBytes = HEX.decode('437b9aec36be423400cdd115d9db3241');
  final sampleBytes = Uint8List.fromList(
    HEX.decode('d1b1c98dd7689fb8ec11d242b123dc9b'),
  );
  final expectedMaskBytes = Uint8List.fromList(
    HEX.decode('8255b4d32060a842352865d142c2d766'),
  );

  // Initialize our dependency-free AES cipher
  final pureAes = PureAES(Uint8List.fromList(hpKeyBytes));

  // Perform the encryption
  final generatedMask = pureAes.encryptBlock(sampleBytes);

  print('Using HP Key    : ${HEX.encode(hpKeyBytes)}');
  print('Using Sample    : ${HEX.encode(sampleBytes)}');
  print('Expected Mask   : ${HEX.encode(expectedMaskBytes)}');
  print('Generated Mask  : ${HEX.encode(generatedMask)}');
  print('');

  // Compare the result
  final bool success = const ListEquality().equals(
    generatedMask,
    expectedMaskBytes,
  );

  if (success) {
    print('✅ Test PASSED: The generated mask is correct!');
  } else {
    print('❌ Test FAILED: The generated mask is incorrect.');
  }
}
