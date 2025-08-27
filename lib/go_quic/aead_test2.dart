import 'dart:convert';

import 'aead.dart';

import 'cipher_suite.dart';
import 'header_protector.dart';
import 'protocol.dart';
import 'dart:math';
import 'dart:typed_data';

(LongHeaderSealer, LongHeaderOpener) getSealerAndOpener(
  CipherSuite cs,
  Version v,
) {
  // t.Helper()
  // key := make([]byte, 16)
  // hpKey := make([]byte, 16)
  // rand.Read(key)
  // rand.Read(hpKey)
  // block, err := aes.NewCipher(key)
  // require.NoError(t, err)
  // aead, err := cipher.NewGCM(block)
  // require.NoError(t, err)

  // return newLongHeaderSealer(&xorNonceAEAD{aead: aead}, newHeaderProtector(cs, hpKey, true, v)),
  // 	newLongHeaderOpener(&xorNonceAEAD{aead: aead}, newHeaderProtector(cs, hpKey, true, v))

  final rand = Random.secure();
  final key = Uint8List.fromList(
    List.generate(cs.keyLen, (_) => rand.nextInt(256)),
  );
  final hpKey = Uint8List.fromList(
    List.generate(cs.keyLen, (_) => rand.nextInt(256)),
  );
  final iv = Uint8List.fromList(
    List.generate(cs.ivLen, (_) => rand.nextInt(256)),
  );

  final aead = cs.aead(key: key, nonceMask: iv);
  final headerProtector = newHeaderProtector(cs, hpKey, true, v);

  return (
    LongHeaderSealer(aead, headerProtector),
    LongHeaderOpener(aead, headerProtector),
  );
}

// func TestEncryptAndDecryptMessage(t *testing.T) {
// 	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
// 		for _, cs := range cipherSuites {
// 			t.Run(fmt.Sprintf("QUIC %s/%s", v, tls.CipherSuiteName(cs.ID)), func(t *testing.T) {
// 				sealer, opener := getSealerAndOpener(t, cs, v)
// 				msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
// 				ad := []byte("Donec in velit neque.")

// 				encrypted := sealer.Seal(nil, msg, 0x1337, ad)

// 				opened, err := opener.Open(nil, encrypted, 0x1337, ad)
// 				require.NoError(t, err)
// 				require.Equal(t, msg, opened)

// 				// incorrect associated data
// 				_, err = opener.Open(nil, encrypted, 0x1337, []byte("wrong ad"))
// 				require.Equal(t, ErrDecryptionFailed, err)

// 				// incorrect packet number
// 				_, err = opener.Open(nil, encrypted, 0x42, ad)
// 				require.Equal(t, ErrDecryptionFailed, err)
// 			})
// 		}
// 	}
// }

void testEncryptAndDecryptMessage() {
  for (final v in Version.values) {
    for (final csId in [0x1301, 0x1302, 0x1303]) {
      final cs = getCipherSuite(csId);
      print(cs);
      final (sealer, opener) = getSealerAndOpener(cs, v);
      final msg = utf8.encode(
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
      );
      final ad = utf8.encode('Donec in velit neque.');

      final encrypted = sealer.seal(msg, 0x1337, ad);
      final opened = opener.open(encrypted, 0x1337, ad);

      // expect(opened, equals(msg));
      print("Opened:   $opened");
      print("Expected: $msg");

      // Test with incorrect AD
      // opener.open(
      //   Uint8List(0),
      //   encrypted,
      //   0x1337,
      //   Uint8List.fromList('wrong ad'.codeUnits),
      // );
      // throwsA(isA<Exception>()),
      // );

      // Test with incorrect packet number
      // opener.open(Uint8List(0), encrypted, 0x42, ad);
      //   throwsA(isA<Exception>()),
      // );
      // });
    }
  }
}

// func TestDecodePacketNumber(t *testing.T) {
// 	msg := []byte("Lorem ipsum dolor sit amet")
// 	ad := []byte("Donec in velit neque.")

// 	sealer, opener := getSealerAndOpener(t, getCipherSuite(tls.TLS_AES_128_GCM_SHA256), protocol.Version1)
// 	encrypted := sealer.Seal(nil, msg, 0x1337, ad)

// 	// can't decode the packet number if encryption failed
// 	_, err := opener.Open(nil, encrypted[:len(encrypted)-1], 0x1337, ad)
// 	require.Error(t, err)
// 	require.Equal(t, protocol.PacketNumber(0x38), opener.DecodePacketNumber(0x38, protocol.PacketNumberLen1))

// 	_, err = opener.Open(nil, encrypted, 0x1337, ad)
// 	require.NoError(t, err)
// 	require.Equal(t, protocol.PacketNumber(0x1338), opener.DecodePacketNumber(0x38, protocol.PacketNumberLen1))
// }

// func TestEncryptAndDecryptHeader(t *testing.T) {
// 	for _, v := range []protocol.Version{protocol.Version1, protocol.Version2} {
// 		t.Run("QUIC "+v.String(), func(t *testing.T) {
// 			for _, cs := range cipherSuites {
// 				t.Run(tls.CipherSuiteName(cs.ID), func(t *testing.T) {
// 					testEncryptAndDecryptHeader(t, cs, v)
// 				})
// 			}
// 		})
// 	}
// }

// func testEncryptAndDecryptHeader(t *testing.T, cs *cipherSuite, v protocol.Version) {
// 	sealer, opener := getSealerAndOpener(t, cs, v)
// 	var lastFourBitsDifferent int

// 	for i := 0; i < 100; i++ {
// 		sample := make([]byte, 16)
// 		rand.Read(sample)
// 		header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
// 		sealer.EncryptHeader(sample, &header[0], header[9:13])
// 		if header[0]&0xf != 0xb5&0xf {
// 			lastFourBitsDifferent++
// 		}
// 		require.Equal(t, byte(0xb5&0xf0), header[0]&0xf0)
// 		require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, header[1:9])
// 		require.NotEqual(t, []byte{0xde, 0xad, 0xbe, 0xef}, header[9:13])
// 		opener.DecryptHeader(sample, &header[0], header[9:13])
// 		require.Equal(t, []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}, header)
// 	}
// 	require.Greater(t, lastFourBitsDifferent, 75)

// 	// decryption failure with different sample
// 	header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
// 	sample := make([]byte, 16)
// 	rand.Read(sample)
// 	sealer.EncryptHeader(sample, &header[0], header[9:13])
// 	rand.Read(sample) // use a different sample
// 	opener.DecryptHeader(sample, &header[0], header[9:13])
// 	require.NotEqual(t, []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}, header)
// }

void main() {
  testEncryptAndDecryptMessage();
}
