import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart' as pc;

import '../aead.dart';
import '../protocol.dart' as protocol;
import '../initial_aead.dart';
import '../protocol.dart';

// #############################################################################
// ## SECTION 1: LOW-LEVEL CRYPTOGRAPHIC PRIMITIVES
// #############################################################################

Uint8List hkdfExtract(Uint8List ikm, {required Uint8List salt}) {
  var hmac = Hmac(sha256, salt);
  return Uint8List.fromList(hmac.convert(ikm).bytes);
}

Uint8List hkdfExpand(Uint8List prk, Uint8List info, int outputLength) {
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

Uint8List hkdfExpandLabel(
  Uint8List secret,
  Uint8List context,
  String label,
  int length,
) {
  final labelBytes = utf8.encode('tls13 $label');
  final hkdfLabel = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xff)
    ..addByte(labelBytes.length)
    ..add(labelBytes)
    ..addByte(context.length)
    ..add(context);
  return hkdfExpand(secret, hkdfLabel.toBytes(), length);
}

// #############################################################################
// ## SECTION 2: CORE PROTOCOL DEFINITIONS
// #############################################################################

// enum Version { version1, version2 }

// enum Perspective { client, server }

typedef PacketNumber = int;
typedef ConnectionID = Uint8List;

Uint8List splitHexString(String hexString) {
  final cleanHex = hexString.startsWith('0x')
      ? hexString.substring(2)
      : hexString;
  return Uint8List.fromList([
    for (int i = 0; i < cleanHex.length; i += 2)
      int.parse(cleanHex.substring(i, i + 2), radix: 16),
  ]);
}

PacketNumber decodePacketNumber(
  int pnLen,
  PacketNumber largestPN,
  PacketNumber truncatedPN,
) {
  final expectedPn = largestPN + 1;
  final pnWindow = 1 << (pnLen * 8);
  final halfWindow = pnWindow ~/ 2;
  final mask = pnWindow - 1;
  final candidatePn = (expectedPn & ~mask) | truncatedPN;
  if (candidatePn > expectedPn + halfWindow && candidatePn >= pnWindow)
    return candidatePn - pnWindow;
  if (candidatePn <= expectedPn - halfWindow &&
      candidatePn < (1 << 62) - pnWindow)
    return candidatePn + pnWindow;
  return candidatePn;
}

// #############################################################################
// ## SECTION 3: AEAD CIPHER AND HEADER PROTECTION
// #############################################################################

// class Aead {
//   final Uint8List key;
//   Aead(this.key);
//   Uint8List encrypt(Uint8List p, Uint8List n, Uint8List ad) =>
//       pc.GCMBlockCipher(pc.AESEngine())
//         ..init(
//           true,
//           pc.AEADParameters(pc.KeyParameter(key), 128, n, ad),
//         ).process(p);
//   Uint8List decrypt(Uint8List c, Uint8List n, Uint8List ad) =>
//       pc.GCMBlockCipher(pc.AESEngine())
//         ..init(
//           false,
//           pc.AEADParameters(pc.KeyParameter(key), 128, n, ad),
//         ).process(c);
// }

// class XorNonceAead {
//   final Aead _aead;
//   final Uint8List _nonceMask;
//   int get overhead => 16;
//   XorNonceAead({required Uint8List key, required Uint8List nonceMask})
//     : _aead = Aead(key),
//       _nonceMask = nonceMask;

//   Uint8List _prepareNonce(PacketNumber pn) {
//     final nonce = Uint8List.fromList(_nonceMask);
//     final pnBytes = ByteData(8)..setUint64(0, pn);
//     for (var i = 0; i < 8; i++) {
//       nonce[4 + i] ^= pnBytes.getUint8(i);
//     }
//     return nonce;
//   }

//   Uint8List seal(Uint8List p, PacketNumber pn, Uint8List ad) =>
//       _aead.encrypt(p, _prepareNonce(pn), ad);
//   Uint8List open(Uint8List c, PacketNumber pn, Uint8List ad) =>
//       _aead.decrypt(c, _prepareNonce(pn), ad);
// }

class AesHeaderProtector {
  final pc.BlockCipher _block;
  AesHeaderProtector(Uint8List hpKey)
    : _block = pc.AESEngine()..init(true, pc.KeyParameter(hpKey));

  void _apply(Uint8List sample, Uint8List firstByte, Uint8List pnBytes) {
    final mask = Uint8List(16);
    _block.processBlock(sample, 0, mask, 0);
    firstByte[0] ^= mask[0] & 0x0f;
    for (var i = 0; i < pnBytes.length; i++) {
      pnBytes[i] ^= mask[i + 1];
    }
  }

  void encrypt(Uint8List s, Uint8List fb, Uint8List pnb) => _apply(s, fb, pnb);
  void decrypt(Uint8List s, Uint8List fb, Uint8List pnb) => _apply(s, fb, pnb);
}

// #############################################################################
// ## SECTION 4: HIGH-LEVEL CRYPTO ORCHESTRATION
// #############################################################################

final quicSaltV1 = splitHexString('0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a');
(Uint8List, Uint8List) computeSecrets(ConnectionID cid) => (
  hkdfExpandLabel(
    hkdfExtract(cid, salt: quicSaltV1),
    Uint8List(0),
    'client in',
    32,
  ),
  hkdfExpandLabel(
    hkdfExtract(cid, salt: quicSaltV1),
    Uint8List(0),
    'server in',
    32,
  ),
);
(Uint8List, Uint8List, Uint8List) computeKeys(Uint8List s) => (
  hkdfExpandLabel(s, Uint8List(0), 'quic key', 16),
  hkdfExpandLabel(s, Uint8List(0), 'quic iv', 12),
  hkdfExpandLabel(s, Uint8List(0), 'quic hp', 16),
);

// class LongHeaderSealer {
//   final XorNonceAead _aead;
//   final AesHeaderProtector _hp;
//   int get overhead => _aead.overhead;
//   LongHeaderSealer(this._aead, this._hp);
//   void encryptHeader(Uint8List s, Uint8List fb, Uint8List pnb) =>
//       _hp.encrypt(s, fb, pnb);
//   Uint8List seal(Uint8List m, PacketNumber pn, Uint8List ad) =>
//       _aead.seal(m, pn, ad);
// }

// class LongHeaderOpener {
//   final XorNonceAead _aead;
//   final AesHeaderProtector _hp;
//   PacketNumber _highest = -1;
//   LongHeaderOpener(this._aead, this._hp);
//   void decryptHeader(Uint8List s, Uint8List fb, Uint8List pnb) =>
//       _hp.decrypt(s, fb, pnb);
//   PacketNumber decodePacketNumber(PacketNumber w, int l) =>
//       protocol.decodePacketNumber(l, _highest, w);
//   Uint8List open(Uint8List c, PacketNumber pn, Uint8List ad) {
//     final d = _aead.open(c, pn, ad);
//     _highest = max(_highest, pn);
//     return d;
//   }
// }

// (LongHeaderSealer, LongHeaderOpener) newInitialAEAD(
//   ConnectionID cid,
//   Perspective p,
// ) {
//   final (clientSecret, serverSecret) = computeSecrets(cid);
//   final (my, other) = p == Perspective.client
//       ? (clientSecret, serverSecret)
//       : (serverSecret, clientSecret);
//   final (myKey, myIV, myHp) = computeKeys(my);
//   final (otherKey, otherIV, otherHp) = computeKeys(other);
//   return (
//     LongHeaderSealer(
//       XorNonceAead(key: myKey, nonceMask: myIV),
//       AesHeaderProtector(myHp),
//     ),
//     LongHeaderOpener(
//       XorNonceAead(key: otherKey, nonceMask: otherIV),
//       AesHeaderProtector(otherHp),
//     ),
//   );
// }

// #############################################################################
// ## SECTION 5: DEMONSTRATION LOGIC
// #############################################################################

Uint8List generateInitialPacket() {
  print('--- 1. Generating a Valid QUIC Initial Packet ---');
  final dcid = splitHexString('0x8394c8f03e515708');
  final scid = splitHexString('0xdeadbeef');
  const packetNumber = 0;
  const pnLength = 1;
  final (sealer, _) = newInitialAEAD(
    dcid,
    Perspective.client,
    Version.version1,
  );
  final plaintextPayload = Uint8List.fromList(utf8.encode("Hello, QUIC!"));

  final headerBuilder = BytesBuilder()
    ..addByte(0xC0 | (pnLength - 1))
    ..add((ByteData(4)..setUint32(0, 1)).buffer.asUint8List())
    ..addByte(dcid.length)
    ..add(dcid)
    ..addByte(scid.length)
    ..add(scid)
    ..addByte(0) // Token Length 0
    ..add(
      (ByteData(2)..setUint16(
            0,
            (plaintextPayload.length + sealer.overhead + pnLength) | 0x4000,
          ))
          .buffer
          .asUint8List(),
    )
    ..addByte(packetNumber);

  final associatedData = headerBuilder.toBytes();
  final pnOffset = associatedData.length - pnLength;
  final sealedPayload = sealer.seal(
    plaintextPayload,
    packetNumber,
    associatedData,
  );
  final sample = sealedPayload.sublist(4 - pnLength, 4 - pnLength + 16);

  // **THE FIX IS HERE:** Modify the header directly, not a copy.
  final protectedHeader = Uint8List.fromList(associatedData);
  sealer.encryptHeader(
    sample,
    Uint8List.view(protectedHeader.buffer, 0, 1),
    Uint8List.view(protectedHeader.buffer, pnOffset, pnLength),
  );

  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealedPayload);
  print('Successfully generated a valid packet.');
  return finalPacket.toBytes();
}

void unprotectAndParseInitialPacket(Uint8List packetBytes) {
  print('\n--- 2. Parsing the Generated QUIC Initial Packet ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version
  final dcidLen = mutablePacket[offset];
  offset += 1;
  final dcid = Uint8List.view(buffer, offset, dcidLen);
  offset += dcidLen;
  offset += 1 + mutablePacket[offset]; // Skip SCID
  offset += 1; // Skip Token Len
  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;

  final (_, opener) = newInitialAEAD(
    dcid,
    Perspective.server,
    Version.version1,
  );

  final sample = Uint8List.view(buffer, pnOffset + 4, 16);
  final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 4);

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final associatedData = Uint8List.view(buffer, 0, payloadOffset);
  final ciphertext = Uint8List.view(buffer, payloadOffset);

  final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
  print('✅ **Payload decrypted successfully!**');
  print('✅ **Recovered Message: "${utf8.decode(plaintext)}"**');
}

void main() {
  try {
    final validPacket = generateInitialPacket();
    unprotectAndParseInitialPacket(validPacket);
  } catch (e, st) {
    print('\nError processing packet: $e');
    print(st);
  }
}
