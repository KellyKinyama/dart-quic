// Create a new file: lib/go_quic/quic_header.dart

import 'dart:typed_data';
import 'package:dart_quic/go_quic/buffer.dart';
import 'package:dart_quic/go_quic/protocol.dart';

// ignore: depend_on_referenced_packages
import 'package:pointycastle/export.dart';

import 'ciphers/aes_gcm.dart';

const PACKET_LONG_HEADER = 0x80;
const PACKET_FIXED_BIT = 0x40;
const PACKET_SPIN_BIT = 0x20;

const CONNECTION_ID_MAX_SIZE = 20;
const PACKET_NUMBER_MAX_SIZE = 4;
final RETRY_AEAD_KEY_VERSION_1 = Uint8List.fromList([
  0xbe,
  0x0c,
  0x69,
  0x0b,
  0x9f,
  0x66,
  0x57,
  0x5a,
  0x1d,
  0x76,
  0x6b,
  0x54,
  0xe3,
  0x68,
  0xc8,
  0x4e,
]);
final RETRY_AEAD_KEY_VERSION_2 = Uint8List.fromList([
  0x8f,
  0xb4,
  0xb0,
  0x1b,
  0x56,
  0xac,
  0x48,
  0xe2,
  0x60,
  0xfb,
  0xcb,
  0xce,
  0xad,
  0x7c,
  0xcc,
  0x92,
]);
final RETRY_AEAD_NONCE_VERSION_1 = Uint8List.fromList([
  0x46,
  0x15,
  0x99,
  0xd3,
  0x5d,
  0x63,
  0x2b,
  0xf2,
  0x23,
  0x98,
  0x25,
  0xbb,
]);
final RETRY_AEAD_NONCE_VERSION_2 = Uint8List.fromList([
  0xd8,
  0x69,
  0x69,
  0xbc,
  0x2d,
  0x7c,
  0x6d,
  0x99,
  0x90,
  0xef,
  0xb0,
  0x4a,
]);
const RETRY_INTEGRITY_TAG_SIZE = 16;
const STATELESS_RESET_TOKEN_SIZE = 16;

enum QuicErrorCode {
  NO_ERROR,
  INTERNAL_ERROR,
  CONNECTION_REFUSED,
  FLOW_CONTROL_ERROR,
  STREAM_LIMIT_ERROR,
  STREAM_STATE_ERROR,
  FINAL_SIZE_ERROR,
  FRAME_ENCODING_ERROR,
  TRANSPORT_PARAMETER_ERROR,
  CONNECTION_ID_LIMIT_ERROR,
  PROTOCOL_VIOLATION,
  INVALID_TOKEN,
  APPLICATION_ERROR,
  CRYPTO_BUFFER_EXCEEDED,
  KEY_UPDATE_ERROR,
  AEAD_LIMIT_REACHED,
  VERSION_NEGOTIATION_ERROR,
  CRYPTO_ERROR,
}

enum QuicPacketType {
  INITIAL,
  ZERO_RTT,
  HANDSHAKE,
  RETRY,
  VERSION_NEGOTIATION,
  ONE_RTT;

  factory QuicPacketType.fromValue(int value, Version v) {
    switch (v) {
      case Version.version1:
        {
          return PACKET_LONG_TYPE_DECODE_VERSION_1[v.value]!;
        }
      case Version.version2:
        {
          return PACKET_LONG_TYPE_DECODE_VERSION_2[v.value]!;
        }
      default:
        {
          throw Exception("Unkown protocol version: $v");
        }
    }
  }
}

// For backwards compatibility only, use `QuicPacketType` in new code.
const PACKET_TYPE_INITIAL = QuicPacketType.INITIAL;

// QUIC version 1
// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
const PACKET_LONG_TYPE_ENCODE_VERSION_1 = {
  QuicPacketType.INITIAL: 0,
  QuicPacketType.ZERO_RTT: 1,
  QuicPacketType.HANDSHAKE: 2,
  QuicPacketType.RETRY: 3,
};
final PACKET_LONG_TYPE_DECODE_VERSION_1 = PACKET_LONG_TYPE_ENCODE_VERSION_1.map(
  (k, v) => MapEntry(v, k),
);

// QUIC version 2
// https://datatracker.ietf.org/doc/html/rfc9369#section-3.2
const PACKET_LONG_TYPE_ENCODE_VERSION_2 = {
  QuicPacketType.INITIAL: 1,
  QuicPacketType.ZERO_RTT: 2,
  QuicPacketType.HANDSHAKE: 3,
  QuicPacketType.RETRY: 0,
};
final PACKET_LONG_TYPE_DECODE_VERSION_2 = PACKET_LONG_TYPE_ENCODE_VERSION_2.map(
  (k, v) => MapEntry(v, k),
);

class QuicHeader {
  final QuicPacketType packetType; // 0 for Initial, 2 for Handshake, etc.
  final Uint8List destinationCid;
  final Uint8List sourceCid;
  final int pnOffset;
  int? payloadLength;
  final int headerLength;
  Uint8List? rawHeader;

  QuicHeader({
    required this.packetType,
    required this.destinationCid,
    required this.sourceCid,
    required this.pnOffset,
    this.payloadLength,
    required this.headerLength,
    this.rawHeader,
  });
}

/// Parses the Long Header of an Initial or Handshake packet.
// QuicHeader pullQuicLongHeader(Buffer buffer) {
//   final initialOffset = buffer.tell();

//   final firstByte = buffer.pullUint8();
//   final packetType = (firstByte & 0x30) >> 4;

//   buffer.pullUint32(); // Skip Version

//   final dcid = buffer.pullVector(1);
//   final scid = buffer.pullVector(1);

//   if (packetType == 0) {
//     // Initial Packet has a Token
//     buffer.pullVarInt(); // Skips Token (pullVector(0) reads a var-int length)
//   }

//   final payloadLength = buffer.pullVarInt();
//   final pnOffset = buffer.tell();
//   final headerLength = pnOffset - initialOffset;

//   return QuicHeader(
//     packetType: packetType,
//     destinationCid: dcid,
//     sourceCid: scid,
//     pnOffset: pnOffset,
//     // payloadLength: payloadLength,
//     headerLength: headerLength,
//   );
// }

QuicHeader buildQuicHeader(
  QuicPacketType packetType,
  Uint8List dcid,
  Uint8List scid,
  Uint8List? token,
  Uint8List lengthField,
  int pnLen,
) {
  List<int> hdr = [];
  int firstByte;

  // שלב 1: הגדרת הביט הראשון לפי סוג הפאקט
  if (packetType == QuicPacketType.INITIAL) {
    firstByte = 0xC0 | ((pnLen - 1) & 0x03); // Long Header, Initial
  } else if (packetType == QuicPacketType.HANDSHAKE) {
    firstByte = 0xE0 | ((pnLen - 1) & 0x03); // Long Header, Handshake
  } else if (packetType == QuicPacketType.ZERO_RTT) {
    firstByte = 0xD0 | ((pnLen - 1) & 0x03); // Long Header, 0-RTT
  } else if (packetType == QuicPacketType.ONE_RTT) {
    firstByte = 0x40 | ((pnLen - 1) & 0x03); // Short Header
    hdr.add(firstByte);
    hdr.addAll(dcid); // ב־short header, זהו ה־Destination CID בלבד
    // return {
    //   header: concatUint8Arrays(hdr),
    //   packetNumberOffset: hdr.reduce((sum, u8) => sum + u8.length, 0)
    // };

    //    return QuicHeader(
    //   packetType: packetType,
    //   destinationCid: dcid,
    //   sourceCid: scid,
    //   pnOffset: hdr.reduce((sum, u8) => sum + u8.length),
    //   // payloadLength: payloadLength,
    //   headerLength: header.length,
    // );
    throw UnimplementedError('1rtt');
  } else {
    throw Exception('Unsupported packet type: $packetType');
  }

  Buffer headerBuf = Buffer();
  // שלב 2: Header בסיסי לכל long header
  hdr.add(firstByte);
  hdr.addAll(Version.fromValue(0x00000001).encodeVersion()); // גרסה (4 בייטים)
  headerBuf.pushUintVar(dcid.length);
  hdr.addAll([...headerBuf.data, ...dcid]);
  headerBuf = Buffer();
  headerBuf.pushUintVar(scid.length);
  hdr.addAll([...headerBuf.data, ...scid]);

  // שלב 3: רק ל־Initial מוסיפים טוקן
  if (packetType == QuicPacketType.INITIAL) {
    token ??= Uint8List(0);

    headerBuf = Buffer();
    headerBuf.pushUintVar(token.length);
    hdr.addAll([...headerBuf.data, ...token]);
  }

  // שלב 4: שדה אורך (Length), חובה
  hdr.addAll(lengthField);

  final header = Uint8List.fromList(hdr);

  // שלב 5: חישוב נקודת התחלה של packet number (מופיע מיד לאחר header)
  return QuicHeader(
    packetType: packetType,
    destinationCid: dcid,
    sourceCid: scid,
    pnOffset: header.length,
    // payloadLength: payloadLength,
    headerLength: header.length,
    rawHeader: header,
  );
}

Uint8List writeVarInt(int value) {
  final Buffer buf = Buffer();
  buf.pushUintVar(value);
  return buf.data;
}

Uint8List encryptQuicPacket(
  QuicPacketType packetType,
  Uint8List encodedFrames,
  Uint8List writeKey,
  Uint8List writeIv,
  Uint8List writeHp,
  int packetNumber,
  Uint8List dcid,
  Uint8List scid,
  Uint8List token,
) {
  int pnLength;
  if (packetNumber <= 0xff) {
    pnLength = 1;
  } else if (packetNumber <= 0xffff)
    pnLength = 2;
  else if (packetNumber <= 0xffffff)
    pnLength = 3;
  else
    pnLength = 4;

  final pnFull = Uint8List(4);
  pnFull[0] = (packetNumber >>> 24) & 0xff;
  pnFull[1] = (packetNumber >>> 16) & 0xff;
  pnFull[2] = (packetNumber >>> 8) & 0xff;
  pnFull[3] = packetNumber & 0xff;
  final packetNumberField = pnFull.sublist(4 - pnLength);

  var unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
  var lengthField = writeVarInt(unprotectedPayloadLength);
  var headerInfo = buildQuicHeader(
    packetType,
    dcid,
    scid,
    token,
    lengthField,
    pnLength,
  );

  var header = headerInfo.rawHeader;
  var packetNumberOffset = headerInfo.pnOffset;

  // בונים AAD
  var fullHeader = Uint8List.fromList([...header!, ...packetNumberField]);

  // ✨ הוספת padding אם צריך כדי לאפשר sample
  var minSampleLength = 32; // או 32 ל־ChaCha20
  var minTotalLength = packetNumberOffset + pnLength + minSampleLength;
  var fullLength =
      header.length + pnLength + encodedFrames.length + 16; // 16 = GCM tag

  if (fullLength < minTotalLength) {
    var extraPadding =
        minTotalLength - (header.length + pnLength + encodedFrames.length);
    var padded = Uint8List(encodedFrames.length + extraPadding);
    padded.setAll(0, encodedFrames);
    encodedFrames = padded;
    // חשוב! גם unprotectedPayloadLength צריך להתעדכן
    unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
    lengthField = writeVarInt(unprotectedPayloadLength);
    headerInfo = buildQuicHeader(
      packetType,
      dcid,
      scid,
      token,
      lengthField,
      pnLength,
    );
    header = headerInfo.rawHeader;
    packetNumberOffset = headerInfo.pnOffset;
    fullHeader = Uint8List.fromList([...header!, ...packetNumberField]);
  }

  final ciphertext = aeadEncrypt(
    writeKey,
    writeIv,
    packetNumber,
    encodedFrames,
    fullHeader,
  );
  // if (ciphertext == null) return null;

  final fullPacket = Uint8List.fromList([
    ...header,
    ...packetNumberField,
    ...ciphertext,
  ]);

  return applyHeaderProtection(
    fullPacket,
    packetNumberOffset,
    writeHp,
    pnLength,
  );
}

Uint8List computeNonce(iv, packetNumber) {
  final nonce = Uint8List.fromList(iv); // עותק של ה־IV המקורי (12 בתים)
  final pnBuffer = Uint8List(12); // 12 בתים, מיושר לימין

  // הכנס את packetNumber לימין של pnBuffer
  int n = packetNumber;
  for (int i = 11; n > 0 && i >= 0; i--) {
    pnBuffer[i] = n & 0xff;
    n >>= 8;
  }

  // בצע XOR בין ה־IV לבין pnBuffer
  for (int i = 0; i < 12; i++) {
    nonce[i] ^= pnBuffer[i];
  }

  return nonce;
}

Uint8List aeadEncrypt(
  Uint8List key,
  Uint8List iv,
  int packetNumber,
  Uint8List plaintext,
  Uint8List aad,
) {
  // try {
  // final algo = key.length == 32 ? 'aes-256-gcm' :
  //              key.length == 16 ? 'aes-128-gcm' :
  //              (() => { throw new Error("Unsupported key length: " + key.length); })();

  final nonce = computeNonce(iv, packetNumber);

  // const cipher = crypto.createCipheriv(algo, Buffer.from(key), Buffer.from(nonce));
  // cipher.setAAD(Buffer.from(aad));

  // const encrypted = Buffer.concat([
  //   cipher.update(Buffer.from(plaintext)),
  //   cipher.final()
  // ]);
  // const tag = cipher.getAuthTag();

  // const result = new Uint8Array(encrypted.length + tag.length);
  // result.set(encrypted, 0);
  // result.set(tag, encrypted.length);

  final result = encrypt(key, plaintext, nonce, aad);
  return result;
}

Uint8List aes_ecb_encrypt(
  Uint8List keyBytes,
  Uint8List plaintext,
  AESEngine blockCipher,
) {
  if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
    throw Exception("Invalid AES key size");
  }

  if (plaintext.length % 16 != 0) {
    throw Exception("Plaintext must be a multiple of 16 bytes");
  }

  blockCipher.processBlock(keyBytes, 0, plaintext, 0);
  return plaintext;
}

Uint8List applyHeaderProtection(packet, pnOffset, hpKey, pnLength) {
  final sample = packet.slice(pnOffset + 4, pnOffset + 4 + 16);
  if (sample.length < 16) {
    throw Exception("Not enough bytes for header protection sample");
  }

  final block = AESEngine()..init(true, KeyParameter(hpKey));

  final maskFull = aes_ecb_encrypt(hpKey, sample, block);
  final mask = maskFull.sublist(0, 5);

  final firstByte = packet[0];
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    packet[0] ^= (mask[0] & 0x0f); // רק 4 ביטים אחרונים
  } else {
    packet[0] ^= (mask[0] & 0x1f); // ל־Short Header
  }

  for (int i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }

  return packet;
}

Uint8List aes128ecb(Uint8List sample, Uint8List hpKey) {
  final block = AESEngine()..init(true, KeyParameter(hpKey));

  final input = sample.sublist(0);

  final out = block.process(input);
  return out;
}

int remove_header_protection(
  Uint8List array,
  int pnOffset,
  Uint8List hpKey,
  bool isShort,
) {
  // Step 1: קח sample של 16 בתים מתוך ה־payload אחרי pnOffset + 4
  var sampleOffset = pnOffset + 4;
  var sample = array.sublist(sampleOffset, sampleOffset + 16);

  var mask = aes128ecb(sample, hpKey).sublist(0, 5); // ECB with no IV

  // Step 2: הסר הגנה מה־first byte
  // var firstByte = array[0];

  if (isShort) {
    // Short Header: רק 5 הביטים הנמוכים מוצפנים
    array[0] ^= mask[0] & 0x1f;
  } else {
    // Long Header: רק 4 הביטים הנמוכים מוצפנים
    array[0] ^= mask[0] & 0x0f;
  }

  // Step 3: הסר הגנה מה־packet number (pnLength נקבע מתוך הביטים עכשיו)
  var pnLength = (array[0] & 0x03) + 1;

  for (var i = 0; i < pnLength; i++) {
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}

int expandPacketNumber(int truncated, int pnLen, int largestReceived) {
  var pnWin = 1 << (pnLen * 8);
  var pnHalf = pnWin >>> 1;
  var expected = largestReceived + 1;
  return truncated + pnWin * ((expected - truncated + pnHalf) / pnWin).floor();
}

int decode_packet_number(Uint8List array, int offset, int pnLength) {
  int value = 0;
  for (int i = 0; i < pnLength; i++) {
    value = (value << 8) | array[offset + i];
  }
  return value;
}

int decode_and_expand_packet_number(array, offset, pnLength, largestReceived) {
  var truncated = decode_packet_number(array, offset, pnLength);
  return expandPacketNumber(truncated, pnLength, largestReceived);
}


// Uint8List decrypt_quic_packet(Buffer array, Uint8List read_key, Uint8List read_iv, Uint8List read_hp, Uint8List dcid, int largest_pn) {
//   if (!(array is Uint8List)) throw Exception("Invalid input");

//   final firstByte = array.data[0];
//   final isShort = (firstByte & 0x80) == 0;
//   final isLong = !isShort;

//   bool keyPhase = false;
//   int pnOffset = 0;
//   int pnLength = 0;
//   Uint8List? aad;
//   Uint8List? ciphertext;
//   Uint8List? tag;
//   int? packetNumber;
//   Uint8List? nonce;

//   if (isLong) {
//     // ---------- ניתוח Long Header ----------
//     final view=array.viewBytes(array.data.length,offset: array.readOffset);
//     // final view = Uint8List.view(array.data.buffer, array.readOffset, array.data.length);
//     final version =ByteData.sublistView(view).getUint32(0);
//     final dcidLen = array.data[5];

//     int offset = 6;
//     final parsed_dcid = array.data.sublist(offset, offset + dcidLen);
//     offset += dcidLen;

//     final scidLen = array.data[offset++];
//     final scid = array.data.sublist(offset, offset + scidLen);
//     offset += scidLen;

//     final typeBits = (firstByte & 0x30) >> 4;
//     final typeMap = ['initial', '0rtt', 'handshake', 'retry'];
//     final packetType = typeMap[typeBits];

//     if (packetType == 'initial') {
//       final tokenLen = readVarInt(array, offset);
//       offset += tokenLen.byteLength + tokenLen.value;
//     }

//     final len = readVarInt(array, offset);
//     offset += len.byteLength;

//     pnOffset = offset;

//     // הסרת הגנת כותרת
//     pnLength = remove_header_protection(array.viewBytes(array.data.length), pnOffset, read_hp, false);

//     if(pnLength!=null){
//       packetNumber = decode_and_expand_packet_number(array, pnOffset, pnLength, largest_pn);
//       nonce = computeNonce(read_iv, packetNumber);

//       final payloadStart = pnOffset + pnLength;
//       final payloadLength = len - pnLength;
//       final payloadEnd = payloadStart + payloadLength;

//       if (payloadEnd > array.length) throw Exception("Truncated long header packet");

//       final payload = array.data.sublist(payloadStart, payloadEnd.toInt());
//       if (payload.length < 16) throw Exception("Encrypted payload too short");

//       ciphertext = payload.sublist(0, payload.length - 16);
//       tag = payload.sublist(payload.length - 16);
//       aad = array.data.sublist(0, pnOffset + pnLength);
//     }else{
//       return null;
//     }

//   } else {
//     // ---------- ניתוח Short Header ----------
//     // פורמט: 1 byte header + DCID + Packet Number + Payload

//     const dcidLen = dcid.length;
//     pnOffset = 1 + dcidLen;

//     // הסרת הגנת כותרת
//     pnLength = remove_header_protection(array, pnOffset, read_hp, true);

//     if(pnLength!==null){
//       keyPhase = Boolean((array[0] & 0x04) >>> 2);

//       packetNumber = decode_and_expand_packet_number(array, pnOffset, pnLength, largest_pn);
//       nonce = computeNonce(read_iv, packetNumber);

//       const payloadStart = pnOffset + pnLength;
//       const payload = array.slice(payloadStart);
//       if (payload.length < 16) throw new Error("Encrypted payload too short");

//       ciphertext = payload.slice(0, payload.length - 16);
//       tag = payload.slice(payload.length - 16);
//       aad = array.slice(0, pnOffset + pnLength);
//     }else{
//       return null;
//     }
    
//   }

//   const plaintext = aes_gcm_decrypt(ciphertext, tag, read_key, nonce, aad);

//   return {
//     packet_number: packetNumber,
//     key_phase: keyPhase,
//     plaintext
//   };
// }

Uint8List testServersInitial(
  QuicPacketType packetType,
  Uint8List dcid,
  Uint8List scid,
  Uint8List? token,
  Uint8List lengthField,
  int pnLen,) {
  final connID = dcid;

  // name:           "QUIC v1",
  final version = Version.version1;
  final header = splitHexString("c1000000010008f067a5502a4262b50040750001");
  final data = splitHexString(
    "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304",
  );
  final expectedSample = splitHexString("2cd0991cd25b0aac406a5816b6394100");
  final expectedHdr = splitHexString(
    "cf000000010008f067a5502a4262b5004075c0d9",
  );
  final expectedPacket = splitHexString(
    "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee",
  );

  // parsePayload(data);

  // {
  // 	name:           "QUIC v2",
  // 	version:        protocol.Version2,
  // 	header:         splitHexString(t, "d16b3343cf0008f067a5502a4262b50040750001"),
  // 	data:           splitHexString(t, "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304"),
  // 	expectedSample: splitHexString(t, "6f05d8a4398c47089698baeea26b91eb"),
  // 	expectedHdr:    splitHexString(t, "dc6b3343cf0008f067a5502a4262b5004075d92f"),
  // 	expectedPacket: splitHexString(t, "dc6b3343cf0008f067a5502a4262b500 4075d92faaf16f05d8a4398c47089698 baeea26b91eb761d9b89237bbf872630 17915358230035f7fd3945d88965cf17 f9af6e16886c61bfc703106fbaf3cb4c fa52382dd16a393e42757507698075b2 c984c707f0a0812d8cd5a6881eaf21ce da98f4bd23f6fe1a3e2c43edd9ce7ca8 4bed8521e2e140"),
  // },

  print("connID: ${HEX.encode(connID)}");
  // 1. Create client sealer
  final (sealer, _) = newInitialAEAD(connID, Perspective.server, version);

  // 3. Seal the payload
  final sealed = sealer.seal(data, 1, header);

  // 4. Extract and verify the sample used for header protection
  // Note: this test vector uses a simplified sample location (first 16 bytes).
  final sample = sealed.sublist(2, 2 + 16);
  // _expectEquals(sample, expectedSample, 'Client Packet Sample');

  print('Server Packet Sample');
  print("Got:      $sample");
  print("Expected: $expectedSample");
  print("");

  // 5. Encrypt the header and verify its protected parts
  final protectedHeader = Uint8List.fromList(header);
  final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
  final pnView = Uint8List.view(
    protectedHeader.buffer,
    protectedHeader.length - 2,
    2,
  );
  sealer.encryptHeader(sample, firstByteView, pnView);

  print('Protected header');
  print("Got:      $protectedHeader");
  print("Expected: $expectedHdr");
  print("");

  // 6. Assemble and verify the final, full packet
  final finalPacket = BytesBuilder()
    ..add(protectedHeader)
    ..add(sealed);

  // _expectEquals(finalPacket.toBytes(), expectedPacket, 'Final Client Packet');
  // print('Final Client Packet');
  // print("Got:      ${finalPacket.toBytes()}");
  // print("Expected: $expectedPacket");
  // print("");

  return finalPacket.toBytes();
}

void unprotectAndParseInitialPacket(Uint8List packetBytes) {
  print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
  final mutablePacket = Uint8List.fromList(packetBytes);
  final buffer = mutablePacket.buffer;
  int offset = 1 + 4; // Skip first byte and version

  // DEBUG: Print initial state
  print('DEBUG: Starting offset: $offset');

  final dcidLen = mutablePacket[offset];
  offset += 1;
  final dcid = Uint8List.view(buffer, offset, dcidLen);
  offset += dcidLen;
  // DEBUG: Verify the most critical piece of info: the DCID
  print('DEBUG: Parsed DCID Length: $dcidLen');
  print('DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}');
  print('DEBUG: Offset after DCID: $offset');

  // Skip SCID and Token
  offset += 1 + mutablePacket[offset];
  offset += 1;
  print('DEBUG: Offset after skipping SCID & Token Len: $offset');

  final lengthField = ByteData.view(buffer, offset, 2).getUint16(0) & 0x3FFF;
  offset += 2;
  final pnOffset = offset;
  // DEBUG: Verify the parsed length
  print('DEBUG: Parsed Length Field (Decimal): $lengthField');
  print('DEBUG: Packet Number starts at offset: $pnOffset');

  final (_, opener) = newInitialAEAD(
    dcid,
    Perspective.server,
    Version.version1,
  );

  final sample = Uint8List.view(buffer, pnOffset + 4, 16);
  final firstByteView = Uint8List.view(buffer, 0, 1);
  final protectedPnBytesView = Uint8List.view(buffer, pnOffset, 4);

  // DEBUG: Show what's being used for header decryption
  print('DEBUG: Sample for header protection (Hex): ${HEX.encode(sample)}');

  opener.decryptHeader(sample, firstByteView, protectedPnBytesView);

  final pnLength = (firstByteView[0] & 0x03) + 1;
  int wirePn = 0;
  for (int i = 0; i < pnLength; i++) {
    wirePn = (wirePn << 8) | protectedPnBytesView[i];
  }
  // DEBUG: Verify packet number details
  print('DEBUG: Decoded Packet Number Length: $pnLength bytes');
  print('DEBUG: Decoded Packet Number on the wire: $wirePn');

  final fullPacketNumber = opener.decodePacketNumber(wirePn, pnLength);
  final payloadOffset = pnOffset + pnLength;
  final associatedData = Uint8List.view(buffer, 0, payloadOffset);

  // This is the line from your code that is causing the error
  final ciphertext = Uint8List.view(
    buffer,
    payloadOffset,
    lengthField - pnLength,
  );

  // DEBUG: CRITICAL CHECK - Inspect the slices right before decryption
  print('DEBUG: Payload starts at offset: $payloadOffset');
  print('DEBUG: Associated Data Length: ${associatedData.length}');
  print(
    'DEBUG: Associated Data (Hex): ${HEX.encode(associatedData.sublist(0, min(16, associatedData.length)))}...',
  );
  print('DEBUG: Ciphertext Length: ${ciphertext.length}');
  print(
    'DEBUG: Ciphertext (Hex): ...${HEX.encode(ciphertext.sublist(max(0, ciphertext.length - 16)))}',
  );

  try {
    final plaintext = opener.open(ciphertext, fullPacketNumber, associatedData);
    print('✅ **Payload decrypted successfully!**');
    print(
      '✅ **Recovered Message (Hex): "${HEX.encode(plaintext.sublist(0, 32))}"...',
    );
  } catch (e, s) {
    print('\n❌ ERROR: Decryption failed as expected.');
    print('Exception: $e');
    print('Stack trace:\n$s');
  }
}