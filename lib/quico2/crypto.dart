import 'dart:convert';
import 'dart:typed_data';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';
import 'package:x25519/x25519.dart';
import 'buffer.dart';
import 'cipher/aes_gcm.dart';
import 'handshake/extensions/extensions.dart';
import 'handshake/handshake.dart';
import 'hash.dart';
import 'hkdf.dart';
import 'package:elliptic/elliptic.dart' as elliptic;

import 'package:pointycastle/export.dart' as pc;

import 'quic_frame.dart';
import 'quic_packet.dart';

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
  var firstByte = array[0];

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

int expandPacketNumber(truncated, pnLen, largestReceived) {
  var pnWin = 1 << (pnLen * 8);
  var pnHalf = pnWin >>> 1;
  var expected = largestReceived + 1;
  return truncated + pnWin * ((expected - truncated + pnHalf) / pnWin).toInt();
}

int decode_packet_number(array, offset, pnLength) {
  int value = 0;
  for (int i = 0; i < pnLength; i++) {
    value = (value << 8) | array[offset + i];
  }
  return value;
}

int decode_and_expand_packet_number(
  Uint8List array,
  int offset,
  int pnLength,
  int largestReceived,
) {
  var truncated = decode_packet_number(array, offset, pnLength);
  return expandPacketNumber(truncated, pnLength, largestReceived);
}

// Uint8List compute_nonce(Uint8List iv, int packetNumber) {
//   final nonce = Uint8List.fromList(iv); // עותק של ה־IV המקורי (12 בתים)
//   final pnBuffer = Uint8List(12); // 12 בתים, מיושר לימין

//   // הכנס את packetNumber לימין של pnBuffer
//   int n = packetNumber;
//   for (int i = 11; n > 0 && i >= 0; i--) {
//     pnBuffer[i] = n & 0xff;
//     n >>= 8;
//   }

//   // בצע XOR בין ה־IV לבין pnBuffer
//   for (int i = 0; i < 12; i++) {
//     nonce[i] ^= pnBuffer[i];
//   }

//   return nonce;
// }

/// Assumed helper to concatenate a list of byte arrays.
Uint8List concatUint8Arrays(List<Uint8List> buffers) {
  final totalLength = buffers.fold<int>(0, (sum, buf) => sum + buf.length);
  final result = Uint8List(totalLength);
  int offset = 0;
  for (final buf in buffers) {
    result.setAll(offset, buf);
    offset += buf.length;
  }
  return result;
}

// ({List<Uint8List> tls_messages, int new_from_offset})
// extract_tls_messages_from_chunks(Map<int, Uint8List> chunks, int fromOffset) {
//   int offset = fromOffset;
//   List<Uint8List> buffers = [];

//   // 1. Collect contiguous chunks starting from fromOffset
//   while (chunks.containsKey(offset)) {
//     var chunk = chunks[offset]!;
//     buffers.add(chunk);
//     offset += chunk.length;
//   }

//   // If no contiguous data found, return current state
//   if (buffers.isEmpty) {
//     return (tls_messages: [], new_from_offset: fromOffset);
//   }

//   // 2. Combine collected chunks into one contiguous buffer
//   // Note: Using a helper or BytesBuilder is more efficient
//   final BytesBuilder builder = BytesBuilder(copy: false);
//   for (var b in buffers) {
//     builder.add(b);
//   }
//   Uint8List combined = builder.takeBytes();

//   List<Uint8List> tlsMessages = [];
//   int i = 0;

//   // 3. Parse TLS Handshake messages
//   // Structure: [Type: 1 byte] [Length: 3 bytes (Uint24)] [Payload: n bytes]
//   while (i + 4 <= combined.length) {
//     int msgType = combined[i];

//     // Read Uint24 Length (Big Endian)
//     int length =
//         (combined[i + 1] << 16) | (combined[i + 2] << 8) | combined[i + 3];

//     // Check if the full message body is available
//     if (i + 4 + length > combined.length) break;

//     // Extract the full message (header + body)
//     tlsMessages.add(combined.sublist(i, i + 4 + length));
//     i += 4 + length;
//   }

//   // 4. Cleanup processed data and handle leftovers
//   if (i > 0) {
//     // Remove old chunks from the map
//     int bytesToRemove = i;
//     int currentCleanupOffset = fromOffset;

//     while (bytesToRemove > 0) {
//       Uint8List? chunk = chunks.remove(currentCleanupOffset);
//       if (chunk == null) break;

//       if (chunk.length <= bytesToRemove) {
//         // Entire chunk consumed
//         bytesToRemove -= chunk.length;
//         currentCleanupOffset += chunk.length;
//       } else {
//         // Chunk partially consumed (TLS message ended in middle of this chunk)
//         Uint8List leftover = chunk.sublist(bytesToRemove);
//         int newChunkOffset = currentCleanupOffset + bytesToRemove;
//         chunks[newChunkOffset] = leftover;
//         bytesToRemove = 0;
//       }
//     }

//     // Update the cumulative offset
//     fromOffset += i;
//   }

//   return (tls_messages: tlsMessages, new_from_offset: fromOffset);
// }

class ExtractionResult {
  final List<TlsHandshakeMessage> tls_messages;
  final int new_from_offset;
  ExtractionResult(this.tls_messages, this.new_from_offset);
}

ExtractionResult extract_tls_messages_from_chunks(
  Map<int, Uint8List> chunks,
  int current_offset,
) {
  final List<TlsHandshakeMessage> messages = [];
  final builder = BytesBuilder();
  int search_offset = current_offset;

  // 1. Build a contiguous stream of bytes from the fragments
  while (chunks.containsKey(search_offset)) {
    final chunk = chunks[search_offset]!;
    builder.add(chunk);
    search_offset += chunk.length;
  }

  final total_data = builder.toBytes();
  if (total_data.isEmpty) return ExtractionResult([], current_offset);

  final buffer = Buffer(data: total_data);
  int bytes_consumed = 0;

  // 2. Parse TLS Handshake messages (Header: Type[1], Length[3])
  while (buffer.remaining >= 4) {
    final msg_type = buffer.pullUint8();
    final msg_len = buffer.pullUint24();

    if (buffer.remaining >= msg_len) {
      final body = buffer.pullBytes(msg_len);
      try {
        // Parse the specific body (ClientHello, etc.)
        final msg = parseHandshakeBody(msg_type, msg_len, Buffer(data: body));
        messages.add(msg);
        bytes_consumed = buffer.readOffset; // Move the 'consumed' pointer
      } catch (e) {
        print("      [TLS] Failed to parse message body: $e");
        break;
      }
    } else {
      // Message is still fragmented, wait for more packets
      break;
    }
  }

  return ExtractionResult(messages, current_offset + bytes_consumed);
}

// export interface CipherInfo {
//   keylen: number;
//   ivlen: number;
//   hash: typeof sha256 | typeof sha384;
//   str: 'sha256' | 'sha384';
// }

/// Represents the cryptographic parameters for a specific cipher suite.
class CipherInfo {
  final int keyLen;
  final int ivLen;
  final String hashStr;

  CipherInfo({
    required this.keyLen,
    required this.ivLen,
    required this.hashStr,
  });

  // Helper to return a Map if you prefer the dynamic JS style
  Map<String, dynamic> toMap() => {
    'keylen': keyLen,
    'ivlen': ivLen,
    'str': hashStr,
  };
}

/// Returns cipher information based on the TLS 1.3 Cipher Suite ID.
CipherInfo get_cipher_info(int cipherSuite) {
  switch (cipherSuite) {
    case 0x1301: // TLS_AES_128_GCM_SHA256
      return CipherInfo(keyLen: 16, ivLen: 12, hashStr: 'sha256');

    case 0x1302: // TLS_AES_256_GCM_SHA384
      return CipherInfo(keyLen: 32, ivLen: 12, hashStr: 'sha384');

    case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
      return CipherInfo(keyLen: 32, ivLen: 12, hashStr: 'sha256');

    default:
      throw Exception(
        "Unsupported cipher suite: 0x${cipherSuite.toRadixString(16)}",
      );
  }
}

({int packet_number, bool key_phase, Uint8List plaintext}) decrypt_quic_packet(
  Uint8List array,
  Uint8List read_key,
  Uint8List read_iv,
  Uint8List read_hp,
  Uint8List dcid,
  int largest_pn,
) {
  final Buffer buf = Buffer(data: array);
  final firstByte = buf.pullUint8();
  final isLongHeader = (firstByte & 0x80) != 0;

  bool keyPhase = false;
  int pnOffset;
  int packetNumber;
  Uint8List nonce;
  Uint8List aad;
  Uint8List ciphertext;
  Uint8List tag;

  if (isLongHeader) {
    // 1. Skip Version (4 bytes)
    buf.pullUint32();

    // 2. DCID and SCID (using pullBytes to advance offset)
    final dcidLen = buf.pullUint8();
    buf.pullBytes(dcidLen);
    final scidLen = buf.pullUint8();
    buf.pullBytes(scidLen);

    // 3. Determine Type to handle Token
    final packetTypeBits = (firstByte & 0x30) >> 4;
    final packetType = QuicPacketType.fromInt(packetTypeBits);

    if (packetType == QuicPacketType.initial) {
      final tokenLen = buf.pullVarInt();
      buf.pullBytes(tokenLen);
    }

    // 4. Get the Length field (Length of PN + Payload)
    final lengthField = buf.pullVarInt();

    // The current readOffset is exactly where the Packet Number starts
    pnOffset = buf.readOffset;

    // 5. Header Protection Removal
    final pnLength = remove_header_protection(array, pnOffset, read_hp, false);
    if (pnLength == null)
      throw Exception("Failed to remove header protection (Long Header)");

    packetNumber = decode_and_expand_packet_number(
      array,
      pnOffset,
      pnLength,
      largest_pn,
    );
    nonce = compute_nonce(read_iv, packetNumber);

    // 6. Define Boundaries
    final payloadStart = pnOffset + pnLength;
    final totalPayloadLen =
        lengthField - pnLength; // Payload field includes PN, so subtract it

    if (payloadStart + totalPayloadLen > array.length) {
      throw Exception("Packet length field exceeds available buffer data");
    }

    final fullPayload = array.sublist(
      payloadStart,
      payloadStart + totalPayloadLen,
    );
    if (fullPayload.length < 16)
      throw Exception("Payload too short for AEAD tag");

    ciphertext = fullPayload.sublist(0, fullPayload.length - 16);
    tag = fullPayload.sublist(fullPayload.length - 16);

    // AAD includes the entire header up to the start of the payload
    aad = array.sublist(0, payloadStart);
  } else {
    // Short Header: [1 byte header] [DCID] [PN] [Payload]
    pnOffset = 1 + dcid.length;

    final pnLength = remove_header_protection(array, pnOffset, read_hp, true);
    if (pnLength == null)
      throw Exception("Failed to remove header protection (Short Header)");

    keyPhase = (firstByte & 0x04) != 0;
    packetNumber = decode_and_expand_packet_number(
      array,
      pnOffset,
      pnLength,
      largest_pn,
    );
    nonce = compute_nonce(read_iv, packetNumber);

    final payloadStart = pnOffset + pnLength;
    final fullPayload = array.sublist(payloadStart);

    if (fullPayload.length < 16)
      throw Exception("Short header payload too small for tag");

    ciphertext = fullPayload.sublist(0, fullPayload.length - 16);
    tag = fullPayload.sublist(fullPayload.length - 16);
    aad = array.sublist(0, payloadStart);
  }

  // 7. AEAD Decryption
  // This will throw if authentication fails, preventing processing of bad data.
  final plaintext = aes_gcm_decrypt(ciphertext, tag, read_key, nonce, aad);

  return (
    packet_number: packetNumber,
    key_phase: keyPhase,
    plaintext: plaintext,
  );
}

/// Decrypts a QUIC packet/payload using AES-GCM.
/// Matches the dynamic signature of the JS original.
/// Decrypts AES-GCM payload. Throws on authentication failure.
Uint8List aes_gcm_decrypt(
  Uint8List ciphertext,
  Uint8List tag,
  Uint8List key,
  Uint8List nonce,
  Uint8List aad,
) {
  if (key.length != 16 && key.length != 32) {
    throw ArgumentError('Invalid AES key length: ${key.length} bytes.');
  }

  // PointyCastle GCM expects tag appended to ciphertext
  final fullCiphertext = Uint8List(ciphertext.length + tag.length);
  fullCiphertext.setAll(0, ciphertext);
  fullCiphertext.setAll(ciphertext.length, tag);

  try {
    // Assuming 'decrypt' is your PointyCastle wrapper
    final Uint8List decrypted = decrypt(key, fullCiphertext, nonce, aad);
    return decrypted;
  } catch (e) {
    throw Exception(
      'AES-GCM Authentication Failed: Bad tag or modified packet.',
    );
  }
}

/// Fast equality check for byte buffers.
bool arraybufferEqual(Uint8List buf1, Uint8List buf2) {
  if (buf1.length != buf2.length) return false;
  for (int i = 0; i < buf1.length; i++) {
    if (buf1[i] != buf2[i]) return false;
  }
  return true;
}

/// QUIC Initial Salts for different versions
final Map<int, Uint8List> INITIAL_SALTS = {
  // QUIC v1 (RFC 9001)
  0x00000001: Uint8List.fromList([
    0x38,
    0x76,
    0x2c,
    0xf7,
    0xf5,
    0x59,
    0x34,
    0xb3,
    0x4d,
    0x17,
    0x9a,
    0xe6,
    0xa4,
    0xc8,
    0x0c,
    0xad,
    0xcc,
    0xbb,
    0x7f,
    0x0a,
  ]),

  // QUIC draft-29
  0xff00001d: Uint8List.fromList([
    0xaf,
    0xbf,
    0xec,
    0x28,
    0x99,
    0x93,
    0xd2,
    0x4c,
    0x9e,
    0x97,
    0x86,
    0xf1,
    0x9c,
    0x61,
    0x11,
    0xe0,
    0x43,
    0x90,
    0xa8,
    0x99,
  ]),

  // QUIC draft-32
  0xff000020: Uint8List.fromList([
    0x7f,
    0xbc,
    0xdb,
    0x0e,
    0x7c,
    0x66,
    0xbb,
    0x77,
    0x7b,
    0xe3,
    0x0e,
    0xbd,
    0x5f,
    0xa5,
    0x15,
    0x87,
    0x3d,
    0x8d,
    0x6e,
    0x67,
  ]),

  // Google QUIC v50 ("Q050")
  0x51303530: Uint8List.fromList([
    0x69,
    0x45,
    0x6f,
    0xbe,
    0xf1,
    0x6e,
    0xd7,
    0xdc,
    0x48,
    0x15,
    0x9d,
    0x98,
    0xd0,
    0x7f,
    0x5c,
    0x3c,
    0x3d,
    0x5a,
    0xa7,
    0x0a,
  ]),
};

/// Derives Initial keys for QUIC version negotiation and Handshake start
dynamic quic_derive_init_secrets(
  Uint8List clientDcid,
  int version,
  String direction,
) {
  final salt = INITIAL_SALTS[version];
  if (salt == null) {
    throw Exception("Unsupported QUIC version: 0x${version.toRadixString(16)}");
  }

  // Initial secrets are always 32 bytes (SHA-256)
  const int secretLen = 32;
  final Uint8List emptyContext = Uint8List(0);

  // 1. Extract the initial secret using the version salt and client DCID
  final Uint8List initialSecret = hkdfExtract(clientDcid, salt: salt);

  // 2. Expand to the specific traffic secret (client or server)
  final String label = direction == 'read' ? 'client in' : 'server in';
  final Uint8List trafficSecret = hkdfExpandLabel(
    initialSecret,
    emptyContext,
    label,
    secretLen,
  );

  // 3. Derive the actual Key, IV, and Header Protection (HP) key
  return quic_derive_from_tls_secrets(trafficSecret);
}

/// Derives QUIC protection parameters from a traffic secret (Initial, Handshake, or App)
({Uint8List hp, Uint8List iv, Uint8List key}) quic_derive_from_tls_secrets(
  Uint8List? trafficSecret, [
  String hashFunc = 'sha256',
]) {
  if (trafficSecret == null) throw Exception("Traffic secret is null");

  final Uint8List emptyContext = Uint8List(0);

  // Note: These lengths are standard for AES-128-GCM (used in Initial packets)
  // For App secrets, these might vary based on the negotiated cipher suite
  final Uint8List key = hkdfExpandLabel(
    trafficSecret,
    emptyContext,
    'quic key',
    16,
  );
  final Uint8List iv = hkdfExpandLabel(
    trafficSecret,
    emptyContext,
    'quic iv',
    12,
  );
  final Uint8List hp = hkdfExpandLabel(
    trafficSecret,
    emptyContext,
    'quic hp',
    16,
  );

  return (key: key, iv: iv, hp: hp);
}

/// Computes the nonce for AES-GCM by XORing the IV with the Packet Number
Uint8List compute_nonce(Uint8List iv, int packetNumber) {
  // Create a copy of the IV
  final Uint8List nonce = Uint8List.fromList(iv);

  // The packet number is XORed into the last 8 bytes of the 12-byte IV
  // We represent the packetNumber as a 64-bit big-endian integer
  for (int i = 0; i < 8; i++) {
    // Shift packetNumber to get the byte at position i (from right to left)
    int byte = (packetNumber >> (8 * (7 - i))) & 0xff;
    // XOR starts at index 4 of the 12-byte IV (12 - 8 = 4)
    nonce[4 + i] ^= byte;
  }

  return nonce;
}

/// Parses a single TLS Handshake message into its components.
/// Returns a dynamic Map with type, length, and the body payload.
dynamic parse_tls_message(Uint8List data) {
  // Ensure we have at least the header (1 byte type + 3 bytes length)
  if (data.length < 4) return null;

  // Handshake Type (e.g., 1 for ClientHello, 2 for ServerHello)
  int type = data[0];

  // Length is a 24-bit integer (Uint24)
  int length = (data[1] << 16) | (data[2] << 8) | data[3];

  // Extract the body.
  // We use sublist to create a copy, or view for a zero-copy reference.
  // Given the dynamic nature of your port, sublist is safer for manipulation.
  Uint8List body;
  if (data.length >= 4 + length) {
    body = data.sublist(4, 4 + length);
  } else {
    // If the data provided is shorter than the declared length
    body = data.sublist(4);
  }

  return {'type': type, 'length': length, 'body': body};
}

dynamic parse_tls_client_hello(Uint8List body) {
  int ptr = 0;

  // Legacy Version (usually 0x0303 for TLS 1.2 compatibility)
  int legacyVersion = (body[ptr++] << 8) | body[ptr++];

  // Random (32 bytes)
  Uint8List random = body.sublist(ptr, ptr + 32);
  ptr += 32;

  // Session ID
  int sessionIdLen = body[ptr++];
  Uint8List sessionId = body.sublist(ptr, ptr + sessionIdLen);
  ptr += sessionIdLen;

  // Cipher Suites
  int cipherSuitesLen = (body[ptr++] << 8) | body[ptr++];
  List<int> cipherSuites = [];
  for (int i = 0; i < cipherSuitesLen; i += 2) {
    cipherSuites.add((body[ptr++] << 8) | body[ptr++]);
  }

  // Compression Methods
  int compressionMethodsLen = body[ptr++];
  Uint8List compressionMethods = body.sublist(ptr, ptr + compressionMethodsLen);
  ptr += compressionMethodsLen;

  // Extensions
  int extensionsLen = (body[ptr++] << 8) | body[ptr++];
  List<dynamic> extensions = [];
  int extEnd = ptr + extensionsLen;

  while (ptr < extEnd) {
    int extType = (body[ptr++] << 8) | body[ptr++];
    int extLen = (body[ptr++] << 8) | body[ptr++];
    Uint8List extData = body.sublist(ptr, ptr + extLen);
    ptr += extLen;
    extensions.add({'type': extType, 'data': extData});
  }

  // Parsed Extension Variables
  String? sni;
  List<dynamic> keyShares = [];
  List<int> supportedVersions = [];
  List<int> supportedGroups = [];
  List<int> signatureAlgorithms = [];
  List<String> alpn = [];
  int? maxFragmentLength;
  Uint8List? padding;
  Uint8List? cookie;
  List<int> pskKeyExchangeModes = [];
  Uint8List? preSharedKey;
  Uint8List? renegotiationInfo;
  Uint8List? quicTransportParametersRaw;

  for (var ext in extensions) {
    Uint8List extView = ext['data'];
    int type = ext['type'];

    if (type == 0x0000) {
      // Server Name Indication (SNI)
      // list_len(2) + name_type(1) + name_len(2) + name(n)
      int nameLen = (extView[3] << 8) | extView[4];
      sni = utf8.decode(extView.sublist(5, 5 + nameLen));
    } else if (type == 0x0033) {
      // Key Share
      int ptr2 = 2; // skip list length
      int end = extView.length;
      while (ptr2 < end) {
        int group = (extView[ptr2++] << 8) | extView[ptr2++];
        int keyLen = (extView[ptr2++] << 8) | extView[ptr2++];
        Uint8List pubkey = extView.sublist(ptr2, ptr2 + keyLen);
        ptr2 += keyLen;
        keyShares.add({'group': group, 'pubkey': pubkey});
      }
    } else if (type == 0x002b) {
      // Supported Versions
      int len = extView[0];
      for (int i = 1; i < 1 + len; i += 2) {
        supportedVersions.add((extView[i] << 8) | extView[i + 1]);
      }
    } else if (type == 0x000a) {
      // Supported Groups
      int len = (extView[0] << 8) | extView[1];
      for (int i = 2; i < 2 + len; i += 2) {
        supportedGroups.add((extView[i] << 8) | extView[i + 1]);
      }
    } else if (type == 0x000d) {
      // Signature Algorithms
      int len = (extView[0] << 8) | extView[1];
      for (int i = 2; i < 2 + len; i += 2) {
        signatureAlgorithms.add((extView[i] << 8) | extView[i + 1]);
      }
    } else if (type == 0x0010) {
      // ALPN
      int listLen = (extView[0] << 8) | extView[1];
      int i = 2;
      while (i < 2 + listLen) {
        int nameLen = extView[i++];
        alpn.add(utf8.decode(extView.sublist(i, i + nameLen)));
        i += nameLen;
      }
    } else if (type == 0x0039) {
      // QUIC Transport Parameters
      quicTransportParametersRaw = extView;
    } else if (type == 0x0001) {
      // Max Fragment Length
      maxFragmentLength = extView[0];
    } else if (type == 0x0015) {
      // Padding
      padding = extView;
    } else if (type == 0x002a) {
      // Cookie
      int len = (extView[0] << 8) | extView[1];
      cookie = extView.sublist(2, 2 + len);
    } else if (type == 0x002d) {
      // PSK Key Exchange Modes
      int len = extView[0];
      for (int i = 1; i <= len; i++) {
        pskKeyExchangeModes.add(extView[i]);
      }
    } else if (type == 0x0029) {
      // Pre-Shared Key
      preSharedKey = extView;
    } else if (type == 0xff01) {
      // Renegotiation Info
      renegotiationInfo = extView;
    }
  }

  return {
    'type': 'client_hello',
    'legacy_version': legacyVersion,
    'random': random,
    'session_id': sessionId,
    'cipher_suites': cipherSuites,
    'compression_methods': compressionMethods,
    'extensions': extensions,
    'sni': sni,
    'key_shares': keyShares,
    'supported_versions': supportedVersions,
    'supported_groups': supportedGroups,
    'signature_algorithms': signatureAlgorithms,
    'alpn': alpn,
    'max_fragment_length': maxFragmentLength,
    'padding': padding,
    'cookie': cookie,
    'psk_key_exchange_modes': pskKeyExchangeModes,
    'pre_shared_key': preSharedKey,
    'renegotiation_info': renegotiationInfo,
    'quic_transport_parameters_raw': quicTransportParametersRaw,
  };
}

/// Builds a TLS 1.3 ServerHello Handshake message.
/// Returns a dynamic Uint8List containing the full handshake message.
Uint8List build_server_hello(
  Uint8List serverRandom,
  Uint8List publicKey,
  Uint8List sessionId,
  int cipherSuite,
  int group,
) {
  // Use a temporary buffer for the Handshake Body
  final bodyBuf = Buffer();

  // 1. Legacy Version (0x0303 for TLS 1.2 compatibility)
  bodyBuf.pushUint8(0x03);
  bodyBuf.pushUint8(0x03);

  // 2. Random (32 bytes)
  bodyBuf.pushBytes(serverRandom);

  // 3. Session ID
  bodyBuf.pushUint8(sessionId.length & 0xFF);
  bodyBuf.pushBytes(sessionId);

  // 4. Cipher Suite (Uint16)
  bodyBuf.pushUint16(cipherSuite);

  // 5. Compression Method (0x00)
  bodyBuf.pushUint8(0x00);

  // --- Extensions Section ---
  final extBuf = Buffer();

  // Extension: Supported Versions (TLS 1.3)
  extBuf.pushUint16(0x002b); // Type
  extBuf.pushUint16(0x0002); // Length
  extBuf.pushUint16(0x0304); // Value: TLS 1.3

  // Extension: Key Share
  extBuf.pushUint16(0x0033); // Type

  // Key Share Content: Group(2) + KeyLen(2) + Key(n)
  int keyExchangeLen = 2 + 2 + publicKey.length;
  extBuf.pushUint16(keyExchangeLen); // Extension Length
  extBuf.pushUint16(group); // Group
  extBuf.pushUint16(publicKey.length);
  extBuf.pushBytes(publicKey);

  // 6. Push Extensions to Body (Length + Content)
  Uint8List extensionsData = extBuf.toBytes();
  bodyBuf.pushUint16(extensionsData.length);
  bodyBuf.pushBytes(extensionsData);

  // --- Final Handshake Message Construction ---
  Uint8List handshakeBody = bodyBuf.toBytes();
  final finalBuf = Buffer();

  // Handshake Type: 0x02 (Server Hello)
  finalBuf.pushUint8(0x02);

  // Handshake Length: Uint24
  int bodyLen = handshakeBody.length;
  finalBuf.pushUint8((bodyLen >> 16) & 0xFF);
  finalBuf.pushUint8((bodyLen >> 8) & 0xFF);
  finalBuf.pushUint8(bodyLen & 0xFF);

  // The actual body
  finalBuf.pushBytes(handshakeBody);

  return finalBuf.toBytes();
}

({
  Uint8List client_handshake_traffic_secret,
  Uint8List handshake_secret,
  Uint8List server_handshake_traffic_secret,
  Uint8List transcript_hash,
})
tls_derive_handshake_secrets(Uint8List sharedSecret, Uint8List transcript) {
  const int hashLen = 32; // SHA-256 length
  final Uint8List empty = Uint8List(0);
  final Uint8List zero = Uint8List(hashLen);
  final pc.SHA256Digest sha256 = pc.SHA256Digest();

  // 1. Early Secret: HKDF-Extract(Salt=empty, IKM=zeros)
  final Uint8List earlySecret = hkdfExtract(zero, salt: empty);

  // 2. Derived Secret: HKDF-Expand-Label(Early Secret, "derived", Hash(empty), HashLen)
  final Uint8List emptyHash = sha256.process(empty);
  final Uint8List derivedSecret = hkdfExpandLabel(
    earlySecret,
    emptyHash,
    "derived",
    hashLen,
  );

  // 3. Handshake Secret: HKDF-Extract(Salt=derived, IKM=sharedSecret)
  // sharedSecret is the output of the Diffie-Hellman key exchange (e.g., X25519)
  final Uint8List handshakeSecret = hkdfExtract(
    sharedSecret,
    salt: derivedSecret,
  );

  // 4. Transcript Hash: Hash of all handshake messages so far (up to ServerHello)
  final Uint8List transcriptHash = sha256.process(transcript);

  // 5. Derive Handshake Traffic Secrets
  final Uint8List clientHts = hkdfExpandLabel(
    handshakeSecret,
    transcriptHash,
    "c hs traffic",
    hashLen,
  );

  final Uint8List serverHts = hkdfExpandLabel(
    handshakeSecret,
    transcriptHash,
    "s hs traffic",
    hashLen,
  );

  return (
    handshake_secret: handshakeSecret,
    client_handshake_traffic_secret: clientHts,
    server_handshake_traffic_secret: serverHts,
    transcript_hash: transcriptHash,
  );
}

Uint8List build_quic_ext(Map<String, dynamic> params) {
  final out = Buffer();

  void addParam(int id, dynamic value) {
    out.pushUintVar(id);

    Uint8List valueBytes;
    if (value is int) {
      // Numbers are encoded as QUIC VarInts
      final temp = Buffer();
      temp.pushUintVar(value);
      valueBytes = temp.toBytes();
    } else if (value is Uint8List) {
      valueBytes = value;
    } else if (value == true) {
      // Booleans (like disable_active_migration) are zero-length presence markers
      valueBytes = Uint8List(0);
    } else {
      throw Exception('Unsupported value type for parameter $id');
    }

    out.pushUintVar(valueBytes.length);
    out.pushBytes(valueBytes);
  }

  // Mapping parameter names to IDs
  if (params['original_destination_connection_id'] != null)
    addParam(0x00, params['original_destination_connection_id']);
  if (params['max_idle_timeout'] != null)
    addParam(0x01, params['max_idle_timeout']);
  if (params['stateless_reset_token'] != null)
    addParam(0x02, params['stateless_reset_token']);
  if (params['max_udp_payload_size'] != null)
    addParam(0x03, params['max_udp_payload_size']);
  if (params['initial_max_data'] != null)
    addParam(0x04, params['initial_max_data']);
  if (params['initial_max_stream_data_bidi_local'] != null)
    addParam(0x05, params['initial_max_stream_data_bidi_local']);
  if (params['initial_max_stream_data_bidi_remote'] != null)
    addParam(0x06, params['initial_max_stream_data_bidi_remote']);
  if (params['initial_max_stream_data_uni'] != null)
    addParam(0x07, params['initial_max_stream_data_uni']);
  if (params['initial_max_streams_bidi'] != null)
    addParam(0x08, params['initial_max_streams_bidi']);
  if (params['initial_max_streams_uni'] != null)
    addParam(0x09, params['initial_max_streams_uni']);
  if (params['ack_delay_exponent'] != null)
    addParam(0x0a, params['ack_delay_exponent']);
  if (params['max_ack_delay'] != null) addParam(0x0b, params['max_ack_delay']);
  if (params['disable_active_migration'] == true) addParam(0x0c, true);
  if (params['active_connection_id_limit'] != null)
    addParam(0x0e, params['active_connection_id_limit']);
  if (params['initial_source_connection_id'] != null)
    addParam(0x0f, params['initial_source_connection_id']);
  if (params['retry_source_connection_id'] != null)
    addParam(0x10, params['retry_source_connection_id']);
  if (params['max_datagram_frame_size'] != null)
    addParam(0x20, params['max_datagram_frame_size']);

  if (params['web_accepted_origins'] != null) {
    for (var origin in params['web_accepted_origins']) {
      addParam(0x2b603742, utf8.encode(origin as String) as Uint8List);
    }
  }

  return out.toBytes();
}

Uint8List hkdf_expand_label(
  Uint8List secret, // This is the PRK and should be used directly
  String label,
  Uint8List context,
  int length,
) {
  return hkdfExpandLabel(
    secret, // This is the PRK and should be used directly
    context,
    label,
    length,
  );
  // throw UnimplementedError("hkdf not implemented");
}

Uint8List hmac(String str, Uint8List finished_key, Uint8List hash_transcript) {
  return hmacSha256(finished_key, hash_transcript);
  // throw UnimplementedError("hkdf not implemented");
}

Uint8List hash_transcript(
  Uint8List messages, //, hash_func
) {
  return createHash(messages);
  // throw UnimplementedError("hkdf not implemented");
}

/// Encodes a list of QUIC frames into a single Uint8List.
/// The [frames] parameter is expected to be a List of dynamic objects/maps.
Uint8List encode_quic_frames(Map<String, QuicFrame> frames) {
  // Use a capacity estimate to reduce re-allocations
  final Buffer buf = Buffer(data: Uint8List(0));
  print("frames runtime type: ${frames.runtimeType}");
  print("frames: $frames");

  for (var frame in frames.values) {
    // frame = frames.value;
    String type = frame.type;
    print("Frame type: $type");

    if (type == 'padding') {
      frame = frame as PaddingFrame;
      int len = frame.length ?? 1;
      for (int j = 0; j < len; j++) buf.pushUint8(0x00);
    } else if (type == 'ping') {
      buf.pushUint8(0x01);
    } else if (type == 'ack') {
      frame = frame as AckFrame;
      bool hasECN = frame.ecn != null;
      buf.pushUint8(hasECN ? 0x03 : 0x02);

      buf.pushUintVar(frame.largest);
      buf.pushUintVar(frame.delay);
      buf.pushUintVar(frame.ranges?.length ?? 0);
      buf.pushUintVar(frame.firstRange ?? 0);

      if (frame.ranges != null) {
        for (var range in frame.ranges) {
          buf.pushUintVar(range.gap);
          buf.pushUintVar(range.length);
        }
      }

      if (hasECN) {
        buf.pushUintVar(frame.ecn!['ect0']!);
        buf.pushUintVar(frame.ecn!['ect1']!);
        buf.pushUintVar(frame.ecn!['ce']!);
      }
      // } else if (type == 'reset_stream') {
      //   buf.pushUint8(0x04);
      //   buf.pushUintVar(frame.id);
      //   buf.pushUint16(frame.error & 0xFFFF);
      //   buf.pushUintVar(frame.finalSize);
      // } else if (type == 'stop_sending') {
      //   buf.pushUint8(0x05);
      //   buf.pushUintVar(frame.id);
      //   buf.pushUint16(frame.error & 0xFFFF);
      // } else if (type == 'crypto') {
      //   buf.pushUint8(0x06);
      //   buf.pushUintVar(frame.offset);
      //   buf.pushUintVar(frame.data.length);
      //   buf.pushBytes(frame.data);
      // } else if (type == 'new_token') {
      //   buf.pushUint8(0x07);
      //   buf.pushUintVar(frame.token.length);
      //   buf.pushBytes(frame.token);
      // } else if (type == 'stream') {
      //   int typeByte = 0x08;
      //   bool hasOffset = frame.offset != null && frame.offset > 0;
      //   bool hasLen = frame.data != null && frame.data.length > 0;
      //   bool hasFin = frame.fin == true;

      //   if (hasOffset) typeByte |= 0x04;
      //   if (hasLen) typeByte |= 0x02;
      //   if (hasFin) typeByte |= 0x01;

      //   buf.pushUint8(typeByte);
      //   buf.pushUintVar(frame.id);
      //   if (hasOffset) buf.pushUintVar(frame.offset);
      //   if (hasLen) buf.pushUintVar(frame.data.length);
      //   if (frame.data != null) buf.pushBytes(frame.data);
      // } else if (type == 'max_data') {
      //   buf.pushUint8(0x09);
      //   buf.pushUintVar(frame.max);
      // } else if (type == 'max_stream_data') {
      //   buf.pushUint8(0x0a);
      //   buf.pushUintVar(frame.id);
      //   buf.pushUintVar(frame.max);
      // } else if (type == 'max_streams_bidi' || type == 'max_streams_uni') {
      //   buf.pushUint8(type == 'max_streams_bidi' ? 0x0b : 0x0c);
      //   buf.pushUintVar(frame.max);
      // } else if (type == 'data_blocked') {
      //   buf.pushUint8(0x0d);
      //   buf.pushUintVar(frame.limit);
      // } else if (type == 'stream_data_blocked') {
      //   buf.pushUint8(0x0e);
      //   buf.pushUintVar(frame.id);
      //   buf.pushUintVar(frame.limit);
      // } else if (type == 'streams_blocked_bidi' ||
      //     type == 'streams_blocked_uni') {
      //   buf.pushUint8(type == 'streams_blocked_bidi' ? 0x0f : 0x10);
      //   buf.pushUintVar(frame.limit);
      // } else if (type == 'new_connection_id') {
      //   buf.pushUint8(0x11);
      //   buf.pushUintVar(frame.seq);
      //   buf.pushUintVar(frame.retire);
      //   buf.pushUint8(frame.connId.length);
      //   buf.pushBytes(frame.connId);
      //   buf.pushBytes(frame.token); // Statutory 16 bytes
      // } else if (type == 'retire_connection_id') {
      //   buf.pushUint8(0x12);
      //   buf.pushUintVar(frame.seq);
      // } else if (type == 'path_challenge' || type == 'path_response') {
      //   buf.pushUint8(type == 'path_challenge' ? 0x13 : 0x14);
      //   buf.pushBytes(frame.data); // Statutory 8 bytes
      // } else if (type == 'connection_close') {
      //   bool isApp = frame.application == true;
      //   buf.pushUint8(isApp ? 0x1d : 0x1c);
      //   buf.pushUint16(frame.error & 0xFFFF);
      //   if (!isApp) {
      //     buf.pushUintVar(frame.frameType ?? 0);
      //   }
      //   Uint8List reason = Uint8List.fromList(utf8.encode(frame.reason ?? ""));
      //   buf.pushUintVar(reason.length);
      //   buf.pushBytes(reason);
      // } else if (type == 'handshake_done') {
      //   buf.pushUint8(0x1e);
      // } else if (type == 'datagram') {
      //   if (frame.contextId != null) {
      //     buf.pushUint8(0x31);
      //     buf.pushUintVar(frame.contextId);
      //   } else {
      //     buf.pushUint8(0x30);
      //   }
      //   buf.pushBytes(frame.data);
    }
  }

  // Returns the final dynamic byte array
  return buf.toBytes();
}

({Uint8List header, int packetNumberOffset}) build_quic_header(
  QuicPacketType packetType, // Use Enum instead of String
  Uint8List dcid,
  Uint8List scid,
  Uint8List? token,
  int unprotectedPayloadLength,
  int pnLen,
) {
  final buf = Buffer();
  int firstByte;

  // --- Step 1: Handle Short Header (1-RTT) ---
  if (packetType == QuicPacketType.oneRtt) {
    // Short Header (1-RTT): 010K bits followed by PN length
    // Note: K (Key Phase) is 0 by default here
    firstByte = 0x40 | ((pnLen - 1) & 0x03);
    buf.pushUint8(firstByte);
    buf.pushBytes(dcid);

    return (header: buf.toBytes(), packetNumberOffset: buf.length);
  }

  // --- Step 2: Handle Long Headers (Initial, Handshake, 0-RTT) ---
  switch (packetType) {
    case QuicPacketType.initial:
      firstByte = 0xC0 | ((pnLen - 1) & 0x03);
    case QuicPacketType.handshake:
      firstByte = 0xE0 | ((pnLen - 1) & 0x03);
    case QuicPacketType.zeroRtt:
      firstByte = 0xD0 | ((pnLen - 1) & 0x03);
    default:
      throw Exception('Unsupported long header packet type: $packetType');
  }

  buf.pushUint8(firstByte);

  // Version (QUIC v1 = 1)
  buf.pushUint32(1);

  // Destination Connection ID: Length is 1 byte, then bytes
  buf.pushUint8(dcid.length);
  buf.pushBytes(dcid);

  // Source Connection ID: Length is 1 byte, then bytes
  buf.pushUint8(scid.length);
  buf.pushBytes(scid);

  // --- Step 3: Initial Packet specific (Token) ---
  if (packetType == QuicPacketType.initial) {
    final t = token ?? Uint8List(0);
    buf.pushUintVar(t.length); // Tokens use VarInt length
    buf.pushBytes(t);
  }

  // --- Step 4: Length Field (VarInt) ---
  // RFC: The Length field is the length of the PN field plus the payload (AEAD tag included)
  buf.pushUintVar(unprotectedPayloadLength);

  // --- Step 5: Finalize ---
  final headerBytes = buf.toBytes();
  return (header: headerBytes, packetNumberOffset: headerBytes.length);
}

/// Encrypts and protects a QUIC packet.
/// Returns the fully protected byte array ready for the wire.

/// Encrypts and protects a QUIC packet using a Buffer-based approach.
Uint8List encrypt_quic_packet(
  QuicPacketType packetType,
  Uint8List encodedFrames,
  Uint8List writeKey,
  Uint8List writeIv,
  Uint8List writeHp,
  int packetNumber,
  Uint8List dcid,
  Uint8List scid,
  Uint8List? token,
) {
  // 1. Determine Packet Number length (1 to 4 bytes)
  int pnLength;
  if (packetNumber <= 0xFF) {
    pnLength = 1;
  } else if (packetNumber <= 0xFFFF) {
    pnLength = 2;
  } else if (packetNumber <= 0xFFFFFF) {
    pnLength = 3;
  } else {
    pnLength = 4;
  }

  // Prepare the truncated packet number bytes (Big Endian)
  final pnField = Uint8List(pnLength);
  for (int i = 0; i < pnLength; i++) {
    pnField[pnLength - 1 - i] = (packetNumber >> (8 * i)) & 0xFF;
  }

  // 2. Padding for Header Protection Sampling
  // RFC 9001: Sampling requires a sample taken from the ciphertext.
  // We need enough bytes after the PN to ensure a 16-byte sample can be taken.
  const int minCiphertextSize = 16;
  if (encodedFrames.length < minCiphertextSize) {
    final paddingLen = minCiphertextSize - encodedFrames.length;
    final padded = Uint8List(minCiphertextSize);
    padded.setAll(0, encodedFrames);
    // Remaining bytes are already 0x00 (PADDING frames)
    encodedFrames = padded;
  }

  // 3. Length Calculation
  // payload_length = pnLength + frames_length + 16 (GCM Tag)
  int unprotectedPayloadLength = pnLength + encodedFrames.length + 16;

  // 4. Build Header
  // Note: We use the enum and the record-based return type
  final headerInfo = build_quic_header(
    packetType,
    dcid,
    scid,
    token,
    unprotectedPayloadLength,
    pnLength,
  );

  final Uint8List header = headerInfo.header;
  final int pnOffset = headerInfo.packetNumberOffset;

  // 5. Construct AAD (The header before protection + the PN field)
  final aad = Uint8List(header.length + pnField.length);
  aad.setAll(0, header);
  aad.setAll(header.length, pnField);

  // 6. AEAD Encryption
  final Uint8List nonce = compute_nonce(writeIv, packetNumber);
  Uint8List encryptedPayload;

  try {
    // encrypt() should return [ciphertext][tag]
    encryptedPayload = encrypt(writeKey, encodedFrames, nonce, aad);
  } catch (e) {
    throw Exception('Encryption failed: $e');
  }

  // 7. Assemble Packet before Header Protection
  final finalPacket = Uint8List(
    header.length + pnField.length + encryptedPayload.length,
  );
  finalPacket.setAll(0, header);
  finalPacket.setAll(header.length, pnField);
  finalPacket.setAll(header.length + pnField.length, encryptedPayload);

  // 8. Apply Header Protection
  // This obfuscates the PN length bits in the first byte and the PN field itself
  final protectedPacket = apply_header_protection(
    finalPacket,
    pnOffset,
    writeHp,
    pnLength,
  );

  return protectedPacket;
}

/// Encrypts a single block (16 bytes) using AES-ECB.
/// This is used specifically for generating the Header Protection mask.
Uint8List aes_ecb_encrypt(Uint8List key, Uint8List block) {
  final engine = pc.AESEngine();
  engine.init(true, pc.KeyParameter(key)); // true for encryption

  final out = Uint8List(16);
  engine.processBlock(block, 0, out, 0);
  return out;
}

/// Applies Header Protection to a QUIC packet.
/// [packet] is the full packet (header + ciphertext).
/// [pnOffset] is the index where the packet number field begins.
/// [hpKey] is the 16-byte Header Protection key.
/// [pnLength] is the length of the truncated packet number (1-4).
Uint8List apply_header_protection(
  Uint8List packet,
  int pnOffset,
  Uint8List hpKey,
  int pnLength,
) {
  // 1. Extract the sample from the ciphertext.
  // The sample starts 4 bytes after the beginning of the packet number field.
  final int sampleStart = pnOffset + 4;
  if (packet.length < sampleStart + 16) {
    throw Exception("Not enough bytes for header protection sample");
  }
  final Uint8List sample = packet.sublist(sampleStart, sampleStart + 16);

  // 2. Generate the mask using AES-ECB
  final Uint8List maskFull = aes_ecb_encrypt(hpKey, sample);
  // We only need up to 5 bytes of the mask
  final Uint8List mask = maskFull.sublist(0, 5);

  // 3. Protect the first byte (Flags)
  final int firstByte = packet[0];
  final bool isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    // Long Header: protect the least significant 4 bits
    packet[0] ^= (mask[0] & 0x0f);
  } else {
    // Short Header: protect the least significant 5 bits
    packet[0] ^= (mask[0] & 0x1f);
  }

  // 4. Protect the Packet Number field
  // XOR the PN field with the remaining bytes of the mask
  for (int i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }

  return packet;
}

List<QuicPacket> parse_quic_datagram(Uint8List array) {
  List<QuicPacket> packets = [];
  int offset = 0;

  while (offset < array.length) {
    // parse_quic_packet is the function that reads the header
    // and determines the packet type and length
    print("Parsing quic packet");
    QuicPacket pkt = parse_quic_packet(array, offset);

    // If parsing fails or length is 0, we can't continue parsing this datagram
    if (pkt == null || pkt.totalLength == null || pkt.totalLength == 0) {
      break;
    }

    final int start = offset;
    final int end = offset + (pkt.totalLength as int);

    // Ensure we don't go out of bounds
    if (end > array.length) break;

    // slice/sublist logic: if the packet takes the whole array, use the original
    // otherwise, take a sublist (slice) of the bytes for this specific packet
    pkt.raw = (start == 0 && end == array.length)
        ? array
        : array.sublist(start, end);

    packets.add(pkt);

    // Advance the offset to the start of the next packet in the datagram
    offset = end;
  }

  return packets;
}

QuicPacket parse_quic_packet(Uint8List array, [offset0 = 0]) {
  // if (!(array != Uint8List)) return null;
  if (offset0 >= array.length) throw Exception('$offset0 >= ${array.length}');

  final Buffer buf = Buffer(data: array);

  final firstByte = buf.pullUint8();
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    if (offset0 + 6 > array.length) {
      throw Exception('$offset0 +6 >= ${array.length}');
    }

    final version = buf.pullUint32();

    final dcidLen = buf.pullUint8();
    // int offset = offset0 + 6;

    if (buf.readOffset + dcidLen + 1 > array.length) {
      throw Exception('${offset0 + 6} >= ${array.length}');
    }
    final dcid = buf.pullBytes(dcidLen);
    // offset += dcidLen;

    final scidLen = buf.pullUint8();
    if (buf.readOffset + scidLen > array.length) {
      throw Exception('${offset0 + 6} >= ${array.length}');
    }
    final scid = buf.pullBytes(scidLen);
    // offset += scidLen;

    // Version negotiation
    if (version == 0) {
      const List<int> supportedVersions = [];
      while (buf.readOffset + 4 <= array.length) {
        final v = buf.pullUint32();
        supportedVersions.add(v);
        // offset += 4;
      }
      return QuicPacket(
        form: QuicPacketForm.long,
        type: QuicPacketType.version_negotiation,
        version: version,
        dcid: dcid,
        scid: scid,
        supportedVersions: supportedVersions,
        totalLength: (buf.readOffset - offset0).toInt(),
      );
    }

    final packetTypeBits = (firstByte & 0x30) >> 4;
    final typeMap = ['initial', '0rtt', 'handshake', 'retry'];
    final QuicPacketType packetType = //typeMap[packetTypeBits] ?? 'unknown';
    QuicPacketType.fromInt(
      packetTypeBits,
    );

    if (packetType == QuicPacketType.retry) {
      final odcid = array.sublist(buf.readOffset);
      return QuicPacket(
        form: QuicPacketForm.long,
        type: QuicPacketType.retry,
        version: version,
        dcid: dcid,
        scid: scid,
        originalDestinationConnectionId: odcid,
        totalLength: (array.length - offset0).toInt(), // כל השאר
      );
    }

    // == קריאה של Token אם זה Initial ==
    Uint8List? token = null;
    if (packetType == QuicPacketType.initial) {
      try {
        final tokenLen = buf.pullVarInt();
        // offset = buf.readOffset;
        if (buf.readOffset + tokenLen > array.length) {
          throw Exception("${buf.readOffset + tokenLen} > ${array.length}");
        }
        token = buf.pullBytes(tokenLen);
        // offset += tokenLen;
      } catch (e) {
        // return th;
        print("Exception $e");
        throw Exception(e);
      }
    }

    // == כאן בא השלב הקריטי: לקרוא את Length ==
    try {
      final lengthInfo = buf.pullVarInt();
      print("lengthInfo: $lengthInfo");
      // offset = buf.readOffset;

      final payloadLength = lengthInfo;
      final totalLength = buf.readOffset - offset0 + payloadLength;

      if (offset0 + totalLength > array.length) {
        throw Exception("${offset0 + totalLength} > ${array.length}");
        // return null;
      }

      return QuicPacket(
        form: QuicPacketForm.long,
        type: packetType,
        version: version,
        dcid: dcid,
        scid: scid,
        token: token,
        totalLength: totalLength.toInt(),
      );
    } catch (e) {
      // return null;
      throw Exception(e.toString());
    }
  } else {
    final totalLength =
        array.length - offset0; // לא ניתן לדעת בדיוק, אז נניח שזה האחרון
    return QuicPacket(
      form: QuicPacketForm.short,
      type: QuicPacketType.oneRtt,
      totalLength: totalLength.toInt(),
    );
  }
}

/// Helper to wrap a body in a TLS Handshake header (type + 24-bit length)
Uint8List wrapHandshake(int type, Uint8List body) {
  final buf = Buffer();
  buf.pushUint8(type);
  // Manual push for Uint24
  buf.pushUint8((body.length >> 16) & 0xff);
  buf.pushUint8((body.length >> 8) & 0xff);
  buf.pushUint8(body.length & 0xff);
  buf.pushBytes(body);
  return buf.toBytes();
}

Uint8List build_alpn_ext(String protocol) {
  final protoBytes = utf8.encode(protocol);
  final buf = Buffer();
  // ALPN extension ID is typically handled in EncryptedExtensions,
  // but this function builds the extension DATA block.
  buf.pushUint16(0x0010); // Type: ALPN
  buf.pushUint16(protoBytes.length + 3); // Length of extension data
  buf.pushUint16(protoBytes.length + 1); // Length of ALPN list
  buf.pushUint8(protoBytes.length); // Length of string
  buf.pushBytes(Uint8List.fromList(protoBytes));
  return buf.toBytes();
}

Uint8List build_encrypted_extensions(
  List<({Uint8List data, int type})> extensions,
) {
  final extBytes = Buffer();
  for (var ext in extensions) {
    extBytes.pushUint16(ext.type);
    extBytes.pushUint16(ext.data.length);
    extBytes.pushBytes(ext.data);
  }

  final body = Buffer();
  Uint8List inner = extBytes.toBytes();
  body.pushUint16(inner.length);
  body.pushBytes(inner);

  return wrapHandshake(0x08, body.toBytes());
}

Uint8List build_certificate(List<dynamic> certificates) {
  final certListBuf = Buffer();
  for (var entry in certificates) {
    Uint8List cert = entry['cert'];
    Uint8List extensions = entry['extensions'] ?? Uint8List(0);

    // Cert length (Uint24)
    certListBuf.pushUint8((cert.length >> 16) & 0xff);
    certListBuf.pushUint8((cert.length >> 8) & 0xff);
    certListBuf.pushUint8(cert.length & 0xff);
    certListBuf.pushBytes(cert);

    // Extensions length (Uint16)
    certListBuf.pushUint16(extensions.length);
    certListBuf.pushBytes(extensions);
  }

  final body = Buffer();
  body.pushUint8(0x00); // Certificate Request Context (empty)
  Uint8List innerList = certListBuf.toBytes();

  // Total list length (Uint24)
  body.pushUint8((innerList.length >> 16) & 0xff);
  body.pushUint8((innerList.length >> 8) & 0xff);
  body.pushUint8(innerList.length & 0xff);
  body.pushBytes(innerList);

  return wrapHandshake(0x0b, body.toBytes());
}

Uint8List build_certificate_verify(int algorithm, Uint8List signature) {
  final body = Buffer();
  body.pushUint16(algorithm);
  body.pushUint16(signature.length);
  body.pushBytes(signature);
  return wrapHandshake(0x0f, body.toBytes());
}

Uint8List build_finished(Uint8List verifyData) {
  return wrapHandshake(0x14, verifyData);
}

dynamic tls_derive_app_secrets(
  Uint8List handshakeSecret,
  Uint8List transcript,
) {
  const int hashLen = 32; // SHA-256 output length
  final Uint8List empty = Uint8List(0);
  final Uint8List zero = Uint8List(hashLen); // 32 zero bytes

  // Step 1: Compute the hash of the empty string (context for the derived secret)
  final pc.SHA256Digest sha256 = pc.SHA256Digest();
  final Uint8List emptyHash = sha256.process(empty);

  // Step 2: Transition from Handshake Secret to Master Secret
  // RFC 8446: HKDF-Expand-Label(Handshake Secret, "derived", Hash(""), HashLen)
  final Uint8List derivedSecret = hkdfExpandLabel(
    handshakeSecret,
    emptyHash,
    "derived",
    hashLen,
  );

  // master_secret = HKDF-Extract(derived_secret, 0...)
  final Uint8List masterSecret = hkdfExtract(zero, salt: derivedSecret);

  // Step 3: Hash the transcript (the handshake history up to Server Finished)
  final Uint8List transcriptHash = sha256.process(transcript);

  // Step 4: Derive Application Traffic Secrets
  // Labels: "c ap traffic" (Client) and "s ap traffic" (Server)
  final Uint8List clientAppSecret = hkdfExpandLabel(
    masterSecret,
    transcriptHash,
    'c ap traffic',
    hashLen,
  );

  final Uint8List serverAppSecret = hkdfExpandLabel(
    masterSecret,
    transcriptHash,
    's ap traffic',
    hashLen,
  );

  return {
    'client_application_traffic_secret': clientAppSecret,
    'server_application_traffic_secret': serverAppSecret,
  };
}

/// Parses QUIC Transport Parameters from a byte buffer.
/// Returns a dynamic Map matching the structure of the original JS object.
dynamic parse_transport_parameters(Uint8List buf, [int start = 0]) {
  // Use the Buffer class for easy offset management
  final reader = Buffer(data: buf);
  // reader.readOffset = start;

  final Map<String, dynamic> out = {'web_accepted_origins': []};

  while (!reader.eof) {
    try {
      // 1. Identify the Parameter ID
      int id = reader.pullVarInt();

      // 2. Identify the Length of the Value
      int length = reader.pullVarInt();

      // 3. Extract the Value Bytes
      if (reader.remaining < length) {
        throw Exception("Truncated value for id 0x${id.toRadixString(16)}");
      }
      Uint8List valueBytes = reader.pullBytes(length);

      // Helper to read a VarInt from the extracted valueBytes
      int pullInternalVarInt() => Buffer(data: valueBytes).pullVarInt();

      // 4. Decode based on Parameter ID
      switch (id) {
        case 0x00:
          out['original_destination_connection_id'] = valueBytes;
          break;
        case 0x01:
          out['max_idle_timeout'] = pullInternalVarInt();
          break;
        case 0x02:
          if (valueBytes.length != 16)
            throw Exception("stateless_reset_token len != 16");
          out['stateless_reset_token'] = valueBytes;
          break;
        case 0x03:
          out['max_udp_payload_size'] = pullInternalVarInt();
          break;
        case 0x04:
          out['initial_max_data'] = pullInternalVarInt();
          break;
        case 0x05:
          out['initial_max_stream_data_bidi_local'] = pullInternalVarInt();
          break;
        case 0x06:
          out['initial_max_stream_data_bidi_remote'] = pullInternalVarInt();
          break;
        case 0x07:
          out['initial_max_stream_data_uni'] = pullInternalVarInt();
          break;
        case 0x08:
          out['initial_max_streams_bidi'] = pullInternalVarInt();
          break;
        case 0x09:
          out['initial_max_streams_uni'] = pullInternalVarInt();
          break;
        case 0x0a:
          out['ack_delay_exponent'] = pullInternalVarInt();
          break;
        case 0x0b:
          out['max_ack_delay'] = pullInternalVarInt();
          break;
        case 0x0c:
          if (length != 0)
            throw Exception("disable_active_migration must be zero-length");
          out['disable_active_migration'] = true;
          break;
        case 0x0e:
          out['active_connection_id_limit'] = pullInternalVarInt();
          break;
        case 0x0f:
          out['initial_source_connection_id'] = valueBytes;
          break;
        case 0x10:
          out['retry_source_connection_id'] = valueBytes;
          break;
        case 0x11:
          out['server_certificate_hash'] = valueBytes;
          break;
        case 0x20:
          out['max_datagram_frame_size'] = pullInternalVarInt();
          break;
        case 0x2b603742:
          String origin = utf8.decode(valueBytes);
          out['web_accepted_origins'].add(origin);
          break;
        default:
          out.putIfAbsent('unknown', () => []).add({
            'id': id,
            'bytes': valueBytes,
          });
          break;
      }
    } catch (e) {
      // If we encounter a bad VarInt or truncation, we stop parsing
      break;
    }
  }

  return out;
}

({
  Uint8List? client_public_key,
  int? selected_cipher,
  int? selected_group,
  Uint8List? server_private_key,
  Uint8List? server_public_key,
  Uint8List? shared_secret,
})
handle_client_hello(ClientHello parsed) {
  final List<int> supportedGroups = [0x001d, 0x0017]; // X25519, P-256
  final List<int> supportedCipherSuites = [0x1301, 0x1302];

  int? selectedCipher;
  int? selectedGroup;
  Uint8List? clientPublicKey;
  Uint8List? serverPrivateKey;
  Uint8List? serverPublicKey;
  Uint8List? sharedSecret;

  // 1. Select Cipher Suite
  for (var cipher in supportedCipherSuites) {
    if (parsed.cipherSuites.contains(cipher)) {
      selectedCipher = cipher;
      break;
    }
  }

  // 2. Select Group and extract Client Public Key from Extensions
  final keyShareExt =
      parsed.extensions.firstWhere(
            (e) => e is KeyShareExtension,
            orElse: () => throw Exception('No KeyShare extension found'),
          )
          as KeyShareExtension;

  for (var group in supportedGroups) {
    final match = keyShareExt.shares.where((s) => s.group == group);
    if (match.isNotEmpty) {
      selectedGroup = group;
      clientPublicKey = match.first.keyExchange;
      break;
    }
  }

  // 3. Key Exchange
  if (selectedGroup != null && clientPublicKey != null) {
    if (selectedGroup == 0x0017) {
      // --- secp256r1 (P-256) Logic ---
      var ec = elliptic.getP256();
      var priv = ec.generatePrivateKey();

      serverPrivateKey = Uint8List.fromList(priv.bytes);
      serverPublicKey = Uint8List.fromList(HEX.decode(priv.publicKey.toHex()));

      var clientPub = elliptic.PublicKey.fromHex(
        ec,
        HEX.encode(clientPublicKey),
      );

      // Calculate Shared Secret (X-coordinate of scalar multiplication)
      var sharedPoint = ec.scalarMul(clientPub, priv.bytes);
      String xHex = sharedPoint.X.toRadixString(16).padLeft(64, '0');
      sharedSecret = Uint8List.fromList(HEX.decode(xHex));
    } else if (selectedGroup == 0x001d) {
      // --- X25519 Logic ---
      var aliceKeyPair = generateKeyPair(); // Server Keypair
      serverPrivateKey = Uint8List.fromList(aliceKeyPair.privateKey);
      serverPublicKey = Uint8List.fromList(aliceKeyPair.publicKey);

      // Secret = X25519(myPrivateKey, theirPublicKey)
      sharedSecret = Uint8List.fromList(
        X25519(serverPrivateKey, clientPublicKey),
      );
    } else {
      throw UnimplementedError('Group 0x${selectedGroup.toRadixString(16)}');
    }
  }

  return (
    selected_cipher: selectedCipher,
    selected_group: selectedGroup,
    client_public_key: clientPublicKey,
    server_private_key: serverPrivateKey,
    server_public_key: serverPublicKey,
    shared_secret: sharedSecret,
  );
}

({
  int? selected_cipher,
  int? selected_group,
  Uint8List? client_public_key,
  Uint8List? server_private_key,
  Uint8List server_public_key,
  Uint8List? shared_secret,
})
deriveHandshakeKeys(ClientHello parsed) {
  const supportedGroups = [0x001d, 0x0017];
  const supportedCiphers = [0x1301, 0x1302];

  int? selectedCipher;
  int? selectedGroup;
  Uint8List? clientPublicKey;
  Uint8List? serverPrivateKey;
  Uint8List? serverPublicKey;
  Uint8List? sharedSecret;

  // 1. Negotiate Cipher Suite
  for (var cipher in supportedCiphers) {
    if (parsed.cipherSuites.contains(cipher)) {
      selectedCipher = cipher;
      break;
    }
  }

  // 2. Negotiate Group and extract KeyShare
  final keyShareExt =
      parsed.extensions.firstWhere(
            (e) => e is KeyShareExtension,
            orElse: () => throw Exception('No KeyShare extension found'),
          )
          as KeyShareExtension;

  for (var group in supportedGroups) {
    final match = keyShareExt.shares.where((s) => s.group == group);
    if (match.isNotEmpty) {
      selectedGroup = group;
      clientPublicKey = match.first.keyExchange;
      break;
    }
  }

  if (selectedGroup == null || clientPublicKey == null) {
    throw Exception('No compatible KeyShare group found');
  }

  // 3. Key Generation & Secret Computation
  if (selectedGroup == 0x001d) {
    // X25519 Logic
    final keyPair = generateKeyPair(); // Using x25519 package
    serverPrivateKey = Uint8List.fromList(keyPair.privateKey);
    serverPublicKey = Uint8List.fromList(keyPair.publicKey);
  } else if (selectedGroup == 0x0017) {
    // P-256 Logic
    final ec = elliptic.getP256();
    final priv = ec.generatePrivateKey();
    serverPrivateKey = Uint8List.fromList(priv.bytes);
    serverPublicKey = Uint8List.fromList(HEX.decode(priv.publicKey.toHex()));
  }

  // 4. Compute Shared Secret using the helper
  sharedSecret = computeSharedSecret(
    group: selectedGroup,
    clientPublicKey: clientPublicKey,
    serverPrivateKey: serverPrivateKey!,
  );

  return (
    selected_cipher: selectedCipher,
    selected_group: selectedGroup,
    client_public_key: clientPublicKey,
    server_private_key: serverPrivateKey,
    server_public_key: serverPublicKey!,
    shared_secret: sharedSecret,
  );
}

/// Computes the shared secret.
/// For X25519, returns 32 bytes. For P-256, returns the 32-byte X-coordinate.
Uint8List computeSharedSecret({
  required int group,
  required Uint8List clientPublicKey,
  required Uint8List serverPrivateKey,
}) {
  if (group == 0x001d) {
    // Result is directly the 32-byte secret
    return Uint8List.fromList(X25519(serverPrivateKey, clientPublicKey));
  } else if (group == 0x0017) {
    final ec = elliptic.getP256();
    final clientPub = elliptic.PublicKey.fromHex(
      ec,
      HEX.encode(clientPublicKey),
    );

    // Perform scalar multiplication
    final sharedPoint = ec.scalarMul(clientPub, serverPrivateKey);

    // TLS 1.3: Shared secret is the X-coordinate, zero-padded to field size (32 bytes)
    return sharedPoint.X.toRadixString(16).padLeft(64, '0').toUint8List();
  } else {
    throw UnimplementedError(
      'Group 0x${group.toRadixString(16)} not supported',
    );
  }
}

extension on String {
  Uint8List toUint8List() => Uint8List.fromList(HEX.decode(this));
}
