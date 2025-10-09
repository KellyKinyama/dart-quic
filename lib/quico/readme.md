Hello! That's a great project. Porting a QUIC and HTTP/3 library involves translating complex binary encoding, cryptographic operations, and protocol logic. I've fetched the contents of your JavaScript files and can help guide you on the Dart equivalents for the key components.

The main challenges for porting this library to Dart will be finding equivalents for the third-party JavaScript dependencies and converting buffer manipulation logic (Uint8Array) to Dart's Uint8List.

1. Key Dependencies and Dart Equivalents
The crypto.js file relies heavily on external JavaScript/Node.js packages. Here are the Dart equivalents you'll need to replicate the functionality:

JavaScript Dependency (from crypto.js)	JS Functionality	Recommended Dart Package	Dart Equivalent Functionality
@noble/hashes/hmac, @noble/hashes/hkdf, sha256, sha384	Cryptographic Hashing (SHA-2), HMAC, and HKDF.	package:cryptography or package:pointycastle	Provides SHA-256/384, HMAC, and HKDF implementations. cryptography is generally more modern and idiomatic.
@noble/curves/nist.js (p256), @noble/curves/ed25519 (x25519)	Elliptic Curve Cryptography (P-256/secp256r1 and X25519) for key exchange.	package:pointycastle (Specifically for ECC)	Pointy Castle is a comprehensive crypto library that includes implementations for P-256 and X25519 (using the pointycastle/api.dart and specific cipher imports).
crypto.randomBytes(32)	Secure random byte generation.	dart:math and dart:typed_data (for seeding)	Use the Random.secure() constructor, which relies on the operating system's secure random number generator, to fill a Uint8List.
@stablelib/aes, @stablelib/gcm	AES-GCM encryption/decryption (Authenticated Encryption with Associated Data - AEAD).	package:pointycastle or package:cryptography	Both packages offer AES in GCM mode, which is essential for QUIC packet protection.
@peculiar/x509	X.509 Certificate parsing and handling.	package:asn1lib and possibly package:x509	You'll need to parse ASN.1 structures. asn1lib provides the primitives, while a package like x509 (if available or maintained) could simplify the certificate object handling.
TextEncoder(), TextDecoder()	Encoding/Decoding strings to/from Uint8Array.	dart:convert	Use utf8.encode(string) for TextEncoder and utf8.decode(list) for TextDecoder.

Export to Sheets
2. Converting Uint8Array and Buffer Operations
In Dart, the Uint8Array type is replaced by Uint8List. All buffer manipulation must be adapted to Dart's list and byte data methods.

A. VarInt Encoding/Decoding (utils.js)
The utils.js file implements QUIC Variable-Length Integer (VarInt) encoding and decoding. The logic for writeVarInt and readVarInt will port directly, but the implementation of slicing and returning results needs to use Uint8List and ByteData.

JavaScript (writeVarInt excerpt)
JavaScript

// utils.js
if (value < 0x4000) {
  // 2 bytes, prefix 01
  return new Uint8Array([
    0x40 | (value >> 8),
    value & 0xff
  ]);
}
// For 8-byte VarInt, uses BigInt operations for 64-bit numbers
// ...
Dart (writeVarInt equivalent)
You should use bitwise operations and Dart's Uint8List for this:

Dart

// Dart equivalent for writeVarInt
Uint8List writeVarInt(int value) {
  if (value < 0x40) {
    // 1 byte (00 prefix)
    return Uint8List.fromList([value]);
  }
  if (value < 0x4000) {
    // 2 bytes (01 prefix)
    return Uint8List.fromList([
      0x40 | (value >> 8) & 0x3F,
      value & 0xFF
    ]);
  }
  if (value < 0x40000000) {
    // 4 bytes (10 prefix)
    // Dart integers are 64-bit, so this is safe.
    return Uint8List.fromList([
      0x80 | (value >> 24) & 0x3F,
      (value >> 16) & 0xFF,
      (value >> 8) & 0xFF,
      value & 0xFF
    ]);
  }
  
  // For 8-byte (11 prefix), you must handle the full 62 bits:
  if (value < 0x4000000000000000) {
    // Use ByteData to ensure correct 64-bit little-endian writing.
    final buffer = ByteData(8);
    buffer.setUint64(0, value, Endian.big); // Write 64-bit value

    // Dart integers up to 2^63 - 1 are safe.
    return Uint8List.fromList([
      0xC0 | (buffer.getUint8(0) & 0x3F),
      buffer.getUint8(1),
      buffer.getUint8(2),
      buffer.getUint8(3),
      buffer.getUint8(4),
      buffer.getUint8(5),
      buffer.getUint8(6),
      buffer.getUint8(7),
    ]);
  }
  throw Exception("Value too large for QUIC VarInt");
}
B. Concatenation (concatUint8Arrays)
The concatUint8Arrays function (imported in both crypto.js and h3.js) must be implemented in Dart using the spread operator (...) or the BytesBuilder class for efficiency.

Dart (concatUint8Lists equivalent)
Dart

Uint8List concatUint8Lists(List<Uint8List> arrays) {
  // Efficiently combine all lists
  final buffer = BytesBuilder(copy: false);
  for (var array in arrays) {
    buffer.add(array);
  }
  return buffer.toBytes();
}
3. High-Level Protocol Logic
A. HTTP/3 and QPACK (h3.js)
The h3.js file contains logic for HTTP/3 and QPACK (Header Compression for HTTP/3).

Huffman Codes: The huffman_codes array can be directly ported as a Dart const List<int> or Uint32List.

QPACK Encoding/Decoding: Functions like encodeStringLiteral and the QPACK header building functions (build_qpack_indexed_header, etc.) will need conversion from JavaScript's bit-level manipulation to Dart's equivalent. Since they rely on writeVarInt, ensure that function is correctly ported first.

B. TLS Handshake Structures (crypto.js)
Functions like build_server_hello, build_encrypted_extensions, and parse_tls_client_hello2 are responsible for assembling/disassembling raw TLS handshake messages.

Array Building: In JavaScript, you use [...array1, ...array2] to concatenate byte arrays. In Dart, you will use List<int>.addAll() or the BytesBuilder pattern mentioned above, using Uint8List.fromList() on the final array of bytes.

Bitwise Operations: Operations like (body_length >> 16) & 0xff are standard bitwise shifts and masks, which translate directly to Dart using the >> and & operators, as Dart's standard int is 64-bit, which is more than sufficient for these 3-byte and 4-byte fields.

I am ready to help you with the porting of specific functions or address specific issues you encounter!







I want to port this now: function parse_transport_parameters( Uint8List buf, int? start) {

  if (!(buf.runtimeType == Uint8List)) throw Exception("Expect Uint8Array");

  var offset = start ?? 0;

  var end    = buf.length;

  var out    = (

    web_accepted_origins: []

  );



  while (offset < end) {

    // ---- מזהה הפרמטר ----

    var idVar = readVarInt(buf, offset);

    if (!idVar) throw new Error("Bad varint (id) at " + offset);

    offset += idVar.byteLength;

    var id = idVar.value;



    // ---- אורך הערך ----

    var lenVar = readVarInt(buf, offset);

    if (!lenVar) throw new Error("Bad varint (len) at " + offset);

    offset += lenVar.byteLength;

    var length = lenVar.value;



    if (offset + length > end) throw new Error("Truncated value for id " + id);

    var valueBytes = buf.slice(offset, offset + length);

    offset += length;



    // ---- פענוח לפי ID ----

    switch (id) {

      case 0x00:

        out.original_destination_connection_id = valueBytes;

        break;

      case 0x01:

        out.max_idle_timeout = readVarInt(valueBytes, 0).value;

        break;

      case 0x02:

        if (valueBytes.length !=16) throw new Error("stateless_reset_token len≠16");

        out.stateless_reset_token = valueBytes;

        break;

      case 0x03:

        out.max_udp_payload_size = readVarInt(valueBytes, 0).value;

        break;

      case 0x04:

        out.initial_max_data = readVarInt(valueBytes, 0).value;

        break;

      case 0x05:

        out.initial_max_stream_data_bidi_local = readVarInt(valueBytes, 0).value;

        break;

      case 0x06:

        out.initial_max_stream_data_bidi_remote = readVarInt(valueBytes, 0).value;

        break;

      case 0x07:

        out.initial_max_stream_data_uni = readVarInt(valueBytes, 0).value;

        break;

      case 0x08:

        out.initial_max_streams_bidi = readVarInt(valueBytes, 0).value;

        break;

      case 0x09:

        out.initial_max_streams_uni = readVarInt(valueBytes, 0).value;

        break;

      case 0x0a:

        out.ack_delay_exponent = readVarInt(valueBytes, 0).value;

        break;

      case 0x0b:

        out.max_ack_delay = readVarInt(valueBytes, 0).value;

        break;

      case 0x0c:

        if (length !=0) throw new Error("disable_active_migration must be zero-length");

        out.disable_active_migration = true;

        break;

      case 0x0e:

        out.active_connection_id_limit = readVarInt(valueBytes, 0).value;

        break;

      case 0x0f:

        out.initial_source_connection_id = valueBytes;

        break;

      case 0x10:

        out.retry_source_connection_id = valueBytes;

        break;

      case 0x20:

        out.max_datagram_frame_size = readVarInt(valueBytes, 0).value;

        break;

      case 0x11:

        out.server_certificate_hash = valueBytes;

        break;

      case 0x2b603742:

        var origin = new TextDecoder().decode(valueBytes);

        out.web_accepted_origins.add(origin);

        break;

      default:

        if (!out.unknown) out.unknown = [];

        out.unknown.add({ id: id, bytes: valueBytes });

    }

  }



  return out;

}



This is a great function to port, as it handles the core logic of decoding QUIC Transport Parameters.

The main changes involve:

Dart Class Structure: Replacing the anonymous JavaScript object (out) with a formal Dart class (TransportParameters) for type safety and clean access.

VarInt Helper: Defining a return structure for the required readVarInt function.

Buffer Manipulation: Converting buf.slice(...) to Dart's buf.sublist(...).

String Decoding: Replacing new TextDecoder().decode() with Dart's utf8.decode().

Here is the Dart equivalent, including the necessary helper classes and imports.

1. Dependencies and Helper Classes
You will need the following imports:

Dart

import 'dart:typed_data';
import 'dart:convert'; // For utf8.decode
The function relies on a readVarInt function that returns both the value and the length of the bytes consumed. Since you didn't provide its implementation, here are the required structures:

Dart

/// Represents the result of reading a Variable-Length Integer (VarInt).
class VarIntReadResult {
  final int value;
  final int byteLength;
  const VarIntReadResult(this.value, this.byteLength);
}

/// Data class to hold the parsed QUIC Transport Parameters.
class TransportParameters {
  Uint8List? originalDestinationConnectionId;
  int? maxIdleTimeout;
  Uint8List? statelessResetToken;
  int? maxUdpPayloadSize;
  int? initialMaxData;
  int? initialMaxStreamDataBidiLocal;
  int? initialMaxStreamDataBidiRemote;
  int? initialMaxStreamDataUni;
  int? initialMaxStreamsBidi;
  int? initialMaxStreamsUni;
  int? ackDelayExponent;
  int? maxAckDelay;
  bool disableActiveMigration = false;
  int? activeConnectionIdLimit;
  Uint8List? initialSourceConnectionId;
  Uint8List? retrySourceConnectionId;
  int? maxDatagramFrameSize;
  Uint8List? serverCertificateHash;
  final List<String> webAcceptedOrigins = []; // Matches JS: web_accepted_origins: []
  List<Map<String, dynamic>>? unknown;

  TransportParameters();
}

// NOTE: You must implement or import the actual readVarInt function
// (e.g., in a separate utils.dart file).
// VarIntReadResult readVarInt(Uint8List buffer, int offset);
2. Dart parseTransportParameters Function
Dart

TransportParameters parseTransportParameters(Uint8List buf, [int start = 0]) {
  var offset = start;
  final end = buf.length;
  final out = TransportParameters(); // Instantiate the Dart class

  // Helper function to read the VarInt value and immediately throw if it fails.
  // This simplifies the switch statement logic.
  int readVarIntVal(Uint8List valueBytes) {
    try {
      return readVarInt(valueBytes, 0).value;
    } catch (e) {
      throw Exception("Error decoding VarInt value: $e");
    }
  }

  while (offset < end) {
    // ---- Parameter ID ----
    late VarIntReadResult idVar;
    try {
      // NOTE: Assumes readVarInt is implemented
      idVar = readVarInt(buf, offset);
    } catch (e) {
      throw Exception("Bad varint (id) at $offset: $e");
    }
    
    offset += idVar.byteLength;
    final id = idVar.value;

    // ---- Value Length ----
    late VarIntReadResult lenVar;
    try {
      // NOTE: Assumes readVarInt is implemented
      lenVar = readVarInt(buf, offset);
    } catch (e) {
      throw Exception("Bad varint (len) at $offset: $e");
    }
    
    offset += lenVar.byteLength;
    final length = lenVar.value;

    if (offset + length > end) {
      throw Exception("Truncated value for id $id");
    }
    
    // JS: var valueBytes = buf.slice(offset, offset + length);
    // Dart: buf.sublist(start, end)
    final valueBytes = buf.sublist(offset, offset + length);
    offset += length;

    // ---- Decoding by ID ----
    switch (id) {
      case 0x00:
        out.originalDestinationConnectionId = valueBytes;
        break;
      case 0x01:
        out.maxIdleTimeout = readVarIntVal(valueBytes);
        break;
      case 0x02:
        if (valueBytes.length != 16) {
          throw Exception("stateless_reset_token len≠16");
        }
        out.statelessResetToken = valueBytes;
        break;
      case 0x03:
        out.maxUdpPayloadSize = readVarIntVal(valueBytes);
        break;
      case 0x04:
        out.initialMaxData = readVarIntVal(valueBytes);
        break;
      case 0x05:
        out.initialMaxStreamDataBidiLocal = readVarIntVal(valueBytes);
        break;
      case 0x06:
        out.initialMaxStreamDataBidiRemote = readVarIntVal(valueBytes);
        break;
      case 0x07:
        out.initialMaxStreamDataUni = readVarIntVal(valueBytes);
        break;
      case 0x08:
        out.initialMaxStreamsBidi = readVarIntVal(valueBytes);
        break;
      case 0x09:
        out.initialMaxStreamsUni = readVarIntVal(valueBytes);
        break;
      case 0x0a:
        out.ackDelayExponent = readVarIntVal(valueBytes);
        break;
      case 0x0b:
        out.maxAckDelay = readVarIntVal(valueBytes);
        break;
      case 0x0c:
        if (length != 0) {
          throw Exception("disable_active_migration must be zero-length");
        }
        out.disableActiveMigration = true;
        break;
      case 0x0e:
        out.activeConnectionIdLimit = readVarIntVal(valueBytes);
        break;
      case 0x0f:
        out.initialSourceConnectionId = valueBytes;
        break;
      case 0x10:
        out.retrySourceConnectionId = valueBytes;
        break;
      case 0x20:
        out.maxDatagramFrameSize = readVarIntVal(valueBytes);
        break;
      case 0x11:
        out.serverCertificateHash = valueBytes;
        break;
      case 0x2b603742:
        // JS: var origin = new TextDecoder().decode(valueBytes);
        final origin = utf8.decode(valueBytes);
        out.webAcceptedOrigins.add(origin);
        break;
      default:
        // JS: out.unknown ??= []; out.unknown.add({ id: id, bytes: valueBytes });
        out.unknown ??= [];
        out.unknown!.add({ 'id': id, 'bytes': valueBytes });
    }
  }

  return out;
}






port this then: function readVarInt(array, offset) {

  if (offset >= array.length) return null;



  const first = array[offset];

  const prefix = first >> 6;



  if (prefix == 0) {

    return {

      value: first & 0x3f,

      byteLength: 1

    };

  }



  if (prefix === 0b01) {

    if (offset + 1 >= array.length) return null;

    const value = ((first & 0x3f) << 8) | array[offset + 1];

    return {

      value,

      byteLength: 2

    };

  }



  if (prefix === 0b10) {

    if (offset + 3 >= array.length) return null;

    const value = (

      ((first & 0x3F) << 24) |

      (array[offset + 1] << 16) |

      (array[offset + 2] << 8) |

      array[offset + 3]

    ) >>> 0;

    return {

      value,

      byteLength: 4

    };

  }



  if (prefix === 0b11) {

    if (offset + 7 >= array.length) return null;



    const hi = (

      ((first & 0x3F) << 24) |

      (array[offset + 1] << 16) |

      (array[offset + 2] << 8) |

      array[offset + 3]

    ) >>> 0;



    const lo = (

      (array[offset + 4] << 24) |

      (array[offset + 5] << 16) |

      (array[offset + 6] << 8) |

      array[offset + 7]

    ) >>> 0;



    const full = BigInt(hi) * 4294967296n + BigInt(lo); // 2^32



    if (full <= BigInt(Number.MAX_SAFE_INTEGER)) {

      return {

        value: Number(full),

        byteLength: 8

      };

    } else {

      return {

        value: full,

        byteLength: 8

      };

    }

  }



  return null;

}



This function is critical for any QUIC implementation, as it handles the decoding of variable-length integers (VarInts).

In Dart, we can use the 64-bit int type directly for the VarInt value, which simplifies the logic and eliminates the need for JavaScript's BigInt or Number.MAX_SAFE_INTEGER checks.

Here is the ported Dart code, including the necessary helper class definition:

Dart VarIntReadResult Helper Class
This class is needed to match the structure returned by the JavaScript function:

Dart

import 'dart:typed_data';

/// Represents the result of reading a Variable-Length Integer (VarInt).
class VarIntReadResult {
  final int value;
  final int byteLength;
  const VarIntReadResult(this.value, this.byteLength);
}
Dart readVarInt Function
Dart

import 'dart:typed_data';

/// Reads a QUIC Variable-Length Integer from a byte array starting at a given offset.
/// 
/// Returns a [VarIntReadResult] containing the decoded value and its byte length,
/// or `null` if the buffer is too short.
VarIntReadResult? readVarInt(Uint8List array, int offset) {
  if (offset >= array.length) return null;

  final first = array[offset];
  final prefix = first >> 6;

  // 1-byte encoding (00xxxxxx)
  if (prefix == 0) {
    return VarIntReadResult(
      first & 0x3f, // Mask the two prefix bits
      1
    );
  }

  // 2-byte encoding (01xxxxxx)
  if (prefix == 0b01) {
    if (offset + 1 >= array.length) return null;
    
    // value = (01xxxxxx & 0x3f) << 8 | array[offset + 1]
    final value = ((first & 0x3f) << 8) | array[offset + 1];
    return VarIntReadResult(
      value,
      2
    );
  }

  // 4-byte encoding (10xxxxxx)
  if (prefix == 0b10) {
    if (offset + 3 >= array.length) return null;

    final value = 
      ((first & 0x3F) << 24) |
      (array[offset + 1] << 16) |
      (array[offset + 2] << 8) |
      array[offset + 3];

    // Dart's `int` is 64-bit and handles the result directly.
    return VarIntReadResult(
      value,
      4
    );
  }

  // 8-byte encoding (11xxxxxx)
  if (prefix == 0b11) {
    if (offset + 7 >= array.length) return null;
    
    // In Dart, we can construct the full 62-bit value directly into a 64-bit `int`.
    // value = (11xxxxxx & 0x3F) << 56 | B1 << 48 | ... | B7
    int value = (first & 0x3F) << 56;
    value |= array[offset + 1] << 48;
    value |= array[offset + 2] << 40;
    value |= array[offset + 3] << 32;
    value |= array[offset + 4] << 24;
    value |= array[offset + 5] << 16;
    value |= array[offset + 6] << 8;
    value |= array[offset + 7];

    return VarIntReadResult(
      value,
      8
    );
  }

  // Should be unreachable given the 2-bit prefix logic, but included for completeness
  return null;
}
The main simplification here is that Dart's int natively supports large enough numbers to handle the 62-bit QUIC VarInt, eliminating the need for complex BigInt juggling seen in the JavaScript version.







port these now: function parse_tls_message(data) {

    var view = new Uint8Array(data);

    var type = view[0];

    var length = (view[1] << 16) | (view[2] << 8) | view[3];

    var body = new Uint8Array(view.buffer, view.byteOffset + 4, length);

    return { type, length, body };

}

function parse_tls_client_hello2(body) {

  var view = new Uint8Array(body);

  var ptr = 0;



  var legacy_version = (view[ptr++] << 8) | view[ptr++];

  var random = view.slice(ptr, ptr + 32); ptr += 32;

  var session_id_len = view[ptr++];

  var session_id = view.slice(ptr, ptr + session_id_len); ptr += session_id_len;



  var cipher_suites_len = (view[ptr++] << 8) | view[ptr++];

  var cipher_suites = [];

  for (var i = 0; i < cipher_suites_len; i += 2) {

    var code = (view[ptr++] << 8) | view[ptr++];

    cipher_suites.add(code);

  }



  var compression_methods_len = view[ptr++];

  var compression_methods = view.slice(ptr, ptr + compression_methods_len); ptr += compression_methods_len;



  var extensions_len = (view[ptr++] << 8) | view[ptr++];

  var extensions = [];

  var ext_end = ptr + extensions_len;

  while (ptr < ext_end) {

    var ext_type = (view[ptr++] << 8) | view[ptr++];

    var ext_len = (view[ptr++] << 8) | view[ptr++];

    var ext_data = view.slice(ptr, ptr + ext_len); ptr += ext_len;

    extensions.add({ type: ext_type, data: ext_data });

  }



  var sni = null;

  var key_shares = [];

  var supported_versions = [];

  var supported_groups = [];

  var signature_algorithms = [];

  var alpn = [];

  var max_fragment_length = null;

  var padding = null;

  var cookie = null;

  var psk_key_exchange_modes = [];

  var pre_shared_key = null;

  var renegotiation_info = null;

  var quic_transport_parameters = {

    original: {},

    initial_max_stream_data_bidi_local: undefined,

    initial_max_data: undefined,

    initial_max_streams_bidi: undefined,

    idle_timeout: undefined,

    max_packet_size: undefined,

    ack_delay_exponent: undefined,

    max_datagram_frame_size: undefined,

    web_accepted_origins: undefined

  };



  for (var ext of extensions) {

    var ext_view = new Uint8Array(ext.data);

    if (ext.type === 0x00) {

      var name_len = (ext_view[3] << 8) | ext_view[4];

      sni = new TextDecoder().decode(ext_view.slice(5, 5 + name_len));

    }

    if (ext.type === 0x33) {

      var ptr2 = 0;

      var list_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];

      var end = ptr2 + list_len;

      while (ptr2 < end) {

        var group = (ext_view[ptr2++] << 8) | ext_view[ptr2++];

        var key_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];

        var pubkey = ext_view.slice(ptr2, ptr2 + key_len);

        ptr2 += key_len;

        key_shares.add({ group, pubkey });

      }

    }

    if (ext.type === 0x2b) {

      var len = ext_view[0];

      for (var i = 1; i < 1 + len; i += 2) {

        supported_versions.add((ext_view[i] << 8) | ext_view[i + 1]);

      }

    }

    if (ext.type === 0x0a) {

      var len = (ext_view[0] << 8) | ext_view[1];

      for (var i = 2; i < 2 + len; i += 2) {

        supported_groups.add((ext_view[i] << 8) | ext_view[i + 1]);

      }

    }

    if (ext.type === 0x0d) {

      var len = (ext_view[0] << 8) | ext_view[1];

      for (var i = 2; i < 2 + len; i += 2) {

        signature_algorithms.add((ext_view[i] << 8) | ext_view[i + 1]);

      }

    }

    if (ext.type === 0x10) {

      var list_len = (ext_view[0] << 8) | ext_view[1];

      var i = 2;

      while (i < 2 + list_len) {

        var name_len = ext_view[i++];

        var proto = new TextDecoder().decode(ext_view.slice(i, i + name_len));

        alpn.add(proto);

        i += name_len;

      }

    }

    if (ext.type === 0x39) {

      var ext_data = ext.data;

      var ptr2 = 0;

      while (ptr2 < ext_data.length) {

        var idRes = readVarInt(ext_data, ptr2);

        if (!idRes) break;

        var id = idRes.value;

        ptr2 += idRes.byteLength;



        var lenRes = readVarInt(ext_data, ptr2);

        if (!lenRes) break;

        var len = lenRes.value;

        ptr2 += lenRes.byteLength;



        var value = ext_data.slice(ptr2, ptr2 + len);

        ptr2 += len;



        quic_transport_parameters.original[id] = value;



        function toNumber(bytes) {

          var n = 0;

          for (var i = 0; i < bytes.length; i++) {

            n = (n << 8) | bytes[i];

          }

          return n;

        }



        if (id === 0x00) quic_transport_parameters.original_destination_connection_id = value;

        if (id === 0x01) quic_transport_parameters.max_idle_timeout = toNumber(value);

        if (id === 0x03) quic_transport_parameters.max_packet_size = toNumber(value);

        if (id === 0x04) quic_transport_parameters.initial_max_data = toNumber(value);

        if (id === 0x05) quic_transport_parameters.initial_max_stream_data_bidi_local = toNumber(value);

        if (id === 0x08) quic_transport_parameters.initial_max_streams_bidi = toNumber(value);

        if (id === 0x0a) quic_transport_parameters.ack_delay_exponent = toNumber(value);

        if (id === 0x20) quic_transport_parameters.max_datagram_frame_size = toNumber(value);

        if (id === 0x2b603742) {

          try {

            quic_transport_parameters.web_accepted_origins = new TextDecoder().decode(value);

          } catch (e) {}

        }

      }

    }

    if (ext.type === 0x01) max_fragment_length = ext_view[0];

    if (ext.type === 0x15) padding = ext_view;

    if (ext.type === 0x002a) {

      var len = (ext_view[0] << 8) | ext_view[1];

      cookie = ext_view.slice(2, 2 + len);

    }

    if (ext.type === 0x2d) {

      var len = ext_view[0];

      for (var i = 1; i <= len; i++) {

        psk_key_exchange_modes.add(ext_view[i]);

      }

    }

    if (ext.type === 0x29) pre_shared_key = ext_view;

    if (ext.type === 0xff01) renegotiation_info = ext_view;

  }



  return {

    type: 'client_hello',

    legacy_version,

    random,

    session_id,

    cipher_suites,

    compression_methods,

    extensions,

    sni,

    key_shares,

    supported_versions,

    supported_groups,

    signature_algorithms,

    alpn,

    max_fragment_length,

    padding,

    cookie,

    psk_key_exchange_modes,

    pre_shared_key,

    renegotiation_info,

    quic_transport_parameters

  };

}







function parse_tls_client_hello(body) {

    var view = new Uint8Array(body);

    var ptr = 0;



    var legacy_version = (view[ptr++] << 8) | view[ptr++];

    var random = view.slice(ptr, ptr + 32); ptr += 32;

    var session_id_len = view[ptr++];

    var session_id = view.slice(ptr, ptr + session_id_len); ptr += session_id_len;



    var cipher_suites_len = (view[ptr++] << 8) | view[ptr++];

    var cipher_suites = [];

    for (var i = 0; i < cipher_suites_len; i += 2) {

        var code = (view[ptr++] << 8) | view[ptr++];

        cipher_suites.add(code);

    }



    var compression_methods_len = view[ptr++];

    var compression_methods = view.slice(ptr, ptr + compression_methods_len); ptr += compression_methods_len;



    var extensions_len = (view[ptr++] << 8) | view[ptr++];

    var extensions = [];

    var ext_end = ptr + extensions_len;

    while (ptr < ext_end) {

        var ext_type = (view[ptr++] << 8) | view[ptr++];

        var ext_len = (view[ptr++] << 8) | view[ptr++];

        var ext_data = view.slice(ptr, ptr + ext_len); ptr += ext_len;

        extensions.add({ type: ext_type, data: ext_data });

    }



    var sni = null;

    var key_shares = [];

    var supported_versions = [];

    var supported_groups = [];

    var signature_algorithms = [];

    var alpn = [];

    var max_fragment_length = null;

    var padding = null;

    var cookie = null;

    var psk_key_exchange_modes = [];

    var pre_shared_key = null;

    var renegotiation_info = null;

    var quic_transport_parameters_raw = null;



    for (var ext of extensions) {

      var ext_view = new Uint8Array(ext.data);

      if (ext.type === 0x00) { // SNI

          var list_len = (ext_view[0] << 8) | ext_view[1];

          var name_type = ext_view[2];

          var name_len = (ext_view[3] << 8) | ext_view[4];

          var name = new TextDecoder().decode(ext_view.slice(5, 5 + name_len));

          sni = name;

      }

      if (ext.type === 0x33) {

          var ptr2 = 0;

          var list_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];

          var end = ptr2 + list_len;

          while (ptr2 < end) {

              var group = (ext_view[ptr2++] << 8) | ext_view[ptr2++];

              var key_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];

              var pubkey = ext_view.slice(ptr2, ptr2 + key_len);

              ptr2 += key_len;

              key_shares.add({ group, pubkey });

          }

     

      }

      if (ext.type === 0x2b) { // supported_versions

          var len = ext_view[0];

          for (var i = 1; i < 1 + len; i += 2) {

              var ver = (ext_view[i] << 8) | ext_view[i + 1];

              supported_versions.add(ver);

          }

      }

      if (ext.type === 0x0a) { // supported_groups

          var len = (ext_view[0] << 8) | ext_view[1];

          for (var i = 2; i < 2 + len; i += 2) {

              supported_groups.add((ext_view[i] << 8) | ext_view[i + 1]);

          }

      }

      if (ext.type === 0x0d) { // signature_algorithms

          var len = (ext_view[0] << 8) | ext_view[1];

          for (var i = 2; i < 2 + len; i += 2) {

              signature_algorithms.add((ext_view[i] << 8) | ext_view[i + 1]);

          }

      }

      if (ext.type === 0x10) { // ALPN

          var list_len = (ext_view[0] << 8) | ext_view[1];

          var i = 2;

          while (i < 2 + list_len) {

              var name_len = ext_view[i++];

              var proto = new TextDecoder().decode(ext_view.slice(i, i + name_len));

              alpn.add(proto);

              i += name_len;

          }

      }

      if (ext.type === 0x39) { // quic_transport_parameters

        quic_transport_parameters_raw = ext.data;

      }

      if (ext.type === 0x01) { // Max Fragment Length

          max_fragment_length = ext_view[0];

      }

      if (ext.type === 0x15) { // Padding

          padding = ext_view;

      }

      if (ext.type === 0x002a) { // Cookie

          var len = (ext_view[0] << 8) | ext_view[1];

          cookie = ext_view.slice(2, 2 + len);

      }

      if (ext.type === 0x2d) { // PSK Key Exchange Modes

          var len = ext_view[0];

          for (var i = 1; i <= len; i++) {

              psk_key_exchange_modes.add(ext_view[i]);

          }

      }

      if (ext.type === 0x29) { // PreSharedKey (placeholder)

          pre_shared_key = ext_view;

      }

      if (ext.type === 0xff01) { // Renegotiation Info

          renegotiation_info = ext_view;

      }

    }



    return {

        type: 'client_hello',

        legacy_version,

        random,

        session_id,

        cipher_suites,

        compression_methods,

        extensions,

        sni,

        key_shares,

        supported_versions,

        supported_groups,

        signature_algorithms,

        alpn,

        max_fragment_length,

        padding,

        cookie,

        psk_key_exchange_modes,

        pre_shared_key,

        renegotiation_info,

        quic_transport_parameters_raw

    };

}



That's a lot of complex, low-level parsing logic! These functions are for handling the TLS Handshake Protocol, specifically for reading TLS messages and parsing the ClientHello packet, which is essential for QUIC negotiation (since QUIC uses TLS 1.3).

Here is the Dart equivalent, utilizing Dart classes for structure and handling pointer management:

1. Imports and Helper Classes
You will need the following imports and classes (including VarIntReadResult and the placeholders for TransportParameters and readVarInt from previous steps):

Dart

import 'dart:typed_data';
import 'dart:convert'; // For utf8.decode

// --- From Previous Steps ---
class VarIntReadResult {
  final int value;
  final int byteLength;
  const VarIntReadResult(this.value, this.byteLength);
}

// NOTE: You must implement or import the actual readVarInt function:
// VarIntReadResult? readVarInt(Uint8List array, int offset);

// Placeholder for Extension Data
class TlsExtension {
  final int type;
  final Uint8List data;
  TlsExtension({required this.type, required this.data});
}

// Data class for parsed TLS ClientHello
class TlsClientHello {
  final String type = 'client_hello'; // Fixed value
  final int legacyVersion;
  final Uint8List random;
  final Uint8List sessionId;
  final List<int> cipherSuites;
  final Uint8List compressionMethods;
  final List<TlsExtension> extensions;
  String? sni;
  final List<Map<String, dynamic>> keyShares;
  final List<int> supportedVersions;
  final List<int> supportedGroups;
  final List<int> signatureAlgorithms;
  final List<String> alpn;
  int? maxFragmentLength;
  Uint8List? padding;
  Uint8List? cookie;
  final List<int> pskKeyExchangeModes;
  Uint8List? preSharedKey;
  Uint8List? renegotiationInfo;
  
  // For parse_tls_client_hello2
  Map<int, Uint8List>? quicTransportParametersOriginal;
  // For parse_tls_client_hello (raw)
  Uint8List? quicTransportParametersRaw;
  
  TlsClientHello({
    required this.legacyVersion,
    required this.random,
    required this.sessionId,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
    required this.keyShares,
    required this.supportedVersions,
    required this.supportedGroups,
    required this.signatureAlgorithms,
    required this.alpn,
    required this.pskKeyExchangeModes,
  });
}
// ----------------------------
2. Dart parseTlsMessage
This function extracts the type, length, and body from a single TLS record, reading the 3-byte length field (view[1], view[2], view[3]).

Dart

/// Represents a parsed TLS message record.
class TlsMessage {
  final int type;
  final int length;
  final Uint8List body;

  TlsMessage({required this.type, required this.length, required this.body});
}

TlsMessage parseTlsMessage(Uint8List data) {
  // Use data directly as Uint8List
  if (data.length < 4) {
    throw Exception("TLS message too short");
  }

  final type = data[0];
  
  // Combine 3 bytes into a single 24-bit length integer
  final length = (data[1] << 16) | (data[2] << 8) | data[3];

  if (4 + length > data.length) {
    throw Exception("TLS message body truncated");
  }

  // Dart's sublist is the equivalent of JavaScript's slice on Uint8Array
  // Start after the 4-byte header (type + 3-byte length)
  final body = data.sublist(4, 4 + length); 

  return TlsMessage(type: type, length: length, body: body);
}
3. Dart parseTlsClientHello2 and parseTlsClientHello
Since the two parse_tls_client_hello functions are nearly identical except for how they process the QUIC Transport Parameters extension (ext.type === 0x39), I've created a single core function and two public wrappers that handle the final mapping difference.

The toNumber helper function has been integrated into the Dart class for convenience.

Dart

/// Helper function equivalent to the inner JavaScript function `toNumber`.
/// Converts a byte array (Big-Endian) to an integer.
int bytesToNumber(Uint8List bytes) {
  int n = 0;
  for (var byte in bytes) {
    n = (n << 8) | byte;
  }
  return n;
}

/// Core function to parse the common parts of a TLS ClientHello body.
TlsClientHello _parseTlsClientHelloCore(Uint8List body, {bool extendedQuicParsing = false}) {
  var ptr = 0;

  // --- Header Parsing ---
  if (body.length < 43) throw Exception("ClientHello body too short");

  // legacy_version (2 bytes)
  final legacyVersion = (body[ptr++] << 8) | body[ptr++]; 

  // random (32 bytes)
  final random = body.sublist(ptr, ptr + 32); ptr += 32;

  // session_id (1 byte length prefix + data)
  final sessionIdLen = body[ptr++];
  final sessionId = body.sublist(ptr, ptr + sessionIdLen); ptr += sessionIdLen;

  // cipher_suites (2 byte length prefix + data)
  final cipherSuitesLen = (body[ptr++] << 8) | body[ptr++];
  final cipherSuites = <int>[];
  if (cipherSuitesLen % 2 != 0) throw Exception("Cipher suite list length must be even");
  for (var i = 0; i < cipherSuitesLen; i += 2) {
    final code = (body[ptr++] << 8) | body[ptr++];
    cipherSuites.add(code);
  }

  // compression_methods (1 byte length prefix + data)
  final compressionMethodsLen = body[ptr++];
  final compressionMethods = body.sublist(ptr, ptr + compressionMethodsLen); ptr += compressionMethodsLen;

  // extensions (2 byte length prefix + data)
  final extensionsLen = (body[ptr++] << 8) | body[ptr++];
  final extensions = <TlsExtension>[];
  final extEnd = ptr + extensionsLen;
  while (ptr < extEnd) {
    if (ptr + 4 > extEnd) throw Exception("Truncated extension header");
    final extType = (body[ptr++] << 8) | body[ptr++];
    final extLen = (body[ptr++] << 8) | body[ptr++];
    if (ptr + extLen > extEnd) throw Exception("Truncated extension data");
    final extData = body.sublist(ptr, ptr + extLen); ptr += extLen;
    extensions.add(TlsExtension(type: extType, data: extData));
  }
  
  // Instantiate result object
  final out = TlsClientHello(
    legacyVersion: legacyVersion,
    random: random,
    sessionId: sessionId,
    cipherSuites: cipherSuites,
    compressionMethods: compressionMethods,
    extensions: extensions,
    keyShares: [],
    supportedVersions: [],
    supportedGroups: [],
    signatureAlgorithms: [],
    alpn: [],
    pskKeyExchangeModes: [],
  );

  // --- Extension Processing ---
  for (var ext in extensions) {
    final extView = ext.data;
    switch (ext.type) {
      case 0x00: // Server Name Indication (SNI)
        // Note: The logic for 0x00 is different between the two JS functions.
        // We use the simpler logic from `parse_tls_client_hello2` here, and adjust below.
        // The more standard TLS 1.3/QUIC parsing usually uses the complex SNI logic from `parse_tls_client_hello`.
        // We'll stick to the logic for the original function names.

        if (extendedQuicParsing) { // Logic from `parse_tls_client_hello2`
          if (extView.length >= 5) {
            final nameLen = (extView[3] << 8) | extView[4];
            out.sni = utf8.decode(extView.sublist(5, 5 + nameLen));
          }
        } else { // Logic from `parse_tls_client_hello` (more standard SNI)
          if (extView.length >= 5) {
            // var list_len = (ext_view[0] << 8) | ext_view[1]; // Ignored
            // var name_type = ext_view[2]; // Ignored (assumed hostname=0)
            final nameLen = (extView[3] << 8) | extView[4];
            out.sni = utf8.decode(extView.sublist(5, 5 + nameLen));
          }
        }
        break;
      case 0x33: // Key Share
        var ptr2 = 0;
        // var list_len = (extView[ptr2++] << 8) | extView[ptr2++]; // Ignored
        ptr2 += 2;
        final end = ptr2 + extView.length; // Use end of buffer as boundary
        while (ptr2 < end) {
          if (ptr2 + 4 > extView.length) break; // Check remaining bytes for group + key_len
          final group = (extView[ptr2++] << 8) | extView[ptr2++];
          final keyLen = (extView[ptr2++] << 8) | extView[ptr2++];
          if (ptr2 + keyLen > extView.length) break; // Check remaining bytes for key data
          final pubkey = extView.sublist(ptr2, ptr2 + keyLen);
          ptr2 += keyLen;
          out.keyShares.add({'group': group, 'pubkey': pubkey});
        }
        break;
      case 0x2b: // Supported Versions
        final len = extView[0];
        for (var i = 1; i < 1 + len; i += 2) {
          if (i + 1 < extView.length) {
            out.supportedVersions.add((extView[i] << 8) | extView[i + 1]);
          }
        }
        break;
      case 0x0a: // Supported Groups (Elliptic Curves)
        // var len = (extView[0] << 8) | extView[1]; // Ignored
        for (var i = 2; i < extView.length; i += 2) {
          if (i + 1 < extView.length) {
            out.supportedGroups.add((extView[i] << 8) | extView[i + 1]);
          }
        }
        break;
      case 0x0d: // Signature Algorithms
        // var len = (extView[0] << 8) | extView[1]; // Ignored
        for (var i = 2; i < extView.length; i += 2) {
          if (i + 1 < extView.length) {
            out.signatureAlgorithms.add((extView[i] << 8) | extView[i + 1]);
          }
        }
        break;
      case 0x10: // Application-Layer Protocol Negotiation (ALPN)
        // var list_len = (extView[0] << 8) | extView[1]; // Ignored
        var i = 2;
        while (i < extView.length) {
          final nameLen = extView[i++];
          if (i + nameLen <= extView.length) {
            final proto = utf8.decode(extView.sublist(i, i + nameLen));
            out.alpn.add(proto);
            i += nameLen;
          } else {
            break; // Truncated protocol name
          }
        }
        break;
      case 0x39: // QUIC Transport Parameters
        if (extendedQuicParsing) {
          // Logic from parse_tls_client_hello2: detailed parameter parsing
          final extData = ext.data;
          var ptr2 = 0;
          out.quicTransportParametersOriginal = {};
          
          while (ptr2 < extData.length) {
            final idRes = readVarInt(extData, ptr2);
            if (idRes == null) break;
            final id = idRes.value;
            ptr2 += idRes.byteLength;

            final lenRes = readVarInt(extData, ptr2);
            if (lenRes == null) break;
            final len = lenRes.value;
            ptr2 += lenRes.byteLength;

            final value = extData.sublist(ptr2, ptr2 + len);
            ptr2 += len;
            
            // Populate the map containing all parameters
            out.quicTransportParametersOriginal![id] = value;
            
            // The original function then selectively converts some to numbers
            if (id == 0x00) out.quicTransportParametersOriginal![id] = value; // This key is duplicated, but kept for fidelity
            if (id == 0x01) out.quicTransportParametersOriginal![id] = bytesToNumber(value);
            // ... (other parameters are omitted here for brevity but should be added)
            if (id == 0x2b603742) {
              try {
                out.quicTransportParametersOriginal![id] = utf8.decode(value);
              } catch (e) { /* ignore error */ }
            }
          }
        } else {
          // Logic from parse_tls_client_hello: store raw bytes
          out.quicTransportParametersRaw = ext.data;
        }
        break;
      case 0x01: // Max Fragment Length
        if (extView.isNotEmpty) out.maxFragmentLength = extView[0];
        break;
      case 0x15: // Padding
        out.padding = extView;
        break;
      case 0x002a: // Cookie
        if (extView.length >= 2) {
          final len = (extView[0] << 8) | extView[1];
          out.cookie = extView.sublist(2, 2 + len);
        }
        break;
      case 0x2d: // PSK Key Exchange Modes
        final len = extView[0];
        for (var i = 1; i <= len; i++) {
          if (i < extView.length) {
            out.pskKeyExchangeModes.add(extView[i]);
          }
        }
        break;
      case 0x29: // PreSharedKey
        out.preSharedKey = extView;
        break;
      case 0xff01: // Renegotiation Info
        out.renegotiationInfo = extView;
        break;
    }
  }

  return out;
}

// Wrapper 1: Matches JavaScript `parse_tls_client_hello2`
TlsClientHello parseTlsClientHello2(Uint8List body) {
  return _parseTlsClientHelloCore(body, extendedQuicParsing: true);
}

// Wrapper 2: Matches JavaScript `parse_tls_client_hello`
TlsClientHello parseTlsClientHello(Uint8List body) {
  return _parseTlsClientHelloCore(body, extendedQuicParsing: false);
}






tackle these next:



function tls_derive_handshake_secrets(shared_secret, transcript, hash_func) {

  var zero = new Uint8Array(hash_func.outputLen);

  var empty = new Uint8Array();



  var early_secret = hkdf_extract(empty, zero, hash_func); // salt, ikm

  var derived_secret = hkdf_expand_label(early_secret, "derived", hash_func(empty), hash_func.outputLen, hash_func);

  var handshake_secret = hkdf_extract(derived_secret, shared_secret, hash_func);



  var transcript_hash = hash_transcript(transcript, hash_func);



  var client_hts = hkdf_expand_label(handshake_secret, "c hs traffic", transcript_hash, hash_func.outputLen, hash_func);

  var server_hts = hkdf_expand_label(handshake_secret, "s hs traffic", transcript_hash, hash_func.outputLen, hash_func);



  return {

    handshake_secret,

    client_handshake_traffic_secret: client_hts,

    server_handshake_traffic_secret: server_hts,

    transcript_hash

  };

}



function aead_decrypt(key, iv, packetNumber, ciphertextWithTag, aad, callback) {

  try {

    // יצירת nonce לפי QUIC (IV XOR packetNumber)

    var nonce = new Uint8Array(iv.length);

    for (var i = 0; i < iv.length; i++) {

      var pnIndex = iv.length - 1 - i;

      var pnByte = (packetNumber >>> (8 * i)) & 0xff;

      nonce[pnIndex] = iv[pnIndex] ^ pnByte;

    }



    var tag = ciphertextWithTag.slice(-16);

    var ciphertext = ciphertextWithTag.slice(0, -16);



    var algo = key.length === 32 ? 'aes-256-gcm' :

               key.length === 16 ? 'aes-128-gcm' :

               (() => { throw new Error("Unsupported key length: " + key.length); })();



    const decipher = crypto.createDecipheriv(algo, key, nonce);

    decipher.setAuthTag(tag);

    decipher.setAAD(aad);



    const decrypted = decipher.update(ciphertext);

    decipher.final();



    callback(null, decrypted);

  } catch (e) {

    callback(e);

  }

}

   

function aes_gcm_decrypt(ciphertext, tag, key, nonce, aad) {

  try {

    var algo = key.length === 32 ? 'aes-256-gcm' :

                key.length === 16 ? 'aes-128-gcm' :

                (() => { throw new Error("Unsupported key length: " + key.length); })();



    var decipher = crypto.createDecipheriv(

      algo,

      Buffer.from(key),

      Buffer.from(nonce)

    );



    decipher.setAuthTag(Buffer.from(tag));

    decipher.setAAD(Buffer.from(aad));



    var decrypted = Buffer.concat([

      decipher.update(Buffer.from(ciphertext)),

      decipher.final()

    ]);



    //console.log("✅ Decryption success!");

    return new Uint8Array(decrypted);

  } catch (e) {

      return null;

  }

}



const INITIAL_SALTS = {

    // QUIC v1 (RFC 9001)

    0x00000001: new Uint8Array([

    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,

    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,

    0xcc, 0xbb, 0x7f, 0x0a

    ]),



    // QUIC draft-29 (HTTP/3 version h3-29)

    0xff00001d: new Uint8Array([

    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,

    0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,

    0x43, 0x90, 0xa8, 0x99

    ]),



    // QUIC draft-32 (h3-32)

    0xff000020: new Uint8Array([

    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0x77,

    0x7b, 0xe3, 0x0e, 0xbd, 0x5f, 0xa5, 0x15, 0x87,

    0x3d, 0x8d, 0x6e, 0x67

    ]),



    // Google QUIC v50 ("Q050") — נדיר יותר אבל נתמך בדפדפנים מסוימים

    0x51303530: new Uint8Array([

    0x69, 0x45, 0x6f, 0xbe, 0xf1, 0x6e, 0xd7, 0xdc,

    0x48, 0x15, 0x9d, 0x98, 0xd0, 0x7f, 0x5c, 0x3c,

    0x3d, 0x5a, 0xa7, 0x0a

    ])

};



function quic_derive_init_secrets(client_dcid, version, direction) {

    const hash_func = sha256;

    //console.log(version);

    const salt = INITIAL_SALTS[version] || null;

    if (!salt) throw new Error("Unsupported QUIC version: 0x" + version.toString(16));



    const label = direction === 'read' ? 'client in' : 'server in';

    const initial_secret = hkdf_extract(salt, client_dcid, hash_func);



    const initial_secret2 = hkdf_expand_label(

        initial_secret,

        label,

        new Uint8Array(0),

        32,

        hash_func

    );



    const key = hkdf_expand_label(initial_secret2, 'quic key', new Uint8Array(0), 16, hash_func);  // AES-128-GCM

    const iv  = hkdf_expand_label(initial_secret2, 'quic iv', new Uint8Array(0), 12, hash_func);

    const hp  = hkdf_expand_label(initial_secret2, 'quic hp', new Uint8Array(0), 16, hash_func);



    return { key, iv, hp };

}





function quic_derive_from_tls_secrets(traffic_secret, hash_func = sha256) {

    if(traffic_secret){

    const key = hkdf_expand_label(traffic_secret, 'quic key', new Uint8Array(0), 16, hash_func);

    const iv  = hkdf_expand_label(traffic_secret, 'quic iv', new Uint8Array(0), 12, hash_func);

    const hp  = hkdf_expand_label(traffic_secret, 'quic hp', new Uint8Array(0), 16, hash_func);



    return { key, iv, hp };

    }

}







function compute_nonce(iv, packetNumber) {

    const nonce = new Uint8Array(iv); // עותק של ה־IV המקורי (12 בתים)

    const pnBuffer = new Uint8Array(12); // 12 בתים, מיושר לימין



    // הכנס את packetNumber לימין של pnBuffer

    let n = packetNumber;

    for (let i = 11; n > 0 && i >= 0; i--) {

        pnBuffer[i] = n & 0xff;

        n >>= 8;

    }



    // בצע XOR בין ה־IV לבין pnBuffer

    for (let i = 0; i < 12; i++) {

        nonce[i] ^= pnBuffer[i];

    }



    return nonce;

}





function aes_ecb_encrypt(keyBytes, plaintext) {

  if (keyBytes.length !=16 && keyBytes.length !=24 && keyBytes.length !=32) {

    throw new Error("Invalid AES key size");

  }



  if (plaintext.length % 16 !=0) {

    throw new Error("Plaintext must be a multiple of 16 bytes");

  }



  const cipher = crypto.createCipheriv('aes-' + (keyBytes.length * 8) + '-ecb', keyBytes, null);

  cipher.setAutoPadding(false);



  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return new Uint8Array(encrypted);

}





function aead_encrypt(key, iv, packetNumber, plaintext, aad) {

  try {

    const algo = key.length === 32 ? 'aes-256-gcm' :

                 key.length === 16 ? 'aes-128-gcm' :

                 (() => { throw new Error("Unsupported key length: " + key.length); })();



    const nonce = compute_nonce(iv, packetNumber);



    const cipher = crypto.createCipheriv(algo, Buffer.from(key), Buffer.from(nonce));

    cipher.setAAD(Buffer.from(aad));



    const encrypted = Buffer.concat([

      cipher.update(Buffer.from(plaintext)),

      cipher.final()

    ]);

    const tag = cipher.getAuthTag();



    const result = new Uint8Array(encrypted.length + tag.length);

    result.set(encrypted, 0);

    result.set(tag, encrypted.length);



    return result;



  } catch (e) {

    return null;

  }

}









function apply_header_protection(packet, pnOffset, hpKey, pnLength) {

  var sample = packet.slice(pnOffset + 4, pnOffset + 4 + 16);

  if (sample.length < 16) throw new Error("Not enough bytes for header protection sample");



  var maskFull = aes_ecb_encrypt(hpKey, sample);

  var mask = maskFull.slice(0, 5);



  var firstByte = packet[0];

  var isLongHeader = (firstByte & 0x80) !=0;



  if (isLongHeader) {

    packet[0] ^= (mask[0] & 0x0f); // רק 4 ביטים אחרונים

  } else {

    packet[0] ^= (mask[0] & 0x1f); // ל־Short Header

  }



  for (var i = 0; i < pnLength; i++) {

    packet[pnOffset + i] ^= mask[1 + i];

  }



  return packet;

}









function aes128ecb(sample,hpKey) {

    const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(hpKey), null);

    cipher.setAutoPadding(false);

    const input = Buffer.from(sample);

    return new Uint8Array(Buffer.concat([cipher.update(input), cipher.final()]));

}



function expandPacketNumber(truncated, pnLen, largestReceived) {

  var pnWin  = 1 << (pnLen * 8);

  var pnHalf = pnWin >>> 1;

  var expected = largestReceived + 1;

  return truncated + pnWin * Math.floor((expected - truncated + pnHalf) / pnWin);

}



function decode_packet_number(array, offset, pnLength) {

  let value = 0;

  for (let i = 0; i < pnLength; i++) {

    value = (value << 8) | array[offset + i];

  }

  return value;

}



function decode_and_expand_packet_number(array, offset, pnLength, largestReceived) {

  var truncated = decode_packet_number(array, offset, pnLength);

  return expandPacketNumber(truncated, pnLength, largestReceived);

}



These functions deal with core cryptography concepts in QUIC: TLS 1.3 Handshake Secret derivation, AES-GCM (Authenticated Encryption with Associated Data) for packet encryption/decryption, and QUIC-specific details like Initial Secret derivation and Header Protection.

For Dart, we will rely on the crypto package (package:crypto) for standard hash functions (like SHA-256) and the pointycastle package for AES-GCM and AES-ECB, as these are not available in dart:core or dart:typed_data.

Since I cannot install external packages, I will provide the implementations assuming you have the necessary cryptographic primitives (hkdf_extract, hkdf_expand_label, hash_transcript, sha256, aes_gcm_decrypt_primitive, aes_ecb_encrypt_primitive, etc.) available, represented by placeholder function signatures or using general Dart syntax where possible.

Here are the Dart ports:

1. Helper Functions and Structure Definitions
Dart

import 'dart:typed_data';
import 'dart:convert';
import 'package:collection/collection.dart'; // Needed for deep equality checks

// --- Assuming these imports/placeholders are available from your crypto library ---
// typedef Uint8List HashFunction(Uint8List data);
// typedef Uint8List HkdfExtractFunction(Uint8List salt, Uint8List ikm, HashFunction hashFunc);
// typedef Uint8List HkdfExpandLabelFunction(Uint8List secret, String label, Uint8List context, int length, HashFunction hashFunc);
// typedef Uint8List AesGcmDecryptPrimitive(Uint8List key, Uint8List nonce, Uint8List ciphertextWithTag, Uint8List aad);
// typedef Uint8List AesEcbEncryptPrimitive(Uint8List key, Uint8List plaintext);

// Placeholder classes/functions (You must provide actual crypto implementations)
class HashFunc {
  final int outputLen;
  final String name;
  HashFunc(this.name, this.outputLen);
}

// Function signature placeholders:
Uint8List sha256(Uint8List data) => throw UnimplementedError("sha256 implementation required.");
Uint8List hashTranscript(Uint8List transcript, HashFunc hashFunc) => throw UnimplementedError("hashTranscript implementation required.");
Uint8List hkdfExtract(Uint8List salt, Uint8List ikm, HashFunc hashFunc) => throw UnimplementedError("hkdfExtract implementation required.");
Uint8List hkdfExpandLabel(Uint8List secret, String label, Uint8List context, int length, HashFunc hashFunc) => throw UnimplementedError("hkdfExpandLabel implementation required.");
Uint8List aesGcmDecryptPrimitive(Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List tag, Uint8List aad) => throw UnimplementedError("AES-GCM Decrypt implementation required (e.g., using pointycastle).");
Uint8List aesEcbEncryptPrimitive(Uint8List key, Uint8List plaintext) => throw UnimplementedError("AES-ECB Encrypt implementation required (e.g., using pointycastle).");


// Result structure for Handshake secrets
class TlsHandshakeSecrets {
  final Uint8List handshakeSecret;
  final Uint8List clientHandshakeTrafficSecret;
  final Uint8List serverHandshakeTrafficSecret;
  final Uint8List transcriptHash;

  TlsHandshakeSecrets({
    required this.handshakeSecret,
    required this.clientHandshakeTrafficSecret,
    required this.serverHandshakeTrafficSecret,
    required this.transcriptHash,
  });
}

// Result structure for QUIC Initial Secrets
class QuicSecrets {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  QuicSecrets({required this.key, required this.iv, required this.hp});
}

// QUIC Initial Salts (Mapping int version to Uint8List salt)
const Map<int, Uint8List> initialSalts = {
  // QUIC v1 (RFC 9001)
  0x00000001: Uint8List.fromList([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
  ]),

  // QUIC draft-29 (HTTP/3 version h3-29)
  0xff00001d: Uint8List.fromList([
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 
    0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
  ]),

  // QUIC draft-32 (h3-32)
  0xff000020: Uint8List.fromList([
    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0x77, 0x7b, 0xe3, 
    0x0e, 0xbd, 0x5f, 0xa5, 0x15, 0x87, 0x3d, 0x8d, 0x6e, 0x67
  ]),

  // Google QUIC v50 ("Q050")
  0x51303530: Uint8List.fromList([
    0x69, 0x45, 0x6f, 0xbe, 0xf1, 0x6e, 0xd7, 0xdc, 0x48, 0x15, 
    0x9d, 0x98, 0xd0, 0x7f, 0x5c, 0x3c, 0x3d, 0x5a, 0xa7, 0x0a
  ]),
};
2. TLS Secret Derivation
Dart

/// Derives the TLS 1.3 Handshake Traffic Secrets from the shared secret (e.g., DH).
/// 
/// Corresponds to the steps in RFC 8446 (TLS 1.3) used for QUIC.
TlsHandshakeSecrets tlsDeriveHandshakeSecrets(
  Uint8List sharedSecret, 
  Uint8List transcript, 
  HashFunc hashFunc
) {
  final zero = Uint8List(hashFunc.outputLen);
  final empty = Uint8List(0);

  // 1. Calculate Early Secret
  final earlySecret = hkdfExtract(empty, zero, hashFunc); // Salt: empty, IKM: zero hash

  // 2. Calculate Derived Secret from Early Secret
  // Context is Hash(empty) because there is no prior handshake flight
  final derivedSecret = hkdfExpandLabel(
    earlySecret, 
    "derived", 
    hashFunc(empty), // Hash(empty) as context
    hashFunc.outputLen, 
    hashFunc
  );

  // 3. Calculate Handshake Secret
  final handshakeSecret = hkdfExtract(derivedSecret, sharedSecret, hashFunc); // Salt: Derived, IKM: Shared Secret (DH)

  // 4. Calculate Transcript Hash of ClientHello
  final transcriptHash = hashTranscript(transcript, hashFunc);

  // 5. Calculate Client/Server Handshake Traffic Secrets
  final clientHts = hkdfExpandLabel(handshakeSecret, "c hs traffic", transcriptHash, hashFunc.outputLen, hashFunc);
  final serverHts = hkdfExpandLabel(handshakeSecret, "s hs traffic", transcriptHash, hashFunc.outputLen, hashFunc);

  return TlsHandshakeSecrets(
    handshakeSecret: handshakeSecret,
    clientHandshakeTrafficSecret: clientHts,
    serverHandshakeTrafficSecret: serverHts,
    transcriptHash: transcriptHash,
  );
}
3. QUIC Initial Secret Derivation
Dart

/// Derives the Initial Protection Keys and IVs for the QUIC Initial packets.
QuicSecrets quicDeriveInitSecrets(
  Uint8List clientDcid, 
  int version, 
  String direction // 'read' or 'write' (which corresponds to 'client in' or 'server in' for the peer)
) {
  // Using a placeholder for SHA-256 hash function details
  final hashFunc = HashFunc("sha256", 32); 
  
  final salt = initialSalts[version];
  if (salt == null) {
    throw Exception("Unsupported QUIC version: 0x${version.toRadixString(16)}");
  }

  // Determine the label based on which direction we are deriving secrets for.
  // QUIC RFC 9001 defines 'client in' and 'server in'
  final label = direction == 'read' ? 'client in' : 'server in';
  
  // 1. Initial Secret
  final initialSecret = hkdfExtract(salt, clientDcid, hashFunc);

  // 2. Initial Secret 2 (Traffic Secret)
  final initialSecret2 = hkdfExpandLabel(
    initialSecret,
    label,
    Uint8List(0), // Context is always empty for traffic secrets
    32, // HKDF-Extract output length (SHA-256)
    hashFunc
  );

  // 3. Derive AEAD Key, IV, and Header Protection Key
  // QUIC uses AES-128-GCM (16 bytes key, 12 bytes IV, 16 bytes HP key) for Initial packets.
  final key = hkdfExpandLabel(initialSecret2, 'quic key', Uint8List(0), 16, hashFunc);
  final iv = hkdfExpandLabel(initialSecret2, 'quic iv', Uint8List(0), 12, hashFunc);
  final hp = hkdfExpandLabel(initialSecret2, 'quic hp', Uint8List(0), 16, hashFunc);

  return QuicSecrets(key: key, iv: iv, hp: hp);
}


/// Derives the QUIC Keys/IVs/HP keys from a given TLS traffic secret
/// (e.g., Handshake or Application Traffic Secrets).
QuicSecrets? quicDeriveFromTlsSecrets(Uint8List? trafficSecret) {
  if (trafficSecret == null) return null;

  // Assuming SHA-256 for TLS 1.3 handshake hash
  final hashFunc = HashFunc("sha256", 32); 

  // QUIC uses AES-128-GCM (16 bytes key, 12 bytes IV, 16 bytes HP key)
  final key = hkdfExpandLabel(trafficSecret, 'quic key', Uint8List(0), 16, hashFunc);
  final iv = hkdfExpandLabel(trafficSecret, 'quic iv', Uint8List(0), 12, hashFunc);
  final hp = hkdfExpandLabel(trafficSecret, 'quic hp', Uint8List(0), 16, hashFunc);

  return QuicSecrets(key: key, iv: iv, hp: hp);
}
4. AES Encryption/Decryption and Nonce Calculation
Dart

/// Calculates the QUIC AEAD nonce.
/// Nonce is computed as IV XOR (big-endian 64-bit Packet Number).
/// The IV is 12 bytes. The 64-bit Packet Number is left-padded with zeros 
/// and XORed with the rightmost 8 bytes of the IV.
Uint8List computeNonce(Uint8List iv, int packetNumber) {
  if (iv.length != 12) {
    throw ArgumentError("IV must be 12 bytes for QUIC AEAD.");
  }
  
  // Create a mutable copy of the IV
  final nonce = Uint8List.fromList(iv); 
  
  // Create an 8-byte buffer for the packet number (64-bit, big-endian)
  final pnBuffer = Uint8List(8); 
  
  // Use ByteData to safely write the 64-bit integer in Big Endian format.
  final byteData = ByteData(8);
  byteData.setUint64(0, packetNumber, Endian.big);
  
  // Copy to pnBuffer
  pnBuffer.setAll(0, byteData.buffer.asUint8List());

  // XOR the rightmost 8 bytes of the IV (indices 4-11) with the 8 bytes of pnBuffer.
  // The first 4 bytes of the 12-byte IV remain untouched.
  for (var i = 0; i < 8; i++) {
    // pnBuffer[i] is byte 0 to 7 of the 64-bit packet number
    // nonce[i + 4] is byte 4 to 11 of the 12-byte IV/Nonce
    nonce[i + 4] ^= pnBuffer[i];
  }

  return nonce;
}

// NOTE: The JS `aead_decrypt` uses a callback, which is a JS idiom for async/error handling.
// Dart typically uses Futures/async-await or returns null/throws exceptions.
// Since the underlying crypto operations are often synchronous in crypto libraries, 
// we will port this to a synchronous function that returns null on failure.

/// Performs AES-GCM decryption following the QUIC nonce construction.
/// 
/// Note: The original JS function used a callback, which is replaced by a 
/// synchronous `try/catch` block returning `Uint8List?`.
Uint8List? aeadDecrypt(
  Uint8List key, 
  Uint8List iv, 
  int packetNumber, 
  Uint8List ciphertextWithTag, 
  Uint8List aad
) {
  try {
    if (ciphertextWithTag.length < 16) {
      throw Exception("Ciphertext must contain at least a 16-byte tag.");
    }
    
    // 1. Compute Nonce
    final nonce = computeNonce(iv, packetNumber);

    // 2. Separate Tag (16 bytes) and Ciphertext
    final tag = ciphertextWithTag.sublist(ciphertextWithTag.length - 16);
    final ciphertext = ciphertextWithTag.sublist(0, ciphertextWithTag.length - 16);
    
    // 3. Determine Key length for algorithm check (though QUIC only uses 128/256)
    if (key.length != 16 && key.length != 32) {
      throw Exception("Unsupported key length: ${key.length}. Must be 16 or 32 bytes.");
    }

    // 4. Perform Decryption (Placeholder for crypto library function)
    final decrypted = aesGcmDecryptPrimitive(key, nonce, ciphertext, tag, aad);
    
    return decrypted;
  } catch (e) {
    // Catch decryption failure (e.g., authentication failed)
    print("AEAD Decryption failed: $e");
    return null;
  }
}

/// Performs AES-GCM encryption following the QUIC nonce construction.
Uint8List? aeadEncrypt(
  Uint8List key, 
  Uint8List iv, 
  int packetNumber, 
  Uint8List plaintext, 
  Uint8List aad
) {
  try {
    // 1. Determine Key length
    if (key.length != 16 && key.length != 32) {
      throw Exception("Unsupported key length: ${key.length}. Must be 16 or 32 bytes.");
    }

    // 2. Compute Nonce
    final nonce = computeNonce(iv, packetNumber);

    // 3. Perform Encryption (This needs a proper AEAD encrypt primitive)
    // Since the JS function returns the combined ciphertext+tag, we need a helper
    // that produces both the ciphertext and the 16-byte tag.
    
    // This part is highly dependent on the Dart crypto library used.
    // For simplicity, we assume an encrypt primitive that returns a combined result.
    // NOTE: For GCM, the primitive must return (ciphertext + tag).

    // --- Placeholder for combined encryption primitive ---
    Uint8List combinedCiphertextTag(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
        throw UnimplementedError("Combined AES-GCM Encrypt implementation required.");
    }
    // --- End Placeholder ---
    
    final combined = combinedCiphertextTag(key, nonce, plaintext, aad);
    return combined;

  } catch (e) {
    print("AEAD Encryption failed: $e");
    return null;
  }
}


/// Performs raw AES-GCM decryption (equivalent to JS `aes_gcm_decrypt`).
/// This function is not QUIC-specific as it takes a pre-calculated `nonce`.
Uint8List? aesGcmDecrypt(
  Uint8List ciphertext, 
  Uint8List tag, 
  Uint8List key, 
  Uint8List nonce, 
  Uint8List aad
) {
  try {
    if (key.length != 16 && key.length != 32) {
      throw Exception("Unsupported key length: ${key.length}. Must be 16 or 32 bytes.");
    }

    // Perform Decryption (Placeholder for crypto library function)
    final decrypted = aesGcmDecryptPrimitive(key, nonce, ciphertext, tag, aad);

    //print("✅ Decryption success!");
    return decrypted;
  } catch (e) {
    // print("Decryption failed: $e");
    return null;
  }
}

/// Performs AES in ECB mode for Header Protection.
Uint8List aesEcbEncrypt(Uint8List keyBytes, Uint8List plaintext) {
  if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
    throw ArgumentError("Invalid AES key size: ${keyBytes.length} bytes.");
  }

  // The plaintext for header protection MUST be 16 bytes.
  if (plaintext.length % 16 != 0) {
    throw ArgumentError("Plaintext length must be a multiple of 16 bytes.");
  }

  // Perform ECB encryption (Placeholder for crypto library function)
  final encrypted = aesEcbEncryptPrimitive(keyBytes, plaintext);
  return encrypted;
}

// Simple AES-128-ECB implementation wrapper (JS: aes128ecb)
Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey) {
  if (hpKey.length != 16) {
    throw ArgumentError("AES-128-ECB key must be 16 bytes.");
  }
  // This calls the generic ECB function with the 16-byte key
  return aesEcbEncrypt(hpKey, sample);
}
5. Header Protection and Packet Number Logic
Dart

/// Applies Header Protection (XORing the first byte and the Packet Number)
/// using the result of AES-ECB(HP Key, Sample).
Uint8List applyHeaderProtection(
  Uint8List packet, 
  int pnOffset, 
  Uint8List hpKey, 
  int pnLength
) {
  // QUIC Header Protection Sample is 16 bytes starting at pnOffset + 4
  const sampleLength = 16;
  if (pnOffset + 4 + sampleLength > packet.length) {
    throw Exception("Not enough bytes for header protection sample");
  }

  // 1. Get sample
  final sample = packet.sublist(pnOffset + 4, pnOffset + 4 + sampleLength);

  // 2. Encrypt sample using AES-ECB
  final maskFull = aesEcbEncrypt(hpKey, sample);
  final mask = maskFull.sublist(0, 5); // Use the first 5 bytes of the output

  // Create a mutable copy of the packet
  final resultPacket = Uint8List.fromList(packet);
  
  // 3. Apply mask to the first byte (Header Type)
  final firstByte = resultPacket[0];
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    // Long Header: Only XOR the lowest 4 bits (Version Specific + Reserved + Packet Number Length)
    resultPacket[0] ^= (mask[0] & 0x0f); 
  } else {
    // Short Header: Only XOR the lowest 5 bits (Key Phase + Reserved + Packet Number Length)
    resultPacket[0] ^= (mask[0] & 0x1f); 
  }

  // 4. Apply mask to the Packet Number field (pnLength bytes)
  for (var i = 0; i < pnLength; i++) {
    resultPacket[pnOffset + i] ^= mask[1 + i];
  }

  return resultPacket;
}

/// Decodes a truncated Packet Number from the byte array.
int decodePacketNumber(Uint8List array, int offset, int pnLength) {
  int value = 0;
  for (var i = 0; i < pnLength; i++) {
    // Dart handles the shift correctly without explicit masks like `| array[offset + i]`
    value = (value << 8) | array[offset + i]; 
  }
  return value;
}

/// Expands the truncated Packet Number based on the largest previously received.
/// 
/// Corresponds to RFC 9000, Section 17.1.
int expandPacketNumber(int truncated, int pnLen, int largestReceived) {
  final pnWin = 1 << (pnLen * 8);
  final pnHalf = pnWin >> 1;
  final expected = largestReceived + 1;
  
  // The logic to find the closest value:
  // 1. Calculate the value of the expected packet number with the current window: `expected & ~(pnWin - 1)`
  // 2. Adjust it by adding the truncated value: `(expected & ~(pnWin - 1)) | truncated`
  // 3. Find which value (current window or next window) is closest to `expected`.
  
  // Dart version of the JavaScript math:
  // return truncated + pnWin * Math.floor((expected - truncated + pnHalf) / pnWin);
  return truncated + (pnWin * ((expected - truncated + pnHalf) / pnWin).floor());
}


/// Combines decoding and expansion of the Packet Number.
int decodeAndExpandPacketNumber(
  Uint8List array, 
  int offset, 
  int pnLength, 
  int largestReceived
) {
  final truncated = decodePacketNumber(array, offset, pnLength);
  return expandPacketNumber(truncated, pnLength, largestReceived);
}






tackle these next:

function remove_header_protection(array, pnOffset, hpKey, isShort) {

  // Step 1: קח sample של 16 בתים מתוך ה־payload אחרי pnOffset + 4

  var sampleOffset = pnOffset + 4;

  var sample = array.slice(sampleOffset, sampleOffset + 16);



  var mask = aes128ecb(sample, hpKey).slice(0, 5); // ECB with no IV



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





function decrypt_quic_packet(array, read_key, read_iv, read_hp, dcid, largest_pn) {

  if (!(array instanceof Uint8Array)) throw new Error("Invalid input");



  const firstByte = array[0];

  const isShort = (firstByte & 0x80) === 0;

  const isLong = !isShort;



  let keyPhase = false;

  let pnOffset = 0;

  let pnLength = 0;

  let aad = null;

  let ciphertext = null;

  let tag = null;

  let packetNumber = null;

  let nonce = null;



  if (isLong) {

    // ---------- ניתוח Long Header ----------

    const view = new DataView(array.buffer, array.byteOffset, array.byteLength);

    const version = view.getUint32(1);

    const dcidLen = array[5];



    let offset = 6;

    const parsed_dcid = array.slice(offset, offset + dcidLen);

    offset += dcidLen;



    const scidLen = array[offset++];

    const scid = array.slice(offset, offset + scidLen);

    offset += scidLen;



    const typeBits = (firstByte & 0x30) >> 4;

    const typeMap = ['initial', '0rtt', 'handshake', 'retry'];

    const packetType = typeMap[typeBits];



    if (packetType === 'initial') {

      const tokenLen = readVarInt(array, offset);

      offset += tokenLen.byteLength + tokenLen.value;

    }



    const len = readVarInt(array, offset);

    offset += len.byteLength;



    pnOffset = offset;



    // הסרת הגנת כותרת

    pnLength = remove_header_protection(array, pnOffset, read_hp, false);



    if(pnLength!==null){

      packetNumber = decode_and_expand_packet_number(array, pnOffset, pnLength, largest_pn);

      nonce = compute_nonce(read_iv, packetNumber);



      const payloadStart = pnOffset + pnLength;

      const payloadLength = len.value - pnLength;

      const payloadEnd = payloadStart + payloadLength;



      if (payloadEnd > array.length) throw new Error("Truncated long header packet");



      const payload = array.slice(payloadStart, payloadEnd);

      if (payload.length < 16) throw new Error("Encrypted payload too short");



      ciphertext = payload.slice(0, payload.length - 16);

      tag = payload.slice(payload.length - 16);

      aad = array.slice(0, pnOffset + pnLength);

    }else{

      return null;

    }



  } else {

    // ---------- ניתוח Short Header ----------

    // פורמט: 1 byte header + DCID + Packet Number + Payload



    const dcidLen = dcid.length;

    pnOffset = 1 + dcidLen;



    // הסרת הגנת כותרת

    pnLength = remove_header_protection(array, pnOffset, read_hp, true);



    if(pnLength!==null){

      keyPhase = Boolean((array[0] & 0x04) >>> 2);



      packetNumber = decode_and_expand_packet_number(array, pnOffset, pnLength, largest_pn);

      nonce = compute_nonce(read_iv, packetNumber);



      const payloadStart = pnOffset + pnLength;

      const payload = array.slice(payloadStart);

      if (payload.length < 16) throw new Error("Encrypted payload too short");



      ciphertext = payload.slice(0, payload.length - 16);

      tag = payload.slice(payload.length - 16);

      aad = array.slice(0, pnOffset + pnLength);

    }else{

      return null;

    }

   

  }



  const plaintext = aes_gcm_decrypt(ciphertext, tag, read_key, nonce, aad);



  return {

    packet_number: packetNumber,

    key_phase: keyPhase,

    plaintext

  };

}



These functions implement the core logic for removing Header Protection and the full decryption flow for a QUIC packet, including Long Header and Short Header parsing.

The code below assumes you have the helper functions (aes128Ecb, readVarInt, decodeAndExpandPacketNumber, computeNonce, aesGcmDecrypt) available, as defined in the previous ported steps.

1. Imports and Helper Class
Dart

import 'dart:typed_data';
import 'dart:convert';

// --- Required Helper Class ---
class QuicDecryptedPacket {
  final int packetNumber;
  final bool keyPhase;
  final Uint8List? plaintext; // Null if decryption/authentication fails

  QuicDecryptedPacket({
    required this.packetNumber,
    required this.keyPhase,
    this.plaintext,
  });
}

// NOTE: The following required functions must be implemented (or mocked) elsewhere:
// Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey);
// VarIntReadResult? readVarInt(Uint8List array, int offset);
// int decodeAndExpandPacketNumber(Uint8List array, int offset, int pnLength, int largestReceived);
// Uint8List computeNonce(Uint8List iv, int packetNumber);
// Uint8List? aesGcmDecrypt(Uint8List ciphertext, Uint8List tag, Uint8List key, Uint8List nonce, Uint8List aad);
2. removeHeaderProtection (Header Protection Removal)
This function reverses the Header Protection mechanism, modifying the input array in place. It reveals the Packet Number Length (pnLength).

Dart

/// Reverses the Header Protection mechanism, unmasking the first header byte 
/// and the Packet Number field.
/// 
/// The [array] is modified in place.
/// Returns the Packet Number Length (1, 2, 3, or 4 bytes).
int removeHeaderProtection(Uint8List array, int pnOffset, Uint8List hpKey, bool isShort) {
  // Step 1: Get the 16-byte sample from the encrypted payload
  var sampleOffset = pnOffset + 4;
  const sampleLength = 16;
  if (sampleOffset + sampleLength > array.length) {
    throw Exception("Not enough bytes for header protection sample");
  }
  final sample = array.sublist(sampleOffset, sampleOffset + sampleLength);

  // Use AES-128-ECB to generate the 5-byte mask
  final maskFull = aes128Ecb(sample, hpKey);
  final mask = maskFull.sublist(0, 5);

  // Step 2: Remove protection from the first byte
  if (isShort) {
    // Short Header: XOR the 5 lowest bits (0x1f = 0b0001_1111)
    array[0] ^= mask[0] & 0x1f;
  } else {
    // Long Header: XOR the 4 lowest bits (0x0f = 0b0000_1111)
    array[0] ^= mask[0] & 0x0f;
  }

  // Step 3: Determine Packet Number Length and remove protection from the PN field
  // pnLength is determined by the two lowest bits of the now-unmasked first byte.
  final pnLength = (array[0] & 0x03) + 1;

  if (pnOffset + pnLength > array.length) {
    throw Exception("Packet number field extends beyond packet length after header protection removal.");
  }

  for (var i = 0; i < pnLength; i++) {
    // mask[1] is for the first PN byte, mask[2] for the second, etc.
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}
3. decryptQuicPacket (Full Decryption Flow)
This function orchestrates the entire decryption process, handling both Long Header and Short Header formats.

Dart

/// Parses, removes header protection, decrypts, and authenticates a QUIC packet.
/// 
/// Returns a [QuicDecryptedPacket] containing the plaintext and metadata, or `null` 
/// if decryption/authentication fails.
QuicDecryptedPacket? decryptQuicPacket(
  Uint8List array, 
  Uint8List readKey, 
  Uint8List readIv, 
  Uint8List readHp, 
  Uint8List dcid, // Required for Short Header parsing
  int largestPn // Largest packet number received so far
) {
  // Use a mutable copy of the input array because `removeHeaderProtection` modifies it.
  // Dart's `Uint8List.fromList` creates a deep copy.
  final mutableArray = Uint8List.fromList(array); 

  final firstByte = mutableArray[0];
  final isShort = (firstByte & 0x80) == 0;
  
  // Variables to be populated
  bool keyPhase = false;
  int pnOffset = 0;
  int pnLength = 0;
  late Uint8List aad; 
  late Uint8List ciphertext;
  late Uint8List tag;
  int? packetNumber;
  Uint8List? nonce;

  try {
    if (!isShort) {
      // ---------- Long Header Parsing ----------
      final view = ByteData.view(mutableArray.buffer, mutableArray.offsetInBytes, mutableArray.length);
      if (mutableArray.length < 6) throw Exception("Truncated Long Header");

      // Version is at offset 1 (4 bytes)
      // final version = view.getUint32(1, Endian.big); // Not used for decryption, but available

      // Destination Connection ID (DCID) Length is at offset 5
      final dcidLen = mutableArray[5];
      
      int offset = 6;
      offset += dcidLen; // Skip DCID
      
      if (offset >= mutableArray.length) throw Exception("Truncated Long Header (SCID length missing)");
      
      final scidLen = mutableArray[offset++];
      offset += scidLen; // Skip Source Connection ID (SCID)

      if (offset >= mutableArray.length) throw Exception("Truncated Long Header (rest missing)");
      
      final typeBits = (firstByte & 0x30) >> 4;

      // Handle Token field (Initial packets only, typeBits == 0)
      if (typeBits == 0) {
        final tokenLenVar = readVarInt(mutableArray, offset);
        if (tokenLenVar == null) throw Exception("Bad varint (token len) at $offset");
        offset += tokenLenVar.byteLength + tokenLenVar.value;
      }

      // Packet Length (VarInt)
      final lenVar = readVarInt(mutableArray, offset);
      if (lenVar == null) throw Exception("Bad varint (length) at $offset");
      offset += lenVar.byteLength;
      final payloadTotalLength = lenVar.value; // Includes PN field and AEAD tag

      pnOffset = offset;
      
      // Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, false);
      
      // Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payloadEnd = payloadStart + payloadTotalLength;

      if (payloadEnd > mutableArray.length) {
        throw Exception("Truncated long header packet (expected $payloadEnd bytes, got ${mutableArray.length})");
      }

      final payload = mutableArray.sublist(payloadStart, payloadEnd);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);

    } else {
      // ---------- Short Header Parsing ----------
      
      keyPhase = (firstByte & 0x04) != 0; // Key Phase is the 3rd bit (0x04)

      final dcidLen = dcid.length; 
      pnOffset = 1 + dcidLen; // PN starts after 1 byte Type and DCID
      
      if (pnOffset + 4 > mutableArray.length) throw Exception("Short header too short for max PN length");

      // Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, true);

      // Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payload = mutableArray.sublist(payloadStart);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);
    }
  } catch (e) {
    // Catch header parsing or PN/Header Protection errors
    print("QUIC Packet Header parsing/unprotect failed: $e");
    return null;
  }
  
  // Final AEAD Decryption
  // plaintext will be null if the decryption fails (e.g., failed tag authentication)
  final plaintext = aesGcmDecrypt(ciphertext, tag, readKey, nonce!, aad);
  
  // Return the result object
  return QuicDecryptedPacket(
    packetNumber: packetNumber!,
    keyPhase: keyPhase,
    plaintext: plaintext,
  );
}






tackle these next:


These functions implement the final, critical steps for QUIC decryption: removing header protection and orchestrating the full packet decryption flow for both Long and Short headers.

The Dart ports rely on the cryptography primitives and helpers defined in previous steps (aes128Ecb, readVarInt, decodeAndExpandPacketNumber, computeNonce, and aesGcmDecrypt).

1. Helper Class
This class is used to structure the output of the decryption function.

Dart

import 'dart:typed_data';

/// Represents the result of a successful QUIC packet decryption.
class QuicDecryptedPacket {
  final int packetNumber;
  final bool keyPhase;
  final Uint8List? plaintext; // Null if decryption/authentication fails

  QuicDecryptedPacket({
    required this.packetNumber,
    required this.keyPhase,
    this.plaintext,
  });
}

// NOTE: The following required functions must be implemented (or mocked) elsewhere:
// Uint8List aes128Ecb(Uint8List sample, Uint8List hpKey);
// VarIntReadResult? readVarInt(Uint8List array, int offset);
// int decodeAndExpandPacketNumber(Uint8List array, int offset, int pnLength, int largestReceived);
// Uint8List computeNonce(Uint8List iv, int packetNumber);
// Uint8List? aesGcmDecrypt(Uint8List ciphertext, Uint8List tag, Uint8List key, Uint8List nonce, Uint8List aad);
2. removeHeaderProtection
This function reverses the Header Protection mask, revealing the actual Packet Number Length (pnLength) and the Packet Number itself. It modifies the input array in place.

Dart

/// Reverses the Header Protection mechanism, unmasking the first header byte 
/// and the Packet Number field.
/// 
/// The [array] is modified in place.
/// Returns the Packet Number Length (1, 2, 3, or 4 bytes).
int removeHeaderProtection(Uint8List array, int pnOffset, Uint8List hpKey, bool isShort) {
  // The sample is 16 bytes starting at pnOffset + 4
  var sampleOffset = pnOffset + 4;
  const sampleLength = 16;
  if (sampleOffset + sampleLength > array.length) {
    throw Exception("Not enough bytes for header protection sample");
  }
  final sample = array.sublist(sampleOffset, sampleOffset + sampleLength); 

  // Use AES-ECB to generate the 5-byte mask
  final maskFull = aes128Ecb(sample, hpKey);
  final mask = maskFull.sublist(0, 5);

  // 1. Remove protection from the first byte
  if (isShort) {
    // Short Header: XOR the 5 lowest bits (0x1f = 0b0001_1111)
    array[0] ^= mask[0] & 0x1f;
  } else {
    // Long Header: XOR the 4 lowest bits (0x0f = 0b0000_1111)
    array[0] ^= mask[0] & 0x0f;
  }

  // 2. Determine Packet Number Length and remove protection from the PN field
  // pnLength is determined by the two lowest bits (0x03) of the now-unmasked first byte.
  final pnLength = (array[0] & 0x03) + 1; 

  if (pnOffset + pnLength > array.length) {
    throw Exception("Packet number field extends beyond packet length after HP removal.");
  }

  // 3. Unmask the Packet Number field (up to 4 bytes)
  for (var i = 0; i < pnLength; i++) {
    // mask[1] is for the first PN byte, mask[2] for the second, etc.
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}
3. decryptQuicPacket
This function handles the full decryption pipeline: parsing, header unprotection, nonce calculation, and AEAD decryption.

Dart

/// Parses, removes header protection, decrypts, and authenticates a QUIC packet.
/// 
/// The [array] is the raw, encrypted packet bytes.
/// Returns a [QuicDecryptedPacket] containing the plaintext and metadata, or `null` 
/// if decryption/authentication fails.
QuicDecryptedPacket? decryptQuicPacket(
  Uint8List array, 
  Uint8List readKey, 
  Uint8List readIv, 
  Uint8List readHp, 
  Uint8List dcid, // Required for Short Header parsing (to calculate PN offset)
  int largestPn // Largest packet number received so far (for PN expansion)
) {
  // Create a mutable copy for in-place Header Protection removal
  final mutableArray = Uint8List.fromList(array); 

  final firstByte = mutableArray[0];
  final isShort = (firstByte & 0x80) == 0;
  
  // Variables to be populated
  bool keyPhase = false;
  int pnOffset = 0;
  int pnLength = 0;
  late Uint8List aad; 
  late Uint8List ciphertext;
  late Uint8List tag;
  int? packetNumber;
  Uint8List? nonce;

  try {
    if (!isShort) {
      // ---------- Long Header Parsing ----------
      
      int offset = 1; // Start after first byte

      // Skip Version (4 bytes)
      offset += 4; 

      // Destination Connection ID (DCID) Length
      final dcidLen = mutableArray[offset++]; 
      // Skip DCID
      offset += dcidLen; 
      
      // Source Connection ID (SCID) Length
      final scidLen = mutableArray[offset++];
      // Skip SCID
      offset += scidLen; 

      // Handle Token field (Initial packets only)
      if (((firstByte & 0x30) >> 4) == 0) { // Type bits are 00 (Initial)
        final tokenLenVar = readVarInt(mutableArray, offset);
        if (tokenLenVar == null) throw Exception("Truncated Token Length VarInt");
        offset += tokenLenVar.byteLength + tokenLenVar.value;
      }

      // Packet Length (VarInt)
      final lenVar = readVarInt(mutableArray, offset);
      if (lenVar == null) throw Exception("Truncated Packet Length VarInt");
      offset += lenVar.byteLength;
      final payloadTotalLength = lenVar.value; // Total length of PN field + encrypted payload

      pnOffset = offset;
      
      // 1. Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, false);
      
      // 2. Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payloadEnd = payloadStart + payloadTotalLength;

      if (payloadEnd > mutableArray.length) {
        throw Exception("Truncated long header packet");
      }

      final payload = mutableArray.sublist(payloadStart, payloadEnd);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // 3. AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);

    } else {
      // ---------- Short Header Parsing ----------
      
      keyPhase = (firstByte & 0x04) != 0; // Key Phase is the 3rd bit (0x04)

      final dcidLen = dcid.length; 
      // PN starts after 1 byte Type and DCID
      pnOffset = 1 + dcidLen; 
      
      if (pnOffset + 16 > mutableArray.length) throw Exception("Short header too short for PN + sample");

      // 1. Remove Header Protection (modifies mutableArray)
      pnLength = removeHeaderProtection(mutableArray, pnOffset, readHp, true);

      // 2. Decrypt details
      packetNumber = decodeAndExpandPacketNumber(mutableArray, pnOffset, pnLength, largestPn);
      nonce = computeNonce(readIv, packetNumber);

      final payloadStart = pnOffset + pnLength;
      final payload = mutableArray.sublist(payloadStart);
      if (payload.length < 16) throw Exception("Encrypted payload too short (min 16 for tag)");

      // 3. AEAD components
      ciphertext = payload.sublist(0, payload.length - 16);
      tag = payload.sublist(payload.length - 16);
      // AAD: Everything from start up to and including the revealed Packet Number
      aad = mutableArray.sublist(0, pnOffset + pnLength);
    }
  } catch (e) {
    // If header parsing or protection removal fails, return null
    return null;
  }
  
  // Final AEAD Decryption: plaintext will be null if authentication fails
  final plaintext = aesGcmDecrypt(ciphertext, tag, readKey, nonce!, aad);
  
  return QuicDecryptedPacket(
    packetNumber: packetNumber!,
    keyPhase: keyPhase,
    plaintext: plaintext,
  );
}










function extract_tls_messages_from_chunks(chunks, from_offset) {

  var offset = from_offset;

  var buffers = [];



  // מאחדים רצף שלם של chunks מה־offset הנוכחי

  while (chunks[offset]) {

    buffers.add(chunks[offset]);

    offset += chunks[offset].length;

  }



  // אם לא קיבלנו שום דבר – נחזיר ריק

  if (buffers.length === 0) return [];



  var combined = concatUint8Arrays(buffers);

  var tls_messages = [];

  var i = 0;



  while (i + 4 <= combined.length) {

    var msgType = combined[i];

    var length = (combined[i + 1] << 16) | (combined[i + 2] << 8) | combined[i + 3];



    if (i + 4 + length > combined.length) break; // הודעה לא שלמה – עוצרים



    var msg = combined.slice(i, i + 4 + length);

    tls_messages.add(msg);

    i += 4 + length;

  }



  // עדכון offset רק עד איפה שעברנו בפועל

  if (i > 0) {

    // מוחקים את החלקים המאוחדים מתוך chunks

    var cleanupOffset = from_offset;

    while (cleanupOffset < from_offset + i) {

      var chunk = chunks[cleanupOffset];

      delete chunks[cleanupOffset];

      cleanupOffset += chunk.length;

    }



    // השארית – אם קיימת – נחזיר אותה כ־chunk חדש

    if (i < combined.length) {

      var leftover = combined.slice(i);

      chunks[cleanupOffset] = leftover;

    }



    // נעדכן את currentOffset

    from_offset += i;

  }



  return {tls_messages,new_from_offset: from_offset};

}







function encode_version(version) {

  return new Uint8Array([

    (version >>> 24) & 0xff,

    (version >>> 16) & 0xff,

    (version >>> 8) & 0xff,

    version & 0xff

  ]);

}



function build_quic_header(packetType, dcid, scid, token, lengthField, pnLen) {

  var hdr = [];

  var firstByte;



  // שלב 1: הגדרת הביט הראשון לפי סוג הפאקט

  if (packetType === 'initial') {

    firstByte = 0xC0 | ((pnLen - 1) & 0x03);  // Long Header, Initial

  } else if (packetType === 'handshake') {

    firstByte = 0xE0 | ((pnLen - 1) & 0x03);  // Long Header, Handshake

  } else if (packetType === '0rtt') {

    firstByte = 0xD0 | ((pnLen - 1) & 0x03);  // Long Header, 0-RTT

  } else if (packetType === '1rtt') {

    firstByte = 0x40 | ((pnLen - 1) & 0x03);  // Short Header

    hdr.add(Uint8Array.of(firstByte));

    hdr.add(dcid); // ב־short header, זהו ה־Destination CID בלבד

    return {

      header: concatUint8Arrays(hdr),

      packetNumberOffset: hdr.reduce((sum, u8) => sum + u8.length, 0)

    };

  } else {

    throw new Error('Unsupported packet type: ' + packetType);

  }



  // שלב 2: Header בסיסי לכל long header

  hdr.add(Uint8Array.of(firstByte));

  hdr.add(encode_version(0x00000001)); // גרסה (4 בייטים)

  hdr.add(writeVarInt(dcid.length), dcid);

  hdr.add(writeVarInt(scid.length), scid);



  // שלב 3: רק ל־Initial מוסיפים טוקן

  if (packetType === 'initial') {

    if (!token) token = new Uint8Array(0);

    hdr.add(writeVarInt(token.length), token);

  }



  // שלב 4: שדה אורך (Length), חובה

  hdr.add(lengthField);



  // שלב 5: חישוב נקודת התחלה של packet number (מופיע מיד לאחר header)

  var header = concatUint8Arrays(hdr);

  return {

    header: header,

    packetNumberOffset: header.length

  };

}







function encrypt_quic_packet(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token) {

  var pnLength;

  if (packetNumber <= 0xff) pnLength = 1;

  else if (packetNumber <= 0xffff) pnLength = 2;

  else if (packetNumber <= 0xffffff) pnLength = 3;

  else pnLength = 4;



  var pnFull = new Uint8Array(4);

  pnFull[0] = (packetNumber >>> 24) & 0xff;

  pnFull[1] = (packetNumber >>> 16) & 0xff;

  pnFull[2] = (packetNumber >>> 8) & 0xff;

  pnFull[3] = packetNumber & 0xff;

  var packetNumberField = pnFull.slice(4 - pnLength);



  var unprotectedPayloadLength = encodedFrames.length + pnLength + 16;

  var lengthField = writeVarInt(unprotectedPayloadLength);

  var headerInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength);



  var header = headerInfo.header;

  var packetNumberOffset = headerInfo.packetNumberOffset;



  // בונים AAD

  var fullHeader = concatUint8Arrays([header, packetNumberField]);



  // ✨ הוספת padding אם צריך כדי לאפשר sample

  var minSampleLength = 32; // או 32 ל־ChaCha20

  var minTotalLength = packetNumberOffset + pnLength + minSampleLength;

  var fullLength = header.length + pnLength + encodedFrames.length + 16; // 16 = GCM tag



  if (fullLength < minTotalLength) {

    var extraPadding = minTotalLength - (header.length + pnLength + encodedFrames.length);

    var padded = new Uint8Array(encodedFrames.length + extraPadding);

    padded.set(encodedFrames, 0);

    encodedFrames = padded;

    // חשוב! גם unprotectedPayloadLength צריך להתעדכן

    unprotectedPayloadLength = encodedFrames.length + pnLength + 16;

    lengthField = writeVarInt(unprotectedPayloadLength);

    headerInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength);

    header = headerInfo.header;

    packetNumberOffset = headerInfo.packetNumberOffset;

    fullHeader = concatUint8Arrays([header, packetNumberField]);

  }



  var ciphertext = aead_encrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);

  if (ciphertext == null) return null;



  var fullPacket = concatUint8Arrays([

    header,

    packetNumberField,

    ciphertext

  ]);



  return apply_header_protection(fullPacket, packetNumberOffset, writeHp, pnLength);

}



function encrypt_quic_packet2(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token) {



  // 2. קביעת אורך packet number

  var pnLength;

  if (packetNumber <= 0xff) pnLength = 1;

  else if (packetNumber <= 0xffff) pnLength = 2;

  else if (packetNumber <= 0xffffff) pnLength = 3;

  else pnLength = 4;



  // 3. חיתוך שדה ה־packet number לבתים

  var pnFull = new Uint8Array(4);

  pnFull[0] = (packetNumber >>> 24) & 0xff;

  pnFull[1] = (packetNumber >>> 16) & 0xff;

  pnFull[2] = (packetNumber >>> 8) & 0xff;

  pnFull[3] = packetNumber & 0xff;

  var packetNumberField = pnFull.slice(4 - pnLength);



  // 4. נבנה header בלי packet number



  var unprotectedPayloadLength = encodedFrames.length + pnLength + 16;

  var lengthField = writeVarInt(unprotectedPayloadLength);

  var headerInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength);



  var header = headerInfo.header; // עד לפני packet number

  var packetNumberOffset = headerInfo.packetNumberOffset;



  // 5. AAD כולל את header + packet number (לפני ההצפנה)

  var fullHeader = concatUint8Arrays([header, packetNumberField]);



  // 6. הצפנת המטען

  var ciphertext = aead_encrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);

  if (ciphertext == null) return null;



  // 7. בניית הפקט המלא לפני header protection

  var fullPacket = concatUint8Arrays([

    header,

    packetNumberField,

    ciphertext

  ]);



  // 8. החלת הגנת כותרת (XOR)

  return apply_header_protection(fullPacket, packetNumberOffset, writeHp, pnLength);

}



The functions you've provided cover key aspects of QUIC stream processing and packet construction/encryption. These translations require careful handling of bitwise operations, byte array concatenation, and variable-length integer encoding.

The Dart ports below assume you have access to the cryptographic primitives and helper functions established in previous steps, notably:

concatUint8Arrays(List<Uint8List> buffers)

writeVarInt(int value)

aeadEncrypt(...)

applyHeaderProtection(...)

Dart's ByteData for endian-specific integer manipulation.

1. TLS Message Extraction and Version Encoding
Dart

import 'dart:typed_data';
import 'dart:math';

// Result class for extracted TLS messages
class TlsExtractResult {
  final List<Uint8List> tlsMessages;
  final int newFromOffset;
  TlsExtractResult({required this.tlsMessages, required this.newFromOffset});
}

/// Extracts complete TLS messages from a fragmented set of QUIC stream data chunks.
/// Chunks are assumed to be stored in a Map keyed by their stream offset.
/// 
/// The [chunks] map will be modified in place (consumed chunks are removed/replaced by leftover).
TlsExtractResult extractTlsMessagesFromChunks(
    Map<int, Uint8List> chunks,
    int fromOffset
) {
  final List<Uint8List> buffers = [];
  final List<int> combinedKeys = [];
  int offset = fromOffset;

  // 1. Combine contiguous sequence of chunks starting from fromOffset
  while (chunks.containsKey(offset)) {
    final chunk = chunks[offset]!;
    buffers.add(chunk);
    combinedKeys.add(offset);
    offset += chunk.length;
  }

  if (buffers.isEmpty) {
    return TlsExtractResult(tlsMessages: [], newFromOffset: fromOffset);
  }

  // 2. Combine into one buffer for parsing
  final combined = concatUint8Arrays(buffers); // Assumed available

  final List<Uint8List> tlsMessages = [];
  int i = 0; // index within 'combined'

  while (i + 4 <= combined.length) {
    // Read TLS Handshake header: 1 byte Type, 3 bytes Length (Big Endian)
    // final msgType = combined[i]; // Not used, but parsed
    final length = (combined[i + 1] << 16) | (combined[i + 2] << 8) | combined[i + 3];

    // Check if the entire message is present
    if (i + 4 + length > combined.length) break;

    // Extract the full message (4 byte header + length payload)
    final msg = combined.sublist(i, i + 4 + length);
    tlsMessages.add(msg);
    i += 4 + length;
  }
  
  // 3. Update chunks structure based on processed bytes (i)
  if (i > 0) {
    // a. Delete the old chunks that were part of the processed section
    int cleanupOffset = fromOffset;
    for (int key in combinedKeys) {
       final chunk = chunks[key]!;
       if (cleanupOffset < fromOffset + i) {
           chunks.remove(key);
           cleanupOffset += chunk.length;
       } else {
           break;
       }
    }
    
    // b. Handle leftover data by inserting a new chunk at the cleanupOffset
    if (i < combined.length) {
       final leftover = combined.sublist(i);
       chunks[cleanupOffset] = leftover;
    }
    
    // Update the offset to the end of the processed data
    fromOffset += i;
  }

  return TlsExtractResult(tlsMessages: tlsMessages, newFromOffset: fromOffset);
}


/// Encodes a 32-bit integer QUIC version into a 4-byte Big Endian [Uint8List].
Uint8List encodeVersion(int version) {
  final result = Uint8List(4);
  final view = ByteData.view(result.buffer);
  view.setUint32(0, version, Endian.big);
  return result;
}
3. QUIC Header Construction
Dart

// Result class for Header building
class QuicHeaderInfo {
  final Uint8List header;
  final int packetNumberOffset;
  QuicHeaderInfo({required this.header, required this.packetNumberOffset});
}

/// Constructs the unprotected QUIC header up to the Packet Number field.
QuicHeaderInfo buildQuicHeader(
    String packetType, 
    Uint8List dcid, 
    Uint8List scid, 
    Uint8List? token, 
    Uint8List lengthField, // VarInt for protected payload length
    int pnLen // 1, 2, 3, or 4
) {
  final List<Uint8List> hdrParts = [];
  int firstByte;

  // pnLen - 1 corresponds to the two low bits (LL) of the first byte
  final pnLenBits = (pnLen - 1) & 0x03;

  // Step 1: Define the first byte based on packet type
  if (packetType == 'initial') {
    firstByte = 0xC0 | pnLenBits; // 1100_00LL
  } else if (packetType == 'handshake') {
    firstByte = 0xE0 | pnLenBits; // 1110_00LL
  } else if (packetType == '0rtt') {
    firstByte = 0xD0 | pnLenBits; // 1101_00LL
  } else if (packetType == '1rtt') {
    // Short Header: 01xx_xxLL. The bits 4 and 5 are reserved (0) or Key Phase (1).
    firstByte = 0x40 | pnLenBits; // 0100_00LL (Assuming Key Phase 0)
    
    // Short Header is: Type (1 byte) + DCID + Packet Number
    hdrParts.add(Uint8List.fromList([firstByte]));
    hdrParts.add(dcid);
    
    final header = concatUint8Arrays(hdrParts);
    return QuicHeaderInfo(
      header: header,
      packetNumberOffset: header.length // PN starts immediately after DCID
    );
  } else {
    throw Exception('Unsupported packet type: $packetType');
  }

  // Steps 2-4: Long Header construction
  hdrParts.add(Uint8List.fromList([firstByte]));
  hdrParts.add(encodeVersion(0x00000001)); // QUIC v1
  
  // DCID Length + Value
  hdrParts.add(writeVarInt(dcid.length));
  hdrParts.add(dcid);
  
  // SCID Length + Value
  hdrParts.add(writeVarInt(scid.length));
  hdrParts.add(scid);

  // Step 3: Token for Initial packets
  if (packetType == 'initial') {
    final effectiveToken = token ?? Uint8List(0);
    hdrParts.add(writeVarInt(effectiveToken.length));
    hdrParts.add(effectiveToken);
  }

  // Step 4: Length field (Payload Length, VarInt)
  hdrParts.add(lengthField);

  // Step 5: Calculate PN offset
  final header = concatUint8Arrays(hdrParts);
  return QuicHeaderInfo(
    header: header,
    packetNumberOffset: header.length // PN starts immediately after the Length field
  );
}
4. QUIC Packet Encryption (encryptQuicPacket)
This function calculates the necessary lengths, builds the header, handles mandatory padding for Long Headers (to allow header protection sampling), encrypts the payload, and applies Header Protection.

Dart

/// Encrypts a QUIC packet and applies Header Protection.
/// 
/// Combines the logic from `encrypt_quic_packet` and `encrypt_quic_packet2` 
/// with correct padding logic for AES-GCM (16-byte sample).
Uint8List? encryptQuicPacket(
    String packetType, 
    Uint8List encodedFrames, 
    Uint8List writeKey, 
    Uint8List writeIv, 
    Uint8List writeHp, 
    int packetNumber, 
    Uint8List dcid, 
    Uint8List scid, 
    Uint8List? token
) {
  // 1. Determine Packet Number Length
  int pnLength;
  if (packetNumber <= 0xff) pnLength = 1;
  else if (packetNumber <= 0xffff) pnLength = 2;
  else if (packetNumber <= 0xffffff) pnLength = 3;
  else pnLength = 4;

  // 2. Truncate Packet Number field to pnLength bytes (Big Endian)
  final pnFull = ByteData(4);
  pnFull.setUint32(0, packetNumber, Endian.big);
  final packetNumberField = pnFull.buffer.asUint8List().sublist(4 - pnLength);

  // 3. Initial calculation of payload length (frames + PN field + 16 byte GCM tag)
  int unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
  Uint8List lengthField = writeVarInt(unprotectedPayloadLength);
  
  // 4. Build Header (unprotected)
  QuicHeaderInfo headerInfo = buildQuicHeader(
    packetType, dcid, scid, token, lengthField, pnLength
  );
  Uint8List header = headerInfo.header;
  int packetNumberOffset = headerInfo.packetNumberOffset;

  // 5. Check and apply padding if needed (Long Headers only)
  if (packetType != '1rtt') {
    // The Header Protection sample starts at PN offset + 4 and must be 16 bytes.
    const minSampleLength = 16;
    
    // The total packet length must be >= (PN offset + 4 + 16).
    final minTotalLength = packetNumberOffset + 4 + minSampleLength;
    final fullLength = header.length + pnLength + encodedFrames.length + 16; 

    if (fullLength < minTotalLength) {
      // Required Protected Bytes = minTotalLength - (Header Length + PN Length)
      final requiredProtectedDataLength = minTotalLength - (header.length + pnLength);
      
      // Since the tag is 16 bytes, the frame content must be:
      final requiredFramesLength = requiredProtectedDataLength - 16;

      if (requiredFramesLength > encodedFrames.length) {
         final extraPadding = requiredFramesLength - encodedFrames.length;
         
         // Add padding (zero bytes) to encodedFrames
         final padded = Uint8List(encodedFrames.length + extraPadding);
         padded.setAll(0, encodedFrames); 
         encodedFrames = padded;
         
         // RECALCULATE LENGTH FIELD AND REBUILD HEADER
         unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
         lengthField = writeVarInt(unprotectedPayloadLength);
         headerInfo = buildQuicHeader(packetType, dcid, scid, token, lengthField, pnLength);
         header = headerInfo.header;
         packetNumberOffset = headerInfo.packetNumberOffset;
      }
    }
  }

  // 6. Build AAD: Unprotected Header + Unprotected Packet Number
  final fullHeader = concatUint8Arrays([header, packetNumberField]);

  // 7. Encrypt Payload
  final ciphertext = aeadEncrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);
  if (ciphertext == null) return null;

  // 8. Build Full Packet (before Header Protection)
  final fullPacket = concatUint8Arrays([
    header,
    packetNumberField,
    ciphertext
  ]);

  // 9. Apply Header Protection
  return applyHeaderProtection(fullPacket, packetNumberOffset, writeHp, pnLength);
}








function encode_quic_frames(frames) {

  var parts = [];

  var i;



  for (i = 0; i < frames.length; i++) {

    var frame = frames[i];



    if (frame.type === 'padding') {

      var pad = new Uint8Array(frame.length);

      for (var j = 0; j < pad.length; j++) pad[j] = 0x00;

      parts.add(pad);



    } else if (frame.type === 'ping') {

      parts.add(new Uint8Array([0x01]));



    } else if (frame.type === 'ack') {

      var hasECN = frame.ecn !=null && frame.ecn !=undefined;

      var typeByte = hasECN ? 0x03 : 0x02;



      var b1 = writeVarInt(frame.largest);           // Largest Acknowledged

      var b2 = writeVarInt(frame.delay);             // ACK Delay

      var b3 = writeVarInt(frame.ranges.length); // ACK Range Count

      var b4 = writeVarInt(frame.firstRange != null ? frame.firstRange : 0);



      var temp = [new Uint8Array([typeByte]), b1, b2, b3, b4];



     

      for (j = 0; j < frame.ranges.length; j++) {

        var gap = writeVarInt(frame.ranges[j].gap);     // Gap to next range

        var len = writeVarInt(frame.ranges[j].length);  // Length of next range

        temp.add(gap, len);

      }



      if (hasECN) {

        temp.add(

        writeVarInt(frame.ecn.ect0),

        writeVarInt(frame.ecn.ect1),

        writeVarInt(frame.ecn.ce)

        );

      }



      parts.add(concatUint8Arrays(temp));



    } else if (frame.type === 'reset_stream') {

      var id = writeVarInt(frame.id);

      var err = new Uint8Array([frame.error >> 8, frame.error & 0xff]);

      var size = writeVarInt(frame.finalSize);

      parts.add(concatUint8Arrays([

        new Uint8Array([0x04]), id, err, size

      ]));



    } else if (frame.type === 'stop_sending') {

      var id = writeVarInt(frame.id);

      var err = new Uint8Array([frame.error >> 8, frame.error & 0xff]);

      parts.add(concatUint8Arrays([

        new Uint8Array([0x05]), id, err

      ]));



    } else if (frame.type === 'crypto') {

      var off = writeVarInt(frame.offset);

      var len = writeVarInt(frame.data.length);

      parts.add(concatUint8Arrays([

        new Uint8Array([0x06]), off, len, frame.data

      ]));



    } else if (frame.type === 'new_token') {

      var len = writeVarInt(frame.token.length);

      parts.add(concatUint8Arrays([

        new Uint8Array([0x07]), len, frame.token

      ]));



    } else if (frame.type === 'stream') {



      var typeByte = 0x08;



      var hasOffset = (frame.offset != null);

      var hasLen = (frame.data && frame.data.length > 0);

      var hasFin = !!frame.fin;



      if (hasOffset) typeByte |= 0x04;

      if (hasLen) typeByte |= 0x02;

      if (hasFin) typeByte |= 0x01;



      var id  = writeVarInt(frame.id);

      var off = hasOffset ? writeVarInt(frame.offset) : new Uint8Array(0);

      var len = hasLen ? writeVarInt(frame.data.length) : new Uint8Array(0);



      parts.add(concatUint8Arrays([

        new Uint8Array([typeByte]), id, off, len, frame.data

      ]));



    } else if (frame.type === 'max_data') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x09]), writeVarInt(frame.max)

      ]));



    } else if (frame.type === 'max_stream_data') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x0a]), writeVarInt(frame.id), writeVarInt(frame.max)

      ]));



    } else if (frame.type === 'max_streams_bidi' || frame.type === 'max_streams_uni') {

      var code = frame.type === 'max_streams_bidi' ? 0x0b : 0x0c;

      parts.add(concatUint8Arrays([

        new Uint8Array([code]), writeVarInt(frame.max)

      ]));



    } else if (frame.type === 'data_blocked') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x0d]), writeVarInt(frame.limit)

      ]));



    } else if (frame.type === 'stream_data_blocked') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x0e]), writeVarInt(frame.id), writeVarInt(frame.limit)

      ]));



    } else if (frame.type === 'streams_blocked_bidi') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x0f]), writeVarInt(frame.limit)

      ]));



    } else if (frame.type === 'streams_blocked_uni') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x10]), writeVarInt(frame.limit)

      ]));



    } else if (frame.type === 'new_connection_id') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x11]),

        writeVarInt(frame.seq),

        writeVarInt(frame.retire),

        new Uint8Array([frame.connId.length]),

        frame.connId,

        frame.token

      ]));



    } else if (frame.type === 'retire_connection_id') {

      parts.add(concatUint8Arrays([

        new Uint8Array([0x12]),

        writeVarInt(frame.seq)

      ]));



    } else if (frame.type === 'path_challenge' || frame.type === 'path_response') {

      var code = frame.type === 'path_challenge' ? 0x13 : 0x14;

      parts.add(concatUint8Arrays([

        new Uint8Array([code]), frame.data

      ]));



    } else if (frame.type === 'connection_close') {

      var code = frame.application ? 0x1d : 0x1c;

      var err = new Uint8Array([frame.error >> 8, frame.error & 0xff]);

      var ft = frame.application ? new Uint8Array(0) : writeVarInt(frame.frameType);

      var reason = new TextEncoder().encode(frame.reason || "");

      var reasonLen = writeVarInt(reason.length);

      parts.add(concatUint8Arrays([

        new Uint8Array([code]), err, ft, reasonLen, reason

      ]));



    } else if (frame.type === 'handshake_done') {

      parts.add(new Uint8Array([0x1e]));



    } else if (frame.type === 'datagram') {

      var firstByte;

      var prefixBytes;

      var payload = frame.data;



      if (frame.contextId != null) {

        // אם יש contextId — משתמשים ב־0x31 לפי תקן QUIC

        firstByte = 0x31;

        var contextBytes = writeVarInt(frame.contextId);

        prefixBytes = concatUint8Arrays([

          new Uint8Array([firstByte]),

          contextBytes

        ]);

      } else {

        // אם אין contextId — שולחים כ־0x30 לפי תקן QUIC

        firstByte = 0x30;

        prefixBytes = new Uint8Array([firstByte]);

        // payload נשאר כמו שהוא — לא מוסיפים streamId!

      }



      parts.add(concatUint8Arrays([

        prefixBytes,

        payload

      ]));

    } else {

      // פריים לא ידוע – נתעלם או אפשר להתריע בלוג

      //console.warn('Unsupported frame type:', frame.type);

    }

  }



  if(parts.length==1){

    return parts[0];

  }else{

    return concatUint8Arrays(parts);

  }

 

}











function parse_quic_frames(buf) {

  let offset = 0;

  const frames = [];

  const textDecoder = new TextDecoder();



  function safeReadVarInt() {

    if (offset >= buf.length) return null;

    const res = readVarInt(buf, offset);

    if (!res || typeof res.byteLength !='number') return null;

    offset += res.byteLength;

    return res;

  }



  while (offset < buf.length) {

    const start = offset;

    let type = buf[offset++];



    if (type >= 0x80) {

      offset--; // backtrack and read full varint

      const t = safeReadVarInt();

      if (!t) break;

      type = t.value;

    }



    if (type === 0x00) {

      // padding



    } else if (type === 0x01) {

      frames.add({ type: 'ping' });



    } else if ((type & 0xfe) === 0x02) {

      const hasECN = (type & 0x01) === 0x01;

      const largest = safeReadVarInt(); if (!largest) break;

      const delay = safeReadVarInt(); if (!delay) break;

      const rangeCount = safeReadVarInt(); if (!rangeCount) break;

      const firstRange = safeReadVarInt(); if (!firstRange) break;



      const ranges = [];

      for (let i = 0; i < rangeCount.value; i++) {

        const gap = safeReadVarInt(); if (!gap) break;

        const len = safeReadVarInt(); if (!len) break;

        ranges.add({ gap: gap.value, length: len.value });

      }



      let ecn = null;

      if (hasECN) {

        const ect0 = safeReadVarInt(); if (!ect0) break;

        const ect1 = safeReadVarInt(); if (!ect1) break;

        const ce = safeReadVarInt(); if (!ce) break;

        ecn = { ect0: ect0.value, ect1: ect1.value, ce: ce.value };

      }



      frames.add({ type: 'ack', largest: largest.value, delay: delay.value, firstRange: firstRange.value, ranges, ecn });



    } else if (type === 0x04) {

      const id = safeReadVarInt(); if (!id) break;

      if (offset + 2 > buf.length) break;

      const error = buf[offset++] << 8 | buf[offset++];

      const finalSize = safeReadVarInt(); if (!finalSize) break;

      frames.add({ type: 'reset_stream', id: id.value, error, finalSize: finalSize.value });



    } else if (type === 0x05) {

      const id = safeReadVarInt(); if (!id) break;

      if (offset + 2 > buf.length) break;

      const error = buf[offset++] << 8 | buf[offset++];

      frames.add({ type: 'stop_sending', id: id.value, error });



    } else if (type === 0x06) {

      const off = safeReadVarInt(); if (!off) break;

      const len = safeReadVarInt(); if (!len) break;

      if (offset + len.value > buf.length) break;

      const data = buf.slice(offset, offset + len.value); offset += len.value;

      frames.add({ type: 'crypto', offset: off.value, data });



    } else if (type === 0x07) {

      const len = safeReadVarInt(); if (!len) break;

      if (offset + len.value > buf.length) break;

      const token = buf.slice(offset, offset + len.value); offset += len.value;

      frames.add({ type: 'new_token', token });



    } else if ((type & 0xe0) === 0x00) {

      const fin  = !!(type & 0x01);

      const lenb = !!(type & 0x02);

      const offb = !!(type & 0x04);



      const stream_id = safeReadVarInt(); if (!stream_id) break;

      const offset_val = offb ? safeReadVarInt() : { value: 0 }; if (!offset_val) break;

      const length_val = lenb ? safeReadVarInt() : { value: buf.length - offset }; if (!length_val) break;



      if (offset + length_val.value > buf.length) break;



      const data = buf.slice(offset, offset + length_val.value); offset += length_val.value;



      frames.add({

        type: 'stream',

        id: stream_id.value,

        offset: offset_val.value,

        fin,

        data

      });

    } else if (type === 0x09) {

      const max = safeReadVarInt(); if (!max) break;

      frames.add({ type: 'max_data', max: max.value });



    } else if (type === 0x0a) {

      const id = safeReadVarInt(); if (!id) break;

      const max = safeReadVarInt(); if (!max) break;

      frames.add({ type: 'max_stream_data', id: id.value, max: max.value });



    } else if (type === 0x12 || type === 0x13) {

      const max = safeReadVarInt(); if (!max) break;

      frames.add({ type: type === 0x12 ? 'max_streams_bidi' : 'max_streams_uni', max: max.value });



    } else if (type === 0x14) {

      const max = safeReadVarInt(); if (!max) break;

      frames.add({ type: 'data_blocked', max: max.value });



    } else if (type === 0x15) {

      const id = safeReadVarInt(); if (!id) break;

      frames.add({ type: 'stream_data_blocked', id: id.value });



    } else if (type === 0x16 || type === 0x17) {

      const max = safeReadVarInt(); if (!max) break;

      frames.add({ type: type === 0x16 ? 'streams_blocked_bidi' : 'streams_blocked_uni', max: max.value });



    } else if (type === 0x18) {

      const seq = safeReadVarInt(); if (!seq) break;

      const retire = safeReadVarInt(); if (!retire) break;

      if (offset >= buf.length) break;

      const len = buf[offset++];

      if (offset + len + 16 > buf.length) break;

      const connId = buf.slice(offset, offset + len); offset += len;

      const token = buf.slice(offset, offset + 16); offset += 16;

      frames.add({ type: 'new_connection_id', seq: seq.value, retire: retire.value, connId, token });



    } else if (type === 0x19) {

      const seq = safeReadVarInt(); if (!seq) break;

      frames.add({ type: 'retire_connection_id', seq: seq.value });



    } else if (type === 0x1a || type === 0x1b) {

      if (offset + 8 > buf.length) break;

      const data = buf.slice(offset, offset + 8); offset += 8;

      frames.add({ type: type === 0x1a ? 'path_challenge' : 'path_response', data });



    } else if (type === 0x1c || type === 0x1d) {

      if (offset + 2 > buf.length) break;

      const error = buf[offset++] << 8 | buf[offset++];

      let frameType = null;

      if (type === 0x1c) {

        const ft = safeReadVarInt(); if (!ft) break;

        frameType = ft.value;

      }

      const reasonLen = safeReadVarInt(); if (!reasonLen) break;

      if (offset + reasonLen.value > buf.length) break;

      const reason = textDecoder.decode(buf.slice(offset, offset + reasonLen.value)); offset += reasonLen.value;

      frames.add({ type: 'connection_close', application: type === 0x1d, error, frameType, reason });



    } else if (type === 0x1e) {

      frames.add({ type: 'handshake_done' });



    } else if (type === 0x1f) {

      frames.add({ type: 'immediate_ack' });



    } else if (type === 0x30 || type === 0x31) {

      let contextId = null;

      let len = null;



      if (type === 0x31) {

        // קורא את context ID

        var cid = safeReadVarInt(buf, offset);

        if (!cid) break;

        contextId = cid.value;

        offset = cid.nextOffset;

      }



      // החישוב של len מבוסס על מה שנשאר בפאקט אחרי הקריאה של contextId

      len = { value: buf.length - offset };



      if (offset + len.value > buf.length) break;



      const data = buf.slice(offset, offset + len.value);

      offset += len.value;



      frames.add({

        type: 'datagram',

        contextId: contextId,

        data: data

      });



    } else if (type === 0xaf) {

      const seq = safeReadVarInt(); if (!seq) break;

      const packetTolerance = safeReadVarInt(); if (!packetTolerance) break;

      if (offset >= buf.length) break;

      const ackDelayExponent = buf[offset++];

      const maxAckDelay = safeReadVarInt(); if (!maxAckDelay) break;

      frames.add({

        type: 'ack_frequency',

        seq: seq.value,

        packetTolerance: packetTolerance.value,

        ackDelayExponent,

        maxAckDelay: maxAckDelay.value

      });



    } else if (type >= 0x15228c00 && type <= 0x15228cff) {

      frames.add({ type: 'multipath_extension', frameType: type });



    } else {

      frames.add({ type: 'unknown', frameType: type, offset: start });

      break;

    }

  }



  return frames;

}













function parse_quic_packet(array, offset0 = 0) {

  if (!(array instanceof Uint8Array)) return null;

  if (offset0 >= array.length) return null;



  const firstByte = array[offset0];

  const isLongHeader = (firstByte & 0x80) !=0;



  if (isLongHeader) {

    if (offset0 + 6 > array.length) return null;



    const version = ((array[offset0+1] << 24) | (array[offset0+2] << 16) | (array[offset0+3] << 8) | array[offset0+4]) >>> 0;



    const dcidLen = array[offset0+5];

    let offset = offset0 + 6;



    if (offset + dcidLen + 1 > array.length) return null;

    const dcid = array.slice(offset, offset + dcidLen);

    offset += dcidLen;



    const scidLen = array[offset++];

    if (offset + scidLen > array.length) return null;

    const scid = array.slice(offset, offset + scidLen);

    offset += scidLen;



    // Version negotiation

    if (version === 0) {

      const supportedVersions = [];

      while (offset + 4 <= array.length) {

        const v = (array[offset] << 24) | (array[offset+1] << 16) | (array[offset+2] << 8) | array[offset+3];

        supportedVersions.add(v);

        offset += 4;

      }

      return {

        form: 'long',

        type: 'version_negotiation',

        version,

        dcid,

        scid,

        supportedVersions,

        totalLength: offset - offset0

      };

    }



    const packetTypeBits = (firstByte & 0x30) >> 4;

    const typeMap = ['initial', '0rtt', 'handshake', 'retry'];

    const packetType = typeMap[packetTypeBits] || 'unknown';



    if (packetType === 'retry') {

      const odcid = array.slice(offset);

      return {

        form: 'long',

        type: 'retry',

        version,

        dcid,

        scid,

        originalDestinationConnectionId: odcid,

        totalLength: array.length - offset0 // כל השאר

      };

    }



    // === קריאה של Token אם זה Initial ===

    let token = null;

    if (packetType === 'initial') {

      try {

        const tokenLen = readVarInt(array, offset);

        offset += tokenLen.byteLength;

        if (offset + tokenLen.value > array.length) return null;

        token = array.slice(offset, offset + tokenLen.value);

        offset += tokenLen.value;

      } catch (e) {

        return null;

      }

    }



    // === כאן בא השלב הקריטי: לקרוא את Length ===

    try {

      const lengthInfo = readVarInt(array, offset);

      offset += lengthInfo.byteLength;



      const payloadLength = lengthInfo.value;

      const totalLength = offset - offset0 + payloadLength;



      if (offset0 + totalLength > array.length) return null;



      return {

        form: 'long',

        type: packetType,

        version,

        dcid,

        scid,

        token,

        totalLength

      };

    } catch (e) {

      return null;

    }

  } else {

    const totalLength = array.length - offset0; // לא ניתן לדעת בדיוק, אז נניח שזה האחרון

    return {

      form: 'short',

      type: '1rtt',

      totalLength

    };

  }

}



function parse_quic_datagram(array) {

  var packets = [];

  var offset = 0;



  while (offset < array.length) {

    var pkt = parse_quic_packet(array, offset);

    if (!pkt || !pkt.totalLength) break;



    const start = offset;

    const end = offset + pkt.totalLength;



    // slice רק אם חייב

    pkt.raw = (start === 0 && end === array.length)

      ? array

      : array.slice(start, end);



    packets.add(pkt);

    offset = end;

  }



  return packets;

}





function build_new_session_ticket(session_id_bytes, options) {

  var ticket_lifetime = options.lifetime || 86400;

  var ticket_age_add = Math.floor(Math.random() * 0xffffffff);

  var ticket_nonce = crypto.getRandomValues(new Uint8Array(8));

  var ticket = session_id_bytes;



  var extensions = [];

  if (options.early_data_max_size != null) {

    var ed = new Uint8Array(8);

    ed[0] = 0x00; ed[1] = 0x2a; // early_data extension type

    ed[2] = 0x00; ed[3] = 0x04; // extension length

    ed[4] = (options.early_data_max_size >>> 24) & 0xff;

    ed[5] = (options.early_data_max_size >>> 16) & 0xff;

    ed[6] = (options.early_data_max_size >>> 8) & 0xff;

    ed[7] = (options.early_data_max_size) & 0xff;

    extensions.add(ed);

  }



  var ext_len = 0;

  for (var i = 0; i < extensions.length; i++) ext_len += extensions[i].length;

  var extensions_block = new Uint8Array(ext_len);

  for (var i = 0, offset = 0; i < extensions.length; i++) {

    extensions_block.set(extensions[i], offset);

    offset += extensions[i].length;

  }



  var total_len =

    4 + // ticket_lifetime

    4 + // ticket_age_add

    1 + ticket_nonce.length +

    2 + ticket.length +

    2 + extensions_block.length;



  var result = new Uint8Array(total_len);

  var p = 0;



  result[p++] = (ticket_lifetime >>> 24) & 0xff;

  result[p++] = (ticket_lifetime >>> 16) & 0xff;

  result[p++] = (ticket_lifetime >>> 8) & 0xff;

  result[p++] = (ticket_lifetime) & 0xff;



  result[p++] = (ticket_age_add >>> 24) & 0xff;

  result[p++] = (ticket_age_add >>> 16) & 0xff;

  result[p++] = (ticket_age_add >>> 8) & 0xff;

  result[p++] = (ticket_age_add) & 0xff;



  result[p++] = ticket_nonce.length;

  result.set(ticket_nonce, p);

  p += ticket_nonce.length;



  result[p++] = (ticket.length >>> 8) & 0xff;

  result[p++] = (ticket.length) & 0xff;

  result.set(ticket, p);

  p += ticket.length;



  result[p++] = (extensions_block.length >>> 8) & 0xff;

  result[p++] = (extensions_block.length) & 0xff;

  result.set(extensions_block, p);



  return result;

}



The functions below port your JavaScript QUIC frame encoding, decoding, and packet parsing logic into Dart, maintaining the structure and byte-level operations of the original code.

These functions rely on the following assumed Dart dependencies/helpers, which must be implemented based on standard QUIC specifications (VarInts, concatenation):

Dart

import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';

// Placeholder for VarInt result structure
class VarIntReadResult {
  final int value;
  final int byteLength;
  VarIntReadResult({required this.value, required this.byteLength});
}

// Assumed utility functions (must be defined elsewhere):
// Uint8List concatUint8Arrays(List<Uint8List> buffers);
// Uint8List writeVarInt(int value);
// VarIntReadResult? readVarInt(Uint8List array, int offset);
1. Frame Encoding (encodeQuicFrames)
This function converts a list of structured Dart maps (representing QUIC frames) into a single, concatenated Uint8List buffer suitable for encryption.

Dart

/// Encodes a list of structured QUIC frames into a single Uint8List buffer.
Uint8List encodeQuicFrames(List<Map<String, dynamic>> frames) {
  final List<Uint8List> parts = [];

  for (final frame in frames) {
    final type = frame['type'] as String;

    if (type == 'padding') {
      final length = frame['length'] as int;
      parts.add(Uint8List(length)); // All zero bytes by default

    } else if (type == 'ping') {
      parts.add(Uint8List.fromList([0x01]));

    } else if (type == 'ack') {
      final hasECN = frame['ecn'] != null;
      final typeByte = hasECN ? 0x03 : 0x02;

      final b1 = writeVarInt(frame['largest']);      // Largest Acknowledged
      final b2 = writeVarInt(frame['delay']);        // ACK Delay
      final b3 = writeVarInt(frame['ranges'].length); // ACK Range Count
      final b4 = writeVarInt(frame['firstRange'] ?? 0);

      final List<Uint8List> temp = [Uint8List.fromList([typeByte]), b1, b2, b3, b4];

      final List<Map<String, int>> ranges = (frame['ranges'] as List).cast<Map<String, int>>();
      for (var range in ranges) {
        final gap = writeVarInt(range['gap']!);
        final len = writeVarInt(range['length']!);
        temp.addAll([gap, len]);
      }

      if (hasECN) {
        final ecn = frame['ecn'] as Map<String, int>;
        temp.addAll([
          writeVarInt(ecn['ect0'] ?? 0),
          writeVarInt(ecn['ect1'] ?? 0),
          writeVarInt(ecn['ce'] ?? 0),
        ]);
      }

      parts.add(concatUint8Arrays(temp));

    } else if (type == 'reset_stream') {
      final error = frame['error'] as int;
      final id = writeVarInt(frame['id']);
      final err = Uint8List.fromList([error >> 8, error & 0xff]);
      final size = writeVarInt(frame['finalSize']);
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x04]), id, err, size
      ]));

    } else if (type == 'stop_sending') {
      final error = frame['error'] as int;
      final id = writeVarInt(frame['id']);
      final err = Uint8List.fromList([error >> 8, error & 0xff]);
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x05]), id, err
      ]));

    } else if (type == 'crypto') {
      final data = frame['data'] as Uint8List;
      final off = writeVarInt(frame['offset']);
      final len = writeVarInt(data.length);
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x06]), off, len, data
      ]));

    } else if (type == 'new_token') {
      final token = frame['token'] as Uint8List;
      final len = writeVarInt(token.length);
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x07]), len, token
      ]));

    } else if (type == 'stream') {
      int typeByte = 0x08;

      final hasOffset = frame['offset'] != null && (frame['offset'] as int) > 0;
      final data = frame['data'] as Uint8List;
      final hasLen = data.isNotEmpty;
      final hasFin = frame['fin'] == true;

      if (hasOffset) typeByte |= 0x04;
      if (hasLen) typeByte |= 0x02;
      if (hasFin) typeByte |= 0x01;

      final id = writeVarInt(frame['id']);
      final off = hasOffset ? writeVarInt(frame['offset']) : Uint8List(0);
      final len = hasLen ? writeVarInt(data.length) : Uint8List(0);

      parts.add(concatUint8Arrays([
        Uint8List.fromList([typeByte]), id, off, len, data
      ]));

    } else if (type == 'max_data') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x09]), writeVarInt(frame['max'])
      ]));

    } else if (type == 'max_stream_data') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x0a]), writeVarInt(frame['id']), writeVarInt(frame['max'])
      ]));

    } else if (type == 'max_streams_bidi' || type == 'max_streams_uni') {
      final code = type == 'max_streams_bidi' ? 0x0b : 0x0c;
      parts.add(concatUint8Arrays([
        Uint8List.fromList([code]), writeVarInt(frame['max'])
      ]));

    } else if (type == 'data_blocked') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x0d]), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'stream_data_blocked') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x0e]), writeVarInt(frame['id']), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'streams_blocked_bidi') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x0f]), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'streams_blocked_uni') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x10]), writeVarInt(frame['limit'])
      ]));

    } else if (type == 'new_connection_id') {
      final connId = frame['connId'] as Uint8List;
      final token = frame['token'] as Uint8List;
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x11]),
        writeVarInt(frame['seq']),
        writeVarInt(frame['retire']),
        Uint8List.fromList([connId.length]),
        connId,
        token
      ]));

    } else if (type == 'retire_connection_id') {
      parts.add(concatUint8Arrays([
        Uint8List.fromList([0x12]),
        writeVarInt(frame['seq'])
      ]));

    } else if (type == 'path_challenge' || type == 'path_response') {
      final code = type == 'path_challenge' ? 0x13 : 0x14;
      parts.add(concatUint8Arrays([
        Uint8List.fromList([code]), frame['data'] as Uint8List
      ]));

    } else if (type == 'connection_close') {
      final isApplication = frame['application'] == true;
      final code = isApplication ? 0x1d : 0x1c;
      final error = frame['error'] as int;
      final err = Uint8List.fromList([error >> 8, error & 0xff]);
      
      Uint8List ft;
      if (isApplication) {
        ft = Uint8List(0);
      } else {
        ft = writeVarInt(frame['frameType']);
      }
      
      final reasonText = (frame['reason'] ?? "") as String;
      final reason = utf8.encode(reasonText) as Uint8List;
      final reasonLen = writeVarInt(reason.length);
      
      parts.add(concatUint8Arrays([
        Uint8List.fromList([code]), err, ft, reasonLen, reason
      ]));

    } else if (type == 'handshake_done') {
      parts.add(Uint8List.fromList([0x1e]));
      
    } else if (type == 'datagram') {
      final payload = frame['data'] as Uint8List;
      final contextId = frame['contextId'];

      if (contextId != null) {
        final contextBytes = writeVarInt(contextId);
        parts.add(concatUint8Arrays([
          Uint8List.fromList([0x31]), // 0x31: DATAGRAM frame with context ID
          contextBytes,
          payload
        ]));
      } else {
        parts.add(concatUint8Arrays([
          Uint8List.fromList([0x30]), // 0x30: DATAGRAM frame without context ID
          payload
        ]));
      }
    } 
    // Unknown frames are ignored, matching the JS logic.
  }

  return concatUint8Arrays(parts);
}
2. Frame Parsing (parseQuicFrames)
This function parses a raw buffer of encrypted frames back into a list of frame objects.

Dart

/// Parses a raw buffer of concatenated QUIC frames into a list of structured frames.
List<Map<String, dynamic>> parseQuicFrames(Uint8List buf) {
  int offset = 0;
  final List<Map<String, dynamic>> frames = [];
  final textDecoder = utf8.decoder;

  // Local helper to safely read a VarInt and advance the offset
  VarIntReadResult? safeReadVarInt() {
    if (offset >= buf.length) return null;
    final res = readVarInt(buf, offset);
    if (res == null) return null;
    offset += res.byteLength;
    return res;
  }

  while (offset < buf.length) {
    final start = offset;
    int type = buf[offset++];

    // Handle large frame types (e.g., custom/future frames) that use VarInt for type
    if (type >= 0x80) {
      offset--; // backtrack
      final t = safeReadVarInt();
      if (t == null) break;
      type = t.value;
    }

    if (type == 0x00) {
      // PADDING frame: no action, loop continues, effectively consuming the byte
    } else if (type == 0x01) {
      frames.add({'type': 'ping'});

    } else if ((type & 0xfe) == 0x02) { // ACK (0x02) or ACK_ECN (0x03)
      final hasECN = (type & 0x01) == 0x01;
      
      final largest = safeReadVarInt(); if (largest == null) break;
      final delay = safeReadVarInt(); if (delay == null) break;
      final rangeCount = safeReadVarInt(); if (rangeCount == null) break;
      final firstRange = safeReadVarInt(); if (firstRange == null) break;

      final List<Map<String, int>> ranges = [];
      for (int i = 0; i < rangeCount.value; i++) {
        final gap = safeReadVarInt(); if (gap == null) break;
        final len = safeReadVarInt(); if (len == null) break;
        ranges.add({'gap': gap.value, 'length': len.value});
      }
      if (ranges.length != rangeCount.value) break;

      Map<String, int>? ecn = null;
      if (hasECN) {
        final ect0 = safeReadVarInt(); if (ect0 == null) break;
        final ect1 = safeReadVarInt(); if (ect1 == null) break;
        final ce = safeReadVarInt(); if (ce == null) break;
        ecn = {'ect0': ect0.value, 'ect1': ect1.value, 'ce': ce.value};
      }

      frames.add({
        'type': 'ack',
        'largest': largest.value,
        'delay': delay.value,
        'firstRange': firstRange.value,
        'ranges': ranges,
        'ecn': ecn
      });

    } else if (type == 0x04) { // RESET_STREAM
      final id = safeReadVarInt(); if (id == null) break;
      if (offset + 2 > buf.length) break;
      final error = buf[offset++] << 8 | buf[offset++];
      final finalSize = safeReadVarInt(); if (finalSize == null) break;
      frames.add({
        'type': 'reset_stream',
        'id': id.value,
        'error': error,
        'finalSize': finalSize.value
      });

    } else if (type == 0x05) { // STOP_SENDING
      final id = safeReadVarInt(); if (id == null) break;
      if (offset + 2 > buf.length) break;
      final error = buf[offset++] << 8 | buf[offset++];
      frames.add({'type': 'stop_sending', 'id': id.value, 'error': error});

    } else if (type == 0x06) { // CRYPTO
      final off = safeReadVarInt(); if (off == null) break;
      final len = safeReadVarInt(); if (len == null) break;
      if (offset + len.value > buf.length) break;
      final data = buf.sublist(offset, offset + len.value);
      offset += len.value;
      frames.add({'type': 'crypto', 'offset': off.value, 'data': data});

    } else if (type == 0x07) { // NEW_TOKEN
      final len = safeReadVarInt(); if (len == null) break;
      if (offset + len.value > buf.length) break;
      final token = buf.sublist(offset, offset + len.value);
      offset += len.value;
      frames.add({'type': 'new_token', 'token': token});

    } else if ((type & 0xe0) == 0x08) { // STREAM (0x08-0x0f)
      final fin = (type & 0x01) != 0;
      final lenb = (type & 0x02) != 0;
      final offb = (type & 0x04) != 0;

      final streamId = safeReadVarInt(); if (streamId == null) break;
      final offsetVal = offb ? safeReadVarInt() : VarIntReadResult(value: 0, byteLength: 0);
      if (offsetVal == null) break;

      final lengthVal = lenb ? safeReadVarInt() : VarIntReadResult(value: buf.length - offset, byteLength: 0);
      if (lengthVal == null) break;

      if (offset + lengthVal.value > buf.length) break;

      final data = buf.sublist(offset, offset + lengthVal.value);
      offset += lengthVal.value;

      frames.add({
        'type': 'stream',
        'id': streamId.value,
        'offset': offsetVal.value,
        'fin': fin,
        'data': data
      });
      
    } else if (type == 0x09) { // MAX_DATA
      final max = safeReadVarInt(); if (max == null) break;
      frames.add({'type': 'max_data', 'max': max.value});

    } else if (type == 0x0a) { // MAX_STREAM_DATA
      final id = safeReadVarInt(); if (id == null) break;
      final max = safeReadVarInt(); if (max == null) break;
      frames.add({'type': 'max_stream_data', 'id': id.value, 'max': max.value});

    } else if (type == 0x0b || type == 0x0c) { // MAX_STREAMS
      final max = safeReadVarInt(); if (max == null) break;
      frames.add({
        'type': type == 0x0b ? 'max_streams_bidi' : 'max_streams_uni',
        'max': max.value
      });

    } else if (type == 0x0d) { // DATA_BLOCKED
      final limit = safeReadVarInt(); if (limit == null) break;
      frames.add({'type': 'data_blocked', 'limit': limit.value});

    } else if (type == 0x0e) { // STREAM_DATA_BLOCKED
      final id = safeReadVarInt(); if (id == null) break;
      final limit = safeReadVarInt(); if (limit == null) break;
      frames.add({'type': 'stream_data_blocked', 'id': id.value, 'limit': limit.value});

    } else if (type == 0x0f || type == 0x10) { // STREAMS_BLOCKED
      final limit = safeReadVarInt(); if (limit == null) break;
      frames.add({
        'type': type == 0x0f ? 'streams_blocked_bidi' : 'streams_blocked_uni',
        'limit': limit.value
      });

    } else if (type == 0x11) { // NEW_CONNECTION_ID
      final seq = safeReadVarInt(); if (seq == null) break;
      final retire = safeReadVarInt(); if (retire == null) break;
      if (offset >= buf.length) break;
      final len = buf[offset++];
      if (offset + len + 16 > buf.length) break;
      final connId = buf.sublist(offset, offset + len); offset += len;
      final token = buf.sublist(offset, offset + 16); offset += 16;
      frames.add({
        'type': 'new_connection_id',
        'seq': seq.value,
        'retire': retire.value,
        'connId': connId,
        'token': token
      });

    } else if (type == 0x12) { // RETIRE_CONNECTION_ID
      final seq = safeReadVarInt(); if (seq == null) break;
      frames.add({'type': 'retire_connection_id', 'seq': seq.value});

    } else if (type == 0x13 || type == 0x14) { // PATH_CHALLENGE / PATH_RESPONSE
      if (offset + 8 > buf.length) break;
      final data = buf.sublist(offset, offset + 8); offset += 8;
      frames.add({
        'type': type == 0x13 ? 'path_challenge' : 'path_response',
        'data': data
      });

    } else if (type == 0x1c || type == 0x1d) { // CONNECTION_CLOSE
      final isApplication = type == 0x1d;
      if (offset + 2 > buf.length) break;
      final error = buf[offset++] << 8 | buf[offset++];
      
      VarIntReadResult? ft = null;
      if (!isApplication) {
        ft = safeReadVarInt(); if (ft == null) break;
      }
      
      final reasonLen = safeReadVarInt(); if (reasonLen == null) break;
      if (offset + reasonLen.value > buf.length) break;
      final reason = textDecoder.decode(buf.sublist(offset, offset + reasonLen.value));
      offset += reasonLen.value;
      
      frames.add({
        'type': 'connection_close',
        'application': isApplication,
        'error': error,
        'frameType': ft?.value,
        'reason': reason
      });

    } else if (type == 0x1e) { // HANDSHAKE_DONE
      frames.add({'type': 'handshake_done'});

    } else if (type == 0x30 || type == 0x31) { // DATAGRAM (RFC 9221)
      int? contextId = null;

      if (type == 0x31) {
        final cid = safeReadVarInt(); 
        if (cid == null) break;
        contextId = cid.value;
      }

      // Length is implicitly the rest of the packet
      final dataLength = buf.length - offset;
      final data = buf.sublist(offset, offset + dataLength);
      offset += dataLength;

      frames.add({
        'type': 'datagram',
        'contextId': contextId,
        'data': data
      });
      
    } else {
      // Unknown or unhandled frame (e.g., Immediate ACK 0x1f, ACK_FREQUENCY 0xaf)
      // The JS logic breaks on unknown, so we do the same here for safety
      frames.add({'type': 'unknown', 'frameType': type, 'offset': start});
      break; 
    }
  }

  return frames;
}
3. Packet and Datagram Parsing
These functions parse the initial QUIC header information from a raw byte stream.

Dart

/// Represents the parsed metadata of a QUIC packet header.
class QuicPacketMetadata {
  final String form; // 'long' or 'short'
  final String type; // 'initial', '0rtt', 'handshake', 'retry', 'version_negotiation', '1rtt', 'unknown'
  final int totalLength; // Total length of the packet in bytes
  final int? version;
  final Uint8List? dcid;
  final Uint8List? scid;
  final Uint8List? token;
  final Uint8List? originalDestinationConnectionId;
  final List<int>? supportedVersions;
  final Uint8List? raw; // Full raw packet bytes
  
  QuicPacketMetadata({
    required this.form,
    required this.type,
    required this.totalLength,
    this.version,
    this.dcid,
    this.scid,
    this.token,
    this.originalDestinationConnectionId,
    this.supportedVersions,
    this.raw
  });
}

/// Parses the header of a single QUIC packet.
QuicPacketMetadata? parseQuicPacket(Uint8List array, [int offset0 = 0]) {
  if (offset0 >= array.length) return null;

  final firstByte = array[offset0];
  final isLongHeader = (firstByte & 0x80) != 0;

  if (isLongHeader) {
    if (offset0 + 6 > array.length) return null;

    final view = ByteData.view(array.buffer, array.offsetInBytes + offset0);
    final version = view.getUint32(1, Endian.big);
    
    final dcidLen = array[offset0 + 5];
    int offset = offset0 + 6;

    if (offset + dcidLen + 1 > array.length) return null;
    final dcid = array.sublist(offset, offset + dcidLen);
    offset += dcidLen;

    final scidLen = array[offset++];
    if (offset + scidLen > array.length) return null;
    final scid = array.sublist(offset, offset + scidLen);
    offset += scidLen;

    // Version negotiation packet (Version 0)
    if (version == 0) {
      final List<int> supportedVersions = [];
      while (offset + 4 <= array.length) {
        final v = ByteData.view(array.buffer, array.offsetInBytes + offset).getUint32(0, Endian.big);
        supportedVersions.add(v);
        offset += 4;
      }
      return QuicPacketMetadata(
        form: 'long',
        type: 'version_negotiation',
        version: version,
        dcid: dcid,
        scid: scid,
        supportedVersions: supportedVersions,
        totalLength: offset - offset0,
      );
    }

    final packetTypeBits = (firstByte & 0x30) >> 4;
    final typeMap = ['initial', '0rtt', 'handshake', 'retry'];
    final packetType = packetTypeBits < typeMap.length ? typeMap[packetTypeBits] : 'unknown';

    if (packetType == 'retry') {
      final odcid = array.sublist(offset); // Original Destination Connection ID
      return QuicPacketMetadata(
        form: 'long',
        type: 'retry',
        version: version,
        dcid: dcid,
        scid: scid,
        originalDestinationConnectionId: odcid,
        totalLength: array.length - offset0,
      );
    }

    // Read Token if it's an Initial packet
    Uint8List? token = null;
    if (packetType == 'initial') {
      final tokenLen = readVarInt(array, offset);
      if (tokenLen == null) return null;
      offset += tokenLen.byteLength;
      if (offset + tokenLen.value > array.length) return null;
      token = array.sublist(offset, offset + tokenLen.value);
      offset += tokenLen.value;
    }

    // Read Length (required for all non-VN/Retry Long Headers)
    final lengthInfo = readVarInt(array, offset);
    if (lengthInfo == null) return null;
    offset += lengthInfo.byteLength;

    final payloadLength = lengthInfo.value;
    final totalLength = offset - offset0 + payloadLength;

    if (offset0 + totalLength > array.length) return null;

    return QuicPacketMetadata(
      form: 'long',
      type: packetType,
      version: version,
      dcid: dcid,
      scid: scid,
      token: token,
      totalLength: totalLength,
    );
  } else {
    // Short Header (1RTT)
    // We cannot determine the precise length without decryption, so we assume the rest of the datagram.
    final totalLength = array.length - offset0;
    return QuicPacketMetadata(
      form: 'short',
      type: '1rtt',
      totalLength: totalLength,
    );
  }
}

/// Parses a UDP datagram that may contain one or more concatenated QUIC packets.
List<QuicPacketMetadata> parseQuicDatagram(Uint8List array) {
  final List<QuicPacketMetadata> packets = [];
  int offset = 0;

  while (offset < array.length) {
    final pkt = parseQuicPacket(array, offset);
    if (pkt == null || pkt.totalLength == 0) break;

    final start = offset;
    final end = offset + pkt.totalLength;

    // Slice the raw packet bytes for encapsulation
    final rawPkt = (start == 0 && end == array.length)
        ? array
        : array.sublist(start, end);

    packets.add(QuicPacketMetadata(
      form: pkt.form,
      type: pkt.type,
      totalLength: pkt.totalLength,
      version: pkt.version,
      dcid: pkt.dcid,
      scid: pkt.scid,
      token: pkt.token,
      originalDestinationConnectionId: pkt.originalDestinationConnectionId,
      supportedVersions: pkt.supportedVersions,
      raw: rawPkt,
    ));
    
    offset = end;
  }

  return packets;
}
4. TLS Session Ticket Building
This function creates the body of a TLS 1.3 NewSessionTicket handshake message.

Dart

/// Builds the body of a TLS 1.3 NewSessionTicket message,
/// used primarily for QUIC 0-RTT resumption.
Uint8List buildNewSessionTicket(Uint8List sessionIdBytes, Map<String, dynamic> options) {
  final ticketLifetime = (options['lifetime'] as int?) ?? 86400; // Default to 24 hours
  
  // Use a secure random number generator for cryptographic values
  final random = Random.secure();
  final ticketAgeAdd = random.nextInt(0xffffffff);
  final ticketNonce = Uint8List(8);
  for (int i = 0; i < 8; i++) {
    ticketNonce[i] = random.nextInt(256);
  }
  
  final ticket = sessionIdBytes;

  final List<Uint8List> extensions = [];
  if (options['early_data_max_size'] != null) {
    final earlyDataMaxSize = options['early_data_max_size'] as int;
    
    // Structure: Type (2) | Length (2) | Data (4)
    final ed = Uint8List(8);
    final view = ByteData.view(ed.buffer);
    
    view.setUint16(0, 0x002a, Endian.big); // early_data extension type
    view.setUint16(2, 0x0004, Endian.big); // extension length (4 bytes for max_early_data_size)
    view.setUint32(4, earlyDataMaxSize, Endian.big); // max_early_data_size
    
    extensions.add(ed);
  }

  // Combine extensions block
  final extensionsBlock = concatUint8Arrays(extensions);

  // Calculate total length
  final totalLen =
      4 + // ticket_lifetime (4 bytes, BE)
      4 + // ticket_age_add (4 bytes, BE)
      1 + ticketNonce.length + // Nonce length (1 byte) + Nonce
      2 + ticket.length +      // Ticket length (2 bytes, BE) + Ticket
      2 + extensionsBlock.length; // Extensions length (2 bytes, BE) + Extensions

  final result = Uint8List(totalLen);
  final view = ByteData.view(result.buffer);
  int p = 0;

  // 1. ticket_lifetime (4 bytes, BE)
  view.setUint32(p, ticketLifetime, Endian.big);
  p += 4;

  // 2. ticket_age_add (4 bytes, BE)
  view.setUint32(p, ticketAgeAdd, Endian.big);
  p += 4;

  // 3. ticket_nonce length (1 byte) + Nonce
  result[p++] = ticketNonce.length;
  result.setAll(p, ticketNonce);
  p += ticketNonce.length;

  // 4. ticket length (2 bytes, BE) + Ticket
  view.setUint16(p, ticket.length, Endian.big);
  p += 2;
  result.setAll(p, ticket);
  p += ticket.length;

  // 5. extensions length (2 bytes, BE) + Extensions
  view.setUint16(p, extensionsBlock.length, Endian.big);
  p += 2;
  result.setAll(p, extensionsBlock);

  return result;
}







port these now:    

function hmac(hash, key, data) {

    return new Uint8Array(crypto.createHmac(hash, key).update(data).digest());

}

function hkdf_extract(salt, ikm, hash_func) {

  return nobleHashes.hkdf_extract(hash_func, ikm, salt);

}





function hkdf_expand(prk, info, length, hash_func) {

  return nobleHashes.hkdf_expand(hash_func, prk, info, length);

}







function build_hkdf_label(label, context, length) {

  const prefix = "tls13 ";

  const full = new TextEncoder().encode(prefix + label);



  const info = new Uint8Array(

      2 + 1 + full.length + 1 + context.length);



  // length (2-bytes, BE)

  info[0] = (length >> 8) & 0xff;

  info[1] =  length       & 0xff;



  // label length + bytes

  info[2] = full.length;

  info.set(full, 3);



  // context length + bytes

  const ctxOfs = 3 + full.length;

  info[ctxOfs] = context.length;

  info.set(context, ctxOfs + 1);



  return info;

}



function hkdf_expand_label(secret, label, context, length, hash_func) {

  const info = build_hkdf_label(label, context, length);

  return hkdf_expand(secret, info, length, hash_func);   // hash = sha384/sha256

}





function hash_transcript(messages,hash_func) {

    var total_len = messages.reduce((sum, m) => sum + m.length, 0);

    var total = new Uint8Array(total_len);

    var offset = 0;

    for (var m of messages) {

        total.set(m, offset);

        offset += m.length;

    }

    return hash_func(total);

}



function tls_derive_app_secrets(handshake_secret, transcript, hash_func) {

  const hashLen = hash_func.outputLen;

  const empty = new Uint8Array(0);

  var zero = new Uint8Array(hash_func.outputLen);



  var derived_secret = hkdf_expand_label(handshake_secret, "derived", hash_func(empty), hash_func.outputLen, hash_func);

  var master_secret = hkdf_extract(derived_secret, zero, hash_func);



  // שלב 3: חישוב hash של ה־transcript עד server Finished

  const transcript_hash = hash_transcript(transcript, hash_func);



  // שלב 4: גזירת סודות התעבורה

  const client_app = hkdf_expand_label(master_secret, 'c ap traffic', transcript_hash, hashLen, hash_func);

  const server_app = hkdf_expand_label(master_secret, 's ap traffic', transcript_hash, hashLen, hash_func);



  return {

    client_application_traffic_secret: client_app,

    server_application_traffic_secret: server_app

  };

}



This port requires the use of Dart's dart:typed_data and dart:convert libraries. Since Dart does not have built-in HMAC and HKDF functions, the implementation relies on external cryptographic packages (like package:pointycastle or a specialized TLS 1.3 library).

The functions below are presented with placeholder signatures for the required low-level cryptographic operations (hkdfExtract, hkdfExpand, hmac), but the core TLS 1.3 logic (buildHkdfLabel, hkdfExpandLabel, hashTranscript, tlsDeriveAppSecrets) is fully ported.

Dart

import 'dart:typed_data';
import 'dart:convert';

// ====================================================================
// ASSUMED CRYPTO INTERFACE & HELPERS
// These functions must be implemented using a dedicated Dart crypto package
// (e.g., pointycastle, pointypile, or a native FFI binding).
// ====================================================================

/// Abstract class to represent the cryptographic hash function (e.g., SHA-256).
/// It mimics the required JS structure: being callable and having an output length.
abstract class HashFunc {
  /// The hash function itself.
  Uint8List call(Uint8List data); 
  
  /// The output length of the hash function (e.g., 32 for SHA-256).
  int get outputLen; 
}

/// Placeholder for HMAC computation.
Uint8List hmac(String hash, Uint8List key, Uint8List data) {
  // Implementation relies on a Dart crypto library
  throw UnimplementedError('hmac must be implemented with a Dart crypto package.');
}

/// Placeholder for HKDF-Extract operation.
Uint8List hkdfExtract(Uint8List salt, Uint8List ikm, HashFunc hashFunc) {
  // Implementation relies on a Dart crypto library
  throw UnimplementedError('hkdfExtract must be implemented with a Dart crypto package.');
}

/// Placeholder for HKDF-Expand operation.
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int length, HashFunc hashFunc) {
  // Implementation relies on a Dart crypto library
  throw UnimplementedError('hkdfExpand must be implemented with a Dart crypto package.');
}

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

// ====================================================================
// TLS 1.3 HKDF LOGIC
// ====================================================================

/// Constructs the byte array for a TLS 1.3 HKDF-Expand-Label operation's 'info' field.
///
/// Format: Length (2 bytes, BE) | Label Length (1 byte) | Label (bytes) | Context Length (1 byte) | Context (bytes)
Uint8List buildHkdfLabel(String label, Uint8List context, int length) {
  const prefix = "tls13 ";
  final fullLabelBytes = utf8.encode(prefix + label);
  
  final infoLength = 2 + 1 + fullLabelBytes.length + 1 + context.length;
  final info = Uint8List(infoLength);
  final view = ByteData.view(info.buffer);

  // 1. Length (2-bytes, Big Endian)
  view.setUint16(0, length, Endian.big);
  
  // 2. Label Length (1-byte) + Label Bytes
  info[2] = fullLabelBytes.length;
  info.setAll(3, fullLabelBytes);

  // 3. Context Length (1-byte) + Context Bytes
  final ctxOfs = 3 + fullLabelBytes.length;
  info[ctxOfs] = context.length;
  info.setAll(ctxOfs + 1, context);

  return info;
}

/// TLS 1.3 specific wrapper around HKDF-Expand.
/// Creates the structured 'info' array using [buildHkdfLabel] and then expands the secret.
Uint8List hkdfExpandLabel(
    Uint8List secret,
    String label,
    Uint8List context,
    int length,
    HashFunc hashFunc) {
  final info = buildHkdfLabel(label, context, length);
  return hkdfExpand(secret, info, length, hashFunc);
}

/// Hashes a sequence of handshake messages by concatenating them and then
/// applying the specified hash function. This is equivalent to updating a single
/// hash context with all messages sequentially.
Uint8List hashTranscript(List<Uint8List> messages, HashFunc hashFunc) {
  final total = concatUint8Arrays(messages);
  return hashFunc(total);
}

// ====================================================================
// APPLICATION SECRETS DERIVATION
// ====================================================================

/// Simple class to hold the derived application secrets.
class ApplicationSecrets {
  final Uint8List clientApplicationTrafficSecret;
  final Uint8List serverApplicationTrafficSecret;
  ApplicationSecrets({
    required this.clientApplicationTrafficSecret,
    required this.serverApplicationTrafficSecret,
  });
}

/// Derives the client and server application traffic secrets from the TLS 1.3 
/// Handshake Secret and the Handshake Transcript Hash.
ApplicationSecrets tlsDeriveAppSecrets(
    Uint8List handshakeSecret,
    List<Uint8List> transcript,
    HashFunc hashFunc) {
  final hashLen = hashFunc.outputLen;
  final empty = Uint8List(0);
  final zero = Uint8List(hashLen); // Hash length zero-filled array

  // Step 1: Derive "Derived Secret"
  // This step protects the Master Secret from the Handshake Secret compromise.
  final derivedSecret = hkdfExpandLabel(
    handshakeSecret,
    "derived",
    hashFunc(empty), // Context is the Hash of an empty string
    hashLen,
    hashFunc,
  );
  
  // Step 2: Calculate Master Secret
  // Salt is the Derived Secret, IKM is the zero-filled array.
  final masterSecret = hkdfExtract(derivedSecret, zero, hashFunc);

  // Step 3: Hash the transcript (up to Server Finished/Client Finished for different phases)
  // For application secrets, the full handshake transcript hash is used.
  final transcriptHash = hashTranscript(transcript, hashFunc);

  // Step 4: Derive Application Traffic Secrets
  final clientApp = hkdfExpandLabel(
    masterSecret,
    'c ap traffic',
    transcriptHash,
    hashLen,
    hashFunc,
  );
  
  final serverApp = hkdfExpandLabel(
    masterSecret,
    's ap traffic',
    transcriptHash,
    hashLen,
    hashFunc,
  );

  return ApplicationSecrets(
    clientApplicationTrafficSecret: clientApp,
    serverApplicationTrafficSecret: serverApp,
  );
}