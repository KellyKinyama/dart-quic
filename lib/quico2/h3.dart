/*
 * quico: HTTP/3 and QUIC implementation for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the open-source project hosted at:
 *     https://github.com/colocohen/quico
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'dart:typed_data';
import 'dart:convert';
import 'utils.dart';

import 'crypto.dart';

var huffman_codes = Uint8List.fromList([
  0x1ff8, //(0)
  0x7fffd8, //(1)
  0xfffffe2, //(2)
  0xfffffe3, //(3)
  0xfffffe4, //(4)
  0xfffffe5, //(5)
  0xfffffe6, //(6)
  0xfffffe7, //(7)
  0xfffffe8, //(8)
  0xffffea, //(9)
  0x3ffffffc, //(10)
  0xfffffe9, //(11)
  0xfffffea, //(12)
  0x3ffffffd, //(13)
  0xfffffeb, //(14)
  0xfffffec, //(15)
  0xfffffed, //(16)
  0xfffffee, //(17)
  0xfffffef, //(18)
  0xffffff0, //(19)
  0xffffff1, //(20)
  0xffffff2, //(21)
  0x3ffffffe, //(22)
  0xffffff3, //(23)
  0xffffff4, //(24)
  0xffffff5, //(25)
  0xffffff6, //(26)
  0xffffff7, //(27)
  0xffffff8, //(28)
  0xffffff9, //(29)
  0xffffffa, //(30)
  0xffffffb, //(31)
  0x14, //' ' (32)
  0x3f8, //'!' (33)
  0x3f9, //'"' (34)
  0xffa, //'#' (35)
  0x1ff9, //'$' (36)
  0x15, //'%' (37)
  0xf8, //'&' (38)
  0x7fa, //''' (39)
  0x3fa, //'(' (40)
  0x3fb, //')' (41)
  0xf9, //'*' (42)
  0x7fb, //'+' (43)
  0xfa, //',' (44)
  0x16, //'-' (45)
  0x17, //'.' (46)
  0x18, //'/' (47)
  0x0, //'0' (48)
  0x1, //'1' (49)
  0x2, //'2' (50)
  0x19, //'3' (51)
  0x1a, //'4' (52)
  0x1b, //'5' (53)
  0x1c, //'6' (54)
  0x1d, //'7' (55)
  0x1e, //'8' (56)
  0x1f, //'9' (57)
  0x5c, //':' (58)
  0xfb, //';' (59)
  0x7ffc, //'<' (60)
  0x20, //'=' (61)
  0xffb, //'>' (62)
  0x3fc, //'?' (63)
  0x1ffa, //'@' (64)
  0x21, //'A' (65)
  0x5d, //'B' (66)
  0x5e, //'C' (67)
  0x5f, //'D' (68)
  0x60, //'E' (69)
  0x61, //'F' (70)
  0x62, //'G' (71)
  0x63, //'H' (72)
  0x64, //'I' (73)
  0x65, //'J' (74)
  0x66, //'K' (75)
  0x67, //'L' (76)
  0x68, //'M' (77)
  0x69, //'N' (78)
  0x6a, //'O' (79)
  0x6b, //'P' (80)
  0x6c, //'Q' (81)
  0x6d, //'R' (82)
  0x6e, //'S' (83)
  0x6f, //'T' (84)
  0x70, //'U' (85)
  0x71, //'V' (86)
  0x72, //'W' (87)
  0xfc, //'X' (88)
  0x73, //'Y' (89)
  0xfd, //'Z' (90)
  0x1ffb, //'[' (91)
  0x7fff0, //'\' (92)
  0x1ffc, //']' (93)
  0x3ffc, //'^' (94)
  0x22, //'_' (95)
  0x7ffd, //'`' (96)
  0x3, //'a' (97)
  0x23, //'b' (98)
  0x4, //'c' (99)
  0x24, //'d' (100)
  0x5, //'e' (101)
  0x25, //'f' (102)
  0x26, //'g' (103)
  0x27, //'h' (104)
  0x6, //'i' (105)
  0x74, //'j' (106)
  0x75, //'k' (107)
  0x28, //'l' (108)
  0x29, //'m' (109)
  0x2a, //'n' (110)
  0x7, //'o' (111)
  0x2b, //'p' (112)
  0x76, //'q' (113)
  0x2c, //'r' (114)
  0x8, //'s' (115)
  0x9, //'t' (116)
  0x2d, //'u' (117)
  0x77, //'v' (118)
  0x78, //'w' (119)
  0x79, //'x' (120)
  0x7a, //'y' (121)
  0x7b, //'z' (122)
  0x7ffe, //'{' (123)
  0x7fc, //'|' (124)
  0x3ffd, //'}' (125)
  0x1ffd, //'~' (126)
  0xffffffc, //(127)
  0xfffe6, //(128)
  0x3fffd2, //(129)
  0xfffe7, //(130)
  0xfffe8, //(131)
  0x3fffd3, //(132)
  0x3fffd4, //(133)
  0x3fffd5, //(134)
  0x7fffd9, //(135)
  0x3fffd6, //(136)
  0x7fffda, //(137)
  0x7fffdb, //(138)
  0x7fffdc, //(139)
  0x7fffdd, //(140)
  0x7fffde, //(141)
  0xffffeb, //(142)
  0x7fffdf, //(143)
  0xffffec, //(144)
  0xffffed, //(145)
  0x3fffd7, //(146)
  0x7fffe0, //(147)
  0xffffee, //(148)
  0x7fffe1, //(149)
  0x7fffe2, //(150)
  0x7fffe3, //(151)
  0x7fffe4, //(152)
  0x1fffdc, //(153)
  0x3fffd8, //(154)
  0x7fffe5, //(155)
  0x3fffd9, //(156)
  0x7fffe6, //(157)
  0x7fffe7, //(158)
  0xffffef, //(159)
  0x3fffda, //(160)
  0x1fffdd, //(161)
  0xfffe9, //(162)
  0x3fffdb, //(163)
  0x3fffdc, //(164)
  0x7fffe8, //(165)
  0x7fffe9, //(166)
  0x1fffde, //(167)
  0x7fffea, //(168)
  0x3fffdd, //(169)
  0x3fffde, //(170)
  0xfffff0, //(171)
  0x1fffdf, //(172)
  0x3fffdf, //(173)
  0x7fffeb, //(174)
  0x7fffec, //(175)
  0x1fffe0, //(176)
  0x1fffe1, //(177)
  0x3fffe0, //(178)
  0x1fffe2, //(179)
  0x7fffed, //(180)
  0x3fffe1, //(181)
  0x7fffee, //(182)
  0x7fffef, //(183)
  0xfffea, //(184)
  0x3fffe2, //(185)
  0x3fffe3, //(186)
  0x3fffe4, //(187)
  0x7ffff0, //(188)
  0x3fffe5, //(189)
  0x3fffe6, //(190)
  0x7ffff1, //(191)
  0x3ffffe0, //(192)
  0x3ffffe1, //(193)
  0xfffeb, //(194)
  0x7fff1, //(195)
  0x3fffe7, //(196)
  0x7ffff2, //(197)
  0x3fffe8, //(198)
  0x1ffffec, //(199)
  0x3ffffe2, //(200)
  0x3ffffe3, //(201)
  0x3ffffe4, //(202)
  0x7ffffde, //(203)
  0x7ffffdf, //(204)
  0x3ffffe5, //(205)
  0xfffff1, //(206)
  0x1ffffed, //(207)
  0x7fff2, //(208)
  0x1fffe3, //(209)
  0x3ffffe6, //(210)
  0x7ffffe0, //(211)
  0x7ffffe1, //(212)
  0x3ffffe7, //(213)
  0x7ffffe2, //(214)
  0xfffff2, //(215)
  0x1fffe4, //(216)
  0x1fffe5, //(217)
  0x3ffffe8, //(218)
  0x3ffffe9, //(219)
  0xffffffd, //(220)
  0x7ffffe3, //(221)
  0x7ffffe4, //(222)
  0x7ffffe5, //(223)
  0xfffec, //(224)
  0xfffff3, //(225)
  0xfffed, //(226)
  0x1fffe6, //(227)
  0x3fffe9, //(228)
  0x1fffe7, //(229)
  0x1fffe8, //(230)
  0x7ffff3, //(231)
  0x3fffea, //(232)
  0x3fffeb, //(233)
  0x1ffffee, //(234)
  0x1ffffef, //(235)
  0xfffff4, //(236)
  0xfffff5, //(237)
  0x3ffffea, //(238)
  0x7ffff4, //(239)
  0x3ffffeb, //(240)
  0x7ffffe6, //(241)
  0x3ffffec, //(242)
  0x3ffffed, //(243)
  0x7ffffe7, //(244)
  0x7ffffe8, //(245)
  0x7ffffe9, //(246)
  0x7ffffea, //(247)
  0x7ffffeb, //(248)
  0xffffffe, //(249)
  0x7ffffec, //(250)
  0x7ffffed, //(251)
  0x7ffffee, //(252)
  0x7ffffef, //(253)
  0x7fffff0, //(254)
  0x3ffffee, //(255)
  0x3fffffff, //EOS (256)
]);

var huffman_bits = Uint8List.fromList([
  13,
  23,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  24,
  30,
  28,
  28,
  30,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  30,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  6,
  10,
  10,
  12,
  13,
  6,
  8,
  11,
  10,
  10,
  8,
  11,
  8,
  6,
  6,
  6,
  5,
  5,
  5,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  7,
  8,
  15,
  6,
  12,
  10,
  13,
  6,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  8,
  7,
  8,
  13,
  19,
  13,
  14,
  6,
  15,
  5,
  6,
  5,
  6,
  5,
  6,
  6,
  6,
  5,
  7,
  7,
  6,
  6,
  6,
  5,
  6,
  7,
  6,
  5,
  5,
  6,
  7,
  7,
  7,
  7,
  7,
  15,
  11,
  14,
  13,
  28,
  20,
  22,
  20,
  20,
  22,
  22,
  22,
  23,
  22,
  23,
  23,
  23,
  23,
  23,
  24,
  23,
  24,
  24,
  22,
  23,
  24,
  23,
  23,
  23,
  23,
  21,
  22,
  23,
  22,
  23,
  23,
  24,
  22,
  21,
  20,
  22,
  22,
  23,
  23,
  21,
  23,
  22,
  22,
  24,
  21,
  22,
  23,
  23,
  21,
  21,
  22,
  21,
  23,
  22,
  23,
  23,
  20,
  22,
  22,
  22,
  23,
  22,
  22,
  23,
  26,
  26,
  20,
  19,
  22,
  23,
  22,
  25,
  26,
  26,
  26,
  27,
  27,
  26,
  24,
  25,
  19,
  21,
  26,
  27,
  27,
  26,
  27,
  24,
  21,
  21,
  26,
  26,
  28,
  27,
  27,
  27,
  20,
  24,
  20,
  21,
  22,
  21,
  21,
  23,
  22,
  22,
  25,
  25,
  24,
  24,
  26,
  23,
  26,
  27,
  26,
  26,
  27,
  27,
  27,
  27,
  27,
  28,
  27,
  27,
  27,
  27,
  27,
  26,
  30,
]);

Map buildHuffmanDecodeTrie() {
  Map root = {};

  for (var i = 0; i < huffman_codes.length; i++) {
    var code = huffman_codes[i];
    var length = huffman_bits[i];
    var node = root;

    for (var j = length - 1; j >= 0; j--) {
      var bit = (code >> j) & 1;

      // In Dart, we use containsKey or null check for Map access
      if (node[bit] == null) {
        node[bit] = {};
      }
      node = node[bit];
    }

    // Assigning the symbol to the leaf node
    node['symbol'] = i;
  }

  return root;
}

var huffman_flat_decode_tables = buildHuffmanDecodeTrie();

var qpack_static_table_entries = [
  [":authority", ""],
  [":path", "/"],
  ["age", "0"],
  ["content-disposition", ""],
  ["content-length", "0"],
  ["cookie", ""],
  ["date", ""],
  ["etag", ""],
  ["if-modified-since", ""],
  ["if-none-match", ""],
  ["last-modified", ""],
  ["link", ""],
  ["location", ""],
  ["referer", ""],
  ["set-cookie", ""],
  [":method", "CONNECT"],
  [":method", "DELETE"],
  [":method", "GET"],
  [":method", "HEAD"],
  [":method", "OPTIONS"],
  [":method", "POST"],
  [":method", "PUT"],
  [":scheme", "http"],
  [":scheme", "https"],
  [":status", "103"],
  [":status", "200"],
  [":status", "304"],
  [":status", "404"],
  [":status", "503"],
  ["accept", "*/*"],
  ["accept", "application/dns-message"],
  ["accept-encoding", "gzip, deflate, br"],
  ["accept-ranges", "bytes"],
  ["access-control-allow-headers", "cache-control"],
  ["access-control-allow-headers", "content-type"],
  ["access-control-allow-origin", "*"],
  ["cache-control", "max-age=0"],
  ["cache-control", "max-age=2592000"],
  ["cache-control", "max-age=604800"],
  ["cache-control", "no-cache"],
  ["cache-control", "no-store"],
  ["cache-control", "public, max-age=31536000"],
  ["content-encoding", "br"],
  ["content-encoding", "gzip"],
  ["content-type", "application/dns-message"],
  ["content-type", "application/javascript"],
  ["content-type", "application/json"],
  ["content-type", "application/x-www-form-urlencoded"],
  ["content-type", "image/gif"],
  ["content-type", "image/jpeg"],
  ["content-type", "image/png"],
  ["content-type", "text/css"],
  ["content-type", "text/html; charset=utf-8"],
  ["content-type", "text/plain"],
  ["content-type", "text/plain;charset=utf-8"],
  ["range", "bytes=0-"],
  ["strict-transport-security", "max-age=31536000"],
  ["strict-transport-security", "max-age=31536000; includesubdomains"],
  ["strict-transport-security", "max-age=31536000; includesubdomains; preload"],
  ["vary", "accept-encoding"],
  ["vary", "origin"],
  ["x-content-type-options", "nosniff"],
  ["x-xss-protection", "1; mode=block"],
  [":status", "100"],
  [":status", "204"],
  [":status", "206"],
  [":status", "302"],
  [":status", "400"],
  [":status", "403"],
  [":status", "421"],
  [":status", "425"],
  [":status", "500"],
  ["accept-language", ""],
  ["access-control-allow-credentials", "FALSE"],
  ["access-control-allow-credentials", "TRUE"],
  ["access-control-allow-headers", "*"],
  ["access-control-allow-methods", "get"],
  ["access-control-allow-methods", "get, post, options"],
  ["access-control-allow-methods", "options"],
  ["access-control-expose-headers", "content-length"],
  ["access-control-request-headers", "content-type"],
  ["access-control-request-method", "get"],
  ["access-control-request-method", "post"],
  ["alt-svc", "clear"],
  ["authorization", ""],
  [
    "content-security-policy",
    "script-src 'none'; object-src 'none'; base-uri 'none'",
  ],
  ["early-data", "1"],
  ["expect-ct", ""],
  ["forwarded", ""],
  ["if-range", ""],
  ["origin", ""],
  ["purpose", "prefetch"],
  ["server", ""],
  ["timing-allow-origin", "*"],
  ["upgrade-insecure-requests", "1"],
  ["user-agent", ""],
  ["x-forwarded-for", ""],
  ["x-frame-options", "deny"],
  ["x-frame-options", "sameorigin"],
];

Map<String, dynamic> decodeVarInt(Uint8List buf, int prefixBits, int pos) {
  final int maxPrefix = (1 << prefixBits) - 1;
  int byte = buf[pos];
  int value = byte & maxPrefix;
  pos++;

  if (value < maxPrefix) {
    // נגמר במרווח-הבייט הראשון
    return {'value': value, 'next': pos};
  }

  int m = 0;
  while (true) {
    byte = buf[pos++];
    value += (byte & 0x7f) << m;
    if ((byte & 0x80) == 0) break;
    m += 7;
  }

  return {'value': value, 'next': pos};
}

Uint8List huffmanEncode(String text) {
  // Convert String to UTF-8 bytes
  List<int> input = utf8.encode(text);
  int bitBuffer = 0;
  int bitLen = 0;
  List<int> output = [];

  for (var i = 0; i < input.length; i++) {
    int sym = input[i];
    int code = huffman_codes[sym];
    int nbits = huffman_bits[sym];

    // Append the Huffman code to the buffer
    bitBuffer = (bitBuffer << nbits) | code;
    bitLen += nbits;

    // While we have at least one full byte (8 bits)
    while (bitLen >= 8) {
      bitLen -= 8;
      // Extract the high 8 bits
      output.add((bitBuffer >> bitLen) & 0xff);
      // Keep only the remaining bits in the buffer to prevent overflow
      bitBuffer &= (1 << bitLen) - 1;
    }
  }

  // Padding: According to HPACK/QPACK spec, fill with 1s
  if (bitLen > 0) {
    int paddingSize = 8 - bitLen;
    bitBuffer = (bitBuffer << paddingSize) | ((1 << paddingSize) - 1);
    output.add(bitBuffer & 0xff);
  }

  return Uint8List.fromList(output);
}

String decodeHuffman(Uint8List buf) {
  List<int> output = [];
  // Assuming huffman_flat_decode_tables is the root Map from buildHuffmanDecodeTrie()
  var node = huffman_flat_decode_tables;
  int current = 0;
  int nbits = 0;

  for (var i = 0; i < buf.length; i++) {
    // Add the next byte to our bit buffer
    current = (current << 8) | buf[i];
    nbits += 8;

    while (nbits > 0) {
      // Extract the most significant bit available
      int bit = (current >> (nbits - 1)) & 1;

      // Navigate the trie
      var nextNode = node[bit];
      if (nextNode == null) {
        throw Exception("Invalid Huffman encoding");
      }
      node = nextNode;
      nbits--;

      // Check if we've reached a leaf node (a symbol)
      // Note: We use 'symbol' as the key since it's a Map
      if (node.containsKey('symbol')) {
        int symbol = node['symbol'];

        // 256 is the EOS (End of String) symbol in HPACK/QPACK Huffman
        if (symbol == 256) {
          break;
        }

        output.add(symbol);

        // Reset to the root of the trie for the next symbol
        node = huffman_flat_decode_tables;

        // Optional: Mask the current buffer to keep it clean, though not strictly
        // necessary with the bit-shifting logic above.
        current &= (1 << nbits) - 1;
      }
    }
  }

  // Convert the list of byte symbols back into a String
  return utf8.decode(output);
}

dynamic parse_qpack_header_block(Uint8List buf) {
  int pos = 0;
  final List<Map<String, dynamic>> headers = [];

  // Required Insert Count (prefix-8)
  final ric = decodeVarInt(buf, 8, pos);
  pos = ric['next'];

  // Delta Base (prefix-7 + S-bit)
  final firstDbByte = buf[pos];
  final bool postBase = (firstDbByte & 0x80) != 0; // S-bit
  final db = decodeVarInt(buf, 7, pos);
  pos = db['next'];

  // Base Index = RIC ± DB לפי S-bit
  final int baseIndex = postBase
      ? ric['value'] + db['value']
      : ric['value'] - db['value'];

  // Header Field Lines
  while (pos < buf.length) {
    final byte = buf[pos];

    // A. Indexed Field Line – 1xxxxxxx
    if ((byte & 0x80) == 0x80) {
      final bool fromStatic = (byte & 0x40) != 0; // T-bit
      final idx = decodeVarInt(buf, 6, pos); // prefix-6
      pos = idx['next'];

      headers.add({
        'type': "indexed",
        'from_static_table': fromStatic,
        'index': idx['value'],
      });
      continue;
    }

    // B. Literal With Name Reference – 01xxxxxx
    if ((byte & 0xC0) == 0x40) {
      final bool neverIndexed = (byte & 0x20) != 0; // N-bit
      final bool fromStatic = (byte & 0x10) != 0; // T-bit
      final nameIdx = decodeVarInt(buf, 4, pos); // prefix-4
      pos = nameIdx['next'];

      final bool valH = (buf[pos] & 0x80) != 0; // H-bit
      final valLen = decodeVarInt(buf, 7, pos); // prefix-7
      pos = valLen['next'];

      final valBytes = buf.sublist(pos, (pos + valLen['value']) as int?);
      pos += (valLen['value'] as int);

      final String value = valH
          ? decodeHuffman(valBytes)
          : utf8.decode(valBytes);

      headers.add({
        'type': "literal_with_name_ref",
        'never_indexed': neverIndexed,
        'from_static_table': fromStatic,
        'name_index': nameIdx['value'],
        'value': value,
      });
      continue;
    }

    // C. Literal With Literal Name – 001xxxxx
    if ((byte & 0xE0) == 0x20) {
      final bool neverIndexed = (byte & 0x10) != 0; // N-bit
      final bool nameH = (byte & 0x08) != 0; // H-bit
      final nameLen = decodeVarInt(buf, 3, pos); // prefix-3
      pos = nameLen['next'];

      final nameBytes = buf.sublist(pos, (pos + nameLen['value']) as int?);
      pos += (nameLen['value'] as int);

      final String name = nameH
          ? decodeHuffman(nameBytes)
          : utf8.decode(nameBytes);

      final bool valH = (buf[pos] & 0x80) != 0; // H-bit
      final valLen = decodeVarInt(buf, 7, pos); // prefix-7
      pos = valLen['next'];

      final valBytes = buf.sublist(pos, (pos + valLen['value']) as int?);
      pos += (valLen['value'] as int);

      final String value = valH
          ? decodeHuffman(valBytes)
          : utf8.decode(valBytes);

      headers.add({
        'type': "literal_with_literal_name",
        'never_indexed': neverIndexed,
        'name': name,
        'value': value,
      });
      continue;
    }

    // תקלה לפי התקן
    throw Exception(
      "Unknown header-block instruction at byte $pos (0x${byte.toRadixString(16)})",
    );
  }

  return {
    'insert_count': ric['value'],
    'delta_base': db['value'],
    'post_base': postBase,
    'base_index': baseIndex,
    'headers': headers,
  };
}

Map<String, dynamic> parse_qpack_header_block_old(Uint8List buf) {
  int pos = 0;
  final List<Map<String, dynamic>> headers = [];

  /* 1) Field-section prefix */
  // Required Insert Count (prefix-8)
  final ric = decodeVarInt(buf, 8, pos);
  pos = ric['next'];

  // Delta Base (prefix-7)
  final db = decodeVarInt(buf, 7, pos);
  pos = db['next'];

  /* 2) Field-line representations */
  while (pos < buf.length) {
    final int byte = buf[pos];

    /* A. Indexed Field Line – 1xxxxxxx */
    if ((byte & 0x80) == 0x80) {
      final bool fromStatic = (byte & 0x40) != 0; // T-bit
      final idx = decodeVarInt(buf, 6, pos); // prefix-6
      pos = idx['next'];

      headers.add({
        'type': "indexed",
        'from_static_table': fromStatic,
        'index': idx['value'],
      });
      continue;
    }

    /* B. Literal Field Line + Name Reference – 01xxxxxx */
    if ((byte & 0xC0) == 0x40) {
      final bool neverIndexed = (byte & 0x20) != 0; // N-bit
      final bool fromStatic = (byte & 0x10) != 0; // T-bit
      final nameIdx = decodeVarInt(buf, 4, pos); // prefix-4
      pos = nameIdx['next'];

      final bool valH = (buf[pos] & 0x80) != 0; // H-bit (Value)
      final valLen = decodeVarInt(buf, 7, pos); // prefix-7
      pos = valLen['next'];

      final Uint8List valBytes = buf.sublist(
        pos,
        (pos + valLen['value']) as int?,
      );
      pos += (valLen['value'] as int);

      final String value = valH
          ? decodeHuffman(valBytes)
          : utf8.decode(valBytes);

      headers.add({
        'type': "literal_with_name_ref",
        'never_indexed': neverIndexed,
        'from_static_table': fromStatic,
        'name_index': nameIdx['value'],
        'value': value,
      });
      continue;
    }

    /* C. Literal Field Line + Literal Name – 001xxxxx */
    if ((byte & 0xE0) == 0x20) {
      final bool neverIndexed = (byte & 0x10) != 0; // N-bit
      final bool nameH = (byte & 0x08) != 0; // H-bit (Name)
      final nameLen = decodeVarInt(buf, 3, pos); // prefix-3
      pos = nameLen['next'];

      final Uint8List nameBytes = buf.sublist(
        pos,
        (pos + nameLen['value']) as int?,
      );
      pos += (nameLen['value'] as int);

      final String name = nameH
          ? decodeHuffman(nameBytes)
          : utf8.decode(nameBytes);

      final bool valH = (buf[pos] & 0x80) != 0; // H-bit (Value)
      final valLen = decodeVarInt(buf, 7, pos); // prefix-7
      pos = valLen['next'];

      final Uint8List valBytes = buf.sublist(
        pos,
        (pos + valLen['value']) as int?,
      );
      pos += (valLen['value'] as int);

      final String value = valH
          ? decodeHuffman(valBytes)
          : utf8.decode(valBytes);

      headers.add({
        'type': "literal_with_literal_name",
        'never_indexed': neverIndexed,
        'name': name,
        'value': value,
      });
      continue;
    }

    /* Logic error based on specification */
    throw Exception(
      "Unknown header-block instruction at byte $pos (0x${byte.toRadixString(16)})",
    );
  }

  return {
    'insert_count': ric['value'],
    'delta_base': db['value'],
    'headers': headers,
  };
}

dynamic extract_h3_frames_from_chunks(
  Map<int, dynamic> chunks,
  int from_offset,
) {
  // Convert keys to a sorted list of integers
  var offsets = chunks.keys.map((k) => int.parse(k.toString())).toList()
    ..sort();

  List<Uint8List> buffers = [];
  int totalLength = 0;

  // Reassemble chunks starting from from_offset
  for (var i = 0; i < offsets.length; i++) {
    var base = offsets[i];
    var chunk = chunks[base] as Uint8List;

    if (from_offset >= base && from_offset < base + chunk.length) {
      var start = from_offset - base;
      var sliced = chunk.sublist(start);
      buffers.add(sliced);
      totalLength += sliced.length;

      for (var j = i + 1; j < offsets.length; j++) {
        var nextChunk = chunks[offsets[j]] as Uint8List;
        buffers.add(nextChunk);
        totalLength += nextChunk.length;
      }
      break;
    }
  }

  if (buffers.isEmpty) {
    return {'frames': [], 'new_from_offset': from_offset};
  }

  // Concatenate all buffered Uint8Lists
  var combined = concatUint8Arrays(buffers);
  int offset = 0;
  List<Map<String, dynamic>> frames = [];

  // Helper function for VarInt reading with safety checks
  Map<String, dynamic>? safeReadVarInt() {
    if (offset >= combined.length) return null;

    var firstByte = combined[offset];
    var lengthBits = firstByte >> 6;
    var neededLength = 1 << lengthBits;

    if (offset + neededLength > combined.length) return null;

    // Using the readVarInt logic translated previously
    var res = readVarInt(combined, offset);
    if (res == null || res['byteLength'] == null) return null;

    offset += (res['byteLength'] as int);
    return res;
  }

  // Frame Parsing Loop
  while (offset < combined.length) {
    var startOffset = offset;

    var frameType = safeReadVarInt();
    if (frameType == null) break;

    var lengthInfo = safeReadVarInt();
    if (lengthInfo == null) {
      offset = startOffset; // Rollback
      break;
    }

    int payloadLength = lengthInfo['value'];
    if (offset + payloadLength > combined.length) {
      offset = startOffset; // Rollback
      break;
    }

    var payload = combined.sublist(offset, offset + payloadLength);
    frames.add({'frame_type': frameType['value'], 'payload': payload});
    offset += payloadLength;
  }

  // Update chunks map to remove processed data
  if (offset > 0) {
    int bytesToRemove = offset;
    Map<int, Uint8List> newChunks = {};
    int currentOffset = from_offset;

    for (var k = 0; k < offsets.length; k++) {
      var base = offsets[k];
      var chunk = chunks[base] as Uint8List;

      if (currentOffset >= base + chunk.length) continue;

      int relStart = max(currentOffset - base, 0);
      int relEnd = min(chunk.length, currentOffset + bytesToRemove - base);

      if (relEnd < chunk.length) {
        var leftover = chunk.sublist(relEnd);
        var newBase = base + relEnd;
        newChunks[newBase] = leftover;
      }

      bytesToRemove -= (relEnd - relStart);
      if (bytesToRemove <= 0) break;
    }

    // Clear and update the original map
    chunks.clear();
    newChunks.forEach((key, value) {
      chunks[key] = value;
    });
    from_offset += offset;
  }

  return {'frames': frames, 'new_from_offset': from_offset};
}

Uint8List build_h3_frames(List<Map<String, dynamic>> frames) {
  List<Uint8List> parts = [];

  for (var i = 0; i < frames.length; i++) {
    var frame = frames[i];

    // frame_type and payload length are written as QUIC VarInts
    var typeBytes = writeVarInt(frame['frame_type']);
    var lenBytes = writeVarInt(frame['payload'].length);
    Uint8List payload = frame['payload'];

    parts.add(typeBytes);
    parts.add(lenBytes);
    parts.add(payload);
  }

  return concatUint8Arrays(parts);
}

int? computeVarIntLen(Uint8List buf, int pos, int prefixBits) {
  if (pos >= buf.length) return null;

  int first = buf[pos];
  int prefixMask = (1 << prefixBits) - 1;
  int prefixVal = first & prefixMask;

  // If value is less than the mask, it's a 1-byte VarInt
  if (prefixVal < prefixMask) return 1;

  int len = 1;
  int idx = pos + 1;
  while (idx < buf.length) {
    len++;
    // Base128 ends when the MSB is 0
    if ((buf[idx] & 0x80) == 0) return len;
    idx++;
  }
  return null; // Incomplete data
}

dynamic safeDecodeVarInt(Uint8List buf, _PosRef posRef, int prefixBits) {
  int? len = computeVarIntLen(buf, posRef.pos, prefixBits);
  if (len == null) return null;

  var res = decodeVarInt(buf, prefixBits, posRef.pos);
  posRef.pos = res['next'];
  return res['value'];
}

// Simple wrapper class to pass position by reference
class _PosRef {
  int pos;
  _PosRef(this.pos);
} /* ---------- פונקציית החילוץ העיקרית ---------- */

// Helper class to pass the position by reference, similar to { pos: 0 } in JS

dynamic extract_qpack_encoder_instructions_from_chunks(
  Map<dynamic, dynamic> chunks,
  int from_offset,
) {
  // 1) Reassemble chunks starting from from_offset
  var offsets = chunks.keys.map((k) => int.parse(k.toString())).toList()
    ..sort();
  List<Uint8List> buffers = [];
  int totalLen = 0;

  for (var i = 0; i < offsets.length; i++) {
    var base = offsets[i];
    var chunk = chunks[base] as Uint8List;
    if (from_offset >= base && from_offset < base + chunk.length) {
      var start = from_offset - base;
      var sliced = chunk.sublist(start);
      buffers.add(sliced);
      totalLen += sliced.length;

      for (var j = i + 1; j < offsets.length; j++) {
        var nextChunk = chunks[offsets[j]] as Uint8List;
        buffers.add(nextChunk);
        totalLen += nextChunk.length;
      }
      break;
    }
  }

  if (buffers.isEmpty) {
    return {'instructions': [], 'new_from_offset': from_offset};
  }

  // concatUint8Arrays is assumed to be your helper that flattens List<Uint8List>
  var combined = concatUint8Arrays(buffers);
  var posRef = _PosRef(0);
  List<Map<String, dynamic>> instructions = [];

  // 2) Instruction Decoding Loop
  while (posRef.pos < combined.length) {
    var startPos = posRef.pos;
    var byte = combined[posRef.pos];

    // --- A. Insert With Name Reference (1xxxxxxx) ---
    if ((byte & 0x80) == 0x80) {
      bool fromStatic = (byte & 0x40) != 0;
      var nameIdx = safeDecodeVarInt(combined, posRef, 6);
      if (nameIdx == null) break;

      if (posRef.pos >= combined.length) {
        posRef.pos = startPos;
        break;
      }
      bool valHuffman = (combined[posRef.pos] & 0x80) != 0;
      var valLen = safeDecodeVarInt(combined, posRef, 7);

      if (valLen == null || posRef.pos + (valLen as int) > combined.length) {
        posRef.pos = startPos;
        break;
      }

      var valBytes = combined.sublist(posRef.pos, posRef.pos + valLen);
      posRef.pos += valLen;
      var value = valHuffman ? decodeHuffman(valBytes) : utf8.decode(valBytes);

      instructions.add({
        'type': 'insert_with_name_ref',
        'from_static_table': fromStatic,
        'name_index': nameIdx,
        'value': value,
      });
      continue;
    }

    // --- B. Insert Without Name Reference (01xxxxxx) ---
    if ((byte & 0xC0) == 0x40) {
      bool nameH = (byte & 0x20) != 0;
      var nameLen = safeDecodeVarInt(combined, posRef, 5);
      if (nameLen == null || posRef.pos + (nameLen as int) > combined.length) {
        posRef.pos = startPos;
        break;
      }
      var nameBytes = combined.sublist(posRef.pos, posRef.pos + nameLen);
      posRef.pos += nameLen;

      if (posRef.pos >= combined.length) {
        posRef.pos = startPos;
        break;
      }
      bool valH = (combined[posRef.pos] & 0x80) != 0;
      var valLen2 = safeDecodeVarInt(combined, posRef, 7);
      if (valLen2 == null || posRef.pos + (valLen2 as int) > combined.length) {
        posRef.pos = startPos;
        break;
      }
      var valBytes2 = combined.sublist(posRef.pos, posRef.pos + valLen2);
      posRef.pos += valLen2;

      var nameStr = nameH ? decodeHuffman(nameBytes) : utf8.decode(nameBytes);
      var valueStr = valH ? decodeHuffman(valBytes2) : utf8.decode(valBytes2);

      instructions.add({
        'type': 'insert_without_name_ref',
        'name': nameStr,
        'value': valueStr,
      });
      continue;
    }

    // --- C. Set Dynamic Table Capacity (001xxxxx) ---
    if ((byte & 0xE0) == 0x20) {
      var capacity = safeDecodeVarInt(combined, posRef, 5);
      if (capacity == null) {
        posRef.pos = startPos;
        break;
      }

      instructions.add({
        'type': 'set_dynamic_table_capacity',
        'capacity': capacity,
      });
      continue;
    }

    // --- D. Duplicate (0000xxxx) ---
    if ((byte & 0xF0) == 0x00) {
      var dupIndex = safeDecodeVarInt(combined, posRef, 4);
      if (dupIndex == null) {
        posRef.pos = startPos;
        break;
      }

      instructions.add({'type': 'duplicate', 'index': dupIndex});
      continue;
    }

    break; // Unknown instruction
  }

  int consumed = posRef.pos;

  // 3) Update chunks map and progress from_offset
  if (consumed > 0) {
    int bytesLeft = consumed;
    Map<int, Uint8List> newChunks = {};
    int currOff = from_offset;

    for (var k = 0; k < offsets.length; k++) {
      var base = offsets[k];
      var chunk = chunks[base] as Uint8List;

      if (currOff >= base + chunk.length) continue;

      int relStart = max(currOff - base, 0);
      int relEnd = min(chunk.length, currOff + bytesLeft - base);

      if (relEnd < chunk.length) {
        var leftover = chunk.sublist(relEnd);
        newChunks[base + relEnd] = leftover;
      }

      bytesLeft -= (relEnd - relStart);
      if (bytesLeft <= 0) break;
    }

    chunks.clear();
    newChunks.forEach((key, val) => chunks[key] = val);
    from_offset += consumed;
  }

  return {'instructions': instructions, 'new_from_offset': from_offset};
}

var h3_settings_frame_params = [
  [0x01, "SETTINGS_QPACK_MAX_TABLE_CAPACITY"],
  [0x06, "SETTINGS_MAX_FIELD_SECTION_SIZE"],
  [0x07, "SETTINGS_QPACK_BLOCKED_STREAMS"],
  [0x08, "SETTINGS_ENABLE_CONNECT_PROTOCOL"],
  [0x33, "SETTINGS_H3_DATAGRAM"],
  [0x2b603742, "SETTINGS_ENABLE_WEBTRANSPORT"], // תקני לפי draft
  [0x0d, "SETTINGS_NO_RFC9114_LEGACY_CODEPOINT"],
  [0x14E9CD29, "SETTINGS_WT_MAX_SESSIONS"],
  [0x4d44, "SETTINGS_ENABLE_METADATA"], // provisional
];

var h3_name_to_id = {};
var h3_id_to_name = {};

// for (var entry = 0; entry < h3_settings_frame_params.length; entry++) {
//   var [id, name] = h3_settings_frame_params[entry];
//   h3_name_to_id[name] = id;
//   h3_id_to_name[id] = name;
// }

// --- HTTP/3 Settings Parsing ---

Map<String, dynamic> parse_h3_settings_frame(Uint8List buf) {
  Map<String, dynamic> settings = {};
  int offset = 0;

  while (offset < buf.length) {
    var idRes = readVarInt(buf, offset);
    if (idRes == null) break;
    offset += (idRes['byteLength'] as int);

    var valRes = readVarInt(buf, offset);
    if (valRes == null) break;
    offset += (valRes['byteLength'] as int);

    int id = idRes['value'];
    int value = valRes['value'];

    // h3_id_to_name is assumed to be a global Map<int, String>
    String name = h3_id_to_name[id] ?? "UNKNOWN_0x${id.toRadixString(16)}";
    settings[name] = value;
  }

  return settings;
}

// --- Building Settings Frames ---

Uint8List build_settings_frame(Map<String, dynamic> settings_named) {
  List<int> frame_payload = [];

  for (var name in settings_named.keys) {
    // h3_name_to_id is assumed to be a global Map<String, int>
    int? id = h3_name_to_id[name];
    if (id == null) {
      throw Exception("Unknown setting name: $name");
    }
    int value = settings_named[name];

    frame_payload.addAll(writeVarInt(id));
    frame_payload.addAll(writeVarInt(value));
  }

  return Uint8List.fromList(frame_payload);
}

Uint8List build_control_stream_old(Map<String, dynamic> settings_named) {
  const Map<String, int> setting_ids = {
    'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0x01,
    'SETTINGS_MAX_FIELD_SECTION_SIZE': 0x06,
    'SETTINGS_ENABLE_WEBTRANSPORT': 0x2b603742,
    'SETTINGS_H3_DATAGRAM': 0x33,
    'SETTINGS_NO_RFC9114_LEGACY_CODEPOINT': 0x0d,
    'SETTINGS_ENABLE_CONNECT_PROTOCOL': 0x08,
    'SETTINGS_WT_MAX_SESSIONS': 0x14E9CD29,
  };

  List<int> frame_payload = [];

  for (var name in settings_named.keys) {
    int? id = setting_ids[name];
    if (id == null) {
      throw Exception("Unknown setting name: $name");
    }

    int value = settings_named[name];
    frame_payload.addAll(writeVarInt(id));
    frame_payload.addAll(writeVarInt(value));
  }

  List<int> frame_header = [
    ...writeVarInt(0x04), // SETTINGS frame type
    ...writeVarInt(frame_payload.length),
  ];

  return Uint8List.fromList([
    0x00, // Stream Type: Control Stream
    ...frame_header,
    ...frame_payload,
  ]);
}

// --- QPACK & Header Encoding ---

List<int> encodeInt(int value, int prefixBits) {
  final int max = (1 << prefixBits) - 1;
  if (value < max) return [value];

  final List<int> bytes = [max];
  value -= max;
  while (value >= 128) {
    bytes.add((value & 0x7F) | 0x80);
    value >>= 7;
  }
  bytes.add(value);
  return bytes;
}

List<int> encodeStringLiteral(Uint8List bytes, int hFlag) {
  List<int> lenBytes = encodeInt(bytes.length, 7);
  lenBytes[0] |= (hFlag << 7); // Set the H bit (Huffman flag)
  return [...lenBytes, ...bytes];
}

Uint8List build_http3_literal_headers_frame(Map<String, dynamic> headers) {
  final List<int> out = [];
  // QPACK Instruction Prefix (Required Insert Count & Delta Base)
  // Simplified here as two zero bytes for an empty dynamic table state
  out.addAll([0x00, 0x00]);

  for (var header_name in headers.keys) {
    final nameBytes = utf8.encode(header_name.toLowerCase());
    final valueBytes = utf8.encode(headers[header_name].toString());

    /* Byte 1: 001 (Literal With Literal Name) | N=0 | H=0 | NameLen(3 bits) */
    final nameLenEnc = encodeInt(nameBytes.length, 3);
    final int firstByte = 0x20 | nameLenEnc[0];

    out.add(firstByte);
    if (nameLenEnc.length > 1) {
      out.addAll(nameLenEnc.sublist(1));
    }
    out.addAll(nameBytes);

    /* Value encoding: H=0 flag + prefix-7 length */
    out.addAll(encodeStringLiteral(Uint8List.fromList(valueBytes), 0));
  }
  return Uint8List.fromList(out);
}

// --- QPACK Instruction Construction ---

Uint8List build_qpack_block_header_ack(int stream_id) {
  List<int> parts = [0x81]; // Instruction type: Header Acknowledgement
  parts.addAll(writeVarInt(stream_id));
  return Uint8List.fromList(parts);
}

Uint8List? build_qpack_known_received_count(int count) {
  if (count <= 0) return null;
  Uint8List buf = writeVarInt(count);
  // Ensure the top two bits are 00 (Instruction: Section Acknowledgment)
  buf[0] &= 0x3F;
  return buf;
}

// --- WebTransport Datagram Parsing ---

dynamic parse_webtransport_datagram(Uint8List payload) {
  var result = readVarInt(payload, 0);
  if (result == null) {
    throw Exception("Invalid VarInt at beginning of payload");
  }

  int stream_id = result['value'];
  int byteLength = result['byteLength'];

  // Extract remaining data as the datagram body
  Uint8List data = payload.sublist(byteLength);

  return {'stream_id': stream_id, 'data': data};
}
