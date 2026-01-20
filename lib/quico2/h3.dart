import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';
import 'buffer.dart'; // Using your existing Buffer class

class HuffmanNode {
  int? symbol;
  HuffmanNode? zero;
  HuffmanNode? one;
}

final Uint32List huffmanCodes = Uint32List.fromList([
  0x1ff8,
  0x7fffd8,
  0xfffffe2,
  0xfffffe3,
  0xfffffe4, // ... (Truncated for brevity, use your full list)
  0x3fffffff, // EOS
]);

final Uint8List huffmanBits = Uint8List.fromList([
  13, 23, 28, 28, 28, // ... (Truncated for brevity, use your full list)
  30,
]);

HuffmanNode buildHuffmanTrie() {
  final root = HuffmanNode();
  for (int i = 0; i < huffmanCodes.length; i++) {
    int code = huffmanCodes[i];
    int length = huffmanBits[i];
    var node = root;
    for (int j = length - 1; j >= 0; j--) {
      int bit = (code >> j) & 1;
      if (bit == 0) {
        node.zero ??= HuffmanNode();
        node = node.zero!;
      } else {
        node.one ??= HuffmanNode();
        node = node.one!;
      }
    }
    node.symbol = i;
  }
  return root;
}

final HuffmanNode huffmanRoot = buildHuffmanTrie();

Map<String, int> decodePrefixVarInt(Uint8List buf, int prefixBits, int pos) {
  int maxPrefix = (1 << prefixBits) - 1;
  int byte = buf[pos];
  int value = byte & maxPrefix;
  pos++;

  if (value < maxPrefix) return {'value': value, 'next': pos};

  int m = 0;
  while (true) {
    int b = buf[pos++];
    value += (b & 0x7f) << m;
    if ((b & 0x80) == 0) break;
    m += 7;
  }
  return {'value': value, 'next': pos};
}

List<int> encodePrefixVarInt(int value, int prefixBits) {
  int max = (1 << prefixBits) - 1;
  if (value < max) return [value];

  List<int> bytes = [max];
  value -= max;
  while (value >= 128) {
    bytes.add((value & 0x7F) | 0x80);
    value >>= 7;
  }
  bytes.add(value);
  return bytes;
}

String decodeHuffman(Uint8List buf) {
  List<int> output = [];
  var node = huffmanRoot;
  int current = 0;
  int nbits = 0;

  for (int i = 0; i < buf.length; i++) {
    current = (current << 8) | buf[i];
    nbits += 8;

    while (nbits > 0) {
      int bit = (current >> (nbits - 1)) & 1;
      var nextNode = (bit == 0) ? node.zero : node.one;

      if (nextNode == null) throw Exception("Invalid Huffman encoding");
      node = nextNode;
      nbits--;

      if (node.symbol != null) {
        if (node.symbol == 256) break; // EOS
        output.add(node.symbol!);
        node = huffmanRoot;
      }
    }
  }
  return utf8.decode(output);
}

Uint8List huffmanEncode(String text) {
  List<int> input = utf8.encode(text);
  int bitBuffer = 0;
  int bitLen = 0;
  List<int> output = [];

  for (int sym in input) {
    int code = huffmanCodes[sym];
    int nbits = huffmanBits[sym];

    bitBuffer = (bitBuffer << nbits) | code;
    bitLen += nbits;

    while (bitLen >= 8) {
      bitLen -= 8;
      output.add((bitBuffer >> bitLen) & 0xff);
    }
  }

  if (bitLen > 0) {
    // Padding with 1s
    bitBuffer = (bitBuffer << (8 - bitLen)) | ((1 << (8 - bitLen)) - 1);
    output.add(bitBuffer & 0xff);
  }
  return Uint8List.fromList(output);
}

// dynamic extractH3FramesFromChunks(Map<int, Uint8List> chunks, int fromOffset) {
//   // Sort offsets and combine buffers
//   var sortedOffsets = chunks.keys.toList()..sort();
//   List<int> combinedList = [];

//   for (var base in sortedOffsets) {
//     var chunk = chunks[base]!;
//     if (fromOffset < base + chunk.length) {
//       int start = (fromOffset > base) ? fromOffset - base : 0;
//       combinedList.addAll(chunk.sublist(start));
//     }
//   }

//   if (combinedList.isEmpty)
//     return {'frames': [], 'new_from_offset': fromOffset};

//   Uint8List combined = Uint8List.fromList(combinedList);
//   num offset = 0;
//   List<Map<String, dynamic>> frames = [];

//   while (offset < combined.length) {
//     num startOffset = offset;

//     // Read Type
//     var typeRes = Buffer.readVarIntStatic(combined, offset.toInt());
//     if (typeRes == null) break;
//     offset += typeRes['byteLength'];

//     // Read Length
//     var lenRes = Buffer.readVarIntStatic(combined, offset.toInt());
//     if (lenRes == null) {
//       offset = startOffset; // Rollback
//       break;
//     }
//     offset += lenRes['byteLength'];

//     int payloadLength = lenRes['value'];
//     if (offset + payloadLength > combined.length) {
//       offset = startOffset; // Rollback
//       break;
//     }

//     // Extract Payload
//     Uint8List payload = combined.sublist(
//       offset.toInt(),
//       offset.toInt() + payloadLength,
//     );
//     frames.add({'frame_type': typeRes['value'], 'payload': payload});
//     offset += payloadLength;
//   }

//   // Update original chunks (Logic to remove processed bytes)
//   if (offset > 0) {
//     int bytesToRemove = offset.toInt();
//     int currentOffset = fromOffset;
//     Map<int, Uint8List> newChunks = {};

//     for (var base in sortedOffsets) {
//       var chunk = chunks[base]!;
//       if (currentOffset >= base + chunk.length) continue;

//       int relEnd = (currentOffset + bytesToRemove - base).clamp(
//         0,
//         chunk.length,
//       );
//       if (relEnd < chunk.length) {
//         newChunks[base + relEnd] = chunk.sublist(relEnd);
//       }
//       bytesToRemove -= (relEnd - (currentOffset - base).clamp(0, chunk.length));
//       if (bytesToRemove <= 0) break;
//     }

//     chunks.clear();
//     chunks.addAll(newChunks);
//     fromOffset += offset.toInt();
//   }

//   return {'frames': frames, 'new_from_offset': fromOffset};
// }

Map<String, dynamic> parse_qpack_header_block(Uint8List buf) {
  int pos = 0;
  List<Map<String, dynamic>> headers = [];

  // 1. Required Insert Count (prefix-8)
  var ricRes = decodePrefixVarInt(buf, 8, pos);
  int ric = ricRes['value']!;
  pos = ricRes['next']!;

  // 2. Delta Base (prefix-7 + S-bit)
  int firstDbByte = buf[pos];
  bool postBase = (firstDbByte & 0x80) != 0; // S-bit (Sign bit)
  var dbRes = decodePrefixVarInt(buf, 7, pos);
  int db = dbRes['value']!;
  pos = dbRes['next']!;

  // Calculate Base Index: BaseIndex = RIC ± DB
  int baseIndex = postBase ? (ric + db) : (ric - db);

  // 3. Process Header Field Lines
  while (pos < buf.length) {
    int byte = buf[pos];

    // A. Indexed Field Line (Starts with 1xxxxxxx)
    if ((byte & 0x80) == 0x80) {
      bool fromStatic = (byte & 0x40) != 0; // T-bit
      var idxRes = decodePrefixVarInt(buf, 6, pos);
      pos = idxRes['next']!;

      headers.add({
        'type': 'indexed',
        'from_static_table': fromStatic,
        'index': idxRes['value'],
      });
      continue;
    }

    // B. Literal With Name Reference (Starts with 01xxxxxx)
    if ((byte & 0xC0) == 0x40) {
      bool neverIndexed = (byte & 0x20) != 0; // N-bit
      bool fromStatic = (byte & 0x10) != 0; // T-bit
      var nameIdxRes = decodePrefixVarInt(buf, 4, pos);
      pos = nameIdxRes['next']!;

      bool valH = (buf[pos] & 0x80) != 0; // H-bit (Huffman)
      var valLenRes = decodePrefixVarInt(buf, 7, pos);
      pos = valLenRes['next']!;

      Uint8List valBytes = buf.sublist(pos, pos + valLenRes['value']!);
      pos += valLenRes['value'] as int;
      String value = valH ? decodeHuffman(valBytes) : utf8.decode(valBytes);

      headers.add({
        'type': 'literal_with_name_ref',
        'never_indexed': neverIndexed,
        'from_static_table': fromStatic,
        'name_index': nameIdxRes['value'],
        'value': value,
      });
      continue;
    }

    // C. Literal With Literal Name (Starts with 001xxxxx)
    if ((byte & 0xE0) == 0x20) {
      bool neverIndexed = (byte & 0x10) != 0; // N-bit
      bool nameH = (byte & 0x08) != 0; // H-bit for name
      var nameLenRes = decodePrefixVarInt(buf, 3, pos);
      pos = nameLenRes['next']!;

      Uint8List nameBytes = buf.sublist(pos, pos + nameLenRes['value']!);
      pos += nameLenRes['value'] as int;
      String name = nameH ? decodeHuffman(nameBytes) : utf8.decode(nameBytes);

      bool valH = (buf[pos] & 0x80) != 0; // H-bit for value
      var valLenRes = decodePrefixVarInt(buf, 7, pos);
      pos = valLenRes['next']!;

      Uint8List valBytes = buf.sublist(pos, pos + valLenRes['value']!);
      pos += valLenRes['value'] as int;
      String value = valH ? decodeHuffman(valBytes) : utf8.decode(valBytes);

      headers.add({
        'type': 'literal_with_literal_name',
        'never_indexed': neverIndexed,
        'name': name,
        'value': value,
      });
      continue;
    }

    throw Exception(
      'Unknown QPACK header-block instruction at byte $pos (0x${byte.toRadixString(16)})',
    );
  }

  return {
    'insert_count': ric,
    'delta_base': db,
    'post_base': postBase,
    'base_index': baseIndex,
    'headers': headers,
  };
}

final List<List<String>> qpackStaticTable = [
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

List<Map<String, String>> resolveHeaders(
  Map<String, dynamic> parsedBlock,
  List<List<String>> dynamicTable,
) {
  List<Map<String, String>> resolved = [];
  List<dynamic> instructions = parsedBlock['headers'];

  for (var instr in instructions) {
    String name = "";
    String value = "";

    switch (instr['type']) {
      case 'indexed':
        var entry = instr['from_static_table']
            ? qpackStaticTable[instr['index']]
            : dynamicTable[instr['index']];
        name = entry[0];
        value = entry[1];
        break;

      case 'literal_with_name_ref':
        var entry = instr['from_static_table']
            ? qpackStaticTable[instr['name_index']]
            : dynamicTable[instr['name_index']];
        name = entry[0];
        value = instr['value'];
        break;

      case 'literal_with_literal_name':
        name = instr['name'];
        value = instr['value'];
        break;
    }

    resolved.add({name: value});
  }

  return resolved;
}

void handleIncomingHeaders(Uint8List payload) {
  // 1. Parse the QPACK Block
  var parsed = parse_qpack_header_block(payload);

  // 2. Resolve to human-readable headers
  // (Assuming dynamicTable is empty for simple implementations)
  var headers = resolveHeaders(parsed, []);

  print("Received Headers: $headers");
}

dynamic extractH3FramesFromChunks(Map<int, Uint8List> chunks, int fromOffset) {
  var offsets = chunks.keys.toList()..sort();
  List<Uint8List> buffers = [];

  // Combine all chunks starting from fromOffset
  for (var base in offsets) {
    var chunk = chunks[base]!;
    if (fromOffset >= base && fromOffset < base + chunk.length) {
      int start = fromOffset - base;
      buffers.add(chunk.sublist(start));
      // Add all subsequent chunks
      int idx = offsets.indexOf(base);
      for (int j = idx + 1; j < offsets.length; j++) {
        buffers.add(chunks[offsets[j]]!);
      }
      break;
    }
  }

  if (buffers.isEmpty) return {'frames': [], 'new_from_offset': fromOffset};

  // Combine into one Uint8List for parsing
  final combined = Uint8List.fromList(buffers.expand((x) => x).toList());
  int offset = 0;
  List<Map<String, dynamic>> frames = [];

  while (offset < combined.length) {
    int startPos = offset;

    // 1. Read Frame Type
    var typeRes = Buffer.readVarIntStatic(combined, offset);
    if (typeRes == null) break;
    offset += typeRes['byteLength'] as int;

    // 2. Read Payload Length
    var lenRes = Buffer.readVarIntStatic(combined, offset);
    if (lenRes == null) {
      offset = startPos; // Rollback
      break;
    }
    offset += lenRes['byteLength'] as int;

    // 3. Check if full payload is available
    int payloadLen = lenRes['value'];
    if (offset + payloadLen > combined.length) {
      offset = startPos; // Rollback
      break;
    }

    Uint8List payload = combined.sublist(offset, offset + payloadLen);
    frames.add({'frame_type': typeRes['value'], 'payload': payload});
    offset += payloadLen;
  }

  // Update chunks and offset
  if (offset > 0) {
    _cleanupProcessedChunks(chunks, fromOffset, offset);
    fromOffset += offset;
  }

  return {'frames': frames, 'new_from_offset': fromOffset};
}

/// Helper to remove processed bytes from the chunks map
void _cleanupProcessedChunks(
  Map<int, Uint8List> chunks,
  int currentPos,
  int bytesToRemove,
) {
  var offsets = chunks.keys.toList()..sort();
  Map<int, Uint8List> nextChunks = {};
  int remainingToRemove = bytesToRemove;

  for (var base in offsets) {
    var chunk = chunks[base]!;
    if (currentPos >= base + chunk.length) continue;

    int relStart = (currentPos > base) ? currentPos - base : 0;
    int canRemove = chunk.length - relStart;
    int actuallyRemoving = min(canRemove, remainingToRemove);

    if (actuallyRemoving < canRemove) {
      int newBase = base + relStart + actuallyRemoving;
      nextChunks[newBase] = chunk.sublist(relStart + actuallyRemoving);
    }

    remainingToRemove -= actuallyRemoving;
    if (remainingToRemove <= 0) break;
  }

  chunks.clear();
  chunks.addAll(nextChunks);
}
