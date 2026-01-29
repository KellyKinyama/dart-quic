import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../../buffer.dart';
import '../handshake.dart';

// #############################################################################
// ## SECTION 1: ABSTRACT AND FALLBACK EXTENSION CLASSES
// #############################################################################
class HsExtension {
  int type;
  Uint8List data;
  HsExtension({required this.type, required this.data});
}

/// Abstract base class for all TLS extensions.
abstract class Extension {
  final int type;
  final Uint8List data;
  String get typeName => extensionTypesMap[type] ?? 'Unknown';
  Extension({required this.type, required this.data});

  /// Serializes the extension's data into bytes.
  /// Note: This serializes the *data* part of the extension only.
  Uint8List toBytes();
}

/// A fallback for any extension type that is not explicitly parsed.
/// It stores the raw data, maintaining the original behavior.
class UnknownExtension extends Extension {
  @override
  final Uint8List data;
  UnknownExtension(int type, this.data) : super(type: type, data: data);
  @override
  String toString() =>
      'Extension(type: $typeName ($type), len: ${data.length})';

  @override
  Uint8List toBytes() {
    return data;
  }
}

// #############################################################################
// ## SECTION 2: SPECIFIC PARSED EXTENSION CLASSES
// #############################################################################

class SupportedVersionsExtension extends Extension {
  final List<int> versions;
  @override
  final Uint8List data;
  SupportedVersionsExtension(this.versions, this.data)
    : super(type: 43, data: data);

  factory SupportedVersionsExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    if (data.length == 2) {
      // ServerHello case
      return SupportedVersionsExtension([buffer.pullUint16()], data);
    }
    // ClientHello case
    final versionsListBytes = buffer.pullVector(1);
    final versionsBuffer = Buffer(data: versionsListBytes);
    final versions = <int>[];
    while (!versionsBuffer.eof) {
      versions.add(versionsBuffer.pullUint16());
    }
    return SupportedVersionsExtension(versions, data);
  }

  Uint8List toBytesLocal({required int messageType}) {
    final buffer = Buffer();
    if (messageType == HandshakeType.server_hello.value) {
      // FIX: Ensure versions is not empty before calling .first
      final selectedVersion = versions.isNotEmpty ? versions.first : 0x0304;
      buffer.pushUint16(selectedVersion);
    } else {
      final versionsBuffer = Buffer();
      for (final v in versions) {
        versionsBuffer.pushUint16(v);
      }
      buffer.pushVector(versionsBuffer.toBytes(), 1);
    }
    return buffer.toBytes();
  }

  // static SupportedVersionsExtension supportedVersions(){

  //   return SupportedVersionsExtension.fromBytes(toBytesLocal( messageType:HandshakeType.client_hello.value));
  //   SupportedVersionsExtension
  // }

  @override
  Uint8List toBytes() =>
      toBytesLocal(messageType: HandshakeType.client_hello.value);

  @override
  String toString() {
    final versionStr = versions
        .map((v) => protocolVersionMap[v] ?? '0x${v.toRadixString(16)}')
        .join(', ');
    if (data.length == 2) {
      return 'SupportedVersions(selected: $versionStr)';
    }
    return 'SupportedVersions(versions: [$versionStr])';
  }
}

class KeyShareEntry {
  final int group;
  final Uint8List keyExchange;
  KeyShareEntry(this.group, this.keyExchange);

  factory KeyShareEntry.fromBytes(Buffer buffer) {
    final group = buffer.pullUint16();
    final keyExchange = buffer.pullVector(2);
    return KeyShareEntry(group, keyExchange);
  }

  Uint8List toBytes() {
    final buffer = Buffer();
    buffer.pushUint16(group);
    buffer.pushVector(keyExchange, 2);
    return buffer.toBytes();
  }

  @override
  String toString() {
    final groupName = namedGroupMap[group] ?? 'Unknown';
    // final keyHex = HEX.encode(keyExchange.take(4).toList());
    final keyHex = HEX.encode(keyExchange.toList());
    return 'KeyShareEntry(group: $groupName, key: $keyHex...)';
  }
}

// class KeyShareExtension extends Extension {
//   final List<KeyShareEntry> shares;
//   @override
//   Uint8List data;
//   KeyShareExtension(this.shares, this.data) : super(type: 51, data: data);

//   // MODIFIED FACTORY CONSTRUCTOR
//   factory KeyShareExtension.fromBytes(
//     Uint8List data, {
//     required int messageType,
//   }) {
//     final buffer = Buffer(data: data);
//     final shares = <KeyShareEntry>[];

//     if (messageType == HandshakeType.client_hello) {
//       // ClientHello contains a list of shares prefixed by its total length
//       final sharesListBytes = buffer.pullVector(2);
//       final sharesBuffer = Buffer(data: sharesListBytes);
//       while (!sharesBuffer.eof) {
//         shares.add(KeyShareEntry.fromBytes(sharesBuffer));
//       }
//     } else {
//       // ServerHello contains just a single KeyShareEntry, not a list
//       shares.add(KeyShareEntry.fromBytes(buffer));
//     }
//     return KeyShareExtension(shares, data);
//   }

//   @override
//   Uint8List toBytes() {
//     final buffer = Buffer();
//     if (shares.length == 1 && typeName != 'key_share_client') {
//       // ServerHello format (single entry, not a list)
//       buffer.pushBytes(shares.first.toBytes());
//     } else {
//       // ClientHello format (a list of entries)
//       final sharesListBuffer = Buffer();
//       for (final share in shares) {
//         sharesListBuffer.pushBytes(share.toBytes());
//       }
//       buffer.pushVector(sharesListBuffer.toBytes(), 2);
//     }
//     return buffer.toBytes();
//   }

//   @override
//   String toString() => 'KeyShare(shares: $shares)';
// }

class KeyShareExtension extends Extension {
  final List<KeyShareEntry> shares;
  KeyShareExtension(this.shares, Uint8List rawData)
    : super(type: 51, data: rawData);

  factory KeyShareExtension.fromBytes(
    Uint8List data, {
    required int messageType,
  }) {
    final buffer = Buffer(data: data);
    final shares = <KeyShareEntry>[];

    if (messageType == HandshakeType.client_hello.value) {
      final sharesListBytes = buffer.pullVector(2);
      final sharesBuffer = Buffer(data: sharesListBytes);
      while (!sharesBuffer.eof) {
        shares.add(KeyShareEntry.fromBytes(sharesBuffer));
      }
    } else {
      shares.add(KeyShareEntry.fromBytes(buffer));
    }
    return KeyShareExtension(shares, data);
  }

  /// ## CORRECTED toBytes() METHOD ##
  Uint8List toBytesLocal({required int messageType}) {
    final buffer = Buffer();
    if (messageType == HandshakeType.server_hello.value) {
      // ServerHello format (single entry, not a list)
      buffer.pushBytes(shares.first.toBytes());
    } else {
      // ClientHello format (a list of entries)
      final sharesListBuffer = Buffer();
      for (final share in shares) {
        sharesListBuffer.pushBytes(share.toBytes());
      }
      buffer.pushVector(sharesListBuffer.toBytes(), 2);
    }
    return buffer.toBytes();
  }

  @override
  Uint8List toBytes() =>
      toBytesLocal(messageType: HandshakeType.client_hello.value);

  @override
  String toString() => 'KeyShare(shares: $shares)';
}

// class KeyShareExtension extends Extension {
//   // In ServerHello, this will be a single entry. In ClientHello, a list.
//   final List<KeyShareEntry> shares;
//   KeyShareExtension(this.shares) : super(51);

//   factory KeyShareExtension.fromBytes(Uint8List data) {
//     final buffer = Buffer(data: data);
//     final shares = <KeyShareEntry>[];

//     // ServerHello contains just one KeyShareEntry, not a list.
//     if (data.length < 4) {
//       // This might be a HelloRetryRequest, which we can handle later if needed.
//       // For now, assume it's a ServerHello by structure.
//       shares.add(KeyShareEntry.fromBytes(buffer));
//     } else {
//       // ClientHello contains a list of shares
//       final sharesListBytes = buffer.pullVector(2);
//       final sharesBuffer = Buffer(data: sharesListBytes);
//       while (!sharesBuffer.eof) {
//         shares.add(KeyShareEntry.fromBytes(sharesBuffer));
//       }
//     }

//     return KeyShareExtension(shares);
//   }

//   @override
//   String toString() => 'KeyShare(shares: $shares)';
// }

/// RFC9000 18.2. Transport Parameter Definitions
enum TransportParameterType {
  original_destination_connection_id(0x00),
  max_idle_timeout(0x01),
  stateless_reset_token(0x02),
  max_udp_payload_size(0x03),
  initial_max_data(0x4),
  initial_max_stream_data_bidi_local(0x5),
  initial_max_stream_data_bidi_remote(0x6),
  initial_max_stream_data_uni(0x07),
  initial_max_streams_bidi(0x8),
  initial_max_streams_uni(0x09),
  ack_delay_exponent(0x0a),
  max_ack_delay(0x0b),
  disable_active_migration(0x0c),
  preferred_address(0x0d),
  active_connection_id_limit(0x0e),
  initial_source_connection_id(0x0f),
  retry_source_connection_id(0x10),
  grease(0xffff); // Use a high value for grease

  const TransportParameterType(this.value);
  final int value;

  factory TransportParameterType.fromInt(int key) {
    // FIX: Use orElse to prevent "No element" crash on unknown IDs or GREASE values
    return values.firstWhere(
      (element) => element.value == key,
      orElse: () => TransportParameterType.grease,
    );
  }
}

/// RFC9000 18. Transport Parameter Encoding
class TransportParameter {
  TransportParameterType id;
  int id_vli; // VLI,
  int len; // VLI,
  Uint8List value; //: []u8,

  TransportParameter({
    required this.id,
    required this.id_vli,
    required this.len,
    required this.value,
  });

  factory TransportParameter.fromBytes(Buffer buffer) {
    final id_vli = buffer.pullVarInt();
    final length_vli = buffer.pullVarInt();
    final value = buffer.pullBytes(length_vli);

    // Handle GREASE
    var id = TransportParameterType.grease;
    if (id_vli < 0xFF) {
      id = TransportParameterType.fromInt(id_vli);
    }

    return TransportParameter(
      id: id,
      id_vli: id_vli,
      len: length_vli,
      value: value,
    );
  }

  Uint8List toBytes() {
    final buffer = Buffer();
    buffer.pushUintVar(id.value);
    buffer.pushVector(value, 1); // pushVector(0) uses a var-int for length
    return buffer.toBytes();
  }

  @override
  String toString() {
    // TODO: implement toString
    return 'TransportParameter{ id: $id, value: ${HEX.encode(value)}}';
  }
}

class TransportParameters extends Extension {
  List<TransportParameter> params;
  @override
  Uint8List data;
  TransportParameters(this.params, this.data) : super(type: 57, data: data);

  factory TransportParameters.fromBytes(
    Uint8List data, {
    required int messageType,
  }) {
    List<TransportParameter> params = [];
    final buffer = Buffer(data: data);
    final len = data.length;

    int i = 0;
    while (i < len) {
      final start = buffer.readOffset;
      final p = TransportParameter.fromBytes(buffer);
      i += buffer.readOffset - start;
      params.add(p);
    }

    return TransportParameters(params, data);
  }

  @override
  Uint8List toBytes() {
    final buffer = Buffer();
    for (final param in params) {
      buffer.pushBytes(param.toBytes());
    }
    print("Raw ext:          ${HEX.encode(data)}");
    final out = buffer.toBytes();
    print("Expected raw ext: ${HEX.encode(out)}");
    return out;
  }

  @override
  String toString() {
    // TODO: implement toString
    return "TransportParameters{ $params}";
  }
}

class SupportedGroupsExtension extends Extension {
  final List<int> namedGroupList;
  @override
  final Uint8List data;

  SupportedGroupsExtension(this.namedGroupList, this.data)
    : super(type: 10, data: data);

  factory SupportedGroupsExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    final groupListBytes = buffer.pullVector(2);
    final groupBuffer = Buffer(data: groupListBytes);
    final groups = <int>[];
    while (!groupBuffer.eof) {
      groups.add(groupBuffer.pullUint16());
    }
    return SupportedGroupsExtension(groups, data);
  }
  @override
  String toString() {
    final groupNames = namedGroupList
        .map((g) => namedGroupMap[g] ?? 'Unknown')
        .join(', ');
    return 'SupportedGroups(groups: [$groupNames])';
  }

  Uint8List toBytes() {
    final buffer = Buffer();
    final groupListBuffer = Buffer();
    for (final group in namedGroupList) {
      groupListBuffer.pushUint16(group);
    }
    buffer.pushVector(groupListBuffer.toBytes(), 2);
    return buffer.toBytes();
  }
}

class SignatureAlgorithmsExtension extends Extension {
  final List<int> supportedSignatureAlgorithms;

  @override
  final Uint8List data;
  SignatureAlgorithmsExtension(this.supportedSignatureAlgorithms, this.data)
    : super(type: 13, data: data);

  factory SignatureAlgorithmsExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    final sigListBytes = buffer.pullVector(2);
    final sigBuffer = Buffer(data: sigListBytes);
    final sigs = <int>[];
    while (!sigBuffer.eof) {
      sigs.add(sigBuffer.pullUint16());
    }
    return SignatureAlgorithmsExtension(sigs, data);
  }
  @override
  String toString() {
    final sigNames = supportedSignatureAlgorithms
        .map((s) => signatureSchemeMap[s] ?? 'Unknown')
        .join(', ');
    return 'SignatureAlgorithms(algorithms: [$sigNames])';
  }

  // In class SignatureAlgorithmsExtension

  Uint8List toBytes() {
    final buffer = Buffer();
    final sigListBuffer = Buffer();
    for (final sig in supportedSignatureAlgorithms) {
      sigListBuffer.pushUint16(sig);
    }
    buffer.pushVector(sigListBuffer.toBytes(), 2);
    return buffer.toBytes();
  }
}

class ServerNameExtension extends Extension {
  final String serverName;

  ServerNameExtension(this.serverName) : super(type: 0, data: Uint8List(0));

  @override
  Uint8List toBytes() {
    final nameBytes = Uint8List.fromList(serverName.codeUnits);
    final entryBuffer = Buffer();
    entryBuffer.pushUint8(0); // NameType: host_name (0)
    entryBuffer.pushVector(nameBytes, 2); // Length + name

    final listBuffer = Buffer();
    listBuffer.pushVector(
      entryBuffer.toBytes(),
      2,
    ); // ServerNameList length + entry

    return listBuffer.toBytes();
  }

  @override
  String toString() => 'ServerName(host: $serverName)';
}

class AlpnExtension extends Extension {
  final List<String> protocols;

  AlpnExtension(this.protocols) : super(type: 16, data: Uint8List(0));

  @override
  Uint8List toBytes() {
    final protocolBuffer = Buffer();
    for (var proto in protocols) {
      final protoBytes = Uint8List.fromList(proto.codeUnits);
      protocolBuffer.pushVector(
        protoBytes,
        1,
      ); // 1-byte length prefix per protocol
    }

    final finalBuffer = Buffer();
    finalBuffer.pushVector(
      protocolBuffer.toBytes(),
      2,
    ); // 2-byte total length prefix
    return finalBuffer.toBytes();
  }

  @override
  String toString() => 'ALPN(protocols: $protocols)';
}

// #############################################################################
// ## SECTION 3: FACTORY PARSER FUNCTION
// #############################################################################

// /// Parses the extension block and returns a list of specific, parsed Extension objects.
// List<Extension> parseExtensions(Buffer buffer, {required int messageType}) {
//   if (buffer.eof) return [];
//   final totalExtLen = buffer.pullUint16();
//   final extEndOffset = buffer.readOffset + totalExtLen;
//   final extensions = <Extension>[];

//   while (buffer.readOffset < extEndOffset) {
//     final extType = buffer.pullUint16();
//     final extData = buffer.pullVector(2);

//     switch (extType) {
//       case 10:
//         extensions.add(SupportedGroupsExtension.fromBytes(extData));
//         break;
//       case 13:
//         extensions.add(SignatureAlgorithmsExtension.fromBytes(extData));
//         break;
//       case 43:
//         extensions.add(SupportedVersionsExtension.fromBytes(extData));
//         break;
//       case 51: // key_share
//         // Pass the messageType context down to the KeyShare parser
//         extensions.add(
//           KeyShareExtension.fromBytes(extData, messageType: messageType),
//         );

//         break;

//       case 57:
//         extensions.add(
//           TransportParameters.fromBytes(extData, messageType: messageType),
//         );
//         break;
//       default:
//         extensions.add(UnknownExtension(extType, extData));
//     }
//   }
//   return extensions;
// }

// // In file: extensions.dart

// /// Serializes a list of Extension objects into the on-the-wire format.
// /// This is the reverse of the parseExtensions function.
// Uint8List serializeExtensions(List<Extension> extensions) {
//   // 1. A temporary buffer to hold the concatenated [type][length][data] blocks.
//   final extensionsContentBuffer = Buffer();

//   for (final ext in extensions) {
//     // Get the specific data for this extension
//     final extData = ext.toBytes();

//     // Write the type (2 bytes)
//     extensionsContentBuffer.pushUint16(ext.type);
//     // Write the data as a vector (2-byte length prefix)
//     extensionsContentBuffer.pushVector(extData, 2);
//   }

//   // 2. A final buffer to hold the complete extensions block.
//   final finalBuffer = Buffer();

//   // 3. Write the total length of the content, followed by the content itself.
//   finalBuffer.pushVector(extensionsContentBuffer.toBytes(), 2);

//   return finalBuffer.toBytes();
// }

List<Extension> parseExtensions(Buffer buffer, {required int messageType}) {
  if (buffer.eof) return [];
  if (buffer.remaining < 2) return [];

  final totalExtLen = buffer.pullUint16();
  final extEndOffset = buffer.readOffset + totalExtLen;
  final extensions = <Extension>[];

  print("      [DEBUG-EXT] Total Extensions Length: $totalExtLen");

  while (buffer.readOffset < extEndOffset) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);

    print("      [DEBUG-EXT] Parsing Type: $extType, Length: $extLen");

    try {
      switch (extType) {
        case 10:
          extensions.add(SupportedGroupsExtension.fromBytes(extData));
          break;
        case 13:
          extensions.add(SignatureAlgorithmsExtension.fromBytes(extData));
          break;
        case 43:
          extensions.add(SupportedVersionsExtension.fromBytes(extData));
          break;
        case 51:
          extensions.add(
            KeyShareExtension.fromBytes(extData, messageType: messageType),
          );
          break;
        case 57:
          extensions.add(
            TransportParameters.fromBytes(extData, messageType: messageType),
          );
          break;
        default:
          extensions.add(UnknownExtension(extType, extData));
      }
    } catch (e) {
      print(
        "      [DEBUG-EXT] Failed to parse extension 0x${extType.toRadixString(16)}: $e",
      );
      // Don't crash the whole CH, just add as unknown
      extensions.add(UnknownExtension(extType, extData));
    }
  }
  return extensions;
}

/// Serializes a list of Extension objects into the on-the-wire format.
// Uint8List serializeExtensions(List<Extension> extensions) {
//   final extensionsContentBuffer = Buffer();
//   for (final ext in extensions) {
//     final extData = ext.toBytes();
//     extensionsContentBuffer.pushUint16(ext.type);
//     extensionsContentBuffer.pushVector(extData, 2);
//   }
//   final finalBuffer = Buffer();
//   finalBuffer.pushVector(extensionsContentBuffer.toBytes(), 2);
//   return finalBuffer.toBytes();
// }

Uint8List serializeExtensions(
  List<Extension> extensions, {
  required int messageType,
}) {
  final extensionsContentBuffer = Buffer();

  for (final ext in extensions) {
    Uint8List extData;
    // Pass the messageType context to the specific extensions that need it
    if (ext is SupportedVersionsExtension) {
      extData = ext.toBytesLocal(messageType: messageType);
    } else if (ext is KeyShareExtension) {
      extData = ext.toBytesLocal(messageType: messageType);
    } else {
      extData = ext.toBytes();
    }

    extensionsContentBuffer.pushUint16(ext.type);
    extensionsContentBuffer.pushVector(extData, 2);
  }

  final finalBuffer = Buffer();
  finalBuffer.pushVector(extensionsContentBuffer.toBytes(), 2);
  return finalBuffer.toBytes();
}
