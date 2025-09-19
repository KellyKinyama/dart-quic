import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../../buffer.dart';
import '../handshake.dart';

// class Extension {
//   final int type;
//   final Uint8List data;
//   Extension(this.type, this.data);
//   @override
//   String toString() =>
//       'Extension(type: ${extensionTypesMap[type] ?? type}, len: ${data.length})';
// }

// List<Extension> parseExtensions(Buffer buffer) {
//   if (buffer.eof) return [];
//   final totalExtLen = buffer.pullUint16();
//   final extEndOffset = buffer.readOffset + totalExtLen;
//   final extensions = <Extension>[];
//   while (buffer.readOffset < extEndOffset) {
//     extensions.add(Extension(buffer.pullUint16(), buffer.pullVector(2)));
//   }
//   return extensions;
// }

// extensions.dart

// import 'dart:typed_data';

// import '../../buffer.dart';
// import 'handshake.dart';

// #############################################################################
// ## SECTION 1: ABSTRACT AND FALLBACK EXTENSION CLASSES
// #############################################################################

/// Abstract base class for all TLS extensions.
abstract class Extension {
  final int type;
  String get typeName => extensionTypesMap[type] ?? 'Unknown';
  Extension(this.type);
}

/// A fallback for any extension type that is not explicitly parsed.
/// It stores the raw data, maintaining the original behavior.
class UnknownExtension extends Extension {
  final Uint8List data;
  UnknownExtension(int type, this.data) : super(type);
  @override
  String toString() =>
      'Extension(type: $typeName ($type), len: ${data.length})';
}

// #############################################################################
// ## SECTION 2: SPECIFIC PARSED EXTENSION CLASSES
// #############################################################################

class SupportedVersionsExtension extends Extension {
  // In a ServerHello, this will contain exactly one version.
  final List<int> versions;
  SupportedVersionsExtension(this.versions) : super(43);

  factory SupportedVersionsExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    // For ServerHello, there's only a single 2-byte version.
    // For ClientHello, it's a vector. We'll handle the SH case for simplicity.
    if (data.length == 2) {
      return SupportedVersionsExtension([buffer.pullUint16()]);
    }
    // Full ClientHello parsing
    final versionsListBytes = buffer.pullVector(1);
    final versionsBuffer = Buffer(data: versionsListBytes);
    final versions = <int>[];
    while (!versionsBuffer.eof) {
      versions.add(versionsBuffer.pullUint16());
    }
    return SupportedVersionsExtension(versions);
  }

  @override
  String toString() {
    final versionStr = versions
        .map((v) => protocolVersionMap[v] ?? '0x${v.toRadixString(16)}')
        .join(', ');
    // ServerHello contains only the selected version
    if (versions.length == 1) {
      return 'SupportedVersions(selected: $versionStr)';
    }
    return 'SupportedVersions(versions: [$versionStr])';
  }
}

/// Represents a single key share entry within the KeyShare extension.
class KeyShareEntry {
  final int group;
  final Uint8List keyExchange;

  KeyShareEntry(this.group, this.keyExchange);

  factory KeyShareEntry.fromBytes(Buffer buffer) {
    final group = buffer.pullUint16();
    final keyExchange = buffer.pullVector(2);
    return KeyShareEntry(group, keyExchange);
  }
  @override
  String toString() {
    final groupName = namedGroupMap[group] ?? 'Unknown';
    final keyHex = HEX.encode(keyExchange.sublist(0, 4));
    return 'KeyShareEntry(group: $groupName, key: $keyHex...)';
  }
}

class KeyShareExtension extends Extension {
  // In ServerHello, this will be a single entry. In ClientHello, a list.
  final List<KeyShareEntry> shares;
  KeyShareExtension(this.shares) : super(51);

  factory KeyShareExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    final shares = <KeyShareEntry>[];

    // ServerHello contains just one KeyShareEntry, not a list.
    if (data.length < 4) {
      // This might be a HelloRetryRequest, which we can handle later if needed.
      // For now, assume it's a ServerHello by structure.
      shares.add(KeyShareEntry.fromBytes(buffer));
    } else {
      // ClientHello contains a list of shares
      final sharesListBytes = buffer.pullVector(2);
      final sharesBuffer = Buffer(data: sharesListBytes);
      while (!sharesBuffer.eof) {
        shares.add(KeyShareEntry.fromBytes(sharesBuffer));
      }
    }

    return KeyShareExtension(shares);
  }

  @override
  String toString() => 'KeyShare(shares: $shares)';
}

class SupportedGroupsExtension extends Extension {
  final List<int> namedGroupList;
  SupportedGroupsExtension(this.namedGroupList) : super(10);

  factory SupportedGroupsExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    final groupListBytes = buffer.pullVector(2);
    final groupBuffer = Buffer(data: groupListBytes);
    final groups = <int>[];
    while (!groupBuffer.eof) {
      groups.add(groupBuffer.pullUint16());
    }
    return SupportedGroupsExtension(groups);
  }
  @override
  String toString() {
    final groupNames = namedGroupList
        .map((g) => namedGroupMap[g] ?? 'Unknown')
        .join(', ');
    return 'SupportedGroups(groups: [$groupNames])';
  }
}

class SignatureAlgorithmsExtension extends Extension {
  final List<int> supportedSignatureAlgorithms;
  SignatureAlgorithmsExtension(this.supportedSignatureAlgorithms) : super(13);

  factory SignatureAlgorithmsExtension.fromBytes(Uint8List data) {
    final buffer = Buffer(data: data);
    final sigListBytes = buffer.pullVector(2);
    final sigBuffer = Buffer(data: sigListBytes);
    final sigs = <int>[];
    while (!sigBuffer.eof) {
      sigs.add(sigBuffer.pullUint16());
    }
    return SignatureAlgorithmsExtension(sigs);
  }
  @override
  String toString() {
    final sigNames = supportedSignatureAlgorithms
        .map((s) => signatureSchemeMap[s] ?? 'Unknown')
        .join(', ');
    return 'SignatureAlgorithms(algorithms: [$sigNames])';
  }
}

// #############################################################################
// ## SECTION 3: FACTORY PARSER FUNCTION
// #############################################################################

/// Parses the extension block and returns a list of specific, parsed Extension objects.
List<Extension> parseExtensions(Buffer buffer) {
  if (buffer.eof) return [];
  final totalExtLen = buffer.pullUint16();
  final extEndOffset = buffer.readOffset + totalExtLen;
  final extensions = <Extension>[];

  while (buffer.readOffset < extEndOffset) {
    final extType = buffer.pullUint16();
    final extData = buffer.pullVector(2);

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
        extensions.add(KeyShareExtension.fromBytes(extData));
        break;
      default:
        extensions.add(UnknownExtension(extType, extData));
    }
  }
  return extensions;
}
