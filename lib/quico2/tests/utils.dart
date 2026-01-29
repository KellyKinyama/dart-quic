import 'dart:typed_data';

Uint8List splitHexString(String hex) {
  final cleanHex = hex.replaceAll(RegExp(r'\s|0x'), '');
  final bytes = <int>[];
  for (var i = 0; i < cleanHex.length; i += 2) {
    bytes.add(int.parse(cleanHex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

String splitHexStringTrimed(String hex) {
  return hex.replaceAll(RegExp(r'\s|0x'), '');
}
