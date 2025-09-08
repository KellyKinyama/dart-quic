// lib/tls_responder.dart
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/export.dart' as pc;
import '../hkdf.dart';
import '../payload_parser9.dart'; // Your main parser file

/// A container for the server's response.
class ServerHelloResponse {
  final Uint8List serverHelloBytes;
  final Uint8List serverHandshakeSecret;
  final Uint8List clientHandshakeSecret;

  ServerHelloResponse(
    this.serverHelloBytes,
    this.serverHandshakeSecret,
    this.clientHandshakeSecret,
  );
}

/// Creates a ServerHello response based on a ClientHello.
Future<ServerHelloResponse> createServerHelloResponse(
  Uint8List clientHelloBytes,
) async {
  // 1. PARSE THE CLIENT HELLO
  final clientHello = parseTlsMessages(clientHelloBytes).first as ClientHello;

  // 2. NEGOTIATE PARAMETERS
  final keyShareExt = clientHello.extensions.firstWhere(
    (ext) => ext.type == 0x0033,
  ); // key_share
  final clientKeyShare = _parseKeyShare(keyShareExt.data);

  // For this example, we assume we support x25519 (0x001d) and the client offered it.
  final clientPublicKeyBytes = clientKeyShare[0x001d]!;
  final clientPublicKey = crypto.SimplePublicKey(
    clientPublicKeyBytes,
    type: crypto.KeyPairType.x25519,
  );

  // We'll choose this cipher suite (assuming client offered it)
  const chosenCipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256

  // 3. PERFORM KEY EXCHANGE
  final algorithm = crypto.X25519();
  final serverKeyPair = await algorithm.newKeyPair();
  final serverPublicKey = await serverKeyPair.extractPublicKey();
  final sharedSecret = await algorithm.sharedSecretKey(
    keyPair: serverKeyPair,
    remotePublicKey: clientPublicKey,
  );
  final sharedSecretBytes = await sharedSecret.extractBytes();

  // 4. DERIVE HANDSHAKE KEYS using the TLS 1.3 Key Schedule
  final handshakeHash = await _hashTranscript(clientHelloBytes);

  final earlySecret = _hkdfExtract(Uint8List(0), Uint8List(32)); // No PSK
  final derivedSecret = _deriveSecret(earlySecret, 'derived', Uint8List(0));
  final handshakeSecret = _hkdfExtract(derivedSecret, sharedSecretBytes);

  final clientHandshakeSecret = _deriveSecret(
    handshakeSecret,
    'c hs traffic',
    handshakeHash,
  );
  final serverHandshakeSecret = _deriveSecret(
    handshakeSecret,
    's hs traffic',
    handshakeHash,
  );

  // 5. BUILD THE SERVER HELLO
  final serverHelloObject = ServerHello(
    random: crypto.SecretKey.random(length: 32).extractSync(),
    legacySessionIdEcho: clientHello.legacySessionId,
    cipherSuite: chosenCipherSuite,
    extensions: [
      TlsExtension(
        0x002b,
        Uint8List.fromList([0x03, 0x04]),
      ), // supported_versions: TLS 1.3
      TlsExtension(
        0x0033, // key_share
        (BytesBuilder()
              ..add(
                (ByteData(2)..setUint16(0, 0x001d)).buffer.asUint8List(),
              ) // x25519
              ..add(
                (ByteData(2)..setUint16(0, 32)).buffer.asUint8List(),
              ) // length
              ..add(await serverPublicKey.extractBytes()))
            .toBytes(),
      ),
    ],
  );

  final serverHelloBytes = buildTlsMessage(serverHelloObject);

  return ServerHelloResponse(
    serverHelloBytes,
    serverHandshakeSecret,
    clientHandshakeSecret,
  );
}

// --- Key Schedule Helper Functions (from RFC 8446) ---

// Uint8List _hkdfExtract(Uint8List salt, Uint8List ikm) {
//   final hmac = pc.Hmac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(salt));
//   return hmac.process(ikm);
// }

// Uint8List _hkdfExpandLabel(Uint8List secret, String label, int length) {
//   final hkdf = pc.HKDF(pc.SHA256Digest());
//   hkdf.init(pc.HkdfParameters(secret, length, Uint8List(0)));
//   final labelBytes = Uint8List.fromList('tls13 $label'.codeUnits);
//   final hkdfLabel = BytesBuilder()
//     ..add((ByteData(2)..setUint16(0, length)).buffer.asUint8List())
//     ..addByte(labelBytes.length)
//     ..add(labelBytes)
//     ..addByte(0); // Context
//   return hkdf.deriveKey(hkdfLabel.toBytes());
// }

Uint8List _deriveSecret(
  Uint8List secret,
  String label,
  Uint8List transcriptHash,
) {
  return hkdfExpandLabel(secret, label, transcriptHash.length);
}

Future<Uint8List> _hashTranscript(Uint8List clientHello) async {
  final hash = await crypto.Sha256().hash(clientHello);
  return Uint8List.fromList(hash.bytes);
}

Map<int, Uint8List> _parseKeyShare(Uint8List keyShareData) {
  final buffer = Buffer(data: keyShareData);
  final totalLen = buffer.pullUint16();
  final shares = <int, Uint8List>{};
  int read = 0;
  while (read < totalLen) {
    final group = buffer.pullUint16();
    final keyLen = buffer.pullUint16();
    final key = buffer.pullBytes(keyLen);
    shares[group] = key;
    read += 4 + keyLen;
  }
  return shares;
}
