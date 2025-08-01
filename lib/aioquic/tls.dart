import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';
import 'package:collection/collection.dart';

// Assuming these are from other parts of the library
import 'buffer.dart';
import 'quic/crypto.dart'; // Placeholder for the previous file's conversion

// Replicate OpenSSL's crypto library behavior.
// In a real implementation, you'd use a robust package like `pointycastle`
// or a platform-specific FFI to a native library.
// For now, these are mock classes.
class X509Certificate {
  // A mock representation of an X509 certificate.
}

class X509Store {
  void addCert(X509Certificate cert) {}
  void loadLocations(String? caFile, String? caPath) {}
}

class X509StoreContext {
  X509StoreContext(
    X509Store store,
    X509Certificate cert,
    List<X509Certificate> chain,
  ) {}
  void verifyCertificate() {}
}

// Replicate cryptography library functionality.
// Assuming we're using PointyCastle for cryptography.
class PrivateKey {
  // A mock representation of a private key.
}

class PublicKey {
  // A mock representation of a public key.
}

// Type definitions
typedef PrivateKeyTypes = PrivateKey;
typedef CertificateIssuerPublicKeyTypes = PublicKey;
typedef Callback = void Function();

// Constants
const TLS_VERSION_1_2 = 0x0303;
const TLS_VERSION_1_3 = 0x0304;
const TLS_VERSION_1_3_DRAFT_28 = 0x7F1C;
const TLS_VERSION_1_3_DRAFT_27 = 0x7F1B;
const TLS_VERSION_1_3_DRAFT_26 = 0x7F1A;

final Uint8List CLIENT_CONTEXT_STRING = Uint8List.fromList(
  utf8.encode("TLS 1.3, client CertificateVerify"),
);
final Uint8List SERVER_CONTEXT_STRING = Uint8List.fromList(
  utf8.encode("TLS 1.3, server CertificateVerify"),
);

DateTime utcnow() {
  return DateTime.now().toUtc();
}

enum AlertDescription {
  close_notify(0),
  unexpected_message(10),
  bad_record_mac(20),
  record_overflow(22),
  handshake_failure(40),
  bad_certificate(42),
  unsupported_certificate(43),
  certificate_revoked(44),
  certificate_expired(45),
  certificate_unknown(46),
  illegal_parameter(47),
  unknown_ca(48),
  access_denied(49),
  decode_error(50),
  decrypt_error(51),
  protocol_version(70),
  insufficient_security(71),
  internal_error(80),
  inappropriate_fallback(86),
  user_canceled(90),
  missing_extension(109),
  unsupported_extension(110),
  unrecognized_name(112),
  bad_certificate_status_response(113),
  unknown_psk_identity(115),
  certificate_required(116),
  no_application_protocol(120);

  final int value;
  const AlertDescription(this.value);
}

class Alert implements Exception {
  final AlertDescription description;
  final String message;
  Alert(this.description, this.message);
}

class AlertBadCertificate extends Alert {
  AlertBadCertificate(String message)
    : super(AlertDescription.bad_certificate, message);
}

class AlertCertificateExpired extends Alert {
  AlertCertificateExpired(String message)
    : super(AlertDescription.certificate_expired, message);
}

class AlertDecodeError extends Alert {
  AlertDecodeError(String message)
    : super(AlertDescription.decode_error, message);
}

class AlertDecryptError extends Alert {
  AlertDecryptError(String message)
    : super(AlertDescription.decrypt_error, message);
}

class AlertHandshakeFailure extends Alert {
  AlertHandshakeFailure(String message)
    : super(AlertDescription.handshake_failure, message);
}

class AlertIllegalParameter extends Alert {
  AlertIllegalParameter(String message)
    : super(AlertDescription.illegal_parameter, message);
}

class AlertInternalError extends Alert {
  AlertInternalError(String message)
    : super(AlertDescription.internal_error, message);
}

class AlertProtocolVersion extends Alert {
  AlertProtocolVersion(String message)
    : super(AlertDescription.protocol_version, message);
}

class AlertUnexpectedMessage extends Alert {
  AlertUnexpectedMessage(String message)
    : super(AlertDescription.unexpected_message, message);
}

enum Direction { DECRYPT, ENCRYPT }

enum Epoch { INITIAL, ZERO_RTT, HANDSHAKE, ONE_RTT }

enum State {
  CLIENT_HANDSHAKE_START,
  CLIENT_EXPECT_SERVER_HELLO,
  CLIENT_EXPECT_ENCRYPTED_EXTENSIONS,
  CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE,
  CLIENT_EXPECT_CERTIFICATE,
  CLIENT_EXPECT_CERTIFICATE_VERIFY,
  CLIENT_EXPECT_FINISHED,
  CLIENT_POST_HANDSHAKE,
  SERVER_EXPECT_CLIENT_HELLO,
  SERVER_EXPECT_CERTIFICATE,
  SERVER_EXPECT_CERTIFICATE_VERIFY,
  SERVER_EXPECT_FINISHED,
  SERVER_POST_HANDSHAKE,
}

Uint8List hkdfLabel(Uint8List label, Uint8List hashValue, int length) {
  final fullLabel = Uint8List.fromList(utf8.encode("tls13 ") + label);
  final buffer = BytesBuilder();
  buffer.addByte((length >> 8) & 0xFF);
  buffer.addByte(length & 0xFF);
  buffer.addByte(fullLabel.length);
  buffer.add(fullLabel);
  buffer.addByte(hashValue.length);
  buffer.add(hashValue);
  return buffer.toBytes();
}

Uint8List hkdfExpandLabel(
  Digest algorithm,
  Uint8List secret,
  Uint8List label,
  Uint8List hashValue,
  int length,
) {
  // This is a simplified implementation. In a real-world scenario, you'd use
  // a proper HKDF implementation from a crypto library.
  return Uint8List(length);
}

Uint8List hkdfExtract(Digest algorithm, Uint8List salt, Uint8List keyMaterial) {
  // Simplified HKDF-extract implementation.
  return Uint8List(algorithm.digestSize);
}

PrivateKeyTypes loadPemPrivateKey(Uint8List data, {Uint8List? password}) {
  // Mock implementation
  return PrivateKey();
}

List<X509Certificate> loadPemX509Certificates(Uint8List data) {
  // Mock implementation
  return [];
}

void verifyCertificate({
  required X509Certificate certificate,
  List<X509Certificate> chain = const [],
  String? serverName,
  Uint8List? cadata,
  String? cafile,
  String? capath,
}) {
  // Mock implementation of certificate verification.
  // This would involve date checking, hostname validation, and chain of trust
  // validation using a crypto library.
}

enum CipherSuite {
  AES_128_GCM_SHA256(0x1301),
  AES_256_GCM_SHA384(0x1302),
  CHACHA20_POLY1305_SHA256(0x1303),
  EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF);

  final int value;
  const CipherSuite(this.value);
}

enum CompressionMethod {
  NULL(0);

  final int value;
  const CompressionMethod(this.value);
}

enum ExtensionType {
  SERVER_NAME(0),
  STATUS_REQUEST(5),
  SUPPORTED_GROUPS(10),
  SIGNATURE_ALGORITHMS(13),
  ALPN(16),
  COMPRESS_CERTIFICATE(27),
  PRE_SHARED_KEY(41),
  EARLY_DATA(42),
  SUPPORTED_VERSIONS(43),
  COOKIE(44),
  PSK_KEY_EXCHANGE_MODES(45),
  KEY_SHARE(51),
  QUIC_TRANSPORT_PARAMETERS(0x0039),
  QUIC_TRANSPORT_PARAMETERS_DRAFT(0xFFA5),
  ENCRYPTED_SERVER_NAME(65486);

  final int value;
  const ExtensionType(this.value);
}

enum Group {
  SECP256R1(0x0017),
  SECP384R1(0x0018),
  SECP521R1(0x0019),
  X25519(0x001D),
  X448(0x001E),
  GREASE(0xAAAA);

  final int value;
  const Group(this.value);
}

enum HandshakeType {
  CLIENT_HELLO(1),
  SERVER_HELLO(2),
  NEW_SESSION_TICKET(4),
  END_OF_EARLY_DATA(5),
  ENCRYPTED_EXTENSIONS(8),
  CERTIFICATE(11),
  CERTIFICATE_REQUEST(13),
  CERTIFICATE_VERIFY(15),
  FINISHED(20),
  KEY_UPDATE(24),
  COMPRESSED_CERTIFICATE(25),
  MESSAGE_HASH(254);

  final int value;
  const HandshakeType(this.value);
}

enum NameType {
  HOST_NAME(0);

  final int value;
  const NameType(this.value);
}

enum PskKeyExchangeMode {
  PSK_KE(0),
  PSK_DHE_KE(1);

  final int value;
  const PskKeyExchangeMode(this.value);
}

enum SignatureAlgorithm {
  ECDSA_SECP256R1_SHA256(0x0403),
  ECDSA_SECP384R1_SHA384(0x0503),
  ECDSA_SECP521R1_SHA512(0x0603),
  ED25519(0x0807),
  ED448(0x0808),
  RSA_PKCS1_SHA256(0x0401),
  RSA_PKCS1_SHA384(0x0501),
  RSA_PKCS1_SHA512(0x0601),
  RSA_PSS_PSS_SHA256(0x0809),
  RSA_PSS_PSS_SHA384(0x080A),
  RSA_PSS_PSS_SHA512(0x080B),
  RSA_PSS_RSAE_SHA256(0x0804),
  RSA_PSS_RSAE_SHA384(0x0805),
  RSA_PSS_RSAE_SHA512(0x0806),
  RSA_PKCS1_SHA1(0x0201),
  SHA1_DSA(0x0202),
  ECDSA_SHA1(0x0203);

  final int value;
  const SignatureAlgorithm(this.value);
}

// Blocks
Future<void> pullBlock(
  Buffer buf,
  int capacity,
  Function(int length) callback,
) async {
  final length = (await buf.pullBytes(
    capacity,
  )).buffer.asByteData().getUint64(0);
  final end = buf.tell() + length;
  await callback(length);
  if (buf.tell() != end) {
    throw AlertDecodeError("extra bytes at the end of a block");
  }
}

Future<void> pushBlock(Buffer buf, int capacity, Function() callback) async {
  final start = buf.tell() + capacity;
  buf.seek(start);
  await callback();
  final end = buf.tell();
  final length = end - start;
  buf.seek(start - capacity);
  final lengthBytes = Uint8List(capacity);
  final byteData = lengthBytes.buffer.asByteData();
  byteData.setUint64(0, length);
  buf.pushBytes(lengthBytes);
  buf.seek(end);
}

// Lists
class SkipItem implements Exception {}

Future<List<T>> pullList<T>(
  Buffer buf,
  int capacity,
  Future<T> Function() func,
) async {
  final items = <T>[];
  await pullBlock(buf, capacity, (length) async {
    final end = buf.tell() + length;
    while (buf.tell() < end) {
      try {
        items.add(await func());
      } on SkipItem {
        continue;
      }
    }
  });
  return items;
}

Future<void> pushList<T>(
  Buffer buf,
  int capacity,
  Function(T) func,
  List<T> values,
) async {
  await pushBlock(buf, capacity, () async {
    for (var value in values) {
      await func(value);
    }
  });
}

Future<Uint8List> pullOpaque(Buffer buf, int capacity) async {
  late Uint8List result;
  await pullBlock(buf, capacity, (length) async {
    result = await buf.pullBytes(length);
  });
  return result;
}

Future<void> pushOpaque(Buffer buf, int capacity, Uint8List value) async {
  await pushBlock(buf, capacity, () {
    buf.pushBytes(value);
  });
}

Future<void> pushExtension(
  Buffer buf,
  int extensionType,
  Function() callback,
) async {
  buf.pushUint16(extensionType);
  await pushBlock(buf, 2, callback);
}

// ServerName
Future<String> pullServerName(Buffer buf) async {
  late String serverName;
  await pullBlock(buf, 2, (length) async {
    final nameType = buf.pullUint8();
    if (nameType != NameType.HOST_NAME.value) {
      throw AlertIllegalParameter(
        "ServerName has an unknown name type $nameType",
      );
    }
    serverName = utf8.decode(await pullOpaque(buf, 2));
  });
  return serverName;
}

Future<void> pushServerName(Buffer buf, String serverName) async {
  await pushBlock(buf, 2, () async {
    buf.pushUint8(NameType.HOST_NAME.value);
    await pushOpaque(buf, 2, utf8.encode(serverName));
  });
}

// KeyShareEntry
typedef KeyShareEntry = Tuple<int, Uint8List>;

Future<KeyShareEntry> pullKeyShare(Buffer buf) async {
  final group = buf.pullUint16();
  final data = await pullOpaque(buf, 2);
  return Tuple(group, data);
}

Future<void> pushKeyShare(Buffer buf, KeyShareEntry value) async {
  buf.pushUint16(value.item1);
  await pushOpaque(buf, 2, value.item2);
}

// ALPN
Future<String> pullAlpnProtocol(Buffer buf) async {
  try {
    return utf8.decode(await pullOpaque(buf, 1));
  } on FormatException {
    throw SkipItem();
  }
}

Future<void> pushAlpnProtocol(Buffer buf, String protocol) async {
  await pushOpaque(buf, 1, utf8.encode(protocol));
}

// Pre-shared Key
typedef PskIdentity = Tuple<Uint8List, int>;

class OfferedPsks {
  List<PskIdentity> identities;
  List<Uint8List> binders;

  OfferedPsks({required this.identities, required this.binders});
}

Future<PskIdentity> pullPskIdentity(Buffer buf) async {
  final identity = await pullOpaque(buf, 2);
  final obfuscatedTicketAge = buf.pullUint32();
  return Tuple(identity, obfuscatedTicketAge);
}

Future<void> pushPskIdentity(Buffer buf, PskIdentity entry) async {
  await pushOpaque(buf, 2, entry.item1);
  buf.pushUint32(entry.item2);
}

Future<Uint8List> pullPskBinder(Buffer buf) async {
  return await pullOpaque(buf, 1);
}

Future<void> pushPskBinder(Buffer buf, Uint8List binder) async {
  await pushOpaque(buf, 1, binder);
}

Future<OfferedPsks> pullOfferedPsks(Buffer buf) async {
  final identities = await pullList(buf, 2, () => pullPskIdentity(buf));
  final binders = await pullList(buf, 2, () => pullPskBinder(buf));
  return OfferedPsks(identities: identities, binders: binders);
}

Future<void> pushOfferedPsks(Buffer buf, OfferedPsks preSharedKey) async {
  await pushList(
    buf,
    2,
    (id) => pushPskIdentity(buf, id),
    preSharedKey.identities,
  );
  await pushList(
    buf,
    2,
    (binder) => pushPskBinder(buf, binder),
    preSharedKey.binders,
  );
}

// Messages
typedef Extension = Tuple<int, Uint8List>;

class ClientHello {
  Uint8List random;
  Uint8List legacySessionId;
  List<int> cipherSuites;
  List<int> legacyCompressionMethods;

  List<String>? alpnProtocols;
  bool earlyData = false;
  List<KeyShareEntry>? keyShare;
  OfferedPsks? preSharedKey;
  List<int>? pskKeyExchangeModes;
  String? serverName;
  List<int>? signatureAlgorithms;
  List<int>? supportedGroups;
  List<int>? supportedVersions;

  List<Extension> otherExtensions;

  ClientHello({
    required this.random,
    required this.legacySessionId,
    required this.cipherSuites,
    required this.legacyCompressionMethods,
    this.alpnProtocols,
    this.earlyData = false,
    this.keyShare,
    this.preSharedKey,
    this.pskKeyExchangeModes,
    this.serverName,
    this.signatureAlgorithms,
    this.supportedGroups,
    this.supportedVersions,
    this.otherExtensions = const [],
  });
}

void pullHandshakeType(Buffer buf, HandshakeType expectedType) {
  final messageType = buf.pullUint8();
  if (messageType != expectedType.value) {
    throw AlertDecodeError(
      "Unexpected handshake message type: $messageType, expected ${expectedType.value}",
    );
  }
}

Future<ClientHello> pullClientHello(Buffer buf) async {
  pullHandshakeType(buf, HandshakeType.CLIENT_HELLO);
  late ClientHello hello;
  await pullBlock(buf, 3, (length) async {
    if (buf.pullUint16() != TLS_VERSION_1_2) {
      throw AlertDecodeError("ClientHello version is not 1.2");
    }

    hello = ClientHello(
      random: await buf.pullBytes(32),
      legacySessionId: await pullOpaque(buf, 1),
      cipherSuites: await pullList(
        buf,
        2,
        () => Future.value(buf.pullUint16()),
      ),
      legacyCompressionMethods: await pullList(
        buf,
        1,
        () => Future.value(buf.pullUint8()),
      ),
    );

    var afterPsk = false;
    Future<void> pullExtension() async {
      if (afterPsk) {
        throw AlertIllegalParameter("PreSharedKey is not the last extension");
      }

      final extensionType = buf.pullUint16();
      final extensionLength = buf.pullUint16();
      if (extensionType == ExtensionType.KEY_SHARE.value) {
        hello.keyShare = await pullList(buf, 2, () => pullKeyShare(buf));
      } else if (extensionType == ExtensionType.SUPPORTED_VERSIONS.value) {
        hello.supportedVersions = await pullList(
          buf,
          1,
          () => Future.value(buf.pullUint16()),
        );
      } else if (extensionType == ExtensionType.SIGNATURE_ALGORITHMS.value) {
        hello.signatureAlgorithms = await pullList(
          buf,
          2,
          () => Future.value(buf.pullUint16()),
        );
      } else if (extensionType == ExtensionType.SUPPORTED_GROUPS.value) {
        hello.supportedGroups = await pullList(
          buf,
          2,
          () => Future.value(buf.pullUint16()),
        );
      } else if (extensionType == ExtensionType.PSK_KEY_EXCHANGE_MODES.value) {
        hello.pskKeyExchangeModes = await pullList(
          buf,
          1,
          () => Future.value(buf.pullUint8()),
        );
      } else if (extensionType == ExtensionType.SERVER_NAME.value) {
        hello.serverName = await pullServerName(buf);
      } else if (extensionType == ExtensionType.ALPN.value) {
        hello.alpnProtocols = await pullList(
          buf,
          2,
          () => pullAlpnProtocol(buf),
        );
      } else if (extensionType == ExtensionType.EARLY_DATA.value) {
        hello.earlyData = true;
      } else if (extensionType == ExtensionType.PRE_SHARED_KEY.value) {
        hello.preSharedKey = await pullOfferedPsks(buf);
        afterPsk = true;
      } else {
        hello.otherExtensions.add(
          Tuple(extensionType, await buf.pullBytes(extensionLength)),
        );
      }
    }

    await pullList(buf, 2, pullExtension);
  });
  return hello;
}

Future<void> pushClientHello(Buffer buf, ClientHello hello) async {
  buf.pushUint8(HandshakeType.CLIENT_HELLO.value);
  await pushBlock(buf, 3, () async {
    buf.pushUint16(TLS_VERSION_1_2);
    buf.pushBytes(hello.random);
    await pushOpaque(buf, 1, hello.legacySessionId);
    await pushList(buf, 2, buf.pushUint16, hello.cipherSuites);
    await pushList(buf, 1, buf.pushUint8, hello.legacyCompressionMethods);

    await pushBlock(buf, 2, () async {
      await pushExtension(buf, ExtensionType.KEY_SHARE.value, () async {
        await pushList(buf, 2, (e) => pushKeyShare(buf, e), hello.keyShare!);
      });
      await pushExtension(
        buf,
        ExtensionType.SUPPORTED_VERSIONS.value,
        () async {
          await pushList(buf, 1, buf.pushUint16, hello.supportedVersions!);
        },
      );
      await pushExtension(
        buf,
        ExtensionType.SIGNATURE_ALGORITHMS.value,
        () async {
          await pushList(buf, 2, buf.pushUint16, hello.signatureAlgorithms!);
        },
      );
      await pushExtension(buf, ExtensionType.SUPPORTED_GROUPS.value, () async {
        await pushList(buf, 2, buf.pushUint16, hello.supportedGroups!);
      });
      if (hello.pskKeyExchangeModes != null) {
        await pushExtension(
          buf,
          ExtensionType.PSK_KEY_EXCHANGE_MODES.value,
          () async {
            await pushList(buf, 1, buf.pushUint8, hello.pskKeyExchangeModes!);
          },
        );
      }
      if (hello.serverName != null) {
        await pushExtension(buf, ExtensionType.SERVER_NAME.value, () async {
          await pushServerName(buf, hello.serverName!);
        });
      }
      if (hello.alpnProtocols != null) {
        await pushExtension(buf, ExtensionType.ALPN.value, () async {
          await pushList(
            buf,
            2,
            (p) => pushAlpnProtocol(buf, p),
            hello.alpnProtocols!,
          );
        });
      }
      for (final ext in hello.otherExtensions) {
        await pushExtension(buf, ext.item1, () {
          buf.pushBytes(ext.item2);
        });
      }
      if (hello.earlyData) {
        await pushExtension(buf, ExtensionType.EARLY_DATA.value, () {});
      }
      if (hello.preSharedKey != null) {
        await pushExtension(buf, ExtensionType.PRE_SHARED_KEY.value, () async {
          await pushOfferedPsks(buf, hello.preSharedKey!);
        });
      }
    });
  });
}

class ServerHello {
  Uint8List random;
  Uint8List legacySessionId;
  int cipherSuite;
  int compressionMethod;

  KeyShareEntry? keyShare;
  int? preSharedKey;
  int? supportedVersion;
  List<Extension> otherExtensions;

  ServerHello({
    required this.random,
    required this.legacySessionId,
    required this.cipherSuite,
    required this.compressionMethod,
    this.keyShare,
    this.preSharedKey,
    this.supportedVersion,
    this.otherExtensions = const [],
  });
}

Future<ServerHello> pullServerHello(Buffer buf) async {
  pullHandshakeType(buf, HandshakeType.SERVER_HELLO);
  late ServerHello hello;
  await pullBlock(buf, 3, (length) async {
    if (buf.pullUint16() != TLS_VERSION_1_2) {
      throw AlertDecodeError("ServerHello version is not 1.2");
    }

    hello = ServerHello(
      random: await buf.pullBytes(32),
      legacySessionId: await pullOpaque(buf, 1),
      cipherSuite: buf.pullUint16(),
      compressionMethod: buf.pullUint8(),
    );

    Future<void> pullExtension() async {
      final extensionType = buf.pullUint16();
      final extensionLength = buf.pullUint16();
      if (extensionType == ExtensionType.SUPPORTED_VERSIONS.value) {
        hello.supportedVersion = buf.pullUint16();
      } else if (extensionType == ExtensionType.KEY_SHARE.value) {
        hello.keyShare = await pullKeyShare(buf);
      } else if (extensionType == ExtensionType.PRE_SHARED_KEY.value) {
        hello.preSharedKey = buf.pullUint16();
      } else {
        hello.otherExtensions.add(
          Tuple(extensionType, await buf.pullBytes(extensionLength)),
        );
      }
    }

    await pullList(buf, 2, pullExtension);
  });
  return hello;
}

Future<void> pushServerHello(Buffer buf, ServerHello hello) async {
  buf.pushUint8(HandshakeType.SERVER_HELLO.value);
  await pushBlock(buf, 3, () async {
    buf.pushUint16(TLS_VERSION_1_2);
    buf.pushBytes(hello.random);

    await pushOpaque(buf, 1, hello.legacySessionId);
    buf.pushUint16(hello.cipherSuite);
    buf.pushUint8(hello.compressionMethod);

    await pushBlock(buf, 2, () async {
      if (hello.supportedVersion != null) {
        await pushExtension(buf, ExtensionType.SUPPORTED_VERSIONS.value, () {
          buf.pushUint16(hello.supportedVersion!);
        });
      }
      if (hello.keyShare != null) {
        await pushExtension(buf, ExtensionType.KEY_SHARE.value, () async {
          await pushKeyShare(buf, hello.keyShare!);
        });
      }
      if (hello.preSharedKey != null) {
        await pushExtension(buf, ExtensionType.PRE_SHARED_KEY.value, () {
          buf.pushUint16(hello.preSharedKey!);
        });
      }
      for (final ext in hello.otherExtensions) {
        await pushExtension(buf, ext.item1, () {
          buf.pushBytes(ext.item2);
        });
      }
    });
  });
}

class NewSessionTicket {
  int ticketLifetime;
  int ticketAgeAdd;
  Uint8List ticketNonce;
  Uint8List ticket;
  int? maxEarlyDataSize;
  List<Extension> otherExtensions;

  NewSessionTicket({
    this.ticketLifetime = 0,
    this.ticketAgeAdd = 0,
    Uint8List? ticketNonce,
    Uint8List? ticket,
    this.maxEarlyDataSize,
    this.otherExtensions = const [],
  }) : ticketNonce = ticketNonce ?? Uint8List(0),
       ticket = ticket ?? Uint8List(0);
}

Future<NewSessionTicket> pullNewSessionTicket(Buffer buf) async {
  final newSessionTicket = NewSessionTicket();
  pullHandshakeType(buf, HandshakeType.NEW_SESSION_TICKET);
  await pullBlock(buf, 3, (length) async {
    newSessionTicket.ticketLifetime = buf.pullUint32();
    newSessionTicket.ticketAgeAdd = buf.pullUint32();
    newSessionTicket.ticketNonce = await pullOpaque(buf, 1);
    newSessionTicket.ticket = await pullOpaque(buf, 2);

    Future<void> pullExtension() async {
      final extensionType = buf.pullUint16();
      final extensionLength = buf.pullUint16();
      if (extensionType == ExtensionType.EARLY_DATA.value) {
        newSessionTicket.maxEarlyDataSize = buf.pullUint32();
      } else {
        newSessionTicket.otherExtensions.add(
          Tuple(extensionType, await buf.pullBytes(extensionLength)),
        );
      }
    }

    await pullList(buf, 2, pullExtension);
  });
  return newSessionTicket;
}

Future<void> pushNewSessionTicket(
  Buffer buf,
  NewSessionTicket newSessionTicket,
) async {
  buf.pushUint8(HandshakeType.NEW_SESSION_TICKET.value);
  await pushBlock(buf, 3, () async {
    buf.pushUint32(newSessionTicket.ticketLifetime);
    buf.pushUint32(newSessionTicket.ticketAgeAdd);
    await pushOpaque(buf, 1, newSessionTicket.ticketNonce);
    await pushOpaque(buf, 2, newSessionTicket.ticket);

    await pushBlock(buf, 2, () async {
      if (newSessionTicket.maxEarlyDataSize != null) {
        await pushExtension(buf, ExtensionType.EARLY_DATA.value, () {
          buf.pushUint32(newSessionTicket.maxEarlyDataSize!);
        });
      }
      for (final ext in newSessionTicket.otherExtensions) {
        await pushExtension(buf, ext.item1, () {
          buf.pushBytes(ext.item2);
        });
      }
    });
  });
}

class EncryptedExtensions {
  String? alpnProtocol;
  bool earlyData = false;
  List<Extension> otherExtensions;

  EncryptedExtensions({
    this.alpnProtocol,
    this.earlyData = false,
    this.otherExtensions = const [],
  });
}

Future<EncryptedExtensions> pullEncryptedExtensions(Buffer buf) async {
  final extensions = EncryptedExtensions();
  pullHandshakeType(buf, HandshakeType.ENCRYPTED_EXTENSIONS);
  await pullBlock(buf, 3, (length) async {
    Future<void> pullExtension() async {
      final extensionType = buf.pullUint16();
      final extensionLength = buf.pullUint16();
      if (extensionType == ExtensionType.ALPN.value) {
        extensions.alpnProtocol = (await pullList(
          buf,
          2,
          () => pullAlpnProtocol(buf),
        ))[0];
      } else if (extensionType == ExtensionType.EARLY_DATA.value) {
        extensions.earlyData = true;
      } else {
        extensions.otherExtensions.add(
          Tuple(extensionType, await buf.pullBytes(extensionLength)),
        );
      }
    }

    await pullList(buf, 2, pullExtension);
  });
  return extensions;
}

Future<void> pushEncryptedExtensions(
  Buffer buf,
  EncryptedExtensions extensions,
) async {
  buf.pushUint8(HandshakeType.ENCRYPTED_EXTENSIONS.value);
  await pushBlock(buf, 3, () async {
    await pushBlock(buf, 2, () async {
      if (extensions.alpnProtocol != null) {
        await pushExtension(buf, ExtensionType.ALPN.value, () async {
          await pushList(buf, 2, (p) => pushAlpnProtocol(buf, p), [
            extensions.alpnProtocol!,
          ]);
        });
      }
      if (extensions.earlyData) {
        await pushExtension(buf, ExtensionType.EARLY_DATA.value, () {});
      }
      for (final ext in extensions.otherExtensions) {
        await pushExtension(buf, ext.item1, () {
          buf.pushBytes(ext.item2);
        });
      }
    });
  });
}

typedef CertificateEntry = Tuple<Uint8List, Uint8List>;

class Certificate {
  Uint8List requestContext;
  List<CertificateEntry> certificates;

  Certificate({Uint8List? requestContext, List<CertificateEntry>? certificates})
    : requestContext = requestContext ?? Uint8List(0),
      certificates = certificates ?? [];
}

Future<Certificate> pullCertificate(Buffer buf) async {
  final certificate = Certificate();
  pullHandshakeType(buf, HandshakeType.CERTIFICATE);
  await pullBlock(buf, 3, (length) async {
    certificate.requestContext = await pullOpaque(buf, 1);

    Future<CertificateEntry> pullCertificateEntry() async {
      final data = await pullOpaque(buf, 3);
      final extensions = await pullOpaque(buf, 2);
      return Tuple(data, extensions);
    }

    certificate.certificates = await pullList(buf, 3, pullCertificateEntry);
  });
  return certificate;
}

Future<void> pushCertificate(Buffer buf, Certificate certificate) async {
  buf.pushUint8(HandshakeType.CERTIFICATE.value);
  await pushBlock(buf, 3, () async {
    await pushOpaque(buf, 1, certificate.requestContext);

    Future<void> pushCertificateEntry(CertificateEntry entry) async {
      await pushOpaque(buf, 3, entry.item1);
      await pushOpaque(buf, 2, entry.item2);
    }

    await pushList(buf, 3, pushCertificateEntry, certificate.certificates);
  });
}

class CertificateRequest {
  Uint8List requestContext;
  List<int>? signatureAlgorithms;
  List<Extension> otherExtensions;

  CertificateRequest({
    Uint8List? requestContext,
    this.signatureAlgorithms,
    this.otherExtensions = const [],
  }) : requestContext = requestContext ?? Uint8List(0);
}

Future<CertificateRequest> pullCertificateRequest(Buffer buf) async {
  final certificateRequest = CertificateRequest();
  pullHandshakeType(buf, HandshakeType.CERTIFICATE_REQUEST);
  await pullBlock(buf, 3, (length) async {
    certificateRequest.requestContext = await pullOpaque(buf, 1);

    Future<void> pullExtension() async {
      final extensionType = buf.pullUint16();
      final extensionLength = buf.pullUint16();
      if (extensionType == ExtensionType.SIGNATURE_ALGORITHMS.value) {
        certificateRequest.signatureAlgorithms = await pullList(
          buf,
          2,
          () => Future.value(buf.pullUint16()),
        );
      } else {
        certificateRequest.otherExtensions.add(
          Tuple(extensionType, await buf.pullBytes(extensionLength)),
        );
      }
    }

    await pullList(buf, 2, pullExtension);
  });
  return certificateRequest;
}

Future<void> pushCertificateRequest(
  Buffer buf,
  CertificateRequest certificateRequest,
) async {
  buf.pushUint8(HandshakeType.CERTIFICATE_REQUEST.value);
  await pushBlock(buf, 3, () async {
    await pushOpaque(buf, 1, certificateRequest.requestContext);

    await pushBlock(buf, 2, () async {
      await pushExtension(
        buf,
        ExtensionType.SIGNATURE_ALGORITHMS.value,
        () async {
          await pushList(
            buf,
            2,
            buf.pushUint16,
            certificateRequest.signatureAlgorithms!,
          );
        },
      );
      for (final ext in certificateRequest.otherExtensions) {
        await pushExtension(buf, ext.item1, () {
          buf.pushBytes(ext.item2);
        });
      }
    });
  });
}

class CertificateVerify {
  int algorithm;
  Uint8List signature;

  CertificateVerify({required this.algorithm, required this.signature});
}

Future<CertificateVerify> pullCertificateVerify(Buffer buf) async {
  pullHandshakeType(buf, HandshakeType.CERTIFICATE_VERIFY);
  late CertificateVerify verify;
  await pullBlock(buf, 3, (length) async {
    final algorithm = buf.pullUint16();
    final signature = await pullOpaque(buf, 2);
    verify = CertificateVerify(algorithm: algorithm, signature: signature);
  });
  return verify;
}

Future<void> pushCertificateVerify(Buffer buf, CertificateVerify verify) async {
  buf.pushUint8(HandshakeType.CERTIFICATE_VERIFY.value);
  await pushBlock(buf, 3, () async {
    buf.pushUint16(verify.algorithm);
    await pushOpaque(buf, 2, verify.signature);
  });
}

class Finished {
  Uint8List verifyData;

  Finished({Uint8List? verifyData}) : verifyData = verifyData ?? Uint8List(0);
}

Future<Finished> pullFinished(Buffer buf) async {
  final finished = Finished();
  pullHandshakeType(buf, HandshakeType.FINISHED);
  finished.verifyData = await pullOpaque(buf, 3);
  return finished;
}

Future<void> pushFinished(Buffer buf, Finished finished) async {
  buf.pushUint8(HandshakeType.FINISHED.value);
  await pushOpaque(buf, 3, finished.verifyData);
}

// Context

Digest cipherSuiteHash(CipherSuite cipherSuite) {
  // Mock implementation, assuming SHA256 for all.
  return SHA256Digest();
}

class KeySchedule {
  final Digest algorithm;
  final CipherSuite cipherSuite;
  int generation;
  final Digest _hash;
  final Uint8List hashEmptyValue;
  Uint8List secret;

  KeySchedule(this.cipherSuite)
    : algorithm = cipherSuiteHash(cipherSuite),
      generation = 0,
      _hash = cipherSuiteHash(cipherSuite),
      hashEmptyValue = Uint8List(cipherSuiteHash(cipherSuite).digestSize),
      secret = Uint8List(cipherSuiteHash(cipherSuite).digestSize);

  Uint8List certificateVerifyData(Uint8List contextString) {
    // This is a simplified representation.
    return Uint8List.fromList(
      Uint8List(64) +
          contextString +
          Uint8List.fromList([0]) +
          _hash.process(Uint8List(0)),
    );
  }

  Uint8List finishedVerifyData(Uint8List secret) {
    final hmacKey = hkdfExpandLabel(
      algorithm,
      secret,
      Uint8List.fromList(utf8.encode("finished")),
      Uint8List(0),
      algorithm.digestSize,
    );
    final hmac = HMac(SHA256Digest(), hmacKey);
    hmac.init(KeyParameter(hmacKey));
    final dataToHash = _hash.process(Uint8List(0));
    hmac.update(dataToHash, 0, dataToHash.length);
    return hmac.process(Uint8List(0));
  }

  Uint8List deriveSecret(Uint8List label) {
    return hkdfExpandLabel(
      algorithm,
      secret,
      label,
      _hash.process(Uint8List(0)),
      algorithm.digestSize,
    );
  }

  void extract(Uint8List? keyMaterial) {
    if (keyMaterial == null) {
      // Logic for extract with no key material
    }
  }
}
