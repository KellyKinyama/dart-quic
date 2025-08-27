// Filename: configuration.dart
import 'dart:io';
import 'package:cryptography/cryptography.dart';
import 'tls.dart'; // From previous conversion
import 'packet.dart';
import 'logger.dart';

const smallestMaxDatagramSize = 1200;

class QuicConfiguration {
  /// A list of supported ALPN protocols.
  final List<String> alpnProtocols;

  /// The length in bytes of local connection IDs.
  final int connectionIdLength;

  /// The idle timeout in seconds.
  final double idleTimeout;

  /// Whether this is the client side of the QUIC connection.
  final bool isClient;

  /// Connection-wide flow control limit.
  final int maxData;
  
  /// The maximum QUIC payload size in bytes to send.
  final int maxDatagramSize;

  /// Per-stream flow control limit.
  final int maxStreamData;
  
  /// The QuicLogger instance to log events to.
  final QuicLogger? quicLogger;

  /// A file-like object in which to log traffic secrets for Wireshark.
  final IOSink? secretsLogFile;

  /// The server name to use for TLS SNI and certificate validation.
  final String? serverName;

  /// A list of supported QUIC versions.
  final List<int> supportedVersions;

  // TLS settings
  final X509Certificate? certificate;
  final List<X509Certificate>? certificateChain;
  final PrivateKey? privateKey;
  final String? caFile;

  QuicConfiguration({
    required this.isClient,
    this.alpnProtocols = const [],
    this.connectionIdLength = 8,
    this.idleTimeout = 60.0,
    this.maxData = 1048576,
    this.maxDatagramSize = smallestMaxDatagramSize,
    this.maxStreamData = 1048576,
    this.quicLogger,
    this.secretsLogFile,
    this.serverName,
    this.supportedVersions = const [QuicProtocolVersion.version1],
    this.certificate,
    this.certificateChain,
    this.privateKey,
    this.caFile,
  });
}