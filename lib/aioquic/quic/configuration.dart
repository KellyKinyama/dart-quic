// The following code is a Dart translation of the `configuration.py` Python module.
// This translation attempts to maintain the original logic and structure while adapting to Dart syntax,
// type system, and conventions. Some Python features, like dynamic typing and certain library functions,
// have been mapped to their nearest Dart equivalents. Due to the complexity and low-level nature of
// the original code, some parts are highly specific and may require corresponding Dart libraries or
// custom implementations. This is a best-effort conversion and may require further refinement
// for a production environment.

import 'dart:io';
import 'dart:typed_data';
import 'package:x509/x509.dart' as x509; // Assuming a library like this for X.509 certs
import 'package:pointycastle/export.dart' as pointycastle; // For private key handling
import '../tls.dart' as tls;
import 'package:quic_dart/quic/logger.dart';
import 'packet.dart';

const int smallestMaxDatagramSize = 1200;

class QuicConfiguration {
  final List<String>? alpnProtocols;
  final String congestionControlAlgorithm;
  final int connectionIdLength;
  final double idleTimeout;
  final bool isClient;
  final int maxData;
  final int maxDatagramSize;
  final int maxStreamData;
  final QuicLogger? quicLogger;
  final dynamic secretsLogFile; // TextIO equivalent
  final String? serverName;
  final tls.SessionTicket? sessionTicket;
  final Uint8List token;
  Uint8List? cadata;
  String? cafile;
  String? capath;
  dynamic certificate; // `Any` type
  List<dynamic> certificateChain; // `List[Any]` type
  final List<tls.CipherSuite>? cipherSuites;
  final double initialRtt;
  final int? maxDatagramFrameSize;
  final int? originalVersion;
  dynamic privateKey; // `Any` type
  final bool quantumReadinessTest;
  final List<int> supportedVersions;
  final int? verifyMode;

  QuicConfiguration({
    this.alpnProtocols,
    this.congestionControlAlgorithm = 'reno',
    this.connectionIdLength = 8,
    this.idleTimeout = 60.0,
    this.isClient = true,
    this.maxData = 1048576,
    this.maxDatagramSize = smallestMaxDatagramSize,
    this.maxStreamData = 1048576,
    this.quicLogger,
    this.secretsLogFile,
    this.serverName,
    this.sessionTicket,
    Uint8List? token,
    this.cadata,
    this.cafile,
    this.capath,
    this.certificate,
    List<dynamic>? certificateChain,
    this.cipherSuites,
    this.initialRtt = 0.1,
    this.maxDatagramFrameSize,
    this.originalVersion,
    this.privateKey,
    this.quantumReadinessTest = false,
    List<int>? supportedVersions,
    this.verifyMode,
  })  : token = token ?? Uint8List(0),
        certificateChain = certificateChain ?? [],
        supportedVersions = supportedVersions ??
            [
              QuicProtocolVersion.version1,
              QuicProtocolVersion.version2,
            ];

  void loadCertChain(
    String certfile, {
    String? keyfile,
    dynamic password, // Union[bytes, str]
  }) {
    final fileContent = File(certfile).readAsBytesSync();
    final boundary = Uint8List.fromList('-----BEGIN PRIVATE KEY-----\n'.codeUnits);
    final chunks = splitBytes(fileContent, boundary);

    final certificates = x509.loadPemCertificates(chunks[0]);
    if (chunks.length == 2) {
      final privateKeyPem = Uint8List.fromList(boundary.toList() + chunks[1].toList());
      // Assuming a function like this exists in the crypto library
      privateKey = pointycastle.loadPemPrivateKey(privateKeyPem);
    }
    certificate = certificates.first;
    certificateChain = certificates.skip(1).toList();

    if (keyfile != null) {
      final keyFileContent = File(keyfile).readAsBytesSync();
      // Assuming `loadPemPrivateKey` handles password-protected keys
      // and a similar logic for converting the password to bytes.
      privateKey = pointycastle.loadPemPrivateKey(
        keyFileContent,
        password: password is String ? password.codeUnits : password,
      );
    }
  }

  void loadVerifyLocations({
    String? cafile,
    String? capath,
    Uint8List? cadata,
  }) {
    this.cafile = cafile;
    this.capath = capath;
    this.cadata = cadata;
  }
}

// A simple utility to split a Uint8List by a byte boundary.
List<Uint8List> splitBytes(Uint8List source, Uint8List boundary) {
  final List<Uint8List> parts = [];
  int lastIndex = 0;
  int currentMatch = 0;

  for (int i = 0; i < source.length; i++) {
    if (source[i] == boundary[currentMatch]) {
      currentMatch++;
      if (currentMatch == boundary.length) {
        parts.add(source.sublist(lastIndex, i - boundary.length + 1));
        lastIndex = i + 1;
        currentMatch = 0;
      }
    } else {
      currentMatch = 0;
    }
  }
  parts.add(source.sublist(lastIndex));
  return parts;
}