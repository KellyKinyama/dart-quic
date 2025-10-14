import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_quic/go_quic/frames/frame_parser.dart';

// import '../aead.dart';
import '../cert_utils.dart';
import '../handshake/handshake.dart';
import '../handshake/server_hello.dart';
// import '../initial_aead.dart';
import '../protocol.dart';

class HandshakeContext {
  int clientEpoch = 0;
  int serverEpoch = 0;
  bool isCipherSuiteInitialized = false;

  List<TlsHandshakeMessage> messages = <TlsHandshakeMessage>[];
  RawDatagramSocket serverSocket;
  // RawDatagramSocket? clientSocket;
  // String ip;
  // int port;
  // late LongHeaderOpener opener;
  // late LongHeaderSealer sealer;

  late final Uint8List connID;

  late Version version;

  EcdsaCert serverEcCertificate;
  HandshakeContext(this.serverEcCertificate, this.serverSocket);

  void handleHandake(RawDatagramSocket clientSocket) {
    final msg = messages.first;
    switch (msg.runtimeType) {
      case ClientHello:
        {
          msg as ClientHello;

          final (localSealer, localOpener) = newInitialAEAD(
            connID,
            Perspective.server,
            version,
          );
          sealer = localSealer;
          opener = localOpener;

          final serverRandom = Uint8List.fromList(
            List.generate(32, (index) => Random.secure().nextInt(255)),
          );
          final serverHello = ServerHello.fromClientHello(
            msg,
            msg.random,
            serverEcCertificate.publickKey,
          );

          final tlsFrame = tlsMessagesToCryptoFrames([serverHello]);
          final cryptByes = encodeQuicFrames(tlsFrame);
          final sealed = sealer.seal(cryptByes, 1, header);
        }
    }
    messages = [];
  }
}
