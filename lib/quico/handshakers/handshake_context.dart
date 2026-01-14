import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

// import 'package:dart_quic/go_quic/frames/frame_parser.dart';

// import '../aead.dart';
import '../cert_utils.dart';
import '../frames/frame_parser.dart';
import '../handshake/handshake.dart';
import '../handshake/server_hello.dart';
// import '../initial_aead.dart';
import '../protocol.dart';
import '../quic_packet.dart';
import '../secrets.dart';

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

  late ({({Uint8List key, Uint8List nonceMask}) aead, Uint8List hp}) opener;

  late ({({Uint8List key, Uint8List nonceMask}) aead, Uint8List hp}) sealer;

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
          final cryptoByes = encodeQuicFrames(tlsFrame);
          // final sealed = sealer.seal(cryptByes, 1, header);
          final sealed = encryptQuicPacket(
            "server initial",
            cryptoByes,
            sealer.aead.key,
            sealer.aead.nonceMask,
            sealer.hp,
            0,
            connID,
            connID,
            null,
          );
        }
    }
    messages = [];
  }
}
