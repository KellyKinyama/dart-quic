import 'dart:io';

import '../cert_utils.dart';

class HandshakeContext {
  int clientEpoch = 0;
  int serverEpoch = 0;
  bool isCipherSuiteInitialized = false;
  // RawDatagramSocket serverSocket;
  // String ip;
  // int port;

  EcdsaCert serverEcCertificate;
  HandshakeContext(this.serverEcCertificate);
}
