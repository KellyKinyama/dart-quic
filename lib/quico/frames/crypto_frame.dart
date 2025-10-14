// #############################################################################
// ## SECTION 2: DATA CLASSES (QUIC and TLS)
// #############################################################################

// QUIC Frame Data Class
import '../handshake/handshake.dart';

class CryptoFrame {
  final int offset;
  final int length;
  final List<TlsHandshakeMessage> messages;
  CryptoFrame(this.offset, this.length, this.messages) {
    // parseTlsMessages(Uint8List cryptoData)
  }

  @override
  String toString() {
    final messageTypes = messages.map((m) => m.typeName).join(', ');
    return 'CryptoFrame(offset: $offset, length: $length, messages: [$messageTypes])';
  }
}
