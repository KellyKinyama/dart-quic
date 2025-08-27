// Filename: retry.dart
import 'dart:io';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'buffer.dart';

// Helper to encode IP and port
Uint8List _encodeAddress(String ip, int port) {
  final builder = BytesBuilder();
  builder.add(InternetAddress(ip).rawAddress);
  final portBytes = ByteData(2)..setUint16(0, port, Endian.big);
  builder.add(portBytes.buffer.asUint8List());
  return builder.toBytes();
}

class QuicRetryTokenHandler {
  late final RSAPrivateKey _privateKey;
  late final RSAPublicKey _publicKey;

  QuicRetryTokenHandler() {
    final keyGen = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
          FortunaRandom()..seed(
            KeyParameter(
              Platform.instance.platformEntropySource().getBytes(32),
            ),
          ),
        ),
      );
    final pair = keyGen.generateKeyPair();
    _publicKey = pair.publicKey as RSAPublicKey;
    _privateKey = pair.privateKey as RSAPrivateKey;
  }

  Uint8List createToken({
    required String remoteIp,
    required int remotePort,
    required Uint8List originalDestinationCid,
    required Uint8List retrySourceCid,
  }) {
    final buf = Buffer(capacity: 512);
    buf.pushUintVar(originalDestinationCid.length);
    buf.pushBytes(originalDestinationCid);
    buf.pushUintVar(retrySourceCid.length);
    buf.pushBytes(retrySourceCid);
    final addrBytes = _encodeAddress(remoteIp, remotePort);
    buf.pushUintVar(addrBytes.length);
    buf.pushBytes(addrBytes);

    final encrypter = OAEPEncoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(_publicKey));
    return encrypter.process(buf.data);
  }

  (Uint8List, Uint8List) validateToken({
    required String remoteIp,
    required int remotePort,
    required Uint8List token,
  }) {
    final decrypter = OAEPEncoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(_privateKey));
    final decrypted = decrypter.process(token);
    final buf = Buffer(data: decrypted);

    final originalDestinationCid = buf.pullBytes(buf.pullUintVar());
    final retrySourceCid = buf.pullBytes(buf.pullUintVar());
    final addrBytes = buf.pullBytes(buf.pullUintVar());

    if (addrBytes.toString() !=
        _encodeAddress(remoteIp, remotePort).toString()) {
      throw Exception('Remote address does not match.');
    }
    return (originalDestinationCid, retrySourceCid);
  }
}
