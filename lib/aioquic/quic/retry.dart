import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

import '../buffer.dart';
import 'connection.dart'; // Assuming NetworkAddress is defined here

// Helper functions for QUIC TLS
// Note: These are simplified implementations based on usage.
void pushOpaque(Buffer buffer, int lengthSize, Uint8List data) {
  if (lengthSize == 1) {
    buffer.pushUint8(data.length);
  } else {
    throw UnimplementedError('Only lengthSize=1 is supported for now');
  }
  buffer.pushBytes(data);
}

Uint8List pullOpaque(Buffer buffer, int lengthSize) {
  int length;
  if (lengthSize == 1) {
    length = buffer.pullUint8();
  } else {
    throw UnimplementedError('Only lengthSize=1 is supported for now');
  }
  return buffer.pullBytes(length);
}

// Convert an IP address and port to a byte array.
Uint8List encodeAddress(NetworkAddress addr) {
  final ipBytes = addr.ipAddress.rawAddress;
  final portBytes = ByteData(2);
  portBytes.setUint16(0, addr.port);

  return Uint8List.fromList(ipBytes + portBytes.buffer.asUint8List());
}

// Custom FortunaRandom implementation to be able to re-seed it.
class FortunaRandomCustom extends FortunaRandom {
  void reseed(Uint8List seed) {
    seed.forEach(seedSource.add);
  }
}

class QuicRetryTokenHandler {
  late final AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> _keyPair;

  QuicRetryTokenHandler() {
    // Generate a secure random number generator.
    final secureRandom = FortunaRandomCustom();
    final seed = Uint8List(32)
      ..fillRange(
        0,
        32,
        1,
      ); // A fixed seed for demonstration. Use a proper random source in production.
    secureRandom.reseed(seed);

    // Generate the RSA key pair.
    final keyGen = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
          secureRandom,
        ),
      );
    _keyPair = keyGen.generateKeyPair();
  }

  Uint8List createToken(
    NetworkAddress addr,
    Uint8List originalDestinationConnectionId,
    Uint8List retrySourceConnectionId,
  ) {
    final buffer = Buffer(capacity: 512);
    pushOpaque(buffer, 1, encodeAddress(addr));
    pushOpaque(buffer, 1, originalDestinationConnectionId);
    pushOpaque(buffer, 1, retrySourceConnectionId);

    final oaep = OAEPEncoding(RSAEngine(), SHA256Digest());
    oaep.init(
      true,
      PublicKeyParameter<RSAPublicKey>(_keyPair.publicKey as RSAPublicKey),
    );
    return oaep.process(buffer.data);
  }

  Tuple2<Uint8List, Uint8List> validateToken(
    NetworkAddress addr,
    Uint8List token,
  ) {
    final oaep = OAEPEncoding(RSAEngine(), SHA256Digest());
    oaep.init(
      false,
      PrivateKeyParameter<RSAPrivateKey>(_keyPair.privateKey as RSAPrivateKey),
    );
    final decryptedData = oaep.process(token);

    final buffer = Buffer(initialData: decryptedData);
    final encodedAddr = pullOpaque(buffer, 1);
    final originalDestinationConnectionId = pullOpaque(buffer, 1);
    final retrySourceConnectionId = pullOpaque(buffer, 1);

    if (!listEquals(encodedAddr, encodeAddress(addr))) {
      throw ArgumentError("Remote address does not match.");
    }

    return Tuple2(originalDestinationConnectionId, retrySourceConnectionId);
  }
}

// A simple utility to compare two lists of Uint8List.
bool listEquals<T>(List<T>? a, List<T>? b) {
  if (a == null) return b == null;
  if (b == null || a.length != b.length) return false;
  if (identical(a, b)) return true;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// Tuple for returning multiple values.
class Tuple2<T1, T2> {
  final T1 value1;
  final T2 value2;
  const Tuple2(this.value1, this.value2);
}
