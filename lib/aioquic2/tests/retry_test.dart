// Filename: test/retry_test.dart
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:collection/collection.dart';
import '../retry.dart';

void main() {
  group('QuicRetryTokenHandlerTest', () {
    test('create and validate token', () {
      final addrIp = '127.0.0.1';
      final addrPort = 1234;
      final originalCid = Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]);
      final retryCid = Uint8List.fromList('abcdefgh'.codeUnits);

      final handler = QuicRetryTokenHandler();

      // Create token
      final token = handler.createToken(
        remoteIp: addrIp,
        remotePort: addrPort,
        originalDestinationCid: originalCid,
        retrySourceCid: retryCid,
      );

      expect(token, isNotNull);
      expect(token.length, equals(256));

      // Validate token - OK
      final (validatedOriginalCid, validatedRetryCid) = handler.validateToken(
        remoteIp: addrIp,
        remotePort: addrPort,
        token: token,
      );

      expect(
        DeepCollectionEquality().equals(validatedOriginalCid, originalCid),
        isTrue,
      );
      expect(
        DeepCollectionEquality().equals(validatedRetryCid, retryCid),
        isTrue,
      );

      // Validate token - wrong address
      expect(
        () => handler.validateToken(
          remoteIp: '1.2.3.4',
          remotePort: 5678,
          token: token,
        ),
        throwsA(isA<Exception>()),
      );
    });
  });
}
