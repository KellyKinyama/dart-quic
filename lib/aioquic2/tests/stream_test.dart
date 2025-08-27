// Filename: test/stream_test.dart
import 'dart:typed_data';
import 'package:test/test.dart';
import '../stream.dart';
import '../packet.dart';
import '../events.dart';

void main() {
  group('QuicStreamReceiver', () {
    test('ordered data', () {
      final stream = QuicStream(streamId: 0);
      final data1 = Uint8List.fromList('01234567'.codeUnits);
      final data2 = Uint8List.fromList('89012345'.codeUnits);

      var event = stream.receiver.handleFrame(
        QuicStreamFrame(offset: 0, data: data1),
      );
      expect(event, isA<StreamDataReceived>());
      expect(event!.data, equals(data1));
      expect(event.endStream, isFalse);
      expect(stream.receiver.startingOffset(), 8);

      event = stream.receiver.handleFrame(
        QuicStreamFrame(offset: 8, data: data2, fin: true),
      );
      expect(event, isA<StreamDataReceived>());
      expect(event!.data, equals(data2));
      expect(event.endStream, isTrue);
      expect(stream.receiver.isFinished, isTrue);
    });

    test('unordered data', () {
      final stream = QuicStream(streamId: 0);
      final data1 = Uint8List.fromList('01234567'.codeUnits);
      final data2 = Uint8List.fromList('89012345'.codeUnits);

      // Receive data out of order
      var event = stream.receiver.handleFrame(
        QuicStreamFrame(offset: 8, data: data2),
      );
      expect(event, isNull); // Data is buffered, not delivered
      expect(stream.receiver.startingOffset(), 0);

      // Receive missing data
      event = stream.receiver.handleFrame(
        QuicStreamFrame(offset: 0, data: data1),
      );
      expect(event, isA<StreamDataReceived>());
      expect(event!.data, equals(Uint8List.fromList([...data1, ...data2])));
      expect(stream.receiver.startingOffset(), 16);
    });

    test('reset stream', () {
      final stream = QuicStream(streamId: 0);
      final event = stream.receiver.handleReset(1, 100);
      expect(event, isA<StreamReset>());
      expect(event.errorCode, 1);
      expect(stream.receiver.isFinished, isTrue);
    });

    test('final size error', () {
      final stream = QuicStream(streamId: 0);
      stream.receiver.handleFrame(
        QuicStreamFrame(offset: 0, data: Uint8List(4), fin: true),
      );
      expect(
        () => stream.receiver.handleFrame(
          QuicStreamFrame(offset: 0, data: Uint8List(8)),
        ),
        throwsA(isA<FinalSizeError>()),
      );
    });
  });
}
