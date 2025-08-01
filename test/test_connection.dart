// ignore_for_file: unused_import
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:http3/src/buffer.dart';
import 'package:http3/src/quic/configuration.dart';
import 'package:http3/src/quic/connection.dart';
import 'package:http3/src/quic/crypto.dart';
import 'package:http3/src/quic/events.dart';
import 'package:http3/src/quic/logger.dart';
import 'package:http3/src/quic/packet.dart';
import 'package:http3/src/quic/packet_builder.dart';
import 'package:http3/src/quic/recovery.dart';
import 'package:http3/src/tls.dart';
import 'package:test/test.dart';

import 'utils.dart';

const clientAddr = Address('1.2.3.4', 1234);
const clientHandshakeDatagramSizes = [1200];

const serverAddr = Address('2.3.4.5', 4433);
const serverInitialDatagramSizes = [1200, 1162];

final handshakeCompletedEvents = [
  HandshakeCompleted,
  ConnectionIdIssued,
  ConnectionIdIssued,
  ConnectionIdIssued,
  ConnectionIdIssued,
  ConnectionIdIssued,
  ConnectionIdIssued,
  ConnectionIdIssued,
];
const tick = 0.05; // seconds

class SessionTicketStore {
  final tickets = <Uint8List, SessionTicket>{};

  void add(SessionTicket ticket) {
    tickets[ticket.ticket] = ticket;
  }

  SessionTicket? pop(Uint8List label) {
    return tickets.remove(label);
  }
}

class QuicReceiveContext {
  final Epoch epoch;
  final ConnectionId hostCid;
  final QuicNetworkPath networkPath;
  final List quicLoggerFrames;
  final double time;
  final QuicProtocolVersion? version;

  QuicReceiveContext({
    required this.epoch,
    required this.hostCid,
    required this.networkPath,
    required this.quicLoggerFrames,
    required this.time,
    required this.version,
  });
}

QuicReceiveContext clientReceiveContext(
  QuicConnection client, {
  Epoch epoch = Epoch.oneRtt,
}) {
  return QuicReceiveContext(
    epoch: epoch,
    hostCid: client.hostCid,
    networkPath: client.networkPaths.values.first,
    quicLoggerFrames: [],
    time: DateTime.now().microsecondsSinceEpoch / 1000000,
    version: null,
  );
}

void consumeEvents(QuicConnection connection) {
  while (connection.nextEvent() != null) {}
}

QuicConnection createStandaloneClient({Map<String, dynamic> clientOptions = const {}}) {
  final client = QuicConnection(
    configuration: QuicConfiguration(
      isClient: true,
      quicLogger: QuicLogger(),
      alpnProtocols: ['hq-interop'],
      **clientOptions,
    ),
  );
  client.ackDelay = Duration.zero;

  // kick-off handshake
  client.connect(serverAddr, now: DateTime.now());

  expect(drop(client), 1);

  return client;
}

QuicConnection createStandaloneServer({ConnectionId? originalDestinationConnectionId}) {
  final serverConfiguration = QuicConfiguration(isClient: false, quicLogger: QuicLogger());
  serverConfiguration.loadCertChain(
    Platform.environment['SERVER_CERTFILE'] ?? 'server.crt',
    Platform.environment['SERVER_KEYFILE'] ?? 'server.key',
  );

  final server = QuicConnection(
    configuration: serverConfiguration,
    originalDestinationConnectionId: originalDestinationConnectionId ?? ConnectionId(Uint8List(8)),
  );
  server.ackDelay = Duration.zero;

  return server;
}

List<int> datagramSizes(List<Tuple2<Uint8List, Address>> items) {
  return items.map((x) => x.item1.length).toList();
}

ConnectionId newConnectionId({
  required int sequenceNumber,
  int retirePriorTo = 0,
  Uint8List? connectionId,
  int capacity = 100,
}) {
  final buf = Buffer(capacity: capacity);
  buf.pushUintVar(sequenceNumber);
  buf.pushUintVar(retirePriorTo);
  buf.pushUintVar(connectionId?.length ?? 8);
  if (connectionId != null) {
    buf.pushBytes(connectionId);
  } else {
    buf.pushBytes(Uint8List(8));
  }
  buf.pushBytes(Uint8List(16)); // stateless reset token
  buf.seek(0);
  return buf;
}

Future<void> clientAndServer({
  Map<String, dynamic> clientKwargs = const {},
  Map<String, dynamic> clientOptions = const {},
  Function(QuicConnection)? clientPatch,
  bool handshake = true,
  Map<String, dynamic> serverKwargs = const {},
  String? serverCertfile,
  String? serverKeyfile,
  Map<String, dynamic> serverOptions = const {},
  Function(QuicConnection)? serverPatch,
  required Function(QuicConnection, QuicConnection) callback,
}) async {
  final clientConfiguration = QuicConfiguration(
    isClient: true,
    quicLogger: QuicLogger(),
    alpnProtocols: ['hq-interop'],
    **clientOptions,
  );
  clientConfiguration.loadVerifyLocations(cafile: 'server.pem');

  final client = QuicConnection(configuration: clientConfiguration, **clientKwargs);
  client.ackDelay = Duration.zero;
  disablePacketPacing(client);
  clientPatch?.call(client);

  final serverConfiguration = QuicConfiguration(
    isClient: false,
    quicLogger: QuicLogger(),
    alpnProtocols: ['hq-interop'],
    **serverOptions,
  );
  serverConfiguration.loadCertChain(
    serverCertfile ?? 'server.crt',
    serverKeyfile ?? 'server.key',
  );

  final server = QuicConnection(
    configuration: serverConfiguration,
    originalDestinationConnectionId: client.originalDestinationConnectionId,
    **serverKwargs,
  );
  server.ackDelay = Duration.zero;
  disablePacketPacing(server);
  serverPatch?.call(server);

  // perform handshake
  if (handshake) {
    client.connect(serverAddr, now: DateTime.now());
    for (var i = 0; i < 3; i++) {
      await roundtrip(client, server);
    }
  }

  await callback(client, server);

  // close
  client.close();
  server.close();
}

void disablePacketPacing(QuicConnection connection) {
  // Dart's equivalent is a bit different, but we can mock it
  // by making next_send_time return null
}

Uint8List encodeTransportParameters(QuicTransportParameters parameters) {
  final buf = Buffer(capacity: 512);
  pushQuicTransportParameters(buf, parameters);
  return buf.data;
}

List<int> sequenceNumbers(List<ConnectionId> connectionIds) {
  return connectionIds.map((x) => x.sequenceNumber).toList();
}

int drop(QuicConnection sender) {
  return sender.datagramsToSend(now: DateTime.now()).length;
}

Future<Tuple2<int, int>> roundtrip(QuicConnection sender, QuicConnection receiver) async {
  final sentToReceiver = await transfer(sender, receiver);
  final sentToSender = await transfer(receiver, sender);
  return Tuple2(sentToReceiver, sentToSender);
}

Future<void> roundtripUntilDone(QuicConnection sender, QuicConnection receiver) async {
  var rounds = 0;
  while (true) {
    final result = await roundtrip(sender, receiver);
    if (result.item1 == 0 && result.item2 == 0) {
      break;
    }
    rounds++;
    assert(rounds < 10);
  }
}

Future<int> transfer(QuicConnection sender, QuicConnection receiver) async {
  var datagrams = 0;
  final fromAddr = sender.isClient ? clientAddr : serverAddr;
  for (var item in sender.datagramsToSend(now: DateTime.now())) {
    datagrams++;
    receiver.receiveDatagram(item.item1, fromAddr, now: DateTime.now());
  }
  return datagrams;
}

void main() {
  group('QuicConnectionTest', () {
    void assertEvents(QuicConnection connection, List expected) {
      final types = <Type>[];
      while (true) {
        final event = connection.nextEvent();
        if (event != null) {
          types.add(event.runtimeType);
        } else {
          break;
        }
      }
      expect(types, expected);
    }

    void assertPacketDropped(QuicConnection connection, String trigger) {
      // Dart equivalent
      // TODO: Implement QuicLogger or a mock
    }

    void assertSentPackets(QuicConnection connection, List<int> expected) {
      final counts = connection.loss.spaces.map((space) => space.sentPackets.length).toList();
      expect(counts, expected);
    }

    void checkHandshake(QuicConnection client, QuicConnection server, {String? alpnProtocol}) {
      expect(client.nextEvent(), isA<ProtocolNegotiated>());
      // TODO: check alpn_protocol value
      expect(client.nextEvent(), isA<HandshakeCompleted>());
      // TODO: check early_data_accepted and session_resumed
      for (var i = 0; i < 7; i++) {
        expect(client.nextEvent(), isA<ConnectionIdIssued>());
      }
      expect(client.nextEvent(), isNull);

      expect(server.nextEvent(), isA<ProtocolNegotiated>());
      // TODO: check alpn_protocol value
      expect(server.nextEvent(), isA<HandshakeCompleted>());
      for (var i = 0; i < 7; i++) {
        expect(server.nextEvent(), isA<ConnectionIdIssued>());
      }
      expect(server.nextEvent(), isNull);
    }
    
    test('test_connect_with_loss_5', () async {
      await clientAndServer(handshake: false, callback: (client, server) async {
        // client sends INITIAL
        var now = DateTime.now();
        client.connect(serverAddr, now: now);
        var items = client.datagramsToSend(now: now);
        expect(datagramSizes(items), [1200]);
        expect(client.getTimer(), lessThan(now.add(Duration(milliseconds: 200))));

        // server receives INITIAL, sends INITIAL + HANDSHAKE
        now = now.add(Duration(milliseconds: (tick * 1000).toInt()));
        server.receiveDatagram(items[0].item1, clientAddr, now: now);
        items = server.datagramsToSend(now: now);
        expect(datagramSizes(items), serverInitialDatagramSizes);
        // TODO: check server.get_timer()

        // client receives INITIAL + HANDSHAKE
        now = now.add(Duration(milliseconds: (tick * 1000).toInt()));
        client.receiveDatagram(items[0].item1, serverAddr, now: now);
        client.receiveDatagram(items[1].item1, serverAddr, now: now);
        items = client.datagramsToSend(now: now);
        expect(datagramSizes(items), [1200]);
        // TODO: check client.get_timer()

        // server receives ACK, sends HANDSHAKE_DONE
        now = now.add(Duration(milliseconds: (tick * 1000).toInt()));
        server.receiveDatagram(items[0].item1, clientAddr, now: now);
        items = server.datagramsToSend(now: now);
        // HANDSHAKE_DONE is in an RTT packet, so its size is smaller
        expect(datagramSizes(items), [32]);
        // TODO: check server.get_timer()

        // HANDSHAKE_DONE is lost, server's PTO fires, HANDSHAKE_DONE is retransmitted
        now = now.add(Duration(milliseconds: 500)); // Simulate time passing
        server.handleTimer(now: now);
        items = server.datagramsToSend(now: now);
        expect(datagramSizes(items), [32]);
        // TODO: check server.get_timer()

        // client receives HANDSHAKE_DONE
        now = now.add(Duration(milliseconds: (tick * 1000).toInt()));
        client.receiveDatagram(items[0].item1, serverAddr, now: now);
        items = client.datagramsToSend(now: now);
        expect(datagramSizes(items), [32]);
        // TODO: check client.get_timer()
        // TODO: check events on both sides
      });
    });
  });
}