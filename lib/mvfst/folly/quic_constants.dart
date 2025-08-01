import 'dart:typed_data';

// Standard Dart library for time and date.
import 'dart:core';

// Quic-specific type aliases and constants.

// A standard Dart Uint8List is a good stand-in for C++'s IOBuf.
typedef Buf = Uint8List;

/// Represents a time point, similar to `std::chrono::time_point`.
typedef TimePoint = DateTime;

/// Replaces `std::chrono::microseconds`.
// typedef Duration = Duration;

// Time representations in Dart.
const int kMicrosecondsPerSecond = 1000000;
const int kMillisecondsPerSecond = 1000;

// Replaces C++'s `std::chrono_literals`.
const Duration 100ms = Duration(milliseconds: 100);
const Duration 15s = Duration(seconds: 15);
const Duration 20s = Duration(seconds: 20);
const Duration 60s = Duration(seconds: 60);

// Default values for common QUIC parameters.
const int kMaxVarInt = (1 << 62) - 1;
const int kDefaultV4UDPSendPacketLen = 1252;
const int kDefaultV6UDPSendPacketLen = 1232;
const int kDefaultUDPSendPacketLen =
    kDefaultV4UDPSendPacketLen < kDefaultV6UDPSendPacketLen
        ? kDefaultV4UDPSendPacketLen
        : kDefaultV6UDPSendPacketLen;
const int kDefaultMaxUDPPayload = 1452;
const int kMinMaxUDPPayload = 1200;
const int kDefaultMsgSizeBackOffSize = 50;
const int kDefaultUDPReadBufferSize = 1500;
const int kNumIovecBufferChains = 16;
const int kMinNumGROBuffers = 1;
const int kMaxNumGROBuffers = 64;
const int kDefaultNumGROBuffers = kMinNumGROBuffers;
const int kMaxNumCoalescedPackets = 5;
const int kRetryIntegrityTagLen = 16;
const int kDefaultBufferSpaceAvailable = 0xFFFFFFFFFFFFFFFF;
const  kDefaultMinRtt = Duration(microseconds: 0xFFFFFFFFFFFFFFFF);
const int kDefaultQuicTransportKnobSpace = 0xfaceb001;
const int kDefaultQuicTransportKnobId = 1;

// --- Enums ---

// `BETTER_ENUM` becomes a standard Dart `enum`.
enum PacketDropReason {
  none,
  connectionNotFound,
  decryptionErrorInitial,
  decryptionErrorHandshake,
  decryptionError0Rtt,
  decryptionError,
  invalidPacketSize,
  invalidPacketSizeInitial,
  invalidPacketVersion,
  invalidPacketInitialByte,
  invalidPacketCid,
  invalidPacketVn,
  parseErrorShortHeader,
  parseErrorLongHeader,
  parseErrorLongHeaderInitial,
  parseErrorException,
  parseErrorBadDcid,
  parseErrorDcid,
  parseErrorPacketBuffered,
  parseErrorClient,
  cipherUnavailable,
  unexpectedRetry,
  unexpectedReset,
  unexpectedNothing,
  unexpectedProtectionLevel,
  emptyData,
  maxBuffered,
  bufferUnavailable,
  peerAddressChange,
  protocolViolation,
  routingErrorWrongHost,
  serverStateClosed,
  transportParameterError,
  workerNotInitialized,
  serverShutdown,
  initialConnidSmall,
  cannotMakeTransport,
  udpTruncated,
  clientStateClosed,
  clientShutdown,
  invalidSrcPort,
  unknownCidVersion,
  cannotForwardData,
}

// `BETTER_ENUM` also becomes a standard Dart `enum`.
enum TransportKnobParamId {
  unknown(0x0),
  noOp(0x1),
  forciblySetUdpPayloadSize(0xba92),
  ccAlgorithmKnob(0xccaa),
  ccExperimental(0xccac),
  ccConfig(0xccad),
  startupRttFactorKnob(0x1111),
  defaultRttFactorKnob(0x2222),
  maxPacingRateKnob(0x4444),
  adaptiveLossDetection(0x5556),
  pacerExperimental(0x5557),
  shortHeaderPaddingKnob(0x6666),
  fixedShortHeaderPaddingKnob(0x6667),
  keepaliveEnabled(0x7777),
  removeFromLossBuffer(0x8888),
  maxPacingRateKnobSequenced(0x9999),
  ackFrequencyPolicy(0x10000),
  fireLoopEarly(0x10001),
  pacingTimerTick(0x10002),
  defaultStreamPriority(0x10003),
  writeLoopTimeFraction(0x10004),
  writesPerStream(0x10005),
  connectionMigration(0x10006),
  keyUpdateInterval(0x10007),
  useNewStreamBlockedCondition(0x10008),
  autotuneRecvStreamFlowControl(0x10009),
  inflightReorderingThreshold(0x1000A),
  pacerMinBurstPackets(0x1000B),
  maxBatchPackets(0x1000C),
  useNewPriorityQueue(0x1000D);

  final int value;
  const TransportKnobParamId(this.value);
}

enum FrameType {
  padding(0x00),
  ping(0x01),
  ack(0x02),
  ackEcn(0x03),
  rstStream(0x04),
  stopSending(0x05),
  cryptoFrame(0x06),
  newToken(0x07),
  stream(0x08),
  streamFin(0x09),
  streamLen(0x0a),
  streamLenFin(0x0b),
  streamOff(0x0c),
  streamOffFin(0x0d),
  streamOffLen(0x0e),
  streamOffLenFin(0x0f),
  maxData(0x10),
  maxStreamData(0x11),
  maxStreamsBidi(0x12),
  maxStreamsUni(0x13),
  dataBlocked(0x14),
  streamDataBlocked(0x15),
  streamsBlockedBidi(0x16),
  streamsBlockedUni(0x17),
  newConnectionId(0x18),
  retireConnectionId(0x19),
  pathChallenge(0x1A),
  pathResponse(0x1B),
  connectionClose(0x1C),
  connectionCloseAppErr(0x1D),
  handshakeDone(0x1E),
  rstStreamAt(0x24),
  datagram(0x30),
  datagramLen(0x31),
  knob(0x1550),
  immediateAck(0xAC),
  ackFrequency(0xAF),
  groupStream(0x32),
  groupStreamFin(0x33),
  groupStreamLen(0x34),
  groupStreamLenFin(0x35),
  groupStreamOff(0x36),
  groupStreamOffFin(0x37),
  groupStreamOffLen(0x38),
  groupStreamOffLenFin(0x39),
  ackReceiveTimestamps(0xB0),
  ackExtended(0xB1);

  final int value;
  const FrameType(this.value);
}

int toFrameError(FrameType frame) {
  return 0x0100 | frame.value;
}

enum ExtendedAckFeatureMask {
  ecnCounts(0x01),
  receiveTimestamps(0x02);

  final int value;
  const ExtendedAckFeatureMask(this.value);
}

enum TransportErrorCode {
  noError(0x0000),
  internalError(0x0001),
  serverBusy(0x0002),
  flowControlError(0x0003),
  streamLimitError(0x0004),
  streamStateError(0x0005),
  finalSizeError(0x0006),
  frameEncodingError(0x0007),
  transportParameterError(0x0008),
  protocolViolation(0x000A),
  invalidMigration(0x000C),
  cryptoBufferExceeded(0x000D),
  cryptoError(0x100),
  cryptoErrorMax(0x1ff),
  invalidToken(0xb);

  final int value;
  const TransportErrorCode(this.value);
}

typedef ApplicationErrorCode = int;

abstract class GenericApplicationErrorCode {
  static const int noError = 0;
  static const int unknown = kMaxVarInt;
}

enum LocalErrorCode {
  noError(0x00000000),
  connectFailed(0x40000000),
  codecError(0x40000001),
  streamClosed(0x40000002),
  streamNotExists(0x40000003),
  creatingExistingStream(0x40000004),
  shuttingDown(0x40000005),
  resetCryptoStream(0x40000006),
  cwndOverflow(0x40000007),
  inflightBytesOverflow(0x40000008),
  lostBytesOverflow(0x40000009),
  newVersionNegotiated(0x4000000A),
  invalidWriteCallback(0x4000000B),
  tlsHandshakeFailed(0x4000000C),
  appError(0x4000000D),
  internalError(0x4000000E),
  transportError(0x4000000F),
  invalidWriteData(0x40000010),
  invalidStateTransition(0x40000011),
  connectionClosed(0x40000012),
  earlyDataRejected(0x40000013),
  connectionReset(0x40000014),
  idleTimeout(0x40000015),
  packetNumberEncoding(0x40000016),
  invalidOperation(0x40000017),
  streamLimitExceeded(0x40000018),
  connectionAbandoned(0x40000019),
  callbackAlreadyInstalled(0x4000001A),
  knobFrameUnsupported(0x4000001B),
  pacerNotAvailable(0x4000001C),
  rtxPoliciesLimitExceeded(0x4000001D),
  congestionControlError(0x4000001E);

  final int value;
  const LocalErrorCode(this.value);
}

enum QuicNodeType {
  client,
  server,
}

enum QuicVersion {
  versionNegotiation(0x00000000),
  mvfst(0xfaceb002),
  quicV1(0x00000001),
  quicV1Alias(0xfaceb003),
  quicV1Alias2(0xfaceb004),
  mvfstExperimental(0xfaceb00e),
  mvfstAlias(0xfaceb010),
  mvfstInvalid(0xfaceb00f),
  mvfstExperimental2(0xfaceb011),
  mvfstExperimental3(0xfaceb013),
  mvfstExperimental4(0xfaceb014),
  mvfstExperimental5(0xfaceb015),
  mvfstPriming(0xfacefeed);

  final int value;
  const QuicVersion(this.value);
}

const int kDrainFactor = 3;

enum QuicBatchingMode {
  batchingModeNone(0),
  batchingModeGso(1),
  batchingModeSendmmsg(2),
  batchingModeSendmmsgGso(3);

  final int value;
  const QuicBatchingMode(this.value);
}

QuicBatchingMode getQuicBatchingMode(int val) {
  return QuicBatchingMode.values.firstWhere(
    (mode) => mode.value == val,
    orElse: () => QuicBatchingMode.batchingModeNone, // Or an appropriate default
  );
}

// ... (rest of the constants and enums)

enum CongestionControlType {
  cubic,
  newReno,
  copa,
  copa2,
  bbr,
  bbr2,
  bbrTesting,
  staticCwnd,
  none,
}

String congestionControlTypeToString(CongestionControlType type) {
  return type.name;
}

CongestionControlType? congestionControlStrToType(String str) {
  try {
    return CongestionControlType.values.byName(str);
  } catch (_) {
    return null;
  }
}

// ... (rest of the constants)

enum WriteDataReason {
  noWrite,
  probes,
  ack,
  cryptoStream,
  stream,
  blocked,
  streamWindowUpdate,
  connWindowUpdate,
  simple,
  reset,
  pathchallenge,
  ping,
  datagram,
  bufferedWrite,
}

enum NoWriteReason {
  writeOk,
  emptyScheduler,
  noFrame,
  noBody,
  socketFailure,
}

enum NoReadReason {
  readOk,
  truncated,
  emptyData,
  retriableError,
  nonretriableError,
  staleData,
}

String writeDataReasonString(WriteDataReason reason) => reason.name;
String writeNoWriteReasonString(NoWriteReason reason) => reason.name;
String readNoReadReasonString(NoReadReason reason) => reason.name;

List<QuicVersion> filterSupportedVersions(List<QuicVersion> versions) {
  // Implementation of this function is not provided in C++ header.
  // We'll return the list as is for now.
  return versions;
}

enum EncryptionLevel {
  initial,
  handshake,
  earlyData,
  appData,
  max,
}

enum DataPathType {
  chainedMemory,
  continuousMemory,
}

typedef PriorityLevel = int;
const int kDefaultMaxPriority = 7;
const int kShortHeaderPaddingModulo = 32;
const int kMaxReceivedPktsTimestampsStored = 10;
const int kDefaultReceiveTimestampsExponent = 3;
const int kEcnECT1 = 0b01;
const int kEcnECT0 = 0b10;
const int kEcnCE = 0b11;
const int kSkipOneInNPacketSequenceNumber = 1000;
const int kDistanceToClearSkippedPacketNumber = 1000;

String nodeToString(QuicNodeType node) {
  return node.name;
}