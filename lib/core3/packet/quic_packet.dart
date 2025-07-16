// quic_packet.dart
import 'dart:typed_data';
import 'package:collection/collection.dart';

import 'package:kwik_core/quic_constants.dart';
import 'package:kwik_core/common/encryption_level.dart';
import 'package:kwik_core/common/pn_space.dart';
import 'package:kwik_core/crypto/aead.dart';
import 'package:kwik_core/frame/ack_frame.dart';
import 'package:kwik_core/frame/connection_close_frame.dart';
import 'package:kwik_core/frame/crypto_frame.dart';
import 'package:kwik_core/frame/data_blocked_frame.dart';
import 'package:kwik_core/frame/datagram_frame.dart';
import 'package:kwik_core/frame/handshake_done_frame.dart';
import 'package:kwik_core/frame/max_data_frame.dart';
import 'package:kwik_core/frame/max_stream_data_frame.dart';
import 'package:kwik_core/frame/max_streams_frame.dart';
import 'package:kwik_core/frame/new_connection_id_frame.dart';
import 'package:kwik_core/frame/new_token_frame.dart';
import 'package:kwik_core/frame/padding.dart';
import 'package:kwik_core/frame/path_challenge_frame.dart';
import 'package:kwik_core/frame/path_response_frame.dart';
import 'package:kwik_core/frame/ping_frame.dart';
import 'package:kwik_core/frame/quic_frame.dart';
import 'package:kwik_core/frame/reset_stream_frame.dart';
import 'package:kwik_core/frame/retire_connection_id_frame.dart';
import 'package:kwik_core/frame/stop_sending_frame.dart';
import 'package:kwik_core/frame/stream_data_blocked_frame.dart';
import 'package:kwik_core/frame/stream_frame.dart';
import 'package:kwik_core/frame/streams_blocked_frame.dart';
import 'package:kwik_core/generic/integer_too_large_exception.dart';
import 'package:kwik_core/generic/invalid_integer_encoding_exception.dart';
import 'package:kwik_core/impl/decryption_exception.dart';
import 'package:kwik_core/impl/invalid_packet_exception.dart';
import 'package:kwik_core/impl/not_yet_implemented_exception.dart';
import 'package:kwik_core/impl/packet_processor.dart';
import 'package:kwik_core/impl/transport_error.dart';
import 'package:kwik_core/impl/version.dart';
import 'package:kwik_core/log/logger.dart';
import 'package:kwik_core/util/bytes.dart';

abstract class QuicPacket {
  static const int maxPacketSize = 1500;

  Version? quicVersion;
  int packetNumber = -1;
  List<QuicFrame> frames = [];
  int packetSize = -1;
  Uint8List? destinationConnectionId;
  bool isProbe = false;

  QuicPacket() {
    frames = [];
  }

  static int computePacketNumberSize(int packetNumber) {
    if (packetNumber <= 0xff) {
      return 1;
    } else if (packetNumber <= 0xffff) {
      return 2;
    } else if (packetNumber <= 0xffffff) {
      return 3;
    } else {
      return 4;
    }
  }

  static Uint8List encodePacketNumber(int packetNumber) {
    if (packetNumber <= 0xff) {
      return Uint8List.fromList([packetNumber]);
    } else if (packetNumber <= 0xffff) {
      return Uint8List.fromList([(packetNumber >> 8), (packetNumber & 0x00ff)]);
    } else if (packetNumber <= 0xffffff) {
      return Uint8List.fromList([
        (packetNumber >> 16),
        (packetNumber >> 8),
        (packetNumber & 0x00ff)
      ]);
    } else if (packetNumber <= 0xffffffff) {
      return Uint8List.fromList([
        (packetNumber >> 24),
        (packetNumber >> 16),
        (packetNumber >> 8),
        (packetNumber & 0x00ff)
      ]);
    } else {
      throw NotYetImplementedException('cannot encode pn > 4 bytes');
    }
  }

  static int encodePacketNumberLength(int flags, int packetNumber) {
    if (packetNumber <= 0xff) {
      return flags;
    } else if (packetNumber <= 0xffff) {
      return (flags | 0x01);
    } else if (packetNumber <= 0xffffff) {
      return (flags | 0x02);
    } else if (packetNumber <= 0xffffffff) {
      return (flags | 0x03);
    } else {
      throw NotYetImplementedException('cannot encode pn > 4 bytes');
    }
  }

  void parsePacketNumberAndPayload(Uint8List buffer, int flags,
      int remainingLength, Aead aead, int largestPacketNumber, Logger log) {
    if (buffer.length < remainingLength) {
      throw InvalidPacketException();
    }

    int currentPosition = 0; // Dart's Uint8List doesn't have a direct 'position' like ByteBuffer
    // For simplicity in conversion, assume buffer is a slice starting at the relevant position
    // In a real implementation, you'd manage offsets carefully.

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
    // "The same number of bytes are always sampled, but an allowance needs
    //   to be made for the endpoint removing protection, which will not know
    //   the length of the Packet Number field.  In sampling the packet
    //   ciphertext, the Packet Number field is assumed to be 4 bytes long
    //   (its maximum possible encoded length)."
    if (buffer.length < 4) {
      throw InvalidPacketException();
    }
    // In Dart, you'd work with sublists or indices for sampling
    // For now, let's assume 'buffer' is already positioned correctly for sampling.
    Uint8List sampleDataForHeaderProtection =
        buffer.sublist(currentPosition + 4, currentPosition + 4 + 16);

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
    // "This algorithm samples 16 bytes from the packet ciphertext."
    if (sampleDataForHeaderProtection.length < 16) {
      throw InvalidPacketException();
    }
    Uint8List sample = sampleDataForHeaderProtection.sublist(0, 16);

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
    // "Header protection is applied after packet protection is applied (see
    //   Section 5.3).  The ciphertext of the packet is sampled and used as
    //   input to an encryption algorithm."
    Uint8List mask = createHeaderProtectionMask(sample, aead);

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1
    // "The output of this algorithm is a 5 byte mask which is applied to the
    //   protected header fields using exclusive OR.  The least significant
    //   bits of the first byte of the packet are masked by the least
    //   significant bits of the first mask byte"
    int decryptedFlags;
    if ((flags & 0x80) == 0x80) {
      // Long header: 4 bits masked
      decryptedFlags = (flags ^ (mask[0] & 0x0f));
    } else {
      // Short header: 5 bits masked
      decryptedFlags = (flags ^ (mask[0] & 0x1f));
    }
    setUnprotectedHeader(decryptedFlags);
    // buffer.position(currentPosition); // Not directly applicable in Dart Uint8List

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
    // "pn_length = (packet[0] & 0x03) + 1"
    int protectedPackageNumberLength = (decryptedFlags & 0x03) + 1;
    Uint8List protectedPackageNumber = buffer.sublist(
        currentPosition, currentPosition + protectedPackageNumberLength);

    Uint8List unprotectedPacketNumber =
        Uint8List(protectedPackageNumberLength);
    for (int i = 0; i < protectedPackageNumberLength; i++) {
      // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
      // " ...and the packet number is
      //   masked with the remaining bytes.  Any unused bytes of mask that might
      //   result from a shorter packet number encoding are unused."
      unprotectedPacketNumber[i] = (protectedPackageNumber[i] ^ mask[1 + i]);
    }
    int truncatedPacketNumber = bytesToInt(unprotectedPacketNumber);
    packetNumber =
        decodePacketNumber(truncatedPacketNumber, largestPacketNumber, protectedPackageNumberLength * 8);
    log.decrypted("Unprotected packet number: $packetNumber");

    currentPosition += protectedPackageNumberLength; // Update current position

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
    // "The associated data, A, for the AEAD is the contents of the QUIC
    //   header, starting from the flags byte in either the short or long
    //   header, up to and including the unprotected packet number."
    Uint8List frameHeader = buffer.sublist(0, currentPosition);
    frameHeader[0] = decryptedFlags;

    // Copy unprotected (decrypted) packet number in frame header, before decrypting payload.
    frameHeader.setRange(
        frameHeader.length - protectedPackageNumberLength,
        frameHeader.length,
        unprotectedPacketNumber);
    log.encrypted("Frame header", frameHeader);

    // "The input plaintext, P, for the AEAD is the payload of the QUIC
    //   packet, as described in [QUIC-TRANSPORT]."
    // "The output ciphertext, C, of the AEAD is transmitted in place of P."
    int encryptedPayloadLength = remainingLength - protectedPackageNumberLength;
    if (encryptedPayloadLength < 1) {
      throw InvalidPacketException();
    }
    Uint8List payload = buffer.sublist(currentPosition,
        currentPosition + encryptedPayloadLength);
    log.encrypted("Encrypted payload", payload);

    Uint8List frameBytes =
        decryptPayload(payload, frameHeader, packetNumber, aead);
    log.decrypted("Decrypted payload", frameBytes);

    frames = [];
    parseFrames(frameBytes, log);
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
    // "An endpoint MUST (...) after removing both packet and header protection, (...)"
    checkReservedBits(decryptedFlags);
  }

  void setUnprotectedHeader(int decryptedFlags) {}

  void checkReservedBits(int decryptedFlags) {
    throw UnimplementedError();
  }

  Uint8List createHeaderProtectionMask(Uint8List sample, Aead aead) {
    return createHeaderProtectionMaskWithLength(sample, 4, aead);
  }

  Uint8List createHeaderProtectionMaskWithLength(
      Uint8List ciphertext, int encodedPacketNumberLength, Aead aead) {
    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4
    // "The same number of bytes are always sampled, but an allowance needs
    //   to be made for the endpoint removing protection, which will not know
    //   the length of the Packet Number field.  In sampling the packet
    //   ciphertext, the Packet Number field is assumed to be 4 bytes long
    //   (its maximum possible encoded length)."
    int sampleOffset = 4 - encodedPacketNumberLength;
    Uint8List sample = Uint8List(16);
    sample.setRange(0, 16, ciphertext.sublist(sampleOffset, sampleOffset + 16));

    return aead.createHeaderProtectionMask(sample);
  }

  Uint8List encryptPayload(
      Uint8List message, Uint8List associatedData, int packetNumber, Aead aead) {
    // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
    // "The nonce, N, is formed by combining the packet
    //   protection IV with the packet number.  The 64 bits of the
    //   reconstructed QUIC packet number in network byte order are left-
    //   padded with zeros to the size of the IV.  The exclusive OR of the
    //   padded packet number and the IV forms the AEAD nonce"
    Uint8List writeIV = aead.getWriteIV();
    ByteData nonceInput = ByteData(writeIV.length);
    for (int i = 0; i < nonceInput.lengthInBytes - 8; i++) {
      nonceInput.setUint8(i, 0x00);
    }
    nonceInput.setUint64(nonceInput.lengthInBytes - 8, packetNumber, Endian.big);

    Uint8List nonce = Uint8List(12);
    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (nonceInput.getUint8(i) ^ writeIV[i]);
    }

    return aead.aeadEncrypt(associatedData, message, nonce);
  }

  Uint8List decryptPayload(
      Uint8List message, Uint8List associatedData, int packetNumber, Aead aead) {
    ByteData nonceInput = ByteData(12);
    nonceInput.setUint32(0, 0, Endian.big); // Equivalent to putInt(0)
    nonceInput.setUint64(4, packetNumber, Endian.big); // Equivalent to putLong(packetNumber)

    if (this is ShortHeaderPacket) {
      aead.checkKeyPhase((this as ShortHeaderPacket).keyPhaseBit);
    }

    Uint8List writeIV = aead.getWriteIV();
    Uint8List nonce = Uint8List(12);
    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (nonceInput.getUint8(i) ^ writeIV[i]);
    }

    return aead.aeadDecrypt(associatedData, message, nonce);
  }

  static int decodePacketNumber(
      int truncatedPacketNumber, int largestPacketNumber, int bits) {
    // https://www.rfc-editor.org/rfc/rfc9000.html#sample-packet-number-decoding
    // "Figure 47: Sample Packet Number Decoding Algorithm"
    int expectedPacketNumber = largestPacketNumber + 1;
    int pnWindow = 1 << bits;
    int pnHalfWindow = (pnWindow ~/ 2);
    int pnMask = (~(pnWindow - 1));

    int candidatePn = (expectedPacketNumber & pnMask) | truncatedPacketNumber;
    if (candidatePn <= expectedPacketNumber - pnHalfWindow &&
        candidatePn < ((1 << 62) - pnWindow)) {
      return candidatePn + pnWindow;
    }
    if (candidatePn > expectedPacketNumber + pnHalfWindow &&
        candidatePn >= pnWindow) {
      return candidatePn - pnWindow;
    }

    return candidatePn;
  }

  void parseFrames(Uint8List frameBytes, Logger log) {
    ByteData buffer = ByteData.view(frameBytes.buffer);
    int offset = 0;

    int frameType = -1;
    try {
      while (offset < buffer.lengthInBytes) {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-12.4
        // "Each frame begins with a Frame Type, indicating its type, followed by additional type-dependent fields"
        int frameStartOffset = offset;
        frameType = buffer.getUint8(offset);
        offset = frameStartOffset; // Reset offset for parsing the frame

        switch (frameType) {
          case 0x00:
            var padding = Padding();
            padding.parse(buffer, offset, log);
            frames.add(padding);
            offset += padding.getFrameLength(); // Assuming parse updates an internal length
            break;
          case 0x01:
            var ping = PingFrame(quicVersion!);
            ping.parse(buffer, offset, log);
            frames.add(ping);
            offset += ping.getFrameLength();
            break;
          case 0x02:
          case 0x03:
            var ack = AckFrame();
            ack.parse(buffer, offset, log);
            frames.add(ack);
            offset += ack.getFrameLength();
            break;
          case 0x04:
            var resetStream = ResetStreamFrame();
            resetStream.parse(buffer, offset, log);
            frames.add(resetStream);
            offset += resetStream.getFrameLength();
            break;
          case 0x05:
            var stopSending = StopSendingFrame(quicVersion!);
            stopSending.parse(buffer, offset, log);
            frames.add(stopSending);
            offset += stopSending.getFrameLength();
            break;
          case 0x06:
            var crypto = CryptoFrame();
            crypto.parse(buffer, offset, log);
            frames.add(crypto);
            offset += crypto.getFrameLength();
            break;
          case 0x07:
            var newToken = NewTokenFrame();
            newToken.parse(buffer, offset, log);
            frames.add(newToken);
            offset += newToken.getFrameLength();
            break;
          case 0x10:
            var maxData = MaxDataFrame();
            maxData.parse(buffer, offset, log);
            frames.add(maxData);
            offset += maxData.getFrameLength();
            break;
          case 0x011:
            var maxStreamData = MaxStreamDataFrame();
            maxStreamData.parse(buffer, offset, log);
            frames.add(maxStreamData);
            offset += maxStreamData.getFrameLength();
            break;
          case 0x12:
          case 0x13:
            var maxStreams = MaxStreamsFrame();
            maxStreams.parse(buffer, offset, log);
            frames.add(maxStreams);
            offset += maxStreams.getFrameLength();
            break;
          case 0x14:
            var dataBlocked = DataBlockedFrame();
            dataBlocked.parse(buffer, offset, log);
            frames.add(dataBlocked);
            offset += dataBlocked.getFrameLength();
            break;
          case 0x15:
            var streamDataBlocked = StreamDataBlockedFrame();
            streamDataBlocked.parse(buffer, offset, log);
            frames.add(streamDataBlocked);
            offset += streamDataBlocked.getFrameLength();
            break;
          case 0x16:
          case 0x17:
            var streamsBlocked = StreamsBlockedFrame();
            streamsBlocked.parse(buffer, offset, log);
            frames.add(streamsBlocked);
            offset += streamsBlocked.getFrameLength();
            break;
          case 0x18:
            var newConnectionId = NewConnectionIdFrame(quicVersion!);
            newConnectionId.parse(buffer, offset, log);
            frames.add(newConnectionId);
            offset += newConnectionId.getFrameLength();
            break;
          case 0x19:
            var retireConnectionId = RetireConnectionIdFrame(quicVersion!);
            retireConnectionId.parse(buffer, offset, log);
            frames.add(retireConnectionId);
            offset += retireConnectionId.getFrameLength();
            break;
          case 0x1a:
            var pathChallenge = PathChallengeFrame(quicVersion!);
            pathChallenge.parse(buffer, offset, log);
            frames.add(pathChallenge);
            offset += pathChallenge.getFrameLength();
            break;
          case 0x1b:
            var pathResponse = PathResponseFrame(quicVersion!);
            pathResponse.parse(buffer, offset, log);
            frames.add(pathResponse);
            offset += pathResponse.getFrameLength();
            break;
          case 0x1c:
          case 0x1d:
            var connectionClose = ConnectionCloseFrame(quicVersion!);
            connectionClose.parse(buffer, offset, log);
            frames.add(connectionClose);
            offset += connectionClose.getFrameLength();
            break;
          case 0x1e:
            var handshakeDone = HandshakeDoneFrame(quicVersion!);
            handshakeDone.parse(buffer, offset, log);
            frames.add(handshakeDone);
            offset += handshakeDone.getFrameLength();
            break;
          case 0x30:
          case 0x31:
            var datagram = DatagramFrame();
            datagram.parse(buffer, offset, log);
            frames.add(datagram);
            offset += datagram.getFrameLength();
            break;
          default:
            if ((frameType >= 0x08) && (frameType <= 0x0f)) {
              var streamFrame = StreamFrame();
              streamFrame.parse(buffer, offset, log);
              frames.add(streamFrame);
              offset += streamFrame.getFrameLength();
            } else {
              // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
              // "An endpoint MUST treat the receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR."
              throw TransportError(
                  QuicConstants.transportErrorCode.frameEncodingError);
            }
        }
      }
    } on InvalidIntegerEncodingException {
      log.error("Parse error while parsing frame of type $frameType.");
      throw TransportError(
          QuicConstants.transportErrorCode.frameEncodingError,
          "invalid integer encoding");
    } on ArgumentError {
      log.error(
          "Parse error while parsing frame of type $frameType, packet will be marked invalid (and dropped)");
      // Could happen when a frame contains a large int (> 2^32-1) where an int value is expected (see VariableLengthInteger.parse()).
      // Strictly speaking, this would not be an invalid packet, but Kwik cannot handle it.
      throw InvalidPacketException("unexpected large int value");
    } on RangeError {
      // Buffer underflow is obviously a frame encoding error.
      log.error("Parse error while parsing frame of type $frameType.");
      throw TransportError(
          QuicConstants.transportErrorCode.frameEncodingError,
          "invalid frame encoding");
    } on IntegerTooLargeException {
      // In this context, integer too large means there is an int value in the frame that can't be valid (e.g.
      // a length of a byte array > 2^32-1), so this really is a frame encoding error.
      log.error("Parse error while parsing frame of type $frameType.");
      throw TransportError(
          QuicConstants.transportErrorCode.frameEncodingError,
          "invalid frame encoding");
    }
  }

  int getPacketNumber() {
    if (packetNumber >= 0) {
      return packetNumber;
    } else {
      throw StateError("PN is not yet known");
    }
  }

  // TODO: move to constructor once setting pn after packet creation is not used anymore
  void setPacketNumber(int pn) {
    if (pn < 0) {
      throw ArgumentError();
    }
    packetNumber = pn;
  }

  Uint8List generatePayloadBytes(int encodedPacketNumberLength) {
    ByteData frameBytes = ByteData(maxPacketSize);
    int offset = 0;
    for (var frame in frames) {
      offset = frame.serialize(frameBytes, offset);
    }
    int serializeFramesLength = offset;

    // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
    // "To ensure that sufficient data is available for sampling, packets are
    //   padded so that the combined lengths of the encoded packet number and
    //   protected payload is at least 4 bytes longer than the sample required
    //   for header protection."

    // "To ensure that sufficient data is available for sampling, packets are padded so that the combined lengths
    //   of the encoded packet number and protected payload is at least 4 bytes longer than the sample required
    //   for header protection. (...). This results in needing at least 3 bytes of frames in the unprotected payload
    //   if the packet number is encoded on a single byte, or 2 bytes of frames for a 2-byte packet number encoding."
    if (encodedPacketNumberLength + serializeFramesLength < 4) {
      Padding padding =
          Padding(4 - encodedPacketNumberLength - serializeFramesLength);
      frames.add(padding);
      offset = padding.serialize(frameBytes, offset);
    }

    return Uint8List.view(frameBytes.buffer, 0, offset);
  }

  void protectPacketNumberAndPayload(Uint8List packetBuffer,
      int packetNumberSize, Uint8List payload, int paddingSize, Aead aead) {
    int packetNumberPosition = packetBuffer.length - packetNumberSize;

    // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
    // "The associated data, A, for the AEAD is the contents of the QUIC
    //   header, starting from the flags octet in either the short or long
    //   header, up to and including the unprotected packet number."
    int additionalDataSize = packetBuffer.length;
    Uint8List additionalData = Uint8List.fromList(packetBuffer);

    Uint8List paddedPayload = Uint8List(payload.length + paddingSize);
    paddedPayload.setRange(0, payload.length, payload);
    Uint8List encryptedPayload =
        encryptPayload(paddedPayload, additionalData, packetNumber, aead);

    // In Dart, you'd extend the original buffer or create a new one with the encrypted payload
    // For simplicity, let's assume `packetBuffer` can be resized or is a growable list
    // In a real scenario, you'd manage buffer writing more carefully.
    // Here, we just return the combined bytes
    Uint8List resultBuffer = Uint8List(packetBuffer.length + encryptedPayload.length);
    resultBuffer.setRange(0, packetBuffer.length, packetBuffer);
    resultBuffer.setRange(packetBuffer.length, resultBuffer.length, encryptedPayload);

    Uint8List protectedPacketNumber;
    Uint8List encodedPacketNumber = encodePacketNumber(packetNumber);
    Uint8List mask =
        createHeaderProtectionMaskWithLength(encryptedPayload, encodedPacketNumber.length, aead);

    protectedPacketNumber = Uint8List(encodedPacketNumber.length);
    for (int i = 0; i < encodedPacketNumber.length; i++) {
      protectedPacketNumber[i] = (encodedPacketNumber[i] ^ mask[1 + i]);
    }

    int flags = resultBuffer[0];
    if ((flags & 0x80) == 0x80) {
      // Long header: 4 bits masked
      flags ^= (mask[0] & 0x0f);
    } else {
      // Short header: 5 bits masked
      flags ^= (mask[0] & 0x1f);
    }
    resultBuffer[0] = flags;

    // Update the packet number in the `resultBuffer`
    resultBuffer.setRange(packetNumberPosition, packetNumberPosition + protectedPacketNumber.length, protectedPacketNumber);

    // The current `packetBuffer` is now `resultBuffer` and its position is at the end of the data.
    // For this Dart conversion, we'll just consider the `resultBuffer` as the final output.
    // You might want to return `resultBuffer` or modify `packetBuffer` in place if it's a growable list.
    packetSize = resultBuffer.length;
    // This `protectPacketNumberAndPayload` would ideally modify the `packetBuffer` in place
    // For this conversion, let's assume `packetBuffer` is a conceptual byte stream that gets built.
  }

  static int bytesToInt(Uint8List data) {
    int value = 0;
    for (int i = 0; i < data.length; i++) {
      value = (value << 8) | (data[i] & 0xff);
    }
    return value;
  }

  void addFrame(QuicFrame frame) {
    frames.add(frame);
  }

  void addFrames(List<QuicFrame> frames) {
    this.frames.addAll(frames);
  }

  int getSize() {
    if (packetSize > 0) {
      return packetSize;
    } else {
      throw StateError("no size for ${runtimeType.toString()}");
    }
  }

  int estimateLength(int additionalPayload);

  EncryptionLevel getEncryptionLevel();

  PnSpace getPnSpace();

  Uint8List generatePacketBytes(Aead aead);

  void parse(Uint8List data, Aead aead, int largestPacketNumber, Logger log,
      int sourceConnectionIdLength);

  List<QuicFrame> getFrames() {
    return frames;
  }

  PacketProcessorProcessResult accept(
      PacketProcessor processor, PacketMetaData metaData);

  bool isCrypto() {
    return !getEncryptionLevel().equals(EncryptionLevel.app) &&
        frames.any((f) => f is CryptoFrame);
  }

  QuicPacket copy() {
    throw StateError("copy() not implemented for ${runtimeType.toString()}");
  }

  bool canBeAcked() {
    return true;
  }

  bool isAckEliciting() {
    return frames.any((frame) => frame.isAckEliciting());
  }

  bool isAckOnly() {
    return frames.every((frame) => frame is AckFrame);
  }

  bool isInflightPacket() {
    return frames.any((frame) => frame.isAckEliciting() || frame is Padding);
  }

  Uint8List? getDestinationConnectionId() {
    return destinationConnectionId;
  }

  void setIsProbe(bool probe) {
    isProbe = probe;
  }

  Version? getVersion() {
    return quicVersion;
  }
}

// short_header_packet.dart
class ShortHeaderPacket extends QuicPacket {
  late int keyPhaseBit;

  ShortHeaderPacket(Version quicVersion) : super() {
    this.quicVersion = quicVersion;
  }

  ShortHeaderPacket.forSending(
      Version quicVersion, Uint8List destinationConnectionId, QuicFrame? frame)
      : super() {
    this.quicVersion = quicVersion;
    this.destinationConnectionId = destinationConnectionId;
    frames = [];
    if (frame != null) {
      frames.add(frame);
    }
  }

  @override
  void parse(Uint8List buffer, Aead aead, int largestPacketNumber, Logger log,
      int sourceConnectionIdLength) {
    log.debug("Parsing ${runtimeType.toString()}");
    if (buffer.length < 1 + sourceConnectionIdLength) {
      throw InvalidPacketException();
    }
    // In Dart, assuming the buffer is already a slice of the relevant part of the packet.
    // If not, you'd need to manage offsets.
    if (0 != 0) {
      // parsePacketNumberAndPayload method requires packet to start at 0.
      throw StateError("Buffer must start at position 0 for parsing.");
    }

    int flags = buffer[0];
    checkPacketType(flags);

    // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-5.1
    // "Packets with short headers (Section 17.3) only include the
    //   Destination Connection ID and omit the explicit length.  The length
    //   of the Destination Connection ID field is expected to be known to
    //   endpoints."
    Uint8List packetConnectionId = Uint8List(sourceConnectionIdLength);
    packetConnectionId.setAll(0, buffer.sublist(1, 1 + sourceConnectionIdLength));
    destinationConnectionId = packetConnectionId;
    log.debug("Destination connection id", packetConnectionId);

    try {
      parsePacketNumberAndPayload(
          buffer.sublist(1 + sourceConnectionIdLength),
          flags,
          buffer.length - (1 + sourceConnectionIdLength),
          aead,
          largestPacketNumber,
          log);
      aead.confirmKeyUpdateIfInProgress();
    } on DecryptionException catch (cantDecrypt) {
      aead.cancelKeyUpdateIfInProgress();
      throw cantDecrypt;
    } finally {
      // In Dart, if you're not using ByteBuffer, you'd need to calculate the size based on what was parsed.
      // For this conversion, let's assume `packetSize` is set by the `parsePacketNumberAndPayload` implicitly
      // or we'd need a more explicit way to track consumed bytes.
      packetSize = buffer.length;
    }
  }

  @override
  void checkReservedBits(int decryptedFlags) {
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
    // "An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both
    //  packet and header protection, as a connection error of type PROTOCOL_VIOLATION. "
    if ((decryptedFlags & 0x18) != 0) {
      throw TransportError(QuicConstants.transportErrorCode.protocolViolation,
          "Reserved bits in short header packet are not zero");
    }
  }

  @override
  void setUnprotectedHeader(int decryptedFlags) {
    keyPhaseBit = ((decryptedFlags & 0x04) >> 2);
  }

  @override
  int estimateLength(int additionalPayload) {
    int packetNumberSize = computePacketNumberSize(packetNumber);
    int payloadSize =
        frames.map((f) => f.getFrameLength()).sum + additionalPayload;
    int padding = Math.max(0, 4 - packetNumberSize - payloadSize);
    return 1 +
        destinationConnectionId!.length +
        (packetNumber < 0 ? 4 : packetNumberSize) +
        payloadSize +
        padding +
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-sample
        // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
        16;
  }

  @override
  EncryptionLevel getEncryptionLevel() {
    return EncryptionLevel.app;
  }

  @override
  PnSpace getPnSpace() {
    return PnSpace.app;
  }

  @override
  Uint8List generatePacketBytes(Aead aead) {
    assert(packetNumber >= 0);

    ByteData buffer = ByteData(maxPacketSize);
    int offset = 0;
    int flags;
    // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-17.3
    // "|0|1|S|R|R|K|P P|"
    // "Spin Bit (S):  The sixth bit (0x20) of byte 0 is the Latency Spin
    //      Bit, set as described in [SPIN]."
    // "Reserved Bits (R):  The next two bits (those with a mask of 0x18) of
    //      byte 0 are reserved. (...) The value included prior to protection MUST be set to 0. "
    flags = 0x40; // 0100 0000
    keyPhaseBit = aead.getKeyPhase();
    flags = (flags | (keyPhaseBit << 2));
    flags = encodePacketNumberLength(flags, packetNumber);
    buffer.setUint8(offset++, flags);
    for (var b in destinationConnectionId!) {
      buffer.setUint8(offset++, b);
    }

    Uint8List encodedPacketNumber = encodePacketNumber(packetNumber);
    for (var b in encodedPacketNumber) {
      buffer.setUint8(offset++, b);
    }

    Uint8List frameBytes = generatePayloadBytes(encodedPacketNumber.length);
    protectPacketNumberAndPayload(
        Uint8List.view(buffer.buffer, 0, offset),
        encodedPacketNumber.length,
        frameBytes,
        0,
        aead);

    // After protectPacketNumberAndPayload, the buffer might be resized or new bytes might be added.
    // For this Dart conversion, assuming the 'protect' method returns the final bytes or updates a
    // mutable buffer that we can then take a view of.
    // Here, we'll just reconstruct the buffer for the return value for simplicity of conversion.
    Uint8List finalPacketBytes = Uint8List(packetSize);
    finalPacketBytes.setAll(0, Uint8List.view(buffer.buffer, 0, packetSize));
    return finalPacketBytes;
  }

  @override
  PacketProcessorProcessResult accept(
      PacketProcessor processor, PacketMetaData metaData) {
    return processor.processShortHeaderPacket(this, metaData);
  }

  void checkPacketType(int flags) {
    if ((flags & 0xc0) != 0x40) {
      // Programming error: this method shouldn't have been called if packet is not a Short Frame
      throw StateError("Invalid packet type for ShortHeaderPacket");
    }
  }

  @override
  Uint8List? getDestinationConnectionId() {
    return destinationConnectionId;
  }

  @override
  String toString() {
    return "Packet "
        "${isProbe ? "P" : ""}"
        "${getEncryptionLevel().name.substring(0, 1)}|"
        "${packetNumber >= 0 ? packetNumber : "."}|"
        "S$keyPhaseBit|"
        "${Bytes.bytesToHex(destinationConnectionId!)}|"
        "$packetSize|"
        "${frames.length}  "
        "${frames.map((f) => f.toString()).join(" ")}";
  }
}

// long_header_packet.dart
abstract class LongHeaderPacket extends QuicPacket {
  static const int minPacketLength = 1 + 4 + 1 + 0 + 1 + 0 + 1 + 1; // type + version + dcid len + dcid + scid len + scid + length + packet number + payload

  Uint8List? sourceConnectionId;

  static bool isLongHeaderPacket(int flags, Version quicVersion) {
    return (flags & 0b1100_0000) == 0b1100_0000;
  }

  static Type determineType(int flags, Version version) {
    int type = (flags & 0x30) >> 4;
    if (InitialPacket.isInitialType(type, version)) {
      return InitialPacket;
    } else if (HandshakePacket.isHandshake(type, version)) {
      return HandshakePacket;
    } else if (RetryPacket.isRetry(type, version)) {
      return RetryPacket;
    } else if (ZeroRttPacket.isZeroRTT(type, version)) {
      return ZeroRttPacket;
    } else {
      // Impossible, conditions are exhaustive
      throw StateError("Could not determine LongHeaderPacket type");
    }
  }

  LongHeaderPacket(Version quicVersion) : super() {
    this.quicVersion = quicVersion;
  }

  LongHeaderPacket.forSending(Version quicVersion,
      Uint8List sourceConnectionId, Uint8List destConnectionId, QuicFrame? frame)
      : super() {
    this.quicVersion = quicVersion;
    this.sourceConnectionId = sourceConnectionId;
    this.destinationConnectionId = destConnectionId;
    frames = [];
    if (frame != null) {
      frames.add(frame);
    }
  }

  LongHeaderPacket.forSendingMultipleFrames(Version quicVersion,
      Uint8List sourceConnectionId, Uint8List destConnectionId, List<QuicFrame> frames)
      : super() {
    if (frames == null) {
      throw ArgumentError.notNull('frames');
    }
    this.quicVersion = quicVersion;
    this.sourceConnectionId = sourceConnectionId;
    this.destinationConnectionId = destConnectionId;
    this.frames = frames;
  }

  @override
  Uint8List generatePacketBytes(Aead aead) {
    assert(packetNumber >= 0);

    ByteData packetBuffer = ByteData(QuicPacket.maxPacketSize);
    int offset = 0;
    offset = generateFrameHeaderInvariant(packetBuffer, offset);
    offset = generateAdditionalFields(packetBuffer, offset);
    Uint8List encodedPacketNumber = QuicPacket.encodePacketNumber(packetNumber);
    Uint8List frameBytes = generatePayloadBytes(encodedPacketNumber.length);
    offset = addLength(packetBuffer, offset, encodedPacketNumber.length, frameBytes.length);
    for (var b in encodedPacketNumber) {
      packetBuffer.setUint8(offset++, b);
    }

    protectPacketNumberAndPayload(
        Uint8List.view(packetBuffer.buffer, 0, offset),
        encodedPacketNumber.length,
        frameBytes,
        0,
        aead);

    // After protectPacketNumberAndPayload, packetSize is updated.
    // Return a view of the filled part of the buffer.
    return Uint8List.view(packetBuffer.buffer, 0, packetSize);
  }

  @override
  void checkReservedBits(int decryptedFlags) {
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
    // "An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both
    //  packet and header protection, as a connection error of type PROTOCOL_VIOLATION. "
    if ((decryptedFlags & 0x0c) != 0) {
      throw TransportError(QuicConstants.transportErrorCode.protocolViolation,
          "Reserved bits in long header packet are not zero");
    }
  }

  @override
  int estimateLength(int additionalPayload) {
    int packetNumberSize = computePacketNumberSize(packetNumber);
    int payloadSize =
        frames.map((f) => f.getFrameLength()).sum + additionalPayload;
    int padding = Math.max(0, 4 - packetNumberSize - payloadSize);
    return 1 +
        4 +
        1 +
        destinationConnectionId!.length +
        1 +
        sourceConnectionId!.length +
        estimateAdditionalFieldsLength() +
        (payloadSize + 1 > 63 ? 2 : 1) + // Length field size (variable-length integer)
        computePacketNumberSize(packetNumber) +
        payloadSize +
        padding +
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-sample
        // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
        16;
  }

  int generateFrameHeaderInvariant(ByteData packetBuffer, int offset) {
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets
    // "Long Header Packet {
    //    Header Form (1) = 1,
    //    Fixed Bit (1) = 1,
    //    Long Packet Type (2),
    //    Type-Specific Bits (4),"
    //    Version (32),
    //    Destination Connection ID Length (8),
    //    Destination Connection ID (0..160),
    //    Source Connection ID Length (8),
    //    Source Connection ID (0..160),
    //    Type-Specific Payload (..),
    //  }

    // Packet type and packet number length
    int flags = QuicPacket.encodePacketNumberLength(
        (0b11000000 | (getPacketType() << 4)), packetNumber);
    packetBuffer.setUint8(offset++, flags);
    // Version
    for (var b in quicVersion!.getBytes()) {
      packetBuffer.setUint8(offset++, b);
    }
    // DCID Len
    packetBuffer.setUint8(offset++, destinationConnectionId!.length);
    // Destination connection id
    for (var b in destinationConnectionId!) {
      packetBuffer.setUint8(offset++, b);
    }
    // SCID Len
    packetBuffer.setUint8(offset++, sourceConnectionId!.length);
    // Source connection id
    for (var b in sourceConnectionId!) {
      packetBuffer.setUint8(offset++, b);
    }
    return offset;
  }

  int getPacketType();

  int generateAdditionalFields(ByteData packetBuffer, int offset);

  int estimateAdditionalFieldsLength();

  int addLength(
      ByteData packetBuffer, int offset, int packetNumberLength, int payloadSize) {
    int packetLength = payloadSize + 16 + packetNumberLength;
    return VariableLengthInteger.encode(packetLength, packetBuffer, offset);
  }

  @override
  void parse(Uint8List buffer, Aead aead, int largestPacketNumber, Logger log,
      int sourceConnectionIdLength) {
    log.debug("Parsing ${runtimeType.toString()}");
    if (0 != 0) {
      // parsePacketNumberAndPayload method requires packet to start at 0.
      throw StateError("Buffer must start at position 0 for parsing.");
    }
    if (buffer.length < minPacketLength) {
      throw InvalidPacketException();
    }

    int offset = 0;
    int flags = buffer[offset++];
    checkPacketType((flags & 0x30) >> 4);

    ByteData byteDataView = ByteData.view(buffer.buffer, buffer.offsetInBytes);

    int versionInt = byteDataView.getUint32(offset, Endian.big);
    offset += 4;
    bool matchingVersion = Version.parse(versionInt).equals(quicVersion);
    if (!matchingVersion) {
      // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
      // "... packets are discarded if they indicate a different protocol version than that of the connection..."
      throw InvalidPacketException("Version does not match version of the connection");
    }

    int dstConnIdLength = buffer[offset++];
    // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-17.2
    // "In QUIC version 1, this value MUST NOT exceed 20.  Endpoints that receive a version 1 long header with a
    // value larger than 20 MUST drop the packet."
    if (dstConnIdLength < 0 || dstConnIdLength > 20) {
      throw InvalidPacketException();
    }
    if (buffer.length - offset < dstConnIdLength) {
      throw InvalidPacketException();
    }
    destinationConnectionId =
        buffer.sublist(offset, offset + dstConnIdLength);
    offset += dstConnIdLength;

    int srcConnIdLength = buffer[offset++];
    if (srcConnIdLength < 0 || srcConnIdLength > 20) {
      throw InvalidPacketException();
    }
    if (buffer.length - offset < srcConnIdLength) {
      throw InvalidPacketException();
    }
    sourceConnectionId = buffer.sublist(offset, offset + srcConnIdLength);
    offset += srcConnIdLength;
    log.debug("Destination connection id", destinationConnectionId!);
    log.debug("Source connection id", sourceConnectionId!);

    offset = parseAdditionalFields(byteDataView, offset);

    int length;
    try {
      // "The length of the remainder of the packet (that is, the Packet Number and Payload fields) in bytes"
      VariableLengthIntegerResult lengthResult =
          VariableLengthInteger.parse(byteDataView, offset);
      length = lengthResult.value;
      offset = lengthResult.bytesRead;
    } on ArgumentError {
      throw TransportError(QuicConstants.transportErrorCode.frameEncodingError);
    } on InvalidIntegerEncodingException {
      throw TransportError(QuicConstants.transportErrorCode.frameEncodingError);
    } on IntegerTooLargeException {
      throw TransportError(QuicConstants.transportErrorCode.frameEncodingError);
    }
    log.debug("Length (PN + payload): $length");

    try {
      parsePacketNumberAndPayload(
          buffer.sublist(offset), flags, length, aead, largestPacketNumber, log);
    } finally {
      // Assuming parsePacketNumberAndPayload updates packetSize based on bytes consumed
      // For a pure Dart conversion, you'd calculate this explicitly based on offsets.
      packetSize = buffer.length;
    }
  }

  @override
  String toString() {
    return "Packet "
        "${isProbe ? "P" : ""}"
        "${getEncryptionLevel().name.substring(0, 1)}|"
        "${packetNumber >= 0 ? packetNumber : "."}|"
        "L|"
        "${packetSize >= 0 ? packetSize : "."}|"
        "${frames.length}  "
        "${frames.map((f) => f.toString()).join(" ")}";
  }

  Uint8List? getSourceConnectionId() {
    return sourceConnectionId;
  }

  void checkPacketType(int type) {
    if (type != getPacketType()) {
      // Programming error: this method shouldn't have been called if packet is not Initial
      throw StateError("Invalid packet type for LongHeaderPacket");
    }
  }

  int parseAdditionalFields(ByteData buffer, int offset);
}

// initial_packet.dart
class InitialPacket extends LongHeaderPacket {
  static int v1Type = 0; // An Initial packet uses long headers with a type value of 0x00.
  static int v2Type = 1; // Initial: 0b01

  Uint8List? token;

  static bool isInitial(int flags, int version) {
    return ((flags & 0b11110000) == 0b11000000 &&
            version == Version.quicVersion1.id) ||
        ((flags & 0b11110000) == 0b11010000 &&
            version == Version.quicVersion2.id);
  }

  static bool isInitialType(int type, Version packetVersion) {
    if (packetVersion.isV2()) {
      return type == v2Type;
    } else {
      return type == v1Type;
    }
  }

  InitialPacket(Version quicVersion, Uint8List sourceConnectionId,
      Uint8List destConnectionId, Uint8List? token, QuicFrame? payload)
      : super.forSending(quicVersion, sourceConnectionId, destConnectionId, payload) {
    this.token = token;
  }

  InitialPacket.empty(Version quicVersion) : super(quicVersion) {
    token = null;
  }

  InitialPacket.fromFrames(Version quicVersion,
      Uint8List sourceConnectionId, Uint8List destConnectionId, Uint8List? token, List<QuicFrame> frames)
      : super.forSendingMultipleFrames(quicVersion, sourceConnectionId, destConnectionId, frames) {
    this.token = token;
  }

  @override
  InitialPacket copy() {
    return InitialPacket.fromFrames(
        quicVersion!, sourceConnectionId!, destinationConnectionId!, token, frames);
  }

  @override
  int getPacketType() {
    if (quicVersion!.isV2()) {
      return v2Type;
    } else {
      return v1Type;
    }
  }

  @override
  int generateAdditionalFields(ByteData packetBuffer, int offset) {
    // Token length (variable-length integer)
    if (token != null) {
      offset = VariableLengthInteger.encode(token!.length, packetBuffer, offset);
      for (var b in token!) {
        packetBuffer.setUint8(offset++, b);
      }
    } else {
      packetBuffer.setUint8(offset++, 0x00);
    }
    return offset;
  }

  @override
  int estimateAdditionalFieldsLength() {
    return token == null ? 1 : 1 + token!.length;
  }

  @override
  EncryptionLevel getEncryptionLevel() {
    return EncryptionLevel.initial;
  }

  @override
  PnSpace getPnSpace() {
    return PnSpace.initial;
  }

  @override
  PacketProcessorProcessResult accept(
      PacketProcessor processor, PacketMetaData metaData) {
    return processor.processInitialPacket(this, metaData);
  }

  @override
  int parseAdditionalFields(ByteData buffer, int offset) {
    // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5:
    // "An Initial packet (shown in Figure 13) has two additional header
    // fields that are added to the Long Header before the Length field."
    try {
      VariableLengthIntegerResult tokenLengthResult =
          VariableLengthInteger.parse(buffer, offset);
      int tokenLength = tokenLengthResult.value;
      offset = tokenLengthResult.bytesRead;

      if (tokenLength > 0) {
        if (tokenLength <= (buffer.lengthInBytes - offset)) {
          token = Uint8List(tokenLength);
          token!.setAll(0, Uint8List.view(buffer.buffer, offset + buffer.offsetInBytes, tokenLength));
          offset += tokenLength;
        } else {
          throw InvalidPacketException();
        }
      }
    } on InvalidIntegerEncodingException {
      throw InvalidPacketException();
    }
    return offset;
  }

  Uint8List? getToken() {
    return token;
  }

  @override
  String toString() {
    return "Packet "
        "${isProbe ? "P" : ""}"
        "${getEncryptionLevel().name.substring(0, 1)}|"
        "${packetNumber >= 0 ? packetNumber : "."}|"
        "L|"
        "${packetSize >= 0 ? packetSize : "."}|"
        "${frames.length}  "
        "Token=${token != null ? Bytes.bytesToHex(token!) : "[]"} "
        "${frames.map((f) => f.toString()).join(" ")}";
  }

  void ensureSize(int minimumSize) {
    int payloadSize = frames.map((f) => f.getFrameLength()).sum;
    int estimatedPacketLength = 1 +
        4 +
        1 +
        destinationConnectionId!.length +
        sourceConnectionId!.length +
        (token != null ? token!.length : 1) +
        2 +
        1 +
        payloadSize +
        16; // 16 is what encryption adds, note that final length might be larger due to multi-byte packet length
    int paddingSize = minimumSize - estimatedPacketLength;
    if (paddingSize > 0) {
      frames.add(Padding(paddingSize));
    }
  }
}