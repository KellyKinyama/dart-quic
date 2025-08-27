/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


import "dart:typed_data";

import "package:dart_quic/kwik/core/QuicConstants.dart";
import "package:dart_quic/kwik/core/common/EncryptionLevel.dart";
import "package:dart_quic/kwik/core/common/PnSpace.dart";
import "package:dart_quic/kwik/core/crypto/Aead.dart";
// import "package:dart_quic/kwik/core/frame.*;
import "package:dart_quic/kwik/core/generic/IntegerTooLargeException.dart";
import "package:dart_quic/kwik/core/generic/InvalidIntegerEncodingException.dart";
// import "package:dart_quic/kwik/core/impl.*;
// import "package:dart_quic/kwik/core/log.Logger;



import "../buffer.dart";
import "../frame/quic_frame.dart";


import "../impl/Version.dart";
import "ShortHeaderPacket.dart";


typedef long=int;
typedef byte=int;

abstract class QuicPacket {

    static final int MAX_PACKET_SIZE = 1500;

    Version quicVersion;
    int packetNumber = -1;
    List<QuicFrame> frames = [];
    int packetSize = -1;
    Uint8List destinationConnectionId;
     bool isProbe;

    QuicPacket();

    static int computePacketNumberSize(int packetNumber) {
        if (packetNumber <= 0xff) {
            return 1;
        }
        else if (packetNumber <= 0xffff) {
            return 2;
        }
        else if (packetNumber <= 0xffffff) {
            return 3;
        }
        else {
            return 4;
        }
    }

    static Uint8List encodePacketNumber(int packetNumber) {
        if (packetNumber <= 0xff) {
            return Uint8List (packetNumber);
        }
        else if (packetNumber <= 0xffff) {
            return Uint8List  .fromList([(packetNumber >> 8), (packetNumber & 0x00ff)]);
        }
        else if (packetNumber <= 0xffffff) {
            return Uint8List  .fromList([ (packetNumber >> 16),  (packetNumber >> 8),  (packetNumber & 0x00ff)]);
        }
        else if (packetNumber <= 0xffffffff) {
            return Uint8List  .fromList([(packetNumber >> 24),  (packetNumber >> 16), (packetNumber >> 8), (packetNumber & 0x00ff)]);
        }
        else {
            throw UnimplementedError("cannot encode pn > 4 bytes");
        }
    }

    /**
     * Updates the given flags byte to encode the packet number length that is used for encoding the given packet number.
     * @param flags
     * @param packetNumber
     * @return
     */
    static int encodePacketNumberLength(int flags, int packetNumber) {
        if (packetNumber <= 0xff) {
            return flags;
        }
        else if (packetNumber <= 0xffff) {
            return  (flags | 0x01);
        }
        else if (packetNumber <= 0xffffff) {
            return  (flags | 0x02);
        }
        else if (packetNumber <= 0xffffffff) {
            return  (flags | 0x03);
        }
        else {
            throw UnimplementedError("cannot encode pn > 4 bytes");
        }
    }

    void parsePacketNumberAndPayload(Buffer buffer, int flags, int remainingLength, Aead aead, int largestPacketNumber) 
    // throws DecryptionException, InvalidPacketException, TransportError 
    {
        if (buffer.remaining() < remainingLength) {
            throw InvalidPacketException();
        }

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "When removing packet protection, an endpoint
        //   first removes the header protection."

        int currentPosition = buffer.position();
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)."
        if (buffer.remaining() < 4) {
            throw InvalidPacketException();
        }
        buffer.position(currentPosition:  currentPosition + 4);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
        // "This algorithm samples 16 bytes from the packet ciphertext."
        if (buffer.remaining() < 16) {
            throw InvalidPacketException();
        }
        Uint8List sample = Uint8List(16);
        buffer.get(sample);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
        // "Header protection is applied after packet protection is applied (see
        //   Section 5.3).  The ciphertext of the packet is sampled and used as
        //   input to an encryption algorithm."
        Uint8List mask = createHeaderProtectionMask(sample, aead);
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1
        // "The output of this algorithm is a 5 byte mask which is applied to the
        //   header fields using exclusive OR.  The least significant
        //   bits of the first byte of the packet are masked by the least
        //   significant bits of the first mask byte"
        int decryptedFlags;
        if ((flags & 0x80) == 0x80) {
            // Long header: 4 bits masked
            decryptedFlags =  (flags ^ mask[0] & 0x0f);
        }
        else {
            // Short header: 5 bits masked
            decryptedFlags =  (flags ^ mask[0] & 0x1f);
        }
        setUnprotectedHeader(decryptedFlags);
        buffer.position(currentPosition:  currentPosition);

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
        // "pn_length = (packet[0] & 0x03) + 1"
        int protectedPackageNumberLength = (decryptedFlags & 0x03) + 1;
        Uint8List protectedPackageNumber = Uint8List(protectedPackageNumberLength);
        buffer.get(protectedPackageNumber);

        Uint8List unprotectedPacketNumber = Uint8List(protectedPackageNumberLength);
        for (int i = 0; i < protectedPackageNumberLength; i++) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
            // " ...and the packet number is
            //   masked with the remaining bytes.  Any unused bytes of mask that might
            //   result from a shorter packet number encoding are unused."
            unprotectedPacketNumber[i] =  (protectedPackageNumber[i] ^ mask[1+i]);
        }
        int truncatedPacketNumber = bytesToInt(unprotectedPacketNumber);
        packetNumber = decodePacketNumber(truncatedPacketNumber, largestPacketNumber, protectedPackageNumberLength * 8);
        // log.decrypted("Unprotected packet number: " + packetNumber);

        currentPosition = buffer.position();
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags byte in either the short or long
        //   header, up to and including the unprotected packet number."
        Uint8List frameHeader = Uint8List(buffer.position());
        buffer.position(0);
        buffer.get(frameHeader);
        frameHeader[0] = decryptedFlags;
        buffer.position(currentPosition:  currentPosition);

        // Copy unprotected (decrypted) packet number in frame header, before decrypting payload.
        System.arraycopy(unprotectedPacketNumber, 0, frameHeader, frameHeader.length - (protectedPackageNumberLength), protectedPackageNumberLength);
        // log.encrypted("Frame header", frameHeader);

        // "The input plaintext, P, for the AEAD is the payload of the QUIC
        //   packet, as described in [QUIC-TRANSPORT]."
        // "The output ciphertext, C, of the AEAD is transmitted in place of P."
        int encryptedPayloadLength = remainingLength - protectedPackageNumberLength;
        if (encryptedPayloadLength < 1) {
            throw InvalidPacketException();
        }
        Uint8List payload = Uint8List(encryptedPayloadLength);
        buffer.get(payload, 0, encryptedPayloadLength);
        // log.encrypted("Encrypted payload", payload);

        Uint8List frameBytes = decryptPayload(payload, frameHeader, packetNumber, aead);
        // log.decrypted("Decrypted payload", frameBytes);

        frames = [];
        parseFrames(frameBytes);
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
        // "An endpoint MUST (...) after removing both packet and header protection, (...)"
        checkReservedBits(decryptedFlags);
    }

    void setUnprotectedHeader(int decryptedFlags) {
        throw UnimplementedError();
    }

    void checkReservedBits(int decryptedFlags)  {
      throw UnimplementedError();
    }

    Uint8List createHeaderProtectionMaskLocal(Uint8List sample, Aead aead) {
        return createHeaderProtectionMask(sample, 4, aead);
    }

    Uint8List createHeaderProtectionMask(Uint8List ciphertext, int encodedPacketNumberLength, Aead aead) {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4
        // "The same number of bytes are always sampled, but an allowance needs
        //   to be made for the endpoint removing protection, which will not know
        //   the length of the Packet Number field.  In sampling the packet
        //   ciphertext, the Packet Number field is assumed to be 4 bytes long
        //   (its maximum possible encoded length)."
        int sampleOffset = 4 - encodedPacketNumberLength;
        Uint8List sample = Uint8List(16);
        System.arraycopy(ciphertext, sampleOffset, sample, 0, 16);

        return aead.createHeaderProtectionMask(sample);
    }

    Uint8List encryptPayload(Uint8List message, Uint8List associatedData, int packetNumber, Aead aead) {

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The nonce, N, is formed by combining the packet
        //   protection IV with the packet number.  The 64 bits of the
        //   reconstructed QUIC packet number in network byte order are left-
        //   padded with zeros to the size of the IV.  The exclusive OR of the
        //   padded packet number and the IV forms the AEAD nonce"
        Uint8List writeIV = aead.getWriteIV();
        Buffer nonceInput = Buffer.allocate(writeIV.length);
        for (int i = 0; i < nonceInput.capacity() - 8; i++)
            nonceInput.put((byte) 0x00);
        nonceInput.putLong(packetNumber);

        Uint8List nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ writeIV[i++]);

        return aead.aeadEncrypt(associatedData, message, nonce);
    }

    Uint8List decryptPayload(Uint8List message, Uint8List associatedData, long packetNumber, Aead aead) throws DecryptionException {
        Buffer nonceInput = Buffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(packetNumber);

        if (this.runtimeType== ShortHeaderPacket) {
            aead.checkKeyPhase(((ShortHeaderPacket) this).keyPhaseBit);
        }

        Uint8List writeIV = aead.getWriteIV();
        Uint8List nonce = new byte[12];
        int i = 0;
        for (byte b : nonceInput.array())
            nonce[i] = (byte) (b ^ writeIV[i++]);

        return aead.aeadDecrypt(associatedData, message, nonce);
    }

    static int decodePacketNumber(int truncatedPacketNumber, int largestPacketNumber, int bits) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#sample-packet-number-decoding
        // "Figure 47: Sample Packet Number Decoding Algorithm"
        int expectedPacketNumber = largestPacketNumber + 1;
        int pnWindow = 1 << bits;
        int pnHalfWindow = (pnWindow / 2).toInt();
        int pnMask = ~ (pnWindow - 1);

        long candidatePn = (expectedPacketNumber & pnMask) | truncatedPacketNumber;
        if (candidatePn <= expectedPacketNumber - pnHalfWindow && candidatePn < (1 << 62) - pnWindow) {
            return candidatePn + pnWindow;
        }
        if (candidatePn > expectedPacketNumber + pnHalfWindow && candidatePn >= pnWindow) {
            return candidatePn - pnWindow;
        }

        return candidatePn;
    }

    void parseFrames(Uint8List frameBytes) 
    // throws InvalidPacketException, TransportError 
    {
        Buffer buffer = Buffer.wrap(frameBytes);

        int frameType = -1;
        try {
            while (buffer.remaining() > 0) {
                // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-12.4
                // "Each frame begins with a Frame Type, indicating its type, followed by additional type-dependent fields"
                buffer.mark();
                frameType = buffer.get();
                buffer.reset();
                switch (frameType) {
                    case 0x00:
                        frames.add(new Padding().parse(buffer, log));
                        break;
                    case 0x01:
                        frames.add(new PingFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x02:
                    case 0x03:
                        frames.add(new AckFrame().parse(buffer, log));
                        break;
                    case 0x04:
                        frames.add(new ResetStreamFrame().parse(buffer, log));
                        break;
                    case 0x05:
                        frames.add(new StopSendingFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x06:
                        frames.add(new CryptoFrame().parse(buffer, log));
                        break;
                    case 0x07:
                        frames.add(new NewTokenFrame().parse(buffer, log));
                        break;
                    case 0x10:
                        frames.add(new MaxDataFrame().parse(buffer, log));
                        break;
                    case 0x011:
                        frames.add(new MaxStreamDataFrame().parse(buffer, log));
                        break;
                    case 0x12:
                    case 0x13:
                        frames.add(new MaxStreamsFrame().parse(buffer, log));
                        break;
                    case 0x14:
                        frames.add(new DataBlockedFrame().parse(buffer, log));
                        break;
                    case 0x15:
                        frames.add(new StreamDataBlockedFrame().parse(buffer, log));
                        break;
                    case 0x16:
                    case 0x17:
                        frames.add(new StreamsBlockedFrame().parse(buffer, log));
                        break;
                    case 0x18:
                        frames.add(new NewConnectionIdFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x19:
                        frames.add(new RetireConnectionIdFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x1a:
                        frames.add(new PathChallengeFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x1b:
                        frames.add(new PathResponseFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x1c:
                    case 0x1d:
                        frames.add(new ConnectionCloseFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x1e:
                        frames.add(new HandshakeDoneFrame(quicVersion).parse(buffer, log));
                        break;
                    case 0x30:
                    case 0x31:
                        frames.add(new DatagramFrame().parse(buffer, log));
                        break;
                    default:
                        if ((frameType >= 0x08) && (frameType <= 0x0f)) {
                            frames.add(new StreamFrame().parse(buffer, log));
                        }
                        else {
                            // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
                            // "An endpoint MUST treat the receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR."
                            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR);
                        }
                }
            }
        }
        catch (InvalidIntegerEncodingException e) {
            // log.error("Parse error while parsing frame of type " + frameType + ".");
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR, "invalid integer encoding");
        }
        catch (IllegalArgumentException e) {
            // log.error("Parse error while parsing frame of type " + frameType + ", packet will be marked invalid (and dropped)");
            // Could happen when a frame contains a large int (> 2^32-1) where an int value is expected (see VariableLengthInteger.parse()).
            // Strictly speaking, this would not be an invalid packet, but Kwik cannot handle it.
            throw new InvalidPacketException("unexpected large int value");
        }
        catch (BufferUnderflowException | IntegerTooLargeException e) {
            // Buffer underflow is obviously a frame encoding error.
            // In this context, integer too large means there is an int value in the frame that can't be valid (e.g.
            // a length of a byte array > 2^32-1), so this really is a frame encoding error.
            // log.error("Parse error while parsing frame of type " + frameType + ".");
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR, "invalid frame encoding");
        }
    }

    int getPacketNumber() {
        if (packetNumber >= 0) {
            return packetNumber;
        }
        else {
            throw IllegalStateException("PN is not yet known");
        }
    }

    // TODO: move to constructor once setting pn after packet creation is not used anymore
    void setPacketNumber(long pn) {
        if (pn < 0) {
            throw new IllegalArgumentException();
        }
        packetNumber = pn;
    }

    ByteBuffer generatePayloadBytes(int encodedPacketNumberLength) {
        Buffer frameBytes = Buffer.allocate(MAX_PACKET_SIZE);
        frames.stream().forEachOrdered(frame -> frame.serialize(frameBytes));
        int serializeFramesLength = frameBytes.position();
        // https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.4.2
        // "To ensure that sufficient data is available for sampling, packets are
        //   padded so that the combined lengths of the encoded packet number and
        //   payload is at least 4 bytes longer than the sample required
        //   for header protection."

        // "To ensure that sufficient data is available for sampling, packets are padded so that the combined lengths
        //   of the encoded packet number and payload is at least 4 bytes longer than the sample required
        //   for header protection. (...). This results in needing at least 3 bytes of frames in the unprotected payload
        //   if the packet number is encoded on a single byte, or 2 bytes of frames for a 2-byte packet number encoding."
        if (encodedPacketNumberLength + serializeFramesLength < 4) {
            Padding padding = new Padding(4 - encodedPacketNumberLength - frameBytes.position());
            frames.add(padding);
            padding.serialize(frameBytes);
        }
        frameBytes.flip();
        return frameBytes;
    }

    void protectPacketNumberAndPayload(Buffer packetBuffer, int packetNumberSize, ByteBuffer payload, int paddingSize, Aead aead) {
        int packetNumberPosition = packetBuffer.position() - packetNumberSize;

        // From https://tools.ietf.org/html/draft-ietf-quic-tls-16#section-5.3:
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags octet in either the short or long
        //   header, up to and including the unprotected packet number."
        int additionalDataSize = packetBuffer.position();
        Uint8List additionalData = new byte[additionalDataSize];
        packetBuffer.flip();  // Prepare for reading from start
        packetBuffer.get(additionalData);  // Position is now where it was at start of this method.
        packetBuffer.limit(packetBuffer.capacity());  // Ensure we can continue writing

        Uint8List paddedPayload = new byte[payload.limit() + paddingSize];
        payload.get(paddedPayload, 0, payload.limit());
        Uint8List encryptedPayload = encryptPayload(paddedPayload, additionalData, packetNumber, aead);
        packetBuffer.put(encryptedPayload);

        Uint8List protectedPacketNumber;
        Uint8List encodedPacketNumber = encodePacketNumber(packetNumber);
        Uint8List mask = createHeaderProtectionMask(encryptedPayload, encodedPacketNumber.length, aead);

        protectedPacketNumber = Uint8List(encodedPacketNumber.length);
        for (int i = 0; i < encodedPacketNumber.length; i++) {
            protectedPacketNumber[i] =  (encodedPacketNumber[i] ^ mask[1+i]);
        }

        int flags = packetBuffer.get(0);
        if ((flags & 0x80) == 0x80) {
            // Long header: 4 bits masked
            flags ^= (byte) (mask[0] & 0x0f);
        }
        else {
            // Short header: 5 bits masked
            flags ^= (byte) (mask[0] & 0x1f);
        }
        packetBuffer.put(0, flags);

        int currentPosition = packetBuffer.position();
        packetBuffer.position(packetNumberPosition);
        packetBuffer.put(protectedPacketNumber);
        packetBuffer.position(currentPosition);
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
        }
        else {
            throw new IllegalStateException("no size for " + this.getClass().getSimpleName());
        }
    }

    /**
     * Estimates what the length of this packet will be after it has been encrypted.
     * The estimated length must not be less than what the actual length will be.
     * Because length estimates are used when preparing packets for sending, where certain (hard) limits must be met
     * (e.g. congestion control, max datagram size, ...), the actual size may never be larger than the estimated size.
     *
     * @param additionalPayload    when not 0, estimate the length if this amount of additional (frame) bytes were added.
     * @return
     */
    abstract int estimateLength(int additionalPayload);

    abstract EncryptionLevel getEncryptionLevel();

    abstract PnSpace getPnSpace();

    abstract Uint8List generatePacketBytes(Aead aead);

    abstract void parse(ByteBuffer data, Aead aead, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException, InvalidPacketException, TransportError;

    List<QuicFrame> getFrames() {
        return frames;
    }

    abstract PacketProcessor.ProcessResult accept(PacketProcessor processor, PacketMetaData metaData);

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-recovery-18#section-2
     * "Crypto Packets:  Packets containing CRYPTO data sent in Initial or Handshake packets."
     * @return whether packet is a Crypto Packet
     */
     bool isCrypto() {
        return !getEncryptionLevel().equals(EncryptionLevel.App)
            && frames.stream().filter(f -> f instanceof CryptoFrame).findFirst().isPresent();
    }

    QuicPacket copy() {
        throw new IllegalStateException();
    }

     bool canBeAcked() {
        return true;
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "Packets that contain ack-eliciting frames elicit an ACK from the receiver (...) and are called ack-eliciting packets."
     bool isAckEliciting() {
        return frames.stream().anyMatch(frame -> frame.isAckEliciting());
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-20#section-2
    // "ACK-only:  Any packet containing only one or more ACK frame(s)."
     bool isAckOnly() {
        return frames.stream().allMatch(frame -> frame instanceof AckFrame);
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "In-flight:  Packets are considered in-flight when they are ack-eliciting or contain a PADDING frame, and they
    //  have been sent but are not acknowledged, declared lost, or abandoned along with old keys."
    // This method covers only the first part, which can be derived from the packet.
     bool isInflightPacket() {
        return frames.stream().anyMatch(frame -> frame.isAckEliciting() || frame instanceof Padding);
    }

    Uint8List getDestinationConnectionId() {
        return destinationConnectionId;
    }

    void setIsProbe( bool probe) {
        isProbe = probe;
    }

    Version getVersion() {
        return quicVersion;
    }
}
