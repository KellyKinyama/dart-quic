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
package tech.kwik.core.packet;

import "dart:typed_data";

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.impl.*;
import tech.kwik.core.log.Logger;
import tech.kwik.core.util.Bytes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * See https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-17.2.5
 */
class RetryPacket extends QuicPacket {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-retry-packet
    // "a Retry packet uses a long packet header with a type value of 0x03."
    static int V1_type = 3;
    // https://www.rfc-editor.org/rfc/rfc9369.html#name-long-header-packet-types
    // "Retry: 0b00"
    static int V2_type = 0;


    static final int RETRY_INTEGRITY_TAG_LENGTH = 16;    // The Retry Integrity Tag is 128 bits.

    // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
    // "The secret key, K, is 128 bits equal to 0xccce187ed09a09d05728155a6cb96be1."
    static final Uint8List SECRET_KEY = new Uint8List.fromList([
             0xcc,  0xce,  0x18,  0x7e,  0xd0,  0x9a,  0x09,  0xd0,
             0x57,  0x28,  0x15,  0x5a,  0x6c,  0xb9,  0x6b,  0xe1 ]);

    // https://www.rfc-editor.org/rfc/rfc9001.html#name-retry-packet-integrity
    // "The secret key, K, is 128 bits equal to 0xbe0c690b9f66575a1d766b54e368c84e."
    static final Uint8List SECRET_KEY_V1 = new Uint8List.fromList([
             0xbe,  0x0c,  0x69,  0x0b,  0x9f,  0x66,  0x57,  0x5a,
             0x1d,  0x76,  0x6b,  0x54,  0xe3,  0x68,  0xc8,  0x4e]);

    // https://www.rfc-editor.org/rfc/rfc9369.html#name-retry-integrity-tag
    // "The key and nonce used for the Retry Integrity Tag (Section 5.8 of [QUIC-TLS]) change to:
    //  (...)
    //  key = 0x8fb4b01b56ac48e260fbcbcead7ccc92
    static final Uint8List SECRET_KEY_V2 = new Uint8List.fromList([
             0x8f,  0xb4,  0xb0,  0x1b,  0x56,  0xac,  0x48,  0xe2,
             0x60,  0xfb,  0xcb,  0xce,  0xad,  0x7c,  0xcc,  0x92]);

    // https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.8
    // "The nonce, N, is 96 bits equal to 0xe54930f97f2136f0530a8c1c."
    static final Uint8List NONCE = new Uint8List.fromList([ 
             0xe5,  0x49,  0x30,  0xf9,  0x7f,  0x21,  0x36,  0xf0,
             0x53,  0x0a,  0x8c,  0x1c]);

    // https://www.rfc-editor.org/rfc/rfc9001.html#name-retry-packet-integrity
    // "The nonce, N, is 96 bits equal to 0x461599d35d632bf2239825bb."
    static final Uint8List NONCE_V1 = new Uint8List.fromList([
             0x46,  0x15,  0x99,  0xd3, 0x5d,  0x63,  0x2b,  0xf2,
             0x23,  0x98,  0x25,  0xbb]);

    // https://www.rfc-editor.org/rfc/rfc9369.html#name-retry-integrity-tag
    // "The key and nonce used for the Retry Integrity Tag (Section 5.8 of [QUIC-TLS]) change to:
    //  (...)
    //  nonce = 0xd86969bc2d7c6d9990efb04a
    static final Uint8List NONCE_V2 = new Uint8List.fromList([
             0xd8,  0x69,  0x69,  0xbc, 0x2d,  0x7c,  0x6d,  0x99,
             0x90,  0xef,  0xb0,  0x4a]);

    // Minimal length for a valid packet:  type version dcid len dcid scid len scid retry-integrety-tag
    static int MIN_PACKET_LENGTH = 1 +  4 +     1 +      0 +  1 +      0 +  16;


    Uint8List sourceConnectionId;

    Uint8List originalDestinationConnectionId;
    Uint8List retryToken;
    Uint8List rawPacketData;
    Uint8List retryIntegrityTag;

    static  bool isRetry(int type, Version quicVersion) {
        if (quicVersion.isV2()) {
            return type == 0;
        }
        else {
            return type == 3;
        }
    }

    RetryPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    RetryPacket(Version quicVersion, Uint8List sourceConnectionId, Uint8List destinationConnectionId, Uint8List originalDestinationConnectionId, Uint8List retryToken) {
        this.quicVersion = quicVersion;
        this.sourceConnectionId = sourceConnectionId;
        this.destinationConnectionId = destinationConnectionId;
        this.originalDestinationConnectionId = originalDestinationConnectionId;
        this.retryToken = retryToken;
        this.rawPacketData = new byte[1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length +
                retryToken.length + RETRY_INTEGRITY_TAG_LENGTH];
    }

    @Override
    void parse(ByteBuffer buffer, Aead aead, long largestPacketNumber, Logger log, int sourceConnectionIdLength) throws DecryptionException, InvalidPacketException {
        log.debug("Parsing " + this.getClass().getSimpleName());
        if (buffer.remaining() < MIN_PACKET_LENGTH) {
            throw new InvalidPacketException();
        }

        packetSize = buffer.remaining();
        rawPacketData = new byte[packetSize];
        buffer.mark();
        buffer.get(rawPacketData);
        buffer.reset();

        byte flags = buffer.get();

         bool matchingVersion = Version.parse(buffer.getInt()).equals(this.quicVersion);

        if (! matchingVersion) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-27#section-5.2
            // "... packets are discarded if they indicate a different protocol version than that of the connection..."
            throw new InvalidPacketException();
        }

        int dstConnIdLength = buffer.get();
        if (buffer.remaining() < dstConnIdLength + 1 + RETRY_INTEGRITY_TAG_LENGTH) {
            throw new InvalidPacketException();
        }
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get();
        if (buffer.remaining() < srcConnIdLength) {
            throw new InvalidPacketException();
        }
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);

        log.debug("Destination connection id", destinationConnectionId);
        log.debug("Source connection id", sourceConnectionId);

        if (buffer.remaining() < RETRY_INTEGRITY_TAG_LENGTH) {
            throw new InvalidPacketException();
        }
        int retryTokenLength = buffer.remaining() - RETRY_INTEGRITY_TAG_LENGTH;
        retryToken = new byte[retryTokenLength];
        buffer.get(retryToken);

        retryIntegrityTag = new byte[RETRY_INTEGRITY_TAG_LENGTH];
        buffer.get(retryIntegrityTag);
    }

    /**
     * Validates the Retry Integrity Tag that is carried by this packet.
     * @param originalDestinationConnectionId
     * @return
     */
     bool validateIntegrityTag(Uint8List originalDestinationConnectionId) {
        return Arrays.equals(computeIntegrityTag(originalDestinationConnectionId), retryIntegrityTag);
    }

    @Override
    EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    PnSpace getPnSpace() {
        return null;
    }

    @Override
    Long getPacketNumber() {
        // Retry Packet doesn't have a packet number
        return null;
    }

    @Override
    int estimateLength(int additionalPayload) {
        throw new NotYetImplementedException();
    }

    @Override
    PacketProcessor.ProcessResult accept(PacketProcessor processor, PacketMetaData metaData) {
        return processor.process(this, metaData);
    }

    @Override
    Uint8List generatePacketBytes(Aead aead) {
        packetSize = 1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length + retryToken.length + 16;
        ByteBuffer buffer = ByteBuffer.allocate(packetSize);
        byte flags = (byte) (0b1100_0000 | (getPacketType() << 4));
        buffer.put(flags);
        buffer.put(quicVersion.getBytes());
        buffer.put((byte) destinationConnectionId.length);
        buffer.put(destinationConnectionId);
        buffer.put((byte) sourceConnectionId.length);
        buffer.put(sourceConnectionId);
        buffer.put(retryToken);
        rawPacketData = buffer.array();
        buffer.put(computeIntegrityTag(originalDestinationConnectionId));
        return buffer.array();
    }

    int getPacketType() {
        if (quicVersion.isV2()) {
            return (byte) V2_type;
        }
        else {
            return (byte) V1_type;
        }

    }

    Uint8List computeIntegrityTag(Uint8List originalDestinationConnectionId) {
        ByteBuffer pseudoPacket = ByteBuffer.allocate(1 + originalDestinationConnectionId.length + 1 + 4 +
                1 + destinationConnectionId.length + 1 + sourceConnectionId.length + retryToken.length);
        pseudoPacket.put((byte) originalDestinationConnectionId.length);
        pseudoPacket.put(originalDestinationConnectionId);
        pseudoPacket.put(rawPacketData, 0, rawPacketData.length - RETRY_INTEGRITY_TAG_LENGTH);

        try {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The Retry Integrity Tag is a 128-bit field that is computed as the output of AEAD_AES_128_GCM [AEAD]..."
            SecretKeySpec secretKey = new SecretKeySpec(quicVersion.isV1()? SECRET_KEY_V1: quicVersion.isV2()? SECRET_KEY_V2: SECRET_KEY, "AES");
            String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, quicVersion.isV1()? NONCE_V1: quicVersion.isV2()? NONCE_V2: NONCE);
            Cipher aeadCipher = Cipher.getInstance(AES_GCM_NOPADDING);
            aeadCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The associated data, A, is the contents of the Retry Pseudo-Packet"
            aeadCipher.updateAAD(pseudoPacket.array());
            // https://tools.ietf.org/html/draft-ietf-quic-tls-25#section-5.8
            // "The plaintext, P, is empty."
            Uint8List cipherText = aeadCipher.doFinal(new byte[0]);
            return cipherText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Inappropriate runtime environment
            throw new QuicRuntimeException(e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Programming error
            throw new RuntimeException();
        }
    }

    @Override
     bool canBeAcked() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-18#section-17.2.5
        // "A Retry packet does not include a packet number and cannot be explicitly acknowledged by a client."
        return false;
    }

    @Override
     bool isInflightPacket() {
        return false;
    }

    @Override
     bool isAckEliciting() {
        return false;
    }

    @Override
     bool isAckOnly() {
        return false;
    }

    Uint8List getRetryToken() {
        return retryToken;
    }

    Uint8List getSourceConnectionId() {
        return sourceConnectionId;
    }

    @Override
    String toString() {
        return "Packet "
                + getEncryptionLevel().name().charAt(0) + "|"
                + "-" + "|"
                + "R" + "|"
                + packetSize + "|"
                + " Retry Token (" + retryToken.length + "): " + Bytes.bytesToHex(retryToken);
    }
}
