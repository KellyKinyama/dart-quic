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

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.PacketProcessor;
import tech.kwik.core.impl.Version;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.stream.Collectors;

class InitialPacket extends LongHeaderPacket {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet
    // "An Initial packet uses long headers with a type value of 0x00."
    static int V1_type = 0;
    // https://www.rfc-editor.org/rfc/rfc9369.html#name-long-header-packet-types
    // "Initial: 0b01"
    static int V2_type = 1;

    Uint8List token;

    /**
     * Checks whether the given flags (first byte of a QUIC packet) and version indicate an Initial packet.
     * @param flags
     * @param version
     * @return
     */
    static  bool isInitial(int flags, int version) {
        return
                // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2
                // "Initial Packet {
                //    Header Form (1) = 1,
                //    Fixed Bit (1) = 1,
                //    Long Packet Type (2) = 0,
                //    Reserved Bits (2),
                //    Packet Number Length (2),
                //    (...)
                //  }"
                ((flags & 0b1111_0000) == 0b1100_0000 && version == Version.QUIC_version_1.getId()) ||
                        // https://www.rfc-editor.org/rfc/rfc9369.html#section-3.2
                        // "Initial: 0b01"
                        ((flags & 0b1111_0000) == 0b1101_0000 && version == Version.QUIC_version_2.getId());
    }

    /**
     * Determines if the given long header type indicates an Initial packet.
     * WARNING: should only be used for long header packets!
     * @param type  the type of the packet, WARNING: this is not the raw flags byte!
     * @param packetVersion  the QUIC version of the long header packet
     * @return
     */
    static  bool isInitialType(int type, Version packetVersion) {
        if (packetVersion.isV2()) {
            return type == V2_type;
        }
        else {
            return type == V1_type;
        }
    }

    InitialPacket(Version quicVersion, Uint8List sourceConnectionId, Uint8List destConnectionId, Uint8List token, QuicFrame payload) {
        super(quicVersion, sourceConnectionId, destConnectionId, payload);
        this.token = token;
    }

    InitialPacket(Version quicVersion) {
        super(quicVersion);
        token = null;
    }

    InitialPacket(Version quicVersion, Uint8List sourceConnectionId, Uint8List destConnectionId, Uint8List token, List<QuicFrame> frames) {
        super(quicVersion, sourceConnectionId, destConnectionId, frames);
        this.token = token;
    }

    InitialPacket copy() {
        return new InitialPacket(quicVersion, sourceConnectionId, destinationConnectionId, token, frames);
    }

    @Override
    byte getPacketType() {
        if (quicVersion.isV2()) {
            return (byte) V2_type;
        }
        else {
            return (byte) V1_type;
        }
    }

    @Override
    void generateAdditionalFields(ByteBuffer packetBuffer) {
        // Token length (variable-length integer)
        if (token != null) {
            VariableLengthInteger.encode(token.length, packetBuffer);
            packetBuffer.put(token);
        }
        else {
            packetBuffer.put((byte) 0x00);
        }
    }

    @Override
    int estimateAdditionalFieldsLength() {
        return token == null? 1: 1 + token.length;
    }

    @Override
    EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Initial;
    }

    @Override
    PnSpace getPnSpace() {
        return PnSpace.Initial;
    }

    @Override
    PacketProcessor.ProcessResult accept(PacketProcessor processor, PacketMetaData metaData) {
        return processor.process(this, metaData);
    }

    @Override
    void parseAdditionalFields(ByteBuffer buffer) throws InvalidPacketException {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-17.5:
        // "An Initial packet (shown in Figure 13) has two additional header
        // fields that are added to the Long Header before the Length field."
        try {
            long tokenLength = VariableLengthInteger.parseLong(buffer);
            if (tokenLength > 0) {
                if (tokenLength <= buffer.remaining()) {
                    token = new byte[(int) tokenLength];
                    buffer.get(token);
                }
                else {
                    throw new InvalidPacketException();
                }
            }
        } catch (InvalidIntegerEncodingException e) {
            throw new InvalidPacketException();
        }
    }

    Uint8List getToken() {
        return token;
    }

    @Override
    String toString() {
        return "Packet "
                + (isProbe? "P": "")
                + getEncryptionLevel().name().charAt(0) + "|"
                + (packetNumber >= 0? packetNumber: ".") + "|"
                + "L" + "|"
                + (packetSize >= 0? packetSize: ".") + "|"
                + frames.size() + "  "
                + "Token=" + (token != null? Bytes.bytesToHex(token): "[]") + " "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

    void ensureSize(int minimumSize) {
        int payloadSize = frames.stream().mapToInt(f -> f.getFrameLength()).sum();
        int estimatedPacketLength = 1 + 4 + 1
                + destinationConnectionId.length + sourceConnectionId.length + (token != null? token.length: 1)
                + 2 + 1 + payloadSize + 16;   // 16 is what encryption adds, note that final length might be larger due to multi-byte packet length
        int paddingSize = minimumSize - estimatedPacketLength;
        if (paddingSize > 0) {
            frames.add(new Padding(paddingSize));
        }
    }
}
