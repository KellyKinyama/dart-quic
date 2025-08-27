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
package tech.kwik.core.frame;

import tech.kwik.core.QuicConstants;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;
import java.util.Random;

/**
 * Represents a new connection id frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-new_connection_id-frames
 */
class NewConnectionIdFrame extends QuicFrame {

    Version quicVersion;
    int sequenceNr;
    int retirePriorTo;
    Uint8List connectionId;
    static Random random = new Random();
    Uint8List statelessResetToken;

    NewConnectionIdFrame(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    NewConnectionIdFrame(Version quicVersion, int sequenceNr, int retirePriorTo, Uint8List newSourceConnectionId) {
        this.quicVersion = quicVersion;
        this.sequenceNr = sequenceNr;
        this.retirePriorTo = retirePriorTo;
        connectionId = newSourceConnectionId;
        statelessResetToken = new byte[128 / 8];
        random.nextBytes(statelessResetToken);
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(sequenceNr)
                + VariableLengthInteger.bytesNeeded(retirePriorTo)
                + 1 + connectionId.length + 16;
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x18);
        VariableLengthInteger.encode(sequenceNr, buffer);
        VariableLengthInteger.encode(retirePriorTo, buffer);
        buffer.put((byte) connectionId.length);
        buffer.put(connectionId);
        buffer.put(statelessResetToken);
    }

    NewConnectionIdFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        buffer.get();

        sequenceNr = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support sequence number larger than max int.
        retirePriorTo = parseVariableLengthIntegerLimitedToInt(buffer);
        int connectionIdLength = buffer.get();
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
        // "Values less than 1 and greater than 20 are invalid and MUST be treated as a connection error of type FRAME_ENCODING_ERROR."
        if (connectionIdLength < 1 || connectionIdLength > 20) {
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR, "invalid connection id length");
        }
        connectionId = new byte[connectionIdLength];
        buffer.get(connectionId);

        statelessResetToken = new byte[128 / 8];
        buffer.get(statelessResetToken);

        return this;
    }

    @Override
    String toString() {
        return "NewConnectionIdFrame[" + sequenceNr + ",<" + retirePriorTo + "|" + Bytes.bytesToHex(connectionId) + "|" + Bytes.bytesToHex(statelessResetToken) + "]";
    }

    int getSequenceNr() {
        return sequenceNr;
    }

    Uint8List getConnectionId() {
        return connectionId;
    }

    int getRetirePriorTo() {
        return retirePriorTo;
    }

    Uint8List getStatelessResetToken() {
        return statelessResetToken;
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
