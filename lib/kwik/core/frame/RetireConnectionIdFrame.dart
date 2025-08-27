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

import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;

/**
 * Represents a retire connection id frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-retire_connection_id-frames
 */
class RetireConnectionIdFrame extends QuicFrame {

    int sequenceNr;

    RetireConnectionIdFrame(Version quicVersion) {
    }

    RetireConnectionIdFrame(Version quicVersion, int sequenceNumber) {
        this.sequenceNr = sequenceNumber;
    }

    RetireConnectionIdFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        buffer.get();
        sequenceNr = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support sequence numbers larger than max int.
        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(sequenceNr);
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x19);
        VariableLengthInteger.encode(sequenceNr, buffer);
    }

    @Override
    String toString() {
        return "RetireConnectionIdFrame[" + sequenceNr + "]";
    }

    @Override
     bool equals(Object obj) {
        return (obj instanceof RetireConnectionIdFrame) &&
                ((RetireConnectionIdFrame) obj).sequenceNr == this.sequenceNr;
    }

    @Override
    int hashCode() {
        return Integer.hashCode(sequenceNr);
    }

    int getSequenceNr() {
        return sequenceNr;
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
