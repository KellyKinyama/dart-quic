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
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;


/**
 * Represents a streams blocked frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames
 */
class StreamsBlockedFrame extends QuicFrame {

     bool bidirectional;
    long streamLimit;

    StreamsBlockedFrame() {
    }

    StreamsBlockedFrame(Version quicVersion,  bool bidirectional, int streamLimit) {
        this.bidirectional = bidirectional;
        this.streamLimit = streamLimit;
    }

    StreamsBlockedFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        byte frameType = buffer.get();
        bidirectional = frameType == 0x16;
        streamLimit = VariableLengthInteger.parseLong(buffer);

        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamLimit);
    }

    @Override
    void serialize(ByteBuffer buffer) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-streams_blocked-frames
        // "A STREAMS_BLOCKED frame of type 0x16 is used to indicate reaching the bidirectional stream limit, and a
        // STREAMS_BLOCKED frame of type 0x17 is used to indicate reaching the unidirectional stream limit."
        buffer.put(bidirectional? (byte) 0x16: (byte) 0x17);
        VariableLengthInteger.encode(streamLimit, buffer);
    }

    @Override
    String toString() {
        return "StreamsBlockedFrame[" + (bidirectional? "B": "U") + "|" + streamLimit + "]";
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }

     bool isBidirectional() {
        return bidirectional;
    }

    long getStreamLimit() {
        return streamLimit;
    }
}
