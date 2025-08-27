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
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;

/**
 * Represents a max streams frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-max_streams-frames
 */
class MaxStreamsFrame extends QuicFrame {

    long maxStreams;
     bool appliesToBidirectional;

    MaxStreamsFrame(long maxStreams,  bool appliesToBidirectional) {
        this.maxStreams = maxStreams;
        this.appliesToBidirectional = appliesToBidirectional;
    }

    MaxStreamsFrame() {
    }

    MaxStreamsFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        byte frameType = buffer.get();
        if (frameType != 0x12 && frameType != 0x13) {
            throw new RuntimeException();  // Would be a programming error.
        }

        appliesToBidirectional = frameType == 0x12;
        maxStreams = VariableLengthInteger.parseLong(buffer);

        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(maxStreams);
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) (appliesToBidirectional? 0x12: 0x13));
        VariableLengthInteger.encode(maxStreams, buffer);
    }

    @Override
    String toString() {
        return "MaxStreamsFrame["
                + (appliesToBidirectional? "B": "U") + ","
                + maxStreams + "]";
    }

    long getMaxStreams() {
        return maxStreams;
    }

     bool isAppliesToBidirectional() {
        return appliesToBidirectional;
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
