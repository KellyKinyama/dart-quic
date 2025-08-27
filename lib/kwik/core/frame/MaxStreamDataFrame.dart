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
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;

import java.nio.ByteBuffer;

/**
 * Represents a max stream data frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames
 */
class MaxStreamDataFrame extends QuicFrame {

    int streamId;
    long maxData;


    MaxStreamDataFrame() {
    }

    MaxStreamDataFrame(int stream, long maxData) {
        this.streamId = stream;
        this.maxData = maxData;
    }

    MaxStreamDataFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        buffer.get();

        streamId = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support stream id's larger than max int.
        maxData = VariableLengthInteger.parseLong(buffer);

        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamId) + VariableLengthInteger.bytesNeeded(maxData);
    }

    @Override
    void serialize(ByteBuffer buffer) {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames
        // "The MAX_STREAM_DATA frame (type=0x11)..."
        buffer.put((byte) 0x11);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(maxData, buffer);
    }

    @Override
    String toString() {
        return "MaxStreamDataFrame[" + streamId + ":" + maxData + "]";
    }

    int getStreamId() {
        return streamId;
    }

    long getMaxData() {
        return maxData;
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
