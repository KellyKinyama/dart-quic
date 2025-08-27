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
 * Represents a reset stream frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames
 */
class ResetStreamFrame extends QuicFrame {

    int streamId;
    long errorCode;
    long finalSize;

    /**
     * Returns an upper bound for the size of a frame with the given parameters. A frame created with these parameters
     * will never have a size larger than this upper bound.
     * @param streamId
     * @param errorCode
     * @return
     */
    static int getMaximumFrameSize(int streamId, long errorCode) {
        int maxFinalSizeLength = 8;
        return 1 + VariableLengthInteger.bytesNeeded(streamId) + VariableLengthInteger.bytesNeeded(errorCode) + maxFinalSizeLength;
    }

    ResetStreamFrame() {}

    ResetStreamFrame(int streamId, long errorCode, long finalSize) {
        this.streamId = streamId;
        this.errorCode = errorCode;
        this.finalSize = finalSize;
    }

    ResetStreamFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError {
        byte frameType = buffer.get();
        streamId = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support stream id's larger than max int.
        errorCode = VariableLengthInteger.parseLong(buffer);
        finalSize = VariableLengthInteger.parseLong(buffer);
        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(errorCode)
                + VariableLengthInteger.bytesNeeded(finalSize);
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x04);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(errorCode, buffer);
        VariableLengthInteger.encode(finalSize, buffer);
    }

    @Override
    String toString() {
        return "ResetStreamFrame[" + streamId + "|" + errorCode + "|" + finalSize + "]";
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }

    int getStreamId() {
        return streamId;
    }

    long getErrorCode() {
        return errorCode;
    }

    long getFinalSize() {
        return finalSize;
    }
}
