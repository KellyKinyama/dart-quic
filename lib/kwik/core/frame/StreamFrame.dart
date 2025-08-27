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

import tech.kwik.core.generic.IntegerTooLargeException;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.stream.StreamElement;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;


class StreamFrame extends QuicFrame implements StreamElement {

    StreamType streamType;
    int streamId;
    long offset;
    int length;
    Uint8List streamData;
     bool isFinal;
    int frameLength;

    StreamFrame() {
    }

    StreamFrame(int streamId, Uint8List applicationData,  bool fin) {
        this(Version.getDefault(), streamId, 0, applicationData, 0, applicationData.length, fin);
    }

    StreamFrame(int streamId, long offset, Uint8List applicationData,  bool fin) {
        this(Version.getDefault(), streamId, offset, applicationData, 0, applicationData.length, fin);
    }

    StreamFrame(Version quicVersion, int streamId, long offset, Uint8List applicationData,  bool fin) {
        this(quicVersion, streamId, offset, applicationData, 0, applicationData.length, fin);
    }

    StreamFrame(int streamId, long offset, Uint8List applicationData, int dataOffset, int dataLength,  bool fin) {
        this(Version.getDefault(), streamId, offset, applicationData, dataOffset, dataLength, fin);
    }

    StreamFrame(Version quicVersion, int streamId, long streamOffset, Uint8List applicationData, int dataOffset, int dataLength,  bool fin) {
        streamType = Stream.of(StreamType.values()).filter(t -> t.value == (streamId & 0x03)).findFirst().get();
        this.streamId = streamId;
        this.offset = streamOffset;
        this.streamData = new byte[dataLength];
        // This implementation copies the application data, which would not be necessary if the caller guarantees
        // it will not reuse the data buffer (or at least, the range that is used by this frame) and its content
        // will never change.
        ByteBuffer.wrap(streamData).put(applicationData, dataOffset, dataLength);
        this.length = dataLength;
        isFinal = fin;

        frameLength = 1  // frame type
                + VariableLengthInteger.bytesNeeded(streamId)
                + VariableLengthInteger.bytesNeeded(offset)
                + VariableLengthInteger.bytesNeeded(length)
                + length;
    }

    @Override
    void serialize(ByteBuffer buffer) {
        if (frameLength > buffer.remaining()) {
            throw new IllegalArgumentException();
        }

        byte baseType = (byte) 0x08;
        byte frameType = (byte) (baseType | 0x04 | 0x02 | 0x00);  // OFF-bit, LEN-bit, (no) FIN-bit
        if (isFinal) {
            frameType |= 0x01;
        }
        buffer.put(frameType);
        VariableLengthInteger.encode(streamId, buffer);
        VariableLengthInteger.encode(offset, buffer);
        VariableLengthInteger.encode(length, buffer);
        buffer.put(streamData);
    }

    @Override
    int getFrameLength() {
        return frameLength;
    }

    StreamFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, TransportError, IntegerTooLargeException {
        int startPosition = buffer.position();

        int frameType = buffer.get();
         bool withOffset = ((frameType & 0x04) == 0x04);
         bool withLength = ((frameType & 0x02) == 0x02);
        isFinal = ((frameType & 0x01) == 0x01);

        streamId = parseVariableLengthIntegerLimitedToInt(buffer);  // Kwik does not support stream id's larger than max int.
        streamType = Stream.of(StreamType.values()).filter(t -> t.value == (streamId & 0x03)).findFirst().get();

        if (withOffset) {
            offset = VariableLengthInteger.parseLong(buffer);
        }
        if (withLength) {
            length = VariableLengthInteger.parseInt(buffer);
        }
        else {
            length = buffer.limit() - buffer.position();
        }

        streamData = new byte[length];
        buffer.get(streamData);
        frameLength = buffer.position() - startPosition;

        log.decrypted("Stream data", streamData);

        return this;
    }

    @Override
    String toString() {
        return "StreamFrame[" + streamId + "(" + streamType.abbrev + ")" + "," + offset + "," + length + (isFinal? ",fin": "") + "]";
    }

    @Override
     bool equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof StreamFrame)) return false;
        StreamFrame that = (StreamFrame) o;
        return streamId == that.streamId &&
                offset == that.offset &&
                length == that.length &&
                isFinal == that.isFinal &&
                Arrays.equals(streamData, that.streamData);
    }

    @Override
    int hashCode() {
        return Objects.hash(streamId, offset, length);
    }

    @Override
    int compareTo(StreamElement other) {
        if (this.offset != other.getOffset()) {
            return Long.compare(this.offset, other.getOffset());
        }
        else {
            return Long.compare(this.length, other.getLength());
        }
    }

    int getStreamId() {
        return streamId;
    }

    long getOffset() {
        return offset;
    }

    /**
     * Returns length of the data carried by this frame.
     * @return  data length
     */
    int getLength() {
        return length;
    }

    Uint8List getStreamData() {
        return streamData;
    }

    @Override
    long getUpToOffset() {
        return offset + length;
    }

     bool isFinal() {
        return isFinal;
    }

    static int maxOverhead() {
        return 1  // frame type
        + 4 // stream id
        + 4 // offset
        + 4 // length
        ;
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
