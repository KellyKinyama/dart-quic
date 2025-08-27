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

import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;

/**
 * Represents a path challenge frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-path_challenge-frames
 */
class PathChallengeFrame extends QuicFrame {

    Uint8List data;

    PathChallengeFrame(Version quicVersion, Uint8List data) {
        if (data.length != 8) {
            throw new IllegalArgumentException();
        }
        this.data = data;
    }

    PathChallengeFrame(Version quicVersion) {
    }

    PathChallengeFrame parse(ByteBuffer buffer, Logger log) {
        byte frameType = buffer.get();
        if (frameType != 0x1a) {
            throw new RuntimeException();  // Would be a programming error.
        }

        data = new byte[8];
        buffer.get(data);
        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + 8;
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x1a);
        buffer.put(data);
    }

    Uint8List getData() {
        return data;
    }

    @Override
    String toString() {
        return "PathChallengeFrame[" + Bytes.bytesToHex(data) + "]";
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}

