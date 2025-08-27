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
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.PacketMetaData;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;

/**
 * Represents a new token frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-new_token-frames
 */
class NewTokenFrame extends QuicFrame {

    Uint8List newToken;

    NewTokenFrame() {
    }

    NewTokenFrame(Uint8List token) {
        newToken = token;
    }

    NewTokenFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, IntegerTooLargeException {
        buffer.get();

        int tokenLength = VariableLengthInteger.parseInt(buffer);
        newToken = new byte[tokenLength];
        buffer.get(newToken);

        log.debug("Got New Token: ", newToken);

        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(newToken.length) + newToken.length;
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x07);
        VariableLengthInteger.encode(newToken.length, buffer);
        buffer.put(newToken);
    }

    @Override
    String toString() {
        return "NewTokenFrame[" + Bytes.bytesToHex(newToken) + "]";
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }

    Uint8List getToken() {
        return newToken;
    }
}
