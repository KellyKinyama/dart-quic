/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.stream;

import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.TransportError;

import java.io.IOException;

class NullStreamInputStream extends StreamInputStream {

    @Override
    long addDataFrom(StreamFrame frame) throws TransportError {
        return 0;
    }

    @Override
    long getCurrentReceiveOffset() {
        return 0;
    }

    @Override
    void abortReading(long applicationProtocolErrorCode) {
    }

    @Override
    long terminate(long errorCode, long finalSize) throws TransportError {
        return 0;
    }

    @Override
    void abort() {
    }

    @Override
    int read() throws IOException {
        return -1;
    }
}
