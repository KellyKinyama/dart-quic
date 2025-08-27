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

import tech.kwik.core.ConnectionConfig;

class ConnectionConfigImpl implements ConnectionConfig {

    final int maxIdleTimeout;
    final int maxOpenUnidirectionalStreams;
    final long maxTotalUnidirectionalStreams;
    final int maxOpenBidirectionalStreams;
    final long maxTotalBidirectionalStreams;
    final long maxConnectionBufferSize;
    final long maxUnidirectionalStreamBufferSize;
    final long maxBidirectionalStreamBufferSize;

    static ConnectionConfig cloneWithMaxUnidirectionalStreamReceiveBufferSize(ConnectionConfig config, long maxUnidirectionalStreamBufferSize) {
        return new ConnectionConfigImpl(
                config.maxIdleTimeout(),
                config.maxOpenPeerInitiatedUnidirectionalStreams(),
                config.maxTotalPeerInitiatedUnidirectionalStreams(),
                config.maxOpenPeerInitiatedBidirectionalStreams(),
                config.maxTotalPeerInitiatedBidirectionalStreams(),
                config.maxConnectionBufferSize(),
                maxUnidirectionalStreamBufferSize,
                config.maxBidirectionalStreamBufferSize());
    }

    static ConnectionConfig cloneWithMaxBidirectionalStreamReceiveBufferSize(ConnectionConfig config, long maxBidirectionalStreamBufferSize) {
        return new ConnectionConfigImpl(
                config.maxIdleTimeout(),
                config.maxOpenPeerInitiatedUnidirectionalStreams(),
                config.maxTotalPeerInitiatedUnidirectionalStreams(),
                config.maxOpenPeerInitiatedBidirectionalStreams(),
                config.maxTotalPeerInitiatedBidirectionalStreams(),
                config.maxConnectionBufferSize(),
                config.maxUnidirectionalStreamBufferSize(),
                maxBidirectionalStreamBufferSize);
    }

    ConnectionConfigImpl(int maxIdleTimeout,
                                 int maxOpenUnidirectionalStreams, long maxTotalUnidirectionalStreams,
                                 int maxOpenBidirectionalStreams, long maxTotalBidirectionalStreams,
                                 long maxConnectionBufferSize,
                                 long maxUnidirectionalStreamBufferSize, long maxBidirectionalStreamBufferSize) {
        this.maxIdleTimeout = maxIdleTimeout;
        this.maxOpenUnidirectionalStreams = maxOpenUnidirectionalStreams;
        this.maxTotalUnidirectionalStreams = maxTotalUnidirectionalStreams;
        this.maxOpenBidirectionalStreams = maxOpenBidirectionalStreams;
        this.maxTotalBidirectionalStreams = maxTotalBidirectionalStreams;
        this.maxConnectionBufferSize = maxConnectionBufferSize;
        this.maxUnidirectionalStreamBufferSize = maxUnidirectionalStreamBufferSize;
        this.maxBidirectionalStreamBufferSize = maxBidirectionalStreamBufferSize;
    }

    @Override
    int maxIdleTimeout() {
        return maxIdleTimeout;
    }

    @Override
    int maxOpenPeerInitiatedUnidirectionalStreams() {
        return maxOpenUnidirectionalStreams;
    }

    @Override
    long maxTotalPeerInitiatedUnidirectionalStreams() {
        return maxTotalUnidirectionalStreams;
    }

    @Override
    int maxOpenPeerInitiatedBidirectionalStreams() {
        return maxOpenBidirectionalStreams;
    }

    @Override
    long maxTotalPeerInitiatedBidirectionalStreams() {
        return maxTotalBidirectionalStreams;
    }

    @Override
    long maxConnectionBufferSize() {
        return maxConnectionBufferSize;
    }

    @Override
    long maxUnidirectionalStreamBufferSize() {
        return maxUnidirectionalStreamBufferSize;
    }

    @Override
    long maxBidirectionalStreamBufferSize() {
        return maxBidirectionalStreamBufferSize;
    }

    @Override
     bool useStrictSmallestAllowedMaximumDatagramSize() {
        return false;
    }
}
