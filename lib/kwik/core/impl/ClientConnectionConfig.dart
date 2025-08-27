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
package tech.kwik.core.impl;

import tech.kwik.core.ConnectionConfig;

class ClientConnectionConfig implements ConnectionConfig {

    int maxIdleTimeout;
    int maxOpenUnidirectionalStreams;
    int maxOpenBidirectionalStreams;
    long maxConnectionBufferSize;
    long maxUnidirectionalStreamBufferSize;
    long maxBidirectionalStreamBufferSize;
    int activeConnectionIdLimit;
    int maxUdpPayloadSize;
     bool useStrictSmallestAllowedMaximumDatagramSize;
     bool enforceMaxUdpPayloadSize;

    @Override
    int maxIdleTimeout() {
        return maxIdleTimeout;
    }

    void setMaxIdleTimeout(int maxIdleTimeout) {
        this.maxIdleTimeout = maxIdleTimeout;
    }

    @Override
    int maxOpenPeerInitiatedUnidirectionalStreams() {
        return maxOpenUnidirectionalStreams;
    }

    void setMaxOpenPeerInitiatedUnidirectionalStreams(int maxOpenUnidirectionalStreams) {
        this.maxOpenUnidirectionalStreams = maxOpenUnidirectionalStreams;
    }

    @Override
    long maxTotalPeerInitiatedUnidirectionalStreams() {
        return Long.MAX_VALUE;
    }

    @Override
    int maxOpenPeerInitiatedBidirectionalStreams() {
        return maxOpenBidirectionalStreams;
    }

    void setMaxOpenPeerInitiatedBidirectionalStreams(int maxOpenBidirectionalStreams) {
        this.maxOpenBidirectionalStreams = maxOpenBidirectionalStreams;
    }

    @Override
    long maxTotalPeerInitiatedBidirectionalStreams() {
        return Long.MAX_VALUE;
    }

    @Override
    long maxConnectionBufferSize() {
        return maxConnectionBufferSize;
    }

    void setMaxConnectionBufferSize(long maxConnectionBufferSize) {
        this.maxConnectionBufferSize = maxConnectionBufferSize;
    }

    @Override
    long maxUnidirectionalStreamBufferSize() {
        return maxUnidirectionalStreamBufferSize;
    }

    void setMaxUnidirectionalStreamBufferSize(long maxUnidirectionalStreamBufferSize) {
        this.maxUnidirectionalStreamBufferSize = maxUnidirectionalStreamBufferSize;
    }

    @Override
    long maxBidirectionalStreamBufferSize() {
        return maxBidirectionalStreamBufferSize;
    }

    void setMaxBidirectionalStreamBufferSize(long maxBidirectionalStreamBufferSize) {
        this.maxBidirectionalStreamBufferSize = maxBidirectionalStreamBufferSize;
    }

    int getActiveConnectionIdLimit() {
        return activeConnectionIdLimit;
    }

    void setActiveConnectionIdLimit(int limit) {
        activeConnectionIdLimit = limit;
    }

    int getMaxUdpPayloadSize() {
        return maxUdpPayloadSize;
    }

    void setMaxUdpPayloadSize(int maxSize) {
        maxUdpPayloadSize = maxSize;
    }

    void setUseStrictSmallestAllowedMaximumDatagramSize( bool value) {
        this.useStrictSmallestAllowedMaximumDatagramSize = value;
    }

    @Override
     bool useStrictSmallestAllowedMaximumDatagramSize() {
        return useStrictSmallestAllowedMaximumDatagramSize;
    }

     bool getEnforceMaxUdpPayloadSize() {
        return enforceMaxUdpPayloadSize;
    }

    void setEnforceMaxUdpPayloadSize( bool enforceMaxUdpPayloadSize) {
        this.enforceMaxUdpPayloadSize = enforceMaxUdpPayloadSize;
    }
}
