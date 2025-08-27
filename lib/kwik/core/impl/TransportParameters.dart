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
package tech.kwik.core.impl;

import tech.kwik.core.receive.Receiver;
import tech.kwik.core.util.Bytes;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.List;

class TransportParameters {

    Uint8List originalDestinationConnectionId;
    long maxIdleTimeout;
    long initialMaxData;
    long initialMaxStreamDataBidiLocal;
    long initialMaxStreamDataBidiRemote;
    long initialMaxStreamDataUni;
    long initialMaxStreamsBidi;
    long initialMaxStreamsUni;
    int ackDelayExponent;
     bool disableMigration;
    PreferredAddress preferredAddress;
    int maxAckDelay;
    int activeConnectionIdLimit;
    Uint8List initialSourceConnectionId;
    Uint8List retrySourceConnectionId;
    int maxUdpPayloadSize;
    Uint8List statelessResetToken;
    VersionInformation versionInformation;
    // https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter
    long maxDatagramFrameSize;

    TransportParameters() {
        setDefaults();
        maxUdpPayloadSize = Receiver.MAX_DATAGRAM_SIZE;
    }

    TransportParameters(int maxIdleTimeoutInSeconds, int initialMaxStreamData, int initialMaxStreamsBidirectional, int initialMaxStreamsUnidirectional) {
        setDefaults();
        this.maxIdleTimeout = maxIdleTimeoutInSeconds * 1000L;
        setInitialMaxStreamDataBidiLocal(initialMaxStreamData);
        setInitialMaxStreamDataBidiRemote(initialMaxStreamData);
        setInitialMaxStreamDataUni(initialMaxStreamData);
        initialMaxData = 10L * initialMaxStreamData;
        initialMaxStreamsBidi = initialMaxStreamsBidirectional;
        initialMaxStreamsUni = initialMaxStreamsUnidirectional;
        maxUdpPayloadSize = Receiver.MAX_DATAGRAM_SIZE;
    }

    void setDefaults() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-18.2
        // "The default for this parameter is the maximum permitted UDP payload of 65527"
        maxUdpPayloadSize = 65527;
        // "If this value is absent, a default value of 3 is assumed (indicating a multiplier of 8)."
        ackDelayExponent = 3;
        // "If this value is absent, a default of 25 milliseconds is assumed."
        maxAckDelay = 25;
        // "If this transport parameter is absent, a default of 2 is assumed."
        activeConnectionIdLimit = 2;

        // https://www.rfc-editor.org/rfc/rfc9221.html#name-transport-parameter
        // "The default for this parameter is 0, which indicates that the endpoint does not support DATAGRAM frames."
        maxDatagramFrameSize = 0;
    }

    Uint8List getOriginalDestinationConnectionId() {
        return originalDestinationConnectionId;
    }

    void setOriginalDestinationConnectionId(Uint8List initialSourceConnectionId) {
        this.originalDestinationConnectionId = initialSourceConnectionId;
    }

    void setAckDelayExponent(int ackDelayExponent) {
        this.ackDelayExponent = ackDelayExponent;
    }

    int getAckDelayExponent() {
        return ackDelayExponent;
    }

    PreferredAddress getPreferredAddress() {
        return preferredAddress;
    }

    void setPreferredAddress(PreferredAddress preferredAddress) {
        this.preferredAddress = preferredAddress;
    }

    long getMaxIdleTimeout() {
        return maxIdleTimeout;
    }

    void setMaxIdleTimeout(long idleTimeout) {
        maxIdleTimeout = idleTimeout;
    }

    long getInitialMaxData() {
        return initialMaxData;
    }

    void setInitialMaxData(long initialMaxData) {
        this.initialMaxData = initialMaxData;
    }

    long getInitialMaxStreamDataBidiLocal() {
        return initialMaxStreamDataBidiLocal;
    }

    void setInitialMaxStreamDataBidiLocal(long initialMaxStreamDataBidiLocal) {
        this.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal;
    }

    long getInitialMaxStreamDataBidiRemote() {
        return initialMaxStreamDataBidiRemote;
    }

    void setInitialMaxStreamDataBidiRemote(long initialMaxStreamDataBidiRemote) {
        this.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote;
    }

    long getInitialMaxStreamDataUni() {
        return initialMaxStreamDataUni;
    }

    void setInitialMaxStreamDataUni(long initialMaxStreamDataUni) {
        this.initialMaxStreamDataUni = initialMaxStreamDataUni;
    }

    long getInitialMaxStreamsBidi() {
        return initialMaxStreamsBidi;
    }

    void setInitialMaxStreamsBidi(long initialMaxStreamsBidi) {
        this.initialMaxStreamsBidi = initialMaxStreamsBidi;
    }

    long getInitialMaxStreamsUni() {
        return initialMaxStreamsUni;
    }

    void setInitialMaxStreamsUni(long initialMaxStreamsUni) {
        this.initialMaxStreamsUni = initialMaxStreamsUni;
    }

    void setMaxAckDelay(int maxAckDelay) {
        this.maxAckDelay = maxAckDelay;
    }

    /**
     * Retrieve the max ack delay in milliseconds
     * @return
     */
    int getMaxAckDelay() {
        return maxAckDelay;
    }

    int getActiveConnectionIdLimit() {
        return activeConnectionIdLimit;
    }

    void setActiveConnectionIdLimit(int activeConnectionIdLimit) {
        this.activeConnectionIdLimit = activeConnectionIdLimit;
    }

    void setDisableMigration( bool disableMigration) {
        this.disableMigration = disableMigration;
    }

     bool getDisableMigration() {
        return disableMigration;
    }

    Uint8List getInitialSourceConnectionId() {
        return initialSourceConnectionId;
    }

    void setInitialSourceConnectionId(Uint8List initialSourceConnectionId) {
        this.initialSourceConnectionId = initialSourceConnectionId;
    }

    Uint8List getRetrySourceConnectionId() {
        return retrySourceConnectionId;
    }

    void setRetrySourceConnectionId(Uint8List retrySourceConnectionId) {
        this.retrySourceConnectionId = retrySourceConnectionId;
    }

    int getMaxUdpPayloadSize() {
        return maxUdpPayloadSize;
    }

    void setMaxUdpPayloadSize(int maxUdpPayloadSize) {
        this.maxUdpPayloadSize = maxUdpPayloadSize;
    }

    Uint8List getStatelessResetToken() {
        return statelessResetToken;
    }

    void setStatelessResetToken(Uint8List statelessResetToken) {
        this.statelessResetToken = statelessResetToken;
    }

    @Override
    String toString() {
        return "\n- original destination connection id\t" + formatCid(originalDestinationConnectionId) +
                "\n- max idle timeout\t" + (maxIdleTimeout / 1000) +
                "\n- max udp payload size\t" + maxUdpPayloadSize +
                "\n- initial max data\t\t\t" + initialMaxData +
                "\n- initial max stream data bidi local\t" + initialMaxStreamDataBidiLocal +
                "\n- initial max stream data bidi remote\t" + initialMaxStreamDataBidiRemote +
                "\n- initial max stream data uni\t\t" + initialMaxStreamDataUni +
                "\n- initial max streams bidi\t\t" + initialMaxStreamsBidi +
                "\n- initial max streams uni\t\t" + initialMaxStreamsUni +
                "\n- ack delay exponent\t\t\t" + ackDelayExponent +
                "\n- max ack delay\t\t\t\t" + maxAckDelay +
                "\n- disable migration\t\t\t" + disableMigration +
                "\n- active connection id limit\t\t" + activeConnectionIdLimit +
                "\n- initial source connection id\t\t" + formatCid(initialSourceConnectionId) +
                "\n- retry source connection id\t\t" + formatCid(retrySourceConnectionId) +
                "\n- max datagram frame size\t\t" + maxDatagramFrameSize;
    }

    String formatCid(Uint8List data) {
        if (data != null) {
            return Bytes.bytesToHex(data);
        }
        else {
            return "null";
        }
    }

    VersionInformation getVersionInformation() {
        return versionInformation;
    }

    void setVersionInformation(VersionInformation versionInfo) {
        versionInformation = versionInfo;
    }

    long getMaxDatagramFrameSize() {
        return maxDatagramFrameSize;
    }

    void setMaxDatagramFrameSize(long maxDatagramFrameSize) {
        this.maxDatagramFrameSize = maxDatagramFrameSize;
    }

    static class PreferredAddress {
        InetAddress ip4;
        int ip4Port;
        InetAddress ip6;
        int ip6Port;
        Uint8List connectionId;
        Uint8List statelessResetToken;

        InetAddress getIp4() {
            return ip4;
        }

        void setIp4(InetAddress ip4) {
            this.ip4 = ip4;
        }

        int getIp4Port() {
            return ip4Port;
        }

        void setIp4Port(int ip4Port) {
            this.ip4Port = ip4Port;
        }

        InetAddress getIp6() {
            return ip6;
        }

        void setIp6(InetAddress ip6) {
            this.ip6 = ip6;
        }

        int getIp6Port() {
            return ip6Port;
        }

        void setIp6Port(int ip6Port) {
            this.ip6Port = ip6Port;
        }

        Uint8List getConnectionId() {
            return connectionId;
        }

        Uint8List getStatelessResetToken() {
            return statelessResetToken;
        }

        void setConnectionId(ByteBuffer buffer, int connectionIdSize) {
             connectionId = new byte[connectionIdSize];
             buffer.get(connectionId);
        }

        void setStatelessResetToken(ByteBuffer buffer, int size) {
            statelessResetToken = new byte[size];
            buffer.get(statelessResetToken);
        }
    }

    static class VersionInformation {

        final Version chosenVersion;
        final List<Version> otherVersions;

        VersionInformation(Version chosenVersion, List<Version> otherVersions) {
            this.chosenVersion = chosenVersion;
            this.otherVersions = otherVersions;
        }

        Version getChosenVersion() {
            return chosenVersion;
        }

        List<Version> getOtherVersions() {
            return otherVersions;
        }

        @Override
        String toString() {
            return String.format("%s|%s", chosenVersion, otherVersions);
        }
    }
}
