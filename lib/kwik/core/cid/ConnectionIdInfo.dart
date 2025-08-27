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
package tech.kwik.core.cid;


class ConnectionIdInfo {

    final int sequenceNumber;
    final Uint8List connectionId;
    ConnectionIdStatus connectionIdStatus;
    final Uint8List statelessResetToken;


    ConnectionIdInfo(int sequenceNumber, Uint8List connectionId, ConnectionIdStatus status) {
        this.sequenceNumber = sequenceNumber;
        this.connectionId = connectionId;
        connectionIdStatus = status;
        this.statelessResetToken = null;
    }

    ConnectionIdInfo(int sequenceNumber, Uint8List connectionId, ConnectionIdStatus status, Uint8List statelessResetToken) {
        this.sequenceNumber = sequenceNumber;
        this.connectionId = connectionId;
        connectionIdStatus = status;
        this.statelessResetToken = statelessResetToken;
    }

    ConnectionIdInfo addStatelessResetToken(Uint8List statelessResetToken) {
        return new ConnectionIdInfo(sequenceNumber, connectionId, connectionIdStatus, statelessResetToken);
    }

    int getSequenceNumber() {
        return sequenceNumber;
    }

    Uint8List getConnectionId() {
        return connectionId;
    }

    ConnectionIdStatus getConnectionIdStatus() {
        return connectionIdStatus;
    }

    Uint8List getStatelessResetToken() {
        return statelessResetToken;
    }

    void setStatus(ConnectionIdStatus newStatus) {
        connectionIdStatus = newStatus;
    }
}

