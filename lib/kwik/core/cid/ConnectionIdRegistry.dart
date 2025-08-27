/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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

import tech.kwik.core.log.Logger;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


abstract class ConnectionIdRegistry {

    static final int DEFAULT_CID_LENGTH = 8;

    /** Maps sequence number to connection ID (info) */
    final Map<Integer, ConnectionIdInfo> connectionIds = new ConcurrentHashMap<>();
    volatile Uint8List currentConnectionId;
    final Logger log;
    final SecureRandom randomGenerator;
    final int connectionIdLength;

    ConnectionIdRegistry(Logger log) {
        this(DEFAULT_CID_LENGTH, log);
    }

    ConnectionIdRegistry(Integer cidLength, Logger logger) {
        connectionIdLength = cidLength != null? cidLength: DEFAULT_CID_LENGTH;
        this.log = logger;

        randomGenerator = new SecureRandom();

        currentConnectionId = generateConnectionId();
        connectionIds.put(0, new ConnectionIdInfo(0, currentConnectionId, ConnectionIdStatus.IN_USE));
    }

    Uint8List retireConnectionId(int sequenceNr) {
        if (connectionIds.containsKey(sequenceNr)) {
            ConnectionIdInfo cidInfo = connectionIds.get(sequenceNr);
            if (cidInfo.getConnectionIdStatus().active()) {
                cidInfo.setStatus(ConnectionIdStatus.RETIRED);
                return cidInfo.getConnectionId();
            }
            else {
                return null;
            }
        }
        else {
            return null;
        }
    }

    /**
     * @deprecated  use getActive to get <em>an</em> active connection ID
     */
    @Deprecated
    Uint8List getCurrent() {
        return currentConnectionId;
    }

    /**
     * Get an active connection ID. There can be multiple active connection IDs, this method returns an arbitrary one.
     * @return  an active connection ID or null if non is active (which should never happen).
     */
    Uint8List getActive() {
        return connectionIds.entrySet().stream()
                .filter(e -> e.getValue().getConnectionIdStatus().active())
                .map(e -> e.getValue().getConnectionId())
                .findFirst().orElse(null);
    }

    Map<Integer, ConnectionIdInfo> getAll() {
        return connectionIds;
    }

    int currentIndex() {
        return connectionIds.entrySet().stream()
                .filter(entry -> Arrays.equals(entry.getValue().getConnectionId(), currentConnectionId))
                .mapToInt(entry -> entry.getKey())
                .findFirst().orElseThrow();
    }

    Uint8List generateConnectionId() {
        Uint8List connectionId = new byte[connectionIdLength];
        randomGenerator.nextBytes(connectionId);
        return connectionId;
    }

    int getConnectionIdlength() {
        return connectionIdLength;
    }

    List<Uint8List> getActiveConnectionIds() {
        return connectionIds.values().stream()
                .filter(cid -> cid.getConnectionIdStatus().active())
                .map(info -> info.getConnectionId())
                .collect(Collectors.toList());
    }
}

