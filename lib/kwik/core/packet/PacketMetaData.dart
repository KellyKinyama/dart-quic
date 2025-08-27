/*
 * Copyright © 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.packet;

import java.net.InetSocketAddress;
import java.time.Instant;

class PacketMetaData {

    final Instant timeReceived;
    final InetSocketAddress sourceAddress;
    final int datagramNumber;
    final  bool moreDataInDatagram;

    PacketMetaData(Instant timeReceived, InetSocketAddress sourceAddress, int datagramNumber) {
        this.timeReceived = timeReceived;
        this.sourceAddress = sourceAddress;
        this.datagramNumber = datagramNumber;
        moreDataInDatagram = false;
    }

    PacketMetaData(PacketMetaData original,  bool moreDataInDatagram) {
        this.timeReceived = original.timeReceived;
        this.sourceAddress = original.sourceAddress;
        this.datagramNumber = original.datagramNumber;
        this.moreDataInDatagram = moreDataInDatagram;
    }

    Instant timeReceived() {
        return timeReceived;
    }

     bool moreDataInDatagram() {
        return moreDataInDatagram;
    }

    InetSocketAddress sourceAddress() {
        return sourceAddress;
    }

    int datagramNumber() {
        return datagramNumber;
    }
}
