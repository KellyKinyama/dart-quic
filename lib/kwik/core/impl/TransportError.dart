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
package tech.kwik.core.impl;

import tech.kwik.core.QuicConstants;

// https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
class TransportError extends Exception {

    final QuicConstants.TransportErrorCode transportErrorCode;

    TransportError(QuicConstants.TransportErrorCode transportErrorCode) {
        super(transportErrorCode.toString());
        this.transportErrorCode = transportErrorCode;
    }

    TransportError(QuicConstants.TransportErrorCode transportErrorCode, String message) {
        super(transportErrorCode + ": " + message);
        this.transportErrorCode = transportErrorCode;
    }

    /**
     * deprecated, use getErrorCode()
     * @return  the code of the transport error that caused this error
     */
    QuicConstants.TransportErrorCode getTransportErrorCode() {
        return transportErrorCode;
    }

    /**
     * @return  the code of the transport error that caused this error
     */
    QuicConstants.TransportErrorCode getErrorCode() {
        return transportErrorCode;
    }

}
