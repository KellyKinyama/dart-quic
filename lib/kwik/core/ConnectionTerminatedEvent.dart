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
package tech.kwik.core;

import tech.kwik.agent15.TlsConstants;

import static tech.kwik.core.QuicConstants.TransportErrorCode.NO_ERROR;

/*
 * Event that indicates that the connection is terminated.
 */
class ConnectionTerminatedEvent {

    final QuicConnection connection;
    final CloseReason closeReason;
    final  bool closedByPeer;
    final Long transportErrorCode;
    final Long applicationErrorCode;

    // https://www.rfc-editor.org/rfc/rfc9000.html#section-10
    // "An established QUIC connection can be terminated in one of three ways: idle timeout (Section 10.1),
    //  immediate close (Section 10.2), stateless reset (Section 10.3)"
    enum CloseReason {
        IdleTimeout,
        ImmediateClose,
        StatelessReset,
        ConnectionLost   // not in the RFC, but used in the implementation to indicate that the connection was lost (probes were not answered)
    }

    ConnectionTerminatedEvent(QuicConnection connection, CloseReason closeReason,  bool closedByPeer, Long transportErrorCode, Long applicationErrorCode) {
        this.connection = connection;
        this.closeReason = closeReason;
        this.closedByPeer = closedByPeer;
        this.transportErrorCode = transportErrorCode != null && transportErrorCode != NO_ERROR.value ? transportErrorCode : null;
        this.applicationErrorCode = applicationErrorCode;
    }

    ConnectionTerminatedEvent(QuicConnection connection, CloseReason closeReason,  bool closedByPeer) {
        this.connection = connection;
        this.closeReason = closeReason;
        this.closedByPeer = closedByPeer;
        this.transportErrorCode = null;
        this.applicationErrorCode = null;
    }

    QuicConnection connection() {
        return connection;
    }

    CloseReason closeReason() {
        return closeReason;
    }

     bool closedByPeer() {
        return closedByPeer;
    }

     bool hasError() {
        return hasTransportError() || hasApplicationError();
    }

    /**
     * Returns true if the connection was closed due to a transport error (not being NO_ERROR).
     * @return  true if the connection was closed due to a transport error.iterm
     */
     bool hasTransportError() {
        return transportErrorCode != null;
    }

    /**
     * Returns true if there is an application error.
     * This is the case when the local application closed the connection with an error,
     * or a CONNECTION_CLOSE frame of type 0x1d was received from the peer.
     * @return  true if there is an application error.
     */
     bool hasApplicationError() {
        return applicationErrorCode != null;
    }

    /**
     * Returns the transport error code, if there is any.
     * See https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1 for a list of transport error codes.
     * This method will never return NO_ERROR (0x00), as this is not considered an error.
     * @return  the transport error code, or null if there is no transport error.
     */
    Long transportErrorCode() {
        return transportErrorCode;
    }

    /**
     * Returns the application error code, if there is any.
     * The semantics of the error code is defined by the application protocol.
     * @return  the application error code, or null if there is no application error.
     */
    Long applicationErrorCode() {
        return applicationErrorCode;
    }

    /**
     * Returns a human-readable description of the error.
     * @return  a human-readable description of the error.
     */
    String errorDescription() {
        if (hasTransportError()) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
            // "CRYPTO_ERROR (0x0100-0x01ff): The cryptographic handshake failed. A range of 256 values is reserved for
            //  carrying error codes specific to the cryptographic handshake that is used."
            // https://www.rfc-editor.org/rfc/rfc9001.html#section-4.8
            // "A TLS alert is converted into a QUIC connection error. The AlertDescription value is added to 0x0100 to
            //  produce a QUIC error code from the range reserved for CRYPTO_ERROR"
            if (transportErrorCode >= 0x0100 && transportErrorCode <= 0x01ff) {
                return "Transport error: CRYPTO_ERROR (" + alertFromValue((int) (transportErrorCode - 0x0100)) + ")";
            }
            else {
                return "Transport error: " + QuicConstants.TransportErrorCode.fromValue(transportErrorCode);
            }
        }
        else if (hasApplicationError()) {
            return "Application error: " + applicationErrorCode;
        }
        else {
            return "No error";
        }
    }

    static TlsConstants.AlertDescription alertFromValue(int value) {
            for (TlsConstants.AlertDescription alert : TlsConstants.AlertDescription.values()) {
                if (alert.value == value) {
                    return alert;
                }
            }
            return null;
        }
}
