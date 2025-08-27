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
package tech.kwik.core.stream;

import tech.kwik.core.QuicConstants;
import tech.kwik.core.QuicStream;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.locks.ReentrantLock;


class QuicStreamImpl implements QuicStream {

    final Version quicVersion;
    final int streamId;
    final Role role;
    final QuicConnectionImpl connection;
    final StreamManager streamManager;
    final Logger log;
    final StreamInputStream inputStream;
    final StreamOutputStream outputStream;
    volatile  bool outputClosed;
    volatile  bool inputClosed;
    final ReentrantLock stateLock;


    QuicStreamImpl(int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController) {
        this(Version.getDefault(), streamId, role, connection, streamManager, flowController, new NullLogger());
    }

    QuicStreamImpl(int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        this(Version.getDefault(), streamId, role, connection, streamManager, flowController, log);
    }

    QuicStreamImpl(Version quicVersion, int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log) {
        this(quicVersion, streamId, role, connection, streamManager, flowController, log, null);
    }

    QuicStreamImpl(Version quicVersion, int streamId, Role role, QuicConnectionImpl connection, StreamManager streamManager, FlowControl flowController, Logger log, Integer sendBufferSize) {
        this.quicVersion = quicVersion;
        this.streamId = streamId;
        this.role = role;
        this.connection = connection;
        this.streamManager = streamManager;
        this.log = log;

        if (isBidirectional() || isUnidirectional() && isPeerInitiated()) {
            inputStream = new StreamInputStreamImpl(this, determineInitialReceiveBufferSize());
        }
        else {
            inputStream = new NullStreamInputStream();
        }

        if (isBidirectional() || isUnidirectional() && isSelfInitiated()) {
            outputStream = createStreamOutputStream(sendBufferSize, flowController);
        }
        else {
            outputStream = new NullStreamOutputStream();
        }

        stateLock = new ReentrantLock();
    }

    long determineInitialReceiveBufferSize() {
        if (isBidirectional()) {
            return streamManager.getMaxBidirectionalStreamBufferSize();
        }
        else {
            return streamManager.getMaxUnidirectionalStreamBufferSize();
        }
    }

    @Override
    InputStream getInputStream() {
        return inputStream;
    }

    @Override
    OutputStream getOutputStream() {
        return outputStream;
    }

    /**
     * Adds data from a newly received frame to the stream.
     *
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @param frame
     * @return the increase in largest offset received; note that this is not (bound by) the length of the frame data,
     *        as there can be gaps in the received data
     */
    long addStreamData(StreamFrame frame) throws TransportError {
        assert frame.getStreamId() == streamId;
        if (isBidirectional() || isUnidirectional() && isPeerInitiated()) {
            return inputStream.addDataFrom(frame);
        }
        else {
            throw new TransportError(QuicConstants.TransportErrorCode.STREAM_STATE_ERROR);
        }
    }

    /**
     * This method is intentionally package-protected, as it should only be called by the (Stream)Packet processor.
     * @return  largest offset received so far
     */
    long getReceivedMaxOffset() {
        return inputStream.getCurrentReceiveOffset();
    }

    @Override
    int getStreamId() {
        return streamId;
    }

    @Override
     bool isUnidirectional() {
        // https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-2.1
        // "The second least significant bit (0x2) of the stream ID distinguishes
        //   between bidirectional streams (with the bit set to 0) and
        //   unidirectional streams (with the bit set to 1)."
        return (streamId & 0x0002) == 0x0002;
    }

    @Override
     bool isClientInitiatedBidirectional() {
        // "Client-initiated streams have even-numbered stream IDs (with the bit set to 0)"
        return (streamId & 0x0003) == 0x0000;
    }

    @Override
     bool isServerInitiatedBidirectional() {
        // "server-initiated streams have odd-numbered stream IDs"
        return (streamId & 0x0003) == 0x0001;
    }

     bool isSelfInitiated() {
        return role == Role.Client && (streamId & 0x0001) == 0x0000
                || role == Role.Server && (streamId & 0x0001) == 0x0001;
    }

     bool isPeerInitiated() {
        return !isSelfInitiated();
    }

    @Override
    void abortReading(long applicationProtocolErrorCode) {
        inputStream.abortReading(applicationProtocolErrorCode);
    }

    @Override
    void resetStream(long errorCode) {
        outputStream.reset(errorCode);
    }

    @Override
    String toString() {
        return "Stream " + streamId;
    }

    StreamOutputStream createStreamOutputStream(Integer sendBufferSize, FlowControl flowControl) {
        return new StreamOutputStreamImpl(this, sendBufferSize, flowControl);
    }

    /**
     * Terminates the receiving input stream (abruptly). Is called when peer sends a RESET_STREAM frame
     *
     * This method is intentionally package-protected, as it should only be called by the StreamManager class.
     *
     * @param errorCode
     * @param finalSize
     * @return the increase of the largest offset given the final size of the reset frame.
     */
    long terminateStream(long errorCode, long finalSize) throws TransportError {
        return inputStream.terminate(errorCode, finalSize);
    }

    // TODO: QuicStream should have a close method that closes both input and output stream and releases all resources and marks itself as terminated.

    /**
     * Resets the output stream so data can again be send from the start of the stream (offset 0). Note that in such
     * cases the caller must (again) provide the data to be sent.
     */
    void resetOutputStream() {
        outputStream.resetOutputStream();
    }

    void stopFlowControl() {
        outputStream.stopFlowControl();
    }

    void abort() {
        outputStream.abort();
        inputStream.abort();
    }

    void updateConnectionFlowControl(int bytesRead) {
        streamManager.updateConnectionFlowControl(bytesRead);
    }

    void outputClosed() {
        try {
            stateLock.lock();
            outputClosed = true;
            if (isBidirectional() && inputClosed || isUnidirectional()) {
                streamManager.streamClosed(streamId);
            }
        }
        finally {
            stateLock.unlock();
        }
    }

    void inputClosed() {
        try {
            stateLock.lock();
            inputClosed = true;
            if (isBidirectional() && outputClosed || isUnidirectional()) {
                streamManager.streamClosed(streamId);
            }
        }
        finally {
            stateLock.unlock();
        }
    }
}
