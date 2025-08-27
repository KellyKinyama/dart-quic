class ConnectionCloseFrame extends QuicFrame {

    long errorCode;
    long triggeringFrameType;
    Uint8List reasonPhrase = new byte[0];
    int tlsError = -1;
    int frameType;

    /**
     * Creates a connection close frame for a normal connection close without errors
     * @param quicVersion
     */
    ConnectionCloseFrame(Version quicVersion) {
        frameType = 0x1c;
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
        // "NO_ERROR (0x0):  An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed
        //  abruptly in the absence of any error."
        errorCode = 0x00;
    }

    ConnectionCloseFrame(Version quicVersion, long error, String reason) {
        frameType = 0x1c;
        errorCode = error;
        if (errorCode >= 0x0100 && errorCode < 0x0200) {
            tlsError = (int) (errorCode - 256);
        }
        if (reason != null && !reason.isBlank()) {
            reasonPhrase = reason.getBytes(StandardCharsets.UTF_8);
        }
    }

    ConnectionCloseFrame(Version quicVersion, long error,  bool quicError, String reason) {
        frameType = quicError? 0x1c: 0x1d;
        errorCode = error;
        if (errorCode >= 0x0100 && errorCode < 0x0200) {
            tlsError = (int) (errorCode - 256);
        }
        if (reason != null && !reason.isBlank()) {
            reasonPhrase = reason.getBytes(StandardCharsets.UTF_8);
        }
    }

    ConnectionCloseFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, IntegerTooLargeException {
        frameType = buffer.get() & 0xff;
        if (frameType != 0x1c && frameType != 0x1d) {
            throw new RuntimeException();  // Programming error
        }

        errorCode = VariableLengthInteger.parseLong(buffer);
        if (frameType == 0x1c) {
            triggeringFrameType = VariableLengthInteger.parseLong(buffer);
        }
        int reasonPhraseLength = VariableLengthInteger.parseInt(buffer);
        if (reasonPhraseLength > 0) {
            reasonPhrase = new byte[reasonPhraseLength];
            buffer.get(reasonPhrase);
        }

        if (frameType == 0x1c && errorCode >= 0x0100 && errorCode < 0x0200) {
            tlsError = (int) (errorCode - 256);
        }

        return this;
    }

     bool hasTransportError() {
        return frameType == 0x1c && errorCode != 0;
    }

     bool hasTlsError() {
        return tlsError != -1;
    }

    long getTlsError() {
        if (hasTlsError()) {
            return tlsError;
        }
        else {
            throw new IllegalStateException("Close does not have a TLS error");
        }
    }

    long getErrorCode() {
        return errorCode;
    }

     bool hasReasonPhrase() {
        return reasonPhrase != null;
    }

    String getReasonPhrase() {
        try {
            return new String(reasonPhrase, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // Impossible: UTF-8 is always supported.
            return null;
        }
    }

     bool hasApplicationProtocolError() {
        return frameType == 0x1d && errorCode != 0;
    }

     bool hasError() {
        return hasTransportError() || hasApplicationProtocolError();
    }

    int getFrameType() {
        return frameType;
    }

    @Override
    int getFrameLength() {
        return 1
                + VariableLengthInteger.bytesNeeded(errorCode)
                + (frameType == 0x1c? VariableLengthInteger.bytesNeeded(0): 0)
                + VariableLengthInteger.bytesNeeded(reasonPhrase.length)
                + reasonPhrase.length;
    }

    @Override
    void serialize(ByteBuffer buffer) {
        if (frameType == 0x1c) {
            buffer.put((byte) 0x1c);
            VariableLengthInteger.encode(errorCode, buffer);
            VariableLengthInteger.encode(0, buffer);  // triggering frame type
            VariableLengthInteger.encode(reasonPhrase.length, buffer);
            buffer.put(reasonPhrase);
        }
        else {  // frameType == 0x1d
            buffer.put((byte) 0x1d);
            VariableLengthInteger.encode(errorCode, buffer);
            VariableLengthInteger.encode(reasonPhrase.length, buffer);
            buffer.put(reasonPhrase);
        }
    }

    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."
    @Override
     bool isAckEliciting() {
        return false;
    }

    @Override
    String toString() {
        return "ConnectionCloseFrame["
                + (hasTlsError()? "TLS " + tlsError: errorCode) + "|"
                + triggeringFrameType + "|"
                + (reasonPhrase != null? new String(reasonPhrase): "-") + "]";
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
