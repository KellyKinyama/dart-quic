import '../buffer.dart';
import '../packet/quic_packet.dart';

abstract class QuicFrame {

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-terms-and-definitions
    // https://tools.ietf.org/html/draft-ietf-quic-recovery-33#section-2
    // "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting."

    /**
     * Returns whether the frame is ack eliciting
     * https://www.rfc-editor.org/rfc/rfc9000.html#name-terms-and-definitions
     * "Ack-eliciting packet: A QUIC packet that contains frames other than ACK, PADDING, and CONNECTION_CLOSE."
     * @return  true when the frame is ack-eliciting
     */
    bool isAckEliciting() {
        return true;
    }

    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData);

    /**
     * Returns the length of the frame (in bytes) if it were to be serialized by the serialize method.
     * @return
     */
    int getFrameLength();

    void serialize(Buffer buffer);

    /**
     * Parse a variable length integer from the buffer for which Kwik does not support a value larger than max int.
     * If the value is larger than Integer.MAX_VALUE, a TransportError of type INTERNAL_ERROR is thrown.
     * If the value itself is not correctly encoded, an InvalidIntegerEncodingException is thrown.
     * @param buffer
     * @return
     * @throws InvalidIntegerEncodingException
     * @throws TransportError
     */
    int parseVariableLengthIntegerLimitedToInt(ByteBuffer buffer) 
    // throws InvalidIntegerEncodingException, TransportError 
    {
        try {
            return VariableLengthInteger.parseInt(buffer);
        }
        catch (IntegerTooLargeException e) {
            // This is not an invalid integer encoding, but a value that is too large for the implementation.
            throw new TransportError(QuicConstants.TransportErrorCode.INTERNAL_ERROR, "value too large");
        }
    }
}