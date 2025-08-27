
import 'quic_frame.dart';

/**
 * Represents a data blocked frame.
 * https://www.rfc-editor.org/rfc/rfc9000.html#name-data_blocked-frames
 */
class DataBlockedFrame extends QuicFrame {

    long streamDataLimit;

    DataBlockedFrame() {
    }

  DataBlockedFrame(long streamDataLimit) {
        this.streamDataLimit = streamDataLimit;
    }

    DataBlockedFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException {
        byte frameType = buffer.get();
        streamDataLimit = VariableLengthInteger.parseLong(buffer);

        return this;
    }

    @Override
    int getFrameLength() {
        return 1 + VariableLengthInteger.bytesNeeded(streamDataLimit);
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x14);
        VariableLengthInteger.encode(streamDataLimit, buffer);
    }

    @Override
    String toString() {
        return "DataBlockedFrame[" + streamDataLimit + "]";
    }

    @Override
    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
