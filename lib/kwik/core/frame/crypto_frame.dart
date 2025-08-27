import 'quic_frame.dart';

class CryptoFrame extends QuicFrame implements StreamElement {

    long offset;
    int length;
    Uint8List cryptoData;
    Uint8List bytes;

    CryptoFrame() {
    }

    CryptoFrame(Version quicVersion, Uint8List payload) {
        this(quicVersion, 0, payload);
    }

    CryptoFrame(Version quicVersion, long offset, Uint8List payload) {
        this.offset = offset;
        cryptoData = payload;
        length = payload.length;
        ByteBuffer frameBuffer = ByteBuffer.allocate(3 * 4 + payload.length);
        VariableLengthInteger.encode(0x06, frameBuffer);
        VariableLengthInteger.encode(offset, frameBuffer);
        VariableLengthInteger.encode(payload.length, frameBuffer);
        frameBuffer.put(payload);

        bytes = new byte[frameBuffer.position()];
        frameBuffer.rewind();
        frameBuffer.get(bytes);
    }

    @Override
    int getFrameLength() {
        return 1
                + VariableLengthInteger.bytesNeeded(offset)
                + VariableLengthInteger.bytesNeeded(cryptoData.length)
                + cryptoData.length;
    }

    @Override
    void serialize(ByteBuffer buffer) {
        buffer.put((byte) 0x06);
        VariableLengthInteger.encode(offset, buffer);
        VariableLengthInteger.encode(cryptoData.length, buffer);
        buffer.put(cryptoData);
    }

    CryptoFrame parse(ByteBuffer buffer, Logger log) throws InvalidIntegerEncodingException, IntegerTooLargeException {
        log.debug("Parsing Crypto frame");
        buffer.get();

        offset = VariableLengthInteger.parseLong(buffer);
        length = VariableLengthInteger.parseInt(buffer);

        cryptoData = new byte[length];
        buffer.get(cryptoData);
        log.decrypted("Crypto data [" + offset + "," + length + "]", cryptoData);

        return this;
    }

    @Override
    String toString() {
        return "CryptoFrame[" + offset + "," + length + "]";
    }

    Uint8List getStreamData() {
        return cryptoData;
    }

    @Override
    long getOffset() {
        return offset;
    }

    @Override
    int getLength() {
        return length;
    }

    @Override
    long getUpToOffset() {
        return offset + length;
    }

    @Override
     bool isFinal() {
        return false;
    }

    @Override
    int compareTo(StreamElement other) {
        if (this.offset != other.getOffset()) {
            return Long.compare(this.offset, other.getOffset());
        }
        else {
            return Long.compare(this.length, other.getLength());
        }
    }

    void accept(FrameProcessor frameProcessor, QuicPacket packet, PacketMetaData metaData) {
        frameProcessor.process(this, packet, metaData);
    }
}
