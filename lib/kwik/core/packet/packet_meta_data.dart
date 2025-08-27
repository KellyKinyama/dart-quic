class PacketMetaData {

     final Instant timeReceived;
     final InetSocketAddress sourceAddress;
     final int datagramNumber;
     final bool moreDataInDatagram;

    PacketMetaData(Instant timeReceived, InetSocketAddress sourceAddress, int datagramNumber) {
        this.timeReceived = timeReceived;
        this.sourceAddress = sourceAddress;
        this.datagramNumber = datagramNumber;
        moreDataInDatagram = false;
    }

    PacketMetaData(PacketMetaData original, bool moreDataInDatagram) {
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