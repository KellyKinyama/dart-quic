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


import "package:dart_quic/kwik/core/frame/AckFrame.dart";
import "package:dart_quic/kwik/core/impl/FrameReceivedListener.dart";
import "package:dart_quic/kwik/core/common/PnSpace.dart";
import "package:dart_quic/kwik/core/packet/QuicPacket.dart";
import "package:dart_quic/kwik/core/send/NullAckGenerator.dart";
import "package:dart_quic/kwik/core/send/Sender.dart";



class GlobalAckGenerator implements FrameReceivedListener<AckFrame> {

    AckGenerator[] ackGenerators;

    GlobalAckGenerator(Sender sender) {
        ackGenerators = new AckGenerator[PnSpace.values().length];
        Arrays.stream(PnSpace.values()).forEach(pnSpace -> ackGenerators[pnSpace.ordinal()] = new AckGenerator(pnSpace, sender));
    }

    void packetReceived(QuicPacket packet) {
        if (packet.canBeAcked()) {
            ackGenerators[packet.getPnSpace().ordinal()].packetReceived(packet);
        }
    }

    @Override
    void received(AckFrame frame, PnSpace pnSpace, Instant timeReceived) {
        ackGenerators[pnSpace.ordinal()].process(frame);
    }

    AckGenerator getAckGenerator(PnSpace pnSpace) {
        return ackGenerators[pnSpace.ordinal()];
    }

    void discard(PnSpace pnSpace) {
        // Discard existing ackgenerator for given space, but install a no-op ack generator to catch calls for received
        // packets in that space. This is necessary because even the space is discarded, packets for that space might
        // be received and processed (until its keys are discarded).
        ackGenerators[pnSpace.ordinal()] = new NullAckGenerator();
    }
}
