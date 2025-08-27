/*
 * Copyright © 2019, 2020, 2025 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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

import "dart:typed_data";

import "package:dart_quic/kwik/core/frame/FrameProcessor.dart";
import "../core/frame/QuicFrame.dart";
import "package:dart_quic/kwik/core/packet/PacketMetaData.dart";
import "package:dart_quic/kwik/core/packet/QuicPacket.dart";
import "package:dart_quic/kwik/core/util/Bytes.dart";

// import java.nio.ByteBuffer;

/**
 * Generic frame, for sending arbitrary frame data. Sole purpose is to test how implementations respond to invalid or
 * incorrect frames.
 */

class RawFrame extends QuicFrame {
  Uint8List rawData;

  RawFrame(Uint8List rawData) {
    this.rawData = rawData;
  }

  @Override
  void serialize(ByteBuffer buffer) {
    buffer.put(rawData);
  }

  @Override
  void accept(
    FrameProcessor frameProcessor,
    QuicPacket packet,
    PacketMetaData metaData,
  ) {
    throw new UnsupportedOperationException("RawFrame cannot be processed");
  }

  @Override
  int getFrameLength() {
    return rawData.length;
  }

  @Override
  String toString() {
    return "RawFrame[" + Bytes.bytesToHex(rawData) + "]";
  }
}
