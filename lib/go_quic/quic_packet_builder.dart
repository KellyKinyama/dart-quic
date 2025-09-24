import 'dart:typed_data';
import 'buffer.dart'; // Make sure to use your project's imports
import 'aead.dart';
import 'initial_aead.dart';
import 'protocol.dart';

class QuicPacketBuilder {
  /// Builds a fully protected QUIC Client Initial packet.
  ///
  /// This function handles header creation, padding, payload encryption (sealing),
  /// and header protection.
  static Uint8List buildClientInitialPacket({
    required Uint8List destinationCid,
    required Uint8List sourceCid,
    required Uint8List
    payload, // This is typically the first part of the TLS ClientHello
    required int packetNumber,
    required Version version,
  }) {
    final pnLength =
        4; // QUIC RFCs recommend a 4-byte packet number for Initial packets.
    final aeadTagLength = 16; // For AES-GCM

    // --- 1. Build the Unprotected Header ---
    final headerBuilder = Buffer();

    // First Byte: Long Header (0x80), Fixed Bit (0x40), Type Initial (0x00), PN Length (0x03 for 4 bytes)
    headerBuilder.pushUint8(0xc0 | (pnLength - 1));
    headerBuilder.pushUint32(version.value);
    headerBuilder.pushVector(destinationCid, 1);
    headerBuilder.pushVector(sourceCid, 1);
    headerBuilder.pushUintVar(0); // Token Length is 0 for the first Initial

    // The "Length" field in the header covers the Packet Number and the sealed payload (including the AEAD tag).
    // We calculate the required padding to meet the QUIC spec's minimum size for Initial packets (1200 bytes).
    final minPacketSize = 1200;
    final headerLength =
        headerBuilder.length +
        2 +
        pnLength; // +2 for a 2-byte varint length field
    final paddingLength =
        minPacketSize - headerLength - payload.length - aeadTagLength;

    final totalPayloadLength =
        payload.length + paddingLength + pnLength + aeadTagLength;
    headerBuilder.pushUintVar(totalPayloadLength);

    // Push the packet number itself.
    final pnBytes = ByteData(4)..setUint32(0, packetNumber);
    headerBuilder.pushBytes(Uint8List.view(pnBytes.buffer, 4 - pnLength));

    final unprotectedHeader = headerBuilder.toBytes();

    // --- 2. Prepare and Seal the Payload ---
    final (sealer, _) = newInitialAEAD(
      destinationCid,
      Perspective.client,
      version,
    );

    final paddedPayloadBuilder = BytesBuilder()
      ..add(payload)
      ..add(Uint8List(paddingLength > 0 ? paddingLength : 0));

    final sealedPayload = sealer.seal(
      paddedPayloadBuilder.toBytes(),
      packetNumber,
      unprotectedHeader,
    );

    // --- 3. Apply Header Protection ---
    final protectedHeader = Uint8List.fromList(unprotectedHeader);

    // The sample is taken from the first 16 bytes of the sealed payload.
    // The sample starts at an offset of (4 - pnLength) bytes into the ciphertext.
    final sample = sealedPayload.sublist(4 - pnLength, 4 - pnLength + 16);

    final firstByteView = Uint8List.view(protectedHeader.buffer, 0, 1);
    final pnView = Uint8List.view(
      protectedHeader.buffer,
      unprotectedHeader.length - pnLength,
      pnLength,
    );

    sealer.encryptHeader(sample, firstByteView, pnView);

    // --- 4. Assemble the Final Packet ---
    return (BytesBuilder()
          ..add(protectedHeader)
          ..add(sealedPayload))
        .toBytes();
  }
}
