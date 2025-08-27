import 'dart:typed_data';

import '../buffer.dart';
import '../crypto/aead.dart';
import '../frame/QuicFrame.dart';
import 'short_header_packet.dart';

abstract class QuicPacket {

int packetNumber = -1;
List<QuicFrame> frames = [];

  void parsePacketNumberAndPayload(
    Buffer buffer,
    int flags,
    int remainingLength,
    Aead aead,

    int largestPacketNumber,
  ) {
    if (buffer.remaining() < remainingLength) {
      throw Exception("InvalidPacketException");
    }

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
    // "When removing packet protection, an endpoint
    //   first removes the header protection."

    int currentPosition = buffer.position();

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
    // "The same number of bytes are always sampled, but an allowance needs
    //   to be made for the endpoint removing protection, which will not know
    //   the length of the Packet Number field.  In sampling the packet
    //   ciphertext, the Packet Number field is assumed to be 4 bytes long
    //   (its maximum possible encoded length)."
    if (buffer.remaining() < 4) {
      throw Exception("InvalidPacketException");
    }
    buffer.position(currentPosition: currentPosition + 4);
    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.2:
    // "This algorithm samples 16 bytes from the packet ciphertext."
    if (buffer.remaining() < 16) {
      throw Exception("InvalidPacketException");
    }
    Uint8List sample = Uint8List(16);
    buffer.get(sample);
    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
    // "Header protection is applied after packet protection is applied (see
    //   Section 5.3).  The ciphertext of the packet is sampled and used as
    //   input to an encryption algorithm."

    Uint8List mask = createHeaderProtectionMaskLocal(sample, aead);
    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1
    // "The output of this algorithm is a 5 byte mask which is applied to the
    //   header fields using exclusive OR.  The least significant
    //   bits of the first byte of the packet are masked by the least
    //   significant bits of the first mask byte"
    int decryptedFlags;
    if ((flags & 0x80) == 0x80) {
      // Long header: 4 bits masked
      decryptedFlags = (flags ^ mask[0] & 0x0f);
    } else {
      // Short header: 5 bits masked
      decryptedFlags = (flags ^ mask[0] & 0x1f);
    }
    setUnprotectedHeader(decryptedFlags);
    buffer.position(currentPosition: currentPosition);

    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
        // "pn_length = (packet[0] & 0x03) + 1"
        int protectedPackageNumberLength = (decryptedFlags & 0x03) + 1;
        Uint8List protectedPackageNumber = Uint8List(protectedPackageNumberLength);
        buffer.get(protectedPackageNumber);

        Uint8List unprotectedPacketNumber = Uint8List(protectedPackageNumberLength);
        for (int i = 0; i < protectedPackageNumberLength; i++) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4.1:
            // " ...and the packet number is
            //   masked with the remaining bytes.  Any unused bytes of mask that might
            //   result from a shorter packet number encoding are unused."
            unprotectedPacketNumber[i] =  (protectedPackageNumber[i] ^ mask[1+i]);
        }
        int truncatedPacketNumber = bytesToInt(unprotectedPacketNumber);
        packetNumber = decodePacketNumber(truncatedPacketNumber, largestPacketNumber, protectedPackageNumberLength * 8);
        print("Unprotected packet number: $packetNumber");

        currentPosition = buffer.position();
        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.3
        // "The associated data, A, for the AEAD is the contents of the QUIC
        //   header, starting from the flags byte in either the short or long
        //   header, up to and including the unprotected packet number."
        Uint8List frameHeader = Uint8List(buffer.position());
        buffer.position(currentPosition:0);
        buffer.get(frameHeader);
        frameHeader[0] = decryptedFlags;
        buffer.position(currentPosition:currentPosition);

        // Copy unprotected (decrypted) packet number in frame header, before decrypting payload.
        System.arraycopy(unprotectedPacketNumber, 0, frameHeader, frameHeader.length - (protectedPackageNumberLength), protectedPackageNumberLength);
        print("Frame header: $frameHeader");

        // "The input plaintext, P, for the AEAD is the payload of the QUIC
        //   packet, as described in [QUIC-TRANSPORT]."
        // "The output ciphertext, C, of the AEAD is transmitted in place of P."
        int encryptedPayloadLength = remainingLength - protectedPackageNumberLength;
        if (encryptedPayloadLength < 1) {
            throw Exception("InvalidPacketException");
        }
        Uint8List payload = Uint8List(encryptedPayloadLength);
        buffer.get(payload,start:  0,end:  encryptedPayloadLength);
        print("Encrypted payload: $payload");

        Uint8List frameBytes = decryptPayload(payload, frameHeader, packetNumber, aead);
        print("Decrypted payload: $frameBytes");

        frames = new ArrayList<>();
        parseFrames(frameBytes, log);
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
        // "An endpoint MUST (...) after removing both packet and header protection, (...)"
        checkReservedBits(decryptedFlags);
  }

  Uint8List createHeaderProtectionMaskLocal(Uint8List sample, Aead aead) {
    return createHeaderProtectionMask(sample, 4, aead);
  }

  Uint8List createHeaderProtectionMask(
    Uint8List ciphertext,
    int encodedPacketNumberLength,
    Aead aead,
  ) {
    // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.4
    // "The same number of bytes are always sampled, but an allowance needs
    //   to be made for the endpoint removing protection, which will not know
    //   the length of the Packet Number field.  In sampling the packet
    //   ciphertext, the Packet Number field is assumed to be 4 bytes long
    //   (its maximum possible encoded length)."
    int sampleOffset = 4 - encodedPacketNumberLength;
    Uint8List sample = Uint8List(16);
    // System.arraycopy(ciphertext, sampleOffset, sample, 0, 16);
    sample.setRange(0, 16, ciphertext.sublist(sampleOffset));

    return aead.createHeaderProtectionMask(sample);
  }

  void setUnprotectedHeader(int decryptedFlags) {
    throw UnimplementedError();
  }

  static int bytesToInt(Uint8List data) {
        int value = 0;
        for (int i = 0; i < data.length; i++) {
            value = (value << 8) | (data[i] & 0xff);

        }
        return value;
    }

    Uint8List decryptPayload(Uint8List message, Uint8List associatedData, int packetNumber, Aead aead) 
    // throws DecryptionException 
    {
        Buffer nonceInput = Buffer.allocate(12);
        nonceInput.putInt(0);
        nonceInput.putLong(packetNumber);

        if (this is ShortHeaderPacket) {
          this as ShortHeaderPacket;
            aead.checkKeyPhase( keyPhaseBit);
        }

        Uint8List writeIV = aead.getWriteIV();
        Uint8List nonce = Uint8List(12);
        int i = 0;
        for (int b in nonceInput.data) {
          nonce[i] =  (b ^ writeIV[i++]);
        }

        return aead.aeadDecrypt(associatedData, message, nonce);
    }
}
