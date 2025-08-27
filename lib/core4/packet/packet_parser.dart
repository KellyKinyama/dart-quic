// PacketParser.dart (UPDATED)
import 'dart:typed_data';
import 'auxiliary.dart'; // Import auxiliary classes
import '../crypto/crypto.dart'; // Import crypto classes
import 'quic_packet.dart'; // Import QuicPacket base
import 'long_header_packet.dart'; // Import LongHeaderPacket base
import 'short_header_packet.dart'; // Import ShortHeaderPacket
import 'initial_packet.dart'; // Import concrete packet types
import 'handshake_packet.dart';
import 'retry_packet.dart';
import 'zero_rtt_packet.dart';
import 'version_negotiation_packet.dart';

class PacketParser {
  final ConnectionSecrets connectionSecrets;
  final VersionHolder quicVersionHolder;
  final int cidLength; // Connection ID length, usually negotiated
  final PacketFilter processorChain;
  final Logger log;
  final Role role;
  // Largest packet number received per encryption level (Initial, Handshake, Application)
  final List<int> largestPacketNumber;
  final Function(Uint8List, Exception)? handleUnprotectPacketFailureFunction;

  PacketParser(
    this.connectionSecrets,
    this.quicVersionHolder,
    this.cidLength,
    this.processorChain,
    this.role,
    this.log, {
    this.handleUnprotectPacketFailureFunction,
  }) : largestPacketNumber = List<int>.filled(PnSpace.values.length, -1);

  void parseAndProcessPackets(Uint8List data, PacketMetaData metaData) {
    int currentOffset = 0;
    final ByteData byteData = data.buffer.asByteData(data.offsetInBytes);

    while (currentOffset < data.length) {
      int originalPacketStartOffset = currentOffset;
      try {
        if (data.length - currentOffset < 1) {
          log.warn("Not enough bytes for packet header. Breaking loop.");
          break;
        }

        int firstByte = byteData.getUint8(currentOffset);
        currentOffset += 1; // Consume the first byte

        QuicPacket packet;
        int packetStartAfterFirstByte =
            currentOffset; // Position after reading the first byte

        // Check for Long Header (fixed bit is 1)
        if (LongHeaderPacket.isLongHeaderPacket(firstByte)) {
          // Long Header Packet
          if (data.length - currentOffset < 4) {
            // Version field for Long Header
            throw InvalidPacketException(
              "Buffer too short for Long Header Version.",
            );
          }
          Version parsedVersion = Version(byteData.getUint32(currentOffset));

          if (parsedVersion == Version.QUIC_RESERVED_VERSION) {
            // It's a Version Negotiation Packet
            packet = VersionNegotiationPacket(parsedVersion);
            // Version Negotiation packets are not header or packet protected.
            // Parse its header directly.
            packet.parseHeader(
              data,
              packetStartAfterFirstByte,
              firstByte,
              quicVersionHolder,
            );
            // Advance currentOffset past the VN packet
            currentOffset =
                data.length; // VN packets consume the rest of the UDP datagram
          } else {
            // Determine concrete type based on type bits and version
            Type packetTypeClass = LongHeaderPacket.determineType(
              firstByte,
              parsedVersion,
            );

            if (packetTypeClass == InitialPacket) {
              packet = InitialPacket(parsedVersion);
            } else if (packetTypeClass == HandshakePacket) {
              packet = HandshakePacket(parsedVersion);
            } else if (packetTypeClass == ZeroRttPacket) {
              packet = ZeroRttPacket(parsedVersion);
            } else if (packetTypeClass == RetryPacket) {
              // RetryPacket does not undergo header protection or packet protection in the same way.
              // It has its own integrity tag.
              packet = RetryPacket(parsedVersion);
            } else {
              throw InvalidPacketException(
                "Unknown long header packet type: $packetTypeClass",
              );
            }

            // For Long Header packets, parse their headers.
            packet.parseHeader(
              data,
              packetStartAfterFirstByte,
              firstByte,
              quicVersionHolder,
            );

            int offsetToPnAndPayload;
            int payloadLengthIncludingPn;
            if (packet is InitialPacket) {
              offsetToPnAndPayload = packet.getHeaderEndOffset();
              payloadLengthIncludingPn = packet.packetLength!;
            } else if (packet is HandshakePacket) {
              offsetToPnAndPayload = packet.getHeaderEndOffset();
              payloadLengthIncludingPn = packet.packetLength!;
            } else if (packet is ZeroRttPacket) {
              offsetToPnAndPayload = packet.getHeaderEndOffset();
              payloadLengthIncludingPn = packet.packetLength!;
            } else if (packet is RetryPacket) {
              // Retry packet already handled its parsing and validation in parseHeader.
              // It consumes its own bytes completely.
              currentOffset = data
                  .length; // Assume Retry consumes the rest of the datagram for now.
              // In a real implementation, the parser would know the exact length of the Retry packet.
              // For this example, if it's a Retry, we consider it fully processed and move to the end.
              processorChain.process(packet, metaData);
              continue; // Skip the common decryption logic for Retry.
            } else {
              throw InvalidPacketException(
                "Unexpected long header packet type for payload processing.",
              );
            }

            EncryptionLevel encryptionLevel;
            Aead aead;
            Uint8List ppKey;
            Uint8List ppIv;

            if (packet is InitialPacket) {
              encryptionLevel = EncryptionLevel.initial;
              aead = connectionSecrets.getAead(EncryptionLevel.initial);
              ppKey = connectionSecrets.getPacketProtectionKey(
                EncryptionLevel.initial,
                role,
              );
              ppIv = connectionSecrets.getPacketProtectionIv(
                EncryptionLevel.initial,
                role,
              );
            } else if (packet is HandshakePacket) {
              encryptionLevel = EncryptionLevel.handshake;
              aead = connectionSecrets.getAead(EncryptionLevel.handshake);
              ppKey = connectionSecrets.getPacketProtectionKey(
                EncryptionLevel.handshake,
                role,
              );
              ppIv = connectionSecrets.getPacketProtectionIv(
                EncryptionLevel.handshake,
                role,
              );
            } else if (packet is ZeroRttPacket) {
              encryptionLevel = EncryptionLevel.zeroRtt;
              aead = connectionSecrets.getAead(EncryptionLevel.zeroRtt);
              ppKey = connectionSecrets.getPacketProtectionKey(
                EncryptionLevel.zeroRtt,
                role,
              );
              ppIv = connectionSecrets.getPacketProtectionIv(
                EncryptionLevel.zeroRtt,
                role,
              );
            } else {
              throw StateError(
                "Unhandled Long Header packet type for decryption.",
              );
            }

            int pnSpaceIndex = _getPnSpaceIndex(encryptionLevel);
            if (pnSpaceIndex == -1) {
              throw InvalidPacketException(
                "Unknown PN Space for encryption level: $encryptionLevel",
              );
            }

            int currentLargestPacketNumber = largestPacketNumber[pnSpaceIndex];

            packet.parsePacketNumberAndPayload(
              data,
              offsetToPnAndPayload,
              payloadLengthIncludingPn,
              aead,
              ppKey,
              ppIv,
              currentLargestPacketNumber,
              log,
            );

            // Update largest packet number for the corresponding PN space
            if (packet.packetNumber > largestPacketNumber[pnSpaceIndex]) {
              largestPacketNumber[pnSpaceIndex] = packet.packetNumber;
            }
            currentOffset =
                offsetToPnAndPayload +
                payloadLengthIncludingPn; // Advance past the whole packet
          }
        } else {
          // Short Header Packet
          // For short header, the DCID must be known from the connection context.
          // The PacketParser's `cidLength` field dictates this.
          // The DCID is the first field after the initial byte in a short header.
          if (data.length - currentOffset < cidLength) {
            throw InvalidPacketException(
              "Buffer too short for Short Header DCID (expected $cidLength bytes).",
            );
          }
          Uint8List dcid = Uint8List.sublistView(
            data,
            currentOffset,
            currentOffset + cidLength,
          );
          currentOffset += cidLength;

          packet = ShortHeaderPacket(
            quicVersionHolder.version!,
          ); // Assumes version is known from connection
          packet.destinationConnectionId =
              dcid; // Set DCID as it's parsed here by the parser.

          // Parse specific header fields (which for short header is mostly about PN length and Key Phase).
          // `currentOffset` is now at the start of the PN.
          packet.parseHeader(data, currentOffset, firstByte, quicVersionHolder);

          EncryptionLevel encryptionLevel = EncryptionLevel.oneRtt;
          Aead aead = connectionSecrets.getAead(EncryptionLevel.oneRtt);
          Uint8List ppKey = connectionSecrets.getPacketProtectionKey(
            EncryptionLevel.oneRtt,
            role,
          );
          Uint8List ppIv = connectionSecrets.getPacketProtectionIv(
            EncryptionLevel.oneRtt,
            role,
          );

          int pnSpaceIndex = _getPnSpaceIndex(encryptionLevel);
          if (pnSpaceIndex == -1) {
            throw InvalidPacketException(
              "Unknown PN Space for encryption level: $encryptionLevel",
            );
          }

          int currentLargestPacketNumber = largestPacketNumber[pnSpaceIndex];

          int remainingPayloadAndPnLength =
              data.length -
              currentOffset; // Remaining after DCID for ShortHeader

          packet.parsePacketNumberAndPayload(
            data,
            currentOffset,
            remainingPayloadAndPnLength,
            aead,
            ppKey,
            ppIv,
            currentLargestPacketNumber,
            log,
          );

          // Update largest packet number for the corresponding PN space
          if (packet.packetNumber > largestPacketNumber[pnSpaceIndex]) {
            largestPacketNumber[pnSpaceIndex] = packet.packetNumber;
          }
          currentOffset +=
              remainingPayloadAndPnLength; // Consume the parsed payload
        }

        processorChain.process(
          packet,
          metaData,
        ); // Process the fully parsed packet
      } on InvalidPacketException catch (e) {
        log.warn(
          "Invalid packet detected: ${e.message}. Skipping to next byte.",
        );
        // If an invalid packet, advance beyond its first byte to try parsing the next.
        currentOffset = originalPacketStartOffset + 1;
        if (handleUnprotectPacketFailureFunction != null) {
          if (!handleUnprotectPacketFailureFunction!(
            data.sublist(originalPacketStartOffset),
            e,
          )) {
            throw TransportError(
              "Failed to unprotect packet: ${e.message}",
              0x01,
            );
          }
        }
      } on DecryptionException catch (e) {
        log.warn(
          "Decryption failed for packet: ${e.message}. Skipping to next byte.",
        );
        currentOffset = originalPacketStartOffset + 1;
        if (handleUnprotectPacketFailureFunction != null) {
          if (!handleUnprotectPacketFailureFunction!(
            data.sublist(originalPacketStartOffset),
            e,
          )) {
            throw TransportError(
              "Failed to decrypt packet: ${e.message}",
              0x01,
            );
          }
        }
      } on Exception catch (e) {
        log.error(
          "Unexpected error during packet parsing: $e. Skipping to next byte.",
        );
        currentOffset = originalPacketStartOffset + 1;
        if (handleUnprotectPacketFailureFunction != null) {
          if (!handleUnprotectPacketFailureFunction!(
            data.sublist(originalPacketStartOffset),
            e,
          )) {
            throw TransportError(
              "Unhandled error during packet parsing: $e",
              0x01,
            );
          }
        }
      }
    }
  }

  // Helper to map EncryptionLevel to PnSpace index
  int _getPnSpaceIndex(EncryptionLevel level) {
    switch (level) {
      case EncryptionLevel.initial:
        return PnSpace.initial.index;
      case EncryptionLevel.handshake:
        return PnSpace.handshake.index;
      case EncryptionLevel.oneRtt:
      case EncryptionLevel.zeroRtt: // 0-RTT uses the application data PN space
        return PnSpace.application.index;
      default:
        return -1; // Should not happen with valid EncryptionLevels
    }
  }
}
