// lib/src/connection.dart
import 'dart:async';
import 'dart:typed_data';

import 'crypto_frame_handler.dart';
import 'enums.dart';
// import 'package:quic_tls_analysis/src/errors.dart';
import 'key_manager.dart';
import 'packet_protector.dart';
import 'tls_stack.dart';
import 'transport_parameters.dart';
// import 'package:quic_tls_analysis/src/types.dart'; // For AEAD/KDF mocks

class QuicConnection {
  final bool isClient;
  final QuicTlsStack _tlsStack;
  final QuicKeyManager _keyManager = QuicKeyManager();
  final QuicPacketProtector _packetProtector = QuicPacketProtector();
  late final CryptoFrameHandler _cryptoFrameHandler;

  EncryptionLevel _currentSendLevel = EncryptionLevel.initial;
  EncryptionLevel _currentReceiveLevel = EncryptionLevel.initial;
  bool _handshakeComplete = false;
  bool _handshakeConfirmed = false;
  bool _0RttEnabled = false; // Client's intent to send 0-RTT
  bool _0RttAcceptedByPeer = false; // Server's acceptance of 0-RTT

  // Mock connection IDs and packet numbers
  Uint8List _localConnectionId = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  Uint8List _peerConnectionId = Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1]);
  int _sendPacketNumber = 0;
  int _receivePacketNumber = 0; // Simplified; real needs per-PN-space tracking

  QuicConnection(this.isClient, this._tlsStack) {
    _cryptoFrameHandler = CryptoFrameHandler(_tlsStack, isClient);
    _setupTlsCallbacks();
  }

  void _setupTlsCallbacks() {
    _tlsStack.onNewTrafficSecrets =
        (level, clientSecret, serverSecret, aead, kdf) {
          _keyManager.installTrafficSecrets(
            level: level,
            clientTrafficSecret: clientSecret,
            serverTrafficSecret: serverSecret,
            negotiatedAead: aead,
            negotiatedKdf: kdf,
            isClient: isClient,
          );
          print('${isClient ? 'Client' : 'Server'} Installed ${level} keys.');

          // Update current receive level for CRYPTO frame handler
          if (level.index > _currentReceiveLevel.index) {
            _currentReceiveLevel = level;
            _cryptoFrameHandler.setCurrentReceiveLevel(level);
          }

          // Special handling for 0-RTT acceptance (RFC 9001, Section 4.6.1)
          if (level == EncryptionLevel.zeroRtt &&
              isClient &&
              _tlsStack.is0RttAccepted()) {
            _0RttAcceptedByPeer = true;
            print('0-RTT accepted by server.');
          }
        };

    _tlsStack.onHandshakeComplete = () {
      _handshakeComplete = true;
      print('${isClient ? 'Client' : 'Server'} Handshake complete.');

      // Install 1-RTT keys if not already (TLS will signal this via onNewTrafficSecrets)
      // Discard Handshake keys (RFC 9001, Section 4.9.2)
      _keyManager.discardHandshakeKeys();
      // Discard 0-RTT keys if client and 1-RTT keys installed (RFC 9001, Section 4.9.3)
      if (isClient && _keyManager.getSendKeys(EncryptionLevel.oneRtt) != null) {
        _keyManager.discardZeroRttKeys(true);
      }
      // For server, it's confirmed here.
      if (!isClient) {
        _handshakeConfirmed = true;
        print('Server Handshake confirmed. Sending HANDSHAKE_DONE frame.');
        // TODO: Send HANDSHAKE_DONE frame.
        _keyManager.discardHandshakeKeys();
        _keyManager.discardZeroRttKeys(false); // Server can discard now
      }
    };

    _tlsStack.onTlsAlert = (alertDescription) {
      // Convert TLS alert to QUIC connection error (RFC 9001, Section 4.8)
      var error = QuicError.fromTlsAlert(alertDescription);
      print('Connection Terminated due to TLS Alert: $error');
      close();
    };
  }

  /// Initiates the QUIC connection handshake.
  void start() {
    print('${isClient ? 'Client' : 'Server'} QUIC connection starting...');

    // Set local transport parameters (RFC 9001, Section 8.2)
    _tlsStack.setTransportParameters(
      QuicTransportParameters(initialMaxData: 60000),
    );

    if (isClient) {
      // Client derives Initial keys based on its initial DCID
      _keyManager.deriveInitialKeys(
        _peerConnectionId,
      ); // client_dst_connection_id
      _tlsStack.startHandshake();
      _currentSendLevel = EncryptionLevel.initial;
      // Client might enable 0-RTT (RFC 9001, Section 4.6.1)
      _0RttEnabled = true; // Client decides to attempt 0-RTT
    } else {
      // Server waits for ClientHello
      // Initial keys will be derived upon receiving the first Initial packet.
      _tlsStack.startHandshake();
    }
  }

  /// Handles incoming UDP datagrams.
  void receiveUdpDatagram(Uint8List datagram) {
    // In a real impl, parse datagram for coalesced packets
    // For simplicity, assume one packet per datagram for now.
    print(
      '${isClient ? 'Client' : 'Server'} Received UDP datagram (${datagram.length} bytes)',
    );

    // Attempt to unprotect with current receive keys
    // This is simplified: real impl tries all possible keys (Initial, Handshake, 0-RTT, 1-RTT)
    // and determines packet type/level based on header bits.
    QuicPacketProtectionKeys? keys = _keyManager.getReceiveKeys(
      _currentReceiveLevel,
    );
    if (keys == null) {
      print(
        'No receive keys for current level $_currentReceiveLevel. Discarding.',
      );
      return;
    }

    // This part requires parsing the packet header to get isLongHeader, pnOffset, headerLength
    // For demo, we'll make assumptions for an "Initial" packet structure.
    bool isLongHeader = (datagram[0] & 0x80) == 0x80;
    int pnOffset = 0; // Simplified
    int headerLength =
        0; // Simplified, derived from parsing actual header fields
    Uint8List dcid = Uint8List(0); // Simplified

    if (isLongHeader) {
      // Example parsing for Initial packet:
      // Fixed Bit (1) = 1, Long Packet Type (2) = 0, Reserved Bits (2), Packet Number Length (2)
      // Version (32), DCID Len (8), Destination Connection ID (0..160), SCID Len (8), Source Connection ID (0..160)
      // Token Length (i), Token (..), Length (i)
      // For Initial, type is 0x00 for Long Header (0x80 | 0x00 = 0x80)
      // Assuming first byte `0xC0` means Initial packet (Fixed Bit, Long Header, Type 0, 2-bit PN len = 01)
      if ((datagram[0] & 0xC0) == 0xC0) {
        // Check for Initial (0xC0 indicates Version=1, Type=0, PN=1)
        int version = ByteData.view(
          datagram.buffer,
          1,
          4,
        ).getUint32(0, Endian.big);
        int dcidLen = datagram[5];
        dcid = datagram.sublist(6, 6 + dcidLen);
        int scidLen = datagram[6 + dcidLen];
        Uint8List scid = datagram.sublist(7 + dcidLen, 7 + dcidLen + scidLen);

        int tokenLengthOffset = 7 + dcidLen + scidLen;
        var tokenLenResult = VarInt.decode(datagram, tokenLengthOffset);
        int tokenLength = tokenLenResult; // Actual token length
        int tokenOffset = tokenLengthOffset + VarInt.encode(tokenLength).length;
        Uint8List token = datagram.sublist(
          tokenOffset,
          tokenOffset + tokenLength,
        );

        int lengthOffset = tokenOffset + tokenLength;
        var lengthResult = VarInt.decode(datagram, lengthOffset);
        int payloadLength = lengthResult; // Length of payload + PN
        pnOffset = lengthOffset + VarInt.encode(payloadLength).length;
        headerLength =
            pnOffset + (datagram[0] & 0x03) + 1; // PN length from header
      }
    } else {
      // Short Header (0x40 - 0x7F)
      // Fixed Bit (1) = 1, Spin Bit (1), Reserved Bits (2), Key Phase (1), Packet Number Length (2)
      // Destination Connection ID (0..160)
      // pnOffset = 1 + dcid.length
      // headerLength = pnOffset + pnLength
      // For demo, assume fixed 8-byte DCID for short header
      dcid = _peerConnectionId; // Or actual extracted DCID
      pnOffset =
          1 + dcid.length; // Assuming 1 byte for first byte of header + DCID
      headerLength =
          pnOffset +
          (datagram[0] & 0x03) +
          1; // Simplified, based on PN length in unmasked byte
    }

    if (!isClient &&
        _currentReceiveLevel == EncryptionLevel.initial &&
        _keyManager.getReceiveKeys(EncryptionLevel.initial) == null) {
      // Server: First Initial packet, derive initial keys using client's DCID
      _keyManager.deriveInitialKeys(dcid);
      keys = _keyManager.getReceiveKeys(EncryptionLevel.initial);
      if (keys == null) {
        print('Server: Could not derive initial keys. Discarding.');
        return;
      }
    }

    Map<String, dynamic>? unprotected = _packetProtector.unprotect(
      packetData: datagram,
      keys: keys!,
      isLongHeader: isLongHeader,
      headerLength: headerLength,
      pnOffset: pnOffset,
    );

    if (unprotected == null) {
      print(
        '${isClient ? 'Client' : 'Server'} Packet unprotection failed. Discarding.',
      );
      // Handle potential protocol errors / attacks, or just out-of-order packets.
      return;
    }

    Uint8List payload = unprotected['payload']!;
    int packetNumber = unprotected['packet_number']!;
    Uint8List unmaskedHeader = unprotected['unmasked_header']!;
    int pnLength = unprotected['pn_length']!;

    _receivePacketNumber =
        packetNumber; // Simplified: per-PN-space handling needed

    print(
      '${isClient ? 'Client' : 'Server'} Received packet #$packetNumber at level $_currentReceiveLevel',
    );

    // Process frames in the payload
    _processFrames(payload, _currentReceiveLevel);

    // After processing, try to send a response (e.g., ACK or handshake messages)
    _sendPendingPackets();

    // Client Handshake Confirmed logic (RFC 9001, Section 4.1.2)
    if (isClient && _handshakeComplete && !_handshakeConfirmed) {
      // Simplified: Assume HANDSHAKE_DONE frame processing or 1-RTT ACK
      _handshakeConfirmed = true;
      _tlsStack.onHandshakeConfirmed?.call();
      _keyManager.discardHandshakeKeys();
      _keyManager.discardZeroRttKeys(true);
    }
  }

  /// Processes the frames contained within a packet payload.
  void _processFrames(Uint8List payload, EncryptionLevel level) {
    int offset = 0;
    while (offset < payload.length) {
      int frameType = VarInt.decode(payload, offset);
      int frameTypeLen = VarInt.encode(frameType).length;

      if (frameType == 0x06) {
        // CRYPTO frame
        var cryptoFrame = CryptoFrame.fromBytes(payload, offset);
        if (cryptoFrame != null) {
          print(
            '  Processing CRYPTO frame: offset=${cryptoFrame.offset}, len=${cryptoFrame.length}',
          );
          _cryptoFrameHandler.addReceivedData(cryptoFrame, level);
        }
        offset +=
            VarInt.encode(cryptoFrame!.length).length +
            cryptoFrame.length +
            frameTypeLen +
            VarInt.encode(cryptoFrame.offset).length; // Advance offset
      } else if (frameType == 0x01) {
        // PADDING frame
        print('  Processing PADDING frame');
        offset +=
            frameTypeLen +
            (payload.length - offset - frameTypeLen); // Consume rest of payload
      } else if (frameType == 0x14) {
        // HANDSHAKE_DONE frame (simplified)
        if (isClient && !_handshakeConfirmed) {
          _handshakeConfirmed = true;
          _tlsStack.onHandshakeConfirmed?.call();
          _keyManager.discardHandshakeKeys();
          _keyManager.discardZeroRttKeys(true);
          print('  Client received HANDSHAKE_DONE. Handshake confirmed!');
        }
        offset += frameTypeLen;
      } else {
        print(
          '  Processing unknown frame type: 0x${frameType.toRadixString(16)}',
        );
        // For demonstration, just advance past the frame type, assuming no other fields
        offset += frameTypeLen; // Placeholder for actual frame parsing
      }
    }
  }

  /// Sends any pending QUIC packets (e.g., handshake messages, ACKs).
  void _sendPendingPackets() {
    // 1. Get TLS handshake messages to send (CRYPTO frames)
    final List<CryptoFrame> cryptoFrames = _cryptoFrameHandler.getFramesToSend(
      _currentSendLevel,
    );

    if (cryptoFrames.isNotEmpty) {
      final keys = _keyManager.getSendKeys(_currentSendLevel);
      if (keys == null) {
        print(
          'No send keys for $_currentSendLevel. Cannot send CRYPTO frames.',
        );
        return;
      }

      for (var frame in cryptoFrames) {
        // Construct a mock packet header (Long Header for Initial/Handshake)
        bool isLongHeader =
            _currentSendLevel == EncryptionLevel.initial ||
            _currentSendLevel == EncryptionLevel.handshake;
        int packetTypeByte = 0; // Placeholder
        if (isLongHeader) {
          if (_currentSendLevel == EncryptionLevel.initial)
            packetTypeByte = 0xC0; // Initial packet
          if (_currentSendLevel == EncryptionLevel.handshake)
            packetTypeByte = 0xC2; // Handshake packet
        } else {
          packetTypeByte = 0x40; // Short header for 0-RTT/1-RTT
          if (_0RttEnabled && _currentSendLevel == EncryptionLevel.zeroRtt)
            packetTypeByte = 0xC1; // 0-RTT (Long Header type 1)
        }

        // Simplified header construction for demonstration
        BytesBuilder headerBuilder = BytesBuilder();
        headerBuilder.addByte(
          packetTypeByte | ((_sendPacketNumber % 4) + 1),
        ); // First byte + PN length bit
        if (isLongHeader) {
          headerBuilder.add(
            Uint8List.fromList([0x00, 0x00, 0x00, 0x01]),
          ); // Version (QUIC v1)
          headerBuilder.addByte(_localConnectionId.length);
          headerBuilder.add(_localConnectionId);
          headerBuilder.addByte(_peerConnectionId.length);
          headerBuilder.add(_peerConnectionId);
          // Token and Length fields for Initial
          if (_currentSendLevel == EncryptionLevel.initial) {
            headerBuilder.add(
              VarInt.encode(0),
            ); // Token Length (no token for now)
            headerBuilder.add(
              VarInt.encode(frame.length + keys.aead.tagLength),
            ); // Payload Length + Tag
          }
        } else {
          headerBuilder.add(_peerConnectionId); // DCID for short header
        }

        int pnOffset = headerBuilder.length;
        headerBuilder.add(
          VarInt.encode(_sendPacketNumber),
        ); // Add packet number (truncated will happen during protect)

        Uint8List rawHeader = headerBuilder.takeBytes();

        Uint8List protectedPacket = _packetProtector.protect(
          rawHeader: rawHeader,
          payload: frame.data,
          keys: keys,
          packetNumber: _sendPacketNumber,
          longHeader: isLongHeader,
          pnOffset: pnOffset,
          pnLength: VarInt.encode(
            _sendPacketNumber,
          ).length, // Actual encoded PN length
        );

        print(
          '${isClient ? 'Client' : 'Server'} Sending $_currentSendLevel packet #${_sendPacketNumber++} (${protectedPacket.length} bytes)',
        );
        // In a real impl, send UDP datagram here
      }
      // After sending, discard Initial keys if client, as Handshake packet was sent
      if (isClient && _currentSendLevel == EncryptionLevel.initial) {
        _keyManager.discardInitialKeys(true);
      }
    }

    // After sending handshake data, if Handshake complete, consider sending 1-RTT application data
    if (_handshakeComplete) {
      if (_currentSendLevel != EncryptionLevel.oneRtt) {
        _currentSendLevel =
            EncryptionLevel.oneRtt; // Switch to 1-RTT for future app data
      }
      // Simulate sending application data
      if (isClient && _0RttEnabled && _0RttAcceptedByPeer) {
        // Client can send 0-RTT application data if accepted
        _sendApplicationData(EncryptionLevel.zeroRtt);
      }
      _sendApplicationData(EncryptionLevel.oneRtt);
    }
  }

  void _sendApplicationData(EncryptionLevel level) {
    if (level == EncryptionLevel.zeroRtt && !_0RttAcceptedByPeer) {
      print('Not sending 0-RTT application data: not accepted by peer.');
      return;
    }
    if (isClient &&
        level == EncryptionLevel.zeroRtt &&
        _keyManager.getSendKeys(EncryptionLevel.oneRtt) != null) {
      print(
        'Client: Not sending 0-RTT application data as 1-RTT keys are installed.',
      );
      return; // RFC 9001, Section 5.6
    }
    if (level != EncryptionLevel.oneRtt && level != EncryptionLevel.zeroRtt) {
      print('Cannot send application data at $level.');
      return;
    }

    final keys = _keyManager.getSendKeys(level);
    if (keys == null) {
      print('No send keys for $level to send application data.');
      return;
    }

    // Simulate sending a STREAM frame (simplified)
    final Uint8List appData = Uint8List.fromList(
      'Hello from ${isClient ? 'Client' : 'Server'} at $level'.codeUnits,
    );
    final BytesBuilder payloadBuilder = BytesBuilder();
    // STREAM frame type 0x08 (STREAM, FIN=0, LEN=1, OFF=1)
    payloadBuilder.addByte(0x08);
    payloadBuilder.add(VarInt.encode(0)); // Stream ID 0
    payloadBuilder.add(VarInt.encode(0)); // Offset 0
    payloadBuilder.add(VarInt.encode(appData.length));
    payloadBuilder.add(appData);

    Uint8List rawPayload = payloadBuilder.takeBytes();

    // Simplified header for Short Header packets (1-RTT / 0-RTT)
    BytesBuilder headerBuilder = BytesBuilder();
    int packetTypeByte = 0x40; // Short Header
    if (level == EncryptionLevel.zeroRtt)
      packetTypeByte = 0xC1; // 0-RTT Long Header
    headerBuilder.addByte(
      packetTypeByte | ((_sendPacketNumber % 4) + 1),
    ); // First byte + PN length bit

    if (level == EncryptionLevel.initial ||
        level == EncryptionLevel.handshake ||
        level == EncryptionLevel.zeroRtt) {
      // Long Header fields for 0-RTT
      headerBuilder.add(
        Uint8List.fromList([0x00, 0x00, 0x00, 0x01]),
      ); // Version (QUIC v1)
      headerBuilder.addByte(_localConnectionId.length);
      headerBuilder.add(_localConnectionId);
      headerBuilder.addByte(_peerConnectionId.length);
      headerBuilder.add(_peerConnectionId);
      // Token and Length fields for 0-RTT (no token for now)
      headerBuilder.add(VarInt.encode(0)); // Token Length
      headerBuilder.add(
        VarInt.encode(rawPayload.length + keys.aead.tagLength),
      ); // Payload Length + Tag
    } else {
      headerBuilder.add(_peerConnectionId); // DCID for short header (1-RTT)
    }

    int pnOffset = headerBuilder.length;
    headerBuilder.add(VarInt.encode(_sendPacketNumber)); // Add packet number

    Uint8List rawHeader = headerBuilder.takeBytes();

    Uint8List protectedPacket = _packetProtector.protect(
      rawHeader: rawHeader,
      payload: rawPayload,
      keys: keys,
      packetNumber: _sendPacketNumber,
      longHeader:
          (level == EncryptionLevel.initial ||
          level == EncryptionLevel.handshake ||
          level == EncryptionLevel.zeroRtt),
      pnOffset: pnOffset,
      pnLength: VarInt.encode(_sendPacketNumber).length,
    );

    print(
      '${isClient ? 'Client' : 'Server'} Sending ${level} application data packet #${_sendPacketNumber++} (${protectedPacket.length} bytes)',
    );
    // In a real impl, send UDP datagram here
  }

  void close() {
    _tlsStack.close();
    print('${isClient ? 'Client' : 'Server'} QUIC connection closed.');
  }
}
