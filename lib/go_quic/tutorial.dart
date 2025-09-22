import 'dart:typed_data';
import 'dart:math';

// This is a conceptual tutorial formatted as Dart code.
// It explains the entire QUIC handshake and data exchange process.
// Note: Cryptographic functions are placeholders for clarity.

/// ## Phase 1: Client-Side Preparation (Offline)
/// The connection begins with the client generating all necessary cryptographic
/// keys before sending any data over the network.
void clientPreparation() {
  /// ### 1a: Generate X25519 Keypair
  /// A standard elliptic-curve keypair for the TLS 1.3 key exchange.
  final clientPrivateKey = Uint8List.fromList([
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
  ]);

  final clientPublicKey = Uint8List.fromList([
    0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a,
    0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75,
    0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54
  ]);

  /// ### 1b: Derive Initial Encryption Keys
  /// These keys are used for the first few packets. They are not fully secure,
  /// as any on-path observer can also derive them.

  // A constant salt, famously derived from the first discovered SHA-1 collision.
  final initialSalt = Uint8List.fromList([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
    0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
  ]);

  // The client generates 8 random bytes that will be used as the initial DCID.
  final clientInitialRandom =
      Uint8List.fromList([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

  final initialSecret =
      hkdfExtract(salt: initialSalt, key: clientInitialRandom);
  final clientSecret =
      hkdfExpandLabel(key: initialSecret, label: 'client in', length: 32);
  final serverSecret =
      hkdfExpandLabel(key: initialSecret, label: 'server in', length: 32);

  // Derive keys, IVs, and header protection (hp) keys for both client and server.
  final clientInitialKey =
      hkdfExpandLabel(key: clientSecret, label: 'quic key', length: 16);
  final clientInitialIv =
      hkdfExpandLabel(key: clientSecret, label: 'quic iv', length: 12);
  final clientInitialHpKey =
      hkdfExpandLabel(key: clientSecret, label: 'quic hp', length: 16);

  final serverInitialKey =
      hkdfExpandLabel(key: serverSecret, label: 'quic key', length: 16);
  final serverInitialIv =
      hkdfExpandLabel(key: serverSecret, label: 'quic iv', length: 12);
  final serverInitialHpKey =
      hkdfExpandLabel(key: serverSecret, label: 'quic hp', length: 16);
}

/// ## Phase 2: The Handshake Begins
void runHandshake() {
  /// ### UDP Datagram 1: Client Hello
  /// The client sends its first packet, containing the TLS ClientHello record.
  /// The entire datagram is padded to 1200 bytes to validate the network path's MTU
  /// and mitigate amplification attacks.
  final udpDatagram1 = {
    'Description': 'Client sends Initial packet with ClientHello.',
    'QUIC Packet': {
      'Header': {
        // 0xc0: Long header, fixed bit, type=Initial, 1-byte packet number.
        'Packet Header Byte': 0xc0,
        'QUIC Version': 0x00000001,
        'Destination Connection ID': '08' '0001020304050607', // 8 random bytes
        'Source Connection ID': '05' '635f636964', // value="c_cid"
        'Packet Length': 259,
        'Packet Number': 0,
      },
      'Decrypted Payload': {
        'CRYPTO Frame': {
          'TLS Record': {
            'ClientHello': {
              'SNI': 'example.ulfheim.net',
              'Key Share': 'clientPublicKey',
              'QUIC Transport Parameters': {
                'initial_source_connection_id': 'c_cid'
              }
            }
          }
        }
      }
    },
    'Padding Length': 1200 - (24 + 259 + 16), // Header + Payload + Auth Tag
  };

  /// ### Server-Side Processing
  /// The server receives Datagram 1. It derives the same initial keys and
  /// generates its own keypair and shared secret to derive the handshake keys.
  final serverPrivateKey = Uint8List(32); // Generated randomly
  final serverPublicKey = derivePublicKey(serverPrivateKey);
  final sharedSecret =
      calculateSharedSecret(theirPublicKey, myPrivateKey);
  final serverHandshakeKeys = deriveHandshakeKeys(sharedSecret);

  /// ### UDP Datagram 2 & 3: Server Hello and Handshake
  /// The server sends its response, often coalescing multiple QUIC packets
  /// into single UDP datagrams to be more efficient.
  final udpDatagram2 = {
    'Description': 'Server sends Initial packet with ServerHello.',
    'Initial Packet': {
      'Header': {
        'Packet Header Byte': 0xc0,
        'QUIC Version': 0x00000001,
        'Destination Connection ID': '05' '635f636964', // Echoes client's SCID
        'Source Connection ID': '05' '735f636964', // Server's chosen ID, "s_cid"
        'Packet Length': 117,
        'Packet Number': 0,
      },
      'Decrypted Payload': {
        'ACK Frame': {'Acknowledged Packet': 0},
        'CRYPTO Frame': {'TLS Record': 'ServerHello'}
      }
    },
  };

  final udpDatagram3 = {
    'Description': 'Server sends Handshake packet with encrypted records.',
    'Handshake Packet': {
      'Header': {
        'Packet Header Byte': 0xe0, // type=Handshake
        // ... CIDs, etc ...
        'Packet Length': 1044,
        'Packet Number': 0,
      },
      'Decrypted Payload': {
        'CRYPTO Frame': {
          'TLS Records': [
            'EncryptedExtensions',
            'Certificate',
            'CertificateVerify (Part 1)',
          ]
        }
      }
    },
    // Another Handshake packet follows immediately
    'Handshake Packet 2': {
      'Header': {
        'Packet Header Byte': 0xe0,
        'Packet Number': 1,
      },
      'Decrypted Payload': {
        'CRYPTO Frame': {
          'TLS Records': [
            'CertificateVerify (Part 2)',
            'Finished',
          ]
        }
      }
    }
  };

  /// ### Client-Side Processing
  /// The client receives the server's packets, verifies the certificate,
  /// calculates the same shared secret, and derives the same handshake and
  /// application keys.
  final clientHandshakeKeys = deriveHandshakeKeys(sharedSecret);
  final clientApplicationKeys = deriveApplicationKeys(clientHandshakeKeys);

  /// ### UDP Datagram 4: Client Acks
  /// The client acknowledges the server's packets and completes its side
  /// of the handshake.
  final udpDatagram4 = {
    'Description': 'Client sends acks for Initial and Handshake packets.',
    'Initial Packet': {
      'Header': {
        'Packet Header Byte': 0xc0,
        'Packet Number': 1,
      },
      'Decrypted Payload': {'ACK Frame': {'Acknowledged Packet': 0}}
    },
    'Handshake Packet': {
      'Header': {
        'Packet Header Byte': 0xe0,
        'Packet Number': 0,
      },
      'Decrypted Payload': {'ACK Frame': {'Acknowledged Packets': '0-1'}}
    },
    'Padding': 'Padded to 1200 bytes'
  };
}

/// ## Phase 3: Application Data Exchange
void runApplicationExchange() {
  /// ### UDP Datagram 5: Client Finishes Handshake and Sends "ping"
  /// The client sends its "Finished" message and immediately follows it
  /// with the first application data packet (1-RTT).
  final udpDatagram5 = {
    'Description': 'Client sends its Finished message and first application data.',
    // Packet 1: Handshake Packet
    'Handshake Packet': {
      'Header': {
        'Packet Header Byte': 0xe0,
        'Packet Number': 1,
      },
      'Decrypted Payload': {
        'ACK Frame': {},
        'CRYPTO Frame': {'TLS Record': 'Finished'}
      }
    },
    // Packet 2: 1-RTT Application Data Packet
    'Application Packet (Short Header)': {
      'Header': {
        'Packet Header Byte': 0x40, // Short header
        'Destination Connection ID': '735f636964', // "s_cid"
        'Packet Number': 0,
      },
      'Decrypted Payload': {
        'STREAM Frame': {
          'Stream ID': 0, // First client-initiated bidirectional stream
          'Offset': 0,
          'Length': 4,
          'FIN': true,
          'Data': 'ping' // 0x70696e67
        }
      }
    }
  };

  /// ### UDP Datagram 6: Server Acknowledges and Responds with "pong"
  final udpDatagram6 = {
    'Description': 'Server acks client, confirms handshake is done, and sends "pong".',
    'Handshake Packet': {
      'Header': {
        'Packet Header Byte': 0xe0,
        'Packet Number': 2,
      },
      'Decrypted Payload': {'ACK Frame': {}}
    },
    'Application Packet (Short Header)': {
      'Header': {
        'Packet Header Byte': 0x40,
        'Destination Connection ID': '635f636964', // "c_cid"
        'Packet Number': 0,
      },
      'Decrypted Payload': {
        'ACK Frame': {},
        'HANDSHAKE_DONE Frame': {},
        'STREAM Frame': {
          'Stream ID': 0,
          'Data': 'pong' // 0x706f6e67
        }
      }
    }
  };

  /// ### UDP Datagram 7: Client Acknowledges "pong"
  final udpDatagram7 = {
    'Description': 'Client acknowledges receipt of the server\'s application data.',
    'Application Packet (Short Header)': {
      'Header': {
        'Packet Header Byte': 0x40,
        'Packet Number': 1,
      },
      'Decrypted Payload': {'ACK Frame': {'Acknowledged Packet': 0}}
    }
  };

  /// ### UDP Datagram 8: Server Closes Connection
  final udpDatagram8 = {
    'Description': 'Server gracefully closes the connection.',
    'Application Packet (Short Header)': {
      'Header': {
        'Packet Header Byte': 0x40,
        'Packet Number': 1,
      },
      'Decrypted Payload': {
        'CONNECTION_CLOSE Frame': {
          'Error Code': 'No Error',
          'Reason': 'graceful shutdown'
        }
      }
    }
  };
}


// --- Placeholder Crypto & Helper Functions ---
Uint8List hkdfExtract({required Uint8List salt, required Uint8List key}) =>
    Uint8List(32);
Uint8List hkdfExpandLabel(
        {required Uint8List key,
        required String label,
        required int length}) =>
    Uint8List(length);
Uint8List derivePublicKey(Uint8List privateKey) => Uint8List(32);
Uint8List calculateSharedSecret(Uint8List theirPublicKey, Uint8List myPrivateKey) =>
    Uint8List(32);
Map<String, dynamic> deriveHandshakeKeys(Uint8List secret) => {};
Map<String, dynamic> deriveApplicationKeys(Map<String, dynamic> handshakeKeys) =>
    {};