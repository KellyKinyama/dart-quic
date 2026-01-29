import 'dart:typed_data';

import 'buffer.dart';

Uint8List create_client_hello_message()  {
        // self.expect_tls_state(TlsClientState::Uninitialized)?;

final client_hello =BytesBuilder();
        // let mut client_hello = vec![];

        // let mut cursor = Cursor::new(&mut client_hello);

        // trace!(
        //     "Creating ClientHello message at position {}",
        //     cursor.position()
        // );

        // cursor.write_u8(HandshakeType::ClientHello.)?;
        // trace!(
        //     "Wrote ClientHello message type (0x01) at position {}",
        //     cursor.position() - 1
        // );

        // Skip the packet length field
        let client_hello_len_pos = cursor.position();
        cursor.seek_relative(TLS_LENGTH_FIELD_SIZE as i64)?;
        trace!(
            "Reserved {TLS_LENGTH_FIELD_SIZE} bytes for ClientHello length at position {}",
            client_hello_len_pos
        );

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // uint16 ProtocolVersion;
        // opaque Random[32];
        // uint8 CipherSuite[2];    /* Cryptographic suite selector */
        // struct {
        //     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        //     Random random;
        //     opaque legacy_session_id<0..32>;
        //     CipherSuite cipher_suites<2..2^16-2>;
        //     opaque legacy_compression_methods<1..2^8-1>;
        //     Extension extensions<8..2^16-1>;
        // } ClientHello;

        // the legacy_version field MUST be set to 0x0303, which is the version number for TLS 1.2.
        cursor.write_u16::<BigEndian>(TLS_12_VERSION)?;
        trace!(
            "Wrote legacy_version: 0x0303 at position {}",
            cursor.position() - 2
        );

        // https://datatracker.ietf.org/doc/html/rfc8446#appendix-C
        let mut rng = rand::thread_rng();
        let client_hello_random: [u8; TLS_HANDSHAKE_RANDOM_SIZE] = rng.gen();
        cursor.write_all(&client_hello_random)?;
        trace!(
            "Wrote client random at position {}: {:02x?}",
            cursor.position() - 32,
            client_hello_random
        );
        self.client_hello_random = Some(client_hello_random);

        // Empty legacy session ID
        cursor.write_u8(0)?;
        trace!(
            "Wrote empty legacy session ID (0x00) at position {}",
            cursor.position() - 1
        );

        let cipher_suites_len = 4;
        cursor.write_u16::<BigEndian>(cipher_suites_len)?;
        trace!(
            "Wrote cipher suites length (0x{:04x}) at position {}",
            cipher_suites_len,
            cursor.position() - 2
        );

        // only support TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
        // TODO: support ChaCha20-Poly1305
        cursor.write_u16::<BigEndian>(TLS_AES_128_GCM_SHA256)?;
        cursor.write_u16::<BigEndian>(TLS_AES_256_GCM_SHA384)?;
        trace!(
            "Wrote cipher suite TLS_AES_128_GCM_SHA256(0x1301) and TLS_AES_256_GCM_SHA384 (0x1302) at position {}",
            cursor.position() - 2
        );

        // Empty legacy compression methods
        let compression_methods_len = 1;
        cursor.write_u8(compression_methods_len)?;
        cursor.write_u8(0)?;
        trace!(
            "Wrote legacy compression methods (len: 0x{:02x}, method: 0x00) at position {}",
            compression_methods_len,
            cursor.position() - 2
        );

        // TLS extensions
        let tls_extensions_len_pos = cursor.position();
        cursor.seek_relative(TLS_EXTS_LENGTH_FIELD_SIZE as i64)?;
        trace!(
            "Reserved {TLS_EXTS_LENGTH_FIELD_SIZE} bytes for extensions length at position {}",
            tls_extensions_len_pos
        );

        let tls_config = &self.tls_config;

        // ServerName extension
        trace!(
            "Writing ServerName extension for: {} at position {}",
            &tls_config.server_name,
            cursor.position()
        );
        if !tls_config.server_name.is_ascii() {
            return Err(anyhow!(
                "Invalid ssl config, server_name {} is not ASCII",
                &tls_config.server_name
            ));
        }
        cursor.write_u16::<BigEndian>(ExtensionType::ServerName.as_u16())?;
        let server_name_len = tls_config.server_name.len();
        let server_name_ext_len = server_name_len + 5;
        cursor.write_u16::<BigEndian>(server_name_ext_len as u16)?;
        let server_name_list_len = server_name_ext_len - 2;
        cursor.write_u16::<BigEndian>(server_name_list_len as u16)?;
        let server_name_host_type = 0;
        cursor.write_u8(server_name_host_type)?;
        cursor.write_u16::<BigEndian>(server_name_len as u16)?;
        cursor.write_all(tls_config.server_name.as_bytes())?;
        trace!("Completed ServerName extension");

        // SupportedGroups extension
        trace!(
            "Writing SupportedGroups extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::SupportedGroups.as_u16())?;
        let support_groups_list_len = 2;
        // Only support x25519
        let support_group = TLS_ECDH_X25519;
        let support_groups_ext_len = support_groups_list_len + 2;
        cursor.write_u16::<BigEndian>(support_groups_ext_len as u16)?;
        cursor.write_u16::<BigEndian>(support_groups_list_len as u16)?;
        cursor.write_u16::<BigEndian>(support_group)?;
        trace!("Added x25519 (0x001d) to supported groups");

        // ALPN protocol names are ASCII strings, as defined by [RFC-1123].
        // The protocol names are case-sensitive, and must be valid UTF-8 sequences that are compatible with ASCII.
        trace!(
            "Writing ALPN protocol {} extension at position {}",
            tls_config.alpn,
            cursor.position()
        );
        cursor
            .write_u16::<BigEndian>(ExtensionType::ApplicationLayerProtocolNegotiation.as_u16())?;
        if !tls_config.alpn.is_ascii() {
            return Err(anyhow!(
                "Invalid ssl config, alpn {} is not ASCII",
                &tls_config.alpn
            ));
        }
        let alpn_len = tls_config.alpn.len();
        let alpn_ext_len = alpn_len + 1;
        let alpn_ext_len_dup = alpn_ext_len + 2;
        cursor.write_u16::<BigEndian>(alpn_ext_len_dup as u16)?;
        cursor.write_u16::<BigEndian>(alpn_ext_len as u16)?;
        cursor.write_u8(alpn_len as u8)?;
        cursor.write_all(tls_config.alpn.as_bytes())?;
        trace!("Completed ALPN extension");

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
        // only plan to support the signature algorithms were chosen by the certificate which is used in my blog
        trace!(
            "Writing SignatureAlgorithms extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::SignatureAlgorithms.as_u16())?;
        // SHA256 + ECDSA
        let sha256_ecd_algorithms = 0x0403;
        let sha256_rsa_algorithms = 0x0804;
        let algo_len = 2 + 2;
        let algo_ext_len = algo_len + 2;
        cursor.write_u16::<BigEndian>(algo_ext_len as u16)?;
        cursor.write_u16::<BigEndian>(algo_len as u16)?;
        cursor.write_u16::<BigEndian>(sha256_ecd_algorithms)?;
        cursor.write_u16::<BigEndian>(sha256_rsa_algorithms)?;
        trace!("Added SHA256+ECDSA (0x0403) and SHA256+RSA (0x0804) to signature algorithms");

        // Since we only support x25519, we need to generate our keyshare for ECDH exchange
        // by the way, x25519 is an implementation for ECDH by using Curve 25519
        trace!(
            "Writing KeyShare extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::KeyShare.as_u16())?;
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|e| anyhow!("Ring failed to generate private key due to {e}"))?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|e| anyhow!("Ring failed to compute public key due to {e}"))?;
        let public_key_len = public_key.as_ref().len();
        let group = 0x001d; // x25519
        let key_share_len = public_key_len + 4;
        let key_share_ext_len = public_key_len + 6;
        cursor.write_u16::<BigEndian>(key_share_ext_len as u16)?;
        cursor.write_u16::<BigEndian>(key_share_len as u16)?;
        cursor.write_u16::<BigEndian>(group)?;
        cursor.write_u16::<BigEndian>(public_key_len as u16)?;
        cursor.write_all(public_key.as_ref())?;
        self.private_key = Some(private_key);

        // TODO: 0-RTT
        // If clients offer "pre_shared_key" without a "psk_key_exchange_modes" extension,
        // servers MUST abort the handshake
        // cursor.write_u16::<BigEndian>(ExtensionType::PskKeyExchangeModes.as_u16())?;
        // cursor.write_u16::<BigEndian>(ExtensionType::PreSharedKey.as_u16())?;

        // SupportedVersions extension
        trace!(
            "Writing SupportedVersions extension at position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::SupportedVersions.as_u16())?;
        let support_versions_list_len = 2;
        let support_version = 0x0304;
        let support_versions_ext_len = support_versions_list_len + 1;
        cursor.write_u16::<BigEndian>(support_versions_ext_len as u16)?;
        cursor.write_u8(support_versions_list_len as u8)?;
        cursor.write_u16::<BigEndian>(support_version)?;
        trace!("Added TLS 1.3 (0x0304) to supported versions");

        // Constructing QUIC tls extension
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-8.2
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18
        trace!(
            "Writing QUIC Transport Parameters extension at start position {}",
            cursor.position()
        );
        cursor.write_u16::<BigEndian>(ExtensionType::QuicTransportParameters.as_u16())?;
        let quic_tp_len_pos = cursor.position();
        cursor.seek_relative(TLS_QUIC_EXT_LENGTH_FIELD_SIZE as i64)?;
        self.transport_parameters_serialize(&mut cursor)?;
        trace!(
            "Completed QUIC transport parameters at position {}",
            cursor.position()
        );

        let cur_pos = cursor.position();
        let quic_ext_len = cur_pos - quic_tp_len_pos - TLS_QUIC_EXT_LENGTH_FIELD_SIZE as u64;
        write_cursor_bytes_with_pos(
            &mut cursor,
            quic_tp_len_pos,
            &u16::to_be_bytes(quic_ext_len as u16),
        )?;
        trace!(
            "Wrote QUIC extension length: {} at position {}",
            quic_ext_len,
            quic_tp_len_pos
        );

        let tls_exts_len = cur_pos - tls_extensions_len_pos - TLS_EXTS_LENGTH_FIELD_SIZE as u64;
        write_cursor_bytes_with_pos(
            &mut cursor,
            tls_extensions_len_pos,
            &u16::to_be_bytes(tls_exts_len as u16),
        )?;

        trace!(
            "Wrote total extensions length: {} at position {}",
            tls_exts_len,
            tls_extensions_len_pos
        );

        let client_hello_len = cur_pos - client_hello_len_pos - TLS_LENGTH_FIELD_SIZE as u64;
        let client_hello_len_bytes = &u32::to_be_bytes(client_hello_len as u32)[1..];
        write_cursor_bytes_with_pos(&mut cursor, client_hello_len_pos, client_hello_len_bytes)?;
        trace!(
            "Wrote total ClientHello length: {} at position {}, length hex data {:x?}",
            client_hello_len,
            client_hello_len_pos,
            client_hello_len_bytes,
        );

        trace!("Completed ClientHello packet, final position: {}", cur_pos);
        // Save the client hello message since the peer's cipher suite choice is unknown at this point
        self.client_hello_message = Some(cursor.get_ref()[..cursor.position() as usize].to_vec());

        self.state = TlsClientState::WaitServerHello;

        Ok(client_hello)
    }