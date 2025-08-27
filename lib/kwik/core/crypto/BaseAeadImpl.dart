/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.crypto;

import at.favre.lib.hkdf.HKDF;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import static tech.kwik.core.impl.Role.Client;

abstract class BaseAeadImpl implements Aead {

    static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    // https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection-keys
    // "The current encryption level secret and the label "quic key" are input to the KDF to produce the AEAD key; the
    //  label "quic iv" is used to derive the Initialization Vector (IV); see Section 5.3. The header protection key
    //  uses the "quic hp" label; see Section 5.4. Using these labels provides key separation between QUIC and TLS;
    //  see Section 9.6."
    static final String QUIC_V1_KDF_LABEL_PREFIX = "quic ";

    // https://www.rfc-editor.org/rfc/rfc9369.html#name-hmac-based-key-derivation-f
    // "The labels used in [QUIC-TLS] to derive packet protection keys (Section 5.1), header protection keys (Section 5.4),
    //  Retry Integrity Tag keys (Section 5.8), and key updates (Section 6.1) change from "quic key" to "quicv2 key",
    //  from "quic iv" to "quicv2 iv", from "quic hp" to "quicv2 hp", and from "quic ku" to "quicv2 ku", to meet the
    //  guidance for new versions in Section 9.6 of that document."
    static final String QUIC_V2_KDF_LABEL_PREFIX = "quicv2 ";

    final Role nodeRole;
    final Logger log;
    final Version quicVersion;

    Uint8List trafficSecret;
    Uint8List newApplicationTrafficSecret;
    Uint8List writeKey;
    Uint8List newKey;
    Uint8List writeIV;
    Uint8List newIV;
    Uint8List hp;
    Cipher hpCipher;
    SecretKeySpec writeKeySpec;
    SecretKeySpec newWriteKeySpec;
    Cipher writeCipher;
    int keyUpdateCounter = 0;
     bool possibleKeyUpdateInProgresss = false;
    volatile Aead peerAead;

    BaseAeadImpl(Version quicVersion, Role nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;
    }

    BaseAeadImpl(Version quicVersion, Uint8List initialSecret, Role nodeRole, Logger log) {
        this.nodeRole = nodeRole;
        this.log = log;
        this.quicVersion = quicVersion;

        Uint8List initialNodeSecret = hkdfExpandLabel(quicVersion, initialSecret, nodeRole == Client? "client in": "server in", "", (short) getHashLength());
        log.secret(nodeRole + " initial secret", initialNodeSecret);

        computeKeys(initialNodeSecret, true, true);
    }

    abstract short getKeyLength();

    abstract short getHashLength();

    abstract HKDF getHKDF();

    @Override
    synchronized void computeKeys(Uint8List trafficSecret) {
        this.trafficSecret = trafficSecret;
        computeKeys(trafficSecret, true, true);
    }

    /**
     * Compute new keys. Note that depending on the role of this Keys object, computing new keys concerns updating
     * the write secrets (role that initiates the key update) or the read secrets (role that responds to the key update).
     * @param selfInitiated        true when this role initiated the key update, so updating write secrets.
     */
    @Override
    synchronized void computeKeyUpdate( bool selfInitiated) {
        String prefix = quicVersion.isV2()? QUIC_V2_KDF_LABEL_PREFIX: QUIC_V1_KDF_LABEL_PREFIX;
        newApplicationTrafficSecret = hkdfExpandLabel(quicVersion, trafficSecret, prefix + "ku", "", getHashLength());
        log.secret("Updated ApplicationTrafficSecret (" + (selfInitiated? "self":"peer") + "): ", newApplicationTrafficSecret);
        computeKeys(newApplicationTrafficSecret, false, selfInitiated);
        if (selfInitiated) {
            // If updating this Keys object was self initiated, the new keys can be installed immediately.
            trafficSecret = newApplicationTrafficSecret;
            keyUpdateCounter++;
            newApplicationTrafficSecret = null;
        }
        // Else, updating this Keys object was initiated by receiving a packet with different key phase, and the new keys
        // can only be installed permanently if the decryption of the packet (that introduced the new key phase) has succeeded.
    }

    /**
     * Confirm that, if a key update was in progress, it has been successful and thus the new keys can (and should) be
     * used for decrypting all incoming packets.
     */
    @Override
    synchronized void confirmKeyUpdateIfInProgress() {
        if (possibleKeyUpdateInProgresss) {
            log.info("Installing updated keys (initiated by peer)");
            trafficSecret = newApplicationTrafficSecret;
            writeKey = newKey;
            writeKeySpec = null;
            writeIV = newIV;
            keyUpdateCounter++;
            newApplicationTrafficSecret = null;
            possibleKeyUpdateInProgresss = false;
            newKey = null;
            newIV = null;
            checkPeerKeys();
        }
    }

    @Override
    int getKeyUpdateCounter() {
        return keyUpdateCounter;
    }

    /**
     * In case keys are updated, check if the peer keys are already updated too (which depends on who initiated the
     * key update).
     */
    void checkPeerKeys() {
        if (peerAead.getKeyUpdateCounter() < keyUpdateCounter) {
            log.debug("Keys out of sync; updating keys for peer");
            peerAead.computeKeyUpdate(true);
        }
    }

    /**
     * Confirm that, if a key update was in progress, it has been unsuccessful and thus the new keys should not be
     * used for decrypting all incoming packets.
     */
    @Override
    synchronized void cancelKeyUpdateIfInProgress() {
        if (possibleKeyUpdateInProgresss) {
            log.info("Discarding updated keys (initiated by peer)");
            newApplicationTrafficSecret = null;
            possibleKeyUpdateInProgresss = false;
            newKey = null;
            newIV = null;
        }
    }

    void computeKeys(Uint8List secret,  bool includeHP,  bool replaceKeys) {
        String labelPrefix = quicVersion.isV2()? QUIC_V2_KDF_LABEL_PREFIX: QUIC_V1_KDF_LABEL_PREFIX;

        // https://tools.ietf.org/html/rfc8446#section-7.3
        Uint8List key = hkdfExpandLabel(quicVersion, secret, labelPrefix + "key", "", getKeyLength());
        if (replaceKeys) {
            writeKey = key;
            writeKeySpec = null;
        }
        else {
            newKey = key;
            newWriteKeySpec = null;
        }
        log.secret(nodeRole + " key", key);

        Uint8List iv = hkdfExpandLabel(quicVersion, secret, labelPrefix + "iv", "", (short) 12);
        if (replaceKeys) {
            writeIV = iv;
        }
        else {
            newIV = iv;
        }
        log.secret(nodeRole + " iv", iv);

        if (includeHP) {
            // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-5.1
            // "The header protection key uses the "quic hp" label"
            hp = hkdfExpandLabel(quicVersion, secret, labelPrefix + "hp", "", getKeyLength());
            log.secret(nodeRole + " hp", hp);
        }
    }

    // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
    Uint8List hkdfExpandLabel(Version quicVersion, Uint8List secret, String label, String context, short length) {

        Uint8List prefix = "tls13 ".getBytes(ISO_8859_1);

        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + prefix.length + label.getBytes(ISO_8859_1).length + 1 + context.getBytes(ISO_8859_1).length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (prefix.length + label.getBytes().length));
        hkdfLabel.put(prefix);
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.getBytes(ISO_8859_1).length));
        hkdfLabel.put(context.getBytes(ISO_8859_1));
        HKDF hkdf = getHKDF();
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

    @Override
    Uint8List getTrafficSecret() {
        return trafficSecret;
    }

    @Override
    Uint8List getWriteIV() {
        if (possibleKeyUpdateInProgresss) {
            return newIV;
        }
        return writeIV;
    }

    Uint8List getHp() {
        return hp;
    }

    abstract Cipher getHeaderProtectionCipher();

    abstract SecretKeySpec getWriteKeySpec();

    abstract Cipher getWriteCipher();

    short getKeyPhase() {
        return (short) (keyUpdateCounter % 2);
    }

    /**
     * Check whether the key phase carried by a received packet still matches the current key phase; if not, compute
     * new keys (to be used for decryption). Note that the changed key phase can also be caused by packet corruption,
     * so it is not yet sure whether a key update is really in progress (this will be sure when decryption of the packet
     * failed or succeeded).
     * @param keyPhaseBit
     */
    void checkKeyPhase(short keyPhaseBit) {
        if ((keyUpdateCounter % 2) != keyPhaseBit) {
            if (newKey == null) {
                computeKeyUpdate(false);
                log.secret("Computed new (updated) key", newKey);
                log.secret("Computed new (updated) iv", newIV);
            }
            log.info("Received key phase does not match current => possible key update in progress");
            possibleKeyUpdateInProgresss = true;
        }
    }

    @Override
    void setPeerAead(Aead peerAead) {
        this.peerAead = peerAead;
    }
}
