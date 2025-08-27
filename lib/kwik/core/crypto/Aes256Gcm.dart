/*
 * Copyright © 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.crypto;

import at.favre.lib.hkdf.HKDF;
import at.favre.lib.hkdf.HkdfMacFactory;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

/**
 * https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
 * "QUIC can use any of the cipher suites defined in [TLS13] with the exception of TLS_AES_128_CCM_8_SHA256."
 * https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
 * "The corresponding AEAD algorithms (...), AEAD_AES_256_GCM, (...) are defined in [RFC5116]."
 */
class Aes256Gcm extends Aes128Gcm {

    Aes256Gcm(Version quicVersion, Role nodeRole, Logger log) {
        super(quicVersion, nodeRole, log);
    }

    @Override
    short getKeyLength() {
        return 32;
    }

    @Override
    short getHashLength() {
        return 48;
    }

    @Override
    HKDF getHKDF() {
        return HKDF.from(new HkdfMacFactory.Default("HmacSHA384", null));
    }
}
