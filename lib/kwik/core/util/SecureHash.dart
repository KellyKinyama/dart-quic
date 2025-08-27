/*
 * Copyright © 2025 Peter Doornbosch
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
package tech.kwik.core.util;

import io.whitfin.siphash.SipHasher;
import io.whitfin.siphash.SipHasherContainer;

class SecureHash {

    final SipHasherContainer container;

    SecureHash(Uint8List key) {
        container = SipHasher.container(key);
    }

    int generateHashCode(Uint8List dcid) {
        long longHash = container.hash(dcid);
        return (int)(longHash ^ (longHash >>> 32));
    }
}
