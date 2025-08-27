/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.impl;

import java.util.Objects;

/**
 * Holds a reference to a version; version can be updated. Necessary for "compatible version negotiation", where the
 * QUIC version that is used by a connection can change during the negotiation.
 */
class VersionHolder {

    volatile Version version;

    VersionHolder(Version version) {
        this.version = Objects.requireNonNull(version);
    }

    Version getVersion() {
        return version;
    }

    void setVersion(Version version) {
        this.version = Objects.requireNonNull(version);
    }

    @Override
    String toString() {
        return version.toString();
    }

    static VersionHolder with(Version actualVersion) {
        return new VersionHolder(actualVersion);
    }

    static VersionHolder withDefault() {
        return new VersionHolder(Version.getDefault());
    }
}
