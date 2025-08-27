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

import "dart:typed_data";

import "../QuicConnection.dart";
import "../buffer.dart";

// import java.nio.ByteBuffer;


/**
 * Represents a QUIC version.
 */
class Version {

     static final Version IETF_draft_27 =  Version(0xff00001b);
     static final Version IETF_draft_29 =  Version(0xff00001d);
     static final Version QUIC_version_1 =  Version(0x00000001);
     static final Version QUIC_version_2 =  Version(0x6b3343cf);

    int versionId;

    static Version of(QuicConnection.QuicVersion version) {
        if (version == null) {
            return null;
        }
        switch (version) {
            case V1:
                return QUIC_version_1;
            case V2:
                return QUIC_version_2;
        }
        return null;
    }
    
    Version(this.versionId);

    Uint8List getBytes() {
        Buffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(versionId);
        return buffer.array();
    }

    static Version parse(int input) {
        return new Version(input);
    }

    static Version getDefault() {
        return QUIC_version_1;
    }

     bool isZero() {
        return versionId == 0x00000000;
    }

     bool isV1() {
        return versionId == QUIC_version_1.versionId;
    }

     bool isV2() {
        return versionId == QUIC_version_2.versionId;
    }

    /**
     * @return   true if version is V1 or V2, false otherwise.
     */
     bool isV1V2() {
        return versionId == QUIC_version_1.versionId || versionId == QUIC_version_2.versionId;
    }

    int getId() {
        return versionId;
    }

    @Override
    String toString() {
        String versionString;
        switch (versionId) {
            case 0x00000001:
                versionString = "v1";
                break;
            case 0x6b3343cf:
                versionString = "v2";
                break;
            default:
                if (versionId > 0xff000000 && versionId <= 0xff000022) {
                    versionString = "draft-" + (versionId - 0xff000000);
                }
                else {
                    versionString = "v-" + Integer.toHexString(versionId);
                }
        }
        return versionString;
    }

    @Override
     bool equals(Object o) {
        if (this == o) return true;
        if (!(o is Version)) return false;
        Version version =  o;
        return versionId == version.versionId;
    }

    @Override
    int hashCode() {
        return versionId;
    }

    QuicConnection.QuicVersion toQuicVersion() {
        if (versionId == QUIC_version_1.versionId) {
            return QuicConnection.QuicVersion.V1;
        }
        else if (versionId == QUIC_version_2.versionId) {
            return QuicConnection.QuicVersion.V2;
        }
        else {
            return null;
        }
    }
}
