package nrw.sit.keycloak.kerberos;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The little DER we need for Kerberos authorization data: TLV walking, context tags,
 * SEQUENCE OF, INTEGER, OCTET STRING and UTF8String. No library, no reflection, no surprises.
 */
final class Der {

    static final int TAG_INTEGER = 0x02;
    static final int TAG_OCTET_STRING = 0x04;
    static final int TAG_UTF8_STRING = 0x0C;
    static final int TAG_SEQUENCE = 0x30;

    /** One decoded TLV: the tag byte, and the value as a slice of the original buffer. */
    static final class Tlv {
        final int tag;
        final byte[] buf;
        final int start;
        final int valueOffset;
        final int valueLength;
        final int end;

        Tlv(int tag, byte[] buf, int start, int valueOffset, int valueLength) {
            this.tag = tag;
            this.buf = buf;
            this.start = start;
            this.valueOffset = valueOffset;
            this.valueLength = valueLength;
            this.end = valueOffset + valueLength;
        }

        byte[] value() {
            byte[] out = new byte[valueLength];
            System.arraycopy(buf, valueOffset, out, 0, valueLength);
            return out;
        }

        /** The complete TLV as encoded, header included. */
        byte[] encoded() {
            byte[] out = new byte[end - start];
            System.arraycopy(buf, start, out, 0, out.length);
            return out;
        }

        /** Context-specific tag number, or -1 if this is not a context-specific tag. */
        int contextTag() {
            return (tag & 0xC0) == 0x80 ? (tag & 0x1F) : -1;
        }

        /** The children of a constructed value, in order. */
        List<Tlv> children() {
            List<Tlv> out = new ArrayList<>();
            int pos = valueOffset;
            while (pos < end) {
                Tlv child = read(buf, pos, end);
                out.add(child);
                pos = child.end;
            }
            return out;
        }

        /** The single child of an explicitly tagged value ([n] EXPLICIT Type). */
        Tlv inner() {
            Tlv child = read(buf, valueOffset, end);
            if (child.end != end) {
                throw new IllegalArgumentException("explicit tag with trailing data");
            }
            return child;
        }

        int asInt() {
            if (tag != TAG_INTEGER || valueLength == 0 || valueLength > 4) {
                throw new IllegalArgumentException("not a small INTEGER (tag " + tag + ", length " + valueLength + ")");
            }
            int v = buf[valueOffset]; // sign-extends
            for (int i = 1; i < valueLength; i++) {
                v = (v << 8) | (buf[valueOffset + i] & 0xFF);
            }
            return v;
        }

        String asUtf8() {
            return new String(buf, valueOffset, valueLength, StandardCharsets.UTF_8);
        }
    }

    private Der() {
    }

    static Tlv read(byte[] buf) {
        Tlv tlv = read(buf, 0, buf.length);
        if (tlv.end != buf.length) {
            throw new IllegalArgumentException("trailing data after DER value");
        }
        return tlv;
    }

    static Tlv read(byte[] buf, int offset, int limit) {
        if (offset + 2 > limit) {
            throw new IllegalArgumentException("truncated DER header");
        }
        int tag = buf[offset] & 0xFF;
        if ((tag & 0x1F) == 0x1F) {
            throw new IllegalArgumentException("multi-byte tags are not supported");
        }
        int pos = offset + 1;
        int first = buf[pos++] & 0xFF;
        int length;
        if (first < 0x80) {
            length = first;
        } else {
            int n = first & 0x7F;
            if (n == 0 || n > 4 || pos + n > limit) {
                throw new IllegalArgumentException("unsupported DER length encoding");
            }
            length = 0;
            for (int i = 0; i < n; i++) {
                length = (length << 8) | (buf[pos++] & 0xFF);
            }
            if (length < 0) {
                throw new IllegalArgumentException("DER length overflow");
            }
        }
        if (pos + length > limit) {
            throw new IllegalArgumentException("DER value exceeds buffer");
        }
        return new Tlv(tag, buf, offset, pos, length);
    }
}
