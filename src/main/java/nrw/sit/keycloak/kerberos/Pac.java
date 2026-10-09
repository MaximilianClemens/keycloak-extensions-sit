package nrw.sit.keycloak.kerberos;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Windows Privilege Attribute Certificate (MS-PAC): the buffer table, the server signature
 * and the parts of {@code KERB_VALIDATION_INFO} (NDR encoded) we need, namely the group SIDs,
 * the user account control flags and the account name.
 *
 * The NDR decoding follows MS-PAC 2.5 / MS-RPCE: 4-byte aligned fields, pointers as 4-byte
 * referent ids, deferred referents in the order the pointers appear, conformant/varying
 * arrays with their {@code MaxCount}/{@code Offset}/{@code ActualCount} headers.
 */
public final class Pac {

    public static final int LOGON_INFO = 1;
    public static final int SERVER_CHECKSUM = 6;
    public static final int KDC_CHECKSUM = 7;
    public static final int CLIENT_INFO = 10;
    public static final int UPN_DNS_INFO = 12;

    /** USER_SMARTCARD_REQUIRED in {@code KERB_VALIDATION_INFO.UserAccountControl} (MS-SAMR 2.2.1.12). */
    public static final int UAC_SMARTCARD_REQUIRED = 0x00001000;

    private final byte[] raw;
    private final Map<Integer, byte[]> buffers = new LinkedHashMap<>();
    private final Map<Integer, Integer> bufferOffsets = new LinkedHashMap<>();

    private Pac(byte[] raw) {
        this.raw = raw;
    }

    public static Pac parse(byte[] raw) {
        Pac pac = new Pac(raw);
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        if (raw.length < 8) {
            throw new IllegalArgumentException("PAC too short");
        }
        int count = bb.getInt();
        int version = bb.getInt();
        if (version != 0 || count < 0 || count > 64 || 8 + count * 16L > raw.length) {
            throw new IllegalArgumentException("PAC header invalid (version " + version + ", " + count + " buffers)");
        }
        for (int i = 0; i < count; i++) {
            int type = bb.getInt();
            int size = bb.getInt();
            long offset = bb.getLong();
            if (size < 0 || offset < 0 || offset + size > raw.length) {
                throw new IllegalArgumentException("PAC buffer " + type + " out of range");
            }
            byte[] data = new byte[size];
            System.arraycopy(raw, (int) offset, data, 0, size);
            pac.buffers.put(type, data);
            pac.bufferOffsets.put(type, (int) offset);
        }
        return pac;
    }

    public boolean has(int type) {
        return buffers.containsKey(type);
    }

    public byte[] buffer(int type) {
        return buffers.get(type);
    }

    // ── signatures ──────────────────────────────────────────────────────────

    /** Signature type of the server checksum buffer, or -1 if absent. */
    public int serverSignatureType() {
        byte[] sig = buffers.get(SERVER_CHECKSUM);
        return sig == null ? -1 : ByteBuffer.wrap(sig).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /**
     * Verifies the server signature (MS-PAC 2.8.2): the checksum under the service key with
     * key usage 17 over the whole PAC, with the signature fields of both checksum buffers zeroed.
     *
     * @param serviceKey the long-term key of the service principal matching the signature type
     * @return true if the signature matches
     */
    public boolean verifyServerSignature(byte[] serviceKey) {
        byte[] sig = buffers.get(SERVER_CHECKSUM);
        byte[] kdcSig = buffers.get(KDC_CHECKSUM);
        if (sig == null || sig.length < 4) {
            return false;
        }
        int type = serverSignatureType();
        byte[] expected = new byte[sig.length - 4];
        System.arraycopy(sig, 4, expected, 0, expected.length);

        byte[] zeroed = raw.clone();
        zeroSignature(zeroed, bufferOffsets.get(SERVER_CHECKSUM), sig.length);
        if (kdcSig != null) {
            zeroSignature(zeroed, bufferOffsets.get(KDC_CHECKSUM), kdcSig.length);
        }
        try {
            return KerberosChecksum.verify(type, serviceKey, KerberosChecksum.KEY_USAGE_PAC_SIGNATURE, zeroed, expected);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void zeroSignature(byte[] data, int offset, int length) {
        // keep SignatureType (4 bytes), zero the signature itself
        for (int i = offset + 4; i < offset + length; i++) {
            data[i] = 0;
        }
    }

    // ── KERB_VALIDATION_INFO ────────────────────────────────────────────────

    /** The decoded parts of the logon information, or null if the PAC has no such buffer. */
    public LogonInfo logonInfo() {
        byte[] data = buffers.get(LOGON_INFO);
        return data == null ? null : LogonInfo.decode(data);
    }

    public static final class LogonInfo {
        public final String effectiveName;
        public final String logonDomainName;
        public final String logonDomainSid;
        public final int userId;
        public final int primaryGroupId;
        public final int userAccountControl;
        /** All group SIDs: domain groups (LogonDomainId + RID), extra SIDs and resource groups. */
        public final List<String> groupSids;

        LogonInfo(String effectiveName, String logonDomainName, String logonDomainSid, int userId,
                  int primaryGroupId, int userAccountControl, List<String> groupSids) {
            this.effectiveName = effectiveName;
            this.logonDomainName = logonDomainName;
            this.logonDomainSid = logonDomainSid;
            this.userId = userId;
            this.primaryGroupId = primaryGroupId;
            this.userAccountControl = userAccountControl;
            this.groupSids = Collections.unmodifiableList(groupSids);
        }

        public boolean smartcardRequired() {
            return (userAccountControl & UAC_SMARTCARD_REQUIRED) != 0;
        }

        static LogonInfo decode(byte[] data) {
            Ndr ndr = new Ndr(data);
            ndr.typeSerializationHeader();
            int infoPtr = ndr.u32();          // KERB_VALIDATION_INFO*
            if (infoPtr == 0) {
                throw new IllegalArgumentException("null KERB_VALIDATION_INFO pointer");
            }

            ndr.skip(6 * 8);                   // six FILETIMEs
            int[] nameRefs = new int[6];       // EffectiveName .. HomeDirectoryDrive
            for (int i = 0; i < 6; i++) {
                nameRefs[i] = ndr.unicodeStringHeader();
            }
            ndr.u16();                         // LogonCount
            ndr.u16();                         // BadPasswordCount
            int userId = ndr.u32();
            int primaryGroupId = ndr.u32();
            int groupCount = ndr.u32();
            int groupIdsPtr = ndr.u32();
            ndr.u32();                         // UserFlags
            ndr.skip(16);                      // UserSessionKey
            int logonServerRef = ndr.unicodeStringHeader();
            int logonDomainNameRef = ndr.unicodeStringHeader();
            int logonDomainIdPtr = ndr.u32();
            ndr.skip(8);                       // Reserved1
            int userAccountControl = ndr.u32();
            ndr.u32();                         // SubAuthStatus
            ndr.skip(8);                       // LastSuccessfulILogon
            ndr.skip(8);                       // LastFailedILogon
            ndr.u32();                         // FailedILogonCount
            ndr.u32();                         // Reserved3
            int sidCount = ndr.u32();
            int extraSidsPtr = ndr.u32();
            int resourceGroupDomainSidPtr = ndr.u32();
            int resourceGroupCount = ndr.u32();
            int resourceGroupIdsPtr = ndr.u32();

            // deferred referents, in pointer order
            String[] names = new String[6];
            for (int i = 0; i < 6; i++) {
                names[i] = nameRefs[i] != 0 ? ndr.unicodeStringBody() : "";
            }
            List<Integer> groupRids = new ArrayList<>();
            if (groupIdsPtr != 0) {
                int max = ndr.u32();
                checkCount(max, groupCount, "GroupIds");
                for (int i = 0; i < max; i++) {
                    groupRids.add(ndr.u32());
                    ndr.u32();                 // Attributes
                }
            }
            if (logonServerRef != 0) {
                ndr.unicodeStringBody();
            }
            String logonDomainName = logonDomainNameRef != 0 ? ndr.unicodeStringBody() : "";
            String logonDomainSid = logonDomainIdPtr != 0 ? ndr.sid() : null;

            List<String> groupSids = new ArrayList<>();
            for (int rid : groupRids) {
                groupSids.add(logonDomainSid + "-" + Integer.toUnsignedString(rid));
            }
            if (extraSidsPtr != 0) {
                int max = ndr.u32();
                checkCount(max, sidCount, "ExtraSids");
                int[] sidPtrs = new int[max];
                for (int i = 0; i < max; i++) {
                    sidPtrs[i] = ndr.u32();
                    ndr.u32();                 // Attributes
                }
                for (int i = 0; i < max; i++) {
                    if (sidPtrs[i] != 0) {
                        groupSids.add(ndr.sid());
                    }
                }
            }
            String resourceDomainSid = resourceGroupDomainSidPtr != 0 ? ndr.sid() : null;
            if (resourceGroupIdsPtr != 0) {
                int max = ndr.u32();
                checkCount(max, resourceGroupCount, "ResourceGroupIds");
                for (int i = 0; i < max; i++) {
                    int rid = ndr.u32();
                    ndr.u32();                 // Attributes
                    if (resourceDomainSid != null) {
                        groupSids.add(resourceDomainSid + "-" + Integer.toUnsignedString(rid));
                    }
                }
            }
            return new LogonInfo(names[0], logonDomainName, logonDomainSid, userId, primaryGroupId,
                    userAccountControl, groupSids);
        }

        private static void checkCount(int max, int declared, String what) {
            if (max < 0 || max > 4096 || max != declared) {
                throw new IllegalArgumentException(what + ": array count " + max + " does not match " + declared);
            }
        }
    }

    /** Minimal NDR (MS-RPCE) reader for the parts of KERB_VALIDATION_INFO we decode. */
    static final class Ndr {
        private final ByteBuffer bb;

        Ndr(byte[] data) {
            this.bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        }

        /** MS-RPCE 2.2.6: common type header (8 bytes) + private header (8 bytes). */
        void typeSerializationHeader() {
            int version = bb.get() & 0xFF;
            int endianness = bb.get() & 0xFF;
            bb.getShort();                     // common header length
            bb.getInt();                       // filler
            bb.getInt();                       // object buffer length
            bb.getInt();                       // filler
            if (version != 1 || endianness != 0x10) {
                throw new IllegalArgumentException("unsupported NDR type serialization header");
            }
        }

        int u16() {
            align(2);
            return bb.getShort() & 0xFFFF;
        }

        int u32() {
            align(4);
            return bb.getInt();
        }

        void skip(int n) {
            bb.position(bb.position() + n);
        }

        void align(int n) {
            int rem = bb.position() % n;
            if (rem != 0) {
                bb.position(bb.position() + (n - rem));
            }
        }

        /** RPC_UNICODE_STRING header: Length, MaximumLength, Buffer pointer. Returns the pointer. */
        int unicodeStringHeader() {
            u16();
            u16();
            return u32();
        }

        /** Deferred body of a unicode string: MaxCount, Offset, ActualCount (in WCHARs), chars. */
        String unicodeStringBody() {
            int max = u32();
            int offset = u32();
            int actual = u32();
            if (actual < 0 || actual > max || actual > 32768 || offset != 0) {
                throw new IllegalArgumentException("unicode string header invalid");
            }
            byte[] chars = new byte[actual * 2];
            bb.get(chars);
            String s = new String(chars, StandardCharsets.UTF_16LE);
            align(4);
            return s;
        }

        /** RPC_SID: MaxCount (= SubAuthorityCount), Revision, SubAuthorityCount, IdentifierAuthority, SubAuthority[]. */
        String sid() {
            int max = u32();
            int revision = bb.get() & 0xFF;
            int count = bb.get() & 0xFF;
            if (revision != 1 || count != max || count > 15) {
                throw new IllegalArgumentException("SID header invalid");
            }
            long authority = 0;
            for (int i = 0; i < 6; i++) {
                authority = (authority << 8) | (bb.get() & 0xFF);
            }
            StringBuilder sb = new StringBuilder("S-1-").append(authority);
            for (int i = 0; i < count; i++) {
                sb.append('-').append(Integer.toUnsignedString(bb.getInt()));
            }
            align(4);
            return sb.toString();
        }
    }
}
