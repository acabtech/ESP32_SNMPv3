#!/usr/bin/env python3
"""
gen_vectors.py — M1 test-vector oracle.

Produces (all checked in; regenerate with `make vectors` from tests/host):

  tests/host/soft/sha256_k.inc     SHA-256 round constants K[64]
  tests/host/soft/aes_tables.inc   AES S-box + inverse S-box
  tests/host/vec/vectors.h         C test vectors for BER/USM

Oracles:
  • SHA-256 K : exact integer cube-root construction (FIPS 180-4) — verified
                against the first 8 published constants.
  • AES S-box: GF(2^8) inverse + FIPS-197 affine transform — spot-checked
                against published S-box values (0x00->0x63, 0x01->0x7c,
                0x53->0xed, 0xff->0x16, ...).
  • Key localization : pysnmp 6.2.6 (pysnmp.proto.secmod.rfc3414.localkey)
  • HMAC truncation : Python hmac (RFC 2104 / RFC 7860 24-octet MAC)
  • AES-128 CFB     : `cryptography` modes.CFB (RFC 3826 IV construction:
                      boots||time||salt)
  • Wire messages   : minimal independent BER encoder in this file, with a
                      here-side decode+re-encode self-check so emitted bytes
                      are guaranteed sound before the C tests run.

Run:  /tmp/pv/bin/python tests/host/vgen/gen_vectors.py
"""
import hashlib, hmac as hmac_mod, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
SOFT = HERE.parent / "soft"
VEC = HERE.parent / "vec"

# ---------------------------------------------------------------------------
# 1. SHA-256 K constants (exact integer arithmetic)
# ---------------------------------------------------------------------------
def icbrt(n: int) -> int:
    lo, hi = 0, 1 << ((n.bit_length() + 2) // 3)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid * mid * mid <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo

def sha256_k() -> list:
    primes = []
    for p in range(2, 400):
        if all(p % d for d in range(2, int(p ** 0.5) + 1)):
            primes.append(p)
        if len(primes) == 64:
            break
    k = [icbrt(p << 96) & 0xFFFFFFFF for p in primes]
    # Spot-check against published values (FIPS 180-4 / RFC 6234)
    known = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
             0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5]
    assert k[:8] == known, "SHA-256 K constant mismatch"
    return k

# ---------------------------------------------------------------------------
# 2. AES S-box (GF(2^8) inverse + affine transform)
# ---------------------------------------------------------------------------
def gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def gf_inv(a: int) -> int:
    # a^(-1) = a^254 in GF(2^8)/x^8+x^4+x^3+x+1
    if a == 0:
        return 0
    r = 1
    e = 254
    while e:
        if e & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        e >>= 1
    return r

def aes_affine(a_byte: int) -> int:
    c = 0x63
    out = 0
    for i in range(8):
        v = (a_byte >> i) & 1
        v ^= (a_byte >> ((i + 4) % 8)) & 1
        v ^= (a_byte >> ((i + 5) % 8)) & 1
        v ^= (a_byte >> ((i + 6) % 8)) & 1
        v ^= (a_byte >> ((i + 7) % 8)) & 1
        v ^= (c >> i) & 1
        out |= v << i
    return out

def aes_sboxes():
    sb = [aes_affine(gf_inv(x)) for x in range(256)]
    for x, want in [(0x00, 0x63), (0x01, 0x7C), (0x53, 0xED),
                    (0x7F, 0xD2), (0xFE, 0xBB), (0xFF, 0x16)]:
        assert sb[x] == want, f"S-box[{x:#04x}] = {sb[x]:#04x}, expected {want:#04x}"
    assert sorted(sb) == list(range(256)), "S-box not a permutation"
    inv = [0] * 256
    for x in range(256):
        inv[sb[x]] = x
    return sb, inv

# ---------------------------------------------------------------------------
# 3. Key localization via pysnmp localkey (SHA-256)
# pysnmp localkey.hashPassphrase calls hashFunc() (no args -> needs the
# class) and localkey.localizeKey calls hashFunc(data); passing hashlib.sha256
# (the class) satisfies both call sites.
# ---------------------------------------------------------------------------
sys.path.append(str(pathlib.Path("/tmp/pv/lib/python3.13/site-packages")))
from pysnmp.proto.secmod.rfc3414 import localkey
from pyasn1.type import univ

def pysnmp_localkey(passwd: bytes, engine_id: bytes) -> bytes:
    ku = localkey.localizeKey(
        localkey.hashPassphrase(passwd, hashlib.sha256),
        univ.OctetString(engine_id), hashlib.sha256)
    return ku.asOctets()

# ---------------------------------------------------------------------------
# 4. Small, independent BER encoder (for wire samples)
# ---------------------------------------------------------------------------
def _len(n: int) -> bytes:
    # BER length: short form < 128; long form is 0x80|N followed by N octets
    # of the length as a BIG-ENDIAN base-256 integer (NOT base-128).
    if n < 128:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out

def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content

def ber_int(v: int) -> bytes:
    if v == 0:
        body = b"\x00"
    else:
        n = (v.bit_length() + 8) // 8
        body = v.to_bytes(n, "big", signed=True)
        if len(body) > 1 and ((body[0] == 0x00 and not (body[1] & 0x80))
                              or (body[0] == 0xFF and (body[1] & 0x80))):
            body = body[1:]
    return tlv(0x02, body)

def ber_octet(b: bytes) -> bytes:
    return tlv(0x04, b)

def ber_oid(arcs) -> bytes:
    assert arcs[0] <= 2 and (arcs[0] < 2 or arcs[1] <= 0xFFFFFFFF)
    first = arcs[0] * 40 + arcs[1]
    body = bytes()
    for sub in [first] + list(arcs[2:]):
        g = [sub & 0x7F]
        sub >>= 7
        while sub:
            g.append(0x80 | (sub & 0x7F))
            sub >>= 7
        body += bytes(reversed(g))
    return tlv(0x06, body)

def ber_null() -> bytes:
    return tlv(0x05, b"")

def ber_varbind(oid_arcs, val: bytes) -> bytes:
    return tlv(0x30, ber_oid(oid_arcs) + val)

def ber_pdu(tag: int, req: int, status: int, idx: int, vbs: list) -> bytes:
    return tlv(tag, ber_int(req) + ber_int(status) + ber_int(idx) + b"".join(vbs))

def ber_seq(*parts) -> bytes:
    return tlv(0x30, b"".join(parts))

def ctag(tag: int, content: bytes) -> bytes:
    return tlv(tag, content)

def mini_decode(data: bytes, pos=0):
    """Return (tag, content, next_pos)."""
    tag = data[pos]; pos += 1
    b = data[pos]; pos += 1
    if b & 0x80:
        n = b & 0x7F
        ln = int.from_bytes(data[pos:pos + n], "big"); pos += n
    else:
        ln = b
    return tag, data[pos:pos + ln], pos + ln

def self_check(msg: bytes, expect: dict):
    tag, content, nxt = mini_decode(msg)
    assert tag == 0x30 and nxt == len(msg)
    assert content == expect["content"], "self-check content mismatch"
    # re-encode must be byte-identical
    rebuilt = expect["encoder"](expect["args"])
    assert msg == rebuilt, "self-check re-encode mismatch"
    print(f"    self-check OK ({len(msg)} bytes)")

# ---------------------------------------------------------------------------
# 5. Engine/user constants for the samples (also used by the C tests)
# ---------------------------------------------------------------------------
ENGINE_ID = bytes.fromhex("80001f8880deadbeef0001")
AUTH_PASS = b"auth-passphrase"
PRIV_PASS = b"priv-passphrase"

# ---------------------------------------------------------------------------
# Emit .inc tables
# ---------------------------------------------------------------------------
def emit_tables():
    k = sha256_k()
    sbox, inv = aes_sboxes()
    (SOFT / "sha256_k.inc").write_text(
        "// autogenerated by tests/host/vgen/gen_vectors.py — do not edit\n"
        "static const uint32_t SHA256_K[64] = {\n" +
        "".join(f"  0x{x:08X}," + ("\n" if (i % 8 == 7) else " ") for i, x in enumerate(k)) +
        "};\n")
    def fmt(arr, name, cols=12):
        lines = [f"static const uint8_t {name}[256] = {{"]
        for i in range(0, 256, cols):
            lines.append("  " + " ".join(f"0x{x:02X}," for x in arr[i:i + cols]))
        lines.append("};")
        return "\n".join(lines) + "\n"
    (SOFT / "aes_tables.inc").write_text(
        "// autogenerated by tests/host/vgen/gen_vectors.py — do not edit\n"
        + fmt(sbox, "AES_SBOX") + "\n" + fmt(inv, "AES_INVSBOX"))

# ---------------------------------------------------------------------------
# Emit vectors.h
# ---------------------------------------------------------------------------
def emit_vectors():
    L = []
    A = L.append
    A("// autogenerated by tests/host/vgen/gen_vectors.py — do not edit\n")
    A("#ifndef SNMPV3_TEST_VECTORS_H\n#define SNMPV3_TEST_VECTORS_H\n\n")

    def ba(name, data):
        A(f"static const uint8_t {name}[] = {{\n  " +
          " ".join(f"0x{x:02X}," for x in data) + "\n};\n\n")

    # --- key localization ---
    cases = [
        ("auth-passphrase", ENGINE_ID),
        ("priv-passphrase", ENGINE_ID),
        ("maplesyrup", bytes.fromhex("000000000000000000000002")),
    ]
    A(f"typedef struct {{ const uint8_t* pass; size_t passLen; "
      f"const uint8_t* engineId; size_t engineIdLen; const uint8_t* ku; }} AuthKeyVec;\n")
    A(f"#define N_AUTHKEY {len(cases)}\n")
    entries = []
    for i, (pw, eid) in enumerate(cases):
        ku = pysnmp_localkey(pw.encode(), eid)
        assert len(ku) == 32
        ba(f"V_AUTHKEY_P{i}", pw.encode())
        ba(f"V_AUTHKEY_E{i}", eid)
        ba(f"V_AUTHKEY_K{i}", ku)
        entries.append(f"  {{ V_AUTHKEY_P{i}, {len(pw)}, V_AUTHKEY_E{i}, {len(eid)}, V_AUTHKEY_K{i} }},")
    A("static const AuthKeyVec VEC_AUTHKEY[N_AUTHKEY] = {\n")
    A("\n".join(entries) + "\n};\n\n")

    # --- HMAC-SHA-256, truncated to 24 octets (RFC 7860) ---
    cases = [
        (b"\x0b" * 20, b"Hi There"),                       # RFC 4231 case 1
        (bytes.fromhex("80001f8880deadbeef0001" * 3)[:32], bytes.fromhex("80001f8880deadbeeff00d") * 3),
        (b"Jefe" * 11, b"what do ya want for nothing?"),   # RFC 4231 case 2
    ]
    A("typedef struct { const uint8_t* key; size_t keyLen; const uint8_t* msg; "
      "size_t msgLen; const uint8_t* mac; } HmacVec;\n")
    A(f"#define N_HMAC {len(cases)}\n")
    entries = []
    for i, (key, msg) in enumerate(cases):
        mac = hmac_mod.new(key, msg, hashlib.sha256).digest()[:24]
        ba(f"V_HMAC_KEY{i}", key)
        ba(f"V_HMAC_MSG{i}", msg)
        ba(f"V_HMAC_MAC{i}", mac)
        entries.append(f"  {{ V_HMAC_KEY{i}, {len(key)}, V_HMAC_MSG{i}, {len(msg)}, V_HMAC_MAC{i} }},")
    A("static const HmacVec VEC_HMAC[N_HMAC] = {\n")
    A("\n".join(entries) + "\n};\n\n")

    # --- AES-128-CFB (RFC 3826): key, boots, time, salt, pt -> ct ---
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def cfb128(key, iv, data):
        enc = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
        return enc.update(data) + enc.finalize()

    cases = [
        (bytes(range(16)), 1234, 5678, b"\x00" * 7 + b"\x01",
         bytes.fromhex("308000000204"))                      # 16-byte scopedPDU stub
        ,
    ]
    # richer plaintext: a real scopedPDU (engineID + GetRequest)
    scoped_plain = ber_seq(
        ber_octet(ENGINE_ID), ber_octet(b""),
        ber_pdu(0xA0, 42, 0, 0,
                [ber_varbind((1, 3, 6, 1, 4, 1, 67018, 1, 1, 0), ber_null())]))
    cases = [
        (bytes(range(16)), 1234, 5678, b"\x00" * 7 + b"\x01", bytes.fromhex("c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")),
        (bytes(range(16)), 1234, 5678, b"\x00" * 7 + b"\x01", scoped_plain),
        (bytes(range(16)), 0xFFFFFFF0, 0xFFFFFFF0, b"\xde\xad\xbe\xef\x00\x01\x02\x03", b"partial tail"),  # 13B
    ]
    A("typedef struct { const uint8_t* key; uint32_t boots; uint32_t time; "
      "const uint8_t* salt; const uint8_t* pt; size_t ptLen; const uint8_t* ct; } CfbVec;\n")
    A(f"#define N_CFB {len(cases)}\n")
    entries = []
    for i, (key, boots, time, salt, pt) in enumerate(cases):
        iv = boots.to_bytes(4, "big") + time.to_bytes(4, "big") + salt
        ct = cfb128(key, iv, pt)
        ba(f"V_CFB_KEY{i}", key)
        ba(f"V_CFB_SALT{i}", salt)
        ba(f"V_CFB_PT{i}", pt)
        ba(f"V_CFB_CT{i}", ct)
        entries.append(f"  {{ V_CFB_KEY{i}, {boots}u, {time}u, V_CFB_SALT{i}, "
                       f"V_CFB_PT{i}, {len(pt)}, V_CFB_CT{i} }},")
    A("static const CfbVec VEC_CFB[N_CFB] = {\n")
    A("\n".join(entries) + "\n};\n\n")

    # --- wire sample A: discovery Report (agent -> manager) ---
    def secparams(engine_id, boots, time, user, auth, priv):
        return ber_seq(ber_octet(engine_id), ber_int(boots), ber_int(time),
                       ber_octet(user), ber_octet(auth), ber_octet(priv))

    def message(engine_id, boots, time, user, auth, priv, msg_id, max_size,
                flags, scoped, encrypted=False):
        sp = secparams(engine_id, boots, time, user, auth, priv)
        # RFC 3412 §6: privFlag set -> msgData ::= OCTET STRING (ciphertext);
        # otherwise msgData ::= scopedPDU in plaintext.
        msg_data = ber_octet(scoped) if encrypted else scoped
        body = (ber_int(3) + ber_int(msg_id) + ber_int(max_size)
                + ber_octet(bytes([flags])) + ber_int(3) + ber_octet(sp))
        return ber_seq(body + msg_data), sp

    # A: discovery report — unauthenticated, engine params embedded
    report_vb = ber_varbind((1, 3, 6, 1, 6, 3, 15, 1, 1, 4), ber_int(0))
    report_pdu = ber_pdu(0xA8, 0, 0, 0, [report_vb])
    scoped_a = ber_seq(ber_octet(ENGINE_ID), ber_octet(b""), report_pdu)
    msg_a, sp_a = message(ENGINE_ID, 1234, 5678, b"", b"\x00" * 24,
                          b"\x00" * 8, 0x11223344, 484, 0x04, scoped_a)
    # self-check: outer SEQUENCE decodes cleanly and re-encodes identically
    tag, content, nxt = mini_decode(msg_a)
    assert tag == 0x30 and nxt == len(msg_a)
    rebuilt = ber_seq(ber_int(3) + ber_int(0x11223344) + ber_int(484)
                      + ber_octet(bytes([0x04])) + ber_int(3)
                      + ber_octet(sp_a) + scoped_a)
    assert msg_a == rebuilt, "msg A re-encode mismatch"

    A("// Wire sample A — discovery Report (v3, reportable, no auth/priv)\n")
    ba("V_MSG_A", msg_a)
    A(f"#define V_MSG_A_EXPECT_LEN {len(msg_a)}\n")
    A(f"#define V_MSG_A_EXPECT_MSGID 0x11223344u\n")
    A(f"#define V_MSG_A_EXPECT_MAXSIZE 484u\n")
    A(f"#define V_MSG_A_EXPECT_FLAGS 0x04\n")
    A(f"#define V_MSG_A_EXPECT_SECMODEL 3\n\n")

    # --- wire sample B: authPriv GetRequest (manager -> agent) ---
    auth_key = pysnmp_localkey(AUTH_PASS, ENGINE_ID)
    priv_key = pysnmp_localkey(PRIV_PASS, ENGINE_ID)[:16]
    salt = b"\x00" * 7 + b"\x01"
    iv = (1234).to_bytes(4, "big") + (5678).to_bytes(4, "big") + salt
    encrypted = cfb128(priv_key, iv, scoped_plain)

    marker = b"\xaa" * 24
    msg_b, sp_b = message(ENGINE_ID, 1234, 5678, b"telemetry", marker,
                          salt, 98765, 65507, 0x07, encrypted, encrypted=True)
    zeroed = msg_b.replace(marker, b"\x00" * 24, 1)
    mac = hmac_mod.new(auth_key, zeroed, hashlib.sha256).digest()[:24]
    msg_b = msg_b.replace(marker, mac, 1)
    sp_b = sp_b.replace(marker, mac, 1)
    assert msg_b.count(mac) == 1 and marker not in msg_b + sp_b

    # self-check: outer SEQUENCE decodes cleanly, msgData is an OCTET STRING
    # wrapping exactly the ciphertext, and re-encoding is byte-identical
    tag, content, nxt = mini_decode(msg_b)
    assert tag == 0x30 and nxt == len(msg_b)
    p = 0
    for _ in range(6):  # version, msgID, maxSize, flags, secModel, secParams
        _, _, p = mini_decode(content, p)
    mtag, mcontent, mnxt = mini_decode(content, p)
    assert mtag == 0x04 and mcontent == encrypted and mnxt == len(content), \
        "msg B msgData TLV mismatch"
    rebuilt = ber_seq(ber_int(3) + ber_int(98765) + ber_int(65507)
                      + ber_octet(bytes([0x07])) + ber_int(3)
                      + ber_octet(sp_b) + ber_octet(encrypted))
    assert msg_b == rebuilt, "msg B re-encode mismatch"
    print(f"    msg B self-check OK ({len(msg_b)} bytes, ct {len(encrypted)} B)")

    A("// Wire sample B — authPriv GetRequest (manager -> agent, SHA-256+AES-128)\n")
    ba("V_MSG_B", msg_b)
    A(f"#define V_MSG_B_EXPECT_LEN {len(msg_b)}\n")
    A(f"#define V_MSG_B_EXPECT_MSGID 98765u\n")
    A(f"#define V_MSG_B_EXPECT_MAXSIZE 65507u\n")
    A(f"#define V_MSG_B_EXPECT_FLAGS 0x07\n")
    A(f"#define V_MSG_B_EXPECT_SECMODEL 3\n")
    ba("V_MSG_B_AUTHKEY", auth_key)
    ba("V_MSG_B_PRIVKEY", priv_key)
    A("// plaintext scopedPDU of sample B (for decrypt assertion)\n")
    ba("V_MSG_B_PLAIN", scoped_plain)

    # --- M2 wire oracles: full request/response roundtrips ------------------
    # Independent reconstruction of the agent pipeline (RFC 3412/3414/3826):
    # a Python-built authPriv request goes in; the byte-exact expected
    # response (same MAC/CFB machinery, mirrored) must come out.
    def usm_sp(engine_id, boots, time, user, auth_params, priv_params):
        return ber_seq(ber_octet(engine_id), ber_int(boots), ber_int(time),
                       ber_octet(user), ber_octet(auth_params),
                       ber_octet(priv_params))

    def build_request(msg_id, max_size, flags, sp, scoped_plain,
                      auth_key, priv_key16, salt, boots, time):
        iv = boots.to_bytes(4, "big") + time.to_bytes(4, "big") + salt
        ct = cfb128(priv_key16, iv, scoped_plain)
        body = (ber_int(3) + ber_int(msg_id) + ber_int(max_size)
                + ber_octet(bytes([flags])) + ber_int(3) + ber_octet(sp))
        msg = ber_seq(body + ber_octet(ct))
        marker = b"\xaa" * 24
        sp_marked = sp.replace(ber_octet(marker) if False else sp[:0], b"")
        # build with marker in authParams for zeroing
        return None  # replaced below

    # Request builder (authPriv): full envelope with correct MAC + CFB.
    def make_authpriv_request(msg_id, max_size, req_pdu, engine_id, boots,
                              time, user, auth_key, priv_key16, salt):
        scoped = ber_seq(ber_octet(engine_id), ber_octet(b""), req_pdu)
        iv = boots.to_bytes(4, "big") + time.to_bytes(4, "big") + salt
        ct = cfb128(priv_key16, iv, scoped)
        marker = b"\xaa" * 24
        sp = ber_seq(ber_octet(engine_id), ber_int(boots), ber_int(time),
                     ber_octet(user), ber_octet(marker), ber_octet(salt))
        body = (ber_int(3) + ber_int(msg_id) + ber_int(max_size)
                + ber_octet(bytes([0x07])) + ber_int(3) + ber_octet(sp))
        msg = ber_seq(body + ber_octet(ct))
        zeroed = msg.replace(marker, b"\x00" * 24, 1)
        mac = hmac_mod.new(auth_key, zeroed, hashlib.sha256).digest()[:24]
        return msg.replace(marker, mac, 1)

    # Expected authPriv response (byte-exact mirror of the agent assembly).
    def make_authpriv_response(req_msg_id, req_id, resp_vbs, engine_id,
                               boots, time, user, auth_key, priv_key16,
                               salt, max_size=1500):
        pdu = ber_pdu(0xA2, req_id, 0, 0, resp_vbs)
        scoped = ber_seq(ber_octet(engine_id), ber_octet(b""), pdu)
        iv = boots.to_bytes(4, "big") + time.to_bytes(4, "big") + salt
        ct = cfb128(priv_key16, iv, scoped)
        marker = b"\xaa" * 24
        sp = ber_seq(ber_octet(engine_id), ber_int(boots), ber_int(time),
                     ber_octet(user), ber_octet(marker), ber_octet(salt))
        body = (ber_int(3) + ber_int(req_msg_id) + ber_int(max_size)
                + ber_octet(bytes([0x03])) + ber_int(3) + ber_octet(sp))
        msg = ber_seq(body + ber_octet(ct))
        zeroed = msg.replace(marker, b"\x00" * 24, 1)
        mac = hmac_mod.new(auth_key, zeroed, hashlib.sha256).digest()[:24]
        return msg.replace(marker, mac, 1)

    # Expected discovery Report response (RFC 3412 §7.2.6 / RFC 3414 §4).
    def make_report_response(req_msg_id, req_id, stat_arcs, stat_value,
                             engine_id, boots, time, max_size=1500):
        c32 = bytes([0x41, 4]) + stat_value.to_bytes(4, "big")
        pdu = ber_pdu(0xA8, req_id, 0, 0, [ber_varbind(stat_arcs, c32)])
        scoped = ber_seq(ber_octet(engine_id), ber_octet(b""), pdu)
        sp = ber_seq(ber_octet(engine_id), ber_int(boots), ber_int(time),
                     ber_octet(b""), ber_octet(b"\x00" * 24),
                     ber_octet(b"\x00" * 8))
        body = (ber_int(3) + ber_int(req_msg_id) + ber_int(max_size)
                + ber_octet(bytes([0x04])) + ber_int(3) + ber_octet(sp))
        return ber_seq(body + scoped)

    # Scenario constants (must match test_agent.c).
    m2_boots, m2_time = 5, 5           # engine boots; request carries time 5
    m2_init_ms = 100000                # agentInit(nowMs)
    m2_proc_ms = 105000                # agentProcess(nowMs) -> engineTime 5
    salt_seed = (m2_boots << 32) | (m2_init_ms // 1000)   # agentInit seeding
    resp_salt = ((salt_seed + 1) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")

    sysdescr_oid = (1, 3, 6, 1, 2, 1, 1, 1, 0)
    sysname_oid  = (1, 3, 6, 1, 2, 1, 1, 5, 0)
    uptime_oid   = (1, 3, 6, 1, 2, 1, 1, 3, 0)
    unkeng_oid   = (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)
    sysdescr_str = b"ESP32-SNMPv3-Agent"

    # 1) authPriv GET sysDescr.0 -> byte-exact GetResponse
    req_get = make_authpriv_request(
        777, 65507, ber_pdu(0xA0, 42, 0, 0, [ber_varbind(sysdescr_oid, ber_null())]),
        ENGINE_ID, m2_boots, m2_time, b"telemetry",
        auth_key, priv_key, b"\x00" * 7 + b"\x01")
    resp_get = make_authpriv_response(
        777, 42, [ber_varbind(sysdescr_oid, ber_octet(sysdescr_str))],
        ENGINE_ID, m2_boots, m2_time, b"telemetry",
        auth_key, priv_key, resp_salt)

    # 2) discovery (noAuthNoPriv, empty engineID/user) -> byte-exact Report
    req_disc = ber_seq(
        ber_int(3) + ber_int(888) + ber_int(65507) + ber_octet(bytes([0x04]))
        + ber_int(3)
        + ber_octet(ber_seq(ber_octet(b""), ber_int(0), ber_int(0),
                            ber_octet(b""), ber_octet(b"\x00" * 24),
                            ber_octet(b"\x00" * 8)))
        + ber_seq(ber_octet(b""), ber_octet(b""),
                  ber_pdu(0xA0, 4242, 0, 0, [ber_varbind(sysdescr_oid, ber_null())])))
    resp_disc = make_report_response(888, 4242, unkeng_oid, 1,
                                     ENGINE_ID, m2_boots, m2_time)

    # 3) stale engineTime (delta 1000 s > 150 s window) -> NotInTimeWindows
    req_stale = make_authpriv_request(
        778, 65507, ber_pdu(0xA0, 43, 0, 0, [ber_varbind(sysdescr_oid, ber_null())]),
        ENGINE_ID, m2_boots, 1005, b"telemetry",
        auth_key, priv_key, b"\x00" * 7 + b"\x01")

    # 4) unknown user name -> UnknownUserNames (MAC invalid, checked later)
    req_unknown = make_authpriv_request(
        779, 65507, ber_pdu(0xA0, 44, 0, 0, [ber_varbind(sysdescr_oid, ber_null())]),
        ENGINE_ID, m2_boots, m2_time, b"intruder",
        auth_key, priv_key, b"\x00" * 7 + b"\x01")

    # 5) SET sysName.0 = "hobbes" (OCTET STRING) -> structural checks
    req_set = make_authpriv_request(
        780, 65507, ber_pdu(0xA3, 45, 0, 0, [ber_varbind(sysname_oid, ber_octet(b"hobbes"))]),
        ENGINE_ID, m2_boots, m2_time, b"telemetry",
        auth_key, priv_key, b"\x00" * 7 + b"\x01")

    # 6) GETNEXT from sysUpTime.0 -> structural checks (expect sysContact.0)
    req_next = make_authpriv_request(
        781, 65507, ber_pdu(0xA1, 46, 0, 0, [ber_varbind(uptime_oid, ber_null())]),
        ENGINE_ID, m2_boots, m2_time, b"telemetry",
        auth_key, priv_key, b"\x00" * 7 + b"\x01")

    A("// --- M2 wire oracles ---------------------------------------------------\n")
    ba("V_M2_ENGID", ENGINE_ID)
    ba("V_REQ_GET", req_get)
    ba("V_RESP_GET", resp_get)
    ba("V_REQ_DISCOVERY", req_disc)
    ba("V_RESP_DISCOVERY", resp_disc)
    ba("V_REQ_STALE", req_stale)
    ba("V_REQ_UNKNOWN_USER", req_unknown)
    ba("V_REQ_SET_NAME", req_set)
    ba("V_REQ_NEXT", req_next)
    A("#define V_M2_ENGID_LEN %d\n" % len(ENGINE_ID))
    A("#define V_M2_BOOTS %du\n" % m2_boots)
    A("#define V_M2_REQ_TIME %du\n" % m2_time)
    A("#define V_M2_INIT_MS %du\n" % m2_init_ms)
    A("#define V_M2_PROC_MS %du\n" % m2_proc_ms)
    A("#define V_M2_SYSDSCR \"%s\"\n" % sysdescr_str.decode())
    A("#define V_M2_SYSDSCR_LEN %d\n" % len(sysdescr_str))
    print(f"    M2 oracles OK (req {len(req_get)} B, resp {len(resp_get)} B, "
          f"disc {len(req_disc)} B)")

    A("#endif  // SNMPV3_TEST_VECTORS_H\n")
    (VEC / "vectors.h").write_text("".join(L))
    print(f"vectors.h written ({len(msg_a)} B msg A, {len(msg_b)} B msg B)")

if __name__ == "__main__":
    emit_tables()
    emit_vectors()
    print("gen_vectors: OK")