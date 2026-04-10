#!/usr/bin/env python3
"""
profanity2 private keys combiner

    FINAL = (SEED_KEY + PROFANITY2_KEY) % secp256k1_order

Requires Python 3.6+, no external dependencies.
"""

import struct
import sys

_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]


def _rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccakf(st):
    for rc in _RC:
        C = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
        D = [C[(x + 4) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        st = [st[i] ^ D[i % 5] for i in range(25)]
        tmp = st[1]
        for i in range(24):
            j = _PI[i]
            st[j], tmp = _rol64(tmp, _RHO[i]), st[j]
        for y in range(0, 25, 5):
            t = st[y:y + 5]
            for x in range(5):
                st[y + x] = t[x] ^ (~t[(x + 1) % 5] & t[(x + 2) % 5])
        st[0] ^= rc
    return st


def _keccak256(data: bytes) -> bytes:
    rate = 136
    st = [0] * 25
    offset = 0
    while len(data) - offset >= rate:
        for i in range(rate // 8):
            st[i] ^= struct.unpack_from('<Q', data, offset + i * 8)[0]
        st = _keccakf(st)
        offset += rate
    msg = bytearray(data[offset:])
    msg.append(0x01)
    msg += b'\x00' * ((rate - len(msg) % rate) % rate)
    msg[-1] |= 0x80
    for i in range(rate // 8):
        st[i] ^= struct.unpack_from('<Q', msg, i * 8)[0]
    st = _keccakf(st)
    return b''.join(x.to_bytes(8, 'little') for x in st[:4])


def _eip55(addr_hex: str) -> str:
    h = _keccak256(addr_hex.encode('ascii')).hex()
    return ''.join(
        c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c
        for i, c in enumerate(addr_hex)
    )


def _point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if P[1] != Q[1]:
            return None
        lam = 3 * P[0] * P[0] * pow(2 * P[1], _P - 2, _P) % _P
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], _P - 2, _P) % _P
    x = (lam * lam - P[0] - Q[0]) % _P
    y = (lam * (P[0] - x) - P[1]) % _P
    return (x, y)


def _point_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = _point_add(R, P)
        P = _point_add(P, P)
        k >>= 1
    return R


def _privkey_to_address(privkey_int):
    pub = _point_mul(privkey_int, (_Gx, _Gy))
    if pub is None:
        raise ValueError("point at infinity")
    pub_bytes = pub[0].to_bytes(32, 'big') + pub[1].to_bytes(32, 'big')
    return _eip55(_keccak256(pub_bytes)[-20:].hex())


def _parse_key(raw: str, label: str) -> int:
    raw = raw.strip()
    if raw.lower().startswith('0x'):
        raw = raw[2:]
    if len(raw) != 64:
        raise ValueError(f"{label}: expected 64 hex characters, got {len(raw)}")
    try:
        value = int(raw, 16)
    except ValueError:
        raise ValueError(f"{label}: not a valid hexadecimal string")
    if not (0 < value < _ORDER):
        raise ValueError(f"{label}: value is outside the valid secp256k1 range")
    return value


def main():
    print("\n  FINAL = (SEED_KEY + PROFANITY2_KEY) % secp256k1_order\n")

    try:
        raw_a = input("  Seed key   (64 hex): ")
        raw_b = input("  Profanity2 (64 hex): ")
        key_a = _parse_key(raw_a, "SEED_KEY")
        key_b = _parse_key(raw_b, "PROFANITY2_KEY")
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.")
        sys.exit(1)
    except ValueError as e:
        print(f"\n  Error: {e}")
        sys.exit(1)

    final = (key_a + key_b) % _ORDER
    if final == 0:
        print("\n  Error: key combination is zero... choose different keys.")
        sys.exit(1)

    try:
        address = _privkey_to_address(final)
    except Exception as e:
        address = f"(could not derive: {e})"

    print(f"\n  Private key: 0x{format(final, '064x')}\n"
          f"  Address    : 0x{address}\n\n"
          "  Always verify the address is correct before use.\n")


if __name__ == '__main__':
    main()
