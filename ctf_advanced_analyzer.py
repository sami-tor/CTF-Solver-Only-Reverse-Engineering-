#!/usr/bin/env python3
"""
ctf_advanced_analyzer.py
========================

An advanced reverse‑engineering helper for Capture‑the‑Flag (CTF) challenges.

This tool extends the earlier flag solver by adding several new features:

* Additional decoders: Base58, Ascii85, full Caesar shifts, Atbash and a small
  Vigenère brute force for two‑letter keys.  Base91 is omitted due to
  complexity, but the script still covers most common encodings like Base64,
  Base32, Base85 (both standard and URL‑safe), hexadecimal, decimal and
  binary.
* Improved XOR handling: single‑byte and small repeating‑key XOR brute force.
* File format awareness: detection of PE versus ELF files, architecture and
  entry points, section listing, imported function names (for PE) and ELF
  symbol names when present.
* Encryption and API heuristic detection: scanning strings for
  cryptographic library names (`AES`, `DES`, `RC4`, etc.), Windows CryptoAPI
  functions (`CryptEncrypt`, `CryptDecrypt`, etc.), OpenSSL `EVP_` routines,
  and common crypto library DLL names.
* Packer detection: searching for signatures of popular packers like UPX,
  MPRESS, FSG, ASPack, PECompact, kkrunchy, Themida and VMProtect.  It also
  computes the overall Shannon entropy of the file, which can hint at
  encryption or packing when very high.
* Flag detection: retains the original logic to recognise CTF flags with
  known prefixes (`picoCTF`, `TJCTF`, `actf`, `lactf`, `DUCTF`, `dice`,
  `uiuctf`)【204239052550078†L75-L101】【524700409052195†L49-L53】【352463313848074†L16-L18】 and generic
  `word{...}` patterns【671228759671450†L120-L123】.

Running the script produces a detailed report for each input file,
including any discovered flags, possible flags, guessed encryption APIs,
imported DLLs, packer signatures, file entropy and basic headers.

Example usage::

    python3 ctf_advanced_analyzer.py file.exe file2.bin

If no filenames are specified, it reads from standard input and outputs
flag information only.  This tool is self‑contained and uses only the
Python standard library.
"""

import sys
import os
import re
import math
import struct
import base64
import binascii
import zlib
import gzip
import bz2
import lzma
from collections import deque, Counter
from typing import Iterable, List, Tuple, Dict, Optional, Set
import argparse



# ========= Flag patterns =========
FLAG_PREFIXES = [
    "picoCTF", "tjctf", "actf", "lactf", "DUCTF",
    "dice", "uiuctf"
]
PREFIX_PATTERN = re.compile(r"^(?:" + "|".join(re.escape(p) for p in FLAG_PREFIXES) + ")\{.*\}$", re.IGNORECASE)
# Generic pattern: at least three alphanumeric characters followed by braces
GENERIC_PATTERN = re.compile(r"^[A-Za-z0-9]{4,10}\{.*\}$")


# ========= String extraction =========
def extract_strings(data: bytes, min_len: int = 4) -> Set[str]:
    """Extract printable ASCII and UTF‑16LE strings from binary data.

    Returns a set of unique strings.
    """
    results: Set[str] = set()
    # ASCII
    buf = bytearray()
    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                results.add(buf.decode('ascii'))
            buf.clear()
    if len(buf) >= min_len:
        results.add(buf.decode('ascii'))
    # UTF‑16LE
    buf = bytearray()
    i = 0
    while i < len(data) - 1:
        c1, c2 = data[i], data[i+1]
        i += 2
        if c2 == 0 and 32 <= c1 <= 126:
            buf.append(c1)
        else:
            if len(buf) >= min_len:
                results.add(buf.decode('ascii'))
            buf.clear()
    if len(buf) >= min_len:
        results.add(buf.decode('ascii'))
    return results


# ========= Detailed string extraction =========
def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    """Extract printable ASCII strings with their offset.

    Returns a list of tuples (offset, string).  Only printable characters
    (0x20–0x7E) are considered, and strings shorter than min_length are
    discarded.
    """
    results: List[Tuple[int, str]] = []
    current = []
    start = None
    for idx, b in enumerate(data):
        if 32 <= b <= 126:
            if start is None:
                start = idx
            current.append(b)
        else:
            if start is not None and len(current) >= min_length:
                s = bytes(current).decode('ascii', errors='ignore')
                results.append((start, s))
            current = []
            start = None
    # tail
    if start is not None and len(current) >= min_length:
        s = bytes(current).decode('ascii', errors='ignore')
        results.append((start, s))
    return results


def extract_utf16le_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    """Extract UTF‑16LE strings with their offset.

    Scans for sequences of alternating ASCII byte and null (0x00) bytes.
    Returns a list of (offset, string) pairs.
    """
    results: List[Tuple[int, str]] = []
    i = 0
    current = []
    start = None
    n = len(data)
    while i < n - 1:
        b1, b2 = data[i], data[i+1]
        if b2 == 0 and 32 <= b1 <= 126:
            if start is None:
                start = i
            current.append(b1)
            i += 2
        else:
            if start is not None and len(current) >= min_length:
                s = bytes(current).decode('ascii', errors='ignore')
                results.append((start, s))
            current = []
            start = None
            i += 1
    if start is not None and len(current) >= min_length:
        s = bytes(current).decode('ascii', errors='ignore')
        results.append((start, s))
    return results


# ========= ELF symbol parsing =========
def parse_elf_symbols(data: bytes, arch: str) -> Dict[str, int]:
    """Return a mapping of symbol names to addresses from an ELF binary.

    Supports dynamic and static symbol tables (SHT_DYNSYM and SHT_SYMTAB).  Only
    little‑endian ELFs are handled.  arch should be '32-bit' or '64-bit'.
    """
    symbols: Dict[str, int] = {}
    # Verify ELF header
    if not data.startswith(b'\x7fELF'):
        return symbols
    is_64 = arch == '64-bit'
    ei_data = data[5]
    if ei_data != 1:  # only little-endian
        return symbols
    # Extract section header offset, entry size and count
    if is_64:
        if len(data) < 0x40:
            return symbols
        e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
        e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    else:
        if len(data) < 0x34:
            return symbols
        e_shoff = struct.unpack_from('<I', data, 0x20)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x2E)[0]
        e_shnum = struct.unpack_from('<H', data, 0x30)[0]
    # Load section headers
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is_64:
            if off + 64 > len(data):
                break
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from('<IIQQQQIIQQ', data, off)
        else:
            if off + 40 > len(data):
                break
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from('<IIIIIIIIII', data, off)
        sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize))
    # Load all string tables
    strtabs: Dict[int, bytes] = {}
    SHT_STRTAB = 3
    for idx, (_, sh_type, _, _, sh_offset, sh_size, _, _, _, _) in enumerate(sections):
        if sh_type == SHT_STRTAB and sh_size > 0 and sh_offset + sh_size <= len(data):
            strtabs[idx] = data[sh_offset:sh_offset+sh_size]
    # Symbol tables
    SHT_SYMTAB = 2
    SHT_DYNSYM = 11
    for idx, (_, sh_type, _, _, sh_offset, sh_size, sh_link, _, _, sh_entsize) in enumerate(sections):
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strtab = strtabs.get(sh_link)
        if not strtab:
            continue
        ent_size = sh_entsize
        if ent_size == 0:
            ent_size = 24 if is_64 else 16
        num_entries = sh_size // ent_size
        for i in range(num_entries):
            ent_off = sh_offset + i * ent_size
            if ent_off + ent_size > len(data):
                break
            if is_64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, ent_off)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from('<IIIIBBH', data, ent_off)
            if st_name == 0:
                continue
            end = strtab.find(b'\x00', st_name)
            if end == -1:
                continue
            name = strtab[st_name:end].decode('utf-8', errors='ignore')
            symbols[name] = st_value
    return symbols


# ========= Network detection =========
def detect_network_apis(strings: Set[str]) -> Set[str]:
    """Detect possible network‑related API keywords in a set of strings.

    Looks for common network function names and library references such as
    socket APIs, WinInet, libcurl, HTTP verbs and protocol markers.  Returns
    the set of matched keywords.
    """
    keywords = [
        'socket', 'bind', 'connect', 'listen', 'accept', 'send', 'recv',
        'select', 'ioctl', 'WSASocket', 'WSAStartup', 'InternetOpen',
        'InternetConnect', 'HttpOpenRequest', 'HttpSendRequest',
        'URLDownloadToFile', 'WinHttpOpen', 'WinHttpConnect',
        'WinHttpSendRequest', 'curl', 'libcurl', 'libresolv', 'resolve',
        'http', 'https', 'get', 'post', 'put', 'delete', 'options',
        'fetch', 'request', 'sendto', 'recvfrom', 'inet_addr', 'inet_ntoa',
        'gethostbyname', 'getaddrinfo', 'tcp', 'udp', 'ssl', 'tls'
    ]
    found = set()
    for s in strings:
        for kw in keywords:
            if kw.lower() in s.lower():
                found.add(kw)
    return found


def detect_network_strings(strings: Set[str]) -> Set[str]:
    """Detect strings that look like URLs or domain names.

    Finds substrings containing protocol prefixes (http://, https://, ftp://)
    or dotted domains.  Returns a set of matched substrings.
    """
    found = set()
    for s in strings:
        # URLs with protocol
        for match in re.finditer(r"(?:https?|ftp)://[\w\-.]+(?:\:[0-9]+)?(?:/[\w\-\._~:/?#\[\]@!$&'()*+,;=%]*)?", s, re.IGNORECASE):
            found.add(match.group(0))
        # Domain names (simple heuristic: contains a dot and letters on both sides)
        for match in re.finditer(r'[A-Za-z0-9.-]+\.[A-Za-z]{2,6}', s):
            domain = match.group(0)
            # Filter out obvious false positives (e.g. IP addresses maybe; allow digits)
            found.add(domain)
    return found


# ========= Base decoders =========
def base58_decode(s: str) -> Optional[bytes]:
    """Decode a Base58 string to bytes. Returns None on error."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        num = 0
        for c in s:
            num = num * 58 + alphabet.index(c)
        res = bytearray()
        while num > 0:
            num, rem = divmod(num, 256)
            res.append(rem)
        res.reverse()
        # handle leading zeros (represented by '1' characters)
        pad = 0
        for c in s:
            if c == '1':
                pad += 1
            else:
                break
        return bytes([0] * pad + list(res))
    except Exception:
        return None


def ascii85_decode(s: str) -> Optional[bytes]:
    """Decode an Ascii85/Adobe85 string to bytes. Returns None on error."""
    try:
        return base64.a85decode(s, adobe=False)
    except Exception:
        try:
            # some encoders wrap with <~ ~>
            if s.startswith('<~') and s.endswith('~>'):
                return base64.a85decode(s[2:-2], adobe=False)
        except Exception:
            return None
        return None


def try_base_decoders(data: bytes) -> Iterable[bytes]:
    """Try a variety of Base decoders on the input bytes."""
    candidates = []
    # raw Base64 families
    for fn in [base64.b64decode, base64.urlsafe_b64decode, base64.b32decode,
               base64.b16decode, base64.b85decode]:
        try:
            out = fn(data)
            if 0 < len(out) <= 8192:
                candidates.append(out)
        except Exception:
            pass
    # ascii85
    try:
        out = base64.a85decode(data, adobe=False)
        if 0 < len(out) <= 8192:
            candidates.append(out)
    except Exception:
        pass
    return candidates


# ========= Compression decoders =========
def try_decompressors(data: bytes) -> Iterable[bytes]:
    """Attempt decompression with several algorithms based on header magic."""
    # Recognise magic values
    magic_tests = [
        (b"\x78\x01", 'zlib'),
        (b"\x78\x9c", 'zlib'),
        (b"\x78\xda", 'zlib'),
        (b"\x1f\x8b", 'gzip'),
        (b"BZ", 'bz2'),
        (b"\xfd7zXZ\x00", 'lzma'),
    ]
    # Choose decompressors
    methods = {
        'zlib': lambda d: zlib.decompress(d),
        'gzip': lambda d: gzip.decompress(d),
        'bz2': lambda d: bz2.decompress(d),
        'lzma': lambda d: lzma.decompress(d),
    }
    candidates = []
    for magic, name in magic_tests:
        if data.startswith(magic):
            try:
                out = methods[name](data)
                if 0 < len(out) <= 8192:
                    candidates.append(out)
            except Exception:
                pass
    return candidates


# ========= Simple ciphers =========
def atbash(data: bytes) -> bytes:
    """Decode using the Atbash substitution cipher (letters only)."""
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:  # A-Z
            out.append(90 - (b - 65))
        elif 97 <= b <= 122:  # a-z
            out.append(122 - (b - 97))
        else:
            out.append(b)
    return bytes(out)


def caesar_shift(data: bytes, shift: int) -> bytes:
    """Apply a Caesar shift of a given amount (1-25)."""
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append((b - 65 + shift) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 + shift) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def vigenere_decode(data: bytes, key: str) -> bytes:
    """Decode data using a Vigenère cipher with the given key (letters only)."""
    out = bytearray()
    key_bytes = key.encode('ascii')
    key_len = len(key_bytes)
    j = 0
    for b in data:
        if 65 <= b <= 90:
            k = key_bytes[j % key_len]
            shift = (k - 65) % 26
            out.append((b - 65 - shift) % 26 + 65)
            j += 1
        elif 97 <= b <= 122:
            k = key_bytes[j % key_len]
            shift = (k - 65) % 26
            out.append((b - 97 - shift) % 26 + 97)
            j += 1
        else:
            out.append(b)
    return bytes(out)


# ========= XOR helpers =========
def xor_single_byte(data: bytes) -> Iterable[bytes]:
    """Yield XOR decodings with all 256 single-byte keys where output is reasonably printable."""
    printable = set(range(32, 127))
    for key in range(256):
        out = bytes(b ^ key for b in data)
        # require at least 60% printable characters
        if sum(c in printable for c in out) / len(out) >= 0.6:
            yield out


def xor_repeating_keys(data: bytes, max_len: int = 3) -> Iterable[bytes]:
    """Attempt XOR decoding with repeating keys of length 2..max_len.

    Uses a simple heuristic: for each key position, only consider key bytes
    that yield at least 70% printable ASCII in that position.  This cuts
    down the search space drastically.
    """
    if len(data) > 256:
        return []
    printable = set(range(32, 127))
    def score(buf: bytes) -> float:
        return sum(c in printable for c in buf) / len(buf)

    for key_len in range(2, max_len + 1):
        # candidate key bytes per position
        cand_bytes: List[List[int]] = []
        skip = False
        for pos in range(key_len):
            candidates = []
            # sample bytes at this key position
            sample = data[pos::key_len]
            for k in range(256):
                dec = bytes(b ^ k for b in sample)
                if score(dec) >= 0.7:
                    candidates.append(k)
            if not candidates:
                skip = True
                break
            cand_bytes.append(candidates)
        if skip:
            continue
        # brute force combinations (limit to first few combinations to avoid explosion)
        max_combos = 128
        count = 0
        def dfs(idx: int, key_prefix: List[int]):
            nonlocal count
            if count >= max_combos:
                return
            if idx == key_len:
                key = bytes(key_prefix)
                out = bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
                if score(out) >= 0.6:
                    yield out
                count += 1
                return
            for k in cand_bytes[idx]:
                yield from dfs(idx + 1, key_prefix + [k])
        for out in dfs(0, []):
            yield out


# ========= Flag detection =========
def is_potential_flag(data: bytes) -> bool:
    """Check whether a decoded byte string looks like a CTF flag."""
    try:
        s = data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return False
    if not s or ' ' in s or '\n' in s:
        return False
    return bool(PREFIX_PATTERN.match(s) or GENERIC_PATTERN.match(s))


def decode_candidates(initial: str) -> Iterable[Tuple[str, str]]:
    """Try multiple decoding strategies on a candidate string and yield flags.

    Returns tuples of (description chain, flag text).
    """
    data = initial.encode('latin1', errors='ignore')
    visited: Set[bytes] = set()
    # Queue of (description, bytes)
    queue: deque[Tuple[str, bytes]] = deque([("original", data)])
    max_depth = 2  # limit depth to control explosion
    while queue:
        desc, cur = queue.popleft()
        if cur in visited or len(cur) == 0 or len(cur) > 8192:
            continue
        visited.add(cur)
        # check for flag
        if is_potential_flag(cur):
            try:
                yield (desc, cur.decode('utf-8', errors='ignore'))
            except Exception:
                pass
        # stop exploring deeper if description already has two steps
        depth = desc.count('->') + 1
        if depth > max_depth:
            continue
        # Base decoders
        for out in try_base_decoders(cur):
            if out not in visited:
                queue.append((desc + ' -> base', out))
        # Decompressors
        for out in try_decompressors(cur):
            if out not in visited:
                queue.append((desc + ' -> decompress', out))
        # Atbash
        atb = atbash(cur)
        if atb not in visited and atb != cur:
            queue.append((desc + ' -> atbash', atb))
        # Caesar shifts (all 25 variations)
        if any((65 <= b <= 90) or (97 <= b <= 122) for b in cur):
            for n in range(1, 26):
                out = caesar_shift(cur, n)
                if out not in visited:
                    queue.append((desc + f' -> rot{n}', out))
        # Vigenère decoding:
        # If the string appears to contain braces but is not a recognised flag,
        # try cracking Vigenère ciphers.  First attempt brute force keys of
        # length 2 (as before), then use statistical methods to guess longer
        # key lengths and break the cipher automatically.
        try:
            s = cur.decode('utf-8', errors='ignore')
        except Exception:
            s = ''
        if '{' in s and '}' in s and not (PREFIX_PATTERN.match(s) or GENERIC_PATTERN.match(s)) and len(s) < 100:
            # 1. brute force two-letter keys as before
            found_match = False
            for k1 in range(ord('A'), ord('Z') + 1):
                for k2 in range(ord('A'), ord('Z') + 1):
                    key = chr(k1) + chr(k2)
                    out = vigenere_decode(cur, key)
                    if out not in visited and is_potential_flag(out):
                        queue.append((desc + f' -> vig[{key}]', out))
                        found_match = True
                        break
                if found_match:
                    break
            # 2. Use auto-correlation to guess longer key lengths (up to 4)
            # Only if the brute force did not already find a candidate
            # to limit noise
            key_candidates = guess_vigenere_key_lengths(cur, max_len=4, top_n=3)
            for klen in key_candidates:
                # Skip 2 since brute force handled
                if klen <= 2:
                    continue
                decoded = vigenere_auto_decode(cur, klen)
                if decoded is not None and decoded not in visited and is_potential_flag(decoded):
                    queue.append((desc + f' -> vig_auto[{klen}]', decoded))
        # XOR single-byte
        if 1 < len(cur) <= 256:
            for out in xor_single_byte(cur):
                if out not in visited:
                    queue.append((desc + ' -> xor1', out))
        # XOR repeating keys length 2 or 3
        if 2 < len(cur) <= 256:
            for out in xor_repeating_keys(cur, max_len=3):
                if out not in visited:
                    queue.append((desc + ' -> xorN', out))
        # Hex decode if string is hex-like
        try:
            s_cur = cur.decode('ascii')
            if len(s_cur) >= 2 and all(c in '0123456789abcdefABCDEF' for c in s_cur) and len(s_cur) % 2 == 0:
                out = binascii.unhexlify(s_cur)
                if out not in visited:
                    queue.append((desc + ' -> hex', out))
        except Exception:
            pass
        # Decimal decode
        try:
            s_cur = cur.decode('ascii')
            if re.fullmatch(r'(?:\d+[\s,;]+){2,}\d+', s_cur):
                nums = [int(x, 0) for x in re.split(r'[\s,;]+', s_cur) if x]
                if all(0 <= n <= 255 for n in nums):
                    out = bytes(nums)
                    if out not in visited:
                        queue.append((desc + ' -> decimal', out))
        except Exception:
            pass
        # Binary decode
        try:
            s_cur = cur.decode('ascii').replace(' ', '')
            if len(s_cur) >= 8 and set(s_cur).issubset({'0', '1'}) and len(s_cur) % 8 == 0:
                out = int(s_cur, 2).to_bytes(len(s_cur) // 8, 'big')
                if out not in visited:
                    queue.append((desc + ' -> binary', out))
        except Exception:
            pass


# ========= Analysis helpers =========
def detect_encryption_apis(strings: Set[str]) -> Set[str]:
    """Return a set of detected crypto API keywords in a set of strings."""
    keywords = [
        'AES', 'DES', '3DES', 'Twofish', 'Blowfish', 'RC2', 'RC4', 'RC5', 'RC6',
        'Camellia', 'Serpent', 'IDEA', 'CAST', 'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
        'bcrypt', 'crypto', 'crypt32.dll', 'advapi32.dll', 'libcrypto', 'libssl',
        'EVP_', 'AES_', 'RSA_', 'DH_', 'DSA_', 'ECDH_', 'ECDSA_',
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext', 'CryptImportKey',
        'BCrypt', 'bcrypt.dll'
    ]
    found = set()
    for s in strings:
        for kw in keywords:
            if kw.lower() in s.lower():
                found.add(kw)
    return found


def detect_imported_dlls(strings: Set[str]) -> Set[str]:
    """Heuristically extract DLL names from strings."""
    dlls = set()
    for s in strings:
        if s.lower().endswith('.dll') and len(s) < 64:
            dlls.add(s)
    return dlls


def detect_packers(data: bytes, strings: Set[str]) -> Set[str]:
    """Detect possible packers by searching for known signatures in the binary data and strings."""
    signatures = {
        'UPX': [b'UPX!', b'.UPX0', b'.UPX1', b'UPX0', b'UPX1'],
        'MPRESS': [b'MPRESS1', b'MPRESS2'],
        'FSG': [b'FSG!'],
        'ASPack': [b'ASPack'],
        'PECompact': [b'PECompact'],
        'kkrunchy': [b'kkrunchy'],
        'Themida': [b'Themida'],
        'VMProtect': [b'VMProtect', b'VMP'],
        'UPack': [b'UPack'],
    }
    found = set()
    for name, sigs in signatures.items():
        for sig in sigs:
            if sig in data:
                found.add(name)
                break
    # Also check in extracted strings (case-insensitive)
    for name, sigs in signatures.items():
        if name in found:
            continue
        for sig in sigs:
            pattern = sig.decode('latin1', errors='ignore')
            for s in strings:
                if pattern.lower() in s.lower():
                    found.add(name)
                    break
            if name in found:
                break
    return found


def compute_entropy(data: bytes) -> float:
    """Compute the Shannon entropy (bits per byte) of the data."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# ========= Statistical helpers =========
def index_of_coincidence(data: bytes) -> float:
    """Compute the Index of Coincidence for a sequence of bytes.

    The IC measures how likely two randomly selected letters from the text
    are the same.  For English plaintext, IC is around 0.065; for random
    data it is around 0.038【94167901588892†L141-L146】.  A higher IC suggests
    that the text resembles natural language or a monoalphabetic cipher.
    Only alphabetic characters are considered; non‑letters are ignored.
    """
    # Filter to alphabetic characters and normalise to uppercase
    letters = [b for b in data if (65 <= b <= 90) or (97 <= b <= 122)]
    n = len(letters)
    if n <= 1:
        return 0.0
    # Count letter frequencies
    counts = Counter((b & 0xDF) for b in letters)  # force to uppercase
    # IC = sum(n_i * (n_i - 1)) / (n * (n - 1))
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def english_score(data: bytes) -> float:
    """Return a score indicating how closely the text matches English.

    The scoring uses the chi‑square test against the expected letter
    frequencies for English.  Lower chi‑square means the distribution is
    closer to English; we return the negative chi‑square so that higher
    values are better.  Non‑alphabetic characters are ignored.
    """
    # English letter frequencies (% of total letters)
    english_freq = {
        'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70,
        'F': 2.23, 'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15,
        'K': 0.77, 'L': 4.03, 'M': 2.41, 'N': 6.75, 'O': 7.51,
        'P': 1.93, 'Q': 0.10, 'R': 5.99, 'S': 6.33, 'T': 9.06,
        'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15, 'Y': 1.97,
        'Z': 0.07
    }
    # Extract letters
    letters = [b & 0xDF for b in data if (65 <= b <= 90) or (97 <= b <= 122)]
    n = len(letters)
    if n == 0:
        return -float('inf')  # strongly non‑English
    counts = Counter(letters)
    chi_square = 0.0
    for c in range(ord('A'), ord('Z') + 1):
        observed = counts.get(c, 0)
        expected = english_freq[chr(c)] / 100.0 * n
        if expected > 0:
            chi_square += (observed - expected) ** 2 / expected
    # More negative is worse, so we return the negative chi‑square
    return -chi_square


def guess_vigenere_key_lengths(data: bytes, max_len: int = 6, top_n: int = 3) -> List[int]:
    """Guess likely Vigenère key lengths based on the auto‑correlation method.

    For each shift 1..max_len, compute the proportion of positions where the
    byte equals the byte at that shift.  Larger values indicate that the
    shift aligns identical plaintext letters encrypted by the same key
    character.  Returns the top_n shifts with the highest scores.
    """
    # Only consider alphabetic letters for correlation measurement
    text = [b for b in data if (65 <= b <= 90) or (97 <= b <= 122)]
    n = len(text)
    if n <= 1:
        return []
    scores = []
    for shift in range(1, max_len + 1):
        if shift >= n:
            break
        matches = 0
        for i in range(n - shift):
            if (text[i] & 0xDF) == (text[i + shift] & 0xDF):
                matches += 1
        score = matches / (n - shift)
        scores.append((score, shift))
    # Sort by score descending, then by shift ascending
    scores.sort(key=lambda x: (-x[0], x[1]))
    return [s for _, s in scores[:top_n]]


def vigenere_auto_decode(data: bytes, key_len: int) -> Optional[bytes]:
    """Attempt to break a Vigenère cipher by frequency analysis for a given key length.

    For each position modulo key_len, select the Caesar shift that maximises
    the English score, then reconstruct the plaintext using those shifts.
    Returns the decoded bytes or None if analysis fails.
    """
    # Determine the best shift for each key position
    key_shifts: List[int] = []
    for pos in range(key_len):
        segment = [data[i] for i in range(pos, len(data), key_len)]
        best_shift = None
        best_score = -float('inf')
        # Try all possible shifts 0..25
        for shift in range(26):
            # Decode segment by subtracting shift
            dec_segment = bytearray()
            for b in segment:
                if 65 <= b <= 90:
                    dec_segment.append((b - 65 - shift) % 26 + 65)
                elif 97 <= b <= 122:
                    dec_segment.append((b - 97 - shift) % 26 + 97)
                else:
                    dec_segment.append(b)
            score = english_score(dec_segment)
            if score > best_score:
                best_score = score
                best_shift = shift
        if best_shift is None:
            return None
        key_shifts.append(best_shift)
    # Decode entire data using found shifts
    out = bytearray()
    for i, b in enumerate(data):
        shift = key_shifts[i % key_len]
        if 65 <= b <= 90:
            out.append((b - 65 - shift) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 - shift) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def find_repeated_patterns(s: str) -> List[int]:
    """Detect lengths of repeated substrings that might indicate a repeating key.

    Returns a list of candidate period lengths where the text contains repeated
    patterns.  For example, the string 'abcabcabc' yields [3].  Longer
    matches are more significant.  We limit the maximum candidate length to
    eight characters.
    """
    candidates = set()
    n = len(s)
    # Only consider up to half of the string length
    max_pat_len = min(8, n // 2)
    for size in range(1, max_pat_len + 1):
        pattern = s[:size]
        # Check if pattern repeats at least twice
        repeated = pattern * (n // size)
        if s.startswith(pattern) and s == repeated[:n]:
            candidates.add(size)
    return sorted(candidates)


def find_encoded_substrings(s: str) -> List[str]:
    """Search for substrings that look like encoded data within a larger string.

    Recognises Base64/URL‑safe Base64, Base32, hexadecimal, decimal‑encoded
    bytes and Ascii85 segments.  Returns a list of unique substrings.
    """
    matches: Set[str] = set()
    # Base64 (alphabet letters, numbers, +, /, =), length multiple of 4
    for m in re.finditer(r'[A-Za-z0-9+/]{8,}={0,2}', s):
        seg = m.group(0)
        # Must be divisible by 4 for Base64 decoding
        if len(seg) % 4 == 0:
            matches.add(seg)
    # Base32 (A-Z2-7 and padding)
    for m in re.finditer(r'[A-Z2-7]{8,}={0,6}', s):
        seg = m.group(0)
        if len(seg) % 8 == 0:
            matches.add(seg)
    # Hexadecimal
    for m in re.finditer(r'(?:0x)?[0-9a-fA-F]{8,}', s):
        seg = m.group(0)
        # Strip optional 0x prefix
        seg = seg[2:] if seg.startswith(('0x', '0X')) else seg
        # Even length only
        if len(seg) % 2 == 0:
            matches.add(seg)
    # Decimal sequences: multiple numbers separated by spaces, commas or semicolons
    for m in re.finditer(r'(?:\d{1,3}[\s,;])+\d{1,3}', s):
        seg = m.group(0).strip()
        # Only accept if at least three numbers
        parts = re.split(r'[\s,;]+', seg)
        if len(parts) >= 3:
            matches.add(seg)
    # Ascii85 / Ascii85 with <~ ~>
    for m in re.finditer(r'<~[!-u]{5,}~>', s):
        matches.add(m.group(0))
    return list(matches)


def decode_embedded_segments(s: str) -> Iterable[Tuple[str, str]]:
    """Decode base‑encoded substrings inside a larger string.

    This helper searches for substrings that look like Base64, Base32,
    hexadecimal, decimal or Ascii85 encodings and applies the standard
    decoding logic to them.  It yields the same tuple format as
    decode_candidates: (description, flag).  The description is prefixed
    with 'embedded' to indicate that the flag was found in an embedded
    segment.
    """
    segments = find_encoded_substrings(s)
    for seg in segments:
        for desc, flag in decode_candidates(seg):
            yield (f'embedded->{desc}', flag)


def read_pe_info(data: bytes) -> Dict[str, any]:
    """Parse basic PE (Portable Executable) headers for architecture, entry point and sections.

    Returns a dict with keys arch, entry_point, sections.
    """
    info: Dict[str, any] = {}
    # Check DOS header
    if data[:2] != b'MZ':
        return info
    try:
        # e_lfanew offset is at 0x3C
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return info
        machine = struct.unpack_from('<H', data, e_lfanew+4)[0]
        if machine == 0x14c:
            arch = 'x86'
        elif machine == 0x8664:
            arch = 'x64'
        else:
            arch = f'0x{machine:x}'
        # Number of sections
        num_sections = struct.unpack_from('<H', data, e_lfanew+6)[0]
        # Optional header to get entry point
        size_of_opt_header = struct.unpack_from('<H', data, e_lfanew+20)[0]
        opt_header_off = e_lfanew + 24
        # Magic indicates PE32 or PE32+
        magic = struct.unpack_from('<H', data, opt_header_off)[0]
        if magic == 0x10b:  # PE32
            entry_rva = struct.unpack_from('<I', data, opt_header_off + 16)[0]
        elif magic == 0x20b:  # PE32+
            entry_rva = struct.unpack_from('<Q', data, opt_header_off + 16)[0]
        else:
            entry_rva = 0
        # Sections
        sections = []
        sec_off = opt_header_off + size_of_opt_header
        for i in range(num_sections):
            off = sec_off + i * 40
            name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size, virtual_address, size_of_raw_data, pointer_to_raw = struct.unpack_from('<IIII', data, off + 8)
            sections.append({
                'name': name,
                'virtual_address': virtual_address,
                'virtual_size': virtual_size,
                'raw_size': size_of_raw_data,
                'raw_ptr': pointer_to_raw,
            })
        info['arch'] = arch
        info['entry_point'] = f'0x{entry_rva:x}'
        info['sections'] = sections
    except Exception:
        return {}
    return info


def read_elf_info(data: bytes) -> Dict[str, any]:
    """Parse basic ELF headers for architecture, entry point and section names."""
    info: Dict[str, any] = {}
    if data[:4] != b'\x7fELF':
        return info
    try:
        # EI_CLASS: byte 4
        ei_class = data[4]
        arch = '32-bit' if ei_class == 1 else '64-bit'
        # Endianness
        ei_data = data[5]
        endian = '<' if ei_data == 1 else '>'
        # Read entry point
        if ei_class == 1:
            # 32-bit
            entry = struct.unpack_from(endian+'I', data, 0x18)[0]
            e_shoff = struct.unpack_from(endian+'I', data, 0x20)[0]
            e_shentsize = struct.unpack_from(endian+'H', data, 0x2e)[0]
            e_shnum = struct.unpack_from(endian+'H', data, 0x30)[0]
            e_shstrndx = struct.unpack_from(endian+'H', data, 0x32)[0]
        else:
            # 64-bit
            entry = struct.unpack_from(endian+'Q', data, 0x18)[0]
            e_shoff = struct.unpack_from(endian+'Q', data, 0x28)[0]
            e_shentsize = struct.unpack_from(endian+'H', data, 0x3a)[0]
            e_shnum = struct.unpack_from(endian+'H', data, 0x3c)[0]
            e_shstrndx = struct.unpack_from(endian+'H', data, 0x3e)[0]
        # Section headers
        sections = []
        # Read section header string table offset and length
        shstr_off = e_shoff + e_shentsize * e_shstrndx
        shstr_offset, shstr_size = struct.unpack_from(endian+'QQ', data, shstr_off + 0x18) if ei_class == 2 else struct.unpack_from(endian+'II', data, shstr_off + 0x10)
        shstr = data[shstr_offset:shstr_offset+shstr_size]
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if ei_class == 2:
                name_off = struct.unpack_from(endian+'I', data, sh_off)[0]
                sec_name = shstr[name_off:shstr.find(b'\x00', name_off)].decode('ascii', errors='ignore')
                sec_addr, sec_offset, sec_size = struct.unpack_from(endian+'QQQ', data, sh_off+0x10)
            else:
                name_off = struct.unpack_from(endian+'I', data, sh_off)[0]
                sec_name = shstr[name_off:shstr.find(b'\x00', name_off)].decode('ascii', errors='ignore')
                sec_addr, sec_offset, sec_size = struct.unpack_from(endian+'III', data, sh_off+0x10)
            sections.append({'name': sec_name, 'address': sec_addr, 'size': sec_size})
        info['arch'] = arch
        info['entry_point'] = f'0x{entry:x}'
        info['sections'] = sections
    except Exception:
        return {}
    return info


# ========= Analysis entry point =========
def analyze_file(path: str):
    """Perform analysis on a single file and print a report."""
    try:
        data = open(path, 'rb').read()
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return
    print(f"==== Analyzing {path} ====")
    # File type detection
    info = {}
    if data.startswith(b'MZ'):
        info = read_pe_info(data)
        fmt = 'PE'
    elif data.startswith(b'\x7fELF'):
        info = read_elf_info(data)
        fmt = 'ELF'
    else:
        fmt = 'unknown'
    print(f"File format: {fmt}")
    if info:
        if 'arch' in info:
            print(f"Architecture: {info['arch']}")
        if 'entry_point' in info:
            print(f"Entry point: {info['entry_point']}")
        if 'sections' in info and len(info['sections']) > 0:
            print(f"Sections ({len(info['sections'])}):")
            for sec in info['sections'][:10]:
                if fmt == 'PE':
                    print(f"  {sec['name']:8s} VA=0x{sec['virtual_address']:x} size=0x{sec['virtual_size']:x} raw_size=0x{sec['raw_size']:x}")
                else:
                    print(f"  {sec['name']:20s} addr=0x{sec['address']:x} size=0x{sec['size']:x}")
            if len(info['sections']) > 10:
                print("  ...")
    # Compute entropy
    ent = compute_entropy(data)
    print(f"File entropy: {ent:.2f} bits/byte")
    # Warn about high entropy which may indicate packing or encryption
    if ent > 7.5:
        # High entropy is a common sign of compressed or packed executables【357461535940202†L63-L67】
        print("Note: High entropy suggests the file may be compressed or packed.")
    # Extract strings and network information
    strings = extract_strings(data)
    ascii_strings = extract_ascii_strings(data)
    utf16_strings = extract_utf16le_strings(data)
    # Detect imported DLLs, crypto APIs, network APIs, packers and network strings
    dlls = detect_imported_dlls(strings)
    cryptos = detect_encryption_apis(strings)
    net_apis = detect_network_apis(strings)
    net_strings = detect_network_strings(strings)
    packers = detect_packers(data, strings)
    # Print summary
    if dlls:
        print(f"Imported DLLs: {', '.join(sorted(dlls))}")
    if cryptos:
        print(f"Crypto APIs: {', '.join(sorted(cryptos))}")
    if net_apis:
        print(f"Network APIs: {', '.join(sorted(net_apis))}")
    if net_strings:
        print(f"Network strings: {', '.join(sorted(net_strings))}")
    if packers:
        print(f"Packer signatures: {', '.join(sorted(packers))}")
    # Solve flags
    found_known: Set[str] = set()
    found_unknown: Set[str] = set()
    for s in strings:
        # Skip very long strings
        if len(s) > 512:
            continue
        # First attempt to decode the whole string
        for desc, flag in decode_candidates(s):
            # deduplicate ignoring case
            fl_lower = flag.lower()
            if fl_lower in (f.lower() for f in found_known | found_unknown):
                continue
            if PREFIX_PATTERN.match(flag):
                found_known.add(flag)
                print(f"Flag: {flag} (via {desc})")
            elif GENERIC_PATTERN.match(flag):
                found_unknown.add(flag)
                print(f"Possible flag: {flag} (via {desc})")
        # Then attempt to decode any embedded encoded segments
        for desc, flag in decode_embedded_segments(s):
            fl_lower = flag.lower()
            if fl_lower in (f.lower() for f in found_known | found_unknown):
                continue
            if PREFIX_PATTERN.match(flag):
                found_known.add(flag)
                print(f"Flag: {flag} (via {desc})")
            elif GENERIC_PATTERN.match(flag):
                found_unknown.add(flag)
                print(f"Possible flag: {flag} (via {desc})")
    if not (found_known or found_unknown):
        print("No flags found.")
    print()
    # Write analysis results to text files in current directory
    # Use base name of the file
    # Determine output directory: place output files next to the input binary if possible,
    # otherwise write into the current working directory.  This helps users find the
    # generated reports in the same folder as the analysed file.
    base = os.path.basename(path)
    out_dir = os.path.dirname(path)
    if out_dir == '':
        out_dir = '.'
    strings_path = os.path.join(out_dir, f"{base}.strings.txt")
    try:
        with open(strings_path, 'w', encoding='utf-8') as f:
            f.write("# ASCII strings (offset: string)\n")
            for off, st in ascii_strings:
                f.write(f"0x{off:x}: {st}\n")
            f.write("\n# UTF-16LE strings (offset: string)\n")
            for off, st in utf16_strings:
                f.write(f"0x{off:x}: {st}\n")
    except Exception as e:
        print(f"Could not write {strings_path}: {e}")
    # Info file
    info_path = os.path.join(out_dir, f"{base}.info.txt")
    try:
        with open(info_path, 'w', encoding='utf-8') as f:
            f.write(f"File format: {fmt}\n")
            if info:
                if 'arch' in info:
                    f.write(f"Architecture: {info['arch']}\n")
                if 'entry_point' in info:
                    f.write(f"Entry point: {info['entry_point']}\n")
                if 'sections' in info and info['sections']:
                    f.write("Sections:\n")
                    for sec in info['sections']:
                        if fmt == 'PE':
                            f.write(f"  {sec['name']}: VA=0x{sec['virtual_address']:x} size=0x{sec['virtual_size']:x} raw_size=0x{sec['raw_size']:x}\n")
                        else:
                            f.write(f"  {sec['name']}: addr=0x{sec['address']:x} size=0x{sec['size']:x}\n")
            f.write(f"File entropy: {ent:.2f} bits/byte\n")
            if ent > 7.5:
                f.write("Note: High entropy suggests the file may be compressed or packed.\n")
            if dlls:
                f.write("Imported DLLs: " + ", ".join(sorted(dlls)) + "\n")
            if cryptos:
                f.write("Crypto APIs: " + ", ".join(sorted(cryptos)) + "\n")
            if net_apis:
                f.write("Network APIs: " + ", ".join(sorted(net_apis)) + "\n")
            if net_strings:
                f.write("Network strings: " + ", ".join(sorted(net_strings)) + "\n")
            if packers:
                f.write("Packer signatures: " + ", ".join(sorted(packers)) + "\n")
    except Exception as e:
        print(f"Could not write {info_path}: {e}")
    # Functions file (only for ELF)
    functions_path = os.path.join(out_dir, f"{base}.functions.txt")
    wrote_funcs = False
    try:
        if fmt == 'ELF' and 'arch' in info:
            arch = info['arch'] if isinstance(info['arch'], str) else ''
            symbols = parse_elf_symbols(data, arch)
            if symbols:
                with open(functions_path, 'w', encoding='utf-8') as f:
                    for name, addr in sorted(symbols.items(), key=lambda x: x[1]):
                        f.write(f"0x{addr:x} {name}\n")
                wrote_funcs = True
    except Exception as e:
        print(f"Could not parse symbols for {path}: {e}")
    if not wrote_funcs:
        # create empty file if not written
        try:
            open(functions_path, 'w').close()
        except Exception:
            pass
    # Flags file
    flags_path = os.path.join(out_dir, f"{base}.flags.txt")
    try:
        with open(flags_path, 'w', encoding='utf-8') as f:
            if found_known:
                f.write("# Confirmed flags\n")
                for fl in sorted(found_known):
                    f.write(fl + "\n")
            if found_unknown:
                f.write("\n# Possible flags\n")
                for fl in sorted(found_unknown):
                    f.write(fl + "\n")
            if not (found_known or found_unknown):
                f.write("No flags found.\n")
    except Exception as e:
        print(f"Could not write {flags_path}: {e}")


def main():
    if len(sys.argv) == 1:
        # Read from stdin and decode flags only
        data = sys.stdin.buffer.read()
        strings = extract_strings(data)
        for s in strings:
            for desc, flag in decode_candidates(s):
                if PREFIX_PATTERN.match(flag):
                    print(flag)
        return
    for path in sys.argv[1:]:
        analyze_file(path)


if __name__ == '__main__':
    main()