"""Masking strategies. Every function takes a raw value and returns what the caller may see."""
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess

HMAC_KEY = os.environ.get("PARDADB_HMAC_KEY", "demo-key-change-me").encode()


def full(v, kind=None):
    return v


def redact(v, kind=None):
    return None if v is None else "[REDACTED]"


def hash_(v, kind=None):
    # Keyed HMAC: same input -> same token, so GROUP BY / COUNT DISTINCT / JOIN still work.
    if v is None:
        return None
    return "h_" + hmac.new(HMAC_KEY, str(v).encode(), hashlib.sha256).hexdigest()[:12]


def partial(v, kind=None):
    if v is None:
        return None
    s = str(v)
    if kind == "card":
        d = re.sub(r"\D", "", s)
        return f"{d[:4]}-XXXX-XXXX-{d[-4:]}"
    if kind == "aadhaar":
        return "XXXX XXXX " + re.sub(r"\D", "", s)[-4:]
    if kind == "email":
        user, _, dom = s.partition("@")
        return user[:1] + "***@" + dom
    if kind == "phone":
        d = re.sub(r"\D", "", s)
        return "XXXXXX" + d[-4:]
    if kind == "person":
        parts = s.split()
        return " ".join([parts[0]] + [p[0] + "****" for p in parts[1:]])
    if kind == "pan":
        return "XXXXX" + s[5:9] + "X"
    return "X" * max(len(s) - 4, 0) + s[-4:]


def bucket(v, kind=None):
    if v is None:
        return None
    n = float(v)
    for hi, label in ((10_000, "< 10K"), (1_00_000, "10K-1L"), (10_00_000, "1L-10L")):
        if n < hi:
            return label
    return "> 10L"


def parda_redact(v, kind=None):
    """Free text: replace only the PII inside the sentence, using the parda engine."""
    if v is None:
        return None
    exe = shutil.which("parda")
    if not exe:
        return "[REDACTED]"
    out = subprocess.run([exe, "redact", "-"], input=str(v), capture_output=True, text=True, timeout=30)
    return out.stdout.strip() if out.returncode == 0 else "[REDACTED]"


STRATEGIES = {
    "FULL": full,
    "PARTIAL": partial,
    "HASH": hash_,
    "REDACT": redact,
    "BUCKET": bucket,
    "PARDA_REDACT": parda_redact,
}
