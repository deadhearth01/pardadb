"""PII scanner: column headers + sampled values -> tag per column.

Values are classified by the parda engine (rules with Luhn / Verhoeff / PAN checks + on-device NER model).
"""
import json
import os
import re
import shutil
import subprocess
from collections import Counter

from .backends import HERE

CATALOG_PATH = os.path.join(HERE, "catalog.json")

# parda entity kind -> (tag, mask kind)
KIND_TAGS = {
    "CreditCard": ("PII_HIGH", "card"),
    "Aadhaar": ("PII_HIGH", "aadhaar"),
    "Pan": ("PII_HIGH", "pan"),
    "UsSsn": ("PII_HIGH", "ssn"),
    "Iban": ("PII_HIGH", "iban"),
    "Passport": ("PII_HIGH", "passport"),
    "Email": ("PII_MEDIUM", "email"),
    "Phone": ("PII_MEDIUM", "phone"),
    "Person": ("PII_MEDIUM", "person"),
    "Address": ("PII_MEDIUM", "address"),
    "Upi": ("PII_MEDIUM", "upi"),
}
FINANCIAL_HEADERS = re.compile(r"(balance|amount|salary|income|credit_limit|loan|txn_amt)", re.I)
HEADER_HINTS = {
    re.compile(r"card|cc_?num|pan_?card", re.I): ("PII_HIGH", "card"),
    re.compile(r"aadhaar|aadhar|ssn|social", re.I): ("PII_HIGH", "aadhaar"),
    re.compile(r"\bpan\b|pan_no", re.I): ("PII_HIGH", "pan"),
    re.compile(r"e_?mail", re.I): ("PII_MEDIUM", "email"),
    re.compile(r"phone|mobile", re.I): ("PII_MEDIUM", "phone"),
    re.compile(r"(full_?)?name$", re.I): ("PII_MEDIUM", "person"),
}


def _scan_one(text):
    out = subprocess.run([shutil.which("parda"), "scan", "--json", "-"], input=text,
                         capture_output=True, text=True, timeout=30)
    return [(it["kind"], it["start"] == 0 and it["end"] >= len(text.rstrip()))
            for it in json.loads(out.stdout or "[]")]


def parda_scan(values):
    """`parda scan --json` per sampled value (parallel); returns [(kind, covers_whole_cell)] per value."""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=16) as pool:
        return list(pool.map(_scan_one, [str(v) for v in values]))


def classify(column, values):
    n = len(values)
    if n == 0:
        return None
    per_value = parda_scan(values)
    # a value "is" a kind only if that entity covers the whole cell (otherwise it's free text containing PII)
    whole = Counter()
    partial_hits = 0
    for v, kinds in zip(values, per_value):
        if kinds:
            partial_hits += 1
            full_kinds = {k for k, w in kinds if w}
            if len(full_kinds) == 1:
                whole[full_kinds.pop()] += 1
    header = next((t for rx, t in HEADER_HINTS.items() if rx.search(column)), None)

    if whole:
        kind, cnt = whole.most_common(1)[0]
        rate = cnt / n
        distinct = len(set(map(str, values))) / n
        if kind == "Person" and distinct < 0.5 and not (header and header[1] == "person"):
            # names are mostly unique; a low-cardinality column (city, status) the model calls "Person" is a false positive
            whole.pop(kind)
            rate = 0
        if rate >= 0.6 and kind in KIND_TAGS:
            tag, mkind = KIND_TAGS[kind]
            conf = min(1.0, rate + (0.1 if header and header[0] == tag else 0))
            return dict(tag=tag, kind=mkind, confidence=round(conf, 2), evidence=f"parda: {kind} in {cnt}/{n} samples")
    if FINANCIAL_HEADERS.search(column) and all(_is_number(v) for v in values):
        return dict(tag="FINANCIAL_CONFIDENTIAL", kind="money", confidence=0.9, evidence="numeric + financial header")
    if partial_hits / n >= 0.2 and any(isinstance(v, str) and len(v.split()) > 4 for v in values):
        return dict(tag="PII_FREE_TEXT", kind="text", confidence=round(partial_hits / n, 2),
                    evidence=f"parda: PII inside free text in {partial_hits}/{n} samples")
    if header:
        return dict(tag=header[0], kind=header[1], confidence=0.5, evidence="header name only (needs review)")
    return None


def _is_number(v):
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


def scan(backend, sample_size=25, on_column=None):
    catalog = {}
    for table in backend.tables():
        for col in backend.columns(table):
            res = classify(col, backend.sample(table, col, sample_size))
            if res:
                catalog.setdefault(table, {})[col] = res
            if on_column:
                on_column(table, col, res)
    return catalog


def save(catalog, backend_name):
    allc = load()
    allc[backend_name] = catalog
    with open(CATALOG_PATH, "w") as f:
        json.dump(allc, f, indent=2)


def load():
    if os.path.exists(CATALOG_PATH):
        with open(CATALOG_PATH) as f:
            return json.load(f)
    return {}
