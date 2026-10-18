# PardaDB

**Dynamic, role-based PII masking for SQL databases, built on the [parda](https://github.com/deadhearth01/parda) PII engine.**

Same database, same query, but each role sees only what it is allowed to. The raw tables are never changed.

Built by Team AVNI for the Talent AP Mega Hackathon 2026, Problem Statement 1: *Smart Data Masking System for PII Protection*.

## What it does

| Part | How |
|---|---|
| **Automated PII scanner** | Samples 25 values per column and classifies them with `parda scan` (Luhn / Verhoeff / PAN rules plus an on-device AI model). Match rate, header hints and a cardinality check produce a tag (`PII_HIGH`, `PII_MEDIUM`, `FINANCIAL_CONFIDENTIAL`, `PII_FREE_TEXT`) with confidence and evidence. |
| **Dynamic masking engine** | Every query is parsed with [sqlglot](https://github.com/tobymao/sqlglot), `SELECT *` is expanded, and each output column is traced back to its source column (lineage through aliases, functions, joins and sub-queries). Results are masked per `tag × role` policy. |
| **Inference guard** | Non-admin roles cannot filter, sort, group or join on columns they may not see (for example `WHERE card_no LIKE '4111%'`), so masked values cannot be guessed. Hashed columns may only be grouped or equi-joined as bare columns against another tagged column. Unresolvable columns, writes, `SELECT ... INTO` and file/system functions (`LOAD_FILE`, `SLEEP`, …) are refused (fail-closed). |
| **Multiple databases** | SQLite and MySQL through one adapter interface. SQLite opens read-only; MySQL uses a SELECT-only `pardadb_reader` account created by `seed`. |
| **Proof and audit** | SHA-256 fingerprints of every raw table before and after; every query (including blocked ones) goes to `audit.jsonl`. |
| **Demo interface** | Terminal UI with live role switching and preset bypass attempts. |

### Policy

| Tag | Admin | Support | Analyst |
|---|---|---|---|
| `PII_HIGH` (card, Aadhaar, PAN) | full | partial (`4111-XXXX-XXXX-1111`) | redact |
| `PII_MEDIUM` (name, email, phone) | full | partial | keyed HMAC hash |
| `FINANCIAL_CONFIDENTIAL` (balance, amount) | full | redact | bucket (`1L-10L`) |
| `PII_FREE_TEXT` (notes) | full | PII inside the text replaced by parda | same |

Any value derived from a masked column (for example `SUBSTR(card_no, 1, 9)`, `UPPER(full_name)`, `balance * 1`) is fully redacted for non-admin roles.

## Run it

Requires Python 3.10+, the [parda](https://github.com/deadhearth01/parda) CLI on `PATH` with its daemon running, and optionally a local MySQL.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pardadb seed     # synthetic bank data into SQLite (+ MySQL if reachable)
.venv/bin/python -m pardadb          # interactive terminal UI
.venv/bin/python -m pardadb demo     # scripted walkthrough
```

`seed` connects to MySQL as an admin (`PARDADB_MYSQL_ADMIN_USER` / `PARDADB_MYSQL_ADMIN_PASSWORD`, default `root` with no password), creates the `pardadb_demo` schema and a SELECT-only `pardadb_reader` account, and stores its random password in `.mysql_reader` (mode 0600). The engine connects as that reader (override with `PARDADB_MYSQL_HOST`, `PARDADB_MYSQL_USER`, `PARDADB_MYSQL_PASSWORD`, `PARDADB_MYSQL_DB`). The HMAC key for hashing comes from `PARDADB_HMAC_KEY`, or a random key generated on first run in `.hmac_key` (mode 0600).

### Terminal UI keys

| Key | Action |
|---|---|
| `1` `2` `3` | role: admin / support / analyst |
| `d` | switch SQLite ↔ MySQL |
| `s` / `c` / `p` | scan / show catalog / show policy |
| `q1` … `q8` | preset queries, including bypass and inference attempts |
| any SQL | run your own `SELECT` |
| `v` / `a` | integrity proof / audit log |

All demo data is synthetic: card numbers pass Luhn and Aadhaar numbers pass Verhoeff, but none belong to real people.

## Layout

```
pardadb/
  backends.py   read-only SQLite and MySQL adapters, table fingerprints
  scanner.py    column sampling + parda classification -> PII catalog
  engine.py     SQL parsing, lineage, inference guard, policy, audit
  masks.py      partial / hash / redact / bucket / in-text masking
  seed.py       synthetic bank data generator
  __main__.py   terminal UI and demo
```

## License

MIT
