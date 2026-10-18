"""PardaDB terminal UI.

python -m pardadb seed            create the synthetic bank DB in SQLite and MySQL
python -m pardadb                 interactive TUI
python -m pardadb demo            auto-play the demo script (for recording)
"""
import json
import os
import sys
import time

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import scanner, seed
from .backends import connect
from .engine import AUDIT_PATH, POLICY, ROLES, Blocked, Engine

con = Console()
ROLE_STYLE = {"admin": "bold green", "support": "bold yellow", "analyst": "bold magenta"}
TAG_STYLE = {"PII_HIGH": "bold red", "PII_MEDIUM": "yellow", "FINANCIAL_CONFIDENTIAL": "bold magenta",
             "PII_FREE_TEXT": "cyan"}
STRAT_STYLE = {"FULL": "green", "PARTIAL": "yellow", "HASH": "magenta", "REDACT": "red", "BUCKET": "magenta",
               "PARDA_REDACT": "cyan"}

PRESETS = [
    ("Basic look-up", "SELECT id, full_name, card_no, aadhaar, email, balance, city FROM customers LIMIT 5"),
    ("SELECT * + alias trick", "SELECT who, x FROM (SELECT *, full_name AS who, card_no AS x FROM customers) c LIMIT 4"),
    ("Function bypass (SUBSTR)", "SELECT full_name, SUBSTR(card_no, 1, 9) AS first_digits FROM customers LIMIT 3"),
    ("Free-text notes column", "SELECT id, notes FROM customers LIMIT 4"),
    ("Join + sub-query", "SELECT t.merchant, t.amount, x.full_name FROM transactions t JOIN "
                          "(SELECT id, full_name FROM customers) x ON t.customer_id = x.id LIMIT 4"),
    ("Analytics on hashes", "SELECT full_name, COUNT(*) AS txns FROM customers c JOIN transactions t "
                            "ON t.customer_id = c.id GROUP BY c.id, full_name LIMIT 5"),
    ("Inference attack (WHERE probe)", "SELECT id, city FROM customers WHERE card_no LIKE '4111%'"),
    ("Write attempt", "DELETE FROM customers"),
]


class State:
    def __init__(self):
        self.backend_name = "sqlite"
        self.role = "admin"
        self.backend = connect(self.backend_name)
        self.catalog = scanner.load().get(self.backend_name, {})
        self.fp_before = self.fingerprints()

    def switch_backend(self, name):
        self.backend_name = name
        self.backend = connect(name)
        self.catalog = scanner.load().get(name, {})
        self.fp_before = self.fingerprints()

    def fingerprints(self):
        return {t: self.backend.fingerprint(t) for t in self.backend.tables()}

    def engine(self):
        return Engine(self.backend, self.catalog)


def header(st):
    t = Text()
    t.append(" PardaDB ", style="bold white on #1f4687")
    t.append("  dynamic PII masking · powered by the parda engine   ", style="dim")
    t.append("DB: ", style="dim")
    t.append(f"{st.backend.name} ", style="bold cyan")
    t.append("  ROLE: ", style="dim")
    t.append(f"{st.role.upper()} ", style=ROLE_STYLE[st.role])
    return Panel(t, box=box.HEAVY, border_style="#1f4687")


def catalog_table(catalog):
    tb = Table(title="PII catalog (auto-tagged)", box=box.SIMPLE_HEAVY, title_style="bold")
    for c in ("table", "column", "tag", "confidence", "evidence"):
        tb.add_column(c)
    for t, cols in catalog.items():
        for c, i in cols.items():
            tb.add_row(t, c, Text(i["tag"], style=TAG_STYLE.get(i["tag"], "")), f"{i['confidence']:.2f}", i["evidence"])
    return tb


def policy_table():
    tb = Table(title="Policy: tag x role -> mask", box=box.SIMPLE_HEAVY, title_style="bold")
    tb.add_column("tag")
    for r in ROLES:
        tb.add_column(r, style=ROLE_STYLE[r])
    for tag, m in POLICY.items():
        tb.add_row(Text(tag, style=TAG_STYLE[tag]), *[Text(m[r], style=STRAT_STYLE[m[r]]) for r in ROLES])
    return tb


def do_scan(st):
    con.print(Panel(f"Scanning {st.backend.name}: column names + 25 sampled values per column, classified by parda",
                    border_style="cyan"))
    found = []

    def cb(t, c, res):
        mark = Text(res["tag"], style=TAG_STYLE.get(res["tag"], "")) if res else Text("clean", style="dim")
        con.print(Text(f"  {t}.{c:<12} -> "), mark)
        found.append(1)

    cat = scanner.scan(st.backend, on_column=cb)
    scanner.save(cat, st.backend_name)
    st.catalog = cat
    con.print(catalog_table(cat))


def do_query(st, sql, title=None):
    con.print(Panel(Text(sql, style="bold white"), title=title or "SQL", border_style="white", box=box.ROUNDED))
    try:
        cols, rows, plan = st.engine().run(sql, st.role)
    except Blocked as e:
        con.print(Panel(Text("BLOCKED  " + str(e), style="bold red"), border_style="red"))
        return
    except Exception as e:  # parse errors etc.
        con.print(Panel(Text(f"ERROR  {e}", style="red"), border_style="red"))
        return
    tb = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    for name, strat, info, srcs in plan:
        label = name if strat == "FULL" else f"{name}\n[{STRAT_STYLE[strat]}]{strat}[/]"
        tb.add_column(label, overflow="fold", max_width=48)
    for r in rows:
        tb.add_row(*["NULL" if v is None else str(v) for v in r])
    con.print(Panel(tb, title=f"Result as {st.role.upper()}", border_style=ROLE_STYLE[st.role].split()[-1]))
    lin = [f"{n} <- {', '.join(f'{t}.{c}' for t, c in sorted(s)) or 'literal'}" for n, _, _, s in plan]
    con.print(Text("lineage: " + " | ".join(lin), style="dim"))


def do_verify(st):
    now = st.fingerprints()
    tb = Table(title="Integrity proof: raw tables untouched", box=box.SIMPLE_HEAVY, title_style="bold")
    for c in ("table", "rows", "sha256 before", "sha256 now", "status"):
        tb.add_column(c)
    for t, (h, n) in now.items():
        b = st.fp_before[t][0]
        tb.add_row(t, str(n), b, h, Text("UNCHANGED", style="bold green") if b == h else Text("CHANGED", style="bold red"))
    con.print(tb)


def do_audit(n=8):
    if not os.path.exists(AUDIT_PATH):
        con.print("no audit records yet")
        return
    lines = open(AUDIT_PATH).read().splitlines()[-n:]
    tb = Table(title="Audit log (latest)", box=box.SIMPLE_HEAVY, title_style="bold")
    for c in ("time", "db", "role", "status", "detail"):
        tb.add_column(c, overflow="fold")
    for l in lines:
        r = json.loads(l)
        detail = r.get("reason") or ", ".join(f"{k}:{v}" for k, v in r.get("masked", {}).items()) or "no masking needed"
        tb.add_row(r["ts"][11:], r["backend"], r["role"],
                   Text(r["status"], style="green" if r["status"] == "OK" else "bold red"), detail)
    con.print(tb)


def menu():
    tb = Table(box=None, show_header=False, padding=(0, 2))
    tb.add_column(style="bold cyan")
    tb.add_column()
    tb.add_row("1 / 2 / 3", "role: admin / support / analyst")
    tb.add_row("d", "switch database (SQLite <-> MySQL)")
    tb.add_row("s", "scan database for PII")
    tb.add_row("c / p", "show catalog / policy")
    tb.add_row("q1..q8", "run a preset query:  " + "  ".join(f"q{i+1} {n}" for i, (n, _) in enumerate(PRESETS)))
    tb.add_row("any SQL", "run your own SELECT")
    tb.add_row("v / a", "verify raw tables unchanged / audit log")
    tb.add_row("x", "exit")
    return Panel(tb, title="commands", border_style="dim")


def interactive():
    st = State()
    con.clear()
    con.print(header(st))
    con.print(menu())
    if not st.catalog:
        con.print("[yellow]No catalog yet for this DB: press s to scan.[/]")
    while True:
        try:
            cmd = con.input(f"[{ROLE_STYLE[st.role]}]{st.role}[/]@[cyan]{st.backend_name}[/] > ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd in ("x", "exit", "quit"):
            break
        if cmd in ("1", "2", "3"):
            st.role = ROLES[int(cmd) - 1]
            con.print(header(st))
        elif cmd == "d":
            st.switch_backend("mysql" if st.backend_name == "sqlite" else "sqlite")
            con.print(header(st))
            if not st.catalog:
                con.print("[yellow]No catalog yet for this DB: press s to scan.[/]")
        elif cmd == "s":
            do_scan(st)
        elif cmd == "c":
            con.print(catalog_table(st.catalog))
        elif cmd == "p":
            con.print(policy_table())
        elif cmd == "v":
            do_verify(st)
        elif cmd == "a":
            do_audit()
        elif cmd == "h":
            con.print(menu())
        elif cmd.startswith("q") and cmd[1:].isdigit() and 1 <= int(cmd[1:]) <= len(PRESETS):
            name, sql = PRESETS[int(cmd[1:]) - 1]
            do_query(st, sql, title=name)
        else:
            do_query(st, cmd)


def demo(pause=2.5):
    """Scripted walkthrough for the video: same steps as the speaking script."""
    st = State()

    def step(title):
        con.rule(f"[bold #00a3ee]{title}")
        time.sleep(pause / 2)

    con.clear()
    con.print(header(st))
    step("1. Auto-scan the database for PII")
    do_scan(st)
    time.sleep(pause)
    step("2. Policy: tag x role -> mask")
    con.print(policy_table())
    time.sleep(pause)
    for role in ROLES:
        st.role = role
        step(f"3. Same query as {role.upper()}")
        con.print(header(st))
        do_query(st, PRESETS[0][1], PRESETS[0][0])
        time.sleep(pause)
    st.role = "support"
    step("4. Bypass attempts as SUPPORT")
    for i in (1, 2, 3):
        do_query(st, PRESETS[i][1], PRESETS[i][0])
        time.sleep(pause)
    st.role = "analyst"
    step("5. Analyst: analytics still work on hashes")
    do_query(st, PRESETS[5][1], PRESETS[5][0])
    time.sleep(pause)
    st.role = "support"
    step("6. Inference attack + write attempt (SUPPORT)")
    do_query(st, PRESETS[6][1], PRESETS[6][0])
    do_query(st, PRESETS[7][1], PRESETS[7][0])
    time.sleep(pause)
    step("7. Same engine, second database: MySQL")
    st.switch_backend("mysql")
    con.print(header(st))
    do_scan(st)
    do_query(st, PRESETS[0][1], PRESETS[0][0])
    time.sleep(pause)
    step("8. Proof: raw tables unchanged + audit trail")
    do_verify(st)
    do_audit()


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "seed":
        if os.path.exists(AUDIT_PATH):
            os.remove(AUDIT_PATH)
        seed.seed_sqlite()
        con.print("[green]SQLite seeded[/]")
        try:
            seed.seed_mysql()
            con.print("[green]MySQL seeded[/]")
        except Exception as e:
            con.print(f"[yellow]MySQL skipped: {e}[/]")
    elif arg == "demo":
        demo(float(sys.argv[2]) if len(sys.argv) > 2 else 2.5)
    else:
        interactive()


if __name__ == "__main__":
    main()
