"""Query-time masking engine.

1. parse the SQL into an AST (sqlglot) and expand SELECT * / aliases against the live schema
2. trace each output column back to its source table.column (lineage), through sub-queries and functions
3. inference guard: refuse filters/sorts/joins on columns the role may not see (stops WHERE-probing)
4. run the read-only query, mask each output column per policy, write an audit record
"""
import datetime
import json
import os

import sqlglot
from sqlglot import exp
from sqlglot.lineage import lineage
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, build_scope

from . import masks
from .backends import HERE

AUDIT_PATH = os.path.join(HERE, "audit.jsonl")
ROLES = ["admin", "support", "analyst"]

# tag x role -> strategy
POLICY = {
    "PII_HIGH": {"admin": "FULL", "support": "PARTIAL", "analyst": "REDACT"},
    "PII_MEDIUM": {"admin": "FULL", "support": "PARTIAL", "analyst": "HASH"},
    "FINANCIAL_CONFIDENTIAL": {"admin": "FULL", "support": "REDACT", "analyst": "BUCKET"},
    "PII_FREE_TEXT": {"admin": "FULL", "support": "PARDA_REDACT", "analyst": "PARDA_REDACT"},
}
# analysts may filter/join on hashed columns only by equality with another hashed column; keep it simple: no.


class Blocked(Exception):
    pass


def _source_columns(node):
    """Leaf (table, column) pairs feeding a lineage node."""
    out = set()
    for n in node.walk():
        if not n.downstream and isinstance(n.source, exp.Table):
            out.add((n.source.name, n.name.split(".")[-1].strip('"`')))
    return out


def _resolve(col, scope, schema, dialect):
    src = scope.sources.get(col.table)
    if isinstance(src, exp.Table):
        return {(src.name, col.name)}
    if isinstance(src, Scope):
        try:
            return _source_columns(lineage(col.name, src.expression, schema=schema, dialect=dialect))
        except Exception:
            return set()
    return set()


class Engine:
    def __init__(self, backend, catalog):
        self.b = backend
        self.catalog = catalog  # {table: {col: {tag, kind, ...}}}
        self.schema = backend.schema()

    def tag_of(self, table, col):
        return self.catalog.get(table, {}).get(col)

    def strategy(self, role, info):
        if info is None:
            return "FULL"
        return POLICY[info["tag"]][role]

    def plan(self, sql, role):
        tree = sqlglot.parse_one(sql, read=self.b.dialect)
        if not isinstance(tree, (exp.Select, exp.Union)) and not tree.find(exp.Select):
            raise Blocked("only read queries are allowed through PardaDB")
        if tree.find(exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create):
            raise Blocked("write statements are blocked: PardaDB is read-only by design")
        tree = qualify(tree, schema=self.schema, dialect=self.b.dialect)

        # inference guard
        if role != "admin":
            root = build_scope(tree)
            for scope in root.traverse():
                for clause in (exp.Where, exp.Having, exp.Order, exp.Group, exp.Join):
                    for node in scope.expression.find_all(clause):
                        for c in node.find_all(exp.Column):
                            for t, cname in _resolve(c, scope, self.schema, self.b.dialect):
                                info = self.tag_of(t, cname)
                                strat = self.strategy(role, info) if info else "FULL"
                                # deterministic hashes may be grouped/joined (equality only), never filtered or sorted
                                if strat == "HASH" and clause in (exp.Group, exp.Join):
                                    continue
                                if strat != "FULL":
                                    raise Blocked(
                                        f"inference guard: role '{role}' cannot filter, sort, group or join on "
                                        f"{t}.{cname} ({info['tag']}); that would leak masked values"
                                    )

        plan = []
        for name in tree.named_selects:
            srcs = _source_columns(lineage(name, tree, schema=self.schema, dialect=self.b.dialect))
            infos = [(s, self.tag_of(*s)) for s in srcs]
            infos = [(s, i) for s, i in infos if i]
            if not infos:
                plan.append((name, "FULL", None, srcs))
                continue
            # strongest restriction wins
            order = ["REDACT", "BUCKET", "HASH", "PARDA_REDACT", "PARTIAL", "FULL"]
            strat = min((self.strategy(role, i) for _, i in infos), key=order.index)
            src, info = infos[0]
            direct = len(srcs) == 1 and isinstance(_find_select(tree, name), exp.Column)
            if strat == "PARTIAL" and not direct:
                strat = "REDACT"  # derived expression (SUBSTR, CONCAT...): partial view is meaningless
            plan.append((name, strat, info, srcs))
        return tree, plan

    def run(self, sql, role):
        rec = dict(ts=datetime.datetime.now().isoformat(timespec="seconds"), backend=self.b.name, role=role, sql=sql)
        try:
            tree, plan = self.plan(sql, role)
        except Blocked as e:
            rec.update(status="BLOCKED", reason=str(e))
            self._audit(rec)
            raise
        cols, rows = self.b.execute(tree.sql(dialect=self.b.dialect))
        out = []
        for r in rows:
            out.append([masks.STRATEGIES[s](v, i["kind"] if i else None) for v, (_, s, i, _) in zip(r, plan)])
        rec.update(status="OK", rows=len(out), masked={n: s for n, s, i, _ in plan if s != "FULL"})
        self._audit(rec)
        return cols, out, plan

    def _audit(self, rec):
        with open(AUDIT_PATH, "a") as f:
            f.write(json.dumps(rec) + "\n")


def _find_select(tree, name):
    sel = tree if isinstance(tree, exp.Select) else tree.find(exp.Select)
    for e in sel.expressions:
        if e.alias_or_name == name:
            return e.this if isinstance(e, exp.Alias) else e
    return None
