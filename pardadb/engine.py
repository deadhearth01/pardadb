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
            pass
    raise Blocked(f"cannot resolve column {col.sql()} for the inference guard; query refused")


def _is_direct(node):
    """True when every hop from the output to the source is a bare column or a rename (no functions, no math)."""
    for n in node.walk():
        e = n.expression
        inner = e.this if isinstance(e, exp.Alias) else e
        if not isinstance(inner, (exp.Column, exp.Table)):
            return False
    return True


BANNED_FUNCS = {"LOAD_FILE", "SLEEP", "BENCHMARK", "LOAD_EXTENSION", "READFILE", "WRITEFILE", "SYS_EXEC", "SYS_EVAL"}


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

    def _base_hash(self, col, scope, role):
        """Column read straight from a base table (no sub-query hop) whose strategy for this role is HASH."""
        src = scope.sources.get(col.table)
        if not isinstance(src, exp.Table):
            return False
        info = self.tag_of(src.name, col.name)
        return bool(info) and self.strategy(role, info) == "HASH"

    def _hash_safe(self, col, clause, scope, role):
        if not self._base_hash(col, scope, role):
            return False
        if isinstance(clause, exp.Group) and col.parent is clause:
            return True
        if isinstance(clause, exp.Join) and isinstance(col.parent, exp.EQ):
            other = col.parent.expression if col.parent.this is col else col.parent.this
            return isinstance(other, exp.Column) and self._base_hash(other, scope, role)
        return False

    def plan(self, sql, role):
        tree = sqlglot.parse_one(sql, read=self.b.dialect)
        if not isinstance(tree, (exp.Select, exp.Union)) and not tree.find(exp.Select):
            raise Blocked("only read queries are allowed through PardaDB")
        if tree.find(exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create):
            raise Blocked("write statements are blocked: PardaDB is read-only by design")
        if tree.find(exp.Into):
            raise Blocked("SELECT ... INTO is blocked")
        for f in tree.find_all(exp.Func):
            name = (f.sql_name() if not isinstance(f, exp.Anonymous) else f.name).upper()
            if name in BANNED_FUNCS:
                raise Blocked(f"function {name} is blocked")
        tree = qualify(tree, schema=self.schema, dialect=self.b.dialect)

        # inference guard
        if role != "admin":
            # ORDER BY on a set operation (UNION / INTERSECT / EXCEPT) may only name an output (bare name or position)
            for setop in tree.find_all(exp.SetOperation):
                order = setop.args.get("order")
                outputs = setop.named_selects
                for item in (order.expressions if order else []):
                    e = item.this if isinstance(item, exp.Ordered) else item
                    if isinstance(e, exp.Literal) and e.is_int and 1 <= int(e.this) <= len(outputs):
                        name = outputs[int(e.this) - 1]
                    elif isinstance(e, exp.Column) and not e.table and e.name in outputs:
                        name = e.name
                    else:
                        raise Blocked(f"ORDER BY {e.sql()} on a set operation must name an output column; query refused")
                    try:
                        srcs = _source_columns(lineage(name, setop, schema=self.schema, dialect=self.b.dialect))
                    except Exception:
                        raise Blocked(f"cannot resolve ORDER BY {name}; query refused")
                    for t, cname in srcs:
                        info = self.tag_of(t, cname)
                        if info and self.strategy(role, info) != "FULL":
                            raise Blocked(f"inference guard: role '{role}' cannot sort on {t}.{cname} ({info['tag']})")
            root = build_scope(tree)
            scopes = list(root.traverse())
            covered = {id(sc.expression) for sc in scopes}
            if any(id(sel) not in covered for sel in tree.find_all(exp.Select)):
                raise Blocked("query contains a SELECT the inference guard cannot analyse; query refused")
            for scope in scopes:
                for clause in (exp.Where, exp.Having, exp.Order, exp.Group, exp.Join, exp.Window, exp.Qualify):
                    for node in scope.expression.find_all(clause):
                        for c in node.find_all(exp.Column):
                            owner = c.find_ancestor(exp.Select)
                            if owner is None:
                                continue  # set-operation ORDER BY: checked above via output lineage
                            if owner is not scope.expression:
                                continue  # belongs to a sub-query scope, which traverse() also visits
                            for t, cname in _resolve(c, scope, self.schema, self.b.dialect):
                                info = self.tag_of(t, cname)
                                strat = self.strategy(role, info) if info else "FULL"
                                if strat == "FULL":
                                    continue
                                # deterministic hashes may be grouped or equi-joined as bare columns, nothing else
                                if strat == "HASH" and self._hash_safe(c, node, scope, role):
                                    continue
                                raise Blocked(
                                    f"inference guard: role '{role}' cannot filter, sort, group or join on "
                                    f"{t}.{cname} ({info['tag']}); that would leak masked values"
                                )

        plan = []
        for name in tree.named_selects:
            node = lineage(name, tree, schema=self.schema, dialect=self.b.dialect)
            srcs = _source_columns(node)
            infos = [(s, self.tag_of(*s)) for s in srcs]
            infos = [(s, i) for s, i in infos if i]
            if not infos:
                plan.append((name, "FULL", None, srcs))
                continue
            # strongest restriction wins
            order = ["REDACT", "BUCKET", "HASH", "PARDA_REDACT", "PARTIAL", "FULL"]
            strat = min((self.strategy(role, i) for _, i in infos), key=order.index)
            src, info = infos[0]
            if strat != "FULL" and not (len(srcs) == 1 and _is_direct(node)):
                strat = "REDACT"  # derived from a masked column (SUBSTR, CONCAT, math...): never partial/hash/bucket
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

