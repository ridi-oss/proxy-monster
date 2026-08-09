# Test-only: the Python parity oracle for the Go probe. Runs on the pinned Python sqlglot 30.12.0
# reference; `driver.py` feeds it the corpus and `analyzer/probe/parity_test.go` diffs its output
# against the Go probe (and regenerates `analyzer/probe/testdata/golden.json` under PROBE_REGEN=1).
"""
proxy-monster Layer-1 lineage probe on sqlglot — emits the ProbeResult JSON the Go probe emits
(origins / references / isWrite), so the two are diffable field by field.

Contract (the Go ProbeResult struct in analyzer/probe/probe.go; the authoritative authorization
schema the analyzer finally emits is StatementFacts in proto/src/main/proto/analyzer.proto):
  resolved       : reached lineage (else fail-closed DENY)
  failedStage    : PARSE | VALIDATE | CONVERT | LINEAGE  (on failure)
  origins        : ordered [{column, origins:[base 'table.col']}] — ordinal = output position (masking binds by it)
  references     : {bucket: [base cols]} — source cols used OUTSIDE the SELECT output; any
                   masked/denied column here → DENY. A conservation backstop routes every column a
                   statement touches in an unmodeled position (incl. a write's payload) to OTHER, so
                   the analyzer is fail-closed by default rather than ALLOW-by-default.
  isWrite        : INSERT/UPDATE/DELETE/MERGE/SELECT-INTO or CTAS/CREATE VIEW — a write can't be
                   masked, so any masked/denied column it touches (origins ∪ references) is DENY.

The reference bucket only feeds the audit reason string; the DENY decision needs only the *union*
of non-output references.
"""
import json
from collections import defaultdict
from sqlglot import parse, exp
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import traverse_scope

# Reference-bucket names — MUST match the bucket constants in analyzer/probe/probe.go.
# OTHER is the conservation catch-all: any column touched in a position we didn't specifically model
# (fail-closed — a protected column landing here → DENY, never a silent ALLOW).
PREDICATE, JOIN, GROUP_BY, ORDER_BY, AGGREGATE, SUBQUERY, SET_OP, RECURSIVE, DERIVED, OTHER = (
    "PREDICATE", "JOIN", "GROUP_BY", "ORDER_BY", "AGGREGATE", "SUBQUERY", "SET_OP", "RECURSIVE", "DERIVED", "OTHER",
)
KNOWN_ROOTS = (exp.Select, exp.SetOperation, exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create)

# Functions that execute arbitrary SQL, reach another server, or touch the filesystem — they can
# smuggle a protected read inside a STRING literal that column lineage can't see, so fail closed.
_DANGEROUS_FUNCS = {
    "dblink", "dblink_exec", "dblink_open", "dblink_fetch", "dblink_send_query",   # cross-server SQL
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",            # filesystem read
    "lo_import", "lo_export", "load_file",                                          # large-object / file IO
    "query_to_xml", "query_to_xml_and_xmlschema", "xpath_table",                    # run-SQL-return-result
}

# ---- Known deliberate DENYs (documented over-denials — fail-closed-SAFE, not analyzer bugs) ----
# These statements DENY because they can't be analyzed here, not because they leak. Catalogued so a
# maintainer triaging a DENY knows it's intentional. Revisit if a real workload needs one.
#
# A. PARITY-CORPUS BOUNDARY — this oracle is pinned to Python sqlglot v30.12.0, which cannot represent
#    sqlglot-go's structural MySQL `REPLACE INTO …` and `INSERT … SET col = val` extensions. Their
#    fail-closed conservation regressions therefore live in Go tests outside the parity corpus
#    (analyzer/probe/newly_parseable_conservation_test.go); adding them here would compare structured
#    Go analysis against an opaque command or parse failure, not a meaningful equivalent AST.
#
# B. INTENTIONAL fail-closed — parses fine, but exposes no analyzable lineage and/or is a policy call:
#      • plain `CREATE TABLE t (cols)` (no AS-query) — creates an empty table, reads nothing; a
#        DDL-authorization decision, not a lineage one.
#      • `COPY (SELECT …) TO …` / bulk-export commands — a raw exfiltration path; deny by default.
#      • data-modifying CTE `WITH a AS (INSERT|UPDATE|DELETE|MERGE …) …` — a write nested in a WITH;
#        multi-target CTE-DML lineage is a re-architecture, so fail closed (see the guard below).
#      • a table-valued function as a STANDALONE FROM source that sqlglot models as a table, e.g.
#        `FROM generate_series(1,10) g` — fails the catalog must-exist check ("unknown table"). (A TVF
#        in a LATERAL, e.g. `… CROSS JOIN LATERAL generate_series(…) g`, IS analyzed: its argument
#        columns route through the table-function source pass.)


class Unresolved(Exception):
    def __init__(self, stage, detail=""):
        self.stage = stage
        self.detail = detail


def _fail(stage, detail=""):
    return {"resolved": False, "failedStage": stage, "detail": detail[:150],
            "outputColumns": 0, "tracedColumns": 0, "origins": [], "references": {}, "isWrite": False,
            "rewrittenSql": None}


# ---- physical-column resolution: trace a Column to its base 'table.column' through derived/CTE/union ----

def _selects_for_output(scope, out_name):
    """The projection expression(s) producing `out_name` in a (Select or SetOp) scope."""
    expr = scope.expression
    if isinstance(expr, exp.SetOperation):
        # a set-op scope: recurse into each branch scope for the same output name
        return None  # handled by caller via union_scopes
    projs = []
    for p in expr.selects:
        if p.alias_or_name == out_name or (isinstance(p, exp.Column) and p.name == out_name):
            projs.append(p)
    if not projs and expr.selects:
        # positional fallback (e.g. CTE column alias list) — match by index if names differ
        pass
    return projs


def _cte_col_names(cte):
    """The CTE column-alias list names (`WITH s(x, tag) AS …` -> ['x','tag']), or None. sqlglot stores it
    on the CTE's TableAlias (`alias.columns`), NOT `cte.args['columns']`; for a Select body qualify pushes
    the aliases into the projections (so the list is empty there), but for a SET-OP body it does not — so
    reading only `cte.args['columns']` misses set-op-CTE renames and loses the lineage of `s.x`."""
    cols = cte.args.get("columns")
    if not cols:
        al = cte.args.get("alias")
        cols = al.args.get("columns") if al is not None else None
    return [c.name for c in cols] if cols else None


def _resolve(col, col2scope, seen):
    """Return set of base 'table.column' for a qualified Column node, tracing through scopes."""
    scope = col2scope.get(id(col))
    if scope is None:
        return set()
    return _resolve_in(col.name, col.table, scope, col2scope, seen)


def _resolve_in(name, alias, scope, col2scope, seen):
    key = (id(scope), alias, name)
    if key in seen:
        return set()
    seen.add(key)
    src, sc = None, scope
    while sc is not None:                        # walk parents for correlated refs
        srcs = sc.sources
        if alias and alias in srcs:
            src = srcs[alias]
            break
        if not alias and len(srcs) == 1:
            src = next(iter(srcs.values()))
            break
        sc = sc.parent
    if src is None:
        return set()
    if isinstance(src, exp.Table):
        return {f"{src.name}.{name}"}            # physical table: src.name is the real table name
    # src is a sub-Scope (derived table / CTE / subquery / union)
    return _resolve_scope_output(src, name, col2scope, seen)


def _resolve_scope_output(scope, out_name, col2scope, seen):
    out = set()
    expr = scope.expression
    # A derived-table/CTE scope that WRAPS a set operation reports is_union=False (only the branch
    # scopes carry is_union=True, and they're never reached via sources[alias]) — so key off the
    # expression, not the flag, and resolve out_name by OUTPUT POSITION across every branch.
    if isinstance(expr, exp.SetOperation):
        branches = _leaf_selects(expr)
        cte = expr.parent
        cte_names0 = _cte_col_names(cte) if isinstance(cte, exp.CTE) else None
        if cte_names0:
            names = cte_names0                                    # CTE column-alias list renames outputs
        else:
            names = [p.alias_or_name for p in branches[0].selects] if branches else []
        # union EVERY position whose output name matches — duplicate output aliases (`region AS leak,
        # ssn AS leak`) are legal, and names.index() would return only the first, silently dropping the
        # protected column at a later position. (For unique names this is identical to a single lookup.)
        for i, nm in enumerate(names):
            if nm == out_name:
                for br in branches:
                    if i < len(br.selects):
                        out |= _bases([br.selects[i]], col2scope)
        return out
    if scope.is_union:
        for branch in scope.union_scopes:        # [left, right]
            out |= _resolve_scope_output(branch, out_name, col2scope, seen)
        return out
    if not isinstance(expr, exp.Select):
        return out
    matched = [p for p in expr.selects if p.alias_or_name == out_name]
    if not matched:
        # CTE column-alias list renames outputs positionally: map by index
        cte = scope.expression.parent
        cte_names0 = _cte_col_names(cte) if isinstance(cte, exp.CTE) else None
        if cte_names0:
            names = cte_names0
            if out_name in names:
                idx = names.index(out_name)
                if idx < len(expr.selects):
                    matched = [expr.selects[idx]]
    for p in matched:
        for c in p.find_all(exp.Column):
            out |= _resolve_in(c.name, c.table, scope, col2scope, seen)
    return out


# ---- identity-aware resolution: like _resolve, but also reports whether EVERY hop on the path is a
# value-preserving bare-column identity. An output is a maskable ORIGIN only if it is — a transform
# anywhere on the path (even one scope down: `SELECT c FROM (SELECT substr(ssn) AS c …) t`) means masking
# the output cell masks the TRANSFORMED value, not the source, so the output must be DERIVED (DENY). ----

def _resolve_ident(col, col2scope, seen):
    """(bases, is_identity) for a column, tracing scopes. is_identity is False if any hop is a transform."""
    scope = col2scope.get(id(col))
    if scope is None:
        return set(), True
    key = (id(scope), col.table, col.name)
    if key in seen:
        return set(), True
    seen = seen | {key}
    src, sc = None, scope
    while sc is not None:
        srcs = sc.sources
        if col.table and col.table in srcs:
            src = srcs[col.table]
            break
        if not col.table and len(srcs) == 1:
            src = next(iter(srcs.values()))
            break
        sc = sc.parent
    if src is None:
        return set(), True
    if isinstance(src, exp.Table):
        return {f"{src.name}.{col.name}"}, True
    return _scope_out_ident(src, col.name, col2scope, seen)


def _scope_out_ident(scope, out_name, col2scope, seen):
    """(bases, is_identity) for output `out_name` of a sub-scope — mirrors _resolve_scope_output but
    marks the path non-identity if the producing projection is a computed expression."""
    expr = scope.expression
    if isinstance(expr, exp.SetOperation):
        branches = _leaf_selects(expr)
        cte = expr.parent
        cte_names0 = _cte_col_names(cte) if isinstance(cte, exp.CTE) else None
        if cte_names0:
            names = cte_names0
        else:
            names = [p.alias_or_name for p in branches[0].selects] if branches else []
        out, ident = set(), True
        for i, nm in enumerate(names):
            if nm == out_name:
                for br in branches:
                    if i < len(br.selects):
                        b, sub = _proj_ident(br.selects[i], col2scope, seen)
                        out |= b
                        ident = ident and sub
        return out, ident
    if scope.is_union:
        out, ident = set(), True
        for branch in scope.union_scopes:
            b, sub = _scope_out_ident(branch, out_name, col2scope, seen)
            out |= b
            ident = ident and sub
        return out, ident
    if not isinstance(expr, exp.Select):
        return set(), True
    matched = [p for p in expr.selects if p.alias_or_name == out_name]
    if not matched:
        cte = expr.parent
        cte_names0 = _cte_col_names(cte) if isinstance(cte, exp.CTE) else None
        if cte_names0:
            names = cte_names0
            if out_name in names:
                idx = names.index(out_name)
                if idx < len(expr.selects):
                    matched = [expr.selects[idx]]
    out, ident = set(), True
    for p in matched:
        b, sub = _proj_ident(p, col2scope, seen)
        out |= b
        ident = ident and sub
    return out, ident


def _proj_ident(p, col2scope, seen):
    """(bases, is_identity) for one projection. Identity iff p is a bare/aliased column AND the column it
    refers to resolves through an identity path. A computed expression → all its columns' bases, non-id."""
    ic = _identity_col(p)
    if ic is None:
        b = set()
        for c in p.find_all(exp.Column):
            bb, _ = _resolve_ident(c, col2scope, seen)
            b |= bb
        return b, False
    return _resolve_ident(ic, col2scope, seen)


def _bases(nodes, col2scope):
    out = set()
    for n in nodes:
        for c in ([n] if isinstance(n, exp.Column) else n.find_all(exp.Column)):
            out |= _resolve(c, col2scope, set())
    return out


def _identity_col(p):
    """If projection `p` is a bare column (optionally just aliased) — a value-preserving IDENTITY of
    that column, so masking the output cell fully protects it — return that Column; else None. Any
    computed expression (function/operator/cast/CASE/…) is NOT an identity: masking its rendered
    result doesn't protect the source value (e.g. last4 of substr(ssn) leaks the first digits)."""
    while isinstance(p, exp.Alias):
        p = p.this
    return p if isinstance(p, exp.Column) else None


def _leaf_selects(setop):
    """All leaf SELECT branches of a (possibly nested) set operation, left-to-right."""
    out = []
    for side in (setop.left, setop.right):
        if isinstance(side, exp.SetOperation):
            out += _leaf_selects(side)
        elif isinstance(side, exp.Select):
            out.append(side)
        elif isinstance(side, exp.Subquery):
            # a parenthesized branch: `(A UNION ALL B) UNION ALL C` wraps the inner set-op in a Subquery —
            # recurse so its leaves are found, else the branch's outputs vanish from origins (over-deny).
            if isinstance(side.this, exp.SetOperation):
                out += _leaf_selects(side.this)
            elif isinstance(side.this, exp.Select):
                out.append(side.this)
    return out


def _from_source_order(sel):
    """Alias order of FROM/JOIN sources, left-to-right — the order the backend expands a bare `SELECT *`
    into (and thus the wire column order the mask ordinals must match). sqlglot's expand_stars instead
    orders physical tables before derived tables, so bare-`*` origins must be re-sorted to this order."""
    order = []

    def alias_of(src):
        if isinstance(src, exp.Subquery):
            return src.alias
        if isinstance(src, exp.Table):
            return src.alias or src.name
        return None

    frm = sel.args.get("from") or sel.args.get("from_")   # sqlglot suffixes the Python keyword arg
    if frm is not None:
        order.append(alias_of(frm.this))
        for e in (frm.args.get("expressions") or []):
            order.append(alias_of(e))
    for j in (sel.args.get("joins") or []):
        if j.this is not None:
            order.append(alias_of(j.this))
    return [a for a in order if a]


def _is_star(p):
    """A projection that IS a star: a bare `*` (exp.Star) or a qualified `t.*` (Column whose this is Star).
    NOT `count(*)` (the Star is a func arg, not a projection)."""
    return isinstance(p, exp.Star) or (isinstance(p, exp.Column) and isinstance(p.this, exp.Star))


def _expandable_sources(sel):
    """The proven-faithful expansion envelope (verified byte-identical vs live PG + MySQL). A starred
    select's FROM/JOIN sources must each be a base table or a subquery (CTE refs parse as tables), and no
    join may be NATURAL (sqlglot's expand_stars does NOT merge NATURAL common columns — it emits both
    copies; NATURAL is already denied globally, this is defense-in-depth). LATERAL / VALUES-constructor /
    unnest / table-valued-function sources fall outside the envelope (residual star and/or dialect-fragile
    regeneration) → the caller fails closed. Returns (ok, reason)."""
    frm = sel.args.get("from") or sel.args.get("from_")
    srcs = ([frm.this] if frm else [])
    for j in (sel.args.get("joins") or []):
        if (j.args.get("method") or "").upper() == "NATURAL" or j.args.get("kind") == "NATURAL":
            return False, "a NATURAL join"
        srcs.append(j.this)
    for s in srcs:
        if isinstance(s, exp.Subquery):
            continue
        # A base table / CTE-ref is `Table(this=Identifier)`. A table-valued FUNCTION (generate_series,
        # json_to_recordset, …) also parses as exp.Table but with `this` = a function node — sqlglot's
        # regeneration of a TVF (esp. one needing a column-definition list) is not verified faithful, so
        # exclude it. Only real base tables / CTE refs and subqueries stay in the envelope.
        if isinstance(s, exp.Table) and isinstance(s.this, exp.Identifier):
            continue
        kind = type(s.this).__name__ if isinstance(s, exp.Table) and s.this is not None else type(s).__name__
        return False, f"a {kind.lower()} source (table-function / VALUES / LATERAL)"
    return True, None


def _resort_bare_star_inplace(osel, qsel):
    """Mutate qsel's projections: re-sort the bare `*`'s expanded BLOCK into FROM-source order, so the
    serialized query's column order (which the backend echoes verbatim, since we send explicit columns)
    equals the order origins index — and matches native `SELECT *` for the client. sqlglot expands physical
    tables before derived tables; the DB uses FROM order. `osel` (pre-qualify) locates the bare Star and
    the explicit projections around it (each a single column, since a bare `*` mixed with ANOTHER star is
    already denied), so `SELECT *, expr` keeps `expr` in place and only the star's span is reordered. Called
    only after the faithful-envelope gate, so every star column resolves to a table/subquery source with an
    alias. Python's sort is stable, preserving each source's internal order; a USING-merge
    `COALESCE(a.id,b.id)` sorts by its first table."""
    star_idx = next((i for i, p in enumerate(osel.selects) if isinstance(p, exp.Star)), None)
    if star_idx is None:
        return
    qs = qsel.selects
    nb, na = star_idx, len(osel.selects) - star_idx - 1
    fo = _from_source_order(qsel)
    pos = {a: i for i, a in enumerate(fo)}
    block = sorted(qs[nb: len(qs) - na], key=lambda p: pos.get(
        p.find(exp.Column).table if p.find(exp.Column) else "", len(fo)))
    qsel.set("expressions", qs[:nb] + block + qs[len(qs) - na:])


def _cte_referenced(cte, root):
    """True if `cte` is referenced as a source anywhere OUTSIDE its own definition (main query or a
    sibling CTE). A CTE never referenced is dead — it contributes no columns to the result, so it must
    not be swept by the fail-closed backstops (e.g. a dead sibling in a WITH RECURSIVE block)."""
    nm = cte.alias_or_name.lower()
    for t in root.find_all(exp.Table):
        if t.name.lower() == nm and t.find_ancestor(exp.CTE) is not cte:
            return True
    return False


# ---- write-payload resolution: UPDATE/MERGE/INSERT payloads aren't in any traverse_scope() scope
# (qualify leaves UPDATE SET cols unqualified; MERGE has 0 scopes), so resolve via an alias→source map. ----

def _alias_sources(node):
    """alias/name -> ('table', real_name) | ('subq', inner Select/SetOp) for one statement level."""
    m = {}
    for t in node.find_all(exp.Table):
        m.setdefault(t.alias or t.name, ("table", t.name))
        m.setdefault(t.name, ("table", t.name))
    for sq in node.find_all(exp.Subquery):
        if sq.alias and isinstance(sq.this, (exp.Select, exp.SetOperation)):
            m[sq.alias] = ("subq", sq.this)
    return m


def _resolve_write(col, alias_map, default_table, seen):
    alias, name = col.table, col.name
    if (alias, name) in seen:
        return set()
    seen.add((alias, name))
    if not alias:
        if default_table:
            return {f"{default_table}.{name}"}
        tbls = {v[1] for v in alias_map.values() if v[0] == "table"}
        return {f"{next(iter(tbls))}.{name}"} if len(tbls) == 1 else set()
    src = alias_map.get(alias)
    if src is None:
        return set()
    if src[0] == "table":
        return {f"{src[1]}.{name}"}
    sub = src[1]
    sub_selects = _leaf_selects(sub) if isinstance(sub, exp.SetOperation) else [sub]
    sub_alias = _alias_sources(sub)
    out = set()
    for s in sub_selects:
        for p in s.selects:
            if p.alias_or_name == name:
                for c in p.find_all(exp.Column):
                    out |= _resolve_write(c, sub_alias, None, seen)
    return out


def _target_name(write_target):
    if write_target is None:
        return None
    if isinstance(write_target, exp.Table):
        return write_target.name
    t = write_target.find(exp.Table)
    return t.name if t else None


def _set_assignments(node):
    """SET-assignment EQ nodes (their LHS is a write destination, not a read): UPDATE/MERGE-WHEN-UPDATE
    SET, and INSERT … ON CONFLICT DO UPDATE SET. Distinct from predicate EQs (same shape, different
    context) — used to exclude assignment targets from the write read-conservation backstop."""
    out = []
    for upd in node.find_all(exp.Update):
        out += [e for e in (upd.args.get("expressions") or []) if isinstance(e, exp.EQ)]
    for oc in node.find_all(exp.OnConflict):
        out += [e for e in (oc.args.get("expressions") or []) if isinstance(e, exp.EQ)]
    return out


# ---- opaque-subquery detection: a Select in expression position (IN/EXISTS/scalar/lateral) ----

def _is_expression_subquery(node):
    """True if this Select/SetOp sits in an expression context (predicate/projection/function arg),
    not a plain FROM/JOIN derived table."""
    p = node.parent
    while p is not None:
        if isinstance(p, (exp.Exists, exp.In, exp.Any, exp.All)):
            return True
        # a subquery that is an ARGUMENT to a function / array constructor / unnest (even in FROM
        # position, e.g. unnest(ARRAY(SELECT ssn …))) is an expression, not a transparent source.
        if isinstance(p, (exp.Func, exp.Array, exp.Unnest)):
            return True
        if isinstance(p, exp.Subquery):
            # a Subquery wrapper: FROM/JOIN source if its parent is From/Join/Lateral; else expression
            gp = p.parent
            if isinstance(gp, (exp.From, exp.Join)):
                return False
            if isinstance(gp, exp.Lateral):
                return True
            if not isinstance(gp, exp.SetOperation):
                return True   # scalar subquery in SELECT/WHERE/etc.
            # else: a parenthesized set-op BRANCH (`(A UNION B) UNION C`) — transparent, its outputs flow to
            # the result; opacity is the ENCLOSING set-op's (an `x IN ((A) UNION (B))` is still opaque via
            # the In ancestor). Fall through to walk up from the set-op rather than classify it opaque here.
        if isinstance(p, exp.Lateral):
            return True
        if isinstance(p, (exp.From, exp.Join)):
            return False
        if isinstance(p, (exp.Select, exp.Insert, exp.Update, exp.Merge, exp.Delete, exp.Create)):
            return False
        p = p.parent
    return False


def _enclosing_opaque(node, opaque_selects):
    """The nearest ancestor Select that is an opaque subquery (so its clause cols are SUBQUERY, not PREDICATE)."""
    p = node.parent
    while p is not None:
        if id(p) in opaque_selects:
            return p
        p = p.parent
    return None


def probe(sql, dialect, schema):
    dialect = dialect.lower() if dialect else None
    # --- parse: exactly one recognized statement, else fail-closed ---
    try:
        stmts = [s for s in parse(sql, dialect=dialect) if s is not None]
    except Exception as e:
        return _fail("PARSE", f"{type(e).__name__}: {e}")
    if len(stmts) != 1:
        return _fail("PARSE", f"expected 1 statement, got {len(stmts)}")
    root = stmts[0]
    if not isinstance(root, KNOWN_ROOTS):
        return _fail("PARSE", f"unsupported root {type(root).__name__}")

    # --- a dangerous function (arbitrary SQL / cross-server / filesystem) can hide a protected read in
    # a string literal that lineage can't see → fail closed. ---
    for fn in root.find_all(exp.Func):
        if (fn.name or "").lower() in _DANGEROUS_FUNCS:
            return _fail("VALIDATE", f"function '{fn.name.lower()}' can execute opaque SQL / IO — not allowed")

    # --- case-fold identifiers for matching. MySQL is case-insensitive for columns (and usually tables)
    # and PG folds unquoted identifiers to lowercase, but sqlglot preserves spelling — so a MySQL
    # `SELECT * FROM Users` never matches the lowercase catalog, silently leaving `*` unexpanded (a full
    # bypass), and `Users.Ssn` resolves to an origin string that misses the policy key. Normalize UNQUOTED
    # identifiers on this analysis copy (the query the backend runs is untouched) and match a lowercased
    # schema, so resolution + policy matching are case-insensitive. For MySQL, also fold QUOTED identifiers:
    # MySQL column names are always case-insensitive and `` `Users`.`SSN` `` otherwise skips the policy key
    # (a leak) or fails the column-existence check as unknown (an over-deny). PG quoted idents ARE
    # case-sensitive, so they stay untouched. ---
    fold_quoted = dialect == "mysql"
    for ident in root.find_all(exp.Identifier):
        if fold_quoted or not ident.args.get("quoted"):
            ident.set("this", ident.this.lower())
    schema = {t.lower(): {c.lower(): v for c, v in cols.items()} for t, cols in schema.items()}

    # --- classify write + pick the query whose OUTPUTS are maskable origins ---
    is_write = False
    analyze_query = root            # Select/SetOp whose outputs -> origins
    insert_select = None            # a Select/SetOp whose outputs are the write payload
    payload_exprs = []              # raw expressions whose columns are the write payload
    write_target = None             # table being written (excluded from must-exist check)

    if isinstance(root, exp.Create):
        write_target = root.this
        if root.expression is not None and isinstance(root.expression, (exp.Select, exp.SetOperation)):
            is_write = True
            analyze_query = root.expression      # CTAS/VIEW: origins carry the inner query
        else:
            return _fail("VALIDATE", "CREATE without analyzable query")
    elif isinstance(root, exp.Insert):
        is_write = True
        analyze_query = None
        write_target = root.this
        if isinstance(root.expression, (exp.Select, exp.SetOperation)):
            insert_select = root.expression
        else:
            payload_exprs = [root.expression]    # VALUES/Tuple
    elif isinstance(root, exp.Update):
        is_write = True
        analyze_query = None
        write_target = root.this
        payload_exprs = [eq.expression for eq in root.args.get("expressions", []) if isinstance(eq, exp.EQ)]
    elif isinstance(root, exp.Delete):
        is_write = True
        analyze_query = None
        write_target = root.this                 # payload none; WHERE -> references
    elif isinstance(root, exp.Merge):
        is_write = True
        analyze_query = None
        write_target = root.this
        whens = root.args.get("whens")
        for when in (whens.expressions if whens else []):
            then = when.args.get("then")
            if isinstance(then, exp.Update):
                payload_exprs += [eq.expression for eq in then.args.get("expressions", []) if isinstance(eq, exp.EQ)]
            elif isinstance(then, exp.Insert):
                ie = then.expression
                if ie is not None:
                    payload_exprs.append(ie)
    elif isinstance(root, exp.Select) and root.args.get("into"):
        is_write = True                          # SELECT ... INTO leak
        write_target = root.args["into"]
        insert_select = root
        analyze_query = None

    # --- fail-closed on constructs the resolver can't reason about reliably ---
    # data-modifying CTE (WITH a AS (INSERT|UPDATE|DELETE|MERGE … [RETURNING …]) …): the write hides in
    # a WITH clause. When the outer statement is a SELECT, root-type-based is_write stays False so the
    # whole write backstop is skipped, and the nested DML's SET/WHERE/RETURNING live in Update/Delete/
    # Insert nodes the read passes (which walk find_all(Select)) never scan — so the write, and any
    # RETURNING of a protected column, is invisible → ALLOW. Analyzing multi-target CTE-DML (several write
    # targets, RETURNING chains) is a re-architecture; fail closed (root-agnostic: also covers a DML CTE
    # nested inside a write root, where payload lineage can't trace through a DELETE/UPDATE-bodied CTE).
    for cte in root.find_all(exp.CTE):
        if isinstance(cte.this, (exp.Insert, exp.Update, exp.Delete, exp.Merge)):
            return _fail("VALIDATE", "data-modifying CTE not supported")
    if list(root.find_all(exp.Pivot)):
        return _fail("VALIDATE", "PIVOT/UNPIVOT not supported")   # output columns are data-dependent
    for j in root.find_all(exp.Join):
        if (j.args.get("method") or "").upper() == "NATURAL":
            return _fail("VALIDATE", "NATURAL JOIN not supported (shared-column lineage is ambiguous)")
    for oc in root.find_all(exp.OnConflict):
        if oc.args.get("constraint"):        # ON CONFLICT ON CONSTRAINT <name>: can't map a named
            return _fail("VALIDATE", "ON CONFLICT ON CONSTRAINT — cannot map a named constraint to columns")

    # --- qualify (VALIDATE stage): bind columns to sources, expand *, and VALIDATE every column
    # exists in the supplied schema (validate_qualify_columns + no inference) so a column absent from
    # the catalog fails closed instead of resolving to a fabricated, unpoliced origin. ---
    try:
        # Validate columns against the schema for READS (an unknown read column → fail closed). For
        # WRITES, skip validation — it raises on a correlated column in a write's subquery (a FALSE
        # unknown, since qualify doesn't wire the write target as a correlation source) — and instead
        # schema-check every resolved write column in the write backstop below.
        qroot = qualify(root.copy(), schema=schema, dialect=dialect,
                        qualify_columns=True, validate_qualify_columns=not is_write,
                        expand_stars=True, infer_schema=False)
    except Exception as e:
        return _fail("VALIDATE", f"{type(e).__name__}: {e}")

    # A MySQL/T-SQL multi-table DELETE (`DELETE a FROM sink a …`) carries a delete-TARGET alias list in
    # args['tables'] — bare alias refs (Table nodes named for the alias), NOT source tables. They just
    # duplicate the FROM's aliased tables, so drop them from the analysis copy; left in, the alias reads
    # as an unknown physical table below and pollutes the write backstop's alias→source map.
    if isinstance(qroot, exp.Delete) and qroot.args.get("tables"):
        qroot.set("tables", None)

    # Drop DEAD (unreferenced) CTEs before analysis. Postgres/MySQL don't execute an unreferenced CTE, so
    # its clauses never touch the backend — but the reference sweeps below would still scan them, so a
    # throwaway `WITH dead AS (SELECT id FROM users WHERE ssn='x') SELECT … FROM orders` would over-deny
    # an unrelated live query. Iterate to a fixpoint: dropping one dead CTE can orphan another that only
    # it referenced. (Safe: a CTE referenced anywhere outside its own body is kept, so this can never drop
    # a live read — a dropped CTE contributed nothing to the result.)
    while True:
        dead = [c for w in qroot.find_all(exp.With) for c in list(w.expressions)
                if not _cte_referenced(c, qroot)]
        if not dead:
            break
        for c in dead:
            w = c.parent
            c.pop()
            if isinstance(w, exp.With) and not w.expressions:
                w.pop()

    # --- every physical SOURCE table must exist in the schema, else fail-closed (Calcite validate) ---
    schema_tables = {t.lower() for t in schema}
    cte_names = {c.alias_or_name.lower() for c in qroot.find_all(exp.CTE)}
    target_names = set()
    if write_target is not None:
        for tt in write_target.find_all(exp.Table):
            target_names.add(tt.name.lower())
    for tbl in qroot.find_all(exp.Table):
        # a table-valued function in FROM (generate_series/json_table/jsonb_each/…, incl. the comma-join
        # "implicit lateral" idiom) is wrapped by sqlglot in a Table whose `this` is the FUNCTION node,
        # not an Identifier (real tables always have an Identifier). It has no catalog entry — skip the
        # must-exist check and let the table-function source pass route its argument columns (so a TVF
        # reading a protected column still DENYs, a non-PII one ALLOWs). (`unnest` gets its own node.)
        if not isinstance(tbl.this, exp.Identifier):
            continue
        nm = tbl.name.lower()
        if nm in cte_names or nm in target_names:
            continue
        if nm not in schema_tables:
            return _fail("VALIDATE", f"unknown table {tbl.name}")

    # --- build scope map (col node -> its scope) for physical resolution. traverse_scope(qroot)
    # returns nothing for write roots (INSERT/UPDATE/MERGE), so also scope every nested SELECT (e.g.
    # a subquery inside INSERT…VALUES or an ON CONFLICT action) or its columns silently vanish. ---
    scopes = []
    seen_scope_exprs = set()
    try:
        for sc in traverse_scope(qroot):
            scopes.append(sc)
            seen_scope_exprs.add(id(sc.expression))
        for sel in qroot.find_all(exp.Select):
            if id(sel) in seen_scope_exprs:
                continue
            for sc in traverse_scope(sel):
                if id(sc.expression) not in seen_scope_exprs:
                    scopes.append(sc)
                    seen_scope_exprs.add(id(sc.expression))
    except Exception as e:
        return _fail("CONVERT", f"{type(e).__name__}: {e}")
    col2scope = {}
    for sc in scopes:
        for c in sc.columns:
            col2scope[id(c)] = sc
    # map each SELECT expression -> its scope, so a node that is NOT an exp.Column (a whole-row
    # TableColumn/Dot) can still be resolved against the correct LOCAL scope (walking to parents),
    # exactly like ordinary columns — instead of a flat, scope-blind alias map.
    scope_of_select = {id(sc.expression): sc for sc in scopes}

    # sqlglot builds NO top scope for a write's own clauses (SET/WHERE/USING/ON/RETURNING) or its
    # target/FROM/USING aliases, so write-clause columns and correlated refs to the target can't resolve
    # — the flat alias map that filled that gap is scope-blind (a CTE named like a table, or an alias
    # reused in a nested scope, misresolves → write exfil). Synthesize the top scope sqlglot omits:
    # `SELECT 1 FROM <target> [CROSS JOIN <FROM/USING sources>]` with the write's WITH in effect, so the
    # aliases resolve with correct SQL scoping (a CTE shadows a same-named table). Then splice it as the
    # parent of the write's orphaned subquery scopes so correlated target refs resolve through it, and
    # resolve direct write-clause columns against it (see _wbase). Fail-degrades to the old path if the
    # synthetic build throws.
    write_scope = None
    if is_write:
        wsrcs = []
        def _add_src(x):
            if isinstance(x, exp.Schema):                    # INSERT target w/ a column list: Schema(this=Table, [cols])
                x = x.this
            if isinstance(x, (exp.Table, exp.Subquery)):     # a real row source (bool flags/None ignored)
                wsrcs.append(x.copy())
        _add_src(qroot.this)
        wfrm = qroot.args.get("from") or qroot.args.get("from_")
        if isinstance(wfrm, exp.From):
            _add_src(wfrm.this)
            for e in (wfrm.args.get("expressions") or []):
                _add_src(e)
        for j in (qroot.args.get("joins") or []):
            _add_src(j.this)
        wusing = qroot.args.get("using")
        if wusing is not None and not isinstance(wusing, bool):
            for u in (wusing if isinstance(wusing, list) else [wusing]):
                _add_src(u)
        if wsrcs:
            try:
                syn = exp.select(exp.Literal.number("1")).from_(wsrcs[0])
                for s in wsrcs[1:]:
                    syn = syn.join(s, join_type="cross")
                wwith = qroot.args.get("with") or qroot.args.get("with_")
                if wwith is not None:
                    syn.set("with", wwith.copy())
                synq = qualify(syn, schema=schema, dialect=dialect, qualify_columns=False,
                               validate_qualify_columns=False, expand_stars=False, infer_schema=False)
                syn_scopes = traverse_scope(synq)
                for sc in syn_scopes:
                    for c in sc.columns:
                        col2scope.setdefault(id(c), sc)
                write_scope = syn_scopes[-1] if syn_scopes else None
            except Exception:
                write_scope = None
        # A CTE in the write ROOT's OWN top-level WITH shadows its same-named table statement-wide, but
        # sqlglot's isolated fallback scoping of the write's nested subqueries (traverse_scope returns
        # nothing for a write root) binds that name to the PHYSICAL table, losing the shadow — so a
        # subquery reading through the shadow CTE resolves to the wrong (real, unpoliced) columns. Rebind
        # each such source (outside the CTE's own body, which legitimately reads the real table) to the
        # CTE's scope. ONLY the top-level WITH shadows statement-wide: a CTE defined in an INNER subquery's
        # WITH is scoped to that subquery (and sqlglot binds it natively), so rebinding by name across the
        # whole statement would let a throwaway inner `WITH users AS (…orders…)` hijack a real users.ssn
        # read in a sibling clause → leak. So collect names from the write's top-level WITH only.
        cte_scopes = {}
        top_with = qroot.args.get("with") or qroot.args.get("with_")
        for cte in (top_with.expressions if top_with is not None else []):
            body = cte.this
            bs = scope_of_select.get(id(body))
            # a set-op-bodied CTE (`WITH s AS (SELECT ssn … UNION ALL SELECT region …)`) is a Union, not a
            # Select, so it never entered scope_of_select — scope it directly and register its columns, or a
            # write subquery reading `s.col` resolves to a physical-looking `s.col` and the read is lost.
            if bs is None and isinstance(body, exp.SetOperation):
                try:
                    for s in traverse_scope(body):
                        for c in s.columns:
                            col2scope.setdefault(id(c), s)
                        scope_of_select.setdefault(id(s.expression), s)
                        if s.expression is body:
                            bs = s
                except Exception:
                    bs = None
            if bs is not None:
                cte_scopes[cte.alias_or_name.lower()] = bs
        for sc in scopes:
            if write_scope is not None and sc.parent is None:    # orphaned write subquery -> write scope
                sc.parent = write_scope
            if sc.expression.find_ancestor(exp.CTE) is None:
                for nm, src in list(sc.sources.items()):
                    # Rebind only a BARE reference to the CTE (the source's REAL table name == the CTE
                    # name), not a different physical table merely ALIASED with the CTE's name: `FROM
                    # users audit_summary` is the `users` table (real name `users`), and rebinding it to a
                    # decoy CTE named `audit_summary` would drop `audit_summary.ssn` = users.ssn → leak.
                    if isinstance(src, exp.Table) and (src.name or "").lower() in cte_scopes:
                        sc.sources[nm] = cte_scopes[(src.name or "").lower()]

    # The source query whose OUTPUT columns are the write payload (values stored) — INSERT … SELECT and
    # SELECT … INTO. Its outputs are resolved by lineage in the write backstop (dead source columns
    # excluded), instead of a blanket column sweep. CTAS routes its outputs through `origins` instead.
    payload_query = None
    if isinstance(qroot, exp.Insert) and isinstance(qroot.expression, (exp.Select, exp.SetOperation)):
        payload_query = qroot.expression
    elif isinstance(qroot, exp.Select) and qroot.args.get("into"):
        payload_query = qroot

    try:
        references = defaultdict(set)
        alias_map = _alias_sources(qroot)

        # ---- opaque subqueries (IN/EXISTS/scalar/lateral) -> SUBQUERY ----
        opaque_selects = set()
        for node in qroot.find_all(exp.Select, exp.SetOperation):
            if _is_expression_subquery(node):
                opaque_selects.add(id(node))
                references[SUBQUERY] |= _bases(list(node.find_all(exp.Column)), col2scope)

        # ---- distinct set-ops (UNION distinct / INTERSECT / EXCEPT) -> SET_OP ----
        for so in qroot.find_all(exp.SetOperation):
            distinct = so.args.get("distinct")
            if isinstance(so, exp.Union) and not distinct:
                continue                          # UNION ALL is transparent (maskable outputs)
            # branch OUTPUT columns of both sides
            for sel in so.find_all(exp.Select):
                if sel.find_ancestor(exp.SetOperation) is so or sel.parent is so:
                    references[SET_OP] |= _bases(list(sel.selects), col2scope)

        # ---- recursive CTE definitions -> RECURSIVE (skip dead ones: a CTE never referenced outside
        # its own definition adds nothing to the result, so it must not fail-close the whole query) ----
        for w in qroot.find_all(exp.With):
            if w.args.get("recursive"):
                for cte in w.expressions:
                    if not _cte_referenced(cte, qroot):
                        continue
                    references[RECURSIVE] |= _bases(list(cte.this.find_all(exp.Column)), col2scope)

        # ---- transparent clause columns (skip cols inside an opaque subquery) ----
        def add_clause(nodes, ctx):
            for n in nodes:
                if n is None:
                    continue
                if _enclosing_opaque(n, opaque_selects) is not None:
                    continue
                references[ctx] |= _bases([n], col2scope)

        def add_output_refs(sel, terms, ctx):
            # Like add_clause, but for ORDER BY / GROUP BY, which can reference an output ALIAS or a
            # positional ORDINAL. sqlglot leaves those as a bare, unbindable ref (or an int literal), so
            # resolve them back to that projection's base columns — else a masked column used as a sort/
            # dedup key (the backend sorts/dedups on CLEARTEXT before masking) leaks and is missed.
            projs = sel.selects
            for t in terms:
                if t is None or _enclosing_opaque(t, opaque_selects) is not None:
                    continue
                inner = t.this if isinstance(t, exp.Ordered) else t
                if isinstance(inner, exp.Literal) and inner.is_int:
                    i = int(inner.name) - 1
                    if 0 <= i < len(projs):
                        references[ctx] |= _bases([projs[i]], col2scope)
                    continue
                for col in inner.find_all(exp.Column):
                    b = _resolve(col, col2scope, set())
                    if not b and not col.table:
                        b = next((_bases([p], col2scope) for p in projs if p.alias_or_name == col.name), set())
                    references[ctx] |= b

        for sel in qroot.find_all(exp.Select):
            if id(sel) in opaque_selects:
                continue
            w = sel.args.get("where")
            if w:
                add_clause([w.this], PREDICATE)
            h = sel.args.get("having")
            if h:
                add_clause([h.this], PREDICATE)
            g = sel.args.get("group")
            if g:
                gcols = list(g.expressions)
                for k in ("rollup", "cube", "grouping_sets"):   # ROLLUP/CUBE/GROUPING SETS live here, not in .expressions
                    for gs in (g.args.get(k) or []):
                        if isinstance(gs, exp.Expression):
                            gcols.append(gs)
                add_output_refs(sel, gcols, GROUP_BY)     # GROUP BY <ordinal>/<alias> too
            q = sel.args.get("qualify")
            if q:
                add_clause([q.this], PREDICATE)
            for j in sel.args.get("joins", []) or []:
                if j.args.get("on"):
                    add_clause([j.args["on"]], JOIN)
                if j.args.get("using"):                   # SELECT JOIN … USING — qualify usually rewrites
                    add_clause(list(j.args["using"]), JOIN)   # to ON, but keep as a belt for any residue
            order = sel.args.get("order")
            if order:
                add_output_refs(sel, list(order.expressions), ORDER_BY)   # ORDER BY <ordinal>/<alias>/<col>
            # DISTINCT dedups on CLEARTEXT values before masking — a cardinality / cross-row-equality
            # oracle (same class as GROUP BY). Plain DISTINCT keys on all projections; DISTINCT ON keys
            # on its own key expressions (which would otherwise be dropped by the read backstop's
            # `- accounted`, since the key column is also a maskable origin).
            dstn = sel.args.get("distinct")
            if dstn is not None:
                on = dstn.args.get("on")
                if on is None:
                    add_clause(list(sel.selects), GROUP_BY)      # plain DISTINCT: all projections
                else:                                            # DISTINCT ON (keys): the key columns
                    keys = on.expressions if isinstance(on, exp.Tuple) else [on]
                    add_output_refs(sel, keys, GROUP_BY)         # via projections (keys aren't in col2scope)
        # ORDER BY on a set-op is attached to the SetOp node; its refs are the union's OUTPUT columns
        # (by ordinal or the left branch's alias), so resolve against the per-position branch bases.
        for so in qroot.find_all(exp.SetOperation):
            order = so.args.get("order")
            if not order:
                continue
            branches = _leaf_selects(so)
            left = branches[0] if branches else None
            pos_bases = []
            if left:
                for i in range(len(left.selects)):
                    b = set()
                    for br in branches:
                        if i < len(br.selects):
                            b |= _bases([br.selects[i]], col2scope)
                    pos_bases.append(b)
            name_of = {left.selects[i].alias_or_name: pos_bases[i] for i in range(len(pos_bases))} if left else {}
            for t in order.expressions:
                inner = t.this if isinstance(t, exp.Ordered) else t
                if isinstance(inner, exp.Literal) and inner.is_int:
                    i = int(inner.name) - 1
                    if 0 <= i < len(pos_bases):
                        references[ORDER_BY] |= pos_bases[i]
                else:
                    for col in inner.find_all(exp.Column):
                        references[ORDER_BY] |= _resolve(col, col2scope, set()) or name_of.get(col.name, set())
        # window (OVER) partition/order
        for over in qroot.find_all(exp.Window):
            if _enclosing_opaque(over, opaque_selects) is None:
                add_clause(list(over.args.get("partition_by", []) or []), PREDICATE)
                o = over.args.get("order")
                if o:
                    add_clause(list(o.expressions), ORDER_BY)
        # aggregate FILTER (WHERE ...) predicate
        for filt in qroot.find_all(exp.Filter):
            if _enclosing_opaque(filt, opaque_selects) is None:
                cond = filt.expression
                add_clause([cond], AGGREGATE)

        # ---- table-function / lateral-VALUES row sources -> OTHER. A source in FROM/JOIN/LATERAL that
        # is not a plain table nor a derived-table subquery — unnest(ARRAY[u.ssn]), generate_series(…
        # length(u.ssn)…), LATERAL (VALUES (u.ssn)), json_table(…) — consumes columns whose flow to the
        # output sqlglot CANNOT trace: the output resolves to nothing (origins=[]) while the input sits
        # in a FROM/JOIN/LATERAL position both backstops skip (READ SKIP_ARGS + the write scoped-skip),
        # so the read leaks and, as a write payload, escapes the sweep. Route every column such a source
        # consumes (whose nearest-enclosing Select is this one — nested subquery sources are handled as
        # their own scope) to references, fail-closed. Covers reads and a write's payload alike. ----
        for sel in qroot.find_all(exp.Select):
            if id(sel) in opaque_selects:
                continue
            src_nodes = []
            frm = sel.args.get("from")
            if frm is not None:
                src_nodes.append(frm)
            for j in (sel.args.get("joins") or []):
                if j.this is not None:
                    src_nodes.append(j.this)          # joined SOURCE only; JOIN ON/USING handled above
            for lat in (sel.args.get("laterals") or []):
                src_nodes.append(lat)
            for node in src_nodes:
                for c in node.find_all(exp.Column):
                    if c.find_ancestor(exp.Select) is sel:   # directly in this select's source clause
                        references[OTHER] |= _bases([c], col2scope)

        # ---- whole-row references -> OTHER. A table/alias used as a VALUE rather than `alias.column` —
        # to_jsonb(u), row_to_json(u), json_agg(u), a bare `SELECT u` (row as composite), composite field
        # access `(u).col`, or a table-qualified star left unexpanded (to_json(u.*)) — serializes the
        # whole row (every column, incl. protected ones) yet produces NO per-column lineage node, so
        # origins/references miss it. (qualify's star expansion covers top-level `u.*`/`*`, not these
        # row-as-scalar forms.) Route the exposed base column(s) to references, fail-closed: DENY if any
        # is protected, ALLOW for a non-PII table. ----
        def _src_in_scope(node, nm):
            """The source (physical Table or a sub-Scope) that alias `nm` binds to at `node`'s location,
            resolved through the LOCAL scope and its parents — the same lexical rule ordinary columns
            use. Nested scopes shadow outer aliases, so this gets `u` right where a flat map gets it wrong."""
            sel = node.find_ancestor(exp.Select)
            sc = scope_of_select.get(id(sel)) if sel is not None else None
            while sc is not None:
                if nm in sc.sources:
                    return sc.sources[nm]
                sc = sc.parent
            # A whole-row / composite ref in a WRITE's OWN clause (`UPDATE … SET x = (u).ssn`, `to_jsonb(u)`
            # in SET/WHERE/USING/RETURNING) has no enclosing exp.Select, so the scope walk finds nothing —
            # resolve against the synthesized write scope (else the ref silently no-ops and, if the alias
            # collides with another table's column name, the write backstop misresolves it → cleartext leak).
            if write_scope is not None and nm in write_scope.sources:
                return write_scope.sources[nm]
            return None

        def _src_all_cols(src):
            """Every base column a source exposes as a whole row: a physical table -> its schema columns;
            a sub-Scope (derived table / CTE / set-op) -> the base columns of its output projections."""
            if isinstance(src, exp.Table):
                return {f"{src.name}.{c}" for c in schema.get(src.name.lower(), {})}
            expr = getattr(src, "expression", None)
            if isinstance(expr, exp.SetOperation):
                out = set()
                for br in _leaf_selects(expr):
                    out |= _bases(list(br.selects), col2scope)
                return out
            if isinstance(expr, exp.Select):
                return _bases(list(expr.selects), col2scope)
            return set()

        # a table/alias in a value position (to_jsonb(u), SELECT u) parses as exp.TableColumn — a table
        # name where a value is expected. Skip one that is a Dot base (`(u).col`) — composite field access,
        # resolved to the single accessed column below.
        for tc in qroot.find_all(exp.TableColumn):
            if tc.find_ancestor(exp.Dot) is not None:
                continue
            src = _src_in_scope(tc, (tc.name or "").lower())
            if src is not None:
                references[OTHER] |= _src_all_cols(src)
        # composite field access `(u).col`: resolve the base alias in scope, then the single field
        for dot in qroot.find_all(exp.Dot):
            base = dot.this
            while isinstance(base, exp.Paren):
                base = base.this
            src = _src_in_scope(dot, (getattr(base, "name", "") or "").lower())
            if src is None:
                continue
            fld = (getattr(dot.expression, "name", "") or "").lower()
            if isinstance(src, exp.Table):
                cols = schema.get(src.name.lower(), {})
                if fld and fld in cols:
                    references[OTHER].add(f"{src.name}.{fld}")     # (u).col -> that one column
                else:
                    references[OTHER] |= _src_all_cols(src)         # (u).* / unknown field -> whole row
            elif fld:
                references[OTHER] |= _resolve_scope_output(src, fld, col2scope, set())  # derived col
            else:
                references[OTHER] |= _src_all_cols(src)
        # a table-qualified star qualify left unexpanded (e.g. `to_json(u.*)` as a function arg) -> whole row
        for c in qroot.find_all(exp.Column):
            if isinstance(c.this, exp.Star) and c.table:
                src = _src_in_scope(c, c.table.lower())
                if src is not None:
                    references[OTHER] |= _src_all_cols(src)

        # ---- proxy-side `*` expansion (reads only): the mask binds by ORDINAL, so the backend's wire
        # column order MUST equal the order origins index. Rather than PREDICT the backend's native `*`
        # order — fragile: it assumes the catalog's column order matches the live DB, and needs every
        # FROM source type enumerated (the whack-a-mole that leaked LATERAL/VALUES/unnest) — we EXPAND `*`
        # here and hand the proxy explicit columns to send: the backend then echoes OUR order, so
        # origins-ordinal == wire-position BY CONSTRUCTION (and stays correct even if the catalog drifts
        # from the DB's physical column order). Every starred select must sit inside the proven-faithful
        # envelope (verified byte-identical vs live PG+MySQL) else fail closed; a sole bare `*` is re-sorted
        # to FROM order so the client still sees native-`*` order. Writes never mask — their payload/
        # RETURNING `*` is handled by the write backstop below, not rewritten. ----
        rewritten_sql = None
        if analyze_query is not None and not is_write:
            # A residual PROJECTION star ANYWHERE in a read (a source qualify could not expand — unnest /
            # array / table-function / LATERAL) means the mask can't bind a concrete column count -> fail
            # closed (the unnest bypass). We deny on ANY residual, with no "doesn't reach the
            # result" exemption: two attempts at such an exemption each leaked (a top-level-only check missed
            # `SELECT x.ssn FROM (SELECT * FROM t, unnest) x`; skipping opaque subqueries missed a LATERAL,
            # which IS opaque for reference-bucketing yet DOES reach the result). The only cost is a rare,
            # fail-SAFE over-deny: `* ` over a table-function inside a control-clause subquery (e.g.
            # `… WHERE EXISTS (SELECT * FROM t, unnest(…))`) — deliberate DENY. `count(*)` is a func arg, not
            # a projection star, so it is never flagged.
            for sel in qroot.find_all(exp.Select):
                if any(_is_star(p) for p in sel.selects):
                    return _fail("VALIDATE", "unexpandable `*` (table-function / array / LATERAL source) — cannot bind mask ordinals")
            # Gate + resort only the TOP-LEVEL read select / set-op branches (aligned with the pre-qualify
            # branches — dead CTEs are dropped from qroot but are never leaf branches, so alignment holds).
            # A nested subquery's bare `*` needs no resort: we send the whole expanded query, so its columns
            # reach the wire in the SAME order origins index them (correctness is by construction; only the
            # top level must match native `*` order for the client, which the resort provides).
            o_branches = _leaf_selects(analyze_query) if isinstance(analyze_query, exp.SetOperation) else [analyze_query]
            q_branches = _leaf_selects(qroot) if isinstance(qroot, exp.SetOperation) else [qroot]
            star_expanded = False
            for i, qsel in enumerate(q_branches):
                osel = o_branches[i] if i < len(o_branches) else None
                if osel is None or not any(_is_star(p) for p in osel.selects):
                    continue
                ok, why = _expandable_sources(osel)
                if not ok:
                    return _fail("VALIDATE", f"`*` over {why} — outside the faithful-expansion envelope")
                if any(isinstance(p, exp.Star) for p in osel.selects):     # a bare `*` (not just `t.*`)
                    if sum(1 for p in osel.selects if _is_star(p)) > 1:
                        # `u.*, *` / `*, *`: a neighboring star's variable width makes the bare `*` block's
                        # boundaries — and every mask ordinal past it — ambiguous. Rare; fail closed.
                        return _fail("VALIDATE", "bare `*` mixed with another star — column order can't bind to mask ordinals")
                    _resort_bare_star_inplace(osel, qsel)                  # bare `*` span -> FROM order
                star_expanded = True
            if star_expanded:
                # KNOWN LIMITATIONS of serializing the rewrite from this analysis copy (both fail-SAFE —
                # a wrong result or a loud error, never a cleartext leak; the mask still binds by ordinal):
                #  1. Identifiers were case-folded above for catalog matching, so on a CASE-SENSITIVE MySQL
                #     (lower_case_table_names=0) a `SELECT *` over a MIXED-CASE table sends folded-lowercase
                #     names → "table doesn't exist". Harmless on the usual case-insensitive MySQL and on PG
                #     (PG folds unquoted itself); tables are lowercase by convention. Proper fix (future):
                #     emit from a non-folded copy / preserve original case.
                #  2. `*` expands to the CATALOG's columns, so `SELECT *` returns catalog columns, not
                #     necessarily the live table's — a column the DB has but the catalog lacks is silently
                #     dropped from the result (protected columns are still masked at their ordinal; nothing
                #     unknown is ever revealed). Keep the catalog in sync with the backend schema.
                rewritten_sql = qroot.sql(dialect=dialect)

        # ---- origins: a top-level output is maskable ONLY if it is the value-preserving IDENTITY of a
        # column (bare / aliased). A DERIVED output (function/operator/subquery) cannot be safely masked
        # — masking its rendered result doesn't protect the source value — so its source columns route to
        # references[DERIVED] (→ DENY if masked), not to origins. qroot's bare-`*` blocks were re-sorted
        # into FROM order in place above, so origins index the exact order the wire returns. An output is
        # a maskable ORIGIN only if it is a TRANSITIVE identity of a column (every resolution hop a bare
        # column); a transform at the top / one scope down / beside a subquery routes to DERIVED. ----
        origins = []
        if analyze_query is not None:
            aq = qroot.expression if isinstance(root, exp.Create) else qroot
            if isinstance(aq, exp.SetOperation):
                branch_sels = [br.selects for br in _leaf_selects(aq)]
                left_sels = branch_sels[0] if branch_sels else []
                for i in range(len(left_sels)):
                    srcs, identity = set(), True
                    for bs in branch_sels:
                        if i < len(bs):
                            b, sub = _proj_ident(bs[i], col2scope, frozenset())
                            srcs |= b
                            identity = identity and sub
                    if identity:
                        origins.append({"column": left_sels[i].alias_or_name, "origins": sorted(srcs)})
                    else:
                        origins.append({"column": left_sels[i].alias_or_name, "origins": []})
                        references[DERIVED] |= srcs
            else:
                for p in aq.selects:
                    bases, is_id = _proj_ident(p, col2scope, frozenset())
                    if is_id:
                        origins.append({"column": p.alias_or_name, "origins": sorted(bases)})
                    else:
                        origins.append({"column": p.alias_or_name, "origins": []})
                        references[DERIVED] |= bases

        # ---- conservation backstops: fail-closed for any position not modeled above (the gate found
        # probe was ALLOW-by-default for unenumerated positions). accounted = everything already
        # bucketed; anything else a statement TOUCHES routes to OTHER (a protected column there -> DENY).
        # A write's payload is NOT a separate bucket — the write backstop below routes it into OTHER
        # like any other column a write reads (this replaces the Calcite-era `writeColumns`, which
        # existed only because a Calcite TableModify exposed the payload in neither origins nor refs). ----
        accounted = set()
        for o in origins:
            accounted |= set(o["origins"])
        for cols in references.values():
            accounted |= cols

        # READ backstop: a column in any transparent-SELECT clause other than its projection list / FROM
        # sources (WHERE/GROUP/HAVING/ORDER/QUALIFY/DISTINCT/… + constructs we didn't model). FROM
        # sources are skipped, so a dead `select id from (select * ...)` is NOT over-denied.
        # NB: sqlglot names the FROM arg "from_" (from is a Python keyword) — skip both spellings so
        # FROM-derived projections (dead columns) don't leak into the backstop.
        # NB: sqlglot suffixes Python-keyword arg names with '_' — the FROM arg is "from_", the WITH
        # arg is "with_". Skip both spellings so FROM-derived projections and CTE definitions (dead
        # columns, handled as their own scopes) don't leak into the backstop.
        SKIP_ARGS = {"expressions", "from", "from_", "joins", "with", "with_", "laterals", "pivots",
                     "into", "hint", "kind", "operation", "operation_modifiers"}
        for sel in qroot.find_all(exp.Select):
            if id(sel) in opaque_selects:
                continue
            for key, node in list(sel.args.items()):
                if key in SKIP_ARGS:
                    continue
                for sub in (node if isinstance(node, list) else [node]):
                    if not isinstance(sub, exp.Expression):
                        continue
                    for c in sub.find_all(exp.Column):
                        if _enclosing_opaque(c, opaque_selects) is None:
                            references[OTHER] |= _resolve(c, col2scope, set()) - accounted

        # WRITE backstop: a write can't mask, so ANY protected column it READS anywhere (predicate/join/
        # RETURNING/ON-CONFLICT action/VALUES-subquery/MERGE ON|WHEN) must DENY. Collect every column
        # except write DESTINATIONS (INSERT target list + SET / ON-CONFLICT LHS) -> OTHER.
        #
        # qualify() does NOT qualify columns in a write's non-SELECT clauses (SET-RHS/WHERE/USING/ON),
        # so an UNqualified write column is resolved against the in-scope tables via the SCHEMA — never
        # defaulted to the target (that stamps a SOURCE table's PII with the target's name, so it matches
        # no policy and slips through). Fail closed on any read column we can't
        # resolve: an unknown/unresolvable write-clause column must not silently vanish.
        if is_write:
            dest_ids = set()
            # INSERT target column list — exp.Schema for a top-level INSERT, exp.Tuple for a MERGE
            # WHEN NOT MATCHED THEN INSERT (cols) — both are destinations (written-to), not reads.
            for ins in qroot.find_all(exp.Insert):
                if isinstance(ins.this, (exp.Schema, exp.Tuple)):
                    for c in ins.this.find_all(exp.Column):
                        dest_ids.add(id(c))
            for eq in _set_assignments(qroot):
                if isinstance(eq.this, exp.Column):
                    dest_ids.add(id(eq.this))
            phys = {t.name for t in qroot.find_all(exp.Table) if t.name.lower() not in cte_names}
            schema_ci = {t.lower(): {col.lower() for col in cols} for t, cols in schema.items()}
            # Tables in the WRITE's OWN scope (its FROM/USING/target — the synthesized write_scope's direct
            # table sources), NOT every table in the statement. The whole-row column-first guard below must
            # test against THIS set: SQL resolves a bare SET/WHERE identifier as a column only if a table in
            # the WRITE's scope has it — a same-named column in a nested subquery (e.g. `orders.user_id` in an
            # EXISTS) does NOT make the outer bare `user_id` a scalar; PG binds it as the whole-row alias.
            # Using global `phys` there let a nested collision suppress whole-row handling and leak the row.
            write_phys = ({s.name.lower() for s in write_scope.sources.values() if isinstance(s, exp.Table)}
                          if write_scope is not None else set())
            # `EXCLUDED` is a real pseudo-relation ONLY inside an INSERT … ON CONFLICT and only when no
            # real table/alias in scope is named `excluded`. Otherwise `excluded.col` is a genuine read
            # of an aliased source and must NOT be skipped (else `UPDATE users AS excluded SET x =
            # excluded.ssn` smuggles cleartext PII past the write backstop).
            has_onconflict = bool(list(qroot.find_all(exp.OnConflict)))
            alias_names_ci = {k.lower() for k in alias_map}

            def _resolve_ws(alias, name):
                """Resolve `alias.name` against the synthesized write scope (scope-correct: a CTE shadows
                a same-named table), replacing the old flat, scope-blind alias map."""
                if write_scope is None or not alias:
                    return set()
                src = write_scope.sources.get(alias)
                if src is None:
                    return set()
                if isinstance(src, exp.Table):
                    return {f"{src.name}.{name}"}
                return _resolve_scope_output(src, name, col2scope, set())   # CTE / derived source

            def _wbase(name, alias, col=None):
                """Resolve a write read-column to base(s), failing closed on unknown. `col` (if given) is
                the AST Column for scope resolution; else this is a bare identifier (e.g. a USING key)."""
                bases = _resolve(col, col2scope, set()) if col is not None else set()
                if not bases and alias:
                    bases = _resolve_ws(alias, name)
                if not bases and not alias:                              # unqualified -> in-scope tables that HAVE it
                    nl = name.lower()
                    bases = {f"{t}.{name}" for t in phys if nl in schema_ci.get(t.lower(), set())}
                # writes skip qualify's validation and _resolve/_resolve_write can fabricate a `table.col`
                # for a column absent from the catalog — fail closed on any base whose column isn't in
                # the schema, never trust a fabricated name.
                if not bases or any(b.rpartition(".")[2].lower() not in schema_ci.get(b.rpartition(".")[0].lower(), set()) for b in bases):
                    return None
                return bases

            # Sweep only the write's OWN unscoped clauses (SET-RHS / WHERE / USING / ON / RETURNING).
            # Columns that live in a traversed SCOPE (the payload SELECT, its CTEs/subqueries) are NOT
            # swept here — a write can't mask, so the payload's stored values are captured by output
            # lineage below and its control clauses by the READ backstop. Sweeping every column blindly
            # instead misreads a DEAD column in a CTE/derived source (present in the tree, never flowing
            # to the write) as a write-read → an over-deny.
            for c in qroot.find_all(exp.Column):
                if id(c) in dest_ids or id(c) in col2scope:
                    continue
                if isinstance(c.this, exp.Star):
                    continue          # a qualified star (`RETURNING sink.*`) — routed wholesale by the
                                      # RETURNING-* / unexpanded-star handler below, not a single column
                # a bare (unqualified) column whose NAME is a write SOURCE ALIAS *and* is NOT a column of
                # any in-scope table is a WHOLE-ROW reference, not a scalar column: `to_jsonb(u)` / `(u).ssn`
                # -base where `FROM users u` aliases users as `u` and no table has a column `u`. Route the
                # whole row's columns (DENY if any is protected). The column-existence guard enforces SQL's
                # resolution order — a bare identifier binds to a COLUMN first, the relation (whole row) only
                # when no such column exists: without it `UPDATE users SET name = ssn FROM orders ssn` reads
                # `ssn` (a real users column) as a whole-row ref to the `orders ssn` alias (no PII) and leaks
                # cleartext `users.ssn`. When a column DOES exist, fall through to `_wbase` -> real resolution.
                if (not c.table and write_scope is not None and c.name
                        and c.name.lower() in write_scope.sources
                        and not any(c.name.lower() in schema_ci.get(t, set()) for t in write_phys)):
                    wsrc = write_scope.sources[c.name.lower()]
                    if isinstance(wsrc, exp.Table):
                        references[OTHER] |= {f"{wsrc.name}.{col}" for col in schema.get(wsrc.name.lower(), {})} - accounted
                        continue
                if ((c.table or "").lower() == "excluded" and has_onconflict
                        and "excluded" not in alias_names_ci):
                    continue          # genuine ON-CONFLICT pseudo-relation (the pending insert row); its
                                      # real reads are the INSERT payload, captured by lineage separately
                bases = _wbase(c.name, c.table, c)
                if bases is None:
                    return _fail("VALIDATE", f"unresolved column '{c.name}' in write")
                references[OTHER] |= bases - accounted
            # payload lineage: an INSERT … SELECT / SELECT … INTO stores its source query's OUTPUT
            # columns — a write can't mask them, so route their bases to OTHER. Output lineage follows
            # only LIVE projections, so a dead source column never reaches here.
            if payload_query is not None:
                pbr = _leaf_selects(payload_query) if isinstance(payload_query, exp.SetOperation) else [payload_query]
                for s in pbr:
                    references[OTHER] |= _bases(list(s.selects), col2scope) - accounted
            # JOIN … USING keys in a write are NOT normalized to ON by qualify and are Identifiers (not
            # Columns), so the loop above misses them — resolve each as a shared key across in-scope tables.
            for j in qroot.find_all(exp.Join):
                for ident in (j.args.get("using") or []):
                    bases = _wbase(ident.name, None, None)
                    if bases is None:
                        return _fail("VALIDATE", f"unresolved USING column '{ident.name}' in write")
                    references[OTHER] |= bases - accounted
            # RETURNING * (and any star qualify left unexpanded in a write): the star is not a Column, so
            # the loop above never sees it, yet it returns the whole row in cleartext. Conservatively treat
            # it as touching EVERY column of every in-scope table — DENY if any is protected, ALLOW otherwise.
            if list(qroot.find_all(exp.Star)):
                for t in phys:
                    for col in schema_ci.get(t.lower(), set()):
                        references[OTHER].add(f"{t}.{col}")
            # MySQL `… ON DUPLICATE KEY UPDATE x = VALUES(ssn)`: VALUES(col) moves the pending row's `col`
            # into another column; sqlglot parses its arg as a bare Identifier (not a Column).
            for fn in qroot.find_all(exp.Func):
                if (fn.name or "").lower() == "values":
                    for a in fn.find_all(exp.Identifier):
                        bases = _wbase(a.name, None, None)
                        if bases is None:
                            return _fail("VALIDATE", f"unresolved VALUES() column '{a.name}' in write")
                        references[OTHER] |= bases - accounted

        refs_out = {k: sorted(v) for k, v in references.items() if v}
        traced = sum(1 for o in origins if o["origins"])
        return {"resolved": True, "failedStage": None, "detail": "ok",
                "outputColumns": len(origins), "tracedColumns": traced,
                "origins": origins, "references": refs_out, "isWrite": is_write,
                # the expanded query the proxy must send so the backend echoes the order origins index
                # (null = no `*` on a read root; send the original verbatim). See the expansion block above.
                "rewrittenSql": rewritten_sql}
    except Exception as e:
        return _fail("LINEAGE", f"{type(e).__name__}: {e}")


def probe_json(sql, dialect, schema_json):
    return json.dumps(probe(sql, dialect, json.loads(schema_json)))
