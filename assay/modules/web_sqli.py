"""SQL injection probing with a two-sided oracle.

The classic scanner failure is reporting every page that happens to contain the
word "SQL" in an error. This module requires a *differential*: the broken quote
must produce a database error, and the balanced quote must not. A page that
errors both ways is a broken page, not an injection point.

Boolean inference uses the same principle - a true condition must match the
original response and a false condition must diverge from it. Either half alone
is noise.

Nothing here attempts exploitation. The output is "this parameter behaves like
a SQL injection point, here is the differential", and the next step is sqlmap
or a manual payload.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.modules.web_active import candidate_urls, existing_params, with_param
from assay.net import Resp, similarity

# Errors that only a database driver emits. Deliberately narrow.
DB_ERRORS: List[Tuple[str, re.Pattern]] = [
    ("MySQL", re.compile(
        r"SQL syntax.*?MySQL|Warning.*?\bmysqli?_|MySqlException|"
        r"valid MySQL result|check the manual that (?:corresponds|fits) to your "
        r"MySQL server version", re.I)),
    ("PostgreSQL", re.compile(
        r"PostgreSQL.*?ERROR|Warning.*?\bpg_|valid PostgreSQL result|"
        r"Npgsql\.|PG::SyntaxError|org\.postgresql\.util\.PSQLException", re.I)),
    ("Microsoft SQL Server", re.compile(
        r"Driver.*? SQL[ _-]*Server|OLE DB.*? SQL Server|\bSQL Server[^&<]{0,40}Driver|"
        r"Warning.*?\bmssql_|Unclosed quotation mark after the character string|"
        r"System\.Data\.SqlClient\.SqlException", re.I)),
    ("Oracle", re.compile(
        r"\bORA-\d{4,5}|Oracle error|Oracle.*?Driver|quoted string not properly "
        r"terminated|OracleException", re.I)),
    ("SQLite", re.compile(
        r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|"
        r"Warning.*?\bsqlite_|\[SQLITE_ERROR\]|unrecognized token:", re.I)),
    ("DB2", re.compile(r"CLI Driver.*?DB2|DB2 SQL error|\bSQLSTATE\b", re.I)),
]


def db_error(body: str) -> Tuple[str, str]:
    """Return (engine, matched text) for the first database error found."""
    for engine, rx in DB_ERRORS:
        m = rx.search(body[:60000])
        if m:
            return engine, m.group(0)[:180]
    return "", ""


@register
class SqliModule(Module):
    name = "sqli"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "SQL injection via error differential and boolean inference"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        out: List[Finding] = []
        tested: set = set()
        budget = 4 if ctx.cfg.profile == "quick" else (
            14 if ctx.cfg.profile == "standard" else 40)

        for url in candidate_urls(ctx, wt):
            for p in existing_params(url):
                if p.startswith("sift_"):
                    continue
                key = (urlsplit(url).path, p)
                if key in tested or len(tested) >= budget:
                    continue
                tested.add(key)
                f = self._error_based(ctx, url, p) or self._boolean(ctx, url, p)
                if f:
                    out.append(f)
        return out

    # -- error differential ------------------------------------------------
    def _error_based(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        base = ctx.http.get(with_param(url, param, "1"))
        if not base.ok:
            return None
        # A page that already errors tells us nothing.
        if db_error(base.body)[0]:
            return None

        broken = ctx.http.get(with_param(url, param, "1'"))
        if not broken.ok:
            return None
        engine, matched = db_error(broken.body)
        if not engine:
            return None

        # The differential: balancing the quote must clear the error.
        balanced = ctx.http.get(with_param(url, param, "1''"))
        if not balanced.ok or db_error(balanced.body)[0]:
            return None

        return Finding(
            title="SQL injection: error differential on '%s'" % param,
            target=url,
            severity="critical",
            confidence="firm",
            category=owasp.A03,
            cwe="CWE-89",
            module=self.name,
            impact=(
                "An unbalanced quote produces a %s error and balancing it clears the "
                "error, so the parameter is concatenated into a SQL statement. That "
                "yields the database contents, and on many deployments file read or "
                "command execution through the DBMS. Confirm and scope the impact with "
                "sqlmap before reporting - do not dump data beyond what proves the "
                "finding." % engine
            ),
            detail="Injected 1' -> %s error; 1'' -> clean. Engine: %s" % (engine, engine),
            repro="%s\n# then: sqlmap -u %s -p %s --batch"
                  % (broken.curl(), url, param),
            refs=["https://owasp.org/www-community/attacks/SQL_Injection",
                  "https://cwe.mitre.org/data/definitions/89.html"],
            tags=["sqli", "verified", "manual-followup"],
            evidence=[
                broken.evidence(label="Single quote -> database error", matched=matched),
                balanced.evidence(label="Balanced quote -> error cleared"),
            ],
            dedupe_key="sqli-error|%s|%s" % (urlsplit(url).path, param),
        )

    # -- boolean inference --------------------------------------------------
    def _boolean(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        """True condition should match the original; false should not."""
        if ctx.cfg.profile == "quick":
            return None
        original = ctx.http.get(with_param(url, param, "1"))
        if not original.ok or original.status >= 500:
            return None

        # Reject endpoints whose output is not stable enough to compare.
        repeat = ctx.http.get(with_param(url, param, "1"))
        if not repeat.ok or similarity(original.body, repeat.body) < 0.97:
            return None

        pairs = [("1' AND '1'='1", "1' AND '1'='2"),
                 ("1 AND 1=1", "1 AND 1=2")]
        for truthy, falsy in pairs:
            rt = ctx.http.get(with_param(url, param, truthy))
            rf = ctx.http.get(with_param(url, param, falsy))
            if not (rt.ok and rf.ok) or rt.status >= 500 or rf.status >= 500:
                continue
            sim_true = similarity(original.body, rt.body)
            sim_false = similarity(original.body, rf.body)
            # True must look like the original, false must diverge clearly.
            if sim_true < 0.95 or sim_false > 0.75:
                continue

            # Re-confirm with a differently-phrased always-false condition.
            rf2 = ctx.http.get(with_param(url, param, falsy.replace("2", "3")))
            if not rf2.ok or similarity(original.body, rf2.body) > 0.75:
                continue

            return Finding(
                title="SQL injection: boolean inference on '%s'" % param,
                target=url,
                severity="high",
                confidence="tentative",
                category=owasp.A03,
                cwe="CWE-89",
                module=self.name,
                impact=(
                    "The response tracks the truth of an injected SQL condition: a "
                    "true clause reproduces the original page and a false clause "
                    "changes it. That is a blind SQL injection primitive, sufficient "
                    "to extract data one bit at a time. Confirm with sqlmap - blind "
                    "inference can also be produced by ordinary input filtering, so "
                    "this one needs a human before it is reported."
                ),
                detail="true=%s (sim %.2f) / false=%s (sim %.2f)"
                       % (truthy, sim_true, falsy, sim_false),
                repro="%s\n# then: sqlmap -u %s -p %s --batch --technique=B"
                      % (rt.curl(), url, param),
                tags=["sqli", "needs-impact-review", "manual-followup"],
                evidence=[
                    rt.evidence(label="True condition matches original"),
                    rf.evidence(label="False condition diverges"),
                ],
                dedupe_key="sqli-bool|%s|%s" % (urlsplit(url).path, param),
            )
        return None
