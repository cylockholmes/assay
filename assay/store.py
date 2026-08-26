"""SQLite persistence.

Findings live on disk rather than in memory so a long run on a small VM does
not balloon, and so a crashed or interrupted scan can be resumed and reported.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional

from assay.models import Evidence, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL, finished REAL, profile TEXT, targets TEXT, args TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    fid TEXT PRIMARY KEY,
    run_id INTEGER,
    last_run INTEGER,
    title TEXT, target TEXT, severity TEXT, confidence TEXT,
    category TEXT, cwe TEXT, module TEXT, impact TEXT, detail TEXT,
    repro TEXT, refs TEXT, tags TEXT, evidence TEXT,
    score REAL, triage TEXT, created REAL, status TEXT DEFAULT 'new', notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_find_score ON findings(score DESC);
CREATE INDEX IF NOT EXISTS idx_find_target ON findings(target);
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY, ip TEXT, data TEXT, updated REAL,
    first_run INTEGER, last_run INTEGER
);
CREATE TABLE IF NOT EXISTS web (
    url TEXT PRIMARY KEY, host TEXT, port INTEGER, status INTEGER,
    title TEXT, server TEXT, tech TEXT, data TEXT, updated REAL,
    first_run INTEGER, last_run INTEGER
);
CREATE TABLE IF NOT EXISTS ai_triage (
    fid TEXT PRIMARY KEY, verdict TEXT, priority INTEGER, fp_risk TEXT,
    rationale TEXT, impact TEXT, next_steps TEXT, commands TEXT, updated REAL
);
CREATE TABLE IF NOT EXISTS ai_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, severity TEXT,
    finding_ids TEXT, impact TEXT, steps TEXT
);
CREATE TABLE IF NOT EXISTS progress (
    key TEXT PRIMARY KEY, value TEXT, updated REAL
);
"""


class Store:
    def __init__(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.commit()
        self.run_id = 0

    # -- lifecycle ---------------------------------------------------------
    def start_run(self, profile: str, targets: List[str], args: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO runs (started, profile, targets, args) VALUES (?,?,?,?)",
                (time.time(), profile, json.dumps(targets[:200]), args),
            )
            self._conn.commit()
            self.run_id = int(cur.lastrowid)
            return self.run_id

    def finish_run(self) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET finished=? WHERE id=?", (time.time(), self.run_id)
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.commit()
            self._conn.close()

    # -- findings ----------------------------------------------------------
    def add_finding(self, f: Finding) -> bool:
        """Insert, or merge evidence into an existing identical finding.

        Returns True when this is a genuinely new finding.
        """
        f.compute_score()
        fid = f.fingerprint()
        with self._lock:
            row = self._conn.execute(
                "SELECT fid, evidence FROM findings WHERE fid=?", (fid,)
            ).fetchone()
            if row:
                try:
                    existing = json.loads(row["evidence"] or "[]")
                except ValueError:
                    existing = []
                merged = existing + [e.__dict__ for e in f.evidence]
                self._conn.execute(
                    "UPDATE findings SET evidence=?, score=MAX(score,?), last_run=?"
                    " WHERE fid=?",
                    (json.dumps(merged[:6]), f.score, self.run_id, fid),
                )
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO findings (fid, run_id, last_run, title, target, severity,"
                " confidence, category, cwe, module, impact, detail, repro, refs, tags,"
                " evidence, score, triage, created, notes)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    fid, self.run_id, self.run_id,
                    f.title, f.target, f.severity, f.confidence,
                    f.category, f.cwe, f.module, f.impact, f.detail, f.repro,
                    json.dumps(f.refs), json.dumps(f.tags),
                    json.dumps([e.__dict__ for e in f.evidence][:6]),
                    f.score, f.triage, f.created, f.notes,
                ),
            )
            self._conn.commit()
            return True

    def findings(self, min_score: float = 0.0, limit: int = 0) -> List[Finding]:
        q = "SELECT * FROM findings WHERE score >= ? ORDER BY score DESC"
        if limit:
            q += " LIMIT %d" % int(limit)
        with self._lock:
            rows = self._conn.execute(q, (min_score,)).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def iter_findings(self) -> Iterator[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY score DESC"
            ).fetchall()
        for r in rows:
            yield self._row_to_finding(r)

    def counts(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT triage, COUNT(*) c FROM findings GROUP BY triage"
            ).fetchall()
            sev = self._conn.execute(
                "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
            ).fetchall()
        out = {r["triage"]: r["c"] for r in rows}
        out.update({r["severity"]: r["c"] for r in sev})
        out["total"] = sum(r["c"] for r in rows)
        return out

    def set_status(self, fid: str, status: str, notes: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET status=?, notes=COALESCE(NULLIF(?,''),notes) WHERE fid=?",
                (status, notes, fid),
            )
            self._conn.commit()

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        f = Finding(
            title=r["title"], target=r["target"], severity=r["severity"],
            confidence=r["confidence"], category=r["category"], cwe=r["cwe"],
            module=r["module"], impact=r["impact"], detail=r["detail"],
            repro=r["repro"], refs=json.loads(r["refs"] or "[]"),
            tags=json.loads(r["tags"] or "[]"),
            evidence=[Evidence(**e) for e in json.loads(r["evidence"] or "[]")],
            created=r["created"], notes=r["notes"] or "",
        )
        f.score = r["score"]
        f.triage = r["triage"]
        return f

    # -- assets ------------------------------------------------------------
    def save_host(self, host: str, ip: str, data: Dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO hosts (host, ip, data, updated, first_run, last_run)"
                " VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(host) DO UPDATE SET ip=excluded.ip, data=excluded.data,"
                " updated=excluded.updated, last_run=excluded.last_run",
                (host, ip, json.dumps(data), time.time(), self.run_id, self.run_id),
            )
            self._conn.commit()

    def save_web(self, url: str, host: str, port: int, status: int, title: str,
                 server: str, tech: List[str], data: Dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO web (url, host, port, status, title, server, tech,"
                " data, updated, first_run, last_run) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(url) DO UPDATE SET status=excluded.status,"
                " title=excluded.title, server=excluded.server, tech=excluded.tech,"
                " data=excluded.data, updated=excluded.updated,"
                " last_run=excluded.last_run",
                (url, host, port, status, title, server, json.dumps(tech),
                 json.dumps(data), time.time(), self.run_id, self.run_id),
            )
            self._conn.commit()

    def web_rows(self) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM web ORDER BY host, port").fetchall()

    def host_rows(self) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM hosts ORDER BY host").fetchall()

    # -- diffing -----------------------------------------------------------
    def runs(self, limit: int = 20) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def diff(self, run_id: Optional[int] = None) -> Dict[str, Any]:
        """What changed in `run_id` compared with everything before it.

        Re-running against the same engagement should surface the delta, not
        the whole picture again - a new subdomain or a newly-appearing finding
        is the signal, and it is buried if every run reprints the baseline.
        """
        current = run_id if run_id is not None else self.run_id
        with self._lock:
            prior = self._conn.execute(
                "SELECT MAX(id) AS p FROM runs WHERE id < ?", (current,)).fetchone()
            previous = prior["p"] if prior and prior["p"] else None

            new_findings = [self._row_to_finding(r) for r in self._conn.execute(
                "SELECT * FROM findings WHERE run_id=? ORDER BY score DESC",
                (current,)).fetchall()]
            # Seen before but not in this run - fixed, or no longer reachable.
            gone = [self._row_to_finding(r) for r in self._conn.execute(
                "SELECT * FROM findings WHERE last_run < ? AND run_id < ?"
                " ORDER BY score DESC", (current, current)).fetchall()] \
                if previous else []
            new_hosts = [r["host"] for r in self._conn.execute(
                "SELECT host FROM hosts WHERE first_run=?", (current,)).fetchall()]
            new_web = [r["url"] for r in self._conn.execute(
                "SELECT url FROM web WHERE first_run=?", (current,)).fetchall()]
        return {"run": current, "previous": previous,
                "is_first_run": previous is None,
                "new_findings": new_findings, "gone_findings": gone,
                "new_hosts": new_hosts, "new_web": new_web}

    def is_new_this_run(self, fid: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT run_id FROM findings WHERE fid=?", (fid,)).fetchone()
        return bool(row and row["run_id"] == self.run_id)

    # -- AI triage ---------------------------------------------------------
    def save_ai(self, result: Dict) -> int:
        """Persist an AI triage pass. Returns the number of findings annotated."""
        n = 0
        with self._lock:
            for item in result.get("triage", []) or []:
                self._conn.execute(
                    "INSERT OR REPLACE INTO ai_triage (fid, verdict, priority, fp_risk,"
                    " rationale, impact, next_steps, commands, updated)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (item.get("id", ""), item.get("verdict", ""),
                     int(item.get("priority", 99)), item.get("false_positive_risk", ""),
                     item.get("rationale", ""), item.get("impact_statement", ""),
                     json.dumps(item.get("next_steps", [])),
                     json.dumps(item.get("commands", [])), time.time()),
                )
                n += 1
            self._conn.execute("DELETE FROM ai_chains")
            for chain in result.get("chains", []) or []:
                self._conn.execute(
                    "INSERT INTO ai_chains (name, severity, finding_ids, impact, steps)"
                    " VALUES (?,?,?,?,?)",
                    (chain.get("name", ""), chain.get("combined_severity", ""),
                     json.dumps(chain.get("finding_ids", [])),
                     chain.get("combined_impact", ""),
                     json.dumps(chain.get("steps", []))),
                )
            self._conn.commit()
        return n

    def ai_for(self, fid: str) -> Optional[Dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ai_triage WHERE fid=?", (fid,)).fetchone()
        if not row:
            return None
        return {"verdict": row["verdict"], "priority": row["priority"],
                "fp_risk": row["fp_risk"], "rationale": row["rationale"],
                "impact": row["impact"],
                "next_steps": json.loads(row["next_steps"] or "[]"),
                "commands": json.loads(row["commands"] or "[]")}

    def ai_chains(self) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM ai_chains").fetchall()
        return [{"name": r["name"], "severity": r["severity"],
                 "finding_ids": json.loads(r["finding_ids"] or "[]"),
                 "impact": r["impact"], "steps": json.loads(r["steps"] or "[]")}
                for r in rows]

