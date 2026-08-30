"""Shared run context handed to every module."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from assay.config import Config
from assay.models import Finding, Target, WebTarget
from assay.net import Baseline, HttpClient
from assay.store import Store


@dataclass
class Context:
    cfg: Config
    store: Store
    http: HttpClient
    tune: Dict
    targets: List[Target] = field(default_factory=list)
    web: List[WebTarget] = field(default_factory=list)
    # origin -> Baseline, shared so every module benefits from one calibration
    baselines: Dict[str, Baseline] = field(default_factory=dict)
    # origin -> crawled URLs (populated by the crawl stage)
    urls: Dict[str, List[str]] = field(default_factory=dict)
    tools: Dict[str, Optional[str]] = field(default_factory=dict)
    # Out-of-band callback session, used by the blind checks. None when the
    # run has no OOB backend configured.
    oob: Optional[object] = None
    # UI hook: fn(stage, message, advance)
    progress: Optional[Callable[[str, str, int], None]] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def say(self, stage: str, msg: str, advance: int = 0) -> None:
        if self.progress:
            try:
                self.progress(stage, msg, advance)
            except Exception:  # UI must never kill a scan
                pass

    def emit(self, finding: Finding) -> bool:
        """Persist a finding. Returns True if it was new."""
        with self._lock:
            new = self.store.add_finding(finding)
        if new and finding.triage in ("CHASE", "LOOK"):
            self.say("finding", "%s  %s  [%s]" % (finding.triage, finding.title, finding.target))
        return new

    def baseline_for(self, origin: str) -> Baseline:
        with self._lock:
            bl = self.baselines.get(origin)
        if bl is None:
            from assay.net import build_baseline
            bl = build_baseline(self.http, origin)
            with self._lock:
                self.baselines[origin] = bl
        return bl

    def add_urls(self, origin: str, urls: "Iterable[str]", cap: int) -> int:
        """Add injection points for an origin, respecting a cap.

        Modules in the same stage run concurrently, so the obvious
        `if u not in bucket and len(bucket) < cap` is a check-then-act race:
        two workers can both pass the test and both append. Cheap to serialise,
        and it keeps the URL pool free of duplicates.
        """
        added = 0
        with self._lock:
            bucket = self.urls.setdefault(origin, [])
            existing = set(bucket)
            for u in urls:
                if len(bucket) >= cap:
                    break
                if u in existing:
                    continue
                existing.add(u)
                bucket.append(u)
                added += 1
        return added

    def has(self, tool: str) -> bool:
        return bool(self.tools.get(tool))
