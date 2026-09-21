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
    # run has no OOB domain configured.
    oob: Optional[object] = None
    # UI hook: fn(stage, message, advance)
    progress: Optional[Callable[[str, str, int], None]] = None
    # The stage whose messages are currently flowing. Remembered so that a
    # reporter with no idea what a stage is -- an external command, which runs
    # several layers below any of them -- can still be labelled with one.
    stage: str = "starting"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def say(self, stage: str, msg: str, advance: int = 0) -> None:
        # "finding" is a channel rather than a stage (the dashboard routes it
        # to the hits table), so it must not become the label for tool output.
        if stage != "finding":
            self.stage = stage
        if self.progress:
            try:
                self.progress(stage, msg, advance)
            except Exception:  # UI must never kill a scan
                pass

    def tool_progress(self, msg: str, tick: bool = True) -> None:
        """Ambient progress from an external command (assay.tools.PROGRESS).

        The command knows nothing about stages, so it borrows whichever one is
        currently talking. A tick updates the status line only; an event -- a
        tool cut short, say -- also earns a line in the scroll log.
        """
        self.say(self.stage, msg, advance=1 if tick else 0)

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
