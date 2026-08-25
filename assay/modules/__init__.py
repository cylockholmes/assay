"""Detection modules.

Each module declares the stage it runs in and whether it operates on web
targets, host targets, or the run as a whole. The engine walks the registry in
stage order; modules never call each other directly.
"""

from __future__ import annotations

from typing import Dict, List, Type

from assay.context import Context
from assay.models import Finding, Target, WebTarget

STAGES = ["recon", "probe", "analyze", "active", "external", "verify"]


class Module:
    name = "base"
    stage = "analyze"
    scope = "web"                 # web | host | global
    desc = ""
    # Skipped unless cfg.aggressive; for anything that writes state or is loud.
    aggressive = False

    def applicable(self, ctx: Context) -> bool:
        if self.aggressive and not ctx.cfg.aggressive:
            return False
        return ctx.cfg.module_enabled(self.name)

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        return []

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        return []

    def run_global(self, ctx: Context) -> List[Finding]:
        return []


_REGISTRY: List[Type[Module]] = []


def register(cls: Type[Module]) -> Type[Module]:
    _REGISTRY.append(cls)
    return cls


def all_modules() -> List[Module]:
    # Import for side effects; keep the list explicit so a broken module is loud.
    from assay.modules import (  # noqa: F401
        host_deep, host_services, secrets, takeover, tls, web_active, web_archive,
        web_domains, web_exposure, web_headers, web_nuclei, web_reflect, web_sqli,
        web_ssrf, web_surface,
    )
    return [cls() for cls in _REGISTRY]


def modules_for_stage(stage: str) -> List[Module]:
    return [m for m in all_modules() if m.stage == stage]
