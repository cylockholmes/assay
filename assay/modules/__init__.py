"""Detection modules.

Each module declares the stage it runs in and whether it operates on web
targets, host targets, or the run as a whole. The engine walks the registry in
stage order; modules never call each other directly.
"""

from __future__ import annotations

from typing import Dict, List, Type

from assay.context import Context
from assay.models import Finding, Target, WebTarget

# Stages the engine executes, in order. A module registered at any other stage
# would never run, so this list and Engine.run() must stay in step - there is a
# test that asserts exactly that.
STAGES = ["probe", "analyze", "active", "external"]


# What a module actually does to the client's systems. This is the axis that
# matters for deciding what is safe to run on a production target, and it is
# deliberately separate from `stage` (when it runs) and `scope` (what it runs
# against).
#
#   passive   no packets reach the client at all - third-party archives,
#             certificate transparency, registry lookups.
#   read      ordinary requests that only retrieve. A GET for /.env is a read
#             even though the content is sensitive.
#   probe     sends crafted input, or unusual verbs and headers. Designed not
#             to change state, but it is not ordinary traffic and it will show
#             up in the client's logs and WAF.
#   mutating  could change data or state. Never runs unless --aggressive.
IMPACT_CLASSES = ["passive", "read", "probe", "mutating"]


class Module:
    name = "base"
    stage = "analyze"
    scope = "web"                 # web | host | global
    desc = ""
    impact_class = "probe"        # see IMPACT_CLASSES above
    # Skipped unless cfg.aggressive; for anything that writes state or is loud.
    aggressive = False

    def applicable(self, ctx: Context) -> bool:
        if self.aggressive and not ctx.cfg.aggressive:
            return False
        if self.impact_class == "mutating" and not ctx.cfg.aggressive:
            return False
        # --safe restricts the run to modules that only retrieve.
        if ctx.cfg.safe_mode and self.impact_class not in ("passive", "read"):
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
        ai_surface, host_deep, host_services, secrets, takeover, tls, web_active, web_bypass, web_archive,
        web_content, web_domains, web_exposure, web_headers, web_inject, web_nuclei, web_reflect, web_sqli,
        web_ssrf, web_surface,
    )
    return [cls() for cls in _REGISTRY]


def modules_for_stage(stage: str) -> List[Module]:
    return [m for m in all_modules() if m.stage == stage]
