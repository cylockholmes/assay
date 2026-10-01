"""assay - signal-first recon and triage."""

from __future__ import annotations

# The single source of truth for the release version. pyproject.toml reads this
# attribute (dynamic version), so it is set in exactly one place. Bump it for a
# real release; day-to-day builds are told apart by the git commit appended at
# runtime (see version_string), so the reported version is never a stale, flat
# "1.0.0" that cannot tell two builds apart.
__version__ = "1.0.0"


def version_string() -> str:
    """Human-readable version for --version, the report and the journal, e.g.
    'assay 1.0.0 (c5268e5)' or 'assay 1.0.0 (c5268e5-dirty)'. Falls back to
    'assay 1.0.0' outside a git checkout. The git lookup lives in env.py (one of
    the few modules allowed to spawn a process); imported lazily so importing
    the package stays cheap and side-effect-free."""
    from assay import env
    build = env.git_build_meta()
    return "assay %s%s" % (__version__, " (%s)" % build if build else "")
