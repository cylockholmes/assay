# Contributing to assay

## Setup

```bash
git clone https://github.com/cylockholmes/assay.git
cd assay
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
git config core.hooksPath .githooks
```

The pre-commit hook blocks real target data (public IPs, `.gov`/`.mil` hosts,
and any term in `.githooks/forbidden-terms.txt`).

## Before opening a pull request

```bash
ruff check --select E9,F63,F7,F82 assay
python -m pytest tests/        # if a tests/ directory is present
assay --version && assay modules
```

## Guidelines

- Every subprocess call is an argv list; never use `shell=True`.
- New detections must require a content match, never a port or status code alone.
- Every detection test should assert both directions: it fires on the real
  condition and stays silent on the benign lookalike.
- Tests and comments must use synthetic data (`example.com`, `203.0.113.x`).
- Declare an honest `impact_class` (`passive`, `read`, `probe`, `mutating`) on every module.
- Checks stop at proof: demonstrate the primitive, never exercise it.
