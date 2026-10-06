<img src="assets/logo.svg" alt="assay" width="268">

![Python](https://img.shields.io/badge/python-%E2%89%A53.9-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-0A7E07?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-black)
![Tests](https://img.shields.io/badge/tests-550%2B%20offline-2f7a4d)
![Use](https://img.shields.io/badge/use-authorized%20testing%20only-ff4d6d)

Recon and triage for authorized offensive testing. Points at hosts and web
targets and answers one question fast: **what here is worth an hour of my
time?**

Built for Kali under WSL2 on a CPU/RAM-limited Windows VM, but it runs on any
Debian-family Linux and degrades gracefully wherever a tool is missing.

> **For authorized testing only.** Point this at systems you have written
> permission to test. Several checks send crafted input and read files from the
> target. See [Rules of engagement](#rules-of-engagement).

## Quick start

Kali/Debian (including WSL):

```bash
sudo apt-get update && sudo apt-get install -y git python3 python3-venv
git clone https://github.com/cylockholmes/assay.git
cd assay && ./install.sh
```

`install.sh` creates a virtualenv, links `assay` into `~/.local/bin`, and
installs the external scanners it orchestrates (apt packages, the Go toolchain,
the ProjectDiscovery suite) — printing every command before it runs.
`--minimal` installs assay + nmap only; `--no-go` skips the Go tools.

Open a new shell (or `source ~/.bashrc`) so `~/.local/bin` and `$GOPATH/bin`
are on PATH, then:

```bash
assay doctor                 # what's installed, WSL networking, resources
assay scan 10.20.0.0/24      # the target is also the scope
```

assay asks for an engagement codename if you did not pass `-n`; press Enter to
name the run after the target. The report opens as it starts filling and keeps
refreshing while the scan runs — `--no-open` just prints the path.

**assay only, bring your own tools:**

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/assay doctor
assay install --dry-run      # print the exact tool-install commands, run nothing
assay install                # install everything missing, after confirming
```

**Updating:** `git pull && ./install.sh`. Databases migrate in place, so run
history and `assay diff` survive the upgrade.

### Running on Windows

- **Inside WSL (recommended).** Clone, install and run everything in your Kali
  distribution. What the defaults assume.
- **On Windows, tools in WSL.** assay is pure Python and runs natively; the
  scanners are Linux binaries. When it detects a Windows host with WSL it
  bridges automatically — each external command runs as `wsl.exe -d <distro> --
  <tool> …` with output paths translated to `/mnt/…`. `assay doctor` reports
  which layout it detected.

  One asymmetry: in bridged mode assay's own HTTP requests originate from
  Windows while the scanners run in WSL — different network positions. If you
  use a VPN or gateway, route **both** sides through it.

---

## What makes it quiet

Most scanners fail by volume: 400 rows, and the two that matter are buried.
assay is built around suppression.

- **Baselines before content checks.** Every origin is first probed with random
  paths to learn what "does not exist" looks like; later responses resembling
  that shell are discarded. Kills the SPA-answers-200-for-everything class
  outright.
- **Content signatures, never status codes.** `/.env` returning 200 proves
  nothing; `/.env` with `DB_PASSWORD=` in a non-HTML body is a finding. Every
  exposure signature requires a body match.
- **Second-request confirmation.** Anything marked `confirmed` was re-tested
  with a second, different sentinel. A CORS header echoing two distinct random
  origins cannot be static.
- **Evidence is mandatory.** A finding with no evidence is scored down 60% and
  sinks. Every row carries request, response and the exact matched text.
- **Impact, not category.** Each finding states what an attacker gets. Pure
  chain material (missing headers, cookie flags, TLS hygiene) collapses into
  single `noise-prone` rows that can never reach the top bucket.

Findings land in three buckets: **CHASE** (verified, real impact), **LOOK**
(probably real, needs a manual step), **NOTE** (context and chain material).

## Heuristics

Things a per-check scanner cannot do because they need the whole picture:

- **Parameters are classified before injection.** Name and observed value decide
  what a parameter carries, so SQL syntax never goes to `redirect=`, traversal
  never goes to `page=2`; ambiguous ones still get every check. `next=/dashboard`
  is read as a **URL**, not a path — the common open-redirect shape.
- **Estate-wide findings are downranked as environmental.** Above 60% prevalence
  (and ≥5 hosts) a finding is collapsed and downranked with the reason recorded —
  not deleted, since occasionally the estate-wide default *is* the finding.
- **Chains are correlated locally** by eight deterministic rules, labelled
  `correlated` to distinguish them from the model's:

| Chain | Why it is worth more than its parts |
|---|---|
| Sibling-subdomain CORS + takeover on that apex | medium + high → authenticated cross-origin read |
| Disclosed credentials + an admin surface | what the credentials open is the finding |
| SSRF + internal hosts named in JavaScript | a list of internal services to aim it at |
| Reflected input + no CSP same-origin | the mitigation that would block a payload is absent |
| Script-readable session cookie + reflection | decides whether an XSS is account takeover |
| Open redirect on an auth path | phishing vs token theft |
| Directory listing + retrievable source same-origin | the listing is the route to the source |
| Two+ unauthenticated AI services | inference plus its data layer = corpus extraction/poisoning |

- **IDOR gets a work queue, not a guess.** Deciding whether object 1004 is yours
  needs a second account, so assay inventories the object-addressing endpoints,
  marks the access-control boundaries, and hands you the list.

## Injection points

Active checks are only as good as their parameters, so assay draws from four
sources, then collapses to one URL per `(path, parameter-set)` — a 300-URL
paginated list costs one test, not 300.

| Source | Tool |
|---|---|
| Linked now | katana, or a native link pass |
| Ever linked | `gau` / `waybackurls` (on by default, `--no-passive` disables) |
| In the JS | native JS endpoint extraction |
| Accepted but never emitted | `arjun` |

## Unauthenticated host analysis

Beyond port/service detection, assay runs targeted nmap NSE scripts and turns
their output into findings — 18 rules covering anonymous FTP, NFS exports,
rsync modules, SMB null sessions and signing, LDAP anonymous bind, SNMP default
communities, RDP/NLA, VNC, IPMI, open SMTP relay and empty DB passwords. Every
rule requires the script output to actually contain the condition — presence of
output proves nothing. UDP NSE checks (SNMP, IPMI, NetBIOS) run only in `deep`.

### Confirmed services — what actually answered

An *open* port is not the same as a service running on it, and it is not a
version. assay follows the scan with one read-only connection to every open
port and records what the service returns:

- **TCP** — the banner a service volunteers (SSH, FTP, SMTP, POP3, IMAP,
  Telnet, MySQL, …), an HTTP response line and `Server` header, or a TLS
  certificate and negotiated version.
- **UDP** — its own standard query and the reply: DNS `version.bind`, SNMP
  `sysDescr`/`public`, NTP, SSDP, mDNS, memcached. Absent a crafted probe, a
  port nmap reports plainly `open` (not open-filtered) counts — it answered
  nmap's payload.

A port that handshakes but returns nothing is **not** listed. The result is a
separate **Confirmed services** table in the report, **sortable by host and by
service**, each row carrying the live version and expandable to the raw
response plus two copy-paste commands: the one that confirmed it, and a
per-service enumeration next step (`ssh2-enum-algos`, `smtp-open-relay`,
`snmpwalk -c public`, `ike-scan`, …). Confirmation is read-only — the one place
bytes are sent to a silent service is a short protocol-correct query (Redis
`PING`, DNS `version.bind`), skipped under `--safe`.

## Surface expansion

On by default (`--no-expand` off), assay grows the target list first:
environment permutations (`dev-`, `staging-`, `api-`…) resolved against DNS,
plus CT logs and subdomain sources unless `--no-passive`. Wildcard DNS is
fingerprinted and its hits discarded. With `dnsx`, permutations are joined by a
real wordlist (SecLists 5k on `standard`, 110k on `deep`; `quick` skips it).

Two checks find surface DNS never advertises:

- **Virtual hosts** — Host-header probing against an in-scope IP; a name counts
  only when it differs from *both* the default and a random-hostname baseline.
- **Exposed origin** — where a CDN/WAF is detected, assay tries the origin IP
  directly with the right Host header; if the app answers without the edge
  headers, every edge-implemented control is bypassable.

## Inventory and CVEs

Every run lists the asset inventory first — hosts with their open ports,
service and version, and the live web endpoints with status/title/server/stack
— in the terminal and report.

```
 host             ip               open  services
 174.78.188.100   174.78.188.100      3  22/ssh (OpenSSH 8.9p1), 443/https
                                         (nginx 1.24.0), 8443/https-alt
  1 host(s) had no open ports
```

This is why *"no findings"* and *"never reached the targets"* are different
outcomes — a scan with an empty inventory tells you which happened.

Every product/version assay could pin down — nmap service detection host-side,
plus `Server`/`X-Powered-By` headers, CMS generator tags and bundled JS
libraries web-side — collapses into one software table, written regardless of
whether anything looks vulnerable. By default each is checked against NVD's
public CVE database (no API key needed; `NVD_API_KEY` speeds it up;
`--no-passive` disables it with every other third-party lookup). A hit is a
`tentative` finding — NVD keyword search is a text match, not a CPE match, so it
means "go verify," not "exploitable."

## Working while it scans

The report is written from the first finding and refreshed every few seconds,
so the first critical can be worked by hand long before the last host is swept;
scroll and filters survive the refresh. It is a triage surface — search,
severity/triage/module filters, confirmed-only toggle, copy buttons on every
repro and submission draft, `/` `j` `k` `o` navigation, and a **Start here**
panel naming the three things to do first.

**Live controls** (in a terminal): **`s`** skip the current stage, **`p`**
pause, **`r`** resume. Pause takes effect at the next launch (a running tool is
left to finish) and holds across stages until you resume.

## What assay writes, and where

Everything from a run lives under one folder, keyed on the codename; nothing is
written outside it during a scan.

```
<--out>/<CODENAME>/
├── assay.db            SQLite — PERSISTENT, accumulates across runs
├── report.html         rebuilt every run (and every few seconds while scanning)
├── activity.log        every request and command, timestamped   (0600)
├── replay.sh           the same actions as runnable commands     (0700)
├── raw/                nmap XML, NSE output, software-inventory.json, confirmed-services.json
├── evidence/           captured request/response bodies
├── ai-payload.json     exactly what was sent to the model        --ai only
├── ai-triage.json      verdicts and chains, re-hydrated locally  --ai only
├── redaction-map.json  pseudonym → real value  (0600)           --ai only
└── oob-payloads.txt    fired OOB payloads, for collaborator correlation
```

`assay.db` is **persistent** — findings, hosts, endpoints, run history and your
triage verdicts accumulate, which is what `assay diff` compares and what makes
a re-run report only the delta (new findings badged **new**). The folder name
derives from the sorted target set, so reordering arguments does not start a
fresh history. Deleting `assay.db` resets the engagement. `report.html`,
`activity.log` and `replay.sh` are replaced each run; `raw/` and `evidence/`
are appended to.

Treat the whole folder as engagement data. `redaction-map.json` and
`ai-triage.json` hold real hostnames/IPs and are written `0600` and never
transmitted. `replay.sh`/`activity.log` record every URL but **not**
credentials — where a request carried `Authorization`/`Cookie`/an API key, the
replay references a shell variable (`export ASSAY_AUTH=… ; ./replay.sh`).

Outside the output folder, only the installer writes: the venv, the
`~/.local/bin/assay` symlink, a one-time `$GOPATH/bin` PATH line in your shell
rc, the Go-built scanners, and nuclei's templates. `assay install --dry-run`
prints every command without running any.

## Everything is replayable

`activity.log` records every request and command in order with timestamps;
`replay.sh` is the same set as runnable, deduplicated commands — so a finding is
reproduced by re-running the exact request, not reconstructed from the report.
`--no-journal` disables it.

## Pacing, and not breaking the client

- `--rate` global req/s and `--rate-per-host` (default 8/s), because a global
  ceiling alone still lets every worker pile onto one host.
- **Adaptive backoff** — a 429/503 halves the rate immediately and honours
  `Retry-After`; it creeps back only after a quiet period.
- `--delay` adds a jittered per-request pause. `--safe` restricts the run to
  modules that only retrieve.

Modules declare what they do to the client (shown by `assay modules`):

| Class | Meaning |
|---|---|
| `passive` | nothing reaches the client — archives, CT logs, registry lookups |
| `read` | ordinary retrieval. A GET for `/.env` is a read |
| `probe` | crafted input, unusual verbs, or fuzzing volume |
| `mutating` | could change state — never runs without `--aggressive` |

## AI and ML infrastructure

A class that barely existed two years ago and is now reliably exposed on
internal networks. Ollama, vLLM, Gradio, Ray, MLflow and the common vector
databases ship with **no authentication** and are routinely bound to
`0.0.0.0`. assay probes eleven plus MCP servers, on ports outside nmap's
top-1000 and therefore added to every scan explicitly (a default scan never
finds `11434` or `8265`).

| Service | Port | What it costs |
|---|---|---|
| Ollama | 11434 | model theft, prompt/corpus extraction, free compute; <0.17.1 also flags CVE-2026-7482 (unauth heap read of system prompts, history, env creds) |
| vLLM / OpenAI-compatible | 8000 | RAG corpus extraction via completions; stolen inference |
| Ray dashboard | 8265 | job submission = arbitrary Python on the cluster — unauth RCE |
| TorchServe management | 8081 | registers a model archive from a URL; handler runs server-side |
| Qdrant / ChromaDB / Weaviate / Milvus | 6333, 8000, 8080, 9091 | corpus readable and writable — RAG answers poisonable |
| MLflow | 5000 | experiments/artifacts, routinely holding training data and creds |
| Gradio | 7860 | full component graph and event API |
| MCP servers | various | whatever the server wraps — fs, shell, DB, cloud API |

Every probe is a read-only GET or a handshake: reachability and the service's
own identification are the finding. Nothing uploads a model, submits a job or
runs inference.

## Networks that proxy everything

Some testing gateways proxy all 80/443 traffic, so every address answers
whether or not a service exists. assay decides from the **response**, not the
connection:

| Response | Verdict |
|---|---|
| 502/503/504, empty body, or 200 with almost no content | the proxy — not a service |
| 401/403 with a real page | **a service**, and a lead — something guards it |
| anything with real content | a service |

It probes **every open TCP port** for HTTP (not a fixed list) — only ports
definitively something else (ssh, mysql, smtp…) are skipped, because on a
proxied network the interesting app is usually on an odd port. It also
identifies the gateway's default page two ways:

- **Inferred** (default) — if most probed hosts return effectively the same
  response, that is the gateway's; those hosts are dropped and it says so. A
  genuine load-balanced pool never reaches a majority and stays.
- **Asserted** — `--proxied-ports 80,443` stops reporting them as services and
  lowers the default-page bar (to three matching hosts and a majority, not
  five). `--no-gateway-filter` disables both.

## Targets and scope are one argument

You give assay one thing: what gets scanned and, by default, what may be
reached. A value naming an existing file is read as one; anything else is an
inline list. Format is detected, not declared.

```bash
assay scan 10.20.0.0/24,app.example.com      # inline, comma or space separated
assay scan targets.txt                        # host list, CSV/TSV, pasted table
assay scan burp-scope.json extra.example.com  # Burp scope export + extras
assay scope 10.20.0.0/24,*.corp.example.com   # check what it understood, run nothing
```

Handled: Burp project scope JSON (advanced + simple mode, disabled entries
ignored), host lists (IPs, CIDRs, domains, wildcards, URLs, `host:port`), IP
ranges (`10.0.0.1-9`), CSV/TSV, markdown/multi-space tables, bulleted lists, an
*Out of Scope* heading, and a `!` line prefix to exclude.

Three behaviours that each prevent a silent mistake:

- **Scope is enforced by default** — no unscoped mode; a redirect off-target is
  not followed.
- **A wildcard is scope, not a target** — `*.corp.example.com` widens scope
  without being scanned; `--expand` enumerates it into real hosts.
- **A Burp path exclusion is reported, not applied** — assay's scope is
  host-level, so it says the rule could not be applied rather than dropping the
  whole target.

`--scope` takes the same formats, for when what may be reached differs from
what is scanned. Every outbound request — assay's own and every tool's — is
checked against scope before a packet leaves the box; blocked hosts are reported
at the end. Running without `--scope` warns loudly; on a real engagement, don't.

## External tools

assay orchestrates these when present and degrades gracefully when not; `assay
doctor` shows what's missing and what each buys you. All optional.

`nmap` · `naabu` · `httpx` · `nuclei` · `katana` · `subfinder` · `dnsx` ·
`ffuf` · `seclists` · `arjun` · `gau` · `waybackurls` · `xsltproc`

| Tool | Why it matters | Without it |
|---|---|---|
| `nmap` | service/version detection; runs the 18 NSE host rules | native sweep of a fixed port list; no service triage or host rules |
| `naabu` | fast sweep first, so nmap only version-scans open ports | nmap does the whole range — much slower on a /24 |
| `httpx` | bulk HTTP probing at 25+ candidates | native probe, slower |
| `katana` | JS-aware crawl — the main parameter source | single link pass; **active checks lose most of their reach** |
| `gau`/`waybackurls` | every URL the host ever served | you see only what is linked today |
| `arjun` | parameters accepted but never emitted | hidden parameters stay untested |
| `ffuf` + `seclists` | unlinked endpoints — admin panels, backups, old APIs | that surface stays invisible |
| `nuclei` | CVE/misconfig volume (filtered and re-scored onto assay's scale) | stage skipped |
| `dnsx` (+ `seclists`) | bulk resolution, CNAME chains, subdomain brute-forcing | threaded `getaddrinfo` + `dig`; brute-forcing skipped |
| `subfinder` | passive subdomain enumeration | falls back to crt.sh |
| `xsltproc` | renders the [NmapView](https://nmapview.github.io) dashboard | report links only to raw XML |

`assay install` handles setup any time — it always prints the full command list
and asks first (refuses non-interactively without `-y`), pins `GOFLAGS=-p=1` on
a constrained VM, and reports what it can't handle on non-Debian systems rather
than guessing.

## Running small

assay reads `/proc/meminfo` and CPU count at startup and derives worker count,
request rate and each tool's concurrency from what's available; on a 2 GB VM it
paces down rather than swapping. Findings stream to SQLite; tool output is
parsed line by line. Override with `--concurrency 4 --rate 10`.

| Profile | Ports | Roughly | Use for |
|---|---|---|---|
| `quick` | top 100 | ~2 min/target | triaging a fresh target list |
| `standard` | top 1000 | ~10–20 min/target | default |
| `deep` | all | hours per target | an overnight pass on a shortlist |

`--passive` and `--expand` run by default and both scale their wordlist with
the profile, so `standard`/`deep` cost more than bare scans; `--no-passive
--no-expand` gets closer to the old numbers.

## Authentication and blind checks

`--basic user:pass`, `--cookie` and `-H` apply to assay's own requests and pass
through to httpx, nuclei and katana. Authenticated web-app logic (IDOR,
privilege escalation) is deliberately out of scope — it needs a human with two
accounts.

Blind SSRF produces no response change, so the only evidence is an out-of-band
callback. assay runs no listener: with `--oob-domain` (a Burp Collaborator
payload domain) it fires uniquely-labelled payloads and writes
`oob-payloads.txt` mapping each to the request that carried it — anything
appearing in your collaborator is a confirmed callback. Without it the blind
checks are skipped and say so.

## Slack notifications

Point assay at a Slack [incoming webhook](https://api.slack.com/messaging/webhooks)
and it pings you at **scan complete** (one-line result summary) and **waiting
for input** (otherwise finished, now blocked on a terminal prompt). Opt-in and
best-effort — nothing is sent without a webhook, and a slow/down webhook never
delays the scan.

```bash
export ASSAY_SLACK_WEBHOOK=https://hooks.slack.com/services/...
assay scan <targets> --profile deep
```

## AI triage (opt-in, redacted)

Off by default. `--ai` sends findings to Claude for judgement — which are worth
reporting, which look like false positives, the next manual step, and which
chain together. Each confirmed service is carried in too, so the model proposes
enumeration commands for it; every command it suggests, for any finding, renders
on that finding's card whether or not it was run.

**Nothing identifying the client ever leaves the box.**

```
findings → redact → VERIFY (hard gate) → Claude → merge back locally
```

Redaction replaces hostnames, IPs, emails, credentials, tokens, usernames,
passwd rows, MACs and UUIDs with stable pseudonyms (`[CLIENT-01]`, `[IP-03]`) —
stable so the model can still find chains without learning who the client is.
The reverse map is written `0600` and never transmitted. The gate is not
advisory: after redaction the payload is re-scanned with the same detectors
**plus** every known client term from your scope and target list, and if
anything survives the run aborts and prints the residue.

There is no default backend; `--ai-backend` is required:

| `--ai-backend` | Route | Who pays |
|---|---|---|
| `api` | Anthropic SDK with your own key (`pip install anthropic`, `ANTHROPIC_API_KEY`) | billed per token |
| `claude-cli` | the Claude Code CLI headless — same binary the desktop app installs, sharing its sign-in | that plan's quota (labelled `equiv`) |

Both send byte-identical redacted payloads and ask for the same schema.
`claude-cli` runs with `--restricted`, `--strict-mcp-config`,
`--disable-slash-commands` and `--no-session-persistence` in an empty temp dir:
no command execution, web fetch, MCP, skills or project settings.

```bash
assay scan target.tld --ai --ai-dry-run              # write the payload, send nothing
assay ai --out ./assay-out --ai-backend claude-cli   # via the desktop app sign-in
assay ai --out ./assay-out --ai-backend api          # via your API key
```

Defaults to metadata only; `--ai-evidence` adds redacted snippets; interactive
runs confirm before sending. `--ai-dry-run` never reaches a backend.

**Running the verification commands during the scan.** Triage returns commands
that would verify or escalate each finding. `assay followup --run` walks them
one at a time; `--ai-followup` runs them as a scan stage. Execution is gated
four ways, per command: an allow-list (read-oriented security tools only),
no-shell (`shlex`-parsed, metacharacters refuse), scope (one out-of-scope
argument refuses the command), and a human approving each one — for which
`--ai-followup` is the up-front approval. `--safe` or a permissive scope stops
the stage regardless. `--ai-followup-limit` (25) and `--ai-followup-timeout`
(120s) bound it; output attaches to each finding (`assay show <n>`).

## Commands

```
assay scan <targets>    run a scan (hosts, CIDRs, URLs, or a file)
assay doctor            tools, WSL networking, resources
assay report            rebuild the HTML report from a previous run
assay show <n>          print finding #n in full, with evidence
assay diff              what changed since the last run
assay ai                AI triage over an existing run (--ai-backend api|claude-cli)
assay followup          un-redact and run the AI's verification commands
assay install           install the external tools (--dry-run to preview)
assay replay <capture>  replay a Burp/HAR capture with credentials stripped
assay submit [n]        generate a submission draft (category, CVSS, repro)
assay modules           list detection modules
```

## Coverage

| OWASP | Checks |
|---|---|
| A01 Broken Access Control | CORS trust boundaries (reflected origin, `null`, sibling-subdomain), path traversal, open redirect, ELMAH/trace.axd |
| A02 Cryptographic Failures | certificate validity, self-signed, legacy TLS, exposed `.htpasswd` |
| A03 Injection | SQL injection (error differential + boolean inference), reflected-input context analysis, traversal oracles |
| A05 Misconfiguration | 36 exposure signatures (VCS, `.env`, actuator, heapdump, `web.config`, source maps, backups), directory listing, GraphQL introspection, HTTP methods |
| A06 Vulnerable Components | nuclei CVE templates, version fingerprinting, software inventory cross-referenced against NVD |
| A07 Auth Failures | WordPress user enumeration, XML-RPC amplification, default-login templates |
| A08 Integrity Failures | Java RMI, JDWP, deserialization templates |
| A10 SSRF | out-of-band with callback correlation, in-band fetch-error oracle, internal host discovery, Host/proxy-header injection |
| Host | active service confirmation (TCP banner, HTTP/`Server`, TLS cert, UDP query) with a sortable table and per-service enum commands; Redis / memcached / Elasticsearch / Docker API / kubelet / Jupyter proven unauthenticated with one read-only request; 18 NSE rules; 15 more service rules with the exact manual step |

## Testing

```bash
.venv/bin/python -m pytest tests/        # whole suite
```

**550+ tests**, all offline — the suite never opens a listening socket or
stands up a vulnerable service. Every detection test asserts **both**
directions: the check fires on the real condition and stays silent on the
benign lookalike. Roughly half are detection tests (one class per module); the
rest guard things that broke at least once — report rendering, schema
migrations, regex backtracking budgets, gateway thresholds, proxy liveness,
`replay.sh` shell-metacharacter safety, URL-pool concurrency, the Windows→WSL
bridge, request accounting, and service confirmation (a bare connection claimed
as confirmed, or a silent/`open` port misread).

Signature data (ports, paths, error strings) is easy to get wrong, so a wrong
value costs a missed detection, never a false claim: everything in `paths.yaml`,
`nse.yaml` and `ai_surface.yaml` requires a content match, none fires on a port
or status code alone. Load-bearing facts were checked against authoritative
sources (CVE ranges against NVD/MITRE, NSE names against nmap docs, Go modules
against the proxy, apt packages against the Kali/Debian indexes), and each AI
signature records its provenance in a `verified:` field.

## Rules of engagement

assay is a testing tool, not an exploitation framework:

- **Scope is enforced, not advisory** — every request is checked before a packet
  leaves the machine.
- **Nothing that changes state runs by default** — non-GET replay and mutating
  checks require `--aggressive`.
- **Checks stop at proof** — the Docker module reads `/version` and never creates
  a container; findings demonstrate the primitive, they do not exercise it.
- **Third-party lookups are on by default; `--no-passive` turns them all off** —
  archive, CT and NVD queries tell someone other than your target what you are
  looking at.
- **AI triage is off unless you ask**, sends pseudonymised data only, and aborts
  rather than transmit anything that fails the redaction check.

A scope file is the safety net, not the permission. You are responsible for
staying inside your authorization.

**Caveats.** Unlinked endpoints need content discovery (`assay install --only
ffuf,seclists`, then `--profile deep`). `--aggressive` enables state-changing
checks — confirm it's within the program's rules first. Findings are leads with
evidence attached, not submissions — reproduce by hand (every finding ships a
`curl`) before reporting.
