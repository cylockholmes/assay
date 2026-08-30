<img src="assets/logo.svg" alt="assay" width="268">

Recon and triage for authorized offensive testing. Points at hosts and web
targets, and answers one question fast: **what here is worth an hour of my
time?**

Built for a specific setup — Kali under WSL2 on Windows 11, on a
CPU/RAM-limited VM, with Burp running on the Windows side — but it runs on any
Debian-family Linux, and degrades gracefully wherever a tool is missing.

> **For authorized testing only.** Point this at systems you have written
> permission to test. Several checks send crafted input and read files from the
> target. See [Rules of engagement](#rules-of-engagement).

## Quick start

Copy-paste, in order. Kali/Debian (including WSL):

```bash
sudo apt-get update && sudo apt-get install -y git python3 python3-venv
git clone https://github.com/cylockholmes/assay.git
cd assay
./install.sh
```

Then open a new shell (or `source ~/.bashrc`) so `~/.local/bin` and
`$GOPATH/bin` are on PATH, and check what you got:

```bash
assay doctor
```

Set up your scope and run the first scan:

```bash
cp scope.example.txt scope.txt
nano scope.txt          # paste the program's in-scope hosts
assay scan 10.20.0.0/24 -n "CODENAME" --scope scope.txt --open
```

`--open` launches the report as soon as it starts filling in, and it keeps
refreshing while the scan runs.

### One-liner

If you would rather not read `install.sh` first — but do read it, it asks for
sudo:

```bash
git clone https://github.com/cylockholmes/assay.git && cd assay && ./install.sh
```

### Without the installer

If you only want assay itself and will bring your own tools:

```bash
git clone https://github.com/cylockholmes/assay.git
cd assay
python3 -m venv .venv
.venv/bin/pip install --upgrade pip setuptools wheel
.venv/bin/pip install -e .
.venv/bin/assay doctor
```

Add the scanners later, at any time:

```bash
assay install --dry-run    # print the exact commands, run nothing
assay install              # install everything missing, after confirming
```

### Everyday commands

```bash
assay scan <target> -n NAME --scope scope.txt --open   # scan
assay diff -o ./assay-out                              # what changed since last run
assay show 3                                           # finding #3 in full
assay submit 3                                         # submission draft
assay replay -o ./assay-out                            # everything it ran
assay ai -o ./assay-out --ai-dry-run                   # redacted AI payload preview
assay report --open                                    # rebuild the report
```

### Updating

```bash
cd assay && git pull && ./install.sh
```

Your existing databases are migrated in place, so run history and `assay diff`
survive the upgrade.

## Install detail

`install.sh` creates a virtualenv, installs assay into it, links `assay` into
`~/.local/bin`, and then installs the external scanners it orchestrates — apt
packages plus the Go toolchain and the ProjectDiscovery suite. It prints every
command before running it.

```bash
./install.sh --minimal    # assay + nmap only, for a small VM
./install.sh --no-go      # skip the Go toolchain and its tools
```

### Running on Windows

Two supported layouts:

**Inside WSL (recommended).** Clone and install in your Kali distribution and
run everything there. Simplest, and what the defaults assume.

**On Windows, tools in WSL.** assay itself is pure Python and runs natively on
Windows, but every scanner it orchestrates is a Linux binary. When it detects a
Windows host with WSL available it bridges automatically — each external command
is executed as `wsl.exe -d <distro> -- <tool> ...`, output paths are translated
to `/mnt/...` so both sides see the same files, and a loopback Burp proxy is
rewritten to the Windows host address so WSL-side tools still reach it.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\pip install -e .
.\.venv\Scripts\assay doctor      # confirms "bridge active" and names the distro
```

`assay doctor` reports which layout it detected. If it says *no WSL
distribution found*, install one — `wsl --install -d kali-linux` — then run
`assay install` to populate the toolchain inside it.

There is one asymmetry worth understanding in bridged mode: assay's own HTTP
requests originate from Windows, while the scanners run inside WSL. They are
different network positions. assay compensates for the Burp proxy
automatically; if you use a VPN or gateway, make sure **both** sides route
through it, or your own requests and your tools' requests will see different
networks.

### WSL2 notes

Two things trip people up:

1. **Burp is on the Windows side.** WSL cannot reach a listener bound to
   Windows' own `127.0.0.1`. Either set `networkingMode=mirrored` in
   `C:\Users\<you>\.wslconfig` and `wsl --shutdown`, or bind Burp's proxy to
   all interfaces and use `--burp http://<windows-ip>:8080`. `assay doctor`
   detects which case you are in and prints the exact fix.
2. **Gateway certificates.** If you connect through a managed VPN or gateway
   that terminates TLS with its own CA, Burp will not trust it until that CA is
   added to Burp's Java trust store (`cacerts`). Import the CA with `keytool`,
   or point Burp at a `cacerts` bundle that already contains it.

### Updating

```bash
git pull && ./install.sh
```

---

## What makes it quiet

Most scanners fail by volume: 400 rows, and the two that matter are buried.
assay's design is built around suppression.

**Baselines before content checks.** Every origin is first probed with random
paths to learn what "this does not exist" looks like. Any later response that
resembles that shell is discarded. This alone removes the entire class of false
positives caused by SPAs that answer `200 text/html` for every path.

**Content signatures, never status codes.** `/.env` returning 200 proves
nothing. `/.env` returning 200 with `DB_PASSWORD=` in a non-HTML body is a
finding. Every one of the 36 exposure signatures requires a body match, and
most also require the Content-Type to be plausible.

**Second-request confirmation.** Anything reported as `confirmed` was re-tested
with a second, different sentinel value. A CORS header echoing one origin might
be static; echoing two distinct random origins cannot be.

**Evidence is mandatory.** A finding with no evidence is scored down by 60% and
sinks. Every row carries the request, the response, and the exact matched text.

**Impact, not category.** Each finding states what an attacker actually gets.
Findings that are only chain material — missing headers, cookie flags, TLS
hygiene — are collapsed into single rows tagged `noise-prone` and can never
reach the top bucket, no matter their nominal severity.

Findings land in three buckets: **CHASE** (verified, real impact), **LOOK**
(probably real, needs a manual step), **NOTE** (context and chain material).

---

## Injection points

The active checks are only as good as the parameters they are given, so assay
draws from four sources rather than a crawl alone:

| Source | Tool | Touches |
|---|---|---|
| Linked now | katana, or a native link pass | target |
| Ever linked | `gau` / `waybackurls` | third-party archives — `--passive` only |
| Known to the client | native JS endpoint extraction | target |
| Accepted but never emitted | `arjun` | target |

Results are collapsed to one representative URL per `(path, parameter-set)`, so
a paginated list of 300 URLs that differ only by id costs one test, not 300.

## Unauthenticated host analysis

Beyond port and service detection, assay runs targeted nmap NSE scripts against
what it finds and converts the output into findings — 18 rules covering
anonymous FTP, NFS exports, rsync modules, SMB null sessions and signing, LDAP
anonymous bind, SNMP default communities, RDP/NLA, VNC auth, IPMI, open SMTP
relay, and empty database passwords.

Every rule requires the script output to actually contain the condition. nmap
runs a script against every candidate port whether or not the condition holds,
so the presence of output proves nothing on its own — this is the same
discipline the web signatures use.

UDP checks (SNMP, IPMI, NetBIOS) run only in `deep`, because a UDP scan is slow
and noisy enough to deserve being a deliberate choice.

## Surface expansion

`--expand` grows the target list before scanning it: environment permutations
(`dev-`, `staging-`, `api-`, …) resolved against DNS, plus CT logs and
subdomain sources when `--passive` is set. Wildcard DNS is fingerprinted and
its hits discarded.

Two checks find surface DNS never advertises:

- **Virtual hosts** — Host-header probing against an in-scope IP. A name only
  counts when it differs from *both* the default response and a random-hostname
  baseline; comparing against one alone reports every host on a catch-all.
- **Exposed origin** — where a CDN/WAF is detected, assay tries the origin IP
  directly with the right Host header. If the same application answers without
  the edge headers, every control implemented at the edge is bypassable.

## Working while it scans

The report is written from the first finding and refreshed every few seconds
while the scan runs, so the first critical can be worked by hand long before
the last host is swept. Scroll position and filters survive the refresh, and
auto-refresh can be paused from the page.

```bash
assay scan 10.20.0.0/24 -n "ZESTY WOMBAT" --scope scope.txt --open
```

The report itself is a triage surface, not a document: search, severity and
triage filters, module filter, confirmed-only toggle, copy buttons on every
repro command and submission draft, and `/` `j` `k` `o` keyboard navigation.
A **Start here** panel names the three things to do first.

## One folder per engagement

`--out` is the root; each engagement gets its own subfolder, keyed on the
codename when you give one:

```
assay-out/
└── ZESTY-WOMBAT/
    ├── report.html          live during the scan, final after
    ├── assay.db             findings, assets, run history
    ├── activity.log         every request and command, timestamped
    ├── replay.sh            the same actions as runnable commands
    ├── raw/                 tool output
    └── evidence/
```

Runs accumulate in the same database, so `assay diff` reports only what
changed since last time — new findings, findings that disappeared, new hosts
and new endpoints. Findings first seen in the current run are badged **new**
in the report. The folder name is derived from the sorted target set, so
reordering the arguments does not start a fresh history.

## Everything is replayable

`activity.log` records every request and every external command in order, with
timestamps. `replay.sh` is the same set as runnable commands, deduplicated —
so a finding can be reproduced by re-running the exact request rather than
reconstructing it from the report. Disable with `--no-journal`.

## Pacing, and not breaking the client

- `--rate` global requests/second, and `--rate-per-host` (default 8/s) because
  a global ceiling alone still lets every worker pile onto one host.
- **Adaptive backoff.** A 429 or 503 halves the rate immediately and honours
  `Retry-After`; the rate creeps back only after a quiet period. A target
  asking us to slow down is not something to retry through.
- `--delay` adds a jittered pause per request.
- `--safe` restricts the run to modules that only retrieve.

Modules declare what they do to the client, and it is reported by
`assay modules`:

| Class | Meaning |
|---|---|
| `passive` | nothing reaches the client — archives, CT logs, registry lookups |
| `read` | ordinary retrieval. A GET for `/.env` is a read |
| `probe` | crafted input, unusual verbs, or fuzzing volume |
| `mutating` | could change state — never runs without `--aggressive` |

## AI and ML infrastructure

A class that barely existed two years ago and is now one of the most reliably
exposed things on an internal network. Ollama, vLLM, Gradio, Ray, MLflow and
the common vector databases all ship with **no authentication**, and the usual
deployment advice tells people to bind them to `0.0.0.0`.

assay probes eleven of them plus MCP servers, on ports that sit outside nmap's
top-1000 and are therefore added to every scan explicitly — a default port scan
never finds `11434` or `8265` on its own.

| Service | Port | What it costs |
|---|---|---|
| Ollama | 11434 | model theft, prompt/corpus extraction, free compute. Version below 0.17.1 also flags CVE-2026-7482, an unauthenticated heap read returning system prompts, chat history and environment credentials |
| vLLM / OpenAI-compatible | 8000 | RAG corpus extraction through ordinary completions; stolen inference |
| Ray dashboard | 8265 | job submission is arbitrary Python on the cluster — unauthenticated RCE |
| TorchServe management | 8081 | registers a model archive from a URL; the handler executes on the server |
| Qdrant / ChromaDB / Weaviate / Milvus | 6333, 8000, 8080, 9091 | the indexed corpus is readable, and writable — RAG answers can be poisoned |
| MLflow | 5000 | experiments and artifacts, which routinely hold training data and credentials |
| Gradio | 7860 | full component graph and event API |
| MCP servers | various | whatever the server wraps — filesystem, shell, database, cloud API — callable with its own credentials |

Every probe is a read-only GET or a protocol handshake. Nothing uploads a
model, submits a job, or runs an inference: reachability and the service's own
identification are the finding, and exercising it would cost the client compute
or change their state. Each finding names which part of the CIA triad it
affects and why.

## Networks that proxy everything

Some testing gateways proxy all port 80 and 443 traffic for security, so every
address in scope answers a connect and returns something whether or not a
service exists. Untreated, a /24 reports as two hundred web endpoints and every
content check runs against the proxy's own error page.

An open port is therefore not evidence of anything. assay decides from the
**response**, not the connection:

| Response | Verdict |
|---|---|
| 502 / 503 / 504 | proxy with nothing behind it — not a service |
| empty body | not a service |
| 200 with almost no content | the proxy, not a site |
| 401 / 403 with a real page | **a service**, and a good lead — something is guarding it |
| anything with real content | a service |

It also probes **every open TCP port** for HTTP, not a fixed list — only ports
whose service is definitively something else (ssh, mysql, smtp…) are skipped.
On a network where 80 and 443 are proxied noise, the interesting application is
usually on an odd port, and a site on 7777 with no service banner would
otherwise be invisible.

On top of that, assay identifies the gateway's default page two ways:

- **Inferred, by default.** If most probed hosts return effectively the same
  response, that response is the gateway's, not two hundred identical
  applications. Those hosts are dropped and it says so. A genuine
  load-balanced pool stays, because it never reaches a majority share.
- **Asserted, when you know.** `--proxied-ports 80,443` tells assay the ports
  are always open, so it stops reporting them as exposed services and lowers
  the bar for identifying the default page — to three matching hosts and a
  majority, rather than five. It does not drop the bar to two: two identical
  responses are just as likely to be a two-node load-balanced pool, and
  filtering a real pool away is worse than the noise it saves.

```bash
assay scan 10.20.0.0/24 -n CODENAME --scope scope.txt --proxied-ports 80,443
```

`--no-gateway-filter` disables both if you would rather see everything.

## Scope enforcement

Every outbound request — assay's own and every external tool's — is checked
against the scope file first. Out-of-scope hosts are refused before a packet
leaves the box, and blocked hosts are reported at the end of the run.

```
*.target.tld
10.20.0.0/16
!vpn.target.tld        # exclusions win
```

Four formats are accepted and detected automatically: a plain list as above,
YAML with `allow:`/`deny:` keys, and **Burp's own scope JSON** — export from
Target > Scope, or lift `target.scope` out of a project settings export.
Burp's advanced-mode host regexes are converted back to plain patterns where
possible, disabled entries are skipped, and exclusions are preserved.

Running without `--scope` warns loudly. On a real engagement, don't.

---

## Burp integration

Three levels, independently usable:

| Flag | Needs | Effect |
|---|---|---|
| `--burp auto` | Community | Proxies every assay **and** external-tool request through Burp; the whole scan lands in Proxy history and the site map |
| `--burp-mirror` | Community | Replays the exact request behind each finding through Burp, so the interesting requests are sitting there ready for Repeater |
| `--burp-scan` | Professional | Queues Burp's active scanner against the URLs assay flagged, via the REST API |

`assay burp --scope-file burp-scope.json` exports assay's scope in Burp's own
format so both tools agree on the boundary.

**WSL note:** `--burp auto` knows Burp is probably on the Windows host. It
tries `127.0.0.1:8080` (works under mirrored networking) and then the WSL2
default gateway. If neither responds, `assay doctor` prints the exact
`.wslconfig` change or listener/firewall setting needed.

---

## Running small

`assay` reads `/proc/meminfo` and CPU count at startup and derives worker count,
request rate, and every external tool's concurrency from what's actually
available. On a 2 GB VM it paces itself down rather than swapping. Findings
stream to SQLite instead of accumulating in memory, and external tool output is
parsed line by line.

Override any of it: `--concurrency 4 --rate 10`.

| Profile | Ports | Roughly | Use for |
|---|---|---|---|
| `quick` | top 100 | ~2 min/target | Triaging a fresh target list |
| `standard` | top 1000 | ~10 min/target | Default |
| `deep` | all | hours | An overnight pass on a shortlist |

---

## Authentication

`--basic user:pass` applies HTTP Basic credentials to assay's own requests and
passes the header through to httpx, nuclei and katana. `--cookie` and `-H` work
the same way.

Testing of authenticated web application logic — IDOR, privilege escalation,
multi-role access control — is deliberately out of scope for now; those need a
human with two accounts, not a scanner.

## Blind vulnerabilities

Blind SSRF produces no change in the response, so assay needs a callback channel:

- **interactsh-client** installed → fully automatic; callbacks are correlated
  and reported as `confirmed`.
- **`--oob-domain`** with a Burp Collaborator payload domain → assay still fires
  uniquely-labelled payloads and writes `oob-payloads.txt` mapping each payload
  to the exact request that carried it, for manual correlation.
- **Neither** → the blind checks are skipped and say so.

A payload that was fired but needs manual correlation still beats a check that
never ran.

## AI triage (opt-in, redacted)

Off by default. `--ai` sends findings to Claude for judgement — which are
worth reporting, which look like false positives, what the next manual step is,
and which findings chain together.

**Nothing identifying the client ever leaves the box.**

```
findings → redact → VERIFY (hard gate) → Claude → merge back locally
```

Redaction replaces hostnames, IPs, emails, credentials, tokens, usernames,
passwd rows, MACs and UUIDs with stable pseudonyms (`[CLIENT-01]`, `[IP-03]`).
Stable means the model can still reason about relationships and find chains —
it just never learns who the client is. The reverse mapping is written to
`redaction-map.json` with `0600` permissions and never transmitted.

The gate is not advisory. After redaction the payload is re-scanned with the
same detectors **plus** every known client term from your scope file and target
list. If anything survives, the run aborts and prints the residue — it does not
send.

```bash
assay scan target.tld --scope scope.txt --ai --ai-dry-run   # write payload, send nothing
cat assay-out/ai-payload.json                                # read exactly what would go
assay ai --out ./assay-out                                    # send it
```

Defaults to metadata only — no response bodies at all. `--ai-evidence` adds
redacted evidence snippets. Interactive runs confirm before sending. Requires
`pip install anthropic` and `ANTHROPIC_API_KEY` (or `ant auth login`).

---

## External tools

assay orchestrates these when present and degrades gracefully when not —
`assay doctor` shows what's missing and what each one buys you.

`nmap` · `naabu` · `httpx` · `nuclei` · `katana` · `subfinder` · `dnsx` ·
`tlsx` · `ffuf` · `seclists` · `arjun` · `gau` · `waybackurls` ·
`interactsh-client` · `puredns` · `testssl.sh` · `gowitness`

### Installing them

`./install.sh` does this on first run, but `assay install` handles it any time:

```bash
assay install --dry-run       # print the exact commands, run nothing
assay install                 # install everything missing, after confirming
assay install -y              # no prompt
assay install --only ffuf,seclists
assay install --required-only # just what assay can't work well without
assay scan <target> --install-missing
```

It resolves apt packages and Go modules from the same registry the rest of the
tool reads, installs the Go toolchain first if it's absent, appends `$GOPATH/bin`
to your shell rc, pulls nuclei's templates, and re-verifies at the end.

Two safeguards worth knowing: it **always prints the full command list and asks
before running anything** (and refuses to run non-interactively without `-y`),
and on a constrained VM it pins `GOFLAGS=-p=1` so parallel Go builds can't OOM
the box. On a non-Debian system it reports what it can't handle rather than
guessing at a package manager.

nuclei is filtered hard on the way in: fingerprinting templates are dropped,
results duplicating a native check are dropped, and survivors are re-scored on
assay's scale so a nuclei `high` can't outrank a locally verified critical.

---

## Commands

```
assay scan <targets>     run a scan (hosts, CIDRs, URLs, or -f file)
assay doctor             tools, Burp reachability, WSL networking, resources
assay report             rebuild the HTML report from a previous run
assay show <n>           print finding #n in full, with evidence
assay ai                 AI triage over an existing run
assay burp               mirror findings / queue a Burp scan / export scope
assay install           install the external tools (--dry-run to preview)
assay replay <capture>  replay an authenticated Burp/HAR capture with the
                        credentials stripped, to find unauthenticated access
assay submit [n]        generate a submission draft (category, CVSS, repro steps)
assay followup          un-redact and run the AI's verification commands
assay modules            list detection modules
```

Output lands in `assay-out/`: `report.html` (self-contained, opens in the
Windows browser from WSL), `assay.db` (queryable SQLite), `raw/` (tool output).

---

## Coverage

| OWASP | Checks |
|---|---|
| A01 Broken Access Control | CORS trust boundaries (reflected origin, `null`, sibling-subdomain), path traversal, open redirect, ELMAH/trace.axd |
| A02 Cryptographic Failures | Certificate validity, self-signed, legacy TLS, exposed `.htpasswd` |
| A03 Injection | SQL injection (error differential + boolean inference), reflected-input context analysis, traversal oracles |
| A05 Misconfiguration | 36 exposure signatures (VCS, `.env`, actuator, heapdump, `web.config`, source maps, backups), directory listing, GraphQL introspection, HTTP methods |
| A06 Vulnerable Components | nuclei CVE templates, version fingerprinting |
| A07 Auth Failures | WordPress user enumeration, XML-RPC amplification, default-login templates |
| A08 Integrity Failures | Java RMI, JDWP, deserialization templates |
| A10 SSRF | Out-of-band SSRF with callback correlation, in-band fetch-error oracle, internal host discovery, Host/proxy-header injection |
| Host | Redis / memcached / Elasticsearch / Docker API / kubelet / Jupyter proven unauthenticated with one read-only request; 18 NSE rules for anonymous FTP, NFS, rsync, SMB null sessions and signing, LDAP, SNMP, RDP/NLA, VNC, IPMI, SMTP relay, empty DB passwords; 15 more service rules with the exact manual step |

---

## Testing

```bash
.venv/bin/python -m tests.test_detection
```

155 offline tests. Every detection test asserts **both** directions — the check
fires on the real condition and stays silent on the benign lookalike (a static
CORS header, a themed 404 containing a keyword, a reflected traversal payload,
a redirect to a fixed internal path).

Tests run entirely against canned responses. assay's suite never opens a
listening socket and never stands up a vulnerable service. The installer tests
stub `apt`/`go` presence to exercise the Kali install plan from any dev machine.

---

## Rules of engagement

assay is a testing tool, not an exploitation framework, and the defaults reflect
that:

- **Scope is enforced, not advisory.** Every request — assay's own and every
  external tool's — is checked against the scope file before a packet leaves the
  machine. Out-of-scope hosts are refused and reported at the end of the run.
- **Nothing that changes state runs by default.** Non-GET replay, and checks
  that could mutate data, require `--aggressive`.
- **Checks stop at proof.** The Docker module reads `/version` and never creates
  a container; the Elasticsearch check reads cluster health and stops. Findings
  demonstrate the primitive; they do not exercise it.
- **Third-party lookups are opt-in.** Archive and certificate-transparency
  queries tell someone other than your target what you are looking at, so they
  only run under `--passive`.
- **AI triage is off unless you ask for it**, sends pseudonymised data only, and
  aborts rather than transmitting anything that fails the redaction check.

You are responsible for staying inside your authorization. A scope file is the
safety net, not the permission.

## Caveats

- Unlinked endpoints need content discovery. The active checks inject into
  parameters found by crawling; a `/download?file=` that nothing links to won't
  be found unless `ffuf` and a wordlist are installed — `assay install --only
  ffuf,seclists` fixes that, then use `--profile deep`.
- `--aggressive` enables checks that may change state. Off by default; confirm
  it's within the program's rules first.
- Findings are leads with evidence attached, not submissions. Reproduce by hand
  before reporting — every finding ships with a `curl` command for exactly that.
