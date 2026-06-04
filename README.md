# Subverse

> A quick tool that visualises a domain's external attack surface — built for pentests and recon.

Feed it a text file of domains/subdomains. Subverse resolves DNS, fingerprints
who hosts what and which services are exposed, then renders a **report-ready
map** so forgotten subdomains, shared-server blast radius, and posture gaps jump
out at a glance.

- **DNS** — A/AAAA/CNAME/MX, authoritative nameservers, zone detection
- **Hosting** — IP → ASN / hosting provider (Team Cymru, no API key) + PTR
- **HTTP/TLS** — per-host status code, redirects, `Server` header, and TLS
  validity (expired / self-signed / hostname mismatch → *insecure TLS*)
- **Services** — `nmap -sV` fingerprint of ports 21/22/25/80/443, with a
  heuristic flag for old / EOL software
- **Email & DNS posture** — SPF (+ fail mode), DKIM selectors, DMARC policy,
  CAA issuers, and wildcard detection

The default output is a **card-grid map grouped by shared hosting IP** — the
view that makes forgotten subdomains and private-IP leaks obvious. It's rendered
as a self-contained **HTML** page and a **PNG** image (via headless Chromium).
An optional node-graph view is available with `--graph`.

```
domains.txt ─▶ resolve ─▶ IP→ASN/provider ─▶ HTTP/TLS ─▶ nmap -sV ─▶ DNS posture ─▶ classify ─▶ render
```

## ⚠️ Authorized use only

Subverse **actively probes** infrastructure (DNS, HTTP/TLS, TCP service
scanning). Only run it against assets you own or are **explicitly authorized**
to assess. It is intended for sanctioned penetration tests and defensive
attack-surface mapping. You are responsible for how you use it.

## Install

Pure Python (**≥ 3.10**) with a single pip dependency, **dnspython**. Three
optional external tools unlock the full output:

| tool | for | install |
|------|-----|---------|
| **nmap** | service / version probing | `brew install nmap` · `apt install nmap` · `winget install Insecure.Nmap` |
| **Chrome/Chromium** | rasterizing the card PNG | already present on most systems; else see below |
| **graphviz** | the `--graph` node image | `brew install graphviz` · `apt install graphviz` |

```bash
git clone https://github.com/unbreached/subverse.git
cd subverse

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt      # just dnspython
# (optional) pip install -e .         # installs the `subverse` command on your PATH
```

Without `pip install -e .` you can always run it as a module: `python -m subverse …`.

### Cross-platform & dependency auto-install

Works on **macOS, Linux and Windows**. Browser/tool discovery is OS-aware, and
the missing-tool helpers detect your package manager:

```bash
python -m subverse --check-deps                    # report what's installed + how to get the rest
python -m subverse --install-deps domains.txt      # auto-install missing tools, then run
```

`--install-deps` uses brew / apt / dnf / pacman / zypper / winget / choco as
appropriate (with `sudo` on Linux when needed). If `dnspython` is missing it is
pip-installed automatically. Set `SUBVERSE_BROWSER=/path/to/chrome` to point at
a specific browser.

## Usage

Start from the bundled example and make your own target list:

```bash
cp domains.example.txt domains.txt     # then edit in your in-scope hosts
python -m subverse domains.txt -o out
```

```bash
# add a header (client / engagement ref) and dump the raw JSON
python -m subverse domains.txt \
    --name acme \
    --org "Acme Corp" \
    --ref "Engagement 2026-001" \
    --json --open

python -m subverse domains.txt --no-scan                 # skip nmap (faster, DNS + HTTP only)
python -m subverse domains.txt --plotter                 # also emit the interactive drag-around graph
python -m subverse domains.txt --graph                   # also emit the static Graphviz node image
python -m subverse domains.txt --ports 80,443,8080,8443  # custom port set
python -m subverse domains.txt --intensity aggressive    # nmap --version-all + banners
```

> **Tip:** the included `.gitignore` keeps `domains.txt` and your `labels.*.txt`
> out of git, so target lists and findings never get committed to a public repo.

### Input format

One host per line. `#` starts a comment. An optional note after the host (any
whitespace) is carried through into the data and tooltips:

```
www.example.com
api.example.com      prod API
old.example.com      decommissioned?
```

### Refining the map (`--labels`)

Role tags ("Reverse-proxy hub", "Info leak", …) and footnotes are
**auto-derived**, then you refine them. A labels file overrides per IP — see
[`labels.example.txt`](labels.example.txt):

```
# ip | role | footnote   (blank keeps the auto value)
203.0.113.10 | Reverse-proxy hub | Fronts most of the public web estate.
192.0.2.7    | Info leak         | Private/internal IP exposed in public DNS.
```

```bash
python -m subverse domains.txt --labels labels.example.txt
```

### Outputs (in `--output-dir`)

| file              | what |
|-------------------|------|
| `<name>.html`     | the card-grid map (open in a browser) |
| `<name>.png`      | the card map rasterized — report evidence |
| `<name>.json`     | raw scan data (with `--json`) |
| `<name>-plotter.html` | **interactive analysis graph** — drag/zoom/hover, filter node types, "risk only" toggle (with `--plotter`) |
| `<name>-graph.*`  | static node-graph image PNG/SVG/DOT (with `--graph`) |

## How the card map reads

- **One card per shared hosting IP**, showing the IP, owner
  (provider / ASN / PTR), an auto-derived **role tag**, and a footnote.
- **Status dots** per subdomain: 🟢 active · 🟠 insecure TLS · 🔴 error/unreachable
  · 🔵 third-party (external CNAME) · ⚫ misconfig/leak (e.g. private IP).
- **Posture badge row**: SPF / DKIM / DMARC / CAA / wildcard, ✓ or ⚠.
- The busiest IP is promoted to a full-width "feature" card so the
  blast-radius story is the first thing you see.

## Layout

```
subverse/
  model.py            dataclasses (the shared scan record)
  resolver.py         DNS: A/AAAA/CNAME/MX/NS, zone detection, PTR
  asn.py              IP → ASN/provider via Team Cymru DNS (no API key)
  http_probe.py       per-host HTTP status + TLS validity
  dns_posture.py      SPF / DKIM / DMARC / CAA / wildcard
  scanner.py          nmap -sV wrapper + XML parse
  flagging.py         heuristic old/risky-software tagging
  classify.py         status categories, role tags, footnotes, --labels overrides
  probe.py            orchestrator (resolve → asn → http → nmap → posture → classify)
  graph.py            ScanResult → abstract node/edge graph (for --graph)
  render_cards.py     card-grid map → HTML + PNG (default)
  render_html.py      interactive vis-network analysis graph (--plotter)
  render_graphviz.py  static DOT → PNG/SVG (--graph)
  platform_utils.py   cross-platform browser discovery / screenshot / open
  bootstrap.py        dependency check + auto-install
  cli.py              argparse entry point
```

## Author & license

Built by **David Jacoby** — [www.davidjacoby.se](https://www.davidjacoby.se) · 2026.

Released under the [MIT License](LICENSE).
