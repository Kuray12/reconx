# ReconX

Modular attack-surface discovery toolkit — a Python CLI that wraps well-known
public recon utilities (subfinder, assetfinder, amass, dnsrecon, dnsx, httpx,
katana, gau, waybackurls, nuclei, xray, ffuf, arjun, sqlmap, dalfox, cloud_enum)
plus **nmap** behind a single streamlined menu.

> **Authorized use only.** Only scan systems you own or have explicit written
> permission to test (bug-bounty scope, signed pentest SOW, or your own lab).
> Notification features only ever deliver to *your own* Telegram chat or inbox.

---

## 1. Menu

```
[1] Deep Scan                          # input target, pick speed
[2] Generate Report -> Send To Telegram
[3] Generate Report -> Send To Email Target
[4] Setup Configuration
[5] Update Tool
[6] Download Wordlists
[9] Out
```

### Deep Scan speeds

After you type the target, you choose one of three modes:

| Speed | Label | Modules |
| --- | --- | --- |
| 1 | **Fast** | subfinder + assetfinder + amass + dnsrecon/dnsx + live-host probe |
| 2 | **Standard** | Fast + URL crawling (katana/gau/waybackurls) + nuclei |
| 3 | **Deep** | Standard + sensitive-data + takeover + **ffuf** + **arjun** + **sqlmap** + **dalfox** + **cloud_enum** + **xray** + **nmap** |

`Deep` runs content discovery (`ffuf`), hidden-parameter discovery (`arjun`),
SQL-injection detection (`sqlmap`), XSS scanning (`dalfox`), cloud-bucket
enumeration (`cloud_enum`), `xray webscan` and `nmap -p- -sV` across every live
host — expect it to take a long time.

---

## 2. Requirements

- Python 3.10+
- Go 1.21+ (to install the Go-based recon binaries)
- nmap (installed automatically by `install.sh`)
- `$GOPATH/bin` (default `~/go/bin` on Linux/macOS, `%USERPROFILE%\go\bin` on
  Windows) on your `PATH`

### Linux / macOS (recommended)

```bash
git clone <your-repo-url> reconx
cd reconx
chmod +x install.sh
./install.sh          # venv + pip deps + Go tools + nmap + seeds .env
source .venv/bin/activate
export PATH="$PATH:$HOME/go/bin"
python reconx.py
```

By hand:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python reconx.py
```

### Windows (PowerShell)

```powershell
cd C:\Users\user\reconx
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python reconx.py
```

The **first thing after cloning is installing dependencies** — `reconx.py` will
not start without them (`rich`, `requests`, `PyYAML`, `Jinja2`,
`python-dotenv`).

### Verify the install

```bash
python -m tests.smoke     # 47 offline checks: config, parsing, FP filter, reports
```

No network or external binaries are needed for the test suite.

---

## 3. External tools

`install.sh` installs all of these for you. To do it manually on Linux/macOS:

```bash
# nmap (system package)
sudo apt install nmap          # Debian/Ubuntu
sudo dnf install nmap          # Fedora
sudo pacman -S nmap            # Arch

# Python-based
pip install dnsrecon
pip install arjun
pip install sqlmap
pip install cloud-enum

# Go-based recon tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

export PATH="$PATH:$(go env GOPATH)/bin"

# Xray (prebuilt binary; needs a config file to actually scan)
# https://github.com/chaitin/xray/releases
```

| Tool | Stage | Purpose |
| --- | --- | --- |
| subfinder, assetfinder, amass | Enumeration | Passive subdomain discovery |
| dnsrecon | DNS | DNS records + zone-transfer check |
| dnsx | DNS | Fast bulk resolution of the subdomain list |
| httpx | Probing | Live-host detection |
| katana, gau, waybackurls | Crawling | URL collection |
| ffuf | Content | Directory/file discovery (uses `wordlists/`) |
| arjun | Params | Hidden GET/POST parameter discovery |
| sqlmap | Injection | SQL-injection detection (non-intrusive, detection only) |
| dalfox | XSS | Cross-site scripting scanning |
| cloud_enum | Cloud | Open S3 / Azure / GCP bucket discovery |
| nuclei, xray | Vuln scan | Template / web vulnerability checks |
| nmap | Ports | Open ports + service versions (Deep only) |

### Wordlists

`install.sh` downloads a small curated set (~1.2 MB) from SecLists into
`wordlists/`:

| File | Size |
| --- | --- |
| `raft-small-directories.txt` | ~159 KB (default for ffuf) |
| `common.txt` | ~37 KB |
| `raft-medium-directories.txt` | ~244 KB |
| `dirbuster-small.txt` | ~708 KB |
| `burp-parameter-names.txt` | ~52 KB |

Download or refresh them any time with menu **[6]**, or drop your own `.txt`
files into `wordlists/` — the tool picks up whatever is there. This avoids
cloning the full ~1 GB SecLists repo.

ReconX detects missing tools and **skips those modules instead of crashing**, so
you can start before everything is installed. The startup *Tool Check* shows
what is missing and how to install it.

---

## 4. Configuration (`.env`)

Everything in `.env` is optional except `OPERATOR_NAME`. The scan target is
typed in interactively when you run **Deep Scan**.

```bash
cp .env.example .env
nano .env
```

| Variable | Meaning |
| --- | --- |
| `OPERATOR_NAME` | Written into every report for accountability |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Your own bot + chat |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | Your mail relay |
| `EMAIL_FROM` / `EMAIL_TO` | Your own sender and inbox |

You can also configure everything through menu **[4] Setup Configuration**.

---

## 5. False-positive control

Recon produces a lot of noise if left unfiltered. ReconX suppresses the two
biggest sources:

**Content discovery (ffuf)** runs in two layers:

1. `ffuf -ac` — ffuf's own auto-calibration, which learns the server's wildcard
   response and filters matching results live.
2. A **verification pass** — each surviving hit is fetched once and its body
   size + SHA-1 hash are recorded. Any size or body hash shared by **3 or more**
   distinct paths is treated as a soft-404 signature and dropped, as are known
   framework paths (`.git/`, `node_modules/`, …) and generic not-found bodies.

A repeated size shared by only two paths is **kept**, so genuine findings are
not over-filtered.

**Sensitive-data regex** ignores placeholder values that are the classic source
of bogus "we found an AWS key" alerts: `EXAMPLE`, `sample`, `dummy`,
`changeme`, `${VAR}`, `<tokens>`, repeated characters, and short numeric
strings.

Filter rules live in `reconx/core/fp_filter.py` and
`reconx/modules/sensitive.py` — both are plain code you can tune.

---

## 6. Output

Every scan prints to the CLI, then writes to `output/`:

- `<target>-<timestamp>.json` — raw structured data
- `<target>-<timestamp>.md` — Markdown report
- `<target>-<timestamp>.html` — self-contained HTML report

Reports include subdomains, DNS records/zone-transfer hits, live hosts,
parameterized URLs, sensitive-data matches, subdomain-takeover candidates,
content discovery, hidden parameters, SQLi/XSS findings, cloud buckets,
nuclei/xray findings, and nmap open ports.

Menus **[2]** and **[3]** reload the most recent scan and deliver it to your
Telegram / email. If Telegram or email is configured, a Deep Scan also offers to
send the report immediately after it finishes.

---

## 7. Project layout

```
reconx/
├─ reconx.py                  # launcher
├─ install.sh                 # Linux/macOS one-shot installer
├─ requirements.txt
├─ .env.example
├─ LICENSE
├─ output/                    # reports (json/md/html) land here
├─ wordlists/                 # curated wordlists (downloaded on demand)
├─ tests/
│  └─ smoke.py                # offline test suite (no network)
└─ reconx/
   ├─ __init__.py
   ├─ core/
   │  ├─ cli.py               # menu loop
   │  ├─ scanner.py           # Deep Scan orchestration (Fast/Standard/Deep)
   │  ├─ config.py            # env + target normalization
   │  ├─ console.py           # colored [*] [+] [!] output
   │  ├─ runner.py            # external-process runner
   │  ├─ report.py            # data model
   │  ├─ reportgenerator.py   # md/html rendering
   │  ├─ fp_filter.py         # soft-404 / false-positive suppression
   │  ├─ wordlists.py         # curated wordlist download/resolution
   │  ├─ setup_wizard.py
   │  └─ update.py
   ├─ modules/
   │  ├─ subdomains.py        # subfinder + assetfinder + amass
   │  ├─ dns_enum.py          # dnsrecon (records/AXFR) + dnsx (resolution)
   │  ├─ probe.py             # httpx (+ Python fallback)
   │  ├─ crawl.py             # waybackurls + gau + katana
   │  ├─ content.py           # ffuf directory/file discovery (+ soft-404 filter)
   │  ├─ params.py            # arjun hidden-parameter discovery
   │  ├─ sqli.py              # sqlmap SQL-injection detection
   │  ├─ xss.py               # dalfox XSS scanning
   │  ├─ cloud.py             # cloud_enum S3/Azure/GCP buckets
   │  ├─ sensitive.py         # regex sensitive-data scan
   │  ├─ takeover.py          # dangling-CNAME fingerprints
   │  ├─ nuclei.py            # nuclei wrapper
   │  ├─ xray.py              # xray webscan wrapper
   │  ├─ nmap_scan.py         # nmap port/service scan
   │  └─ dorking.py           # dork generator
   └─ notify/
      ├─ __init__.py          # dispatcher
      ├─ telegram.py
      └─ email.py
```

---

## 8. Notifications are self-only

The Telegram and email modules read credentials exclusively from your own `.env`
and deliver only to the chat/inbox configured there. There is no code path that
sends scan results to an arbitrary third party.

---

## 9. Troubleshooting

- **"tidak ditemukan di PATH"** → install the tool and restart the shell.
- **httpx yields nothing** → ReconX falls back to a small Python prober.
- **Deep Scan is slow** → that is nmap `-p-`; use speed `2` (Standard) instead.
- **`install.sh: bad interpreter`** → CRLF line endings; run
  `sed -i 's/\r$//' install.sh` or `git config core.autocrlf input`.
- **nmap needs root** → run the tool with `sudo`, or use speed 1/2.

---

## 10. Publishing to GitHub

```bash
cd reconx
git init
git add .
git commit -m "Initial commit: ReconX recon toolkit"
git branch -M main
git remote add origin https://github.com/<you>/reconx.git
git push -u origin main
```

`.gitignore` excludes `.env` and scan output, so secrets never get committed.
`.github/workflows/ci.yml` runs the test suite on Python 3.10–3.13 on every
push.

> Tip: if you upload via the GitHub web UI, remember that dotfiles
> (`.env.example`, `.gitignore`, `.github/`) are easy to miss with drag-and-drop.
> Use `git push`, or `git add -f .env.example .gitignore .github` to be sure.
