# Network Sentinel (macOS)

Native **macOS** desktop app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, **signature detection**, **DNS hygiene**, and **host firewall enforcement** — with a modern dark Avalonia UI sharing a palette with the iOS app.

> **Host-based** intrusion detection and prevention. It detects on its own heuristics and, with Suricata attached (0.6.x), on signature/payload inspection — then enforces in the kernel via **PF**. It is not an inline network appliance: it protects the Mac it runs on, not a segment, and it does not sit in the forwarding path.

macOS port of [davidfweiser/NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) (Linux Avalonia / original Windows WPF). Platform layers use **`lsof`/`netstat`/`nettop`**, **PF (`pfctl`)** elevated via **osascript** or **sudo**, the **macOS unified log** (`log stream`), and **`~/Library/Application Support/NetworkSentinel`**. Version **0.6.2**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `lsof` (with `netstat` fallback) |
| **Live connections** | Process name, local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this Mac, reverse DNS, geo/ISP when public |
| **Activity chart** | Live ~5-minute chart of connection samples with **threat markers** and a current/peak legend |
| **Poll interval** | Selectable in **Settings** (0.5 s – 10 s); doubles as the chart's sample rate |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance — fast (45 s window) **and slow/paced** (10 min window, catches `nmap -T1`-style scans)
- **Scans of closed ports** (opt-in) — a PF SYN-log rule makes probes visible that never appear as connections (the kernel answers closed-port SYNs with a RST before the socket table ever sees them); a `pflog0` watcher turns them into alerts within seconds
- **Failed logon bursts** from the macOS unified log (`sshd`, `sudo`, `login`, Screen Sharing) — catches SSH/PAM brute-force even when it reuses one TCP session or paces below the connection-rate thresholds
- **Outbound beaconing** — regular-interval new sessions to an uncommon remote port (C2 "calling home" signature); common client ports and LAN peers are excluded
- SSH and SMB hammering
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- First-seen remote hosts — tracked **across restarts** (30-day persistent host history), so relaunching doesn't make every known peer look new again
- **UDP peers** — connected UDP sockets with a real remote address count toward the scan/probe heuristics and the Remote Computers view (multicast/broadcast chatter like mDNS/SSDP is excluded)

### Intrusion detection (0.4.0)
| Detector | What it catches |
|----------|-----------------|
| **New-listener alerts** | A new port starts listening after the baseline (backdoor/implant signature), or a known port changes owner process (service replaced/impersonated). Baseline persists in `host-history.json`; loopback-only and ephemeral (49152+) listeners are skipped. |
| **Threat-intel blocklists** | Remote IPs checked against **FireHOL level1** and **Spamhaus DROP** (fetched daily over HTTPS, cached offline). A match is an instant **Critical** — those ranges are attack infrastructure. |
| **Process reputation** | Shells/interpreters (`bash`, `python`, `nc`, …) holding outbound connections to public hosts (reverse-shell signature, High); binaries running from `/tmp`, `~/Downloads`, `/Users/Shared` with network activity; **unsigned** (`codesign`) or **quarantined** binaries talking to public addresses. Executable paths resolve via `libproc` — no per-poll shelling out. |
| **Honeypot decoy ports** (opt-in) | Binds decoy TCP ports (default `2323,3389,5900`). Nothing legitimate connects to a decoy, so any completed connection is a **zero-false-positive Critical**. Busy ports are skipped automatically. |
| **ARP / gateway watch** | The default gateway's MAC address changing (**Critical** — classic ARP-spoof MITM opener) or another LAN IP claiming the gateway's MAC (High). |
| **Launch-item watch** | New or modified plists in `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` — the standard persistence step right after a successful intrusion. |
| **Exfiltration monitor** | `nettop` per-connection byte counters; alerts when outbound traffic to a single non-allowlisted public host exceeds a threshold (default **250 MB / 10 min**). LAN destinations (NAS backups) and allowlisted hosts stay quiet. |

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo). Threat events and the host/listener baseline **persist across restarts** (`threat-log.jsonl`, `host-history.json`).

### Suricata signatures (0.6.x)

Network Sentinel watches *behaviour* — rates, sequences, byte volumes. It does not inspect payloads, so it cannot recognise a specific exploit or a known C2 protocol. Suricata does exactly that, and this ingests its **EVE JSON** alerts as threat events so a signature match feeds the same threat list, the same webhook, and the same auto-block gates as everything else.

```bash
brew install suricata          # the console only reads the log; it never runs Suricata
```

Then enable **Settings → Intrusion detection → Suricata alerts**. The EVE path defaults to the Homebrew location for this Mac (`/opt/homebrew/...` on Apple Silicon, `/usr/local/...` on Intel); override it if yours differs. **Max severity** filters by Suricata's own rating — it counts *down*, so 1 is most severe and the default 3 keeps informational noise out. **Ignored SIDs** mutes individual signatures that false-positive on your traffic.

Which end of the flow is the threat matters here: Suricata's `src_ip` is the packet source, which for an outbound C2 callback is *this machine*. Auto-blocking that would firewall the Mac off from itself, so the remote end is whichever side is not local — and "local" includes this host's own interface addresses, not just private ranges.

Reading `eve.json` usually needs root or a mode change; the status line says so when it can't.

### WireGuard peer monitoring (0.6.x)

WireGuard is a single **unconnected UDP socket**, so a peer's traffic never becomes a tracked connection — on a VPN server, the socket table shows nothing about who is attached. This reads `wg show all dump` instead, and alerts on new peers, handshakes going stale, and per-peer transfer volume.

```bash
brew install wireguard-tools   # provides `wg`; needs root to read device state
```

Enable **Settings → Intrusion detection → WireGuard peer watch**. `wg` is resolved by absolute path (Homebrew's prefix, by architecture) rather than through `PATH`, because an app launched from Finder or by launchd does not inherit the shell `PATH` that puts Homebrew on it. Without `wireguard-tools` the status line says so and nothing else changes.

**No key material is ever read.** A device line's second field is the interface *private* key and a peer line's third is the *preshared* key; both are skipped rather than parsed, and a test asserts neither can appear in a parsed peer.

**A peer's public endpoint is protected from auto-block.** That endpoint is where the client's encrypted packets come from, so blocking it kills that client's VPN — and a peer alert (or any other detector tripping on peer traffic) would otherwise nominate exactly that address. Manual blocking is deliberately unaffected.

### DNS hygiene (0.6.x)

Almost nothing connects without resolving a name first, so DNS is where a compromise usually shows earliest — and it is an exfiltration channel the exfiltration monitor cannot see, because that counts TCP socket bytes and DNS is UDP.

It also closes a hole in this app's own defences. The allowlist resolves its domains over whatever DNS this Mac is using, and auto-block never touches a resolved allowlist address. Poison the resolver and an attacker's address is written into the never-block list under a trusted domain's name. Each answer is therefore compared against the networks that domain has resolved into before (/24 for IPv4, /48 for IPv6), and only a move that shares nothing with that history alerts — so CDN rotation stays quiet. That history persists, because a restart that silently re-seeded would adopt a poisoned answer as the new truth.

| Detection | Level |
|---|---|
| Plaintext DNS leaving this Mac | Medium |
| Encrypted DNS silently falling back to plaintext | High |
| Queries to a resolver you did not approve | High |
| A VPN client bypassing this host's resolver | Medium |
| An allowlisted domain resolving into an unfamiliar network | High |

The fallback case is the one nobody catches: resolvers usually degrade to plaintext rather than fail, so a blocked port 853 or an expired certificate quietly removes the protection you configured.

**Limits are explicit.** Port 53 is plaintext and detected anywhere. 853 is DoT. DoH is HTTPS on 443 and indistinguishable from the web, so it only counts as encrypted when the destination is a resolver you listed under **Approved resolvers** — without that list a DoH setup looks like *no DNS at all* rather than a leak. Queries to a resolver running **on this Mac** are never flagged: local-resolver-with-encrypted-upstream is the arrangement that keeps queries visible here while hiding them from the network. A query to your *router* is not exempt — it genuinely leaves the machine in the clear, onto a segment anything can read.

#### PF flow events

DNS hygiene is fed by PF's state table, not the socket tables. `lsof` and `netstat` only show sockets this Mac owns, and for UDP they show almost nothing — a DNS query is a send on an unconnected socket that is gone before the next poll. PF tracks state for UDP as well as TCP, and for traffic this Mac merely forwards, so it sees flows no socket table will.

This is where macOS differs from the Linux build, which subscribes to conntrack netlink and receives a kernel event per flow:

- **It polls** (once a second) and diffs successive `pfctl -s state` dumps. A flow that opens *and* closes inside one interval is never seen. Repeated queries to the same resolver — what every check above keys on — are seen reliably.
- **PF must be enabled.** macOS boots with PF off unless something turns it on; blocking any address enables it, or `sudo pfctl -e`.
- **It needs root**, and unlike a netlink subscription the privilege is spent *per poll*, so it only runs when elevation is silent (root, or passwordless/cached `sudo` for `pfctl`). It never raises a password dialog — a monitor that prompts once a second is worse than one that is off. The status line says which of these is missing.

The app still does not configure your resolver. Installing a local forwarder and pointing it upstream over DoT is a one-time job whose failure mode takes out name resolution for this Mac and every tunnel client at once — a different kind of tool from a monitor.

### Remote alerting (webhook)
Set **Settings → Webhook URL** to push Critical threats off the machine — the payload adapts automatically: **ntfy** (plain text + `Title`/`Priority` headers), **Slack** (`{"text": …}`), **Discord** (`{"content": …}`), anything else gets a generic JSON document. Per-source/type cooldown stops a burst from flooding the channel.

**Critical alerts (on by default).** A `Critical` threat is announced actively rather than just added to a list: the desktop app posts a macOS notification, and the web console badges the tab title (`⚠ 2 · Network Sentinel`) and raises a browser notification. Repeats of the same source + threat type are suppressed for 5 minutes so a burst can't spam you. Turn it off under **Settings → Critical threat alerts**.

### Remote access over HTTPS (0.5.0 – 0.5.1)
Reach the browser console from outside this Mac without hand-editing config or leaving the app:

| | |
|---|---|
| **HTTPS** | Kestrel terminates TLS alongside the plain-HTTP port; hostname requests redirect, bare-IP requests stay on HTTP. Certificates reload on renewal without a restart. |
| **DuckDNS** | A free hostname that follows your public IP, refreshed every 5 minutes by whichever front-end is running. Token stored `0600` in its own file, never sent to the browser. |
| **Issue certificate** (0.5.1) | One button in **Settings → Remote access** runs the whole Let's Encrypt DNS-01 flow and fills in the certificate paths. Failures name the cause; the transcript lands in `logs/cert-issue.log`. |
| **Login lockout** | Five wrong master-password attempts lock that client IP, doubling from 1 minute to 1 hour. |

Full setup is under [HTTPS and remote access](#https-and-remote-access-050) below.

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Dedicated **PF anchor** `com.networksentinel` (only manages its own rules)
- Block rules are created as an `-In`/`-Out` pair and **removed together** in one click
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`), run through one prevention engine shared by all three front-ends — see [Auto-block](#auto-block)
- **Dry run** — decide and report what would be blocked without writing a single PF rule
- Settings in `~/Library/Application Support/NetworkSentinel/settings.json`
- **Authorize firewall** — elevates only `pfctl` via Mac admin password dialog. The GUI always runs as your user

### Known-good allowlist (never block)
Trusted sites are protected so auto-block (and manual block) will not cut off everyday tools:

| Source | Location |
|--------|----------|
| **Built-in defaults** | `Data/allowlist-default.json` (GitHub, xAI/Grok, Microsoft, Google, Cloudflare DNS, NuGet, …) |
| **Your additions** | `~/Library/Application Support/NetworkSentinel/allowlist.json` |
| **Remote feed** | Optional refresh from the upstream repo’s `allowlist-default.json` on GitHub |

---

## Requirements

- **macOS** 12+ (Apple Silicon or Intel)
- [.NET 8 SDK or runtime](https://dotnet.microsoft.com/download) (or use a self-contained publish)
- Avalonia desktop dependencies (bundled with the runtime on macOS)
- Admin rights (password dialog) for PF firewall changes
- Optional, each enabling one detector: `brew install suricata` (signature alerts), `brew install wireguard-tools` (peer monitoring). PF flow events and DNS hygiene additionally need PF enabled and **silent** root — see [PF flow events](#pf-flow-events)

---

## Quick start

```bash
cd NetworkSentinel-mac
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_ROOT="$HOME/.dotnet"

dotnet run -c Release
```

### Terminal UI (TUI)

```bash
dotnet run -c Release -- --tui
# or after publish:
./NetworkSentinel --tui
# or:  NETWORKSENTINEL_TUI=1 ./NetworkSentinel
```

| Key | Action |
|-----|--------|
| `1`–`7` / `Tab` | Dashboard · Connections · Hosts · Threats · Ports · Firewall · **Allowlist** |
| `↑` `↓` / `j` `k` | Move selection |
| `/` or `f` | Filter |
| `p` | Pause / resume monitoring |
| `a` | Toggle auto-block |
| `m` | Cycle auto-block minimum severity |
| `b` / `x` | Block / unblock selected IP (or prompt) |
| `n` / `+` | **Add domain or IP to allowlist** (never block) |
| `d` | Remove selected allowlist Domain/IP (on Allowlist view) |
| `g` | Restore good sites (unblock allowlisted IPs) |
| `u` | Authorize firewall elevation (admin password) |
| `c` | Clear threat alerts |
| `r` | Refresh firewall · on Allowlist: refresh DNS/feed |
| `h` / `F1` | Help |
| `q` | Quit |

### Headless web console

Runs the same monitor and firewall engine with a browser front-end instead of the Avalonia GUI — useful over SSH or on a Mac with no logged-in desktop session.

```bash
dotnet run -c Release -- -w          # auto-picks a free high port (prefers 18765)
dotnet run -c Release -- -w 18765    # explicit port
# or:  NETWORKSENTINEL_WEB=1 ./NetworkSentinel
```

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers), monitoring/firewall status, recent threats |
| **Connections / Threats** | Live traffic with a **Block** button on every row |
| **Hosts** | Remote peers; block / unblock by row or by typed IP |
| **Ports** | Local listeners; one-click **Block port** |
| **Firewall** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, poll interval, geo lookups, auth-log monitoring, closed-port scan detection, critical threat alerts, **Suricata alerts**, **WireGuard peer watch**, **PF flow events**, **DNS hygiene**, **HTTPS + DuckDNS remote access** (incl. one-click **Issue certificate**), auto-block + minimum severity + **dry run**, block direction, allowlist feed, **change master password**, **Remove all rules** |

#### Sleep / Wake

The first button in the web console header is a single **Sleep ⇄ Wake** toggle:

- **Sleep** stops *everything the console watches* — the connection/port poll plus the auth-log, closed-port probe, ARP, launch-item, exfiltration and honeypot watchers — and parks the page: the live tabs dim, a banner explains the state, and the browser drops its 2.5-second refresh so a sleeping console costs nothing on either end
- **Wake** starts monitoring again from live data and restores the normal refresh
- **Firewall blocks stay in force while asleep.** Sleeping stops watching; it never unblocks an address the machine is already protected from
- The state is the server's, not the browser's: reload or open a second tab and you still see *Asleep*, and the **Settings → Live monitoring** switch is the same control. While asleep the page keeps a 30-second heartbeat so a wake from anywhere shows up here
- Sleep is a runtime state — it is not written to `settings.json`, so restarting the service comes back up monitoring
- Sleep applies to the process you pressed it in; a desktop or TUI instance is a separate process and keeps running (the TUI has its own `p` key for the same thing)

**Master password.** The first visit creates one; every later visit requires it. Change it under **Settings → Master password**. If you can't reach a browser yet, set or reset it from the terminal:

```bash
sudo ./NetworkSentinel --set-master-password
```

That requires root and resolves the real target user via `SUDO_USER` (using `dscl`), so the hash lands in **your** `~/Library/Application Support/NetworkSentinel/web-master.json` — not root's. Restart the web console afterwards so it picks up the change. The hash is PBKDF2-SHA256 (random salt, 200k iterations) — never plain text.

**Setup code for remote first visits.** Creating the master password from **another machine** additionally asks for a one-time **setup code**, printed where the console runs — the terminal, or the unified log when it runs as a launchd service:

```bash
log show --last 10m --predicate 'process == "NetworkSentinel"' | grep "Setup code"
```

The console binds all interfaces before any password exists, so without this the first scanner to find the port could claim the master password and with it firewall control. The code is random per process start and compared in constant time; wrong guesses feed the same per-IP lockout as wrong passwords. Setup from **localhost needs no code**, and the login page only shows the field when the server says it applies.

The web console **refuses to block its own port**, which would otherwise cut off your browser mid-request and look like a crash.

Failed password attempts are throttled **per client IP**: five wrong guesses trigger a lockout that doubles with each further attempt (1 minute up to 1 hour), and locked-out clients get `429` with a `Retry-After`. A fixed delay alone only slows one connection at a time — this caps a parallel guesser.

### HTTPS and remote access (0.5.0)

The console is served by **Kestrel**, so it can terminate TLS itself (macOS `HttpListener` cannot). HTTP and HTTPS are served side by side: the LAN keeps working on plain HTTP while requests that arrive **by hostname** are redirected to TLS — requests to a bare IP are left alone, since the certificate only covers the name.

```bash
./NetworkSentinel -w --https \
    --tls-cert ~/Library/Application\ Support/NetworkSentinel/tls/myhost.duckdns.org.fullchain.cer \
    --tls-key  ~/Library/Application\ Support/NetworkSentinel/tls/myhost.duckdns.org.key
```

| Flag | Meaning |
|------|---------|
| `--https` | Serve TLS in addition to HTTP |
| `--https-port PORT` | TLS port (default **18443**; below 1024 needs root) |
| `--tls-cert PATH` | PEM fullchain, or a `.pfx` / `.p12` bundle |
| `--tls-key PATH` | PEM private key (omit for `.pfx`) |
| `--tls-password PW` | Password for a `.pfx` / `.p12` |
| `--no-https` | Force plain HTTP for this run |

Flags win over `settings.json` for that run **without overwriting it**, so `--https` is safe to try. The same values live under **Settings → Remote access** in *both* front-ends — the desktop app and the web console — so you never have to hand-edit a config file; endpoint changes take effect at the console's next restart. Certificate files are re-read when they change on disk, so an **ACME renewal applies without restarting** the console. Session cookies gain the `Secure` flag automatically when the request arrives over TLS.

#### Free trusted certificate for a duckdns.org name

[DuckDNS](https://www.duckdns.org) gives a free hostname that follows your public IP. The certificate comes from Let's Encrypt via a **DNS-01** challenge — proving control by writing a TXT record through the DuckDNS API, so **nothing has to be reachable on port 80**.

**From the app (0.5.1).** Once the subdomain and token are saved, **Settings → Remote access → Issue certificate** does the whole thing — in the desktop app and in the web console. It installs `acme.sh` on first run (registering the account against the email beside the button), issues the certificate, and fills in the two path fields. The button reads *Issuing…* while it runs; expect a few minutes waiting on DNS propagation. Only one issuance runs at a time — concurrent ACME runs for the same name fight over the same TXT record.

If it fails, the status line says why rather than pointing at a terminal: a rejected DuckDNS token, a DNS record that didn't propagate, and Let's Encrypt rate-limiting are each named outright, followed by acme.sh's own last lines. The full transcript lands in `~/Library/Application Support/NetworkSentinel/logs/cert-issue.log`.

**From a terminal**, the same script does the same work:

```bash
./NetworkSentinel --set-duckdns               # subdomain + token (token is prompted, not a flag)
./scripts/issue-duckdns-cert.sh               # installs acme.sh if needed, issues + installs the cert
```

Run both as your normal user — **not** under `sudo`. They write into *your* `~/Library/Application Support/NetworkSentinel`, which is where the GUI and the console read from; under `sudo` the files would land in root's home instead and be invisible to the app.

`acme.sh` exits 2 when a certificate is still current and it skips the renewal. That is not a failure — the script installs the existing certificate and says so. Re-issue early with `NS_FORCE_RENEW=1`, but sparingly: Let's Encrypt rate-limits repeat issuance for the same name.

The token is stored in `~/Library/Application Support/NetworkSentinel/duckdns.json` with mode `0600`, is **never sent to the browser** (the settings page shows only whether one is saved), and never appears in the update URL's response. While the console runs it refreshes the A record every 5 minutes. `acme.sh` installs its own renewal cron entry.

> **Before you forward a port.** This console can add and remove firewall rules on this Mac, and anyone who guesses the master password gets that control. A VPN or [Tailscale](https://tailscale.com) is the safer way to reach it from outside — `tailscale serve` even supplies a valid certificate with no port-forwarding at all. If you do forward a port, forward **only** the HTTPS one and use a long unique password.

### Tests

```bash
dotnet test Tests/NetworkSentinel.Tests
```

180 xunit tests covering the pure-logic seams the enforcement path depends on: IP normalization (port stripping, zone ids, IPv4-mapped collapse), the non-public/CGNAT range boundaries, atomic writes under concurrent writers, the prevention gate stack (driven end to end in dry-run mode, so no rule is ever written), `pfctl -s state` and `wg show` parsing, Suricata EVE alerts, and DNS hygiene detections.

`TestEnv` points `HOME` at a throwaway directory before anything touches `AppPaths`, and **fails loudly** if the redirect did not take — otherwise a persisting service would write into your real `~/Library/Application Support/NetworkSentinel`.

Two seams stay uncovered, both needing a live privileged firewall: the startup ledger↔PF reconciliation's actual `pfctl` calls, and the auto-block retry timing.

### Release build

```bash
dotnet build -c Release
dotnet publish -c Release -r osx-arm64 --self-contained false -o bin/publish
./bin/publish/NetworkSentinel
```

Self-contained (no system .NET runtime needed):

```bash
./scripts/package.sh              # osx-arm64 on Apple Silicon
./scripts/package.sh osx-x64      # Intel Macs
```

### Installing the package

`package.sh` produces `dist/networksentinel-<version>-<rid>.tar.gz` plus a ready `dist/Network Sentinel.app` you can drag to Applications. To install from the tarball on a Mac with no .NET:

```bash
tar xzf networksentinel-0.6.2-osx-arm64.tar.gz
cd networksentinel-0.6.2-osx-arm64
sudo ./install.sh                        # /Applications + /usr/local/bin
./install.sh --user                      # ~/Applications + ~/.local/bin, no root
sudo ./install.sh --desktop-shortcut     # also drop a shortcut on the Desktop
sudo ./install.sh --no-desktop           # CLI only (headless / server)
```

| Flag | Meaning |
|------|---------|
| `--user` | Install under `~/.local` and `~/Applications` — no root |
| `--desktop-shortcut` | Also put a **Network Sentinel** shortcut on the Desktop (opt-in) |
| `--no-desktop` | Skip the Applications bundle entirely; CLI layout under `/usr/local/lib` |

By default the install *is* the app bundle: `Network Sentinel.app` holds the payload in `Contents/MacOS`, and `networksentinel` on your `PATH` is a symlink into it, so the GUI and the command are always the same build. That is what puts the app in Launchpad and Spotlight with its own icon — a bundle that merely launched a binary elsewhere would lose its identity, because macOS finds an app's `Info.plist` by walking up from the running executable's path.

`--desktop-shortcut` is opt-in because a headless Mac has no Desktop and no use for an icon. Two details the installer handles that a plain `cp` does not:

- The shortcut is a **symlink to the bundle**, not a copy — an upgrade replaces the bundle in place and the shortcut keeps working, where a copied app goes stale. A Finder *alias* would need an Automation grant the installer can't get from a `sudo` shell; Finder launches a symlinked `.app` just the same.
- Under `sudo` the shortcut goes to `SUDO_USER`'s Desktop, not root's, where nobody would find it.

Uninstall removes the bundle, the symlink and the shortcut:

```bash
sudo networksentinel-uninstall      # or:  sudo ./uninstall.sh
./uninstall.sh --user               # user install
```

The bundle is **ad-hoc signed** (`codesign -s -`). That is enough for a locally built app to run on Apple Silicon, which refuses unsigned binaries outright — it is not distribution signing, so a copy that is *downloaded* rather than built here still gets quarantined.

---

## Firewall / auto-block

**Prefer running the GUI as your user** (not `sudo`). When you block an IP/port (or click **Authorize firewall**), only `pfctl` is elevated and macOS shows a standard admin password dialog.

```bash
# correct
./NetworkSentinel

# avoid for GUI
# sudo ./NetworkSentinel
```

PF details:
- Anchor name: `com.networksentinel`
- Rules file: `/etc/pf.anchors/com.networksentinel` (mirrored under Application Support)
- First authorize may append an anchor hook to `/etc/pf.conf` (backup: `/etc/pf.conf.networksentinel.bak`)
- Only Network Sentinel’s own rules are managed; other PF rules are left alone

---

## Using the app

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Stats, activity chart, latest threats, observed hosts |
| **Live Connections** | Active TCP sessions; block remote IP per row |
| **Remote Computers** | Tracked peers, origin, threat level; block / unblock |
| **Break-in Attempts** | Heuristic alerts with origin and method |
| **Open Ports** | Listening TCP/UDP; optional inbound port block |
| **Firewall & Block** | Manual IP/port rules, auto-block, allowlist, managed rule list |
| **Settings** | Mirrors the web console's Settings tab, including **Remote access** (below) |

### Remote access from the desktop Settings (0.5.0)

**Settings → Remote access (web console)** configures HTTPS and DuckDNS without touching a config file or the command line:

| Field | What goes in it |
|-------|-----------------|
| **DuckDNS subdomain** | Just the label — `myhost`, not `myhost.duckdns.org`. The switch arms the 5-minute refresh. |
| **DuckDNS token** | Your token from duckdns.org, masked as you type. **Update now** tests it immediately and reports the result. |
| **Issue certificate** | Runs the Let's Encrypt issuance and fills in the two paths below. The email beside it is used only on first run, to register the ACME account. |
| **Serve the console over HTTPS** | On/off, with the TLS port beside it |
| **Certificate** / **Private key** | Filled in by **Issue certificate**; editable if the files live elsewhere |
| **Redirect HTTP to HTTPS** | On by default |

A status line at the top of the card shows certificate expiry, the live DuckDNS result, and the full console URL once both halves are configured. Certificate and port changes apply the next time the **web console** starts — the desktop app doesn't serve anything itself — but the **DuckDNS refresh runs in the desktop app too**, so the hostname stays current whenever either front-end is open.

The token is written to `duckdns.json` (mode `0600`), not `settings.json`; the GUI, TUI, and web console all read the same file.

### Auto-block
1. Click **Authorize firewall** (or allow the first password prompt when blocking).
2. Turn **Auto-block** **On**.
3. Choose **Minimum severity** (default **High**).
4. Public IPs that hit that severity get PF drop rules automatically.
5. Private/LAN addresses, “new host” info events, and allowlisted sites are **never** auto-blocked.

**One enforcement engine.** Every automatic block goes through `PreventionService`, whatever raised the threat and whichever frontend is running. The gates run cheapest-first and a threat must clear all of them:

> severity ≥ minimum → not informational-only → routable public IP → not allowlisted → not this machine's own address → not a protected endpoint (WireGuard peers) → not operator-protected → not already blocked → not suppressed by a manual unblock → not already claimed by a recent attempt

That last gate is not one flat interval. An address is claimed for 10 minutes once a batch acts on it, but a block that fails for a reason *other* than elevation retries after 45 seconds — leaving an actively hammering host alone for ten minutes over one transient `pfctl` error is worse than retrying. An elevation failure is never per-address, so it pauses auto-block **globally** until the backoff expires or you authorize elevation, which lifts it immediately.

This replaced three near-identical copies of the auto-block loop that had drifted: only the web console honoured the manual-unblock suppression list, so the desktop GUI and the TUI would re-block an address you had just deliberately released. Releasing an address by hand now suppresses auto-block for it for 24 hours, in every frontend, and that survives a restart. Blocking it again by hand clears the suppression.

**Dry run** (Settings → Auto-block) decides and reports blocks without writing any PF rule. Every gate still runs and the status line still names what *would* have been dropped. Inline prevention turns a false positive from noise into an outage, so this is the safe way to promote a noisy new detection source from alerting to blocking. Dry run deliberately does not consume an address's retry slot, so switching blocking on afterwards acts on exactly the addresses you were just watching.

**What auto-block will never touch.** LAN, loopback, link-local, multicast/broadcast, and **CGNAT (100.64.0.0/10** — where Tailscale and many VPN tunnel subnets live**)**. Blocking a CGNAT address would only ever cut off a tunnel peer, so it is not something a heuristic should decide.

**Startup reconciliation.** `firewall-rules.json` survives a reboot; the rules loaded into PF do not — macOS boots with PF disabled unless something enables it. Without a check, the app would report addresses as blocked and auto-block would skip re-blocking a still-active attacker, while nothing was actually in force. At startup Network Sentinel lists the anchor's live rules and, if any ledger entry is missing, re-applies the generated ruleset. If the re-apply fails it drops those entries instead, so auto-block stops believing they are covered. This only runs when elevation is silent (root, or cached/passwordless `sudo`) — startup never raises a password dialog. Otherwise it is skipped and retried on the next start.

A **manual** block of a CGNAT address is still allowed, behind a confirmation naming what it costs — a hostile tailnet peer brute-forcing SSH is a real case, and refusing it in the manual path too would leave you with no way to stop the attack from inside the app. Addresses that would cut this Mac off from its own network (LAN, loopback, link-local, multicast) stay refused everywhere.

---

## How it works (high level)

```text
  SentinelCore builds and cross-wires the graph below; the GUI, TUI and web
  console are only event handlers and presentation on top of it.

┌──────────────────┐   poll ~1.2s   ┌───────────────────────┐
│ lsof / netstat   │ ─────────────► │                       │
├──────────────────┤                │                       │
│ pfctl -s state   │  flow events   │ NetworkMonitorService  │
│ (UDP + forwarded)│ ─────────────► │                       │
├──────────────────┤                │                       │
│ unified log,     │                │                       │
│ pflog0, nettop,  │ ─────────────► │                       │
│ wg, Suricata EVE │                └───────────┬───────────┘
└──────────────────┘                            │
                                                ▼
                     ┌──────────────────────────────────────────────┐
                     │ Detectors: heuristics · threat intel · proc  │
                     │ reputation · ARP · launch items · exfil ·    │
                     │ honeypot · signatures · WireGuard · DNS      │
                     └──────────────────────┬───────────────────────┘
                                            │ ThreatEvent
                                            ▼
                     ┌──────────────────────────────────────────────┐
                     │ PreventionService — one gate stack, one       │
                     │ enforcement path (dry run stops here)        │
                     └──────────────────────┬───────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────┐
              ▼                             ▼                         ▼
     Geo / DNS lookup          GUI · TUI · web console        FirewallService
     (origin details)          (MVVM / Spectre / Kestrel)     osascript → pfctl
```

---

## Project layout

| Path | Role |
|------|------|
| `Native/MacNetTable.cs` | `lsof` / `netstat` parsing + PID mapping |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | PF via pfctl + osascript; rule ledger; PF probe-log rule |
| `Services/AuthLogMonitor.cs` | Failed-logon detection from the macOS unified log |
| `Services/ProbeLogMonitor.cs` | Closed-port scan detection from the PF packet log |
| `Services/AppSettings.cs` / `AppPaths.cs` | Application Support + JSON settings; atomic (temp-sibling + rename) writes |
| `Services/SentinelCore.cs` | Composition root — builds and cross-wires the graph all three front-ends share |
| `Services/PreventionService.cs` | The single enforcement engine: gate stack, suppression, retry/elevation backoff, dry run |
| `Services/LocalAddresses.cs` | This Mac's own interface addresses, so a detector can never firewall the host off from itself |
| `Services/SuricataService.cs` | Tails Suricata's EVE JSON and turns alerts into threat events |
| `Services/WireGuardMonitor.cs` | `wg show all dump` — peers, handshakes, per-peer transfer; reads no key material |
| `Services/DnsHygieneMonitor.cs` | Plaintext/DoT/DoH classification, resolver drift, allowlist poisoning |
| `Native/PfStateFlows.cs` | PF state-table flow events (UDP + forwarded traffic) — the macOS stand-in for conntrack netlink |
| `Tests/NetworkSentinel.Tests/` | xunit suite (180 tests); `TestEnv` redirects `HOME` so nothing touches the real profile |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring, Settings view (incl. Remote access) |
| `MainWindow.axaml` | Avalonia dashboard UI |
| `Themes/Colors.axaml` | Palette ported from `NetworkSentinel-iOS/Theme.swift`, shared with the web console |
| `Tui/TuiApp.cs` | Spectre.Console terminal UI (`--tui`) |
| `Web/WebApp.cs` / `WebAuthStore.cs` | Headless browser console (`--web`, Kestrel) + master-password auth |
| `Services/TlsCertificateProvider.cs` | Loads the console's PEM/PFX certificate; hot-reloads on renewal |
| `Services/DuckDnsUpdater.cs` | DuckDNS dynamic-DNS refresh; token stored `0600` |
| `Services/LoginThrottle.cs` | Per-IP lockout for the console's password endpoints |
| `Services/CertIssuanceService.cs` | Runs the issuance script behind the **Issue certificate** button; diagnoses acme.sh failures |
| `scripts/issue-duckdns-cert.sh` | Let's Encrypt DNS-01 issuance for a duckdns.org name (also driven non-interactively by the button) |
| `Program.cs` | Entry point; GUI / TUI / web routing, crash log |

---

## Linux / Windows → macOS changes

| Upstream | macOS |
|----------|--------|
| Linux Avalonia / Windows WPF | Avalonia 11 (`net8.0`) |
| `/proc/net` + inode map | `lsof -nP -iTCP/-iUDP` (+ `netstat` fallback) |
| nftables / iptables + pkexec | PF (`pfctl`) + osascript admin dialog |
| `~/.local/share/NetworkSentinel` | `~/Library/Application Support/NetworkSentinel` |
| `linux-x64` package | `osx-arm64` / `osx-x64` package |
| `journalctl` / `/var/log/auth.log` | `log stream` over the unified log (+ `/var/log/system.log` fallback) |
| iptables/nft `LOG` rule + `kern.log` | PF `log` rule + `tcpdump` on `pflog0` |
| `getent passwd` (service user) | `dscl . -read /Users/…` + `id -u/-g` |
| `systemd` web service | run `--web` directly (no launchd unit shipped yet) |
| `notify-send` / `gdbus` desktop alerts | `osascript display notification` (or `terminal-notifier` when installed) |
| conntrack **netlink** flow events (`AF_NETLINK`/`NETLINK_NETFILTER`) | **polled** PF state table (`pfctl -s state`, diffed each second) — macOS has no netlink equivalent, so this is a reimplementation rather than a port. A flow that opens *and* closes inside one interval is missed |
| `ip6tables` for IPv6 blocking | PF rules cover both families, so no second backend. The zone-id/IPv4-mapped address normalization from that change does apply here |
| `/var/log/suricata/eve.json` | Homebrew's prefix, resolved at runtime (`/opt/homebrew/…` on Apple Silicon, `/usr/local/…` on Intel) |
| `wg` on `PATH` | `wg` by absolute Homebrew path — a Finder- or launchd-launched app does not inherit the shell `PATH` |
| polkit wording for elevation failures | osascript's `User canceled. (-128)`, which is what a dismissed admin dialog returns |
| `XDG_DATA_HOME` redirect in tests | `HOME` redirect, since `AppPaths` resolves Application Support from the user profile |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Scan/brute-force heuristics count **new inbound connections to ports this Mac is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing. The only outbound rule is the beacon detector, which requires a regular cadence to an uncommon port on a public IP.
- Public IP geolocation uses the free `ipwho.is` endpoint over **HTTPS**, falling back to `ip-api.com` (plain HTTP) only if that fails. Both are rate-limited and best-effort. Toggle lookups off in **Settings**, or set `"GeoLookupEnabled": false`; reverse DNS still runs.
- **Failed-logon detection** reads the unified log via `log stream` and needs no elevation. macOS redacts some message arguments as `<private>`, which can hide the peer address; when that happens the app says so under **Settings → Auth-log monitoring** rather than silently reporting nothing. Set `"AuthLogMonitorEnabled": false` to turn it off.
- **Closed-port scan detection** is off by default because it needs admin rights twice over: to add the PF log rule, and to run the privileged `tcpdump` that decodes `pflog0` (BPF devices are root-only). Enable it under **Settings → Closed-port scan detection** — a single password prompt installs the rule, creates `pflog0`, and starts the decoder, which writes `/var/log/networksentinel-probe.log` for the app to tail unprivileged. The rule appears on the **Firewall** tab as `NetworkSentinel-ProbeLog` and is removed with the toggle.
- **Critical threat alerts** post through `osascript`, so macOS attributes the banner to **Script Editor** rather than to Network Sentinel, and it obeys Script Editor's entry in **System Settings → Notifications**. Installing `terminal-notifier` (`brew install terminal-notifier`) is picked up automatically at startup and gives the notification its own identity. **Settings → Critical threat alerts** shows which channel is in use.
  - The rule is `pass in log proto tcp from any to any flags S/SA no state`, placed **last** in the anchor and deliberately **not** `quick`. macOS `pfctl` has no `match` keyword, so a log-only rule is impossible — but every managed block above it is `block drop … quick`, so blocked peers short-circuit and never reach it, and `no state` confines the pass to the SYN alone without adding a state entry. The behaviour change is limited to inbound TCP SYNs nothing else in your ruleset blocked. If you maintain your own PF rules, review that before enabling.
- Process names for other users’ sockets may show as `Kernel / unknown` without root; monitoring still works.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by PF.
- **Full Disk Access / Privacy**: `lsof` may warn about unreadable mounts (e.g. Time Machine SMB); that is normal and ignored.
- If the app ever exits unexpectedly, check `~/Library/Application Support/NetworkSentinel/logs/crash.log` — unhandled errors are logged there with a stack trace.

---

## Troubleshooting

| Problem | What to do |
|---------|------------|
| Password dialog cancelled | Click **Authorize firewall** again, or allow the dialog when blocking. |
| `.NET location: Not found` | Set `DOTNET_ROOT` / `PATH` to your .NET install, or use a self-contained publish. |
| Process names missing | Expected for protected / other users’ processes; monitoring still works. |
| PF rules not taking effect | Run **Authorize firewall** once so the anchor is hooked into `/etc/pf.conf`. Check `sudo pfctl -a com.networksentinel -s rules`. |
| `lsof` SMB warnings | Harmless; Time Machine / network volumes the process cannot stat. |
| Auth-log alerts never fire | Check **Settings → Auth-log monitoring**. If it reports addresses redacted as `<private>`, macOS is withholding the peer IP; an Apple logging profile that enables private data for `com.apple.sshd` restores it. |
| Closed-port detection stuck on "waiting for the PF probe log" | The privileged decoder isn't running. Toggle **Closed-port scan detection** off and on and allow the password prompt; verify with `sudo pfctl -a com.networksentinel -s rules` and `ls -l /var/log/networksentinel-probe.log`. |
| Critical alerts never appear in the desktop app | macOS delivers them as **Script Editor**; allow that app in **System Settings → Notifications** (and turn off Do Not Disturb / a Focus mode). `brew install terminal-notifier` switches to a channel with its own identity. |
| Critical alerts never appear in the web console | The browser needs permission — re-toggle **Settings → Critical threat alerts** and accept the prompt. If it says *blocked*, allow notifications for the site in your browser settings. Note that browsers only grant notification permission on `localhost` or over HTTPS. |
| Port shows `LISTEN` locally but the web console is unreachable from another machine | The process listening only proves the app is up. macOS Application Firewall or an upstream network firewall can still drop inbound traffic — allow the binary in **System Settings → Network → Firewall**. |

---

## License

Private project — all rights reserved unless you add a license file later.
