# Network Sentinel (macOS)

Native **macOS** desktop app for **live network monitoring**, **data-flow metering**, **remote peer tracking**, **break-in heuristics**, **signature detection**, **DNS hygiene**, and **host firewall configuration and enforcement** — with a modern dark Avalonia UI sharing a palette with the iOS app.

> **Host-based** intrusion detection and prevention. It detects on its own heuristics and, with Suricata attached (0.6.x), on signature/payload inspection — then enforces in the kernel via **PF**. It is not an inline network appliance: it protects the Mac it runs on, not a segment, and it does not sit in the forwarding path.

macOS port of [davidfweiser/NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) (Linux Avalonia / original Windows WPF). Platform layers use **`lsof`/`netstat`/`nettop`**, **PF (`pfctl`)** elevated via **osascript** or **sudo**, the **macOS unified log** (`log stream`), and **`~/Library/Application Support/NetworkSentinel`**. Version **0.7.13**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `lsof` (with `netstat` fallback) |
| **Live connections** | Process name, local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this Mac, reverse DNS, geo/ISP when public |
| **Activity chart** | Live ~5-minute chart of connection samples with **threat markers** and a current/peak legend |
| **Data flow charts** (0.7.0) | Live in/out throughput on one shared scale, this month's totals, and a **month of daily bars** (or twelve months) — see [Data-flow metering](#data-flow-metering-070) |
| **Poll interval** | Selectable in **Settings** (0.5 s – 10 s); doubles as the chart's sample rate |

### Data-flow metering (0.7.0)

The dashboard answers "how much data went in and out?" as well as "who is talking to this Mac?". Three cards, all fed by one meter, on **the GUI dashboard and the web console** (the console got them in 0.7.1):

| Card | What it shows |
|------|----------------|
| **Data flow** | Inbound and outbound throughput over the last ~10 minutes, drawn on **one shared zero-based scale** — two independently scaled lines would make a trickle of uploads look like a match for a saturated download |
| **This month** | Bytes in, bytes out, the total, and the daily average so far |
| **Monthly data in and out** | Paired bars per day for the current month, or per month for the last twelve |

The source is `netstat -ib` — the cumulative per-interface byte counters the kernel already maintains. No packet capture, no root, and one short-lived subprocess every 5 seconds. Each sample is diffed against the previous one, so the chart shows traffic rather than counter values.

Three details decide whether the numbers are right, and each is covered by a test:

- **One row per interface.** netstat prints an interface once per address it holds and repeats the same totals on every row; only the `<Link#n>` row is counted. Summing all of them would multiply a dual-stack interface's traffic by four or five.
- **Physical interfaces only.** A VPN's `utun` carries bytes that already crossed `en0`, encapsulated — counting both double-counts every tunnelled byte. Loopback is excluded for the same reason it is excluded everywhere else: it never leaves the machine.
- **Counters reset.** A reboot or an interface bounce restarts them at zero; a counter that moved backwards is treated as a fresh start and its current value is the delta.

Daily totals persist to `traffic-history.json` (400 days, enough for the twelve-month view), and so do the last raw counters — on the next launch the diff continues where it left off, so traffic that crossed the wire while the console was closed still counts. That first delta spans however long the app was shut, so it is added to the day's total but deliberately **not** charted as a rate: dividing hours of traffic by one 5-second interval would draw a spike that never happened and flatten every real reading after it. Turn the whole thing off in **Settings → Monitoring → Traffic metering**; the history is kept, just no longer updated.

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
- Dedicated **PF anchor** `com.networksentinel` — the only ruleset this app writes to
- Only *manages* rules of its own: auto-block, manual blocks and expiry never touch anything else. Since 0.7.3 the Firewall Config page also **shows the rest of the host firewall** — the pf ruleset, Apple's anchors and the Application Firewall — but nothing automatic acts on a foreign rule
- Block rules are created as an `-In`/`-Out` pair and **removed together** in one click
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`), run through one prevention engine shared by all three front-ends — see [Auto-block](#auto-block)
- **Dry run** — decide and report what would be blocked without writing a single PF rule
- Settings in `~/Library/Application Support/NetworkSentinel/settings.json`
- **Authorize firewall** — elevates only `pfctl` via Mac admin password dialog. The GUI always runs as your user

### Firewall configuration (0.7.0, rebuilt in 0.7.3, listener actions in 0.7.4, front-end parity in 0.7.5)

**Firewall Config**, a submenu under **Firewall & Block**, is where rules are written by hand — add, edit and delete inbound and outbound rules, laid out the way the Linode Cloud Manager firewall page lays them out and the way [FireWallConfig](https://github.com/davidfweiser/FireWallConfig) does on Ubuntu: one list per direction, columns for **Label · Action · Protocol · Port range · Sources**, and one form that both creates and edits.

| Field | Accepts |
|-------|---------|
| **Preset** | SSH, HTTP, HTTPS, DNS, MySQL, PostgreSQL, WireGuard, the web console's ports, ICMP — or Custom |
| **Action** | `Allow` or `Block` |
| **Direction** | `Inbound` or `Outbound` |
| **Label** | `block-inbound-ssh`; left empty, it is **minted from the port's service name** |
| **Protocol** | TCP, UDP, ICMP, or Any |
| **Port range** | `22`, `8000-8001`, `80, 443` — empty means every port |
| **Sources** / **Destinations** | `All IPv4, All IPv6`, `10.0.0.0/8`, `203.0.113.5`, or a comma-separated mix |

Rules land in the same PF anchor and the same `firewall-rules.json` ledger as everything else the app blocks, so they survive a restart and are re-applied by the [startup reconciliation](#auto-block).

**Since 0.7.3 the page reads the whole host firewall, not just this app's ledger.** Until then it listed only rules Network Sentinel had written itself, which is a near-empty page beside the two firewalls macOS actually runs. One machine has one firewall; the page now shows all of it, named after the host:

| Source | Read with |
|---|---|
| **PF status and rules** | `pfctl -si`, `pfctl -sr` — whether PF is enabled, and every rule in the main ruleset |
| **PF anchors** | `pfctl -sA`, then `pfctl -a NAME -sr` for each — Apple's `com.apple/*` anchors, Internet Sharing, and our own |
| **PF without root** | `/etc/pf.conf` and `/etc/pf.anchors/*` — world-readable, and where `com.networksentinel` keeps our rules |
| **Application Firewall** | `socketfilterfw --getglobalstate`, `--getblockall`, `--listapps` — the per-app firewall from System Settings |
| **Listeners** | `lsof -nP -iTCP -sTCP:LISTEN` and `-iUDP`, falling back to `netstat -an` |

**Both firewalls, one list.** macOS runs two and they answer different questions: PF filters packets by address and port, while the Application Firewall decides which *binaries* may accept incoming connections. Reading only one leaves the other invisible. Loopback rules and the bare `pass all` every permissive ruleset opens with are folded out, so the list is rules somebody chose; everything else stays, each named in a **Created by** column — `macOS`, `AirDrop`, `Internet Sharing`, `Application Firewall`, `Network Sentinel` — so a foreign rule is never mistaken for one this app is responsible for.

**The reads never ask for your password.** `pfctl` needs root to open `/dev/pf`, but a firewall view that raises an admin dialog every refresh is a view nobody opens. So the scan runs as you, retries once under `sudo -n`, and otherwise falls back to `/etc/pf.conf` and `/etc/pf.anchors` — which still carries this app's own rules, because that is where they are written. The policy line says which of those happened, so a short list reads as a privilege problem rather than an empty firewall.

**Listening services.** Under the two rule lists, what is actually listening with the verdict the rules above pass on it: **Open** (reachable from anywhere), **Restricted** (admitted, but only from named addresses), **Local only** (bound to loopback), **Not allowed** (listening into a closed door), **No firewall**. A rule list on its own does not answer "is this port reachable"; the two together do. Note that unprivileged `lsof` only sees your own processes — another reason the privilege line matters.

**Since 0.7.4, each listener row carries a New rule button**, in the GUI and the web console, which opens the editor above with that socket's protocol and port already in it — the alternative is reading the port off `lsof` in a terminal and retyping it, which is how ports go into a rule set wrong. **Sources is deliberately left empty**: it matches the remote end of a connection, so seeding it with the socket's own bind address (`0.0.0.0`, `::`, this Mac's LAN address) would write a rule that matches nothing an attacker sends. A row whose port is not a plain number has nothing to prefill and says so rather than opening a form with an unparseable port in it. The editor sits above the lists, so opening it from a row near the bottom of a scrolled page scrolls it into view — otherwise the button reads as one that did nothing.

**The list survives a firewall it cannot read** (0.7.4). Listeners come from `lsof`, which reports your own sockets with no elevation at all, but the scan used to throw them away whenever neither PF nor the Application Firewall returned any state — emptying the table on exactly the Macs where it matters most: an unprivileged run, or a Mac with PF off and the Application Firewall never switched on. The verdict column reads **No firewall** there, which is the answer.

**Both front-ends say the same thing (0.7.5).** The desktop window and the web console build the same three lines from the same fields, in the same order — summary, listening sockets, policy. The desktop gained the *Scanned HH:mm:ss, not live* stamp the console had, so a page read an hour ago says so rather than passing for current; the console gained the listening-socket count and how many of them are reachable from anywhere, which the desktop had; and the console's policy paragraph moved below the summary, where the desktop keeps it. The sentence describing what the listener table is, is now one sentence written once and shown in both. Since 0.7.12 the console's page is also *shaped* like the desktop's rather than only worded like it — see [Layout](#layout-073).

**Nothing is cut off (0.7.5).** The Firewall Config grids were the only ones in the app not trimming their cells, so a long rule label or an IPv6 range stopped mid-value with no ellipsis and no way to read the rest. Every cell trims now, and the columns whose values are routinely wider than any sensible column — label, addresses, created-by, process, bind address — carry the full value as a tooltip. Label and addresses share the leftover width rather than one of them being pinned narrow. The action column sizes to its two buttons instead of the 150px it was pinned at, which had been slicing the rounded edge off **Delete**; and the rail title wraps rather than reading "Network Sentine".

> The app's own probe-log rule is `pass in log … no state`, which matches every TCP port in order to see SYNs to closed ones. It is listed as **Log** rather than Allow, and it is not counted as an admission — otherwise turning closed-port scan detection on would mark every port on the Mac "Open".

**Writes still go into our own anchor**, which is the only ruleset this app owns. `/etc/pf.conf` and the Apple anchors are loaded whole, so a line written into one would be undone by the next reload. Deleting works on rows this app wrote and on **Application Firewall** entries (`socketfilterfw --remove`, a supported per-app operation); a pf rule belonging to `pf.conf` or an Apple anchor is refused with the reason, because pf has no rule handle to delete by and a reload would restore it anyway. Editing a foreign rule deletes it where it lives and rewrites it — PF has no in-place edit — and if the delete fails the save stops rather than leaving both rules in force.

**Rules this app writes carry their ledger name as a PF `label`**, which is how a rescan tells them apart from the
rest of the host's. It has to be the label rather than the `# name` comment above the rule: `pfctl` keeps labels and
drops comments, so the comment is for whoever reads the anchor file and the label is the identity that survives into
the kernel — without it, Delete and Edit on those rows would have nothing to act on.

**The scan is cached.** The web console polls `/api/state` every 2.5 s, and shelling out to `pfctl`, `socketfilterfw` and `lsof` that often would be absurd; the **Rescan the host firewall** button forces a fresh read, and any write invalidates the cache.

**What the view is careful to say.** The page states the **real** default policies it read off the machine and words the consequence to match. macOS PF passes anything no rule matches, so on a stock Mac an **Allow** rule opens a path *through the rules above it* rather than granting access on its own; where a catch-all block or the Application Firewall's block-all is in force, it says instead that a service is only reachable if a rule admits it.

**Precedence is fixed, not incidental.** Every rule is written `quick`, so the anchor is first-match-wins. Blocks minted by auto-block and the Firewall page are emitted **first**, then config rules in list order. A config *Allow* rule therefore cannot reopen an address auto-block just shut — which is exactly what would happen if ledger insertion order decided precedence.

**Two rules get a confirmation before they load**: one that blocks every address on every port in a direction, and one that blocks inbound SSH. Both are legitimate; both can end your access to the machine while you are using it. A rule PF refuses to load is rolled back out of the ledger rather than left there claiming to be in force.

Rules created *by the app* (auto-block, manual blocks, the probe-log rule) are listed too, labelled in a **Created by** column, and can be deleted from here — deleting an auto-block rule suppresses re-blocking for 24 hours, exactly as releasing it on the Firewall page does. They cannot be *edited* here: rewriting one as a config rule would change what it matches.

### Known-good allowlist (never block)
Trusted sites are protected so auto-block (and manual block) will not cut off everyday tools:

| Source | Location |
|--------|----------|
| **Built-in defaults** | `Data/allowlist-default.json` (GitHub, xAI/Grok, Microsoft, Google, Cloudflare DNS, NuGet, …) |
| **Your additions** | `~/Library/Application Support/NetworkSentinel/allowlist.json` |
| **Remote feed** | Optional refresh from the upstream repo’s `allowlist-default.json` on GitHub |

---

## Requirements

- **macOS 12+ only** (Apple Silicon or Intel). There is no Linux or Windows build here: the monitor reads this Mac's sockets with `lsof` and PF's state table, and the firewall is `pfctl` and the `com.networksentinel` anchor — none of which another OS has, so no privilege level there could apply a rule. The Linux and Windows firewalls are driven by the separate ports of this app. Since 0.7.9 the console modes say that and refuse to start rather than asking to be elevated, and the GUI carries the same sentence into the window
- [.NET 8 SDK or runtime](https://dotnet.microsoft.com/download) (or use a self-contained publish)
- Avalonia desktop dependencies (bundled with the runtime on macOS)
- Admin rights (password dialog) for PF firewall changes — except from the web console, which cannot raise one: see [Firewall elevation on a headless Mac](#firewall-elevation-on-a-headless-mac)
- **Text size (0.7.13).** Every size in the GUI is an absolute device-independent pixel. macOS already draws those against the display's backing scale, so 100% is right on most Macs and is the default here — the Linux build ships 1.75 because an X11 session on an unscaled 4K panel does not scale at all. The knob is still the one way to make the whole window bigger: **Settings → Display → Text size** offers six steps up to 250%, applies straight away, and persists as `UiScale` in `settings.json`, clamped to 1.0–2.5 on read. The window is drawn through a `LayoutTransformControl`, which scales during layout rather than at paint, so wrapping, trimming and the table columns all stay correct — the window gets bigger rather than clipped. GUI only: the TUI is sized by the terminal and the web console by the browser
- No `which` binary is needed: `sudo`, `osascript` and `pfctl` are resolved in-process against `PATH` plus `/usr/local/sbin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin` — a GUI launched from Finder inherits a minimal `PATH`, and a launchd job's is narrower still
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
| `1`–`8` / `Tab` | Dashboard · Connections · Hosts · Threats · Ports · Firewall · Allowlist · **Settings** |
| `↑` `↓` / `j` `k` | Move selection |
| `/` or `f` | Filter |
| `p` | Pause / resume monitoring |
| `a` | Toggle auto-block |
| `m` | Cycle auto-block minimum severity |
| `b` / `x` | Block / unblock selected IP (or prompt) |
| `n` / `+` | **Add domain or IP to allowlist** (never block) |
| `d` | Remove selected allowlist Domain/IP (on Allowlist view) |
| `g` | Restore good sites (unblock allowlisted IPs) |
| `u` | Authorize firewall elevation (admin password) — **also unlocks Settings** |
| `Enter` | On **Settings**: flip a toggle, cycle a choice, or edit a value |
| `c` | Clear threat alerts |
| `r` | Refresh firewall · on Allowlist: refresh DNS/feed |
| `h` / `F1` | Help |
| `q` | Quit |

#### Settings from the terminal (0.7.8)

The TUI could watch and block but not configure: every setting meant reaching for
the desktop window or the web console, neither of which exists on a headless Mac
you only ever meet over SSH. **Settings** is the eighth view, and it carries the
same catalogue the web console's Settings tab does — monitoring and poll interval,
every detector and its thresholds, auto-block and its severity, direction, dry run
and rule expiry, the webhook, and the whole remote-access group: HTTPS, port, TLS
paths, redirect, HTTPS-only, DuckDNS, and Let's Encrypt issuance.

**It is locked until you authorize.** The screen shows nothing — not even current
values — until firewall elevation has been authorized this session with `u`, or the
TUI is already running as root. One password, not two: the same authorization that
lets the firewall be written unlocks the screen, because a settings page left open
on an unattended terminal is the same exposure as a firewall left writable.

**Enter is the only edit key.** It flips a toggle and cycles a choice in place;
anything that has to be typed opens a prompt below the display, seeded with the
current value. In that prompt **Enter alone keeps the value and `-` clears it** —
on a terminal, a stray Return must not silently empty a webhook URL. A rejected
value (a port out of range, a certificate path that does not exist) is reported in
the footer and **nothing is written**, so a bad entry cannot leave the file half
changed.

Each change is pushed into the running service *and* saved, the way the web console
applies them, so a detector switched on here starts working without a restart. The
file is the same `settings.json` the desktop and web console read — but a console
already running in another process keeps its in-memory copy until it restarts.

### Headless web console

Runs the same monitor and firewall engine with a browser front-end instead of the Avalonia GUI — useful over SSH or on a Mac with no logged-in desktop session.

```bash
dotnet run -c Release -- -w          # auto-picks a free high port (prefers 18765)
dotnet run -c Release -- -w 18765    # explicit port
# or:  NETWORKSENTINEL_WEB=1 ./NetworkSentinel
```

#### Layout (0.7.3)

The console is laid out like the desktop window, because they are the same product and the menus should not be a
different shape in each: a **230 px navigation rail** on the left carrying the desktop's menu names and hierarchy —
Firewall Config and Allowlist indented under **Firewall & Block**, Help under **Settings** — with a **STATUS** block
pinned to its foot (monitor state, firewall privilege, and the **Enable auto-block** checkbox with the engine's own
wording under it). To the right, the same hero header the desktop carries: clock, **Network Defense Console**, the
`high/critical · blocked · auto-block` subtitle built from the same three numbers, and the action row. Below ~900 px
the rail folds into a wrapping row above the content.

**And drawn like it too (0.7.12).** Matching the shape left the two still looking
unrelated, so the console's styling is now taken from the values in the desktop's
`Themes/Controls.axaml` and `Themes/Colors.axaml` — the 18 px card radius and padding,
the danger gradient's two stops — rather than approximated by eye. They are still two
stylesheets in two languages and can drift if only one is edited; the point is that
where they agree today, they agree on a number someone can look up. Rail entries draw
the ring and dot of the RadioButton they have always been, with the selected one
filled. A list is a card carrying its name, a line of context under it, and that
section's action on the right of the same row — so **Add an Inbound Rule** sits on the
list it adds to instead of in a strip above everything. Column headers are sentence
case as the grid draws them, not uppercase; the zebra banding is gone for the flat card
and horizontal rules the desktop uses; and row buttons are the desktop's mini-ghost and
mini-danger, which makes **Delete** the solid danger gradient rather than an outline.

**The dashboard boxes the desktop had (0.7.7).** Two panels the desktop window carried
and the console did not: **Threat intensity**, the high/critical count on its own beside
the activity chart, and **This month**, the running month's data in and out beside the
data-flow chart. Neither needed a new API field — the console was already sending all
five month values and spending them on the footer sentence under the chart, which is
too long to read at a glance. The console's pulse reads **IDLE** rather than LIVE while
asleep, because the count beneath it is then the last one measured rather than a live
one; the desktop has no sleep mode and so no equivalent. With metering off the month box
shows em dashes rather than zeros, because nothing was measured. The monthly bar chart,
which the console already drew unlabelled, gained the desktop's **Monthly data in and
out** heading above its range dropdown. Below 900 px each pair stacks instead of
splitting the width between two unreadable columns.

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers) beside **Threat intensity**, **data-flow charts** (0.7.1) beside the running month's totals, **Monthly data in and out**, monitoring/firewall status, recent threats |
| **Live Connections / Break-in Attempts** | Live traffic with a **Block** button on every row |
| **Remote Computers** | Remote peers; block / unblock by row or by typed IP |
| **Open Ports** | Local listeners; one-click **Block port** |
| **Firewall & Block** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Firewall Config** (0.7.1, rebuilt 0.7.3) | The whole host firewall — the pf ruleset, Apple's anchors, the Application Firewall and Network Sentinel's own rules — plus listening services and their firewall verdict; add / edit / delete, and (0.7.4) **New rule** on a listener row to start one prefilled from that socket. Since 0.7.5 it says the same three lines the desktop page does |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, poll interval, geo lookups, auth-log monitoring, closed-port scan detection, critical threat alerts, **Suricata alerts**, **WireGuard peer watch**, **PF flow events**, **DNS hygiene**, **HTTPS + DuckDNS remote access** (incl. one-click **Issue certificate**), auto-block + minimum severity + **dry run**, block direction, allowlist feed, **change master password**, **Remove all rules** |

The navigation rail shows the running version (e.g. `v0.7.13`) — check it after an upgrade to confirm the new build
is live. Since 0.7.2 the console notices this for you: a tab left open across an upgrade shows a banner naming both
versions and offering a reload, because the page polls `/api/state` but never re-requests its own HTML, so the old UI
would otherwise stay put and look like the upgrade never installed. It never reloads on its own — you may be
mid-rule in the Firewall Config form.

#### Sleep / Wake

The first button in the web console's hero action row is a single **Sleep ⇄ Wake** toggle:

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

Once HTTPS works, **Settings → Remote access → HTTPS only** (0.7.6) turns the plain-HTTP listener off entirely, so the master password can never cross the wire in the clear — the strongest setting for a console reachable beyond localhost, and the one that closes the bare-IP gap above, since there is no HTTP listener left to hit. Bare-IP visits then get a certificate warning but still connect encrypted. The switch is deliberately fail-open: it is honored only when the certificate actually loads at startup, so a broken or expired cert means the console falls back to plain HTTP (with a warning in the banner and on the settings page) instead of leaving you locked out.

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

283 xunit tests covering the pure-logic seams the enforcement path depends on: IP normalization (port stripping, zone ids, IPv4-mapped collapse), the non-public/CGNAT range boundaries, atomic writes under concurrent writers, the prevention gate stack (driven end to end in dry-run mode, so no rule is ever written), `pfctl -s state` and `wg show` parsing, the host firewall scan (fixtures are real `pfctl -nvf`, `socketfilterfw` and `lsof` output, so they carry pfctl's own rewrites), Suricata EVE alerts, and DNS hygiene detections.

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
tar xzf networksentinel-0.7.13-osx-arm64.tar.gz
cd networksentinel-0.7.13-osx-arm64
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

### Firewall elevation on a headless Mac

The macOS admin dialog is drawn by the window server on the Mac running the process.
That is fine for the desktop app and for the TUI, which can fall back to sudo's own
prompt on its TTY — and useless for the **web console**, where the operator is in a
browser somewhere else. A browser cannot answer a dialog raised on the host, so
*asking* is off the table entirely: the console has to already hold the right to
write.

From 0.7.10 it says so before the form rather than at the save. Firewall Config
carries a **Read-only** notice with the fix already written out for this host, and
Add / Edit / Delete are disabled while it is showing. Apply a fix, then press
**Rescan the host firewall** (or **Authorize firewall**, which on the web console
re-checks rather than prompting) and the notice clears.

Two ways to give it the right, in the order the notice offers them:

```bash
# 1. Run the console itself as root
sudo ./NetworkSentinel --web

# 2. Or keep it running as this user, with passwordless sudo
echo 'YOUR_USER ALL=(root) NOPASSWD: /bin/bash' | sudo tee /etc/sudoers.d/networksentinel
sudo chmod 0440 /etc/sudoers.d/networksentinel
sudo visudo -c
```

**The second is a root shell in all but name,** and the notice says so rather than
passing it off as scoped to the firewall. PF rules here are applied by generating a
ruleset and running it as a script, so the grant has to name `/bin/bash`; there is no
equivalent of the Linux port's line naming `nft` and `ufw`, and no `CAP_NET_ADMIN` to
hold instead. On a shared Mac, run the console as root.

Either route is also what lets **auto-block expiry** run. Timed blocks are swept by a
background timer that will not raise a password dialog in anyone's face, so it only
sweeps when the rule can be removed without asking. That probe is cached from 0.7.10,
because a refused `sudo -n` is written to the very log this app watches for break-in
attempts and a probe per snapshot would have Network Sentinel reporting on itself;
**Rescan** and **Authorize firewall** clear the cache, so a grant written a moment ago
is seen at once.

---

## Using the app

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Stats, activity chart, **data-flow and monthly in/out charts**, latest threats, observed hosts |
| **Live Connections** | Active TCP sessions; block remote IP per row |
| **Remote Computers** | Tracked peers, origin, threat level; block / unblock |
| **Break-in Attempts** | Heuristic alerts with origin and method |
| **Open Ports** | Listening TCP/UDP; optional inbound port block |
| **Firewall & Block** | Manual IP/port rules, auto-block, allowlist, managed rule list |
| **Firewall Config** | Add / edit / delete inbound and outbound rules — Linode-style lists per direction |
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
| **HTTPS only (turn off plain HTTP)** | Off by default (0.7.6). Needs HTTPS on with a working certificate; takes effect the next time the web console starts |

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
                                            ▲                         ▲
                                            │                         │
                      ┌─────────────────────┴──────┐   ┌──────────────┴─────────────┐
                      │ TrafficMeterService        │   │ Firewall Config rules      │
                      │ netstat -ib → rates +      │   │ (label · action · proto ·  │
                      │ daily in/out history       │   │  ports · addresses) → PF   │
                      └────────────────────────────┘   └────────────────────────────┘
```

The meter runs on its own 5-second cadence rather than the monitor's poll: the byte counters are cumulative, so consistent spacing is what makes the deltas comparable, and metering continues while monitoring is paused.

---

## Project layout

| Path | Role |
|------|------|
| `Native/MacNetTable.cs` | `lsof` / `netstat` parsing + PID mapping |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | PF via pfctl + osascript; rule ledger; PF probe-log rule; config-rule save/delete |
| `Services/FirewallRuleSpec.cs` | The Firewall Config rule: port/address parsing, validation, PF rendering |
| `Services/TrafficMeterService.cs` | `netstat -ib` byte counters → live rates + a persisted daily in/out history |
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
| `Tests/NetworkSentinel.Tests/` | xunit suite (235 tests); `TestEnv` redirects `HOME` so nothing touches the real profile |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring, Settings view (incl. Remote access) |
| `ViewModels/MainViewModel.FirewallConfig.cs` | Firewall Config view: rule lists, the add/edit form, impact confirmations |
| `ViewModels/MainViewModel.Traffic.cs` | Dashboard data-flow charts and month totals |
| `Controls/Sparkline.cs` / `Controls/TrafficChart.cs` | Connection-activity chart; dual in/out line and paired-bar charts |
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
- Public IP geolocation uses the free `ipwho.is` endpoint, falling back to `ipapi.co` only if that fails — **both over HTTPS**, so the peer IPs this app observes never cross the wire in cleartext (the fallback was previously plain-HTTP `ip-api.com`). Both are rate-limited and best-effort. Toggle lookups off in **Settings**, or set `"GeoLookupEnabled": false`; reverse DNS still runs.
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
| **The web console says Firewall Config is read-only** | It is: the admin dialog would open on the Mac running the console, not in your browser. The notice carries the two fixes for this host — see [Firewall elevation on a headless Mac](#firewall-elevation-on-a-headless-mac). Before 0.7.10 the console drew the editor anyway, accepted a rule, and then held the request for five minutes waiting on a dialog nobody could see. |
| **A rule cannot be deleted: "Several rules have exactly that shape"** | Fixed in 0.7.9. Two rules of the same shape — which is what you end up with after a delete appears to fail and you add it again — matched either row's key, so the lookup refused both and neither could be deleted or edited afterwards. The identity now carries the rule's name and anchor as well, and rows nothing could tell apart are taken first rather than refused. |
| **"No rule named X" for a rule that is already gone** | One managed rule can hold several rows in the scan — an inbound rule and the outbound sibling written with it — and removing any one row takes them all. A click on a sibling row therefore arrives after the rule has gone, which is what was asked for. Since 0.7.9 the message says that rather than reading as delete being broken. |
| **Linux or Windows says it needs root / administrator privileges** | This is the macOS port — it reads this Mac's sockets and writes PF rules, none of which another OS has, so no privilege level there can apply a rule. Run it on a Mac, or use the Linux or Windows port. Since 0.7.9 it says that instead of asking to be elevated; `NETWORKSENTINEL_ALLOW_UNSUPPORTED_OS=1` starts the console modes anyway, though they cannot do anything useful. |
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
