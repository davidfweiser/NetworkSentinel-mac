using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NetworkSentinel.Models;
using NetworkSentinel.Services;

namespace NetworkSentinel.Tui;

/// <summary>How a setting is edited, which decides what Enter does on its row.</summary>
internal enum SettingKind
{
    /// <summary>Enter flips it immediately — no prompt, so a toggle costs one keystroke.</summary>
    Toggle,
    /// <summary>Enter opens a prompt seeded with the current value.</summary>
    Number,
    Text,
    /// <summary>Enter advances to the next value in <see cref="SettingItem.Choices"/>.</summary>
    Choice,
    /// <summary>Not a value at all — Enter runs something.</summary>
    Action
}

/// <summary>
/// Thrown by an Apply to reject a value. The message is shown in the footer and
/// nothing is written: a rejected setting must not leave the file half-changed.
/// </summary>
internal sealed class SettingRejectedException : Exception
{
    public SettingRejectedException(string message) : base(message) { }
}

/// <summary>One row of the Settings view.</summary>
internal sealed class SettingItem
{
    public string Section { get; init; } = "";
    public string Label { get; init; } = "";
    public string Description { get; init; } = "";
    public SettingKind Kind { get; init; } = SettingKind.Toggle;

    /// <summary>Current value as displayed. "on"/"off" for a toggle.</summary>
    public Func<string> Read { get; init; } = () => "";

    /// <summary>Applies a new value and returns the message to show. May throw
    /// <see cref="SettingRejectedException"/>.</summary>
    public Func<string, string> Apply { get; init; } = _ => "";

    /// <summary>Prompt hint for Number/Text, cycle order for Choice.</summary>
    public string[] Choices { get; init; } = Array.Empty<string>();
    public string Hint { get; init; } = "";

    public bool IsOn => Kind == SettingKind.Toggle && Read() == "on";
}

/// <summary>
/// The TUI's editable settings, in the order the web console's Settings tab lists
/// them, and applied the same way it applies them: each change is pushed into the
/// live service <em>and</em> saved, so a headless box does not have to be restarted
/// for a detector to come on.
///
/// This mirrors the web console rather than sharing code with it, deliberately —
/// the TUI is the front-end you reach over SSH when the others are unavailable, and
/// a settings screen that cannot be opened without the web console running would
/// defeat the point. The cost is that a setting added to the console must be added
/// here too; the catalogue is one list so that stays a one-line change.
///
/// Everything writes the same <c>settings.json</c> the desktop and web console read
/// (<see cref="AppPaths"/>), so a change made here is a change everywhere — though a
/// console already running in another process keeps its in-memory copy until it
/// restarts.
/// </summary>
internal sealed class TuiSettings
{
    private readonly AppSettings _settings;
    private readonly NetworkMonitorService _monitor;
    private readonly PreventionService _prevention;
    private readonly FirewallService _firewall;
    private readonly AllowlistService _allowlist;
    private readonly TrafficMeterService _traffic;

    /// <summary>Own instance, exactly as the desktop view-model keeps one: DuckDNS
    /// lives in its own 0600 file next to the settings, not in AppSettings.</summary>
    private readonly DuckDnsUpdater _duckDns = new();

    public TuiSettings(SentinelCore core)
    {
        _settings = core.Settings;
        _monitor = core.Monitor;
        _prevention = core.Prevention;
        _firewall = core.Firewall;
        _allowlist = core.Allowlist;
        _traffic = core.Traffic;
        Items = BuildCatalogue();
    }

    public IReadOnlyList<SettingItem> Items { get; }

    public string DuckDnsStatus => _duckDns.Status;

    /// <summary>Domain and token, for the certificate-issuance action.</summary>
    public (string Domain, string Token, string Email) AcmeInputs
        => (_duckDns.Config.Domain, _duckDns.Config.Token, _settings.AcmeAccountEmail);

    private static string OnOff(bool on) => on ? "on" : "off";

    private SettingItem Toggle(string section, string label, string description, Func<bool> read, Func<bool, string> apply)
        => new()
        {
            Section = section,
            Label = label,
            Description = description,
            Kind = SettingKind.Toggle,
            Read = () => OnOff(read()),
            Apply = raw =>
            {
                var message = apply(raw == "on");
                _settings.Save();
                return message;
            }
        };

    private SettingItem Value(string section, string label, string description, SettingKind kind,
        Func<string> read, Func<string, string> apply, string hint = "")
        => new()
        {
            Section = section,
            Label = label,
            Description = description,
            Kind = kind,
            Hint = hint,
            Read = read,
            Apply = raw =>
            {
                var message = apply(raw.Trim());
                _settings.Save();
                return message;
            }
        };

    private static int RequireInt(string raw, int min, int max, string complaint)
        => int.TryParse(raw, out var n) && n >= min && n <= max
            ? n
            : throw new SettingRejectedException(complaint);

    private DuckDnsConfig CloneDuckDns() => new()
    {
        Enabled = _duckDns.Config.Enabled,
        Domain = _duckDns.Config.Domain,
        Token = _duckDns.Config.Token,
        IntervalMinutes = _duckDns.Config.IntervalMinutes
    };

    private List<SettingItem> BuildCatalogue()
    {
        const string monitoring = "Monitoring";
        const string detection = "Detection";
        const string autoBlock = "Auto-block";
        const string alerts = "Alerts";
        const string remote = "Remote access";

        return new List<SettingItem>
        {
            // ── Monitoring ────────────────────────────────────────────────────
            Value(monitoring, "Poll interval", "How often connections and ports are re-read, in milliseconds.",
                SettingKind.Number,
                () => $"{_settings.MonitorPollMs} ms",
                raw =>
                {
                    var ms = RequireInt(raw, 500, 60_000, "Poll interval must be between 500 and 60000 milliseconds.");
                    _monitor.PollIntervalMs = ms;
                    _settings.MonitorPollMs = ms;
                    return $"Poll interval: {ms} ms";
                }, "milliseconds, 500-60000"),

            Toggle(monitoring, "Geo lookups", "Country/city/ISP for public peers, over HTTPS. Reverse DNS runs either way.",
                () => _settings.GeoLookupEnabled,
                on =>
                {
                    _monitor.GeoLookupsEnabled = on;
                    _settings.GeoLookupEnabled = on;
                    return $"Geo lookups: {OnOff(on)}";
                }),

            Toggle(monitoring, "Traffic metering", "Interface byte counters behind the data-flow and monthly charts.",
                () => _settings.TrafficMeterEnabled,
                on =>
                {
                    _settings.TrafficMeterEnabled = on;
                    if (on) _traffic.Start(); else _traffic.Stop();
                    return $"Traffic metering: {OnOff(on)}";
                }),

            Toggle(monitoring, "Critical threat alerts", "Desktop notification when a critical threat is raised.",
                () => _settings.CriticalAlertsEnabled,
                on =>
                {
                    _settings.CriticalAlertsEnabled = on;
                    return $"Critical threat alerts: {OnOff(on)}";
                }),

            Toggle(monitoring, "Allowlist remote feed", "Pull the shared allowlist from GitHub as well as the local one.",
                () => _settings.AllowlistUseRemoteFeed,
                on =>
                {
                    _allowlist.UseRemoteFeed = on;
                    _settings.AllowlistUseRemoteFeed = on;
                    return $"Allowlist remote feed: {OnOff(on)}";
                }),

            // ── Detection ─────────────────────────────────────────────────────
            Toggle(detection, "Auth-log monitoring", "Failed SSH/sudo/login/Screen Sharing attempts read from the macOS unified log.",
                () => _settings.AuthLogMonitorEnabled,
                on =>
                {
                    _monitor.AuthMonitoringEnabled = on;
                    _settings.AuthLogMonitorEnabled = on;
                    return on ? $"Auth-log monitoring: on ({_monitor.AuthLogStatus})" : "Auth-log monitoring: off";
                }),

            Toggle(detection, "Closed-port scan detection",
                "Installs a PF SYN-log rule and decodes pflog0, so probes to closed ports are seen. Needs firewall elevation.",
                () => _settings.ProbeLogEnabled,
                on =>
                {
                    _settings.ProbeLogEnabled = on;
                    var fw = on ? _firewall.EnableProbeLogging() : _firewall.DisableProbeLogging();
                    _monitor.ProbeMonitoringEnabled = on && fw.Success;
                    return on
                        ? (fw.Success
                            ? "Closed-port scan detection: on (probe-log firewall rule installed)"
                            : $"Closed-port scan detection: could not install firewall rule — {fw.Message}")
                        : "Closed-port scan detection: off";
                }),

            Toggle(detection, "Threat-intel feeds", "Match remote addresses against public block lists.",
                () => _settings.ThreatIntelEnabled,
                on =>
                {
                    _monitor.ThreatIntelEnabled = on;
                    _settings.ThreatIntelEnabled = on;
                    return on ? $"Threat-intel feeds: on ({_monitor.ThreatIntelStatus})" : "Threat-intel feeds: off";
                }),

            Toggle(detection, "Process reputation", "Flag listening processes running from unusual paths.",
                () => _settings.ProcessReputationEnabled,
                on =>
                {
                    _monitor.ProcessReputationEnabled = on;
                    _settings.ProcessReputationEnabled = on;
                    return $"Process reputation checks: {OnOff(on)}";
                }),

            Toggle(detection, "New-listener alerts", "Raise a signal when a port starts listening that was not before.",
                () => _settings.NewListenerAlertsEnabled,
                on =>
                {
                    _monitor.NewListenerAlertsEnabled = on;
                    _settings.NewListenerAlertsEnabled = on;
                    return $"New-listener alerts: {OnOff(on)}";
                }),

            Toggle(detection, "ARP / gateway watch", "Notice the gateway's MAC changing under you.",
                () => _settings.ArpWatchEnabled,
                on =>
                {
                    _monitor.ArpWatchEnabled = on;
                    _settings.ArpWatchEnabled = on;
                    return on ? $"ARP / gateway watch: on ({_monitor.ArpWatchStatus})" : "ARP / gateway watch: off";
                }),

            Toggle(detection, "Launch-item watch", "Watch LaunchAgents and LaunchDaemons for new or modified startup items.",
                () => _settings.LaunchItemWatchEnabled,
                on =>
                {
                    _monitor.LaunchWatchEnabled = on;
                    _settings.LaunchItemWatchEnabled = on;
                    return on ? $"Launch-item watch: on ({_monitor.LaunchWatchStatus})" : "Launch-item watch: off";
                }),

            Toggle(detection, "Exfiltration monitor", "Alert on sustained outbound volume to one destination.",
                () => _settings.ExfilMonitorEnabled,
                on =>
                {
                    _monitor.ExfilMonitorEnabled = on;
                    _settings.ExfilMonitorEnabled = on;
                    return on ? $"Exfiltration monitor: on ({_monitor.ExfilStatus})" : "Exfiltration monitor: off";
                }),

            Value(detection, "Exfiltration threshold", "Megabytes to one destination per 10 minutes before it is reported.",
                SettingKind.Number,
                () => $"{_settings.ExfilMbPer10Min} MB / 10 min",
                raw =>
                {
                    var mb = RequireInt(raw, 10, int.MaxValue,
                        "Exfiltration threshold must be a number of megabytes, 10 or more.");
                    _monitor.ExfilThresholdMb = mb;
                    _settings.ExfilMbPer10Min = mb;
                    return $"Exfiltration alert threshold: {mb} MB / 10 min";
                }, "MB per 10 minutes, 10 or more"),

            Toggle(detection, "PF flow events", "Read PF's state table for flow events — UDP, and traffic this Mac forwards. Needs PF enabled and root.",
                () => _settings.FlowEventsEnabled,
                on =>
                {
                    _monitor.FlowEventsEnabled = on;
                    _settings.FlowEventsEnabled = on;
                    return on ? $"Flow events: on ({_monitor.FlowEventsStatus})" : "Flow events: off — timed polling only";
                }),

            Toggle(detection, "DNS hygiene", "Plaintext DNS egress, unapproved resolvers, and encrypted DNS falling back.",
                () => _settings.DnsHygieneEnabled,
                on =>
                {
                    _monitor.DnsHygieneEnabled = on;
                    _settings.DnsHygieneEnabled = on;
                    return on ? $"DNS hygiene: on ({_monitor.DnsHygieneStatus})" : "DNS hygiene monitoring: off";
                }),

            Value(detection, "Approved resolvers", "Resolver IPs that count as yours. DoH is only recognised toward these.",
                SettingKind.Text,
                () => _settings.DnsApprovedResolvers.Length == 0 ? "(none)" : _settings.DnsApprovedResolvers,
                raw =>
                {
                    var parsed = DnsHygieneMonitor.ParseResolvers(raw);
                    if (raw.Length > 0 && parsed.Count == 0)
                        throw new SettingRejectedException(
                            "Enter resolver IP addresses separated by commas, e.g. 10.8.0.1, 127.0.0.53.");
                    var normalised = string.Join(",", parsed);
                    _monitor.DnsApprovedResolvers = normalised;
                    _settings.DnsApprovedResolvers = normalised;
                    return parsed.Count == 0
                        ? "No approved resolvers set — every plaintext query is reported, and DoH cannot be recognised."
                        : $"Approved resolvers: {normalised}";
                }, "comma-separated IPs, empty to clear"),

            Toggle(detection, "WireGuard peer monitoring", "Per-peer handshake and transfer accounting.",
                () => _settings.WireGuardMonitorEnabled,
                on =>
                {
                    _monitor.WireGuardMonitorEnabled = on;
                    _settings.WireGuardMonitorEnabled = on;
                    return on ? $"WireGuard peers: on ({_monitor.WireGuardStatus})" : "WireGuard peer monitoring: off";
                }),

            Value(detection, "Per-peer transfer alert", "Megabytes per peer per 10 minutes. 0 turns the alert off.",
                SettingKind.Number,
                () => _settings.WireGuardPeerMbPer10Min == 0 ? "off" : $"{_settings.WireGuardPeerMbPer10Min} MB / 10 min",
                raw =>
                {
                    var mb = RequireInt(raw, 0, int.MaxValue, "Enter 0 to disable, or a positive number of megabytes.");
                    _monitor.WireGuardPeerMbPer10Min = mb;
                    _settings.WireGuardPeerMbPer10Min = mb;
                    return mb == 0 ? "Per-peer transfer alerts off" : $"Per-peer transfer alert threshold: {mb} MB / 10 min";
                }, "MB per 10 minutes, 0 to disable"),

            Toggle(detection, "Suricata ingestion", "Read Suricata's EVE JSON and raise its alerts as threats.",
                () => _settings.SuricataEnabled,
                on =>
                {
                    _monitor.SuricataEnabled = on;
                    _settings.SuricataEnabled = on;
                    return on ? $"Suricata ingestion: on ({_monitor.SuricataStatus})" : "Suricata ingestion: off";
                }),

            Value(detection, "Suricata EVE path", "Absolute path to eve.json.", SettingKind.Text,
                () => _settings.SuricataEvePath.Length == 0 ? SuricataService.DefaultEvePath : _settings.SuricataEvePath,
                raw =>
                {
                    var path = string.IsNullOrWhiteSpace(raw) ? SuricataService.DefaultEvePath : raw;
                    if (!path.StartsWith('/'))
                        throw new SettingRejectedException("Enter an absolute path to Suricata's eve.json.");
                    _monitor.SuricataEvePath = path;
                    _settings.SuricataEvePath = path;
                    return _settings.SuricataEnabled
                        ? _monitor.SuricataStatus
                        : $"EVE path saved ({path}) — enable Suricata ingestion to read it.";
                }, "absolute path, empty for the default"),

            Value(detection, "Suricata max severity", "Suricata counts down: 1 is most severe. Alerts above this number are ignored.",
                SettingKind.Number,
                () => _settings.SuricataMaxSeverity.ToString(),
                raw =>
                {
                    var sev = RequireInt(raw, 1, 4,
                        "Suricata severity must be 1-4 (Suricata counts down: 1 is most severe).");
                    _monitor.SuricataMaxSeverity = sev;
                    _settings.SuricataMaxSeverity = sev;
                    return $"Accepting Suricata alerts of severity {sev} or lower-numbered";
                }, "1-4"),

            Value(detection, "Muted Suricata signatures", "Signature IDs to ignore, comma separated.", SettingKind.Text,
                () => _settings.SuricataIgnoredSids.Length == 0 ? "(none)" : _settings.SuricataIgnoredSids,
                raw =>
                {
                    _monitor.SuricataIgnoredSids = raw;
                    _settings.SuricataIgnoredSids = raw;
                    return raw.Length == 0 ? "No Suricata signatures muted" : $"Muted Suricata signatures: {raw}";
                }, "comma-separated sids, empty to clear"),

            Toggle(detection, "Honeypot", "Open decoy ports; anything that connects has no business there.",
                () => _settings.HoneypotEnabled,
                on =>
                {
                    _monitor.HoneypotPorts = HoneypotService.ParsePorts(_settings.HoneypotPorts);
                    _monitor.HoneypotEnabled = on;
                    _settings.HoneypotEnabled = on;
                    return on ? _monitor.HoneypotStatus : "Honeypot: off";
                }),

            Value(detection, "Decoy ports", "Ports the honeypot listens on.", SettingKind.Text,
                () => _settings.HoneypotPorts,
                raw =>
                {
                    var ports = HoneypotService.ParsePorts(raw);
                    if (ports.Count == 0)
                        throw new SettingRejectedException("Enter decoy ports as a comma-separated list, e.g. 2323,3389,5900.");
                    _settings.HoneypotPorts = string.Join(",", ports);
                    _monitor.HoneypotPorts = ports;
                    return _settings.HoneypotEnabled
                        ? _monitor.HoneypotStatus
                        : $"Decoy ports saved ({_settings.HoneypotPorts}) — enable the honeypot to arm them.";
                }, "e.g. 2323,3389,5900"),

            // ── Auto-block ────────────────────────────────────────────────────
            Toggle(autoBlock, "Auto-block", "Write firewall rules for threats that clear every gate.",
                () => _settings.AutoBlockEnabled,
                on =>
                {
                    _prevention.Enabled = on;
                    _settings.AutoBlockEnabled = on;
                    return _prevention.Describe();
                }),

            new SettingItem
            {
                Section = autoBlock,
                Label = "Minimum severity",
                Description = "The lowest threat level that may trigger a block. Below High is a wider net than the default.",
                Kind = SettingKind.Choice,
                Choices = new[] { "Low", "Medium", "High", "Critical" },
                Read = () => _settings.GetMinLevel().ToString(),
                Apply = raw =>
                {
                    if (!Enum.TryParse<ThreatLevel>(raw, true, out var level))
                        throw new SettingRejectedException($"Unknown severity: {raw}");
                    _prevention.MinLevel = level;
                    _settings.SetMinLevel(level);
                    _settings.Save();
                    return _prevention.Describe();
                }
            },

            Toggle(autoBlock, "Block inbound", "Auto-block writes an inbound rule.",
                () => _settings.AutoBlockInbound,
                on =>
                {
                    _prevention.BlockInbound = on;
                    _settings.AutoBlockInbound = on;
                    return $"Block inbound: {OnOff(on)}";
                }),

            Toggle(autoBlock, "Block outbound", "Auto-block writes an outbound rule. Can cut this host's own connections.",
                () => _settings.AutoBlockOutbound,
                on =>
                {
                    _prevention.BlockOutbound = on;
                    _settings.AutoBlockOutbound = on;
                    return $"Block outbound: {OnOff(on)}";
                }),

            Toggle(autoBlock, "Dry run", "Decide and report, but write no firewall rules.",
                () => _settings.PreventionDryRun,
                on =>
                {
                    _prevention.DryRun = on;
                    _settings.PreventionDryRun = on;
                    return on
                        ? "Dry run ON — auto-block will report what it would drop, without writing rules"
                        : "Dry run OFF — auto-block writes firewall rules";
                }),

            Value(autoBlock, "Rule expiry", "Minutes before an auto-created rule is removed. 0 keeps it until you remove it.",
                SettingKind.Number,
                () => _settings.AutoBlockExpiryMinutes == 0 ? "never" : $"{_settings.AutoBlockExpiryMinutes} min",
                raw =>
                {
                    var minutes = RequireInt(raw, 0, int.MaxValue, "Enter 0 for permanent, or a positive number of minutes.");
                    _settings.AutoBlockExpiryMinutes = minutes;
                    _firewall.AutoBlockExpiry = minutes > 0 ? TimeSpan.FromMinutes(minutes) : null;
                    return minutes == 0
                        ? "Auto-block rules are permanent until removed."
                        : $"New auto-block rules expire after {minutes} minutes.";
                }, "minutes, 0 for permanent"),

            // ── Alerts ────────────────────────────────────────────────────────
            Value(alerts, "Webhook URL", "Critical threats are POSTed here. Empty turns it off.", SettingKind.Text,
                () => _settings.WebhookUrl.Length == 0 ? "(off)" : _settings.WebhookUrl,
                raw =>
                {
                    _monitor.WebhookUrl = raw;
                    _settings.WebhookUrl = raw;
                    return raw.Length == 0
                        ? "Webhook alerts: off"
                        : $"Webhook alerts: Critical threats will POST to {raw}";
                }, "URL, empty to turn off"),

            // ── Remote access ─────────────────────────────────────────────────
            // Kestrel binds at startup, so these are saved here and take effect when
            // the web console restarts. Said in each message rather than assumed.
            Toggle(remote, "HTTPS", "Serve the web console over TLS. Takes effect when the web console restarts.",
                () => _settings.WebHttpsEnabled,
                on =>
                {
                    if (on && string.IsNullOrWhiteSpace(_settings.WebTlsCertPath))
                        throw new SettingRejectedException(
                            "Set the certificate path first — see scripts/issue-duckdns-cert.sh for a Let's Encrypt certificate.");
                    _settings.WebHttpsEnabled = on;
                    return on
                        ? $"HTTPS enabled on port {_settings.WebHttpsPort} — restart the web console to apply."
                        : "HTTPS disabled — restart the web console to apply.";
                }),

            Value(remote, "HTTPS port", "TLS port for the web console.", SettingKind.Number,
                () => _settings.WebHttpsPort.ToString(),
                raw =>
                {
                    var port = RequireInt(raw, 1, 65535, "HTTPS port must be between 1 and 65535.");
                    _settings.WebHttpsPort = port;
                    return $"HTTPS port set to {port} — restart the web console to apply.";
                }, "1-65535"),

            Value(remote, "Certificate path", "PEM or PFX the console serves. Validated now, so a bad path is not found at restart.",
                SettingKind.Text,
                () => _settings.WebTlsCertPath.Length == 0 ? "(not set)" : _settings.WebTlsCertPath,
                raw => ApplyTlsPath(certPath: true, raw), "absolute path, empty to clear"),

            Value(remote, "Private key path", "Key for a PEM certificate. Leave empty for a PFX.", SettingKind.Text,
                () => _settings.WebTlsKeyPath.Length == 0 ? "(not set)" : _settings.WebTlsKeyPath,
                raw => ApplyTlsPath(certPath: false, raw), "absolute path, empty to clear"),

            Toggle(remote, "Redirect HTTP to HTTPS", "Hostname requests over plain HTTP are sent to the TLS port.",
                () => _settings.WebHttpsRedirect,
                on =>
                {
                    _settings.WebHttpsRedirect = on;
                    return on
                        ? "Hostname requests over plain HTTP will redirect to HTTPS."
                        : "HTTP requests are served as-is (no HTTPS redirect).";
                }),

            Toggle(remote, "HTTPS only", "Skip the plain-HTTP listener entirely. Fails open if the certificate cannot load at startup.",
                () => _settings.WebHttpsOnly,
                on =>
                {
                    if (on && !_settings.WebHttpsEnabled)
                        throw new SettingRejectedException(
                            "Switch HTTPS on first — turning off plain HTTP without it would leave no console at all.");
                    _settings.WebHttpsOnly = on;
                    return on
                        ? "Plain HTTP will be off (HTTPS only) — restart the web console to apply. If the certificate fails to load at startup, HTTP stays on so you aren't locked out."
                        : "Plain HTTP will be served alongside HTTPS — restart the web console to apply.";
                }),

            Toggle(remote, "DuckDNS dynamic DNS", "Keep a duckdns.org hostname pointed at this machine's public IP.",
                () => _duckDns.Config.Enabled,
                on =>
                {
                    var cfg = CloneDuckDns();
                    cfg.Enabled = on;
                    if (on && (cfg.Domain.Length == 0 || cfg.Token.Length == 0))
                        throw new SettingRejectedException("Enter the DuckDNS subdomain and token first.");
                    return _duckDns.Apply(cfg);
                }),

            Value(remote, "DuckDNS subdomain", "Just the label — \"myhost\" for myhost.duckdns.org.", SettingKind.Text,
                () => _duckDns.Config.Domain.Length == 0 ? "(not set)" : _duckDns.Config.Domain,
                raw =>
                {
                    var cfg = CloneDuckDns();
                    cfg.Domain = DuckDnsUpdater.NormalizeDomain(raw);
                    if (raw.Length > 0 && cfg.Domain.Length == 0)
                        throw new SettingRejectedException("Enter the subdomain label, e.g. myhost (or myhost.duckdns.org).");
                    _duckDns.Apply(cfg);
                    return cfg.Domain.Length == 0 ? "DuckDNS subdomain cleared." : $"DuckDNS subdomain: {cfg.Domain}";
                }, "e.g. myhost"),

            // Never shown back: the token is a credential, and the prompt is the only
            // place it is ever typed. Empty clears it, the same as the web console.
            Value(remote, "DuckDNS token", "Written to duckdns.json (owner-only) and never displayed again.", SettingKind.Text,
                () => _duckDns.Config.Token.Length > 0 ? "(stored)" : "(not set)",
                raw =>
                {
                    var cfg = CloneDuckDns();
                    cfg.Token = raw;
                    _duckDns.Apply(cfg);
                    return raw.Length == 0 ? "DuckDNS token cleared." : $"DuckDNS token saved — {_duckDns.Status}";
                }, "token, empty to clear"),

            Value(remote, "Let's Encrypt account email", "Used when issuing a certificate.", SettingKind.Text,
                () => _settings.AcmeAccountEmail.Length == 0 ? "(not set)" : _settings.AcmeAccountEmail,
                raw =>
                {
                    _settings.AcmeAccountEmail = raw;
                    return raw.Length == 0
                        ? "Let's Encrypt account email cleared."
                        : $"Let's Encrypt account email set to {raw}.";
                }, "email address, empty to clear"),

            new SettingItem
            {
                Section = remote,
                Label = "Issue certificate",
                Description = "Run Let's Encrypt issuance through DuckDNS. Takes minutes — it waits on DNS propagation.",
                Kind = SettingKind.Action,
                Read = () => "press Enter",
                Apply = _ => throw new SettingRejectedException("Handled by the Settings view.")
            }
        };
    }

    /// <summary>
    /// Shared by both TLS path rows: whichever changed, the pair is re-validated
    /// together, because a certificate is only usable with its key.
    /// </summary>
    private string ApplyTlsPath(bool certPath, string raw)
    {
        if (raw.Length > 0 && !File.Exists(raw))
            throw new SettingRejectedException($"File not found: {raw}");

        if (certPath) _settings.WebTlsCertPath = raw;
        else _settings.WebTlsKeyPath = raw;

        if (_settings.WebTlsCertPath.Length == 0)
            return "Certificate path cleared — HTTPS cannot start without it.";

        var ok = TlsCertificateProvider.TryLoad(_settings.WebTlsCertPath, _settings.WebTlsKeyPath,
            _settings.WebTlsPfxPassword, out var probe, out var probeError);
        probe?.Dispose();
        return ok
            ? "Certificate OK — restart the web console to apply."
            : $"Saved, but the certificate cannot be loaded yet: {probeError}";
    }
}
