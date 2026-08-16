using System.IO;
using System.Text.Json;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

public sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public bool AutoBlockEnabled { get; set; }
    public string AutoBlockMinLevel { get; set; } = nameof(ThreatLevel.High);
    public bool AutoBlockInbound { get; set; } = true;
    public bool AutoBlockOutbound { get; set; } = true;

    /// <summary>Geo lookups use a free web endpoint (HTTPS preferred); set false to disable.</summary>
    public bool GeoLookupEnabled { get; set; } = true;

    /// <summary>Watch the macOS unified log for failed-logon bursts; set false to disable.</summary>
    public bool AuthLogMonitorEnabled { get; set; } = true;

    /// <summary>
    /// Detect scans of CLOSED ports via a PF log rule + pflog0 watch.
    /// Off by default because installing the rule and reading pflog0 both need
    /// admin rights (Mac password dialog).
    /// </summary>
    public bool ProbeLogEnabled { get; set; }

    /// <summary>Refresh the allowlist from this repo's GitHub feed; set false to use only local/built-in lists.</summary>
    public bool AllowlistUseRemoteFeed { get; set; } = true;

    /// <summary>
    /// Meter bytes in/out from the interface counters and keep the daily history
    /// behind the dashboard's data-flow charts. Unprivileged and cheap, so on by
    /// default; turning it off also stops the history file from growing.
    /// </summary>
    public bool TrafficMeterEnabled { get; set; } = true;

    /// <summary>
    /// Actively warn when a Critical-level threat is detected: desktop notification
    /// in the GUI, tab-title badge + browser notification in the web console.
    /// </summary>
    public bool CriticalAlertsEnabled { get; set; } = true;

    /// <summary>
    /// Milliseconds between monitor polls (clamped to 500–10000 when applied).
    /// Doubles as the activity-chart sample rate.
    /// </summary>
    public int MonitorPollMs { get; set; } = NetworkMonitorService.DefaultPollIntervalMs;

    /// <summary>
    /// IPs the user manually unblocked/removed. Auto-block will not recreate rules for these
    /// until the UTC expiry (or the user blocks the IP again). Shared across GUI / TUI / web.
    /// </summary>
    public Dictionary<string, DateTime> AutoBlockSuppressedUntil { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Decide and report auto-blocks without writing PF rules. Inline prevention turns a
    /// false positive into an outage, so a noisy new detection source should run here
    /// first — watch what it would have dropped before letting it drop anything.
    /// </summary>
    public bool PreventionDryRun { get; set; }

    /// <summary>Ingest Suricata's EVE JSON alerts as threat events (payload inspection / signatures).</summary>
    public bool SuricataEnabled { get; set; }

    /// <summary>Path to Suricata's EVE JSON log.</summary>
    public string SuricataEvePath { get; set; } = SuricataService.DefaultEvePath;

    /// <summary>Highest Suricata severity number to accept — Suricata counts down, so 1 is most severe.</summary>
    public int SuricataMaxSeverity { get; set; } = 3;

    /// <summary>Comma-separated Suricata signature IDs to ignore (per-rule mute for false positives).</summary>
    public string SuricataIgnoredSids { get; set; } = "";

    /// <summary>
    /// Watch WireGuard peers via `wg show`. WireGuard's single unconnected UDP socket is
    /// never a tracked connection, so on a VPN server this is the only view of who is
    /// attached. Needs root and wireguard-tools.
    /// </summary>
    public bool WireGuardMonitorEnabled { get; set; }

    /// <summary>
    /// Megabytes sent to one WireGuard peer within 10 minutes before alerting (0 = off).
    /// </summary>
    public int WireGuardPeerMbPer10Min { get; set; }

    /// <summary>
    /// Read PF's state table for flow events — the only view of UDP traffic and of
    /// traffic this Mac forwards. Needs PF enabled and root, so off by default.
    /// </summary>
    public bool FlowEventsEnabled { get; set; }

    /// <summary>
    /// Watch DNS hygiene: plaintext egress, encrypted DNS falling back, unapproved
    /// resolvers, VPN clients bypassing the resolver, allowlist poisoning. Needs flow
    /// events, so it needs PF enabled and root.
    /// </summary>
    public bool DnsHygieneEnabled { get; set; }

    /// <summary>
    /// Resolvers this host is meant to use, comma separated. Also what identifies a DoH
    /// endpoint on 443 — without it a DoH setup looks like no DNS at all rather than a leak.
    /// </summary>
    public string DnsApprovedResolvers { get; set; } = "";

    /// <summary>Check remote IPs against public threat-intel blocklists (FireHOL level1, Spamhaus DROP).</summary>
    public bool ThreatIntelEnabled { get; set; } = true;

    /// <summary>Flag unsigned binaries, suspicious install paths, and shell processes with outbound connections.</summary>
    public bool ProcessReputationEnabled { get; set; } = true;

    /// <summary>Alert when a new port starts listening after baseline, or a known port changes owner process.</summary>
    public bool NewListenerAlertsEnabled { get; set; } = true;

    /// <summary>Watch the ARP table for gateway MAC changes (ARP spoofing / MITM).</summary>
    public bool ArpWatchEnabled { get; set; } = true;

    /// <summary>Watch LaunchAgents / LaunchDaemons folders for new or modified startup items.</summary>
    public bool LaunchItemWatchEnabled { get; set; } = true;

    /// <summary>Sample per-connection byte counts (nettop) and alert on large sustained outbound transfers.</summary>
    public bool ExfilMonitorEnabled { get; set; } = true;

    /// <summary>Outbound megabytes to a single uncommon public host within 10 minutes before alerting.</summary>
    public int ExfilMbPer10Min { get; set; } = 250;

    /// <summary>Listen on decoy ports; any completed connection is a Critical alert. Off by default (binds ports).</summary>
    public bool HoneypotEnabled { get; set; }

    /// <summary>Comma-separated decoy TCP ports for the honeypot.</summary>
    public string HoneypotPorts { get; set; } = "2323,3389,5900";

    /// <summary>
    /// Minutes before auto-created block rules expire (0 = never). Expired rules are removed
    /// silently when possible (root / cached sudo) or at the next firewall change.
    /// </summary>
    public int AutoBlockExpiryMinutes { get; set; }

    /// <summary>
    /// Serve the web console over HTTPS in addition to HTTP. Needs <see cref="WebTlsCertPath"/>;
    /// endpoint changes only take effect when the web console restarts.
    /// </summary>
    public bool WebHttpsEnabled { get; set; }

    /// <summary>TCP port for the HTTPS endpoint. Ports below 1024 need root.</summary>
    public int WebHttpsPort { get; set; } = 18443;

    /// <summary>PEM fullchain (Let's Encrypt fullchain.cer) or a .pfx / .p12 bundle.</summary>
    public string WebTlsCertPath { get; set; } = "";

    /// <summary>PEM private key. Ignored for .pfx / .p12 certificates.</summary>
    public string WebTlsKeyPath { get; set; } = "";

    /// <summary>Password for a .pfx / .p12 certificate. Empty for PEM.</summary>
    public string WebTlsPfxPassword { get; set; } = "";

    /// <summary>
    /// Redirect plain-HTTP requests to HTTPS when the request arrived by hostname.
    /// Requests to a bare IP keep serving HTTP — the certificate only covers the name,
    /// so redirecting those would trade a working page for a certificate warning.
    /// </summary>
    public bool WebHttpsRedirect { get; set; } = true;

    /// <summary>
    /// Address the Let's Encrypt account is registered against. Only read the first time
    /// acme.sh is installed; kept so a retry does not ask for it again. Not a credential.
    /// </summary>
    public string AcmeAccountEmail { get; set; } = "";

    /// <summary>POST alerts to this webhook URL (ntfy / Slack / Discord / generic JSON). Empty = off.</summary>
    public string WebhookUrl { get; set; } = "";

    /// <summary>Minimum threat level that triggers the webhook.</summary>
    public string WebhookMinLevel { get; set; } = nameof(ThreatLevel.Critical);

    public ThreatLevel GetWebhookMinLevel()
        => Enum.TryParse<ThreatLevel>(WebhookMinLevel, true, out var level) ? level : ThreatLevel.Critical;

    public ThreatLevel GetMinLevel()
    {
        return Enum.TryParse<ThreatLevel>(AutoBlockMinLevel, true, out var level)
            ? level
            : ThreatLevel.High;
    }

    public void SetMinLevel(ThreatLevel level) => AutoBlockMinLevel = level.ToString();

    private static string SettingsPath
        => Path.Combine(AppPaths.DataDirectory, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            var path = SettingsPath;
            if (!File.Exists(path))
                return new AppSettings();

            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
            settings.AutoBlockSuppressedUntil ??= new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            return settings;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        try
        {
            // Owner-only like web-master.json and duckdns.json: settings.json can hold
            // the .pfx password and the webhook URL, which are secrets too.
            AppPaths.WriteAtomic(SettingsPath, JsonSerializer.Serialize(this, JsonOptions),
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // best-effort persistence
        }
    }
}
