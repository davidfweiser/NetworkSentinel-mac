using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// The shared service graph: monitor, firewall, allowlist, settings — constructed,
/// cross-wired, and disposed in ONE place.
///
/// Each frontend (GUI, TUI, web console) used to build this graph itself with a
/// copied ~20-line block, and the copies drifted: only the GUI applied the
/// persisted poll interval, so the TUI and web console silently ran at the default
/// cadence no matter what was saved; only the TUI failed to dispose the allowlist;
/// and every new setting had to be wired three times to exist everywhere. The
/// frontends now own only what is genuinely theirs: event handlers, presentation,
/// and user interaction.
/// </summary>
public sealed class SentinelCore : IDisposable
{
    public AppSettings Settings { get; }
    public NetworkMonitorService Monitor { get; } = new();
    public FirewallService Firewall { get; } = new();
    public AllowlistService Allowlist { get; } = new();
    public PreventionService Prevention { get; }
    public TrafficMeterService Traffic { get; } = new();
    public DnsFilterService DnsFilter { get; } = new();

    public SentinelCore(AppSettings? settings = null)
    {
        Settings = settings ?? AppSettings.Load();

        Prevention = new PreventionService(Firewall, Allowlist, Settings);
        // A persisted value outside the offered range (hand-edited settings.json)
        // must not silently arm auto-block at Low.
        if (Prevention.MinLevel is not (ThreatLevel.Medium or ThreatLevel.High or ThreatLevel.Critical))
            Prevention.MinLevel = ThreatLevel.High;

        Firewall.Allowlist = Allowlist;
        Firewall.AutoBlockExpiry = ExpiryMinutesToSpan(Settings.AutoBlockExpiryMinutes);
        Firewall.StartExpirySweep();

        Monitor.GeoLookupsEnabled = Settings.GeoLookupEnabled;
        Monitor.AuthMonitoringEnabled = Settings.AuthLogMonitorEnabled;
        Monitor.ProbeMonitoringEnabled = Settings.ProbeLogEnabled;
        Monitor.PollIntervalMs = Settings.MonitorPollMs;
        Monitor.ThreatIntelEnabled = Settings.ThreatIntelEnabled;
        Monitor.ProcessReputationEnabled = Settings.ProcessReputationEnabled;
        Monitor.NewListenerAlertsEnabled = Settings.NewListenerAlertsEnabled;
        Monitor.ArpWatchEnabled = Settings.ArpWatchEnabled;
        Monitor.LaunchWatchEnabled = Settings.LaunchItemWatchEnabled;
        Monitor.ExfilMonitorEnabled = Settings.ExfilMonitorEnabled;
        Monitor.ExfilThresholdMb = Settings.ExfilMbPer10Min;
        Monitor.HoneypotPorts = HoneypotService.ParsePorts(Settings.HoneypotPorts);
        Monitor.HoneypotEnabled = Settings.HoneypotEnabled;
        Monitor.SuricataEvePath = Settings.SuricataEvePath;
        Monitor.SuricataMaxSeverity = Settings.SuricataMaxSeverity;
        Monitor.SuricataIgnoredSids = Settings.SuricataIgnoredSids;
        Monitor.SuricataEnabled = Settings.SuricataEnabled;
        Monitor.WireGuardPeerMbPer10Min = Settings.WireGuardPeerMbPer10Min;
        Monitor.WireGuardMonitorEnabled = Settings.WireGuardMonitorEnabled;
        Monitor.DnsApprovedResolvers = Settings.DnsApprovedResolvers;
        Monitor.DnsHygieneEnabled = Settings.DnsHygieneEnabled;
        // The filtering resolver is a separate process on another machine, so the switch
        // only needs to know where to reach it; its live state is read back rather than
        // assumed from here.
        DnsFilter.Configure(Settings.DnsFilterUrl, Settings.DnsFilterUsername, Settings.DnsFilterPassword);
        // DNS hygiene is fed by the flow source, so switching it on implies flow events.
        Monitor.FlowEventsEnabled = Settings.FlowEventsEnabled || Settings.DnsHygieneEnabled;
        Monitor.WebhookUrl = Settings.WebhookUrl;
        Monitor.WebhookMinLevel = Settings.GetWebhookMinLevel();
        Monitor.IsIpAllowlisted = ip => Allowlist.IsAllowed(ip, out _);
        // A WireGuard peer's public endpoint must never be auto-blocked — that kills the tunnel.
        Prevention.IsProtectedAddress = Monitor.IsWireGuardPeerEndpoint;
        // Lets the DNS monitor see every allowlist answer and catch poisoning of the never-block list.
        Allowlist.ResolutionObserver = Monitor.AllowlistResolutionObserver;

        // Root can re-install the probe-log rule silently; unprivileged runs wait
        // for the user to authorize elevation instead of failing at startup.
        if (Settings.ProbeLogEnabled && Firewall.IsRoot)
            _ = Task.Run(() => Firewall.EnableProbeLogging());

        Allowlist.UseRemoteFeed = Settings.AllowlistUseRemoteFeed;

        // Independent of the monitor's poll loop: the byte counters are cumulative,
        // so the meter's own cadence is what makes its deltas comparable, and it
        // keeps recording while monitoring is paused.
        if (Settings.TrafficMeterEnabled)
            Traffic.Start();
    }

    /// <summary>0 (and anything negative) means auto-block rules never expire.</summary>
    public static TimeSpan? ExpiryMinutesToSpan(int minutes)
        => minutes > 0 ? TimeSpan.FromMinutes(minutes) : null;

    public void Dispose()
    {
        Monitor.Dispose();
        Allowlist.Dispose();
        Traffic.Dispose();
        DnsFilter.Dispose();
    }
}
