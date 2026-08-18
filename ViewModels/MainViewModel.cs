using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSentinel.Models;
using NetworkSentinel.Services;

namespace NetworkSentinel.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    // The shared graph is built and cross-wired by SentinelCore; these are views
    // onto it so the rest of this class reads unchanged.
    private readonly SentinelCore _core = new();
    private readonly NetworkMonitorService _monitor;
    private readonly FirewallService _firewall;
    private readonly AllowlistService _allowlist;
    private readonly PreventionService _prevention;
    private readonly DesktopNotifier _notifier = new();
    private readonly DuckDnsUpdater _duckDns = new();
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _clockTimer;
    // The blocked set, the retry backoff and the suppression list all live in
    // PreventionService now — this class kept its own copies of all three.
    private int _monitorRefreshQueued;
    private bool _suppressProbeLogHandler;

    [ObservableProperty] private string _clockText = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss");
    [ObservableProperty] private string _selectedNav = "Dashboard";
    [ObservableProperty] private bool _showDashboard = true;
    [ObservableProperty] private bool _showConnections;
    [ObservableProperty] private bool _showHosts;
    [ObservableProperty] private bool _showThreats;
    [ObservableProperty] private bool _showPorts;
    [ObservableProperty] private bool _showFirewall;
    [ObservableProperty] private bool _showSettings;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _heroSubtitle = "Watching local ports, remote peers, and break-in patterns in real time.";
    [ObservableProperty] private string _firewallStatusText = "";
    [ObservableProperty] private string _firewallMessage = "";
    [ObservableProperty] private string _autoBlockStatusText = "Auto-block is off.";
    [ObservableProperty] private string _allowlistStatusText = "Loading known-good allowlist…";
    [ObservableProperty] private string _allowlistInput = "";
    [ObservableProperty] private bool _isAdmin;
    [ObservableProperty] private bool _autoBlockEnabled;
    [ObservableProperty] private string _autoBlockMinLevel = nameof(ThreatLevel.High);
    [ObservableProperty] private string _manualBlockIp = "";
    [ObservableProperty] private string _manualBlockPort = "";
    [ObservableProperty] private string _manualBlockProtocol = "TCP";
    [ObservableProperty] private bool _blockInbound = true;
    [ObservableProperty] private bool _blockOutbound = true;
    [ObservableProperty] private bool _preventionDryRun;
    [ObservableProperty] private FirewallRuleInfo? _selectedFirewallRule;
    [ObservableProperty] private AllowlistEntryView? _selectedAllowlistEntry;
    [ObservableProperty] private RemoteHost? _selectedHost;
    [ObservableProperty] private ThreatEvent? _selectedThreat;
    [ObservableProperty] private NetworkConnection? _selectedConnection;
    [ObservableProperty] private ListeningPort? _selectedPort;

    // ── Settings view (mirrors the web console's Settings tab) ─────────────────
    [ObservableProperty] private bool _geoLookupEnabled = true;
    [ObservableProperty] private bool _authLogMonitorEnabled = true;
    [ObservableProperty] private bool _probeLogEnabled;
    [ObservableProperty] private bool _allowlistUseRemoteFeed = true;
    [ObservableProperty] private bool _criticalAlertsEnabled = true;
    [ObservableProperty] private string _selectedMonitorPoll = "1.2 seconds (default)";
    [ObservableProperty] private string _authLogStatusText = "";
    [ObservableProperty] private string _probeLogStatusText = "";
    [ObservableProperty] private string _settingsMessage = "";
    [ObservableProperty] private bool _threatIntelEnabled = true;
    [ObservableProperty] private bool _processReputationEnabled = true;
    [ObservableProperty] private bool _newListenerAlertsEnabled = true;
    [ObservableProperty] private bool _arpWatchEnabled = true;
    [ObservableProperty] private bool _launchItemWatchEnabled = true;
    [ObservableProperty] private bool _exfilMonitorEnabled = true;
    [ObservableProperty] private string _exfilThresholdMbText = "250";
    [ObservableProperty] private bool _honeypotEnabled;
    [ObservableProperty] private string _honeypotPortsText = "2323,3389,5900";
    [ObservableProperty] private string _webhookUrl = "";
    [ObservableProperty] private string _selectedAutoBlockExpiry = "Never (permanent)";

    // ── Remote access (web console HTTPS + DuckDNS) ────────────────────────────
    // These configure the headless console (`--web`); this GUI only edits and
    // persists them. The DuckDNS refresh does run here too, so the hostname stays
    // current whenever either front-end is open.
    [ObservableProperty] private bool _httpsEnabled;
    [ObservableProperty] private string _httpsPortText = "18443";
    [ObservableProperty] private string _tlsCertPath = "";
    [ObservableProperty] private string _tlsKeyPath = "";
    [ObservableProperty] private bool _httpsRedirect = true;
    [ObservableProperty] private bool _duckDnsEnabled;
    [ObservableProperty] private string _duckDnsDomain = "";
    [ObservableProperty] private string _duckDnsToken = "";
    [ObservableProperty] private string _remoteAccessStatus = "";

    /// <summary>Registered with Let's Encrypt the first time acme.sh is installed; unused after that.</summary>
    [ObservableProperty] private string _acmeEmail = "";

    /// <summary>True while the issuance script runs — disables the button and drives its busy text.</summary>
    [ObservableProperty] private bool _isIssuingCertificate;

    /// <summary>Availability of the desktop notification channel (fixed at startup).</summary>
    public string CriticalAlertStatusText => _notifier.StatusText;

    // ── Activity chart legend (mirrors the web chart's legend row) ─────────────
    [ObservableProperty] private string _activityConnectionsText = "connections";
    [ObservableProperty] private string _activityThreatText = "threat detected (none in window)";
    [ObservableProperty] private string _activityFromText = "";
    [ObservableProperty] private string _activityToText = "";
    [ObservableProperty] private string _activityWindowText = "collecting…";

    /// <summary>Live window title shown in the taskbar / top bar when minimized.</summary>
    [ObservableProperty] private string _windowTitle = "Network Sentinel";

    /// <summary>Multi-line tooltip / tray summary for the system indicator.</summary>
    [ObservableProperty] private string _trayToolTip = "Network Sentinel — starting…";

    /// <summary>Short one-line status for tray menu header.</summary>
    [ObservableProperty] private string _trayStatusLine = "Network Sentinel";

    public string AppVersion { get; } = FormatAppVersion();

    public string DataDirectoryText { get; } = AppPaths.DataDirectory;

    public DashboardStats Stats => _monitor.Stats;
    public ObservableCollection<NetworkConnection> Connections { get; } = new();
    public ObservableCollection<ListeningPort> ListeningPorts { get; } = new();
    public ObservableCollection<RemoteHost> RemoteHosts { get; } = new();
    public ObservableCollection<ThreatEvent> Threats { get; } = new();
    public ObservableCollection<FirewallRuleInfo> FirewallRules { get; } = new();
    public ObservableCollection<AllowlistEntryView> AllowlistEntries { get; } = new();
    public ObservableCollection<double> ActivitySeries { get; } = new();
    public ObservableCollection<double> ThreatSeries { get; } = new();
    public ObservableCollection<string> ProtocolOptions { get; } = new() { "TCP", "UDP" };
    public ObservableCollection<string> MonitorPollOptions { get; } = new()
    {
        "0.5 seconds",
        "1.2 seconds (default)",
        "2.5 seconds",
        "5 seconds",
        "10 seconds"
    };
    public ObservableCollection<string> AutoBlockLevelOptions { get; } = new()
    {
        nameof(ThreatLevel.Medium),
        nameof(ThreatLevel.High),
        nameof(ThreatLevel.Critical)
    };
    public ObservableCollection<string> AutoBlockExpiryOptions { get; } = new()
    {
        "Never (permanent)",
        "1 hour",
        "6 hours",
        "24 hours",
        "7 days"
    };

    public MainViewModel()
    {
        _settings = _core.Settings;
        _monitor = _core.Monitor;
        _firewall = _core.Firewall;
        _allowlist = _core.Allowlist;
        _prevention = _core.Prevention;
        _autoBlockEnabled = _settings.AutoBlockEnabled;
        _autoBlockMinLevel = _settings.AutoBlockMinLevel;
        if (!AutoBlockLevelOptions.Contains(_autoBlockMinLevel))
            _autoBlockMinLevel = nameof(ThreatLevel.High);
        _blockInbound = _settings.AutoBlockInbound;
        _blockOutbound = _settings.AutoBlockOutbound;
        _preventionDryRun = _settings.PreventionDryRun;
        // The clamp above can change the level, and assigning the backing field does not
        // fire OnAutoBlockMinLevelChanged, so push it to the engine explicitly.
        _prevention.MinLevel = ParseMinLevel(_autoBlockMinLevel);

        // Assign backing fields, not properties: the generated setters would fire the
        // OnXChanged handlers below and re-save settings (or re-elevate) during startup.
        _geoLookupEnabled = _settings.GeoLookupEnabled;
        _authLogMonitorEnabled = _settings.AuthLogMonitorEnabled;
        _probeLogEnabled = _settings.ProbeLogEnabled;
        _allowlistUseRemoteFeed = _settings.AllowlistUseRemoteFeed;
        _trafficMeterEnabled = _settings.TrafficMeterEnabled;
        _criticalAlertsEnabled = _settings.CriticalAlertsEnabled;
        _selectedMonitorPoll = PollMsToLabel(_settings.MonitorPollMs);
        _threatIntelEnabled = _settings.ThreatIntelEnabled;
        _processReputationEnabled = _settings.ProcessReputationEnabled;
        _newListenerAlertsEnabled = _settings.NewListenerAlertsEnabled;
        _arpWatchEnabled = _settings.ArpWatchEnabled;
        _launchItemWatchEnabled = _settings.LaunchItemWatchEnabled;
        _exfilMonitorEnabled = _settings.ExfilMonitorEnabled;
        _exfilThresholdMbText = _settings.ExfilMbPer10Min.ToString();
        _honeypotEnabled = _settings.HoneypotEnabled;
        _honeypotPortsText = _settings.HoneypotPorts;
        _webhookUrl = _settings.WebhookUrl;
        _selectedAutoBlockExpiry = ExpiryMinutesToLabel(_settings.AutoBlockExpiryMinutes);

        // Backing fields, not properties: assigning the property here would fire the
        // OnChanged handlers below and re-save settings during construction.
        _httpsEnabled = _settings.WebHttpsEnabled;
        _httpsPortText = _settings.WebHttpsPort.ToString();
        _tlsCertPath = _settings.WebTlsCertPath;
        _tlsKeyPath = _settings.WebTlsKeyPath;
        _httpsRedirect = _settings.WebHttpsRedirect;
        _duckDnsEnabled = _duckDns.Config.Enabled;
        _duckDnsDomain = _duckDns.Config.Domain;
        _duckDnsToken = _duckDns.Config.Token;
        _acmeEmail = _settings.AcmeAccountEmail;
        if (_duckDns.Config.IsUsable)
            _duckDns.Start();
        _remoteAccessStatus = BuildRemoteAccessStatus();

        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
        _monitor.Start();

        IsAdmin = _firewall.IsAdministrator;
        FirewallStatusText = _firewall.PrivilegeText;
        UpdateAutoBlockStatusText();
        RefreshFirewallRules();
        InitializeFirewallConfig();
        InitializeTraffic();
        _ = InitializeAllowlistAsync();

        _clockTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clockTimer.Tick += (_, _) =>
        {
            ClockText = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss");
            // Keep chrome fresh even between monitor polls (clock second tick).
            if (DateTime.Now.Second % 2 == 0)
                UpdateStatusChrome();
            // The DuckDNS half of this updates on its own schedule, so poll the
            // cached parts rather than leaving a stale "refreshing…" on screen.
            if (ShowSettings)
                RefreshRemoteAccessStatus();
        };
        _clockTimer.Start();
        UpdateStatusChrome();
        RefreshMonitorStatusText();
    }

    private async Task InitializeAllowlistAsync()
    {
        try
        {
            await _allowlist.InitializeAsync();

            // The firewall call runs before marshalling to the UI thread, not inside
            // the InvokeAsync lambda: it shells out to pfctl and can raise the admin
            // password dialog, which froze the window during startup.
            var restored = _firewall.IsAdministrator
                ? await Task.Run(() => _firewall.UnblockAllowlistedAddresses())
                : null;

            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                SyncAllowlistUi();
                if (restored != null && restored.Success &&
                    !restored.Message.Contains("No allowlisted", StringComparison.OrdinalIgnoreCase))
                {
                    FirewallMessage = restored.Message;
                    RefreshFirewallRules();
                }
            });
        }
        catch (Exception ex)
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
                AllowlistStatusText = $"Allowlist load error: {ex.Message}");
        }
    }

    private void SyncAllowlistUi()
    {
        AllowlistEntries.Clear();
        foreach (var e in _allowlist.GetEntries())
            AllowlistEntries.Add(e);
        AllowlistStatusText = _allowlist.StatusText;
    }

    private void OnMonitorUpdated()
    {
        if (Dispatcher.UIThread.CheckAccess())
        {
            RefreshCollections();
            return;
        }

        if (Interlocked.CompareExchange(ref _monitorRefreshQueued, 1, 0) != 0)
            return;

        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _monitorRefreshQueued, 0);
            RefreshCollections();
        }, DispatcherPriority.Background);
    }

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (threats.Count == 0)
            return;

        if (CriticalAlertsEnabled)
        {
            var critical = threats.Where(t => t.Level >= ThreatLevel.Critical).ToList();
            if (critical.Count > 0)
                _ = Task.Run(() => _notifier.NotifyCritical(critical));
        }

        if (!AutoBlockEnabled)
            return;

        _ = Task.Run(() =>
        {
            try
            {
                ProcessAutoBlocks(threats);
            }
            catch (Exception ex)
            {
                Dispatcher.UIThread.Post(() =>
                {
                    FirewallMessage = $"Auto-block error: {ex.Message}";
                    UpdateAutoBlockStatusText();
                });
            }
        });
    }

    /// <summary>
    /// Every gate and every rule write lives in PreventionService now. This used to be
    /// one of three near-identical copies that had drifted — this one never honoured
    /// the manual-unblock suppression list, so the GUI would re-block an address the
    /// user had just deliberately released.
    /// </summary>
    private void ProcessAutoBlocks(IReadOnlyList<ThreatEvent> threats)
    {
        var result = _prevention.Apply(threats);
        if (!result.HasMessages)
            return;

        Dispatcher.UIThread.Post(() =>
        {
            FirewallMessage = result.Summary;
            UpdateAutoBlockStatusText();
            if (result.RulesChanged)
            {
                RefreshFirewallRules();
                RefreshCollections();
            }
        });
    }

    private void RefreshCollections()
    {
        RefreshBlockedIpsInBackground();

        foreach (var host in _monitor.RemoteHosts)
            host.IsBlocked = _prevention.IsBlocked(host.IpAddress);

        Sync(Connections, FilterConnections(_monitor.Connections));
        Sync(ListeningPorts, _monitor.ListeningPorts);
        Sync(RemoteHosts, FilterHosts(_monitor.RemoteHosts));
        Sync(Threats, FilterThreats(_monitor.Threats));

        var activity = _monitor.Activity;
        ActivitySeries.Clear();
        ThreatSeries.Clear();
        foreach (var sample in activity)
        {
            ActivitySeries.Add(sample.ConnectionCount);
            ThreatSeries.Add(sample.ThreatCount);
        }
        UpdateActivityLegend(activity);

        var high = Stats.HighThreats;
        var blocked = _prevention.BlockedCount;
        var auto = AutoBlockEnabled ? $"Auto-block ON (≥{AutoBlockMinLevel})" : "Auto-block OFF";
        HeroSubtitle = high > 0
            ? $"{high} high/critical · {blocked} blocked · {auto}"
            : $"{blocked} IPs blocked · {auto}";

        UpdateStatusChrome();
    }

    /// <summary>
    /// Fills the chart legend the way the web console does: current and peak
    /// connection counts, total alerts in the window, and the window's time range.
    /// </summary>
    private void UpdateActivityLegend(IReadOnlyList<ActivitySample> activity)
    {
        if (activity.Count < 2)
        {
            ActivityConnectionsText = "connections";
            ActivityThreatText = "threat detected (none in window)";
            ActivityFromText = "";
            ActivityToText = "";
            ActivityWindowText = "collecting…";
            return;
        }

        var first = activity[0];
        var last = activity[^1];
        var peak = activity.Max(a => a.ConnectionCount);
        var threatTotal = activity.Sum(a => a.ThreatCount);
        var span = last.Time - first.Time;

        ActivityConnectionsText = $"connections (now {last.ConnectionCount}, peak {peak})";
        ActivityThreatText = threatTotal > 0
            ? $"threat detected ({threatTotal} in window)"
            : "threat detected (none in window)";
        ActivityFromText = first.Time.ToString("HH:mm:ss");
        ActivityToText = last.Time.ToString("HH:mm:ss");
        // The span is derived, not assumed: a slower poll interval widens it.
        ActivityWindowText = span.TotalMinutes >= 1
            ? $"last {Math.Round(span.TotalMinutes)} min"
            : $"last {Math.Max(1, (int)span.TotalSeconds)} s";
    }

    /// <summary>
    /// Refresh window title + tray text so the top bar / task list still show
    /// live stats when the main window is minimized.
    /// </summary>
    public void UpdateStatusChrome()
    {
        var sessions = Stats.ActiveConnections;
        var ports = Stats.ListeningPorts;
        var hosts = Stats.RemoteHosts;
        var threats = Stats.ThreatsToday;
        var high = Stats.HighThreats;
        var blocked = _prevention.BlockedCount;
        var mon = Stats.IsMonitoring ? "Live" : "Paused";
        var auto = AutoBlockEnabled ? $"auto≥{AutoBlockMinLevel}" : "auto off";

        // Compact title for taskbar / window list (GNOME top bar / dock).
        WindowTitle = high > 0
            ? $"NS ⚠{high} · {sessions} sess · {hosts} hosts · {threats} evt"
            : $"NS · {sessions} sess · {ports} ports · {hosts} hosts · {threats} evt";

        TrayStatusLine = high > 0
            ? $"Network Sentinel · ⚠ {high} high · {sessions} sessions ({mon})"
            : $"Network Sentinel · {sessions} sessions · {hosts} remotes ({mon})";

        TrayToolTip =
            $"Network Sentinel  ·  {AppVersion}  ·  {mon}\n" +
            $"TCP sessions: {sessions}\n" +
            $"Listening ports: {ports}\n" +
            $"Remote hosts: {hosts}\n" +
            $"Threat events today: {threats}\n" +
            $"High / critical: {high}\n" +
            $"Blocked IPs: {blocked}  ·  {auto}";
    }

    private void RefreshBlockedIpsInBackground(bool force = false)
        => _prevention.RefreshBlockedIps(force, set => Dispatcher.UIThread.Post(() =>
        {
            foreach (var host in _monitor.RemoteHosts)
                host.IsBlocked = set.Contains(host.IpAddress);
        }));

    private static ThreatLevel ParseMinLevel(string value)
        => Enum.TryParse<ThreatLevel>(value, true, out var level) ? level : ThreatLevel.High;

    private void UpdateAutoBlockStatusText()
    {
        if (!AutoBlockEnabled)
        {
            AutoBlockStatusText = "Auto-block is off. Threats are logged only; nothing is blocked automatically.";
            return;
        }

        if (!IsAdmin)
        {
            AutoBlockStatusText = $"Auto-block is ON (≥ {AutoBlockMinLevel}), but firewall elevation was not available.";
            return;
        }

        AutoBlockStatusText =
            $"Auto-block is ON — public IPs at {AutoBlockMinLevel}+ severity are blocked in the host firewall " +
            $"({(BlockInbound ? "in" : "")}{(BlockInbound && BlockOutbound ? "+" : "")}{(BlockOutbound ? "out" : "")}).";
    }

    private void PersistSettings()
    {
        _settings.AutoBlockEnabled = AutoBlockEnabled;
        _settings.AutoBlockMinLevel = AutoBlockMinLevel;
        _settings.AutoBlockInbound = BlockInbound;
        _settings.AutoBlockOutbound = BlockOutbound;
        _settings.PreventionDryRun = PreventionDryRun;
        _settings.Save();
        UpdateAutoBlockStatusText();
    }

    partial void OnAutoBlockEnabledChanged(bool value)
    {
        _prevention.Enabled = value;
        PersistSettings();
        if (value && !IsAdmin)
            FirewallMessage = "Auto-block enabled, but firewall elevation failed — try Authorize firewall.";
        else if (value)
            FirewallMessage = $"Auto-block enabled for {AutoBlockMinLevel}+ threats (password dialog may appear).";
        else
            FirewallMessage = "Auto-block disabled.";
    }

    partial void OnAutoBlockMinLevelChanged(string value)
    {
        _prevention.MinLevel = ParseMinLevel(value);
        PersistSettings();
    }

    partial void OnBlockInboundChanged(bool value)
    {
        _prevention.BlockInbound = value;
        PersistSettings();
    }

    partial void OnBlockOutboundChanged(bool value)
    {
        _prevention.BlockOutbound = value;
        PersistSettings();
    }

    partial void OnPreventionDryRunChanged(bool value)
    {
        _prevention.DryRun = value;
        PersistSettings();
        FirewallMessage = value
            ? "Dry run on — auto-block will report what it would drop, without writing rules."
            : "Dry run off — auto-block writes PF rules.";
        UpdateAutoBlockStatusText();
    }

    private IEnumerable<NetworkConnection> FilterConnections(IReadOnlyList<NetworkConnection> source)
    {
        if (string.IsNullOrWhiteSpace(SearchText)) return source;
        var q = SearchText.Trim();
        return source.Where(c =>
            c.DisplayLocal.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.DisplayRemote.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.StateText.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    private IEnumerable<RemoteHost> FilterHosts(IReadOnlyList<RemoteHost> source)
    {
        if (string.IsNullOrWhiteSpace(SearchText)) return source;
        var q = SearchText.Trim();
        return source.Where(h =>
            h.IpAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.HostName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.Status.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.BlockStatusText.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    private IEnumerable<ThreatEvent> FilterThreats(IReadOnlyList<ThreatEvent> source)
    {
        if (string.IsNullOrWhiteSpace(SearchText)) return source;
        var q = SearchText.Trim();
        return source.Where(t =>
            t.SourceIp.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Detail.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Origin.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Method.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    private static void Sync<T>(ObservableCollection<T> target, IEnumerable<T> source) where T : class
    {
        var list = source.ToList();
        var wanted = new HashSet<T>(list);

        for (int i = target.Count - 1; i >= 0; i--)
        {
            if (!wanted.Contains(target[i]))
                target.RemoveAt(i);
        }

        for (int i = 0; i < list.Count; i++)
        {
            var item = list[i];
            int currentIndex = target.IndexOf(item);
            if (currentIndex == i) continue;
            if (currentIndex >= 0)
                target.Move(currentIndex, i);
            else
                target.Insert(i, item);
        }
    }

    partial void OnSearchTextChanged(string value) => RefreshCollections();

    [RelayCommand]
    private void Navigate(string? page)
    {
        SelectedNav = page ?? "Dashboard";
        ShowDashboard = SelectedNav == "Dashboard";
        ShowConnections = SelectedNav == "Connections";
        ShowHosts = SelectedNav == "Hosts";
        ShowThreats = SelectedNav == "Threats";
        ShowPorts = SelectedNav == "Ports";
        ShowFirewall = SelectedNav == "Firewall";
        ShowFirewallConfig = SelectedNav == "FirewallConfig";
        ShowSettings = SelectedNav == "Settings";

        if (ShowFirewall)
            RefreshFirewallRules();
        if (ShowFirewallConfig)
            _ = RefreshFirewallConfigAsync();
        if (ShowSettings)
            RefreshMonitorStatusText();
    }

    // ── Settings handlers ─────────────────────────────────────────────────────
    // Each mirrors the equivalent set_setting case in the web console so the two
    // front-ends produce identical state in settings.json.

    partial void OnGeoLookupEnabledChanged(bool value)
    {
        _monitor.GeoLookupsEnabled = value;
        _settings.GeoLookupEnabled = value;
        _settings.Save();
        SettingsMessage = $"Geo lookups: {(value ? "on" : "off")}";
    }

    partial void OnAuthLogMonitorEnabledChanged(bool value)
    {
        _monitor.AuthMonitoringEnabled = value;
        _settings.AuthLogMonitorEnabled = value;
        _settings.Save();
        RefreshMonitorStatusText();
        SettingsMessage = value
            ? $"Auth-log monitoring: on ({_monitor.AuthLogStatus})"
            : "Auth-log monitoring: off";
    }

    partial void OnProbeLogEnabledChanged(bool value)
    {
        // Set while reverting the toggle after a failed rule install, so the revert
        // doesn't re-enter this handler and try to undo itself.
        if (_suppressProbeLogHandler) return;

        _settings.ProbeLogEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? "Installing probe-log firewall rule…"
            : "Removing probe-log firewall rule…";

        // Installing/removing the SYN-log rule shells out to pfctl/tcpdump and may
        // prompt for elevation, so keep it off the UI thread.
        _ = Task.Run(() =>
        {
            var result = value ? _firewall.EnableProbeLogging() : _firewall.DisableProbeLogging();
            Dispatcher.UIThread.Post(() =>
            {
                _monitor.ProbeMonitoringEnabled = value && result.Success;
                if (value && !result.Success)
                {
                    // Rule install failed (usually no elevation) — don't leave the
                    // toggle claiming a detection that isn't running.
                    _settings.ProbeLogEnabled = false;
                    _settings.Save();
                    _suppressProbeLogHandler = true;
                    try { ProbeLogEnabled = false; }
                    finally { _suppressProbeLogHandler = false; }
                    SettingsMessage = $"Closed-port scan detection: could not install firewall rule — {result.Message}";
                }
                else
                {
                    SettingsMessage = value
                        ? "Closed-port scan detection: on (probe-log firewall rule installed)"
                        : "Closed-port scan detection: off";
                }
                RefreshMonitorStatusText();
            });
        });
    }

    partial void OnCriticalAlertsEnabledChanged(bool value)
    {
        _settings.CriticalAlertsEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Critical threat alerts: on — {_notifier.StatusText}"
            : "Critical threat alerts: off";
    }

    partial void OnAllowlistUseRemoteFeedChanged(bool value)
    {
        _allowlist.UseRemoteFeed = value;
        _settings.AllowlistUseRemoteFeed = value;
        _settings.Save();
        SettingsMessage = $"Allowlist remote feed: {(value ? "on" : "off")}";
    }

    partial void OnSelectedMonitorPollChanged(string value)
    {
        var ms = PollLabelToMs(value);
        _monitor.PollIntervalMs = ms;
        _settings.MonitorPollMs = ms;
        _settings.Save();
        SettingsMessage = $"Monitor poll interval: {value}";
    }

    partial void OnThreatIntelEnabledChanged(bool value)
    {
        _monitor.ThreatIntelEnabled = value;
        _settings.ThreatIntelEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Threat-intel feeds: on ({_monitor.ThreatIntelStatus})"
            : "Threat-intel feeds: off";
    }

    partial void OnProcessReputationEnabledChanged(bool value)
    {
        _monitor.ProcessReputationEnabled = value;
        _settings.ProcessReputationEnabled = value;
        _settings.Save();
        SettingsMessage = $"Process reputation checks: {(value ? "on" : "off")}";
    }

    partial void OnNewListenerAlertsEnabledChanged(bool value)
    {
        _monitor.NewListenerAlertsEnabled = value;
        _settings.NewListenerAlertsEnabled = value;
        _settings.Save();
        SettingsMessage = $"New-listener alerts: {(value ? "on" : "off")}";
    }

    partial void OnArpWatchEnabledChanged(bool value)
    {
        _monitor.ArpWatchEnabled = value;
        _settings.ArpWatchEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"ARP / gateway watch: on ({_monitor.ArpWatchStatus})"
            : "ARP / gateway watch: off";
    }

    partial void OnLaunchItemWatchEnabledChanged(bool value)
    {
        _monitor.LaunchWatchEnabled = value;
        _settings.LaunchItemWatchEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Launch-item watch: on ({_monitor.LaunchWatchStatus})"
            : "Launch-item watch: off";
    }

    partial void OnExfilMonitorEnabledChanged(bool value)
    {
        _monitor.ExfilMonitorEnabled = value;
        _settings.ExfilMonitorEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Exfiltration monitor: on ({_monitor.ExfilStatus})"
            : "Exfiltration monitor: off";
    }

    partial void OnExfilThresholdMbTextChanged(string value)
    {
        if (!int.TryParse(value?.Trim(), out var mb) || mb < 10)
        {
            SettingsMessage = "Exfiltration threshold must be a number ≥ 10 (MB per 10 minutes).";
            return;
        }

        _monitor.ExfilThresholdMb = mb;
        _settings.ExfilMbPer10Min = mb;
        _settings.Save();
        SettingsMessage = $"Exfiltration alert threshold: {mb} MB / 10 min";
    }

    // ── Remote access (web console HTTPS + DuckDNS) ────────────────────────────

    partial void OnHttpsEnabledChanged(bool value)
    {
        if (value && string.IsNullOrWhiteSpace(TlsCertPath))
        {
            SettingsMessage = "Choose a certificate first — run scripts/issue-duckdns-cert.sh to get one.";
            HttpsEnabled = false;
            return;
        }

        _settings.WebHttpsEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Web console HTTPS enabled on port {_settings.WebHttpsPort} — restart the web console to apply."
            : "Web console HTTPS disabled — restart the web console to apply.";
        RefreshRemoteAccessStatus(reloadCertificate: true);
    }

    partial void OnHttpsPortTextChanged(string value)
    {
        if (!int.TryParse(value?.Trim(), out var port) || port is < 1 or > 65535)
        {
            SettingsMessage = "HTTPS port must be a number between 1 and 65535.";
            return;
        }

        _settings.WebHttpsPort = port;
        _settings.Save();
        SettingsMessage = $"Web console HTTPS port set to {port} — restart the web console to apply.";
        RefreshRemoteAccessStatus(reloadCertificate: true);
    }

    partial void OnTlsCertPathChanged(string value) => ApplyTlsPath(certChanged: true, value);

    partial void OnTlsKeyPathChanged(string value) => ApplyTlsPath(certChanged: false, value);

    private void ApplyTlsPath(bool certChanged, string value)
    {
        var path = value?.Trim() ?? "";
        if (path.Length > 0 && !File.Exists(path))
        {
            SettingsMessage = $"File not found: {path}";
            return;
        }

        if (certChanged) _settings.WebTlsCertPath = path;
        else _settings.WebTlsKeyPath = path;
        _settings.Save();

        if (_settings.WebTlsCertPath.Length == 0)
        {
            SettingsMessage = "Certificate cleared — the web console cannot serve HTTPS without one.";
            RefreshRemoteAccessStatus(reloadCertificate: true);
            return;
        }

        // Validate now rather than at the next console start, where a bad path
        // means no console at all.
        if (TlsCertificateProvider.TryLoad(_settings.WebTlsCertPath, _settings.WebTlsKeyPath,
                _settings.WebTlsPfxPassword, out var cert, out var error))
        {
            SettingsMessage = $"Certificate OK — expires {cert!.NotAfter:yyyy-MM-dd}. " +
                              "Restart the web console to apply.";
            cert.Dispose();
        }
        else
        {
            SettingsMessage = $"Saved, but the certificate cannot be loaded yet: {error}";
        }

        RefreshRemoteAccessStatus(reloadCertificate: true);
    }

    partial void OnHttpsRedirectChanged(bool value)
    {
        _settings.WebHttpsRedirect = value;
        _settings.Save();
        SettingsMessage = value
            ? "Plain-HTTP requests that arrive by hostname will redirect to HTTPS."
            : "HTTP requests are served as-is (no HTTPS redirect).";
    }

    partial void OnDuckDnsEnabledChanged(bool value)
    {
        if (value && (DuckDnsDomain.Trim().Length == 0 || DuckDnsToken.Trim().Length == 0))
        {
            SettingsMessage = "Enter the DuckDNS subdomain and token first.";
            DuckDnsEnabled = false;
            return;
        }

        SettingsMessage = ApplyDuckDns();
    }

    partial void OnDuckDnsDomainChanged(string value) => SettingsMessage = ApplyDuckDns();

    partial void OnDuckDnsTokenChanged(string value) => SettingsMessage = ApplyDuckDns();

    private string ApplyDuckDns()
    {
        var status = _duckDns.Apply(new DuckDnsConfig
        {
            Enabled = DuckDnsEnabled,
            Domain = DuckDnsUpdater.NormalizeDomain(DuckDnsDomain),
            Token = DuckDnsToken.Trim(),
            IntervalMinutes = _duckDns.Config.IntervalMinutes
        });

        RefreshRemoteAccessStatus();
        return status;
    }

    partial void OnAcmeEmailChanged(string value)
    {
        _settings.AcmeAccountEmail = value.Trim();
        _settings.Save();
    }

    /// <summary>
    /// Issue a Let's Encrypt certificate for the saved DuckDNS name by running
    /// scripts/issue-duckdns-cert.sh, then point the console at what it produced.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanIssueCertificate))]
    private async Task IssueCertificateAsync()
    {
        var domain = DuckDnsUpdater.NormalizeDomain(DuckDnsDomain);
        if (domain.Length == 0 || DuckDnsToken.Trim().Length == 0)
        {
            SettingsMessage = "Enter the DuckDNS subdomain and token first — issuance proves control through them.";
            return;
        }

        // The token is masked in the UI; the real one lives in duckdns.json.
        var token = _duckDns.Config.Token;
        if (token.Length == 0)
        {
            SettingsMessage = "No DuckDNS token saved yet — enter one first.";
            return;
        }

        IsIssuingCertificate = true;
        IssueCertificateCommand.NotifyCanExecuteChanged();
        SettingsMessage = $"Issuing a certificate for {domain}.duckdns.org — this waits on DNS propagation and can take a few minutes…";

        try
        {
            var result = await CertIssuanceService.IssueAsync(domain, token, AcmeEmail);

            if (result.Success)
            {
                // Fill the paths in for the user; both fields stay editable.
                TlsCertPath = result.CertPath;
                if (result.KeyPath.Length > 0)
                    TlsKeyPath = result.KeyPath;

                SettingsMessage = $"{result.Message} Paths filled in below — switch HTTPS on, then restart the web console.";
            }
            else
            {
                SettingsMessage = result.Message;
            }
        }
        finally
        {
            IsIssuingCertificate = false;
            IssueCertificateCommand.NotifyCanExecuteChanged();
            RefreshRemoteAccessStatus(reloadCertificate: true);
        }
    }

    private bool CanIssueCertificate() => !IsIssuingCertificate;

    /// <summary>Refresh the DuckDNS record immediately instead of waiting for the next cycle.</summary>
    [RelayCommand]
    private async Task UpdateDuckDnsNowAsync()
    {
        if (!_duckDns.Config.IsUsable)
        {
            SettingsMessage = "Enter the DuckDNS subdomain and token, then switch DuckDNS on.";
            return;
        }

        SettingsMessage = "Updating DuckDNS…";
        await _duckDns.UpdateOnceAsync();
        SettingsMessage = _duckDns.Status;
        RefreshRemoteAccessStatus();
    }

    /// <summary>
    /// Cached HTTPS half of the remote-access status. Reading and parsing the certificate
    /// is far too expensive to redo on the one-second clock tick, and it only changes when
    /// one of these settings does.
    /// </summary>
    private string _httpsStatusPart = "";

    private void RefreshRemoteAccessStatus(bool reloadCertificate = false)
    {
        if (reloadCertificate || _httpsStatusPart.Length == 0)
            _httpsStatusPart = BuildHttpsStatusPart();

        var parts = new List<string> { _httpsStatusPart, _duckDns.Status };
        if (_duckDns.Config.IsUsable && _settings.WebHttpsEnabled)
            parts.Add($"Console URL: https://{_duckDns.Hostname}:{_settings.WebHttpsPort}/");

        var text = string.Join("  ·  ", parts);
        if (text != RemoteAccessStatus)
            RemoteAccessStatus = text;
    }

    private string BuildHttpsStatusPart()
    {
        if (!_settings.WebHttpsEnabled)
            return "HTTPS off — the web console serves plain HTTP only.";

        if (TlsCertificateProvider.TryLoad(_settings.WebTlsCertPath, _settings.WebTlsKeyPath,
                _settings.WebTlsPfxPassword, out var cert, out var error))
        {
            var text = $"HTTPS ready on port {_settings.WebHttpsPort} — certificate expires {cert!.NotAfter:yyyy-MM-dd}.";
            cert.Dispose();
            return text;
        }

        return $"HTTPS enabled but the certificate cannot be loaded: {error}";
    }

    private string BuildRemoteAccessStatus()
    {
        _httpsStatusPart = BuildHttpsStatusPart();
        var parts = new List<string> { _httpsStatusPart, _duckDns.Status };
        if (_duckDns.Config.IsUsable && _settings.WebHttpsEnabled)
            parts.Add($"Console URL: https://{_duckDns.Hostname}:{_settings.WebHttpsPort}/");
        return string.Join("  ·  ", parts);
    }

    partial void OnHoneypotEnabledChanged(bool value)
    {
        _monitor.HoneypotPorts = HoneypotService.ParsePorts(HoneypotPortsText);
        _monitor.HoneypotEnabled = value;
        _settings.HoneypotEnabled = value;
        _settings.Save();
        SettingsMessage = value ? _monitor.HoneypotStatus : "Honeypot: off";
    }

    partial void OnHoneypotPortsTextChanged(string value)
    {
        var ports = HoneypotService.ParsePorts(value);
        if (ports.Count == 0)
        {
            SettingsMessage = "Enter decoy ports as a comma-separated list, e.g. 2323,3389,5900.";
            return;
        }

        _settings.HoneypotPorts = string.Join(",", ports);
        _settings.Save();
        _monitor.HoneypotPorts = ports;
        SettingsMessage = HoneypotEnabled
            ? _monitor.HoneypotStatus
            : $"Decoy ports saved ({_settings.HoneypotPorts}) — enable the honeypot to arm them.";
    }

    partial void OnWebhookUrlChanged(string value)
    {
        var url = value?.Trim() ?? "";
        _monitor.WebhookUrl = url;
        _settings.WebhookUrl = url;
        _settings.Save();
        SettingsMessage = string.IsNullOrEmpty(url)
            ? "Webhook alerts: off"
            : $"Webhook alerts: Critical threats will POST to {url}";
    }

    partial void OnSelectedAutoBlockExpiryChanged(string value)
    {
        var minutes = ExpiryLabelToMinutes(value);
        _settings.AutoBlockExpiryMinutes = minutes;
        _settings.Save();
        _firewall.AutoBlockExpiry = ExpiryMinutesToSpan(minutes);
        SettingsMessage = minutes == 0
            ? "Auto-block rules are permanent until removed."
            : $"New auto-block rules expire after {value}.";
    }

    private static int ExpiryLabelToMinutes(string? label) => label switch
    {
        "1 hour" => 60,
        "6 hours" => 360,
        "24 hours" => 1440,
        "7 days" => 10_080,
        _ => 0
    };

    private static string ExpiryMinutesToLabel(int minutes) => minutes switch
    {
        60 => "1 hour",
        360 => "6 hours",
        1440 => "24 hours",
        10_080 => "7 days",
        _ => "Never (permanent)"
    };

    // One definition, in SentinelCore — the three frontends each had their own.
    private static TimeSpan? ExpiryMinutesToSpan(int minutes)
        => SentinelCore.ExpiryMinutesToSpan(minutes);

    private void RefreshMonitorStatusText()
    {
        AuthLogStatusText = string.IsNullOrWhiteSpace(_monitor.AuthLogStatus)
            ? (AuthLogMonitorEnabled ? "Starting…" : "Disabled.")
            : _monitor.AuthLogStatus;
        ProbeLogStatusText = string.IsNullOrWhiteSpace(_monitor.ProbeLogStatus)
            ? (ProbeLogEnabled ? "Starting…" : "Disabled — no firewall rule installed.")
            : _monitor.ProbeLogStatus;
    }

    private static int PollLabelToMs(string? label) => label switch
    {
        "0.5 seconds" => 500,
        "2.5 seconds" => 2500,
        "5 seconds" => 5000,
        "10 seconds" => 10_000,
        _ => NetworkMonitorService.DefaultPollIntervalMs
    };

    private static string PollMsToLabel(int ms) => ms switch
    {
        500 => "0.5 seconds",
        2500 => "2.5 seconds",
        5000 => "5 seconds",
        10_000 => "10 seconds",
        _ => "1.2 seconds (default)"
    };

    [RelayCommand]
    private void ToggleMonitoring()
    {
        if (Stats.IsMonitoring)
            _monitor.Stop();
        else
            _monitor.Start();
    }

    [RelayCommand]
    private void ToggleAutoBlock() => AutoBlockEnabled = !AutoBlockEnabled;

    [RelayCommand]
    private void ClearThreats() => _monitor.ClearThreats();

    [RelayCommand]
    private void RefreshNow()
    {
        RefreshCollections();
        if (ShowFirewall) RefreshFirewallRules();
    }

    [RelayCommand]
    private void RefreshFirewallRules()
    {
        IsAdmin = _firewall.IsAdministrator;
        FirewallStatusText = _firewall.PrivilegeText;
        try
        {
            _prevention.RefreshBlockedIpsNow();
            var rules = _firewall.GetManagedRules();
            FirewallRules.Clear();
            foreach (var rule in rules)
                FirewallRules.Add(rule);
        }
        catch (Exception ex)
        {
            FirewallMessage = $"Could not read firewall rules: {ex.Message}";
        }

        foreach (var host in RemoteHosts)
            host.IsBlocked = _prevention.IsBlocked(host.IpAddress);
        foreach (var host in _monitor.RemoteHosts)
            host.IsBlocked = _prevention.IsBlocked(host.IpAddress);
    }

    [RelayCommand]
    private async Task RunAsAdmin()
    {
        // Pre-authorize osascript/sudo for pfctl only — do not relaunch the GUI as root.
        if (_firewall.IsRoot)
        {
            FirewallMessage = "Already running as root (prefer running as your user).";
            return;
        }

        var answer = await DialogService.ConfirmAsync(
            "Network Sentinel will request admin rights only for PF firewall tools (pfctl) via a Mac password dialog.\n\n" +
            "The app itself stays running as your user.\n\nContinue?",
            "Authorize firewall");

        if (!answer) return;

        try
        {
            var result = await Task.Run(() => _firewall.AuthorizeElevation());
            if (result.Success)
            {
                // Lifts the auto-block stand-down. It was set when the password dialog
                // was dismissed and cleared only by time, so authorizing successfully
                // used to change nothing for five minutes while the console kept
                // reporting auto-block as paused.
                _prevention.NoteElevationAuthorized();
                if (_settings.ProbeLogEnabled)
                    await Task.Run(() => _firewall.EnableProbeLogging());
            }
            FirewallMessage = result.Message;
            IsAdmin = _firewall.IsAdministrator;
            FirewallStatusText = _firewall.PrivilegeText;
            if (result.Success)
                await DialogService.ShowInfoAsync(result.Message, "Firewall authorization");
            else
                await DialogService.ShowWarningAsync(result.Message, "Authorization failed");
        }
        catch (Exception ex)
        {
            await DialogService.ShowWarningAsync(
                $"Could not authorize:\n{ex.Message}",
                "Authorization failed");
        }
    }

    [RelayCommand]
    private async Task BlockHost(RemoteHost? host)
    {
        if (host == null) return;
        await BlockIpInternal(host.IpAddress, $"Remote host block · {host.GeoSummary}");
    }

    [RelayCommand]
    private async Task UnblockHost(RemoteHost? host)
    {
        if (host == null) return;
        await UnblockIpInternal(host.IpAddress);
    }

    [RelayCommand]
    private async Task BlockThreatIp(ThreatEvent? threat)
    {
        if (threat == null) return;
        await BlockIpInternal(threat.SourceIp, $"Threat block · {threat.TypeText}: {threat.Title}");
    }

    [RelayCommand]
    private async Task BlockConnectionIp(NetworkConnection? connection)
    {
        if (connection == null) return;
        if (string.IsNullOrWhiteSpace(connection.RemoteAddress) ||
            connection.RemoteAddress is "0.0.0.0" or "::")
        {
            FirewallMessage = "This connection has no remote peer to block.";
            return;
        }

        await BlockIpInternal(connection.RemoteAddress, $"Session block · {connection.ProcessName} {connection.DisplayRemote}");
    }

    [RelayCommand]
    private async Task BlockSelectedPort(ListeningPort? port)
    {
        if (port == null) return;

        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var answer = await DialogService.ConfirmAsync(
            $"Block inbound traffic to local {port.Protocol} port {port.Port}?\n\n" +
            $"Service: {port.ServiceHint}\nProcess: {port.ProcessName}\n\n" +
            "This creates a host firewall drop rule for that port on this PC.",
            "Block local port");

        if (!answer) return;

        // Off the UI thread: firewall calls shell out to osascript/pfctl, and the
        // admin password dialog would otherwise freeze the whole window.
        var result = await Task.Run(() => _firewall.BlockPort(
            port.Port,
            port.Protocol,
            FirewallDirection.Inbound,
            $"Port block · {port.ServiceHint} · {port.ProcessName}"));

        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Firewall");
        RefreshFirewallRules();
    }

    [RelayCommand]
    private async Task BlockManualIp()
    {
        if (string.IsNullOrWhiteSpace(ManualBlockIp))
        {
            FirewallMessage = "Enter an IP address to block.";
            return;
        }

        if (await BlockIpInternal(ManualBlockIp.Trim(), "Manual block from Firewall tab"))
            ManualBlockIp = "";
    }

    [RelayCommand]
    private async Task UnblockManualIp()
    {
        if (string.IsNullOrWhiteSpace(ManualBlockIp))
        {
            FirewallMessage = "Enter an IP address to unblock.";
            return;
        }

        await UnblockIpInternal(ManualBlockIp.Trim());
    }

    [RelayCommand]
    private async Task BlockManualPort()
    {
        if (!int.TryParse(ManualBlockPort, out var port))
        {
            FirewallMessage = "Enter a valid port number (1–65535).";
            return;
        }

        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var direction = ResolveDirection();
        var result = await Task.Run(() =>
            _firewall.BlockPort(port, ManualBlockProtocol, direction, "Manual port block from Firewall tab"));
        FirewallMessage = result.Message;
        if (!result.Success)
            await DialogService.ShowWarningAsync(result.Message, "Firewall");
        RefreshFirewallRules();
    }

    [RelayCommand]
    private async Task RemoveSelectedRule(FirewallRuleInfo? rule = null)
    {
        rule ??= SelectedFirewallRule;
        if (rule == null)
        {
            FirewallMessage = "Select a rule to remove.";
            return;
        }

        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var name = rule.Name;
        var answer = await DialogService.ConfirmAsync($"Remove firewall rule?\n\n{name}", "Remove rule");
        if (!answer) return;

        var result = await Task.Run(() => _firewall.RemoveRule(name));
        FirewallMessage = result.Message;
        SelectedFirewallRule = null;
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private async Task RemoveAllManagedRules()
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var answer = await DialogService.ConfirmAsync(
            "Remove ALL Network Sentinel firewall rules from the host firewall?\n\nThis cannot be undone (you can re-block later).",
            "Remove all managed rules");
        if (!answer) return;

        var result = await Task.Run(() => _firewall.RemoveAllManagedRules());
        FirewallMessage = result.Message;
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private async Task RefreshAllowlistAsync()
    {
        AllowlistStatusText = "Refreshing allowlist (DNS + optional remote feed)…";
        try
        {
            await _allowlist.RefreshAsync();
            SyncAllowlistUi();
            if (IsAdmin)
            {
                var restored = await Task.Run(() => _firewall.UnblockAllowlistedAddresses());
                FirewallMessage = restored.Message;
                RefreshFirewallRules();
                RefreshCollections();
            }
        }
        catch (Exception ex)
        {
            AllowlistStatusText = $"Refresh failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task AddAllowlistEntry()
    {
        var input = AllowlistInput.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            FirewallMessage = "Enter a domain (github.com) or IP to protect.";
            return;
        }

        bool ok;
        string message;
        if (System.Net.IPAddress.TryParse(input, out _))
            ok = _allowlist.TryAddIp(input, out message);
        else
            ok = _allowlist.TryAddDomain(input, out message);

        FirewallMessage = message;
        AllowlistStatusText = message;
        if (ok)
        {
            AllowlistInput = "";
            SyncAllowlistUi();
            if (IsAdmin)
            {
                var restored = await Task.Run(() => _firewall.UnblockAllowlistedAddresses());
                if (restored.Success)
                    FirewallMessage = message + " · " + restored.Message;
                RefreshFirewallRules();
            }
        }
        else
        {
            await DialogService.ShowInfoAsync(message, "Allowlist");
        }
    }

    [RelayCommand]
    private async Task RemoveAllowlistEntry()
    {
        if (SelectedAllowlistEntry == null)
        {
            FirewallMessage = "Select an allowlist entry to remove.";
            return;
        }

        if (SelectedAllowlistEntry.Kind == "Resolved")
        {
            await DialogService.ShowInfoAsync(
                "Resolved IPs come from domain DNS. Remove the Domain entry instead, or wait for the next refresh.",
                "Allowlist");
            return;
        }

        if (!_allowlist.TryRemove(SelectedAllowlistEntry.Value, SelectedAllowlistEntry.Kind, out var message))
        {
            await DialogService.ShowInfoAsync(message, "Allowlist");
            return;
        }

        FirewallMessage = message;
        SelectedAllowlistEntry = null;
        SyncAllowlistUi();
    }

    [RelayCommand]
    private async Task RestoreAllowlisted()
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var result = await Task.Run(() => _firewall.UnblockAllowlistedAddresses());
        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Restore allowlisted");
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private async Task OpenAllowlistFolder()
    {
        try
        {
            _allowlist.EnsureUserDatabaseExists();
            var dir = Path.GetDirectoryName(_allowlist.LocalDatabasePath)!;
            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            await DialogService.ShowWarningAsync(ex.Message, "Open allowlist folder");
        }
    }

    private async Task<bool> BlockIpInternal(string ip, string reason)
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return false;
        }

        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out var error))
        {
            FirewallMessage = error;
            await DialogService.ShowWarningAsync(error, "Block IP");
            return false;
        }

        if (FirewallService.IsNeverBlockable(normalized))
        {
            FirewallMessage = "Private/local addresses are not blocked by default (would break LAN).";
            await DialogService.ShowInfoAsync(FirewallMessage, "Block IP");
            return false;
        }

        // Auto-block never touches CGNAT, but the operator can — after being told what
        // it costs, because this is where a VPN client's own tunnel gets cut.
        if (GeoIpService.IsCarrierGradeNat(normalized))
        {
            var proceed = await DialogService.ConfirmAsync(
                $"{normalized} is in the carrier-NAT range (100.64.0.0/10) used by Tailscale and VPN tunnels.\n\n" +
                "Blocking it will cut off that tunnel peer. Block it anyway?",
                "Block IP");
            if (!proceed)
            {
                FirewallMessage = "Block cancelled.";
                return false;
            }
        }

        bool overrideAllowlist = false;
        if (_allowlist.IsAllowed(normalized, out var allowReason))
        {
            var overrideAnswer = await DialogService.ConfirmAsync(
                $"{normalized} is protected by the allowlist ({allowReason}).\n\n" +
                "Blocking it may break trusted services (GitHub, Microsoft, DNS, …).\n\nBlock it anyway?",
                "Allowlist protection");

            if (!overrideAnswer)
            {
                FirewallMessage = $"Protected by allowlist — not blocked: {normalized} ({allowReason}).";
                return false;
            }

            overrideAllowlist = true;
        }

        var direction = ResolveDirection();
        var answer = await DialogService.ConfirmAsync(
            $"Create host firewall DROP rules for:\n\n{normalized}\nDirection: {direction}\n\n{reason}\n\nInbound blocks stop them reaching you; outbound stops this PC talking back.",
            "Block IP in host firewall");

        if (!answer) return false;

        var result = await Task.Run(() => _firewall.BlockIp(normalized, direction, reason, overrideAllowlist));
        if (result.Success)
        {
            // Blocking by hand is an explicit reversal of an earlier release — without
            // this, a prior manual unblock kept suppressing auto-block for 24 h.
            _prevention.ClearSuppression(normalized);
            _prevention.NoteBlocked(normalized);
        }
        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Firewall");

        RefreshFirewallRules();
        RefreshCollections();
        return result.Success;
    }

    private async Task UnblockIpInternal(string ip)
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var result = await Task.Run(() => _firewall.UnblockIp(ip));
        if (result.Success && FirewallService.TryNormalizeIp(ip, out var normalized, out _))
        {
            // Suppresses auto-block for 24 h so a deliberate release isn't undone by
            // the next detection, and persists across restarts.
            _prevention.NoteUnblocked(normalized);
        }
        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Firewall");

        RefreshFirewallRules();
        RefreshCollections();
    }

    private FirewallDirection ResolveDirection()
    {
        if (BlockInbound && BlockOutbound) return FirewallDirection.Both;
        if (BlockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Inbound;
    }

    private async Task PromptElevation()
    {
        FirewallMessage = "Admin rights required for firewall changes (Mac password dialog).";
        var answer = await DialogService.ConfirmAsync(
            "Changing host firewall rules needs admin rights.\n\n" +
            "The app will ask for your Mac admin password — it will NOT restart as root.\n\nAuthorize now?",
            "Elevation required");
        if (answer)
            await RunAsAdmin();
    }

    private static string FormatAppVersion()
    {
        var asm = Assembly.GetExecutingAssembly();
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            var plus = info.IndexOf('+');
            if (plus >= 0)
                info = info[..plus];
            return info.StartsWith("v", StringComparison.OrdinalIgnoreCase) ? info : $"v{info}";
        }

        var version = asm.GetName().Version;
        return version is null ? "v0.2.0" : $"v{version.Major}.{version.Minor}.{version.Build}";
    }

    public void Dispose()
    {
        _clockTimer.Stop();
        _monitor.Updated -= OnMonitorUpdated;
        _monitor.ThreatsDetected -= OnThreatsDetected;
        _traffic.Updated -= OnTrafficUpdated;
        PersistSettings();
        _duckDns.Dispose();
        _core.Dispose();
    }
}
