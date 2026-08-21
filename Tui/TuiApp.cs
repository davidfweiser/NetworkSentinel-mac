using System.Reflection;
using System.Text;
using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace NetworkSentinel.Tui;

/// <summary>
/// Terminal UI for Network Sentinel — same monitoring / firewall services as the Avalonia GUI.
/// Launch with <c>--tui</c> or when no graphical display is available.
/// </summary>
public sealed class TuiApp : IDisposable
{
    private enum View
    {
        Dashboard = 0,
        Connections = 1,
        Hosts = 2,
        Threats = 3,
        Ports = 4,
        Firewall = 5,
        Allowlist = 6,
        Settings = 7,
        Help = 8
    }

    private static readonly string[] ViewNames =
    [
        "Dashboard", "Connections", "Hosts", "Threats", "Ports", "Firewall", "Allowlist", "Settings", "Help"
    ];

    /// <summary>
    /// Spectre.Console forbids Ask/Confirm/Status while Live is running.
    /// Keys only schedule a prompt; Live exits, we run the prompt, then Live restarts.
    /// </summary>
    private enum PromptKind
    {
        None,
        Filter,
        Authorize,
        Block,
        Unblock,
        AddAllowlist,
        RemoveAllowlist,
        RefreshAllowlist,
        RestoreAllowlisted,
        EditSetting,
        IssueCertificate
    }

    // The shared graph is built and cross-wired by SentinelCore; these are views
    // onto it so the rest of this class reads unchanged.
    private readonly SentinelCore _core = new();
    private readonly NetworkMonitorService _monitor;
    private readonly FirewallService _firewall;
    private readonly AllowlistService _allowlist;
    private readonly AppSettings _settings;
    // The blocked set, the retry backoff and the suppression list all live in
    // PreventionService now — this class kept its own copies of all three.
    private readonly PreventionService _prevention;

    private View _view = View.Dashboard;
    private string _filter = "";
    private string _statusMessage = "TUI ready — monitoring started.";
    private int _selectedIndex;
    private int _scrollOffset;
    private bool _running = true;
    private bool _autoBlockEnabled;
    private string _autoBlockMinLevel;
    private bool _blockInbound;
    private bool _blockOutbound;
    private PromptKind _pendingPrompt = PromptKind.None;
    private string _appVersion = FormatAppVersion();

    /// <summary>The editable settings, built once against the same service graph.</summary>
    private readonly TuiSettings _tuiSettings;

    /// <summary>
    /// Settings stay hidden until firewall elevation has actually been authorised
    /// this session (or we are already root). The screen writes the same file the
    /// desktop and web console read, so it is not something to leave open on a
    /// terminal somebody walked away from.
    /// </summary>
    private bool _settingsUnlocked;

    public TuiApp()
    {
        _settings = _core.Settings;
        _monitor = _core.Monitor;
        _firewall = _core.Firewall;
        _allowlist = _core.Allowlist;
        _prevention = _core.Prevention;
        _tuiSettings = new TuiSettings(_core);
        _settingsUnlocked = _firewall.IsRoot;
        _autoBlockEnabled = _settings.AutoBlockEnabled;
        _autoBlockMinLevel = _settings.AutoBlockMinLevel;
        if (_autoBlockMinLevel is not (nameof(ThreatLevel.Medium) or nameof(ThreatLevel.High) or nameof(ThreatLevel.Critical)))
            _autoBlockMinLevel = nameof(ThreatLevel.High);
        _blockInbound = _settings.AutoBlockInbound;
        _blockOutbound = _settings.AutoBlockOutbound;
        // The clamp above can change the level, so push it to the engine explicitly.
        _prevention.MinLevel = Enum.TryParse<ThreatLevel>(_autoBlockMinLevel, true, out var lvl)
            ? lvl
            : ThreatLevel.High;

        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
    }

    public async Task RunAsync()
    {
        if (!AnsiConsole.Profile.Capabilities.Interactive)
        {
            AnsiConsole.MarkupLine("[red]Interactive terminal required for TUI mode.[/]");
            AnsiConsole.MarkupLine("Run from a real TTY, or use the Avalonia GUI without [cyan]--tui[/].");
            return;
        }

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _running = false;
        };

        AnsiConsole.Clear();
        AnsiConsole.MarkupLine("[bold cyan]Network Sentinel[/] [grey]TUI[/] — loading…");

        try
        {
            await _allowlist.InitializeAsync();
            _statusMessage = _allowlist.StatusText;
        }
        catch (Exception ex)
        {
            _statusMessage = $"Allowlist load error: {ex.Message}";
        }

        RefreshBlockedIps(force: true);
        _monitor.Start();

        try
        {
            // Live display and interactive prompts cannot run at the same time in Spectre.Console.
            // Loop: draw until a key requests a prompt → exit Live → prompt on plain console → redraw.
            while (_running)
            {
                await AnsiConsole.Live(BuildRoot())
                    .AutoClear(true)
                    .Overflow(VerticalOverflow.Ellipsis)
                    .Cropping(VerticalOverflowCropping.Bottom)
                    .StartAsync(async ctx =>
                    {
                        while (_running && _pendingPrompt == PromptKind.None)
                        {
                            ctx.UpdateTarget(BuildRoot());
                            ctx.Refresh();

                            // Input is polled far more often than the tables are rebuilt.
                            // Drawing and reading used to share one 200ms tick, which meant
                            // at most five keys a second: arrow presses queued in the
                            // terminal buffer and arrived long after the eye had moved on,
                            // so the cursor drifted past the row you were aiming at. Now a
                            // keypress is picked up within ~20ms and forces an immediate
                            // redraw, while an idle screen still refreshes on the slow tick.
                            for (var slice = 0; slice < 10; slice++)
                            {
                                if (HandleInput())
                                    break;
                                if (!_running || _pendingPrompt != PromptKind.None)
                                    break;
                                await Task.Delay(20);
                            }
                        }
                    });

                if (!_running)
                    break;

                if (_pendingPrompt != PromptKind.None)
                {
                    var kind = _pendingPrompt;
                    _pendingPrompt = PromptKind.None;
                    // Leave alternate/live screen so stdin prompts are stable.
                    AnsiConsole.Clear();
                    AnsiConsole.Cursor.Show();
                    try
                    {
                        await RunPromptAsync(kind);
                    }
                    finally
                    {
                        try { AnsiConsole.Cursor.Hide(); } catch { /* ignore */ }
                    }
                }
            }
        }
        finally
        {
            _monitor.Stop();
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[grey]Network Sentinel TUI stopped.[/]");
        }
    }

    private void OnMonitorUpdated()
    {
        // Live loop redraws on its own cadence; nothing to marshal to UI thread.
        RefreshBlockedIps(force: false);
    }

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (!_autoBlockEnabled || threats.Count == 0)
            return;

        _ = Task.Run(() =>
        {
            try
            {
                ProcessAutoBlocks(threats);
            }
            catch (Exception ex)
            {
                _statusMessage = $"Auto-block error: {ex.Message}";
            }
        });
    }

    /// <summary>
    /// Every gate and every rule write lives in PreventionService now. This used to be
    /// one of three near-identical copies that had drifted — this one never honoured
    /// the manual-unblock suppression list, so the TUI would re-block an address the
    /// user had just deliberately released.
    /// </summary>
    private void ProcessAutoBlocks(IReadOnlyList<ThreatEvent> threats)
    {
        var result = _prevention.Apply(threats);
        if (!result.HasMessages)
            return;

        _statusMessage = result.Summary;
        if (result.RulesChanged)
            RefreshBlockedIps(force: true);
    }

    private FirewallDirection ResolveDirection() => _prevention.ResolveDirection();

    private void RefreshBlockedIps(bool force)
        => _prevention.RefreshBlockedIps(force, set =>
        {
            foreach (var host in _monitor.RemoteHosts)
                host.IsBlocked = set.Contains(host.IpAddress);
        });

    /// <summary>
    /// Handles every key waiting in the buffer, not one per frame. Holding an arrow
    /// down enqueues keys faster than a frame tick can retire them, and a one-per-tick
    /// reader turns that backlog into a cursor that keeps moving after you let go.
    /// </summary>
    /// <returns>True when at least one key was handled, so the caller can redraw now.</returns>
    private bool HandleInput()
    {
        var handled = false;
        while (_pendingPrompt == PromptKind.None && _running && Console.KeyAvailable)
        {
            HandleKey(Console.ReadKey(true));
            handled = true;
        }
        return handled;
    }

    private void HandleKey(ConsoleKeyInfo key)
    {
        switch (key.Key)
        {
            case ConsoleKey.Q when key.Modifiers == ConsoleModifiers.None:
                _running = false;
                return;

            case ConsoleKey.D1:
            case ConsoleKey.NumPad1:
                SwitchView(View.Dashboard);
                break;
            case ConsoleKey.D2:
            case ConsoleKey.NumPad2:
                SwitchView(View.Connections);
                break;
            case ConsoleKey.D3:
            case ConsoleKey.NumPad3:
                SwitchView(View.Hosts);
                break;
            case ConsoleKey.D4:
            case ConsoleKey.NumPad4:
                SwitchView(View.Threats);
                break;
            case ConsoleKey.D5:
            case ConsoleKey.NumPad5:
                SwitchView(View.Ports);
                break;
            case ConsoleKey.D6:
            case ConsoleKey.NumPad6:
                SwitchView(View.Firewall);
                break;
            case ConsoleKey.D7:
            case ConsoleKey.NumPad7:
                SwitchView(View.Allowlist);
                break;
            case ConsoleKey.D8:
            case ConsoleKey.NumPad8:
                SwitchView(View.Settings);
                break;
            case ConsoleKey.D9:
            case ConsoleKey.NumPad9:
            case ConsoleKey.H:
            case ConsoleKey.F1:
            case ConsoleKey.Oem2 when key.Modifiers == ConsoleModifiers.Shift: // ?
                SwitchView(View.Help);
                break;

            // Enter edits the selected setting. Toggles and choices flip in place;
            // anything that needs typing schedules a prompt, because Spectre forbids
            // Ask() while the Live display is running.
            case ConsoleKey.Enter when _view == View.Settings:
                HandleSettingsEnter();
                break;

            case ConsoleKey.Tab:
                SwitchView((View)(((int)_view + 1) % ViewNames.Length));
                break;

            case ConsoleKey.UpArrow:
            case ConsoleKey.K:
                MoveSelection(-1);
                break;
            case ConsoleKey.DownArrow:
            case ConsoleKey.J:
                MoveSelection(1);
                break;
            case ConsoleKey.PageUp:
                MoveSelection(-10);
                break;
            case ConsoleKey.PageDown:
                MoveSelection(10);
                break;
            case ConsoleKey.Home:
                _selectedIndex = 0;
                _scrollOffset = 0;
                break;
            case ConsoleKey.End:
                MoveSelection(10_000);
                break;

            case ConsoleKey.P:
                ToggleMonitoring();
                break;
            case ConsoleKey.A:
                ToggleAutoBlock();
                break;
            case ConsoleKey.C:
                _monitor.ClearThreats();
                _statusMessage = "Threat alerts cleared.";
                break;
            case ConsoleKey.R:
                if (_view == View.Allowlist)
                    _pendingPrompt = PromptKind.RefreshAllowlist;
                else
                {
                    RefreshBlockedIps(force: true);
                    _statusMessage = "Firewall / block list refreshed.";
                }
                break;
            case ConsoleKey.U:
                _pendingPrompt = PromptKind.Authorize;
                break;
            case ConsoleKey.B:
                _pendingPrompt = PromptKind.Block;
                break;
            case ConsoleKey.X:
                _pendingPrompt = PromptKind.Unblock;
                break;
            case ConsoleKey.M:
                CycleMinLevel();
                break;
            case ConsoleKey.N:
            case ConsoleKey.Insert:
            case ConsoleKey.OemPlus:
            case ConsoleKey.Add:
                _pendingPrompt = PromptKind.AddAllowlist;
                break;
            case ConsoleKey.D when key.Modifiers == ConsoleModifiers.None:
            case ConsoleKey.Delete:
                // Immediate validation (no console prompt needed for some cases)
                if (_view != View.Allowlist)
                {
                    _statusMessage = "Switch to Allowlist (7), select a Domain/IP row, then press d.";
                    break;
                }
                _pendingPrompt = PromptKind.RemoveAllowlist;
                break;
            case ConsoleKey.G:
                _pendingPrompt = PromptKind.RestoreAllowlisted;
                break;
            case ConsoleKey.Oem2: // /
            case ConsoleKey.F:
                _pendingPrompt = PromptKind.Filter;
                break;
            case ConsoleKey.Escape:
                if (!string.IsNullOrEmpty(_filter))
                {
                    _filter = "";
                    _selectedIndex = 0;
                    _scrollOffset = 0;
                    _statusMessage = "Filter cleared.";
                }
                else
                {
                    _running = false;
                }
                break;

            case ConsoleKey.L when key.Modifiers == ConsoleModifiers.Control:
                _filter = "";
                _selectedIndex = 0;
                _scrollOffset = 0;
                _statusMessage = "Filter cleared.";
                break;
        }
    }

    private async Task RunPromptAsync(PromptKind kind)
    {
        try
        {
            switch (kind)
            {
                case PromptKind.Filter:
                    RunPromptFilter();
                    break;
                case PromptKind.Authorize:
                    RunPromptAuthorize();
                    break;
                case PromptKind.Block:
                    RunPromptBlock();
                    break;
                case PromptKind.Unblock:
                    RunPromptUnblock();
                    break;
                case PromptKind.AddAllowlist:
                    RunPromptAddAllowlist();
                    break;
                case PromptKind.RemoveAllowlist:
                    RunPromptRemoveAllowlist();
                    break;
                case PromptKind.RefreshAllowlist:
                    await RunPromptRefreshAllowlistAsync();
                    break;
                case PromptKind.RestoreAllowlisted:
                    RunPromptRestoreAllowlisted();
                    break;
                case PromptKind.EditSetting:
                    RunPromptEditSetting();
                    break;
                case PromptKind.IssueCertificate:
                    await RunPromptIssueCertificateAsync();
                    break;
            }
        }
        catch (Exception ex)
        {
            _statusMessage = $"Prompt failed: {ex.Message}";
        }

        // Drain any leftover keypresses from the prompt (e.g. Enter echo).
        while (Console.KeyAvailable)
            Console.ReadKey(true);
    }

    /// <summary>Plain stdin prompt — safe after Live display has exited.</summary>
    private static string ReadLine(string label, string defaultValue = "")
    {
        if (!string.IsNullOrEmpty(defaultValue))
            Console.Write($"{label} [{defaultValue}]: ");
        else
            Console.Write($"{label}: ");

        var line = Console.ReadLine();
        if (line == null)
            return defaultValue;
        line = line.Trim();
        return line.Length == 0 ? defaultValue : line;
    }

    private static bool Confirm(string message, bool defaultYes = false)
    {
        var hint = defaultYes ? "Y/n" : "y/N";
        Console.Write($"{message} [{hint}] ");
        var line = Console.ReadLine()?.Trim() ?? "";
        if (line.Length == 0)
            return defaultYes;
        return line is "y" or "Y" or "yes" or "YES";
    }

    private void SwitchView(View view)
    {
        _view = view;
        _selectedIndex = 0;
        _scrollOffset = 0;
    }

    private void MoveSelection(int delta)
    {
        var count = GetRowCount();
        if (count <= 0)
        {
            _selectedIndex = 0;
            return;
        }

        _selectedIndex = Math.Clamp(_selectedIndex + delta, 0, count - 1);
        var visible = Math.Max(5, Console.WindowHeight - 16);
        if (_selectedIndex < _scrollOffset)
            _scrollOffset = _selectedIndex;
        else if (_selectedIndex >= _scrollOffset + visible)
            _scrollOffset = _selectedIndex - visible + 1;
    }

    private int GetRowCount() => _view switch
    {
        View.Connections => FilterConnections().Count,
        View.Hosts => FilterHosts().Count,
        View.Threats => FilterThreats().Count,
        View.Ports => _monitor.ListeningPorts.Count,
        View.Firewall => _firewall.GetManagedRules().Count,
        View.Allowlist => FilterAllowlist().Count,
        View.Dashboard => Math.Max(FilterThreats().Count, FilterHosts().Count),
        View.Settings => _settingsUnlocked ? _tuiSettings.Items.Count : 0,
        _ => 0
    };

    private void ToggleMonitoring()
    {
        if (_monitor.Stats.IsMonitoring)
        {
            _monitor.Stop();
            _statusMessage = "Monitoring paused.";
        }
        else
        {
            _monitor.Start();
            _statusMessage = "Monitoring resumed.";
        }
    }

    private void ToggleAutoBlock()
    {
        _autoBlockEnabled = !_autoBlockEnabled;
        _settings.AutoBlockEnabled = _autoBlockEnabled;
        _settings.Save();
        _statusMessage = _autoBlockEnabled
            ? $"Auto-block ON (≥ {_autoBlockMinLevel})" +
              (_firewall.IsAdministrator ? "" : " — need admin for firewall changes")
            : "Auto-block OFF";
    }

    private void CycleMinLevel()
    {
        _autoBlockMinLevel = _autoBlockMinLevel switch
        {
            nameof(ThreatLevel.Medium) => nameof(ThreatLevel.High),
            nameof(ThreatLevel.High) => nameof(ThreatLevel.Critical),
            _ => nameof(ThreatLevel.Medium)
        };
        _settings.AutoBlockMinLevel = _autoBlockMinLevel;
        _settings.Save();
        _statusMessage = $"Auto-block minimum severity: {_autoBlockMinLevel}";
    }

    private void RunPromptFilter()
    {
        Console.WriteLine();
        Console.WriteLine("Filter (empty clears)");
        // Empty default so blank Enter clears; show current as hint only.
        Console.Write(string.IsNullOrEmpty(_filter)
            ? "Filter: "
            : $"Filter (current: {_filter}, Enter clears if blank): ");
        var line = Console.ReadLine()?.Trim() ?? "";
        // If user pressed Enter with empty and we want to keep filter, they'd retype it.
        // Spec: empty clears (same as GUI watermark behavior for filter reset via /).
        _filter = line;
        _selectedIndex = 0;
        _scrollOffset = 0;
        _statusMessage = string.IsNullOrEmpty(_filter) ? "Filter cleared." : $"Filter: {_filter}";
    }

    private void RunPromptAuthorize()
    {
        Console.WriteLine();
        if (_firewall.IsRoot)
        {
            _statusMessage = "Already root — firewall rules apply directly.";
            return;
        }

        if (!Confirm("Authorize firewall elevation (Mac admin password may be required)?"))
        {
            _statusMessage = "Authorization cancelled.";
            return;
        }

        var result = _firewall.AuthorizeElevation();
        if (result.Success)
        {
            // Lifts the auto-block stand-down, which was otherwise cleared only by
            // time — so authorizing successfully changed nothing for five minutes.
            _prevention.NoteElevationAuthorized();
            if (_settings.ProbeLogEnabled)
                _firewall.EnableProbeLogging();
            // The same password that unlocks firewall writes unlocks Settings — one
            // authorisation, not two, and never a second password prompt of our own.
            _settingsUnlocked = true;
        }
        _statusMessage = result.Message + (result.Success ? "  Settings (8) unlocked." : "");
    }

    // ── Settings ──────────────────────────────────────────────────────────────
    // The same values the desktop and web console edit, written to the same file.
    // Enter is the only edit key: it flips a toggle, advances a choice, and opens a
    // prompt for anything that has to be typed.

    /// <summary>Row the pending edit prompt belongs to.</summary>
    private int _pendingSettingIndex = -1;

    private void HandleSettingsEnter()
    {
        if (!_settingsUnlocked)
        {
            _statusMessage = "Settings are locked — press u to authorize first.";
            return;
        }

        var items = _tuiSettings.Items;
        if (items.Count == 0)
            return;

        var index = Math.Clamp(_selectedIndex, 0, items.Count - 1);
        var item = items[index];
        switch (item.Kind)
        {
            case SettingKind.Toggle:
                ApplySetting(item, item.IsOn ? "off" : "on");
                break;

            case SettingKind.Choice:
            {
                // Unknown current value lands on the first choice rather than throwing.
                var at = Array.IndexOf(item.Choices, item.Read());
                ApplySetting(item, item.Choices[(at + 1) % item.Choices.Length]);
                break;
            }

            case SettingKind.Action:
                _pendingPrompt = PromptKind.IssueCertificate;
                break;

            default:
                _pendingSettingIndex = index;
                _pendingPrompt = PromptKind.EditSetting;
                break;
        }
    }

    /// <summary>
    /// A rejected value must leave the file untouched, so the catalogue throws and
    /// nothing is saved — the footer says why instead.
    /// </summary>
    private void ApplySetting(SettingItem item, string value)
    {
        try
        {
            _statusMessage = item.Apply(value);
        }
        catch (SettingRejectedException ex)
        {
            _statusMessage = $"Not changed — {ex.Message}";
        }
        catch (Exception ex)
        {
            _statusMessage = $"Could not change {item.Label}: {ex.Message}";
        }
    }

    private void RunPromptEditSetting()
    {
        var items = _tuiSettings.Items;
        if (_pendingSettingIndex < 0 || _pendingSettingIndex >= items.Count)
            return;

        var item = items[_pendingSettingIndex];
        _pendingSettingIndex = -1;

        Console.WriteLine();
        Console.WriteLine($"{item.Label} — {item.Description}");
        if (item.Hint.Length > 0)
            Console.WriteLine($"  ({item.Hint})");
        // Enter alone keeps the current value: on a terminal, a stray Enter must not
        // silently clear a webhook URL or a resolver list. "-" is the explicit clear.
        Console.WriteLine("  Enter alone keeps the current value; type - to clear it.");
        Console.Write($"{item.Label} [{item.Read()}]: ");

        var line = Console.ReadLine();
        if (line == null || line.Trim().Length == 0)
        {
            _statusMessage = $"{item.Label} unchanged.";
            return;
        }

        var value = line.Trim();
        ApplySetting(item, value == "-" ? "" : value);
    }

    /// <summary>
    /// Let's Encrypt issuance through DuckDNS. Runs while the Live display is stopped,
    /// because it takes minutes and its output is worth watching scroll past.
    /// </summary>
    private async Task RunPromptIssueCertificateAsync()
    {
        var (domain, token, email) = _tuiSettings.AcmeInputs;

        Console.WriteLine();
        if (domain.Length == 0 || token.Length == 0)
        {
            _statusMessage = "Set the DuckDNS subdomain and token first.";
            Console.WriteLine(_statusMessage);
            return;
        }

        if (!Confirm($"Issue a Let's Encrypt certificate for {domain}.duckdns.org? This runs for several minutes."))
        {
            _statusMessage = "Certificate issuance cancelled.";
            return;
        }

        Console.WriteLine("Issuing — this waits on DuckDNS TXT propagation, so it can take a few minutes…");
        var result = await CertIssuanceService.IssueAsync(domain, token, email);

        if (result.Success && result.CertPath.Length > 0)
        {
            // Same as the console: fill the paths in, so the only thing left is
            // switching HTTPS on and restarting.
            _settings.WebTlsCertPath = result.CertPath;
            if (result.KeyPath.Length > 0)
                _settings.WebTlsKeyPath = result.KeyPath;
            _settings.Save();
            _statusMessage = $"{result.Message} Paths filled in — switch HTTPS on, then restart the console.";
        }
        else
        {
            _statusMessage = result.Message;
        }

        Console.WriteLine(_statusMessage);
        Console.WriteLine($"Full log: {CertIssuanceService.LogPath}");
        Console.Write("Press Enter to return… ");
        Console.ReadLine();
    }

    private IRenderable BuildSettingsPanel()
    {
        if (!_settingsUnlocked)
        {
            // Deliberately says what to press rather than listing any values: the point
            // of the lock is that the screen shows nothing until someone authenticates.
            return new Panel(new Markup(
                "[yellow]Settings are locked.[/]\n\n" +
                "Press [cyan]u[/] to authorize firewall elevation (your Mac admin password).\n" +
                "The same authorization unlocks this screen — settings are not shown before it.\n\n" +
                "[dim]Running as root unlocks it without a prompt.[/]"))
            {
                Header = new PanelHeader("[bold]Settings[/]"),
                Border = BoxBorder.Rounded,
                Expand = true
            };
        }

        var items = _tuiSettings.Items;
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Settings[/] ({items.Count}) — Enter edits the selected row");
        table.AddColumns(
            new TableColumn("").Width(2),
            // Trimmed with an ellipsis rather than wrapped, so a row stays a row.
            new TableColumn("Section").NoWrap(),
            new TableColumn("Setting").NoWrap(),
            new TableColumn("Value").NoWrap(),
            // One line per setting: wrapping the description doubles every row's
            // height and pushes half the catalogue off an 80-column terminal.
            new TableColumn("What it does").NoWrap());

        var visible = VisibleWindow(items.Count);
        var lastSection = "";
        for (var i = visible.start; i < visible.end; i++)
        {
            var item = items[i];
            var selected = i == _selectedIndex;
            var value = item.Read();
            var shown = item.Kind switch
            {
                SettingKind.Toggle => value == "on" ? "[green]on[/]" : "[grey]off[/]",
                SettingKind.Action => $"[cyan]{Markup.Escape(value)}[/]",
                _ => Markup.Escape(Truncate(value, 28))
            };

            // The section is printed once per run of rows, so the eye can find a group
            // without the word repeating down the whole column.
            var section = item.Section == lastSection ? "" : item.Section;
            lastSection = item.Section;

            table.AddRow(
                selected ? "[cyan]▶[/]" : " ",
                $"[dim]{Markup.Escape(section)}[/]",
                selected ? $"[cyan]{Markup.Escape(item.Label)}[/]" : Markup.Escape(item.Label),
                shown,
                $"[dim]{Markup.Escape(Truncate(item.Description, Math.Max(24, TermWidth - 62)))}[/]");
        }

        return table;
    }

    private void RunPromptBlock()
    {
        Console.WriteLine();
        var ip = TryGetSelectedIp();
        if (string.IsNullOrWhiteSpace(ip))
            ip = ReadLine("IP to block");
        else
            Console.WriteLine($"Selected: {ip}");

        if (string.IsNullOrWhiteSpace(ip))
        {
            _statusMessage = "Block cancelled (no IP).";
            return;
        }

        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Cannot block — run Authorize (u) for admin rights.";
            return;
        }

        // Same pre-flight the GUI and web console do, so all three frontends agree.
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out var error))
        {
            _statusMessage = error;
            return;
        }

        if (FirewallService.IsNeverBlockable(normalized))
        {
            _statusMessage = "Private/local addresses are not blocked (would break LAN).";
            return;
        }

        var overrideAllowlist = false;
        if (_allowlist.IsAllowed(normalized, out var allowReason))
        {
            // The GUI and web offer this override; the TUI used to just fail, so an
            // operator could not block an allowlisted address from here at all.
            if (!Confirm($"{normalized} is protected by the allowlist ({allowReason}). Block it anyway?"))
            {
                _statusMessage = $"Protected by allowlist — not blocked: {normalized} ({allowReason}).";
                return;
            }
            overrideAllowlist = true;
        }

        if (!Confirm($"Block {normalized} ({ResolveDirection()})?"))
        {
            _statusMessage = "Block cancelled.";
            return;
        }

        // Auto-block never touches CGNAT; a manual block may, once confirmed.
        if (GeoIpService.IsCarrierGradeNat(normalized) &&
            !Confirm($"{normalized} is carrier-NAT (100.64.0.0/10) — blocking it cuts off that tunnel peer. Block it anyway?"))
        {
            _statusMessage = "Block cancelled.";
            return;
        }

        var result = _firewall.BlockIp(normalized, ResolveDirection(), "TUI block", overrideAllowlist);
        _statusMessage = result.Message;
        if (result.Success)
        {
            // Blocking by hand is an explicit reversal of an earlier release — without
            // this, a prior manual unblock kept suppressing auto-block for 24 h.
            _prevention.ClearSuppression(normalized);
            _prevention.NoteBlocked(normalized);
            RefreshBlockedIps(force: true);
        }
    }

    private void RunPromptUnblock()
    {
        Console.WriteLine();
        var ip = TryGetSelectedIp();
        if (string.IsNullOrWhiteSpace(ip))
            ip = ReadLine("IP to unblock");
        else
            Console.WriteLine($"Selected: {ip}");

        if (string.IsNullOrWhiteSpace(ip))
        {
            _statusMessage = "Unblock cancelled (no IP).";
            return;
        }

        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Cannot unblock — run Authorize (u) for admin rights.";
            return;
        }

        var result = _firewall.UnblockIp(ip.Trim());
        if (result.Success && FirewallService.TryNormalizeIp(ip, out var normalized, out _))
        {
            // Suppresses auto-block for 24 h so a deliberate release isn't undone by
            // the next detection. This was the one frontend where auto-block could
            // re-block an address seconds after the operator released it.
            _prevention.NoteUnblocked(normalized);
        }
        _statusMessage = result.Message;
        RefreshBlockedIps(force: true);
    }

    private string? TryGetSelectedIp()
    {
        try
        {
            return _view switch
            {
                View.Connections => FilterConnections().ElementAtOrDefault(_selectedIndex)?.RemoteAddress,
                View.Hosts => FilterHosts().ElementAtOrDefault(_selectedIndex)?.IpAddress,
                View.Threats => FilterThreats().ElementAtOrDefault(_selectedIndex)?.SourceIp,
                View.Firewall => ExtractIpFromRule(_firewall.GetManagedRules().ElementAtOrDefault(_selectedIndex)),
                View.Dashboard => FilterThreats().ElementAtOrDefault(_selectedIndex)?.SourceIp
                                  ?? FilterHosts().ElementAtOrDefault(_selectedIndex)?.IpAddress,
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractIpFromRule(FirewallRuleInfo? rule)
    {
        if (rule == null || string.IsNullOrWhiteSpace(rule.RemoteAddresses))
            return null;
        var first = rule.RemoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return first;
    }

    private IReadOnlyList<NetworkConnection> FilterConnections()
    {
        var source = _monitor.Connections;
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(c =>
            c.DisplayLocal.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.DisplayRemote.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.StateText.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private IReadOnlyList<RemoteHost> FilterHosts()
    {
        var source = _monitor.RemoteHosts;
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(h =>
            h.IpAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.HostName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.Status.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private IReadOnlyList<ThreatEvent> FilterThreats()
    {
        var source = _monitor.Threats;
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(t =>
            t.SourceIp.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Detail.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Origin.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Method.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private IReadOnlyList<AllowlistEntryView> FilterAllowlist()
    {
        var source = _allowlist.GetEntries();
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(e =>
            e.Kind.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            e.Value.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            e.Detail.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void RunPromptAddAllowlist()
    {
        Console.WriteLine();
        Console.WriteLine("Add to allowlist — domain (github.com) or IP (1.2.3.4). Never blocked.");
        var input = ReadLine("Domain or IP");
        if (string.IsNullOrWhiteSpace(input))
        {
            _statusMessage = "Allowlist add cancelled.";
            return;
        }

        bool ok;
        string message;
        if (System.Net.IPAddress.TryParse(input, out _))
            ok = _allowlist.TryAddIp(input, out message);
        else
            ok = _allowlist.TryAddDomain(input, out message);

        _statusMessage = message;
        if (!ok)
            return;

        // Domains resolve in the background; optionally restore any blocks on allowlisted IPs.
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(800);
                if (_firewall.IsAdministrator)
                {
                    var restored = _firewall.UnblockAllowlistedAddresses();
                    if (restored.Success &&
                        !restored.Message.Contains("No allowlisted", StringComparison.OrdinalIgnoreCase))
                        _statusMessage = message + " · " + restored.Message;
                }
            }
            catch { /* best-effort */ }
        });

        if (_view != View.Allowlist)
            SwitchView(View.Allowlist);
        else
        {
            _selectedIndex = 0;
            _scrollOffset = 0;
        }
    }

    private void RunPromptRemoveAllowlist()
    {
        var rows = FilterAllowlist();
        var entry = rows.ElementAtOrDefault(_selectedIndex);
        if (entry == null)
        {
            _statusMessage = "No allowlist entry selected.";
            return;
        }

        if (entry.Kind.Equals("Resolved", StringComparison.OrdinalIgnoreCase))
        {
            _statusMessage = "Resolved IPs come from DNS of a Domain — remove the Domain entry instead.";
            return;
        }

        Console.WriteLine();
        if (!Confirm($"Remove allowlist entry {entry.Kind}: {entry.Value}?"))
        {
            _statusMessage = "Remove cancelled.";
            return;
        }

        if (!_allowlist.TryRemove(entry.Value, entry.Kind, out var message))
        {
            _statusMessage = message;
            return;
        }

        _statusMessage = message;
        var count = FilterAllowlist().Count;
        _selectedIndex = count == 0 ? 0 : Math.Clamp(_selectedIndex, 0, count - 1);
    }

    private async Task RunPromptRefreshAllowlistAsync()
    {
        Console.WriteLine();
        Console.WriteLine("Refreshing allowlist (DNS + optional remote feed)…");
        await _allowlist.RefreshAsync();
        _statusMessage = _allowlist.StatusText;
        if (_firewall.IsAdministrator)
        {
            var restored = _firewall.UnblockAllowlistedAddresses();
            if (restored.Success &&
                !restored.Message.Contains("No allowlisted", StringComparison.OrdinalIgnoreCase))
                _statusMessage += " · " + restored.Message;
        }
        RefreshBlockedIps(force: true);
        Console.WriteLine(_statusMessage);
    }

    private void RunPromptRestoreAllowlisted()
    {
        Console.WriteLine();
        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Cannot restore — press u to authorize admin rights.";
            return;
        }

        if (!Confirm("Unblock any Network Sentinel rules that hit allowlisted IPs?"))
        {
            _statusMessage = "Restore cancelled.";
            return;
        }

        var result = _firewall.UnblockAllowlistedAddresses();
        _statusMessage = result.Message;
        RefreshBlockedIps(force: true);
    }

    private IRenderable BuildRoot()
    {
        var layout = new Layout("root")
            .SplitRows(
                new Layout("header").Size(4),
                new Layout("nav").Size(3),
                new Layout("body"),
                new Layout("footer").Size(4));

        layout["header"].Update(BuildHeader());
        layout["nav"].Update(BuildNav());
        layout["body"].Update(BuildBody());
        layout["footer"].Update(BuildFooter());
        return layout;
    }

    private IRenderable BuildHeader()
    {
        var stats = _monitor.Stats;
        var mon = stats.IsMonitoring ? "[green]LIVE[/]" : "[yellow]PAUSED[/]";
        var auto = _autoBlockEnabled
            ? $"[red]AUTO ≥ {_autoBlockMinLevel}[/]"
            : "[grey]auto off[/]";
        var blocked = _prevention.BlockedCount;

        var grid = new Grid().AddColumns(5);
        grid.AddRow(
            new Markup($"[bold]Ports[/]\n[cyan bold]{stats.ListeningPorts}[/]"),
            new Markup($"[bold]Sessions[/]\n[blue bold]{stats.ActiveConnections}[/]"),
            new Markup($"[bold]Hosts[/]\n[purple bold]{stats.RemoteHosts}[/]"),
            new Markup($"[bold]Threats[/]\n[yellow bold]{stats.ThreatsToday}[/]"),
            new Markup($"[bold]High[/]\n[red bold]{stats.HighThreats}[/]"));

        return new Panel(grid)
        {
            Header = new PanelHeader(
                $"[bold cyan] Network Sentinel [/][grey]{_appVersion}[/]  {mon}  {auto}  [grey]blocked {blocked}[/]  [dim]{DateTime.Now:HH:mm:ss}[/]"),
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(Color.Grey)
        };
    }

    private IRenderable BuildNav()
    {
        var parts = new List<string>();
        for (var i = 0; i < ViewNames.Length; i++)
        {
            var label = $"{i + 1}:{ViewNames[i]}";
            if ((View)i == _view)
                parts.Add($"[black on cyan] {label} [/]");
            else
                parts.Add($"[grey]{label}[/]");
        }

        var filterHint = string.IsNullOrEmpty(_filter)
            ? "[dim]/ filter[/]"
            : $"[yellow]filter:[/] {_filter.EscapeMarkup()}";

        return new Panel(new Markup(string.Join("  ", parts) + "   " + filterHint))
        {
            Border = BoxBorder.None,
            Padding = new Padding(1, 0)
        };
    }

    private IRenderable BuildBody() => _view switch
    {
        View.Dashboard => BuildDashboard(),
        View.Connections => BuildConnectionsTable(),
        View.Hosts => BuildHostsTable(),
        View.Threats => BuildThreatsTable(),
        View.Ports => BuildPortsTable(),
        View.Firewall => BuildFirewallPanel(),
        View.Allowlist => BuildAllowlistPanel(),
        View.Settings => BuildSettingsPanel(),
        View.Help => BuildHelp(),
        _ => new Markup("Unknown view")
    };

    private IRenderable BuildDashboard()
    {
        var activity = BuildSparkline(_monitor.Activity.Select(a => (double)a.ConnectionCount).ToList(), "Activity");
        var threats = FilterThreats().Take(8).ToList();
        var hosts = FilterHosts().Take(8).ToList();

        var threatTable = new Table().Expand().Border(TableBorder.Simple);
        threatTable.AddColumns("Time", "Lvl", "IP", "Title");
        if (threats.Count == 0)
            threatTable.AddRow("-", "-", "-", "[dim]No threats yet[/]");
        else
        {
            for (var i = 0; i < threats.Count; i++)
            {
                var t = threats[i];
                var mark = i == _selectedIndex ? "[cyan]>[/] " : "  ";
                threatTable.AddRow(
                    mark + t.TimeText,
                    ColorLevel(t.Level),
                    Markup.Escape(t.SourceIp),
                    Markup.Escape(Truncate(t.Title, 40)));
            }
        }

        var hostTable = new Table().Expand().Border(TableBorder.Simple);
        // IP first (never cut for hostname length); host name is secondary.
        hostTable.AddColumns("IP", "Host", "Geo", "Threat", "Blk");
        if (hosts.Count == 0)
            hostTable.AddRow("[dim]No peers yet[/]", "-", "-", "-", "-");
        else
        {
            var hostW = Math.Max(12, (TermWidth / 2) - 28);
            var geoW = Math.Max(10, TermWidth / 8);
            foreach (var h in hosts)
            {
                h.IsBlocked = _prevention.IsBlocked(h.IpAddress);
                hostTable.AddRow(
                    Markup.Escape(h.IpAddress),
                    Markup.Escape(Truncate(h.HostName, hostW)),
                    Markup.Escape(Truncate(h.GeoSummary, geoW)),
                    ColorLevel(h.ThreatLevel),
                    h.IsBlocked ? "[red]Y[/]" : "[dim]·[/]");
            }
        }

        var split = new Layout()
            .SplitRows(
                new Layout("spark").Size(5),
                new Layout("bottom").SplitColumns(
                    new Layout("threats"),
                    new Layout("hosts")));

        split["spark"].Update(new Panel(activity) { Header = new PanelHeader("[bold]Live activity[/]"), Border = BoxBorder.Rounded });
        split["bottom"]["threats"].Update(new Panel(threatTable) { Header = new PanelHeader("[bold]Recent threats[/]"), Border = BoxBorder.Rounded });
        split["bottom"]["hosts"].Update(new Panel(hostTable) { Header = new PanelHeader("[bold]Remote hosts[/]"), Border = BoxBorder.Rounded });
        return split;
    }

    private static string BuildSparkline(IReadOnlyList<double> values, string label)
    {
        if (values.Count == 0)
            return $"[dim]{label}: waiting for samples…[/]";

        const string blocks = " ▁▂▃▄▅▆▇█";
        var max = values.Max();
        if (max <= 0) max = 1;
        var sb = new StringBuilder();
        sb.Append($"[cyan]{label}[/]  ");
        foreach (var v in values.TakeLast(48))
        {
            var idx = (int)Math.Round(v / max * (blocks.Length - 1));
            idx = Math.Clamp(idx, 0, blocks.Length - 1);
            sb.Append(blocks[idx]);
        }

        sb.Append($"  [dim]now {values[^1]:0}  peak {max:0}[/]");
        return sb.ToString();
    }

    private IRenderable BuildConnectionsTable()
    {
        var rows = FilterConnections();
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Live connections[/] ({rows.Count})");
        // Local/Remote show full endpoint (IP:port). Reverse-DNS is its own column so
        // long hostnames cannot truncate the address.
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Process"),
            new TableColumn("Local"),
            new TableColumn("Remote"),
            new TableColumn("Host"),
            new TableColumn("State"),
            new TableColumn("Geo"));

        var w = TermWidth;
        var procW = Math.Clamp(w / 10, 10, 18);
        var hostW = Math.Clamp(w / 5, 16, 40);
        var geoW = Math.Clamp(w / 6, 12, 28);
        // Endpoints: IPv6 + port can approach ~50 chars; keep room on wide terminals.
        var epW = Math.Clamp((w - 50) / 2, 22, 55);

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No matching connections[/]", "", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var c = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                var local = $"{c.LocalAddress}:{c.LocalPort}";
                var remote = string.IsNullOrWhiteSpace(c.RemoteAddress) || c.RemoteAddress is "0.0.0.0" or "::"
                    ? "—"
                    : $"{c.RemoteAddress}:{c.RemotePort}";
                table.AddRow(
                    sel,
                    Markup.Escape(Truncate(c.ProcessName, procW)),
                    Markup.Escape(Truncate(local, epW)),
                    Markup.Escape(Truncate(remote, epW)),
                    Markup.Escape(Truncate(c.RemoteHostName, hostW)),
                    Markup.Escape(c.StateText),
                    Markup.Escape(Truncate(c.GeoSummary, geoW)));
            }
        }

        return table;
    }

    private IRenderable BuildHostsTable()
    {
        var rows = FilterHosts();
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Remote computers[/] ({rows.Count})");
        // IP column is untruncated (IPv6 ≤ 45). Hostname is separate so long DNS
        // names no longer clip the address off the right edge.
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("IP"),
            new TableColumn("Host"),
            new TableColumn("Origin"),
            new TableColumn("Act").Width(4),
            new TableColumn("Threat"),
            new TableColumn("Status"),
            new TableColumn("Block"));

        var w = TermWidth;
        var hostW = Math.Clamp(w / 4, 18, 48);
        var geoW = Math.Clamp(w / 5, 14, 36);
        // IPv6 max textual length is 45; always allow full IP.
        const int ipW = 45;

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No remote hosts yet[/]", "", "", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var h = rows[i];
                h.IsBlocked = _prevention.IsBlocked(h.IpAddress);
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    Markup.Escape(Truncate(h.IpAddress, ipW)),
                    Markup.Escape(Truncate(h.HostName, hostW)),
                    Markup.Escape(Truncate(h.GeoSummary, geoW)),
                    h.ActiveConnections.ToString(),
                    ColorLevel(h.ThreatLevel),
                    Markup.Escape(Truncate(h.Status, 14)),
                    h.IsBlocked ? "[red]Blocked[/]" : "[green]Allowed[/]");
            }
        }

        return table;
    }

    private IRenderable BuildThreatsTable()
    {
        var rows = FilterThreats();
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Break-in attempts[/] ({rows.Count})");
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Time"),
            new TableColumn("Level"),
            new TableColumn("Type"),
            new TableColumn("Source IP"),
            new TableColumn("Title"),
            new TableColumn("Origin"));

        var w = TermWidth;
        var titleW = Math.Clamp(w / 4, 20, 48);
        var originW = Math.Clamp(w / 5, 16, 40);
        const int ipW = 45;

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No threat events[/]", "", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var t = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    t.TimeText,
                    ColorLevel(t.Level),
                    Markup.Escape(Truncate(t.TypeText, 18)),
                    Markup.Escape(Truncate(t.SourceIp, ipW)),
                    Markup.Escape(Truncate(t.Title, titleW)),
                    Markup.Escape(Truncate(t.Origin, originW)));
            }
        }

        return table;
    }

    private IRenderable BuildPortsTable()
    {
        var rows = _monitor.ListeningPorts;
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Open ports[/] ({rows.Count})");
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Proto"),
            new TableColumn("Endpoint"),
            new TableColumn("PID"),
            new TableColumn("Process"),
            new TableColumn("Service"));

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No listeners[/]", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var p = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    p.Protocol,
                    Markup.Escape(p.DisplayEndpoint),
                    p.ProcessId.ToString(),
                    Markup.Escape(Truncate(p.ProcessName, 20)),
                    Markup.Escape(Truncate(p.ServiceHint, 24)));
            }
        }

        return table;
    }

    private IRenderable BuildFirewallPanel()
    {
        IReadOnlyList<FirewallRuleInfo> rules;
        try
        {
            rules = _firewall.GetManagedRules();
        }
        catch (Exception ex)
        {
            return new Panel($"[red]Could not read firewall rules:[/] {Markup.Escape(ex.Message)}")
            {
                Header = new PanelHeader("[bold]Firewall[/]"),
                Border = BoxBorder.Rounded
            };
        }

        var info = new Markup(
            $"[bold]Privilege[/]: {Markup.Escape(_firewall.PrivilegeText)}\n" +
            $"[bold]Auto-block[/]: {(_autoBlockEnabled ? $"[red]ON ≥ {_autoBlockMinLevel}[/]" : "[grey]off[/]")}  " +
            $"in={_blockInbound} out={_blockOutbound}\n" +
            $"[bold]Allowlist[/]: {Markup.Escape(Truncate(_allowlist.StatusText, 70))}  [dim](view 7 · n add)[/]\n" +
            $"[bold]Blocked IPs (managed)[/]: {_prevention.BlockedCount}");

        var table = new Table().Expand().Border(TableBorder.Simple);
        table.AddColumns("", "Kind", "Dir", "Target", "Name");
        var visible = VisibleWindow(rules.Count);
        if (rules.Count == 0)
            table.AddRow(" ", "[dim]No Network Sentinel rules[/]", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var r = rules[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    Markup.Escape(r.KindText),
                    Markup.Escape(r.DirectionText),
                    Markup.Escape(Truncate(r.TargetText, 28)),
                    Markup.Escape(Truncate(r.Name, 36)));
            }
        }

        var layout = new Layout().SplitRows(
            new Layout("info").Size(6),
            new Layout("rules"));
        layout["info"].Update(new Panel(info) { Header = new PanelHeader("[bold]Firewall & block[/]"), Border = BoxBorder.Rounded });
        layout["rules"].Update(new Panel(table) { Header = new PanelHeader($"[bold]Managed rules[/] ({rules.Count})"), Border = BoxBorder.Rounded });
        return layout;
    }

    private IRenderable BuildAllowlistPanel()
    {
        var rows = FilterAllowlist();
        var info = new Markup(
            $"[bold]Known-good allowlist[/] — these domains/IPs are [green]never blocked[/] by auto-block or manual block.\n" +
            $"{Markup.Escape(Truncate(_allowlist.StatusText, 100))}\n" +
            $"[dim]File:[/] {Markup.Escape(Truncate(_allowlist.LocalDatabasePath, 70))}\n" +
            "[dim]Keys:[/] [cyan]n[/]/[cyan]+[/] add domain or IP · [cyan]d[/] remove · [cyan]r[/] refresh · [cyan]g[/] restore good sites · [cyan]/[/] filter");

        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Allowlist entries[/] ({rows.Count})");
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Kind").Width(12),
            new TableColumn("Value"),
            new TableColumn("Detail"));

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
        {
            table.AddRow(" ", "[dim]Empty — press n to add a domain or IP[/]", "", "");
        }
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var e = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                var kindColor = e.Kind.Equals("Domain", StringComparison.OrdinalIgnoreCase) ? "green"
                    : e.Kind.Equals("IP", StringComparison.OrdinalIgnoreCase) ? "cyan"
                    : e.Kind.Equals("Resolved", StringComparison.OrdinalIgnoreCase) ? "grey"
                    : "yellow";
                table.AddRow(
                    sel,
                    $"[{kindColor}]{Markup.Escape(e.Kind)}[/]",
                    Markup.Escape(Truncate(e.Value, Math.Clamp(TermWidth / 3, 32, 64))),
                    Markup.Escape(Truncate(e.Detail, Math.Clamp(TermWidth / 3, 24, 56))));
            }
        }

        var layout = new Layout().SplitRows(
            new Layout("info").Size(7),
            new Layout("list"));
        layout["info"].Update(new Panel(info)
        {
            Header = new PanelHeader("[bold]Allowlist (never block)[/]"),
            Border = BoxBorder.Rounded
        });
        layout["list"].Update(table);
        return layout;
    }

    private static IRenderable BuildHelp()
    {
        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold]Keyboard shortcuts[/]");
        table.AddColumns("Key", "Action");
        table.AddRow("1–8 / Tab", "Switch view (Dashboard…Settings)");
        table.AddRow("9 / h / F1", "Help");
        table.AddRow("↑↓ / j k", "Move selection");
        table.AddRow("PgUp/PgDn", "Scroll selection faster");
        table.AddRow("/ or f", "Set text filter");
        table.AddRow("Ctrl+L", "Clear filter");
        table.AddRow("p", "Pause / resume monitoring");
        table.AddRow("a", "Toggle auto-block");
        table.AddRow("m", "Cycle auto-block min severity");
        table.AddRow("b", "Block selected IP (or prompt)");
        table.AddRow("x", "Unblock selected IP (or prompt)");
        table.AddRow("u", "Authorize firewall elevation (admin password) — also unlocks Settings");
        table.AddRow("Enter", "On Settings: flip a toggle, cycle a choice, or edit a value");
        table.AddRow("n / + / Ins", "Add domain or IP to allowlist");
        table.AddRow("d / Del", "Remove selected allowlist Domain/IP");
        table.AddRow("g", "Restore good sites (unblock allowlisted)");
        table.AddRow("c", "Clear threat alerts");
        table.AddRow("r", "Refresh firewall cache · on Allowlist: refresh DNS/feed");
        table.AddRow("q / Esc", "Quit");
        table.AddRow("", "[dim]Allowlist data: ~/.local/share/NetworkSentinel/allowlist.json[/]");
        table.AddRow("", "[dim]Settings write the same settings.json the desktop and web console read.[/]");
        table.AddRow("", "[dim]A console already running elsewhere keeps its copy until it restarts.[/]");
        return table;
    }

    private IRenderable BuildFooter()
    {
        var stats = _monitor.Stats;
        var keys = _view switch
        {
            View.Allowlist =>
                "[dim]7 allowlist · n/+ add domain or IP · d remove · r refresh · g restore · / filter · q quit[/]",
            View.Settings when !_settingsUnlocked =>
                "[dim]8 settings · [/][yellow]locked — press u to authorize[/][dim] · h help · q quit[/]",
            View.Settings =>
                "[dim]8 settings · ↑↓ select · Enter edit · / filter · h help · q quit[/]",
            _ =>
                "[dim]1-8 views · p pause · a auto · b block · n allowlist-add · u auth · / filter · h help · q quit[/]"
        };

        // Full address of the selected row so nothing is lost if a column is still tight.
        var selection = GetSelectedSummary();
        var msg = Markup.Escape(Truncate(_statusMessage, Math.Max(40, TermWidth - 4)));
        var status = string.IsNullOrEmpty(selection)
            ? $"[grey]{Markup.Escape(Truncate(stats.StatusText, 40))}[/]  {msg}"
            : $"[grey]{Markup.Escape(Truncate(stats.StatusText, 24))}[/]  [cyan]{Markup.Escape(Truncate(selection, TermWidth - 30))}[/]  {msg}";
        return new Panel(new Markup(keys + "\n" + status))
        {
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(Color.Grey)
        };
    }

    /// <summary>Full selected address/detail for the footer (avoids hidden truncation).</summary>
    private string GetSelectedSummary()
    {
        try
        {
            return _view switch
            {
                View.Hosts => FilterHosts().ElementAtOrDefault(_selectedIndex) is { } h
                    ? (string.IsNullOrWhiteSpace(h.HostName) ? h.IpAddress : $"{h.IpAddress}  {h.HostName}")
                    : "",
                View.Connections => FilterConnections().ElementAtOrDefault(_selectedIndex) is { } c
                    ? $"{c.RemoteAddress}:{c.RemotePort}" +
                      (string.IsNullOrWhiteSpace(c.RemoteHostName) ? "" : $"  {c.RemoteHostName}")
                    : "",
                View.Threats => FilterThreats().ElementAtOrDefault(_selectedIndex) is { } t
                    ? $"{t.SourceIp}  {t.Title}"
                    : "",
                View.Allowlist => FilterAllowlist().ElementAtOrDefault(_selectedIndex) is { } e
                    ? $"{e.Kind}: {e.Value}"
                    : "",
                _ => ""
            };
        }
        catch
        {
            return "";
        }
    }

    private (int start, int end) VisibleWindow(int count)
    {
        if (count <= 0) return (0, 0);
        var height = Math.Max(5, Console.WindowHeight - 16);
        var start = Math.Clamp(_scrollOffset, 0, Math.Max(0, count - 1));
        if (_selectedIndex < start) start = _selectedIndex;
        if (_selectedIndex >= start + height) start = _selectedIndex - height + 1;
        start = Math.Clamp(start, 0, Math.Max(0, count - height));
        _scrollOffset = start;
        var end = Math.Min(count, start + height);
        return (start, end);
    }

    private static string ColorLevel(ThreatLevel level) => level switch
    {
        ThreatLevel.Critical => "[red bold]Critical[/]",
        ThreatLevel.High => "[red]High[/]",
        ThreatLevel.Medium => "[yellow]Medium[/]",
        ThreatLevel.Low => "[blue]Low[/]",
        _ => "[grey]Info[/]"
    };

    private static int TermWidth
    {
        get
        {
            try { return Math.Max(60, Console.WindowWidth); }
            catch { return 120; }
        }
    }

    private static string Truncate(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (max <= 1) return s.Length <= 1 ? s : "…";
        return s.Length <= max ? s : s[..(max - 1)] + "…";
    }

    private static string FormatAppVersion()
    {
        try
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            return v == null ? "v?" : $"v{v.Major}.{v.Minor}.{v.Build}";
        }
        catch
        {
            return "v?";
        }
    }

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _monitor.ThreatsDetected -= OnThreatsDetected;
        // Disposes the monitor and the allowlist together — the allowlist's timers
        // and HTTP client used to leak here because only this frontend forgot it.
        _core.Dispose();
    }
}
