using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Which front-end is driving <see cref="FirewallService"/>. The only thing it
/// decides is where a password could be typed: a desktop session can raise the
/// macOS admin dialog, a terminal can prompt on its own TTY, and the web console
/// can do neither — the operator is in a browser, and any dialog would have to
/// appear on the Mac they are not sitting at.
/// </summary>
public enum FirewallUiSurface
{
    /// <summary>The Avalonia GUI — osascript can raise the admin dialog.</summary>
    Desktop,

    /// <summary>The TUI over SSH or a console — sudo can prompt on the TTY.</summary>
    Terminal,

    /// <summary>The headless web console — nothing can prompt.</summary>
    Web
}

/// <summary>
/// Manages host firewall rules owned by Network Sentinel on macOS via PF
/// (<c>pfctl</c>) anchors. The GUI always runs as the normal user; privileged
/// commands are elevated per-call with <c>osascript</c> (admin password dialog)
/// or <c>sudo</c>.
/// </summary>
public sealed class FirewallService
{
    public const string RulePrefix = "NetworkSentinel";
    public const string PfAnchorName = "com.networksentinel";
    public const string ProbeLogRuleName = "NetworkSentinel-ProbeLog";

    /// <summary>
    /// Decoded PF log lines land here. pflog0 itself is only readable by root
    /// (BPF), so the privileged writer started by <see cref="EnableProbeLogging"/>
    /// decodes it to this world-readable text file and
    /// <see cref="ProbeLogMonitor"/> tails that as the normal user.
    /// </summary>
    public const string ProbeLogPath = "/var/log/networksentinel-probe.log";

    /// <summary>
    /// The decoder runs as a LaunchDaemon, not a backgrounded child. A `nohup … &amp;`
    /// started inside `do shell script … with administrator privileges` does not
    /// survive: osascript reaps the process group when the elevated shell exits, so
    /// the decoder died instantly and closed-port detection silently logged nothing.
    /// launchd is the only mechanism that keeps a root process alive here — and it
    /// restarts it (KeepAlive) and restores it after a reboot for free.
    /// </summary>
    private const string ProbeDaemonLabel = "com.networksentinel.probelog";

    private const string ProbeDaemonPlist = "/Library/LaunchDaemons/com.networksentinel.probelog.plist";
    private const string ProbeWriterPath = "/usr/local/libexec/networksentinel-probe-writer.sh";

    /// <summary>
    /// Cap on packets per tcpdump invocation. The writer loop restarts tcpdump
    /// afterwards, which truncates the log — that is what bounds the file size.
    /// ProbeLogMonitor detects the truncation and reseeks.
    /// </summary>
    private const int ProbePacketCap = 200_000;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public AllowlistService? Allowlist { get; set; }

    /// <summary>
    /// True on the one platform whose firewall this service can drive. Everything
    /// below — PF, <c>pfctl</c>, the anchor hook in /etc/pf.conf, <c>geteuid</c>,
    /// the osascript admin dialog — is macOS, and the read path is <c>lsof</c> and
    /// <c>pfctl</c>, so there is no privilege level on another OS that would let a
    /// rule be written. Checked before the elevation probes so a Linux or Windows
    /// run is told what is actually wrong instead of being sent to find a password
    /// that would not help if it were typed.
    /// </summary>
    public static bool PlatformSupported => OperatingSystem.IsMacOS();

    /// <summary>What to say instead of asking for a password the OS has no use for.</summary>
    public const string UnsupportedPlatformText =
        "Network Sentinel drives the macOS host firewall (PF, through pfctl and the com.networksentinel " +
        "anchor) and has no backend for this operating system, so no privilege level here can apply a " +
        "rule — running it as root or Administrator would not change that. Run it on a Mac; the Linux " +
        "and Windows firewalls are driven by the separate ports of this app.";

    /// <summary>True when euid is root (GUI should normally not run as root).</summary>
    public bool IsRoot => IsRootProcess();

    /// <summary>Static form, for the read path which has no instance to hand.</summary>
    internal static bool IsRootProcess()
    {
        // The P/Invoke below binds to libc; calling it off a Unix host throws every time.
        if (!PlatformSupported) return false;
        try { return geteuid() == 0; }
        catch { return false; }
    }

    /// <summary>True when firewall changes can be attempted (root or elevatable).</summary>
    public bool IsAdministrator => PlatformSupported && (IsRoot || CanElevate);

    /// <summary>
    /// Whether an elevation helper exists at all. This used to be a bare <c>true</c>,
    /// on the grounds that a Mac always has the osascript admin dialog — which is
    /// right about the binary and wrong about the operator, because the dialog opens
    /// on the Mac's own screen. See <see cref="CanApplyRules"/> for the question the
    /// callers were actually asking.
    /// </summary>
    public bool CanElevate =>
        PlatformSupported && (IsRoot || CommandExists("osascript") || CommandExists("sudo"));

    /// <summary>
    /// Which front-end is running. Set once at startup by <c>Program</c>; the default
    /// suits the GUI, which is the one process that does not set it.
    /// </summary>
    public static FirewallUiSurface Surface { get; set; } = FirewallUiSurface.Desktop;

    /// <summary>
    /// Whether a password prompt could actually reach the operator who is asking.
    /// The admin dialog osascript raises is drawn by the window server on the Mac
    /// running this process: fine for the desktop app, useless for a browser
    /// somewhere else, and there is no session to draw on under launchd at all.
    /// </summary>
    private static bool CanPromptOnThisSurface()
    {
        if (!PlatformSupported) return false;
        if (Surface == FirewallUiSurface.Web) return false;
        if (Surface == FirewallUiSurface.Desktop && CommandExists("osascript")) return true;
        return CommandExists("sudo") && HasTerminal();
    }

    /// <summary>Whether sudo could prompt on a terminal — false for a GUI started from Finder.</summary>
    private static bool HasTerminal()
    {
        try { return !Console.IsInputRedirected; }
        catch { return false; }
    }

    /// <summary>
    /// True when a rule written now would actually reach the kernel: this process is
    /// root, or sudo runs the rule script without asking, or there is somewhere on
    /// this surface to type a password.
    ///
    /// <see cref="IsAdministrator"/> only reports that some elevation helper exists,
    /// which on macOS is always — so on a headless web console it was true on a Mac
    /// where every single write fails. That is how an operator came to open the rule
    /// editor, fill it in, and learn only at Save that the console had never been
    /// able to write anything.
    /// </summary>
    public bool CanApplyRules
        => PlatformSupported && (IsRoot || CanElevateSilently() || CanPromptOnThisSurface());

    /// <summary>
    /// What to do about a Mac that cannot show the operator a prompt, as commands to
    /// run rather than a section to go and find. <paramref name="asBlock"/> keeps the
    /// newlines for a console or a preformatted block; the flowed form is for a
    /// one-line status.
    /// </summary>
    public static string HeadlessElevationHelp(bool asBlock = true)
    {
        var steps = SudoersInstallCommands();
        return asBlock
            ? $"{HeadlessElevationLead}\n\n{steps}\n\n{HeadlessElevationTail}"
            : $"{HeadlessElevationLead} {steps.Replace("\n", "  ")} {HeadlessElevationTail}";
    }

    /// <summary>
    /// The commands on their own, so a front-end that can lay out a code block does
    /// not have to pick them back out of the prose. PF rules are applied by running a
    /// generated script, so the grant has to name the shell — which is why running the
    /// console as root is offered first rather than as a fallback.
    /// </summary>
    public static string SudoersInstallCommands()
        => "sudo NetworkSentinel --web        # run the console itself as root\n" +
           "\n" +
           "# or, to keep it running as this user:\n" +
           $"echo '{SudoersGrantText()}' | sudo tee /etc/sudoers.d/networksentinel\n" +
           "sudo chmod 0440 /etc/sudoers.d/networksentinel\n" +
           "sudo visudo -c";

    /// <summary>
    /// The sudoers grant that makes writes work where nothing can prompt, with this
    /// host's own user name filled in. It names <c>/bin/bash</c> because that is what
    /// a PF rule write actually runs — the ruleset is generated and applied as a
    /// script — and callers say plainly that this is a root shell in all but name.
    /// </summary>
    public static string SudoersGrantText()
        => $"{Environment.UserName} ALL=(root) NOPASSWD: /bin/bash";

    public const string HeadlessElevationLead =
        "The macOS admin dialog opens on the Mac running this console, not in your browser, so a write " +
        "has to be able to proceed without one. From a Terminal on that Mac:";

    public const string HeadlessElevationTail =
        "The sudoers line is a root shell in all but name, because PF rules are applied by running a " +
        "generated script — on a shared Mac, run the console as root instead. Then use Rescan to " +
        "re-check.";

    /// <summary>
    /// Why a write cannot even be attempted, naming the gap that is actually there:
    /// an OS with no backend, no helper at all, or a helper with no way to ask for a
    /// password on this surface.
    /// </summary>
    private FirewallOperationResult NoElevation(string action)
    {
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (Surface == FirewallUiSurface.Web)
            return FirewallOperationResult.Fail(
                $"This user has no passwordless sudo, so the web console cannot {action}: the admin " +
                $"dialog would have to appear on the Mac running the console, not in your browser.\n\n" +
                HeadlessElevationHelp());

        if (!CanElevate)
            return FirewallOperationResult.Fail(
                $"No elevation helper is installed, so Network Sentinel cannot {action}.");

        return FirewallOperationResult.Fail(
            $"Elevation is available but has no way to ask for a password, so Network Sentinel cannot {action}. " +
            "Run it from a Terminal, or grant this user passwordless sudo (see “Firewall elevation on a " +
            "headless Mac” in the README).");
    }

    public string PrivilegeText
    {
        get
        {
            if (!PlatformSupported)
                return UnsupportedPlatformText;
            if (IsRoot)
                return "Running as root — PF rules can be applied directly.";
            if (CanElevateSilently())
                return "Running as your user with passwordless sudo — rules apply without a prompt.";
            if (Surface == FirewallUiSurface.Web)
                return "Running as your user with no passwordless sudo, so the console cannot write rules: " +
                       "the admin dialog would appear on the Mac running it, not in this browser. " +
                       HeadlessElevationHelp(asBlock: false);
            return "Running as your user. Firewall changes will ask for your Mac password (osascript admin dialog or sudo).";
        }
    }

    /// <summary>
    /// One sentence for a form that is about to write a rule: what applying will
    /// actually ask for on this host. The editor used to state "asks for your Mac
    /// password" unconditionally, which reads as a demand on the two hosts where
    /// nothing is asked at all — already root, and passwordless sudo — and promises a
    /// dialog on the one surface that cannot show one.
    /// </summary>
    public string ElevationNote
    {
        get
        {
            if (!PlatformSupported)
                return UnsupportedPlatformText;
            if (IsRoot)
                return "Applying writes the rule directly — this process is already root.";
            if (CanElevateSilently())
                return "Applying writes the rule through passwordless sudo — nothing is asked for.";
            if (Surface == FirewallUiSurface.Web)
                return "Applying will fail: this console has no passwordless sudo, and the macOS admin " +
                       "dialog cannot be shown in a browser. " + HeadlessElevationHelp(asBlock: false);
            if (Surface == FirewallUiSurface.Desktop && CommandExists("osascript"))
                return "Applying asks for your Mac password (admin dialog).";
            // The terminal path tries the admin dialog first and falls back to sudo on
            // this TTY, so over SSH — where there is no session to draw a dialog on —
            // the second half is what actually happens.
            if (HasTerminal())
                return "Applying asks for your Mac password (admin dialog, or sudo on this terminal).";
            return "Applying will fail: this session has no way to show a password prompt.";
        }
    }

    /// <summary>
    /// Expiry applied to auto-created block rules (null = permanent). Manual
    /// blocks are always permanent; auto-block passes this through.
    /// </summary>
    public TimeSpan? AutoBlockExpiry { get; set; }

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null, bool overrideAllowlist = false, TimeSpan? expiresAfter = null)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        // Auto-block screens CGNAT out one gate earlier, so anything reaching here in
        // that range is a deliberate manual block.
        if (IsNeverBlockable(normalized))
            return FirewallOperationResult.Fail("Refusing to block private/local addresses (LAN, loopback, link-local).");

        if (!overrideAllowlist && Allowlist != null && Allowlist.IsAllowed(normalized, out var allowReason))
            return FirewallOperationResult.Fail($"Refusing to block allowlisted address {normalized} ({allowReason}).");

        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: true, reason, expiresAfter);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: false, reason, expiresAfter);
            ok &= r.Success;
            results.Add(r.Message);
        }

        return ok
            ? FirewallOperationResult.Ok($"Blocked {normalized} ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockIp(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        var inName = IpRuleName(normalized, true);
        var outName = IpRuleName(normalized, false);
        var r1 = RemoveRuleByName(inName);
        var r2 = RemoveRuleByName(outName);

        if (!r1.Success && !r2.Success)
            return FirewallOperationResult.Fail($"No Network Sentinel block rules found for {normalized}.");

        return FirewallOperationResult.Ok($"Unblocked {normalized}. Removed managed inbound/outbound rules when present.");
    }

    public FirewallOperationResult BlockPort(int port, string protocol, FirewallDirection direction = FirewallDirection.Inbound, string? reason = null)
    {
        if (port is < 1 or > 65535)
            return FirewallOperationResult.Fail("Port must be between 1 and 65535.");

        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (protocol is not ("TCP" or "UDP"))
            return FirewallOperationResult.Fail("Protocol must be TCP or UDP.");

        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsurePortRule(port, protocol, isInbound: true, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsurePortRule(port, protocol, isInbound: false, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        return ok
            ? FirewallOperationResult.Ok($"Port {protocol}/{port} blocked ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockPort(int port, string protocol)
    {
        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        var r1 = RemoveRuleByName(PortRuleName(port, protocol, true));
        var r2 = RemoveRuleByName(PortRuleName(port, protocol, false));
        if (!r1.Success && !r2.Success)
            return FirewallOperationResult.Fail($"No managed port rules for {protocol}/{port}.");

        return FirewallOperationResult.Ok($"Removed managed rules for {protocol}/{port}.");
    }

    public FirewallOperationResult RemoveRule(string ruleName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Fail("Only Network Sentinel managed rules can be removed here.");

            if (!IsAdministrator)
                return NoElevation("modify the host firewall");

            var name = ruleName.Trim();

            // Blocks are created as an -In/-Out pair. Removing only the clicked row left
            // the sibling active, so the IP stayed blocked and remove "didn't work".
            //
            // Config rules are never paired, and their names end in an operator's
            // label — "block-inbound-In" would otherwise drag an unrelated
            // "block-inbound-Out" rule out of the ledger with it.
            var isPaired = !name.StartsWith($"{RulePrefix}-Rule-", StringComparison.OrdinalIgnoreCase);
            var siblings = new List<string> { name };
            if (isPaired && name.EndsWith("-In", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-In".Length] + "-Out");
            else if (isPaired && name.EndsWith("-Out", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-Out".Length] + "-In");

            // Drop both from the ledger first, then reload PF once — one password
            // prompt for the pair instead of one per sibling. The gate covers only
            // load-modify-save, not the privileged reload below: holding it across a
            // password dialog would stall auto-block for as long as the dialog is up.
            List<string> removed;
            lock (LedgerGate)
            {
                var ledger = LoadLedger();
                removed = siblings
                    .Where(s => ledger.Any(r => string.Equals(r.Name, s, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                if (removed.Count == 0)
                    return FirewallOperationResult.Fail(AlreadyGoneText(name));

                ledger.RemoveAll(r => removed.Contains(r.Name, StringComparer.OrdinalIgnoreCase));
                SaveLedger(ledger);
            }

            var applied = ApplyPfFromLedger();
            if (!applied.Success)
                return FirewallOperationResult.Fail(applied.Message);

            return FirewallOperationResult.Ok(removed.Count > 1
                ? $"Removed inbound + outbound rules ({removed[0]} and its pair)."
                : $"Removed “{removed[0]}”.");
        }
        catch (Exception ex)
        {
            // Never let firewall backend failures tear down the web host process.
            return FirewallOperationResult.Fail($"Remove failed: {ex.Message}");
        }
    }

    /// <param name="skip">Rules to leave in place (kept for API parity with the Windows/Linux builds).</param>
    public FirewallOperationResult RemoveAllManagedRules(Func<FirewallRuleInfo, bool>? skip = null)
    {
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        int removed;
        int keptCount;
        bool droppedProbeRule;
        lock (LedgerGate)
        {
            var rules = LoadLedger();
            var kept = skip == null
                ? new List<FirewallRuleInfo>()
                : rules.Where(skip).ToList();
            removed = rules.Count - kept.Count;
            keptCount = kept.Count;

            // Wiping the ledger also drops the probe-log rule from the anchor, so the
            // privileged decoder would otherwise keep running with nothing logging to it.
            droppedProbeRule =
                rules.Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase)) &&
                !kept.Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase));

            SaveLedger(kept);
        }

        var script = BuildApplyPfScript(out var buildError);
        if (script == null)
            return FirewallOperationResult.Fail(buildError);
        if (droppedProbeRule)
            script += "\n" + ProbeWriterStopScript();

        var applied = RunPrivilegedShell(script);
        if (!applied.Success)
            return applied;

        var msg = $"Removed {removed} Network Sentinel firewall rule(s).";
        if (keptCount > 0)
            msg += $" Kept {keptCount}.";
        return FirewallOperationResult.Ok(msg);
    }

    /// <summary>
    /// Best-effort IP from a managed rule name or remote field (for auto-block suppress after Remove).
    /// </summary>
    public static bool TryExtractIpFromManagedRule(string? ruleName, string? remoteAddresses, out string ip)
    {
        ip = "";
        if (!string.IsNullOrWhiteSpace(remoteAddresses) &&
            TryNormalizeIp(remoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault(), out ip, out _))
            return true;

        if (string.IsNullOrWhiteSpace(ruleName))
            return false;

        // NetworkSentinel-IP-1.2.3.4-In  or  NetworkSentinel-IP-2001_db8__1-Out
        var m = Regex.Match(ruleName.Trim(),
            @"^NetworkSentinel-IP-(.+)-(In|Out)$",
            RegexOptions.IgnoreCase);
        if (!m.Success)
            return false;

        var raw = m.Groups[1].Value.Replace('_', ':');
        return TryNormalizeIp(raw, out ip, out _);
    }

    public FirewallOperationResult UnblockAllowlistedAddresses()
    {
        if (Allowlist == null)
            return FirewallOperationResult.Fail("Allowlist is not available.");

        if (!IsAdministrator)
            return NoElevation("remove firewall rules");

        var rules = GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock).ToList();
        int removed = 0;
        var notes = new List<string>();

        foreach (var rule in rules)
        {
            var remote = rule.RemoteAddresses;
            if (string.IsNullOrWhiteSpace(remote)) continue;
            if (!Allowlist.IsAllowed(remote, out var why)) continue;

            if (RemoveRuleByName(rule.Name).Success)
            {
                removed++;
                notes.Add($"{remote} ({why})");
            }
        }

        if (removed == 0)
            return FirewallOperationResult.Ok("No allowlisted IPs were blocked by Network Sentinel rules.");

        return FirewallOperationResult.Ok(
            $"Restored {removed} allowlisted address(es): {string.Join("; ", notes.Take(12))}" +
            (notes.Count > 12 ? "…" : ""));
    }

    // ── Firewall Config rules (operator-authored) ────────────────────────

    /// <summary>
    /// Every managed rule in ledger order, which is the order they are loaded
    /// into PF. <see cref="GetManagedRules"/> sorts for the flat rule list;
    /// the Firewall Config view needs the real evaluation order instead,
    /// because the ruleset is first-match-wins.
    /// </summary>
    public IReadOnlyList<FirewallRuleInfo> GetConfigRules()
    {
        var ledger = LoadLedger();
        return ledger
            // App-minted blocks are written to the anchor ahead of config rules
            // (see BuildPfRuleset), so the list has to show them that way too.
            .OrderBy(r => r.Kind == FirewallRuleKind.Custom ? 1 : 0)
            .ToList();
    }

    /// <summary>
    /// Creates or replaces one operator-authored rule and reloads PF.
    /// Passing <paramref name="replaceName"/> edits in place: the old entry is
    /// dropped and the new one takes its position at the end of the config
    /// section, in one ledger write and one elevation prompt.
    /// </summary>
    public FirewallOperationResult SaveCustomRule(FirewallRuleSpec spec, string? replaceName = null)
    {
        // Validate before normalising — see FirewallRuleSpecs.TryPrepare for why the
        // other order turns an unparseable port range into "every port".
        if (!FirewallRuleSpecs.TryPrepare(spec, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        string name;
        lock (LedgerGate)
        {
            var ledger = LoadLedger();
            if (!string.IsNullOrWhiteSpace(replaceName))
            {
                var existing = ledger.FirstOrDefault(r =>
                    string.Equals(r.Name, replaceName, StringComparison.OrdinalIgnoreCase));
                if (existing == null)
                    return FirewallOperationResult.Fail($"No rule named “{replaceName}” to edit — it may have been removed.");
                if (existing.Kind != FirewallRuleKind.Custom)
                    return FirewallOperationResult.Fail("Only Firewall Config rules can be edited here.");
                ledger.RemoveAll(r => string.Equals(r.Name, replaceName, StringComparison.OrdinalIgnoreCase));
            }

            name = UniqueCustomRuleName(normalized.Label, ledger);
            ledger.Add(FirewallRuleSpecs.ToRule(normalized, name));
            SaveLedger(ledger);
        }

        var applied = ApplyPfFromLedger();
        if (applied.Success)
        {
            return FirewallOperationResult.Ok(string.IsNullOrWhiteSpace(replaceName)
                ? $"Added rule “{normalized.Label}”."
                : $"Saved rule “{normalized.Label}”.");
        }

        // A rule PF would not load must not stay in the ledger claiming to be in
        // force — the next apply would fail on it too, taking every other rule
        // with it.
        RemoveFromLedger(name);
        ApplyPfFromLedger();
        return FirewallOperationResult.Fail($"PF rejected the rule, so it was not kept: {applied.Message}");
    }

    /// <summary>
    /// Deletes a rule that came from a host scan rather than this app's ledger.
    /// The Firewall Config view lists the whole host firewall, so Delete has to
    /// work on rows Network Sentinel did not write; refusing them all would make
    /// the list a read-only report with buttons that lie.
    ///
    /// How far it can go differs by backend, and the difference is macOS's, not
    /// ours. An Application Firewall entry is one app with one verdict, and
    /// socketfilterfw removes it by path. A pf rule has no handle and no delete
    /// verb — the ruleset is replaced wholesale by whatever loaded it, so
    /// deleting one line means editing the file that declares it. Doing that to
    /// /etc/pf.conf or an Apple anchor on an operator's behalf would put us in
    /// the business of rewriting system configuration to remove a row from a
    /// table, and a reload would bring it back anyway.
    /// </summary>
    public FirewallOperationResult DeleteHostRule(FirewallRuleInfo rule)
    {
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        // One of ours: go through the ledger so its bookkeeping stays truthful.
        if (!rule.IsForeign || rule.Kind != FirewallRuleKind.Other)
            return RemoveRule(rule.Name);

        if (rule.Backend.Equals("alf", StringComparison.OrdinalIgnoreCase))
            return RemoveAlfApp(rule);

        // A rule in our own anchor is ours even when the scan could not match it to
        // a ledger entry — rebuilding the anchor from the ledger drops it.
        if (rule.Handle.Equals(PfAnchorName, StringComparison.OrdinalIgnoreCase))
            return RemoveRule(rule.Name);

        var where = rule.Handle.Length > 0
            ? $"the “{rule.Handle}” anchor"
            : (rule.Table.Length > 0 ? rule.Table : "the PF ruleset");

        return FirewallOperationResult.Fail(
            $"“{rule.LabelText}” is part of {where}, which PF loads as a whole — it has no rule handle to " +
            "delete it by, and a reload would restore it. Remove it where it is declared.");
    }

    /// <summary>
    /// Drops one binary from the Application Firewall's list. Unlike a pf rule
    /// this is a supported single-item operation, so the Delete button means what
    /// it says for these rows.
    /// </summary>
    private FirewallOperationResult RemoveAlfApp(FirewallRuleInfo rule)
    {
        var path = rule.Table;
        if (path.Length == 0)
            return FirewallOperationResult.Fail($"“{rule.LabelText}” carries no application path to remove.");

        var result = RunPrivilegedShell(
            $"{ShellQuote(HostFirewallScanner.SocketFilterFw)} --remove {ShellQuote(path)}");

        return result.Success
            ? FirewallOperationResult.Ok($"Removed “{rule.LabelText}” from the Application Firewall.")
            : FirewallOperationResult.Fail($"The Application Firewall refused the delete: {result.Message}");
    }

    /// <summary>Rule names are the ledger key, so a repeated label gets a suffix.</summary>
    private static string UniqueCustomRuleName(string label, List<FirewallRuleInfo> ledger)
    {
        var baseName = $"{RulePrefix}-Rule-{Sanitize(label)}";
        var name = baseName;
        var suffix = 2;
        while (ledger.Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)))
            name = $"{baseName}-{suffix++}";
        return name;
    }

    public IReadOnlyList<FirewallRuleInfo> GetManagedRules()
    {
        var ledger = LoadLedger();
        return ledger
            .OrderBy(r => r.Kind)
            .ThenBy(r => r.RemoteAddresses)
            .ThenBy(r => r.LocalPorts)
            .ThenBy(r => r.Direction)
            .ToList();
    }

    public bool IsIpBlocked(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out _))
            return false;

        return GetManagedRules().Any(r =>
            r.Kind == FirewallRuleKind.IpBlock && !r.IsExpired &&
            string.Equals(r.RemoteAddresses, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public HashSet<string> GetBlockedIps()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock && !r.IsExpired))
        {
            if (!string.IsNullOrWhiteSpace(rule.RemoteAddresses))
                set.Add(rule.RemoteAddresses);
        }
        return set;
    }

    /// <summary>
    /// Pre-authorize elevation with a no-op privileged command so the first real
    /// block does not surprise the user. Does NOT relaunch the GUI as root.
    /// </summary>
    public FirewallOperationResult AuthorizeElevation()
    {
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (IsRoot)
            return FirewallOperationResult.Ok("Already running as root.");

        // On the web console there is no dialog to raise, so the button does the other
        // useful thing instead: it re-checks whether sudo will run the rule script now.
        // That is what an operator who has just written the sudoers file wants, and
        // re-checking is the only way to answer it without waiting out the probe cache.
        InvalidateElevationProbe();
        if (CanElevateSilently())
        {
            // Nothing to authorize, but the anchor hook still has to be there or the
            // first rule loads into a ruleset /etc/pf.conf never reads. Hooking it
            // costs no dialog on this path, so the button does the whole job rather
            // than reporting success and leaving the one side effect undone.
            var silentHook = EnsureAnchorHooked();
            return silentHook.Success
                ? FirewallOperationResult.Ok(
                    "Nothing to authorize — this user already has passwordless sudo, so rules apply " +
                    "without a prompt.")
                : FirewallOperationResult.Fail(
                    "Passwordless sudo works, but could not install the PF anchor hook: " + silentHook.Message);
        }

        if (!CanApplyRules)
            return NoElevation("apply firewall rules");

        // Touch a harmless privileged read — triggers admin password once.
        var probe = RunPrivilegedShell("/sbin/pfctl -s info >/dev/null 2>&1; /sbin/pfctl -e 2>/dev/null; true");
        if (probe.Success)
        {
            // Ensure anchor is hooked for future rule loads.
            var hook = EnsureAnchorHooked();
            if (!hook.Success)
                return FirewallOperationResult.Fail(
                    "Password OK, but could not install PF anchor hook: " + hook.Message);

            return FirewallOperationResult.Ok(
                "Authorization OK. Firewall changes can proceed (you may be prompted again after a while).");
        }

        var tail = Surface == FirewallUiSurface.Web
            ? $"\n\n{HeadlessElevationHelp()}"
            : "\n\nRun the app as your user and allow the Mac admin password dialog when blocking.";

        return FirewallOperationResult.Fail("Elevation failed or was cancelled. " + probe.Message + tail);
    }

    [Obsolete("GUI must not restart as root. Use AuthorizeElevation() instead.")]
    public void RestartAsAdministrator()
    {
        var result = AuthorizeElevation();
        if (!result.Success)
            throw new InvalidOperationException(result.Message);
    }

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason, TimeSpan? expiresAfter = null)
    {
        var name = IpRuleName(ip, isInbound);
        var description = reason ?? $"Blocked by Network Sentinel at {DateTime.Now:u}";

        UpsertLedger(new FirewallRuleInfo
        {
            Name = name,
            Description = description,
            Enabled = true,
            IsBlock = true,
            Direction = isInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
            RemoteAddresses = ip,
            LocalPorts = "",
            Protocol = "Any",
            Kind = FirewallRuleKind.IpBlock,
            ExpiresUtc = expiresAfter.HasValue ? DateTime.UtcNow + expiresAfter.Value : null
        });

        var applied = ApplyPfFromLedger();
        return applied.Success
            ? FirewallOperationResult.Ok($"Rule “{name}” applied (PF).")
            : FirewallOperationResult.Fail($"Failed PF apply {name}: {applied.Message}");
    }

    private FirewallOperationResult EnsurePortRule(int port, string protocol, bool isInbound, string? reason)
    {
        var name = PortRuleName(port, protocol, isInbound);
        var description = reason ?? $"Port blocked by Network Sentinel at {DateTime.Now:u}";

        UpsertLedger(new FirewallRuleInfo
        {
            Name = name,
            Description = description,
            Enabled = true,
            IsBlock = true,
            Direction = isInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
            RemoteAddresses = "",
            LocalPorts = port.ToString(),
            Protocol = protocol.ToUpperInvariant(),
            Kind = FirewallRuleKind.PortBlock
        });

        var applied = ApplyPfFromLedger();
        return applied.Success
            ? FirewallOperationResult.Ok($"Rule “{name}” applied (PF).")
            : FirewallOperationResult.Fail($"Failed PF apply {name}: {applied.Message}");
    }

    /// <summary>
    /// Wording for a rule that is not there to remove. One managed rule can hold
    /// several rows in the host scan — an inbound rule and the outbound sibling
    /// written with it, or a protocol Any that lists once per family — and removing
    /// any one row takes them all. So a click on a sibling row from the same listing
    /// arrives after the rule is already gone. That is the requested end state, not a
    /// fault, and reporting it as "No rule named …" read as delete being broken.
    /// </summary>
    private static string AlreadyGoneText(string name) =>
        $"“{name}” is no longer in the firewall — it was already removed, most likely " +
        "together with another row of the same rule.";

    private FirewallOperationResult RemoveRuleByName(string name)
    {
        var hadLedger = LoadLedger().Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        RemoveFromLedger(name);
        var applied = ApplyPfFromLedger();

        if (!hadLedger && applied.Success)
            return FirewallOperationResult.Fail(AlreadyGoneText(name));

        return applied.Success
            ? FirewallOperationResult.Ok($"Removed “{name}”.")
            : FirewallOperationResult.Fail(applied.Message);
    }

    /// <summary>
    /// Rebuilds the PF anchor ruleset from the JSON ledger and loads it.
    /// </summary>
    private FirewallOperationResult ApplyPfFromLedger()
    {
        var script = BuildApplyPfScript(out var error);
        if (script == null)
            return FirewallOperationResult.Fail(error);

        return RunPrivilegedShell(script);
    }

    /// <summary>
    /// Writes the anchor file from the ledger and returns ONE privileged script that
    /// hooks the anchor into pf.conf, enables PF, and loads the rules. Callers that
    /// need extra privileged work (see <see cref="EnableProbeLogging"/>) append to
    /// this script rather than making a second elevated call: every RunPrivilegedShell
    /// is its own osascript process and therefore its own password dialog, so an
    /// operation split across calls asked for the password repeatedly and answering
    /// only the first prompt looked exactly like authentication failing.
    /// Returns null and sets <paramref name="error"/> if the rules file cannot be written.
    /// </summary>
    private string? BuildApplyPfScript(out string error)
    {
        error = "";
        // Every apply already carries an elevation prompt, so expired rules are
        // dropped for free here — the ledger and the loaded ruleset stay in sync.
        PruneExpiredFromLedger();
        var rulesPath = UserPfRulesPath;
        try
        {
            File.WriteAllText(rulesPath, BuildPfRuleset(LoadLedger()));
        }
        catch (Exception ex)
        {
            error = $"Could not write PF rules file: {ex.Message}";
            return null;
        }

        var systemRules = $"/etc/pf.anchors/{PfAnchorName}";
        return AnchorHookScript() + "\n" +
               $"cp {ShellQuote(rulesPath)} {ShellQuote(systemRules)}\n" +
               $"chmod 644 {ShellQuote(systemRules)}\n" +
               $"/sbin/pfctl -e 2>/dev/null || true\n" +
               $"/sbin/pfctl -a {ShellQuote(PfAnchorName)} -f {ShellQuote(systemRules)}\n";
    }

    internal static string BuildPfRuleset(IEnumerable<FirewallRuleInfo> rules)
    {
        var live = rules.Where(r => r.Enabled && !r.IsExpired).ToList();

        var sb = new StringBuilder();
        sb.AppendLine($"# Network Sentinel PF anchor — managed rules (do not edit by hand)");
        sb.AppendLine($"# Generated {DateTime.Now:u}");
        sb.AppendLine();

        // Every rule below is `quick`, so the file is first-match-wins. App-minted
        // blocks are emitted FIRST and therefore always win: a Firewall Config
        // "Allow" rule must never be able to reopen an address that auto-block
        // just shut, which is exactly what would happen if the ledger's insertion
        // order decided precedence.
        foreach (var rule in live.Where(r => r.IsBlock && r.Kind != FirewallRuleKind.Custom))
        {
            // The comment names the rule in the file, for remove-by-name and for
            // anyone reading it. The label is the same name inside the kernel:
            // pfctl drops comments and keeps labels, so it is the only identity
            // HostFirewallScanner can match back to this ledger entry on a rescan.
            sb.AppendLine($"# {rule.Name}");
            var label = $" label \"{FirewallRuleSpecs.PfLabel(rule.Name)}\"";
            if (rule.Kind == FirewallRuleKind.IpBlock && !string.IsNullOrWhiteSpace(rule.RemoteAddresses))
            {
                var ip = rule.RemoteAddresses.Trim();
                if (rule.Direction == FirewallDirection.Inbound)
                    sb.AppendLine($"block drop in quick from {ip} to any{label}");
                else
                    sb.AppendLine($"block drop out quick from any to {ip}{label}");
            }
            else if (rule.Kind == FirewallRuleKind.PortBlock &&
                     int.TryParse(rule.LocalPorts, out var port) &&
                     port is >= 1 and <= 65535)
            {
                var proto = (rule.Protocol ?? "tcp").Trim().ToLowerInvariant();
                if (proto is not ("tcp" or "udp"))
                    proto = "tcp";

                if (rule.Direction == FirewallDirection.Inbound)
                    sb.AppendLine($"block drop in quick proto {proto} from any to any port {port}{label}");
                else
                    sb.AppendLine($"block drop out quick proto {proto} from any port {port} to any{label}");
            }
            sb.AppendLine();
        }

        // Firewall Config rules, in the order the operator listed them.
        foreach (var rule in live.Where(r => r.Kind == FirewallRuleKind.Custom))
        {
            sb.AppendLine($"# {rule.Name}");
            sb.AppendLine(FirewallRuleSpecs.BuildPfLine(rule));
            sb.AppendLine();
        }

        // Probe-log rule, deliberately LAST and deliberately not `quick`.
        //
        // macOS pfctl has no `match` keyword (it is a syntax error here), so the
        // only way to log without a verdict does not exist — the rule has to be a
        // pass. Two things keep that safe: every managed block above is
        // `block drop ... quick`, so a blocked peer short-circuits and never reaches
        // this rule; and `no state` means the pass applies to the SYN alone and
        // creates no state entry, so every other packet of the connection is
        // evaluated exactly as it was before. The net behaviour change is confined
        // to inbound TCP SYNs that nothing else in the ruleset blocked.
        if (live.Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase)))
        {
            sb.AppendLine($"# {ProbeLogRuleName}");
            sb.AppendLine($"pass in log proto tcp from any to any flags S/SA no state label \"{ProbeLogRuleName}\"");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    // ── Closed-port scan detection (PF log) ──────────────────────────────

    /// <summary>
    /// Installs the PF SYN-log rule and starts the privileged decoder that turns
    /// pflog0 packets into <see cref="ProbeLogPath"/>. Probes to CLOSED ports are
    /// answered with a RST before they ever appear in the socket table, so
    /// connection polling cannot see them — this rule makes them visible.
    ///
    /// Rule load and decoder start happen in ONE elevated shell, so the user sees
    /// a single password dialog.
    /// </summary>
    public FirewallOperationResult EnableProbeLogging()
    {
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        UpsertLedger(new FirewallRuleInfo
        {
            Name = ProbeLogRuleName,
            Description = "Logs inbound TCP SYNs via PF so scans of closed ports are detectable",
            Enabled = true,
            IsBlock = false,
            Direction = FirewallDirection.Inbound,
            RemoteAddresses = "",
            LocalPorts = "",
            Protocol = "TCP",
            Kind = FirewallRuleKind.Other
        });

        var script = BuildApplyPfScript(out var error);
        if (script == null)
        {
            RemoveFromLedger(ProbeLogRuleName);
            return FirewallOperationResult.Fail(error);
        }

        var result = RunPrivilegedShell(script + "\n" + ProbeWriterStartScript());
        if (!result.Success)
        {
            // Do not leave the ledger claiming a detection that is not running.
            RemoveFromLedger(ProbeLogRuleName);
            return FirewallOperationResult.Fail($"Failed to enable probe logging: {result.Message}");
        }

        return FirewallOperationResult.Ok("Probe logging enabled (PF log rule + pflog0 decoder).");
    }

    public FirewallOperationResult DisableProbeLogging()
    {
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        RemoveFromLedger(ProbeLogRuleName);

        var script = BuildApplyPfScript(out var error);
        if (script == null)
            return FirewallOperationResult.Fail(error);

        var result = RunPrivilegedShell(script + "\n" + ProbeWriterStopScript());
        return result.Success
            ? FirewallOperationResult.Ok("Probe logging disabled.")
            : result;
    }

    public bool IsProbeLoggingInstalled()
        => GetManagedRules().Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Privileged fragment that creates pflog0 and installs + loads the decoder
    /// LaunchDaemon. tcpdump exits after <see cref="ProbePacketCap"/> packets and the
    /// wrapper loop restarts it against a truncated file, which is what bounds the log
    /// size — ProbeLogMonitor treats the shrink as "reseek", not an error.
    /// </summary>
    private static string ProbeWriterStartScript()
    {
        // Both the loop and the plist go into files via QUOTED heredocs so their
        // bodies pass through verbatim — nesting a multi-line loop or XML inside
        // `sh -c '...'` inside AppleScript is exactly what breaks the elevation call.
        //
        // No BPF filter on the tcpdump, on purpose. The PF rule already logs nothing
        // but inbound bare SYNs, so a `tcp[tcpflags]` filter would be redundant — and
        // it compiles to an AF_INET-only test against DLT_PFLOG, which would silently
        // drop every IPv6 probe. ProbeLogMonitor re-checks "Flags [S]" when it parses,
        // which covers both families.
        return $"""
            {ProbeWriterStopScript()}
            /sbin/ifconfig pflog0 create 2>/dev/null || true
            /sbin/ifconfig pflog0 up 2>/dev/null || true
            : > {ProbeLogPath}
            chmod 644 {ProbeLogPath}
            mkdir -p /usr/local/libexec
            cat > {ProbeWriterPath} <<'NSPROBEEOF'
            #!/bin/sh
            while :; do
              /usr/sbin/tcpdump -n -e -l -i pflog0 -c {ProbePacketCap} > {ProbeLogPath} 2>/dev/null
              sleep 1
            done
            NSPROBEEOF
            chown root:wheel {ProbeWriterPath}
            chmod 755 {ProbeWriterPath}
            cat > {ProbeDaemonPlist} <<'NSPLISTEOF'
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
            	<key>Label</key>
            	<string>{ProbeDaemonLabel}</string>
            	<key>ProgramArguments</key>
            	<array>
            		<string>{ProbeWriterPath}</string>
            	</array>
            	<key>RunAtLoad</key>
            	<true/>
            	<key>KeepAlive</key>
            	<true/>
            	<key>ProcessType</key>
            	<string>Background</string>
            </dict>
            </plist>
            NSPLISTEOF
            chown root:wheel {ProbeDaemonPlist}
            chmod 644 {ProbeDaemonPlist}
            # bootstrap is the modern API; fall back to load -w on older systems.
            launchctl bootstrap system {ProbeDaemonPlist} 2>/dev/null || launchctl load -w {ProbeDaemonPlist} 2>/dev/null || true
            """;
    }

    /// <summary>Privileged fragment that unloads the decoder daemon and removes its files.</summary>
    private static string ProbeWriterStopScript()
    {
        return $"""
            launchctl bootout system/{ProbeDaemonLabel} 2>/dev/null || launchctl unload -w {ProbeDaemonPlist} 2>/dev/null || true
            rm -f {ProbeDaemonPlist}
            pkill -f 'tcpdump -n -e -l -i pflog0' 2>/dev/null || true
            rm -f {ProbeWriterPath}
            """;
    }

    /// <summary>
    /// True when the privileged decoder daemon is actually loaded. The PF rule and the
    /// log file can both be present while the decoder is dead, in which case the app
    /// would tail an empty file forever and report a detection that is not running.
    /// </summary>
    public static bool IsProbeWriterRunning()
    {
        try
        {
            var psi = new ProcessStartInfo("/bin/launchctl")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("print");
            psi.ArgumentList.Add($"system/{ProbeDaemonLabel}");

            using var p = Process.Start(psi);
            if (p == null) return false;
            // Drain both pipes concurrently — `launchctl print` is verbose enough to
            // fill a pipe buffer, and a blocking stdout read would deadlock against it
            // while keeping the WaitForExit bound below from ever engaging.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(4000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return false;
            }
            try { Task.WaitAll(stdoutTask, stderrTask); } catch { /* pipes torn down */ }
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Ensures /etc/pf.conf references our anchor (with backup), once.
    /// </summary>
    private FirewallOperationResult EnsureAnchorHooked()
        => RunPrivilegedShell(AnchorHookScript());

    /// <summary>
    /// Idempotent shell fragment: create the anchor file if missing, append the
    /// pf.conf anchor lines if absent, enable and reload PF. Safe to run repeatedly
    /// and safe to concatenate ahead of other privileged commands.
    /// </summary>
    private static string AnchorHookScript()
    {
        var marker = $"anchor \"{PfAnchorName}\"";
        var loadLine = $"load anchor \"{PfAnchorName}\" from \"/etc/pf.anchors/{PfAnchorName}\"";
        var emptyRules = $"/etc/pf.anchors/{PfAnchorName}";

        return $"""
            set -e
            mkdir -p /etc/pf.anchors
            if [ ! -f {ShellQuote(emptyRules)} ]; then
              printf '%s\n' '# Network Sentinel anchor' > {ShellQuote(emptyRules)}
              chmod 644 {ShellQuote(emptyRules)}
            fi
            if [ -f /etc/pf.conf ] && ! grep -qF {ShellQuote(marker)} /etc/pf.conf 2>/dev/null; then
              cp /etc/pf.conf /etc/pf.conf.networksentinel.bak 2>/dev/null || true
              printf '\n# Network Sentinel\n%s\n%s\n' {ShellQuote(marker)} {ShellQuote(loadLine)} >> /etc/pf.conf
            fi
            /sbin/pfctl -e 2>/dev/null || true
            /sbin/pfctl -f /etc/pf.conf 2>/dev/null || true
            """;
    }

    private static string UserPfRulesPath
        => Path.Combine(AppPaths.DataDirectory, "pf-anchor.conf");

    // ── Block expiry ─────────────────────────────────────────────────────

    private Timer? _expiryTimer;

    /// <summary>
    /// Starts the background sweep that removes expired block rules. Removal
    /// needs root for pfctl, so the sweep only acts when it can elevate
    /// silently (running as root, or sudo credentials are cached); otherwise
    /// expired rules are cleaned up by the next user-triggered firewall
    /// change (see <see cref="BuildApplyPfScript"/>) — never by a surprise
    /// password dialog from a timer.
    /// </summary>
    public void StartExpirySweep()
    {
        if (_expiryTimer == null)
        {
            // One-time startup pass, off the caller's thread: the ledger survives a
            // reboot but the loaded PF rules don't, so reconcile before the first sweep.
            _ = Task.Run(() => ReconcileLedgerWithKernel());
        }
        _expiryTimer ??= new Timer(_ => TrySweepExpired(), null,
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Realigns the ledger and the rules actually loaded in PF. firewall-rules.json
    /// survives a reboot; the loaded anchor does not — macOS boots with PF disabled
    /// unless something enables it, so after a restart the app reported addresses as
    /// blocked, and the auto-block "already blocked" gate skipped re-blocking a
    /// still-active attacker, while no rule existed in the kernel. The same
    /// divergence appears after an external <c>pfctl -F</c>.
    ///
    /// Listing (and repairing) needs elevation, so this only acts when that can
    /// happen silently — root, or cached/passwordless sudo — and never raises a
    /// password dialog from startup. When it can't, the ledger is left alone and the
    /// next process start retries.
    ///
    /// Where Linux drops the stale ledger entries, macOS re-applies them: the anchor
    /// ruleset is generated wholesale from the ledger, so restoring it is one
    /// <c>pfctl -f</c> with machinery that already exists, and restoring protection
    /// beats discarding it. Dropping entries is the fallback for when the re-apply
    /// itself fails, so the "already blocked" gate still can't suppress a real block.
    /// </summary>
    public FirewallOperationResult ReconcileLedgerWithKernel()
    {
        try
        {
            var expected = LoadLedger()
                .Where(r => r.Enabled && r.IsBlock && !r.IsExpired)
                .ToList();
            if (expected.Count == 0)
                return FirewallOperationResult.Ok("Ledger has no live block rules — nothing to reconcile.");

            if (!CanElevateSilently())
                return FirewallOperationResult.Fail("Cannot list PF rules without prompting — reconciliation skipped.");

            var listed = RunPrivilegedSilent($"/sbin/pfctl -a {ShellQuote(PfAnchorName)} -s rules 2>&1");
            // A missing anchor or a disabled PF is the post-reboot case, not an error:
            // it means nothing is loaded, so every ledger entry is unenforced.
            var dump = listed.Success && !LooksLikeNothingLoaded(listed.Message)
                ? listed.Message
                : "";

            // pfctl -s rules prints normalized rules and drops the "# <name>" comments
            // BuildPfRuleset writes, so the Linux name-containment test does not work
            // here. Match on what pfctl does print: the address, or the port.
            var missing = expected.Where(r => !IsLoaded(r, dump)).ToList();
            if (missing.Count == 0)
                return FirewallOperationResult.Ok("PF rules match the ledger.");

            var script = BuildApplyPfScript(out var buildError);
            if (script != null)
            {
                var applied = RunPrivilegedSilent(script);
                if (applied.Success)
                    return FirewallOperationResult.Ok(
                        $"Re-applied {missing.Count} block rule{(missing.Count == 1 ? "" : "s")} that were in the ledger but not loaded in PF.");
                buildError = applied.Message;
            }

            // Could not restore them, so stop claiming they are in force: a stale
            // ledger entry makes auto-block skip an address it should be blocking.
            lock (LedgerGate)
            {
                var ledger = LoadLedger();
                ledger.RemoveAll(r => missing.Any(m => string.Equals(m.Name, r.Name, StringComparison.OrdinalIgnoreCase)));
                SaveLedger(ledger);
            }

            return FirewallOperationResult.Fail(
                $"Could not re-apply {missing.Count} unloaded rule{(missing.Count == 1 ? "" : "s")} ({buildError}); " +
                "dropped them from the ledger so auto-block can act on those addresses again.");
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail($"Reconcile failed: {ex.Message}");
        }
    }

    /// <summary>Is this ledger rule visible in a <c>pfctl -s rules</c> dump?</summary>
    internal static bool IsLoaded(FirewallRuleInfo rule, string dump)
    {
        if (dump.Length == 0) return false;

        if (rule.Kind == FirewallRuleKind.IpBlock && !string.IsNullOrWhiteSpace(rule.RemoteAddresses))
            return dump.Contains(rule.RemoteAddresses.Trim(), StringComparison.OrdinalIgnoreCase);

        if (rule.Kind == FirewallRuleKind.PortBlock && int.TryParse(rule.LocalPorts, out var port))
            return dump.Contains($"port = {port}", StringComparison.Ordinal)
                   || dump.Contains($"port {port}", StringComparison.Ordinal);

        // Anything we cannot check is left alone rather than reported as unloaded —
        // a false "missing" would re-apply or delete a rule for no reason.
        return true;
    }

    internal static bool LooksLikeNothingLoaded(string message)
        => message.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase)
           || message.Contains("does not exist", StringComparison.OrdinalIgnoreCase)
           || message.Contains("pf not enabled", StringComparison.OrdinalIgnoreCase)
           || message.Contains("Operation not supported", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Elevation that can never prompt: root, or sudo -n. Used by the startup and
    /// timer paths, where a password dialog would appear out of nowhere.
    /// </summary>
    private FirewallOperationResult RunPrivilegedSilent(string shellScript)
        => IsRoot
            ? RunProcess("/bin/bash", "-c", shellScript)
            : RunProcess("sudo", "-n", "/bin/bash", "-c", shellScript);

    private void TrySweepExpired()
    {
        try
        {
            if (!LoadLedger().Any(r => r.IsExpired))
                return;
            if (!CanElevateSilently())
                return;

            // BuildApplyPfScript prunes the ledger; the silent shell reloads PF.
            var script = BuildApplyPfScript(out _);
            if (script != null)
                RunPrivilegedShell(script);
        }
        catch
        {
            // sweep is best-effort; the next manual firewall action cleans up
        }
    }

    /// <summary>
    /// Whether sudo will apply a rule without asking for anything.
    ///
    /// The answer is cached because a refused <c>sudo -n</c> is written to the auth
    /// log, which this very application watches for break-in attempts; probing on
    /// every snapshot would have Network Sentinel reporting on itself. Auto-block
    /// expiry and startup reconciliation both gate on this, so it is asked far more
    /// often than it can change.
    /// </summary>
    internal static bool CanElevateSilently()
    {
        if (!PlatformSupported) return false;
        if (IsRootProcess()) return true;
        if (!CommandExists("sudo")) return false;

        var now = Environment.TickCount64;
        lock (SilentProbeLock)
        {
            if (_silentProbeStampMs != 0 &&
                now - _silentProbeStampMs < (_silentProbeResult ? SilentProbeOkTtlMs : SilentProbeFailTtlMs))
                return _silentProbeResult;
        }

        var result = ProbeSilentSudo();

        lock (SilentProbeLock)
        {
            _silentProbeResult = result;
            _silentProbeStampMs = Environment.TickCount64;
        }
        return result;
    }

    /// <summary>
    /// Forgets the cached <see cref="CanElevateSilently"/> answer, so an operator who
    /// has just written the sudoers file sees the change on the next Rescan instead of
    /// waiting out the cache.
    /// </summary>
    public static void InvalidateElevationProbe()
    {
        lock (SilentProbeLock)
            _silentProbeStampMs = 0;
    }

    private static bool ProbeSilentSudo()
    {
        try
        {
            // A blanket NOPASSWD grant answers here and costs one process.
            if (RunProcess("sudo", "-n", "/usr/bin/true").Success)
                return true;

            // A grant scoped to the shell does not, and that is the one a rule write
            // needs: the PF ruleset is generated and applied as a script, so this asks
            // for exactly what RunPrivilegedShell will ask for.
            return RunProcess("sudo", "-n", "/bin/bash", "-c", "exit 0").Success;
        }
        catch
        {
            // Treated as "cannot elevate silently" — the callers are all best-effort.
            return false;
        }
    }

    private static readonly object SilentProbeLock = new();
    private static bool _silentProbeResult;
    private static long _silentProbeStampMs;

    /// <summary>A grant that works is stable; re-checking it often buys nothing.</summary>
    private const int SilentProbeOkTtlMs = 60_000;

    /// <summary>
    /// A grant that is missing is the case an operator is actively fixing, but every
    /// probe leaves a line in the auth log, so it is re-checked less often than it is
    /// asked about and <see cref="InvalidateElevationProbe"/> covers the impatient.
    /// </summary>
    private const int SilentProbeFailTtlMs = 300_000;

    private static void PruneExpiredFromLedger()
    {
        lock (LedgerGate)
        {
            var ledger = LoadLedger();
            if (ledger.RemoveAll(r => r.IsExpired) > 0)
                SaveLedger(ledger);
        }
    }

    // ── Elevation ────────────────────────────────────────────────────────

    /// <summary>
    /// Runs a shell script elevated via osascript (GUI password) or sudo.
    /// Complex scripts are written to a temp file so AppleScript never has to
    /// embed nested shell quotes (which caused -2740 syntax errors).
    /// </summary>
    private static FirewallOperationResult RunPrivilegedShell(string shellScript)
    {
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (IsRootProcess())
            return RunProcess("/bin/bash", "-c", shellScript);

        // 1) sudo -n (cached / passwordless)
        var cachedMessage = "";
        if (CommandExists("sudo"))
        {
            var cached = RunProcess("sudo", "-n", "/bin/bash", "-c", shellScript);
            if (cached.Success)
                return cached;
            cachedMessage = cached.Message;
        }

        // The web console gets no further. osascript would put its admin dialog on the
        // Mac's own screen, where nobody is sitting, and then hold this request for the
        // full interactive timeout waiting for an answer that cannot come — so a rule
        // added from a browser used to hang for five minutes before failing.
        if (Surface == FirewallUiSurface.Web)
            return FirewallOperationResult.Fail(NoPasswordPromptText(cachedMessage));

        // 2) osascript admin dialog — run bash against a temp script file.
        //    Inlining multi-line shell with nested quotes into `do shell script "..."`
        //    breaks AppleScript ("A identifier can't go after this \"\"" / -2740).
        string? tempPath = null;
        try
        {
            tempPath = Path.Combine(
                Path.GetTempPath(),
                $"networksentinel-pf-{Environment.ProcessId}-{Guid.NewGuid():N}.sh");
            var body = shellScript.Replace("\r\n", "\n").Replace('\r', '\n');
            if (!body.EndsWith('\n'))
                body += "\n";
            File.WriteAllText(tempPath, body);

            // Single-quoted path is safe for bash; only AS-escape the outer command.
            var shellCmd = $"/bin/bash {ShellQuote(tempPath)}";
            var asLiteral = shellCmd
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"");

            // The admin dialog waits on a human, so it gets the interactive allowance
            // rather than the 30s one used for non-interactive commands.
            var osa = RunProcessTimed(
                "osascript",
                InteractiveProcessTimeoutMs,
                "-e",
                $"do shell script \"{asLiteral}\" with administrator privileges");
            if (osa.Success)
                return osa;

            // 3) Interactive sudo when we have a TTY (TUI / Terminal) — also a human
            //    typing a password, so the same allowance applies.
            if (CommandExists("sudo") && !Console.IsInputRedirected)
                return RunProcessTimed("sudo", InteractiveProcessTimeoutMs, "/bin/bash", "-c", shellScript);

            return FirewallOperationResult.Fail(
                string.IsNullOrWhiteSpace(osa.Message)
                    ? "Need admin rights for firewall changes. Allow the password dialog, or run from Terminal with sudo."
                    : osa.Message);
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail(ex.Message);
        }
        finally
        {
            if (tempPath != null)
            {
                try { File.Delete(tempPath); }
                catch { /* ignore */ }
            }
        }
    }

    /// <summary>
    /// The sudo-but-nowhere-to-show-the-dialog case, with sudo's own refusal kept so a
    /// wrong sudoers entry is not reported as a missing one. The desktop wording named
    /// a password dialog; read in a browser pointed at a Mac in another room, that is
    /// not a thing the operator can act on, so the console gets the advice that fits it
    /// with the grant already filled in for this host.
    /// </summary>
    private static string NoPasswordPromptText(string sudoMessage)
    {
        var text =
            "The web console cannot write firewall rules: sudo wants a password, and there is nowhere " +
            "to ask for one — the macOS admin dialog is drawn on the Mac running this console, not in " +
            $"your browser.\n\n{HeadlessElevationHelp()}";
        return string.IsNullOrWhiteSpace(sudoMessage) ? text : $"{text}\n\nsudo said: {sudoMessage.Trim()}";
    }

    /// <summary>
    /// Where a firewall tool or an elevation helper is looked for. PATH first, then the
    /// standard directories — a GUI launched from Finder inherits a minimal PATH that
    /// omits /usr/local/bin, and a launchd job's is narrower still, while <c>pfctl</c>
    /// lives in /sbin and the App Firewall helper under /usr/libexec.
    /// </summary>
    private static readonly string[] FallbackToolDirectories =
    {
        "/usr/local/sbin", "/usr/local/bin", "/opt/homebrew/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"
    };

    /// <summary>
    /// Whether a command is present. This used to shell out to <c>which</c> — a process
    /// per probe, for an answer this process can work out itself by walking PATH, and
    /// one that <see cref="IsAdministrator"/> now asks for on every alert.
    /// </summary>
    private static bool CommandExists(string name) => ResolveExecutable(name) != null;

    /// <summary>
    /// Absolute path of a command, or null when it is not installed. Resolved by
    /// walking PATH and then <see cref="FallbackToolDirectories"/> in this process.
    /// </summary>
    internal static string? ResolveExecutable(string name)
    {
        if (name.Contains('/'))
            return IsExecutableFile(name) ? name : null;

        foreach (var dir in ExecutableSearchPath())
        {
            var candidate = Path.Combine(dir, name);
            if (IsExecutableFile(candidate))
                return candidate;
        }

        return null;
    }

    /// <summary>PATH, then the standard fallbacks, each directory yielded once.</summary>
    internal static IEnumerable<string> ExecutableSearchPath()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            if (seen.Add(dir))
                yield return dir;

        foreach (var dir in FallbackToolDirectories)
            if (seen.Add(dir))
                yield return dir;
    }

    /// <summary>
    /// A file that exists and carries an execute bit. The mode check matters: PATH
    /// entries routinely hold same-named data files, and a directory named like the
    /// tool would otherwise resolve as the tool.
    /// </summary>
    internal static bool IsExecutableFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            if (OperatingSystem.IsWindows()) return true;   // no Unix mode to read

            const UnixFileMode anyExecute =
                UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
            return (File.GetUnixFileMode(path) & anyExecute) != 0;
        }
        catch
        {
            return false;
        }
    }

    // ── Read-only command execution ──────────────────────────────────────
    //
    // HostFirewallScanner reads the live ruleset (`pfctl -sr`, the anchors,
    // `socketfilterfw --listapps`, `lsof`). Those are inspections, not changes,
    // so they must never raise the osascript admin dialog — a firewall view that
    // asks for a password every refresh is a view nobody opens. The order is:
    // try it as we are, then retry under `sudo -n`, which either works from
    // cached/NOPASSWD credentials or fails immediately. Where both are denied
    // the scanner falls back to the world-readable /etc/pf.conf and
    // /etc/pf.anchors, and says so in the privilege note.

    private const int ReadProcessTimeoutMs = 8_000;

    /// <summary>Whether a read-only tool is present. Absolute paths are checked directly.</summary>
    internal static bool ReadCommandExists(string path)
        => path.StartsWith('/') ? File.Exists(path) : CommandExists(path);

    /// <summary>
    /// Runs a read-only command and returns its streams separately — unlike
    /// <see cref="RunProcess"/>, which merges them, and would feed stderr into a
    /// parser. Never elevates interactively.
    /// </summary>
    internal static (bool Ok, string StdOut, string StdErr) ReadCommand(string file, params string[] args)
    {
        var direct = ReadProcess(file, args);
        if (direct.Ok && direct.StdOut.Trim().Length > 0) return direct;

        // "pfctl: /dev/pf: Permission denied" as a normal user is the usual case;
        // passwordless sudo is the one retry worth making.
        if (!IsRootProcess())
        {
            var elevated = ReadProcess("/usr/bin/sudo", new[] { "-n", file }.Concat(args).ToArray());
            if (elevated.Ok && elevated.StdOut.Trim().Length > 0) return elevated;
        }

        return direct;
    }

    private static (bool Ok, string StdOut, string StdErr) ReadProcess(string file, IReadOnlyList<string> args)
    {
        try
        {
            var psi = new ProcessStartInfo(file)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var arg in args) psi.ArgumentList.Add(arg);

            using var p = Process.Start(psi);
            if (p == null) return (false, "", $"Could not start {file}.");

            // Both pipes drained concurrently — see RunProcessTimed for why reading
            // one to EOF first deadlocks.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(ReadProcessTimeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return (false, "", $"{file} did not finish within {ReadProcessTimeoutMs / 1000}s.");
            }

            return (p.ExitCode == 0,
                    stdoutTask.GetAwaiter().GetResult(),
                    stderrTask.GetAwaiter().GetResult());
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
        }
    }

    private const int DefaultProcessTimeoutMs = 30_000;

    /// <summary>Paths that raise a password dialog include a human typing — allow minutes, not seconds.</summary>
    private const int InteractiveProcessTimeoutMs = 300_000;

    private static FirewallOperationResult RunProcess(string file, params string[] args)
        => RunProcessTimed(file, DefaultProcessTimeoutMs, args);

    private static FirewallOperationResult RunProcessTimed(string file, int timeoutMs, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            using var p = Process.Start(psi);
            if (p == null)
                return FirewallOperationResult.Fail($"Could not start {file}.");

            // Both pipes drained concurrently: reading stdout to EOF before touching
            // stderr deadlocks when the child fills the stderr buffer first — and the
            // blocked read meant the WaitForExit timeout below never engaged, so a
            // hung pfctl/osascript pinned the calling thread indefinitely.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return FirewallOperationResult.Fail($"{file} did not finish within {timeoutMs / 1000}s.");
            }

            string stdout = stdoutTask.GetAwaiter().GetResult();
            string stderr = stderrTask.GetAwaiter().GetResult();
            string combined = (stdout + "\n" + stderr).Trim();

            if (p.ExitCode == 0)
                return FirewallOperationResult.Ok(combined);

            // pfctl -e often returns non-zero when already enabled
            if (combined.Contains("pf enabled", StringComparison.OrdinalIgnoreCase) ||
                combined.Contains("already enabled", StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Ok(combined);

            return FirewallOperationResult.Fail(string.IsNullOrWhiteSpace(combined)
                ? $"{file} exit code {p.ExitCode}"
                : combined);
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail(ex.Message);
        }
    }

    // ── Rule ledger (JSON under Application Support) ─────────────────────

    private static string LedgerPath
        => Path.Combine(AppPaths.DataDirectory, "firewall-rules.json");

    private static List<FirewallRuleInfo> LoadLedger()
    {
        try
        {
            if (!File.Exists(LedgerPath)) return new List<FirewallRuleInfo>();
            var json = File.ReadAllText(LedgerPath);
            return JsonSerializer.Deserialize<List<FirewallRuleInfo>>(json, JsonOptions)
                   ?? new List<FirewallRuleInfo>();
        }
        catch
        {
            return new List<FirewallRuleInfo>();
        }
    }

    private static void SaveLedger(List<FirewallRuleInfo> rules)
    {
        try
        {
            AppPaths.WriteAtomic(LedgerPath, JsonSerializer.Serialize(rules, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    /// <summary>
    /// Serialises load-modify-save of the ledger. WriteAtomic makes each write
    /// all-or-nothing, but not the read-modify-write around it: the ledger has three
    /// writers (the expiry sweep, startup reconciliation, and auto-block), and two
    /// interleaving reads both saved their own stale snapshot — erasing a block
    /// recorded meanwhile and orphaning its PF rule, invisible to the UI and to the
    /// sweep. Process-wide only: a desktop app and a launchd web console sharing one
    /// data directory can still lose an update to each other, which needs flock.
    /// </summary>
    private static readonly object LedgerGate = new();

    private static void UpsertLedger(FirewallRuleInfo rule)
    {
        lock (LedgerGate)
        {
            var list = LoadLedger();
            list.RemoveAll(r => string.Equals(r.Name, rule.Name, StringComparison.OrdinalIgnoreCase));
            list.Add(rule);
            SaveLedger(list);
        }
    }

    private static void RemoveFromLedger(string name)
    {
        lock (LedgerGate)
        {
            var list = LoadLedger();
            list.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            SaveLedger(list);
        }
    }

    public static string IpRuleName(string ip, bool inbound)
        => $"{RulePrefix}-IP-{Sanitize(ip)}-{(inbound ? "In" : "Out")}";

    public static string PortRuleName(int port, string protocol, bool inbound)
        => $"{RulePrefix}-Port-{protocol.ToUpperInvariant()}-{port}-{(inbound ? "In" : "Out")}";

    private static string Sanitize(string value)
        => Regex.Replace(value, @"[^A-Za-z0-9.\-_]", "_");

    private static string ShellQuote(string value)
    {
        if (string.IsNullOrEmpty(value)) return "''";
        return "'" + value.Replace("'", "'\\''") + "'";
    }

    public static bool TryNormalizeIp(string? ip, out string normalized, out string error)
    {
        normalized = "";
        error = "";
        if (string.IsNullOrWhiteSpace(ip))
        {
            error = "IP address is empty.";
            return false;
        }

        ip = ip.Trim();
        if (ip.StartsWith('['))
        {
            var end = ip.IndexOf(']');
            if (end > 1)
                ip = ip[1..end];
        }
        else if (ip.Contains(':') && IPAddress.TryParse(ip, out _) == false)
        {
            var idx = ip.LastIndexOf(':');
            if (idx > 0 && ip.Count(c => c == ':') == 1)
                ip = ip[..idx];
        }

        if (!IPAddress.TryParse(ip, out var address))
        {
            error = $"Invalid IP address: {ip}";
            return false;
        }

        // ::ffff:a.b.c.d is how dual-stack sockets report IPv4 peers — rules and
        // bookkeeping should use the IPv4 form so both spellings mean one address.
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        // Drop any IPv6 zone id (fe80::1%en0 parses fine but pfctl rejects it in a
        // rule, and two zone spellings of one address must compare equal).
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            address = new IPAddress(address.GetAddressBytes());

        normalized = address.ToString();
        return true;
    }

    public static bool IsPrivateOrLocal(string ip)
        => GeoIpService.IsNonPublic(ip);

    /// <summary>
    /// Addresses no rule may ever target, because dropping them breaks the machine's
    /// own connectivity: LAN, loopback, link-local, multicast/broadcast.
    ///
    /// Narrower than <see cref="IsPrivateOrLocal"/>, which also covers CGNAT and is
    /// the right gate for <em>automatic</em> blocking. Blocking a tunnel peer is a
    /// bad default, not an impossible request — a hostile tailnet peer brute-forcing
    /// SSH is a real case, and refusing it in the manual path too left the operator
    /// with no way to stop the attack from inside the app.
    /// </summary>
    public static bool IsNeverBlockable(string ip)
        => GeoIpService.IsNonPublic(ip) && !GeoIpService.IsCarrierGradeNat(ip);

    [DllImport("libc")]
    private static extern uint geteuid();
}

public enum FirewallDirection
{
    Inbound,
    Outbound,
    Both
}

public enum FirewallRuleKind
{
    IpBlock,
    PortBlock,
    Other,

    /// <summary>
    /// A rule the operator wrote in the Firewall Config view: any action, any
    /// direction, a protocol, a port range and an address list. The other kinds
    /// are minted by the app (auto-block, manual block, probe logging).
    /// </summary>
    Custom
}

public sealed class FirewallRuleInfo
{
    public string Name { get; init; } = "";

    /// <summary>
    /// Operator-facing name for a Firewall Config rule (<c>block-inbound-ssh</c>).
    /// Empty on rules the app minted itself, which fall back to a description
    /// derived from what they match.
    /// </summary>
    public string Label { get; init; } = "";

    public string Description { get; init; } = "";
    public bool Enabled { get; init; }
    public bool IsBlock { get; init; }
    public FirewallDirection Direction { get; init; }
    public string RemoteAddresses { get; init; } = "";
    public string LocalPorts { get; init; } = "";
    public string Protocol { get; init; } = "Any";
    public FirewallRuleKind Kind { get; init; }

    /// <summary>UTC time this rule stops applying (null = permanent). Set by auto-block expiry.</summary>
    public DateTime? ExpiresUtc { get; init; }

    // ── Host-scan fields ─────────────────────────────────────────────────
    //
    // Set by HostFirewallScanner on rules read back out of the kernel, which is
    // most of what the Firewall Config view lists: the pf.conf ruleset, Apple's
    // anchors, the Application Firewall's per-app entries, and this app's own
    // anchor. They are never persisted — the ledger holds only rules Network
    // Sentinel wrote, and it already knows their shape.

    /// <summary>
    /// Which subsystem put the rule in force — "Network Sentinel", "macOS",
    /// "Application Firewall", "Internet Sharing", "PF". Drives the Created by
    /// column, so a foreign rule is never mistaken for one this app owns.
    /// </summary>
    [JsonIgnore] public string Origin { get; init; } = "";

    /// <summary>
    /// The PF anchor the rule lives in, empty for the main ruleset. Deleting a
    /// rule means knowing which anchor holds it — pf has no rule handles, so the
    /// anchor is as specific as an identifier gets.
    /// </summary>
    [JsonIgnore] public string Handle { get; init; } = "";

    /// <summary>PF anchor path, or the ALF app path for an Application Firewall entry.</summary>
    [JsonIgnore] public string Table { get; init; } = "";

    /// <summary>Interface the rule is pinned to ("on en0"), empty when it matches every one.</summary>
    [JsonIgnore] public string Chain { get; init; } = "";

    /// <summary>Address family — <c>inet</c>, <c>inet6</c>, or empty for both.</summary>
    [JsonIgnore] public string Family { get; init; } = "";

    /// <summary>
    /// True for a rule read out of the kernel that this app did not write. The
    /// editor still opens it, but deletes route to whichever backend owns it.
    /// </summary>
    [JsonIgnore] public bool IsForeign { get; init; }

    /// <summary>
    /// Which subsystem holds the rule — "pf" or "alf". Deletes route on it: an
    /// Application Firewall entry comes out through socketfilterfw, while a pf
    /// rule belongs to whichever anchor file declares it.
    /// </summary>
    [JsonIgnore] public string Backend { get; init; } = "";

    /// <summary>Verdict as PF words it: Pass, Drop, Reject.</summary>
    [JsonIgnore] public string Verdict { get; init; } = "";

    /// <summary>
    /// The rule's own PF label, empty when it carries none. Distinct from
    /// <see cref="Label"/>, which falls back to a minted name — an unnamed bare
    /// pass in the main ruleset is plumbing, and only the label tells them apart.
    /// </summary>
    [JsonIgnore] public string Comment { get; init; } = "";

    public bool IsExpired => ExpiresUtc.HasValue && ExpiresUtc.Value <= DateTime.UtcNow;

    public string ExpiryText => ExpiresUtc.HasValue
        ? (IsExpired ? "Expired" : $"Expires {ExpiresUtc.Value.ToLocalTime():HH:mm}")
        : "Permanent";

    public string DirectionText => Direction.ToString();
    public string KindText => Kind switch
    {
        FirewallRuleKind.IpBlock => "IP block",
        FirewallRuleKind.PortBlock => "Port block",
        FirewallRuleKind.Custom => "Config rule",
        _ => "Rule"
    };

    /// <summary>Only Firewall Config rules can be edited; the rest are app-minted.</summary>
    public bool IsCustom => Kind == FirewallRuleKind.Custom;

    public bool IsInbound => Direction != FirewallDirection.Outbound;

    /// <summary>Label column: the operator's name, or a description of what the rule matches.</summary>
    public string LabelText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Label)) return Label;
            return Kind switch
            {
                FirewallRuleKind.IpBlock => $"auto-block-{(IsInbound ? "inbound" : "outbound")}-{AddressText}",
                FirewallRuleKind.PortBlock => $"block-{(IsInbound ? "inbound" : "outbound")}-port-{LocalPorts}",
                _ => Name
            };
        }
    }

    /// <summary>Where the rule came from, so app-minted rules are not mistaken for config.</summary>
    public string OriginText
    {
        get
        {
            // A scanned rule already knows who wrote it; the ledger kinds below
            // only describe rules this app minted.
            if (!string.IsNullOrWhiteSpace(Origin)) return Origin;

            if (string.Equals(Name, FirewallService.ProbeLogRuleName, StringComparison.OrdinalIgnoreCase))
                return "Probe logging";

            return Kind switch
            {
                FirewallRuleKind.IpBlock => "Auto/manual block",
                FirewallRuleKind.PortBlock => "Port block",
                FirewallRuleKind.Custom => "Firewall config",
                _ => "Managed"
            };
        }
    }

    public string ProtocolText => string.IsNullOrWhiteSpace(Protocol) ? "Any" : Protocol;

    public string PortRangeText => string.IsNullOrWhiteSpace(LocalPorts) ? "All ports" : LocalPorts;

    /// <summary>Sources on an inbound rule, destinations on an outbound one.</summary>
    public string AddressListText => string.IsNullOrWhiteSpace(RemoteAddresses)
        ? FirewallRuleSpecs.AnyAddressText
        : RemoteAddresses;
    /// <summary>Best-effort IP target for display (falls back to parsing the rule name).</summary>
    public string AddressText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(RemoteAddresses) && RemoteAddresses is not ("Any" or "*"))
                return RemoteAddresses;
            var ipMatch = Regex.Match(
                Name,
                @"^NetworkSentinel-IP-(.+)-(In|Out)$",
                RegexOptions.IgnoreCase);
            if (ipMatch.Success)
                return ipMatch.Groups[1].Value.Replace('_', ':');
            return "";
        }
    }

    public string TargetText => Kind == FirewallRuleKind.IpBlock
        ? (string.IsNullOrWhiteSpace(RemoteAddresses) ? "—" : RemoteAddresses)
        : $"{Protocol}/{LocalPorts}";
    public string EnabledText => Enabled ? "On" : "Off";
    /// <summary>
    /// Block, Allow — or Log, for a scanned <c>pass … log … no state</c> rule.
    /// Calling that one "Allow" is technically true and practically a lie: this
    /// app's own probe-log rule matches every TCP port, so the list would carry a
    /// row reading "Allow · TCP · all ports · anywhere" that nobody wrote as a
    /// permission. Only the scan sets <see cref="Verdict"/>, so ledger rules are
    /// unaffected.
    /// </summary>
    public string ActionText => Verdict.Equals("Log", StringComparison.OrdinalIgnoreCase)
        ? "Log"
        : IsBlock ? "Block" : "Allow";
}

public sealed class FirewallOperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = "";

    public static FirewallOperationResult Ok(string message) => new() { Success = true, Message = message };
    public static FirewallOperationResult Fail(string message) => new() { Success = false, Message = message };
}
