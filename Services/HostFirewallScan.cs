using System.Globalization;
using System.Text.RegularExpressions;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>One listening socket, with the verdict the firewall passes on it.</summary>
public sealed class HostListener
{
    public string Protocol { get; init; } = "TCP";
    public string Address { get; init; } = "";
    public string Port { get; init; } = "";
    public string Process { get; init; } = "—";
    public string State { get; init; } = "LISTEN";

    /// <summary>
    /// "Open", "Restricted", "Not allowed", "Local only" or "No firewall" — what
    /// the inbound rules do to traffic arriving here. A listener the firewall
    /// does not admit is not reachable, however loudly it is listening, and a
    /// listener nothing covers is the one worth knowing about.
    /// </summary>
    public string Covered { get; set; } = "Unknown";

    public string ServiceName =>
        int.TryParse(Port, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p)
            ? PortCatalog.GetHint(p, Protocol)
            : Port;
}

/// <summary>
/// The host firewall as one scan: the rules actually in the kernel, the default
/// policies, and what is listening behind them.
/// </summary>
public sealed class HostFirewallSnapshot
{
    /// <summary>The machine — the firewall is named after the host it protects.</summary>
    public string HostLabel { get; init; } = "";

    /// <summary>"PF", "Application Firewall", "PF + Application Firewall" or "none".</summary>
    public string Backend { get; init; } = "none";

    public string Status { get; init; } = "Unknown";
    public bool Enabled { get; init; }
    public string DefaultInbound { get; init; } = "Unknown";
    public string DefaultOutbound { get; init; } = "Unknown";
    public string Description { get; init; } = "";

    /// <summary>What could not be read, and what would fix it.</summary>
    public string PrivilegeNote { get; init; } = "";

    public IReadOnlyList<FirewallRuleInfo> Inbound { get; init; } = Array.Empty<FirewallRuleInfo>();
    public IReadOnlyList<FirewallRuleInfo> Outbound { get; init; } = Array.Empty<FirewallRuleInfo>();
    public IReadOnlyList<HostListener> Listeners { get; init; } = Array.Empty<HostListener>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> BackendsSeen { get; init; } = Array.Empty<string>();
    public DateTime ScannedUtc { get; init; } = DateTime.UtcNow;

    public string RulesSummary
    {
        get
        {
            var parts = new List<string>();
            if (Inbound.Count > 0) parts.Add($"{Inbound.Count} Inbound");
            if (Outbound.Count > 0) parts.Add($"{Outbound.Count} Outbound");
            return parts.Count > 0 ? string.Join(" · ", parts) : "No rules";
        }
    }

    /// <summary>Inbound rules that admit traffic — the ports genuinely open.</summary>
    public IReadOnlyList<FirewallRuleInfo> OpenPorts => Inbound.Where(r => !r.IsBlock).ToList();

    public static HostFirewallSnapshot Unreadable(string note, IReadOnlyList<string>? errors = null) => new()
    {
        HostLabel = Environment.MachineName,
        Backend = "none",
        Status = "Unknown",
        Description = "No PF ruleset or Application Firewall state could be read.",
        PrivilegeNote = note,
        Errors = errors ?? Array.Empty<string>()
    };
}

/// <summary>One backend's contribution, before the fold into a single firewall.</summary>
internal sealed class BackendRules
{
    public List<FirewallRuleInfo> Inbound { get; } = new();
    public List<FirewallRuleInfo> Outbound { get; } = new();
    public string DefaultInbound { get; set; } = "Accept";
    public string DefaultOutbound { get; set; } = "Accept";
    public bool Enabled { get; set; }
    public string Status { get; set; } = "Disabled";
    public bool Any => Inbound.Count > 0 || Outbound.Count > 0;
}

/// <summary>
/// Reads the host firewall the way
/// <see href="https://github.com/davidfweiser/FireWallConfig">FireWallConfig</see>
/// does, and for the same reason. The Firewall Config view used to list only
/// what this app had written itself, out of its own JSON ledger. On a Mac that is
/// a near-empty list sitting next to a pf ruleset and an Application Firewall
/// that between them decide what actually reaches the machine. One machine has
/// one firewall; this reads all of it.
///
/// macOS runs two firewalls at once and they answer different questions, so both
/// are read and folded into one list:
/// <list type="table">
/// <item><term>PF</term><description><c>pfctl -si</c>, <c>-sr</c>, <c>-sA</c> and each anchor — packet filtering by address and port</description></item>
/// <item><term>ALF</term><description><c>socketfilterfw</c> — the per-application firewall from System Settings</description></item>
/// <item><term>Listeners</term><description><c>lsof -nP -iTCP -sTCP:LISTEN</c>, falling back to <c>netstat -an</c></description></item>
/// </list>
///
/// pfctl needs root to open /dev/pf, and the reads must never raise a password
/// dialog (see <see cref="FirewallService.ReadCommand"/>), so a normal user run
/// falls back to the world-readable <c>/etc/pf.conf</c> and <c>/etc/pf.anchors</c>.
/// That fallback is not merely a stub: this app's own rules live in
/// <c>/etc/pf.anchors/com.networksentinel</c>, so the list stays useful without
/// elevation and the policy line says when a short list is a privilege problem
/// rather than an empty firewall.
///
/// Every parser is static and takes text, so the suite exercises them against
/// captured output with no firewall and no root shell.
/// </summary>
public sealed class HostFirewallScanner
{
    private readonly FirewallService _firewall;

    public HostFirewallScanner(FirewallService firewall) => _firewall = firewall;

    internal const string Pfctl = "/sbin/pfctl";
    internal const string SocketFilterFw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    internal const string Lsof = "/usr/sbin/lsof";
    internal const string Netstat = "/usr/sbin/netstat";

    internal const string PfConfPath = "/etc/pf.conf";
    internal const string PfAnchorDirectory = "/etc/pf.anchors";

    /// <summary>
    /// Anchors whose contents are Apple's own plumbing. They are listed by name
    /// so the fold can attribute them, not skipped — an operator who turned on
    /// Internet Sharing should see what it opened.
    /// </summary>
    private static readonly Dictionary<string, string> KnownAnchors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["com.apple"] = "macOS",
        ["com.apple/200.AirDrop"] = "AirDrop",
        ["com.apple/250.ApplicationFirewall"] = "Application Firewall",
        ["com.apple.internet-sharing"] = "Internet Sharing",
        [FirewallService.PfAnchorName] = "Network Sentinel"
    };

    public HostFirewallSnapshot Scan()
    {
        var errors = new List<string>();
        var backends = new List<string>();

        var pf = CollectPf(errors, backends);
        var alf = CollectAlf(errors, backends);

        var inbound = new List<FirewallRuleInfo>();
        var outbound = new List<FirewallRuleInfo>();
        var defaultIn = "Accept";
        var defaultOut = "Accept";
        var enabled = false;
        var status = "Disabled";

        if (pf != null)
        {
            inbound.AddRange(pf.Inbound.Where(r => !IsPlumbing(r)));
            outbound.AddRange(pf.Outbound.Where(r => !IsPlumbing(r)));
            defaultIn = pf.DefaultInbound;
            defaultOut = pf.DefaultOutbound;
            enabled = pf.Enabled;
            status = pf.Status;
        }

        if (alf != null)
        {
            inbound.AddRange(alf.Inbound);
            // The Application Firewall only filters inbound, so it never widens the
            // outbound default — but a blanket block-all is the stricter inbound
            // policy of the two and wins.
            if (alf.Enabled)
            {
                enabled = true;
                if (alf.DefaultInbound == "Drop") defaultIn = "Drop";
                if (pf is not { Enabled: true }) status = alf.Status;
            }
        }

        inbound = Dedupe(inbound);
        outbound = Dedupe(outbound);
        AttributeOwnRules(inbound);
        AttributeOwnRules(outbound);

        var backend = (pf, alf) switch
        {
            (not null, not null) => "PF + Application Firewall",
            (not null, null) => "PF",
            (null, not null) => "Application Firewall",
            _ => "none"
        };

        var listeners = CollectListeners(errors);
        AnnotateCoverage(listeners, inbound, enabled);

        var note = PrivilegeNote();
        if (backend == "none")
        {
            return HostFirewallSnapshot.Unreadable(
                "Neither PF nor the Application Firewall returned any state. " + note, errors);
        }

        return new HostFirewallSnapshot
        {
            HostLabel = Environment.MachineName,
            Backend = backend,
            Status = status,
            Enabled = enabled,
            DefaultInbound = defaultIn,
            DefaultOutbound = defaultOut,
            Description = $"Host firewall ({backend}).",
            PrivilegeNote = note,
            Inbound = inbound,
            Outbound = outbound,
            Listeners = listeners,
            Errors = errors,
            BackendsSeen = backends.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private string PrivilegeNote()
    {
        if (_firewall.IsRoot)
            return "Running as root — the live PF ruleset and every process name are visible.";
        return "Running unprivileged: pfctl needs root to open /dev/pf, so the ruleset is read through " +
               "sudo -n where that is allowed and from /etc/pf.conf and /etc/pf.anchors otherwise. " +
               "lsof shows only this user's processes. Run the app elevated if the list looks short.";
    }

    // ── PF ───────────────────────────────────────────────────────────────

    /// <summary>
    /// The live ruleset where pfctl can be run, the config files where it cannot.
    /// Both paths produce the same shape, and the anchors are walked either way —
    /// this app's own rules live in one, so an unprivileged read still shows them.
    /// </summary>
    private BackendRules? CollectPf(List<string> errors, List<string> backends)
    {
        if (!FirewallService.ReadCommandExists(Pfctl) && !File.Exists(PfConfPath)) return null;

        var result = new BackendRules();
        var live = false;

        var info = FirewallService.ReadCommand(Pfctl, "-si");
        if (info.Ok && info.StdOut.Trim().Length > 0)
        {
            live = true;
            var (pfEnabled, pfStatus) = ParsePfStatus(info.StdOut);
            result.Enabled = pfEnabled;
            result.Status = pfStatus;
        }
        else if (!string.IsNullOrWhiteSpace(info.StdErr))
        {
            errors.Add("pfctl -si: " + FirstLine(info.StdErr));
        }

        if (live)
        {
            backends.Add("pfctl");
            var main = FirewallService.ReadCommand(Pfctl, "-sr");
            if (main.Ok) Fold(result, ParsePfRules(main.StdOut, origin: "PF", anchor: "", source: "pfctl -sr"));
            else if (!string.IsNullOrWhiteSpace(main.StdErr)) errors.Add("pfctl -sr: " + FirstLine(main.StdErr));

            var anchors = FirewallService.ReadCommand(Pfctl, "-sA");
            foreach (var anchor in ParseAnchorList(anchors.StdOut))
            {
                var rules = FirewallService.ReadCommand(Pfctl, "-a", anchor, "-sr");
                if (!rules.Ok || rules.StdOut.Trim().Length == 0) continue;
                Fold(result, ParsePfRules(rules.StdOut, OriginForAnchor(anchor), anchor, $"pfctl -a {anchor} -sr"));
            }
        }
        else
        {
            // Unprivileged fallback. /etc/pf.conf is the ruleset macOS loads at
            // boot, so it is what pfctl would have shown, minus anything a running
            // service inserted dynamically — which is why the privilege note says so.
            if (!File.Exists(PfConfPath)) return result.Any || result.Enabled ? result : null;
            backends.Add("/etc/pf.conf");

            var conf = ReadTextFile(PfConfPath, errors);
            Fold(result, ParsePfRules(conf, origin: "PF", anchor: "", source: PfConfPath));

            foreach (var anchor in ParseAnchorList(conf.Length > 0 ? ExtractAnchorNames(conf) : ""))
            {
                var path = Path.Combine(PfAnchorDirectory, anchor);
                if (!File.Exists(path)) continue;
                backends.Add(path);
                Fold(result, ParsePfRules(ReadTextFile(path, errors), OriginForAnchor(anchor), anchor, path));
            }

            // The config file says what is loaded, never whether pf is running —
            // `pfctl -si` is the only answer to that and it was denied.
            result.Status = "Unknown (needs root)";
        }

        if (result.Inbound.Any(r => r.IsBlock && IsCatchAllRule(r)))
            result.DefaultInbound = "Drop";
        if (result.Outbound.Any(r => r.IsBlock && IsCatchAllRule(r)))
            result.DefaultOutbound = "Drop";

        return result;
    }

    private static void Fold(BackendRules target, BackendRules source)
    {
        target.Inbound.AddRange(source.Inbound);
        target.Outbound.AddRange(source.Outbound);
    }

    private static string OriginForAnchor(string anchor)
    {
        if (KnownAnchors.TryGetValue(anchor, out var known)) return known;
        // "com.apple/250.ApplicationFirewall" nested under a wildcard parent.
        foreach (var (prefix, label) in KnownAnchors)
        {
            if (anchor.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase)) return label;
        }
        return anchor.Length > 0 ? anchor : "PF";
    }

    private static string ReadTextFile(string path, List<string> errors)
    {
        try { return File.ReadAllText(path); }
        catch (Exception ex) { errors.Add($"{path}: {ex.Message}"); return ""; }
    }

    /// <summary>Parses the first line of <c>pfctl -si</c>: "Status: Enabled for 0 days …".</summary>
    internal static (bool Enabled, string Status) ParsePfStatus(string text)
    {
        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("Status:", StringComparison.OrdinalIgnoreCase)) continue;

            var rest = line["Status:".Length..].Trim();
            if (rest.StartsWith("Enabled", StringComparison.OrdinalIgnoreCase)) return (true, "Enabled");
            if (rest.StartsWith("Disabled", StringComparison.OrdinalIgnoreCase)) return (false, "Disabled");
            return (false, rest.Length > 0 ? Capitalize(rest.Split(' ')[0]) : "Unknown");
        }
        return (false, "Unknown");
    }

    /// <summary>
    /// Anchor names, one per line and indented, from <c>pfctl -sA</c>. Wildcard
    /// parents ("com.apple/*") are dropped — they are a reference to the children,
    /// which the listing names in their own right.
    /// </summary>
    internal static IEnumerable<string> ParseAnchorList(string text)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim().Trim('"');
            if (line.Length == 0 || line.EndsWith("/*", StringComparison.Ordinal)) continue;
            if (line.Contains(' ')) continue;
            if (seen.Add(line)) yield return line;
        }
    }

    private static readonly Regex AnchorReference =
        new(@"^\s*(?:load\s+)?anchor\s+""([^""]+)""", RegexOptions.Compiled | RegexOptions.Multiline);

    /// <summary>Anchor names referenced by a pf.conf, for the unprivileged path.</summary>
    internal static string ExtractAnchorNames(string conf)
        => string.Join("\n", AnchorReference.Matches(conf ?? "")
            .Select(m => m.Groups[1].Value)
            .Where(n => !n.EndsWith("/*", StringComparison.Ordinal)));

    /// <summary>
    /// Parses PF rule syntax, as printed by <c>pfctl -sr</c> and as written in
    /// pf.conf. Hand-tokenised rather than pattern-matched: PF takes braced lists
    /// (<c>port { 80 443 }</c>, <c>from { 10.0.0.1 10.0.0.2 }</c>) and a regex
    /// that copes with those is less readable than the loop, not more.
    ///
    /// Which end of the rule matters depends on the direction, and it is the same
    /// convention <see cref="FirewallRuleSpecs.BuildPfLine"/> writes: an inbound
    /// rule is about the source address and the local port it arrives on, an
    /// outbound rule about the destination address and the port being reached.
    /// </summary>
    internal static BackendRules ParsePfRules(string text, string origin, string anchor, string source = "")
    {
        var result = new BackendRules();

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var rule = ParsePfLine(raw, origin, anchor, source);
            if (rule == null) continue;
            if (rule.Direction == FirewallDirection.Outbound) result.Outbound.Add(rule);
            else result.Inbound.Add(rule);
        }

        return result;
    }

    internal static FirewallRuleInfo? ParsePfLine(string raw, string origin, string anchor, string source = "")
    {
        var line = StripComment(raw);
        if (line.Length == 0) return null;

        var tokens = Tokenize(line);
        if (tokens.Count == 0) return null;

        var verb = tokens[0].ToLowerInvariant();
        if (verb is not ("pass" or "block")) return null;

        var isBlock = verb == "block";
        var outbound = false;
        var directionSeen = false;
        var quick = false;
        var iface = "";
        var family = "";
        var protocol = FirewallRuleSpecs.ProtocolAny;
        var sources = new List<string>();
        var destinations = new List<string>();
        var sourcePorts = "";
        var destPorts = "";
        var label = "";
        var verdict = isBlock ? "Drop" : "Pass";
        var logSeen = false;
        var statelessSeen = false;

        for (var i = 1; i < tokens.Count; i++)
        {
            var token = tokens[i].ToLowerInvariant();
            switch (token)
            {
                case "in": outbound = false; directionSeen = true; break;
                case "out": outbound = true; directionSeen = true; break;
                case "quick": quick = true; break;
                case "log": logSeen = true; break;
                case "drop": verdict = "Drop"; break;
                case "return":
                case "return-rst":
                case "return-icmp":
                case "return-icmp6":
                    verdict = "Reject";
                    break;
                case "inet": family = "inet"; break;
                case "inet6": family = "inet6"; break;
                case "all":
                    // Shorthand for "from any to any" — nothing to record.
                    break;
                case "on":
                    if (i + 1 < tokens.Count)
                    {
                        iface = tokens[++i];
                        // "on ! lo0" — the negation belongs with the name.
                        if (iface == "!" && i + 1 < tokens.Count) iface = "!" + tokens[++i];
                    }
                    break;
                case "proto":
                    if (i + 1 < tokens.Count) protocol = NormalizeProtocolWord(StripBraces(tokens[++i]));
                    break;
                case "from":
                    if (i + 1 < tokens.Count) sources.AddRange(SplitList(tokens[++i]));
                    break;
                case "to":
                    if (i + 1 < tokens.Count) destinations.AddRange(SplitList(tokens[++i]));
                    break;
                case "port":
                    if (i + 1 < tokens.Count)
                    {
                        var spec = ParsePortSpec(tokens, ref i);
                        // A port that follows "from" belongs to the source; the rule's
                        // own port — the one an operator means — follows "to".
                        if (LastAddressKeyword(tokens, i) == "from") sourcePorts = MergePorts(sourcePorts, spec);
                        else destPorts = MergePorts(destPorts, spec);
                    }
                    break;
                case "label":
                    if (i + 1 < tokens.Count) label = tokens[++i].Trim('"');
                    break;
                case "tag":
                    if (i + 1 < tokens.Count) i++;
                    break;
                case "flags":
                case "keep":
                case "modulate":
                case "synproxy":
                    if (i + 1 < tokens.Count) i++;
                    break;
                case "no":
                    // "no state" — one word of payload.
                    if (i + 1 < tokens.Count && tokens[i + 1].Equals("state", StringComparison.OrdinalIgnoreCase))
                        statelessSeen = true;
                    if (i + 1 < tokens.Count) i++;
                    break;
            }
        }

        // PF without an explicit direction filters both ways. It is listed as
        // inbound, which is the direction the reachability question is about.
        _ = directionSeen;
        _ = quick;

        // `pass in log ... no state` is instrumentation, not a decision: it is how
        // this app's own probe logging sees SYNs to closed ports, and how a tcpdump
        // rule is usually written. It passes, so it cannot be called a block — but
        // counting it as an admission would mark every port on the machine Open the
        // moment probe logging was switched on, which is the opposite of what the
        // reachability column is for.
        if (verdict == "Pass" && logSeen && statelessSeen) verdict = "Log";

        var addresses = outbound ? destinations : sources;
        var ports = destPorts.Length > 0 ? destPorts : sourcePorts;

        return BuildRule(
            action: verdict,
            protocol: protocol,
            ports: ports,
            addresses: JoinSources(addresses, family),
            outbound: outbound,
            origin: origin,
            backend: "pf",
            table: source,
            chain: iface,
            family: family,
            comment: label,
            handle: anchor);
    }

    /// <summary>
    /// Which address keyword a "port" clause belongs to. PF writes
    /// <c>from any port 1024:65535 to any port 22</c>, so the nearest preceding
    /// from/to decides whose port it is.
    /// </summary>
    private static string LastAddressKeyword(List<string> tokens, int index)
    {
        for (var i = index; i >= 0; i--)
        {
            var token = tokens[i].ToLowerInvariant();
            if (token is "from" or "to") return token;
        }
        return "to";
    }

    /// <summary>
    /// Reads a port clause, which PF writes several ways: <c>port = 22</c>,
    /// <c>port 8000:8001</c>, <c>port { 80 443 }</c>, <c>port &gt; 1024</c>. The
    /// comparison operators are kept verbatim so a rule is never shown as more
    /// specific than it is.
    /// </summary>
    private static string ParsePortSpec(List<string> tokens, ref int index)
    {
        var next = tokens[++index];
        var op = "";
        if (next is "=" or "!=" or "<" or ">" or "<=" or ">=")
        {
            op = next == "=" ? "" : next;
            if (index + 1 >= tokens.Count) return "";
            next = tokens[++index];
        }

        var value = StripBraces(next).Replace(":", "-");
        var joined = string.Join(", ", SplitList(value).Where(v => v.Length > 0));
        return op.Length > 0 ? $"{op} {joined}" : joined;
    }

    /// <summary>Splits a PF token that may be a braced list into its members.</summary>
    private static IEnumerable<string> SplitList(string token)
        => StripBraces(token)
            .Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(t => t != "{" && t != "}");

    private static string StripBraces(string token)
        => token.Trim().Trim('{', '}').Trim();

    private static string StripComment(string raw)
    {
        var line = (raw ?? "").Trim();
        var hash = line.IndexOf('#');
        // Only a comment that starts the line or follows whitespace — a '#' can
        // appear inside a quoted label.
        if (hash == 0) return "";
        if (hash > 0 && line.Count(c => c == '"') % 2 == 0 && line[hash - 1] == ' ')
            line = line[..hash].Trim();
        return line;
    }

    /// <summary>
    /// Splits a PF line into tokens, keeping a braced list as one token and a
    /// quoted string intact. <c>from { 10.0.0.1 10.0.0.2 } to any</c> becomes
    /// four tokens, not eight.
    /// </summary>
    internal static List<string> Tokenize(string line)
    {
        var tokens = new List<string>();
        var current = new System.Text.StringBuilder();
        var depth = 0;
        var quoted = false;

        foreach (var c in line)
        {
            if (c == '"')
            {
                quoted = !quoted;
                current.Append(c);
                continue;
            }
            if (!quoted && c == '{') depth++;
            if (!quoted && c == '}') depth--;

            if (!quoted && depth == 0 && char.IsWhiteSpace(c))
            {
                if (current.Length > 0) { tokens.Add(current.ToString()); current.Clear(); }
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0) tokens.Add(current.ToString());

        return tokens.Select(t => t.Trim()).Where(t => t.Length > 0).ToList();
    }

    // ── Application Firewall ─────────────────────────────────────────────

    /// <summary>
    /// The per-application firewall from System Settings — the one most Mac
    /// operators mean by "the firewall", and the one pf says nothing about. Its
    /// entries are inbound decisions per binary rather than per port, so they are
    /// listed as address-less inbound rules named after the app.
    /// </summary>
    private BackendRules? CollectAlf(List<string> errors, List<string> backends)
    {
        if (!FirewallService.ReadCommandExists(SocketFilterFw)) return null;

        var state = FirewallService.ReadCommand(SocketFilterFw, "--getglobalstate");
        if (!state.Ok && state.StdOut.Trim().Length == 0)
        {
            if (!string.IsNullOrWhiteSpace(state.StdErr))
                errors.Add("socketfilterfw: " + FirstLine(state.StdErr));
            return null;
        }

        backends.Add("socketfilterfw");
        var result = new BackendRules
        {
            Enabled = ParseAlfEnabled(state.StdOut),
            Status = ParseAlfEnabled(state.StdOut) ? "Enabled" : "Disabled"
        };

        var blockAll = FirewallService.ReadCommand(SocketFilterFw, "--getblockall");
        result.DefaultInbound = ParseAlfBlockAll(blockAll.StdOut) ? "Drop" : "Accept";

        var apps = FirewallService.ReadCommand(SocketFilterFw, "--listapps");
        if (apps.StdOut.Trim().Length > 0)
            result.Inbound.AddRange(ParseAlfApps(apps.StdOut));
        else if (!string.IsNullOrWhiteSpace(apps.StdErr))
            errors.Add("socketfilterfw --listapps: " + FirstLine(apps.StdErr));

        return result;
    }

    /// <summary>"Firewall is enabled. (State = 1)" — the parenthesised state is the reliable half.</summary>
    internal static bool ParseAlfEnabled(string text)
    {
        var line = (text ?? "").Trim();
        if (Regex.IsMatch(line, @"State\s*=\s*[12]")) return true;
        if (Regex.IsMatch(line, @"State\s*=\s*0")) return false;
        return line.Contains("enabled", StringComparison.OrdinalIgnoreCase) &&
               !line.Contains("disabled", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"Firewall has block all state set to disabled." — block-all overrides every app entry.</summary>
    internal static bool ParseAlfBlockAll(string text)
    {
        var line = (text ?? "").Trim();
        if (line.Length == 0) return false;
        // The sentence names the setting before its value, so "block all … enabled"
        // must be read from the end rather than by searching for "enabled".
        return line.TrimEnd('.').EndsWith("enabled", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly Regex AlfAppLine =
        new(@"^\s*\d+\s*:\s*(?<path>.+?)\s*$", RegexOptions.Compiled);

    /// <summary>
    /// Parses <c>socketfilterfw --listapps</c>, whose entries span two lines: a
    /// numbered path, then the verdict in parentheses beneath it.
    /// </summary>
    internal static List<FirewallRuleInfo> ParseAlfApps(string text)
    {
        var result = new List<FirewallRuleInfo>();
        string? pending = null;

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Trim().Length == 0) continue;

            var trimmed = line.Trim();
            if (trimmed.StartsWith("Total number of apps", StringComparison.OrdinalIgnoreCase)) continue;

            if (trimmed.StartsWith('(') )
            {
                if (pending == null) continue;
                var block = trimmed.Contains("Block", StringComparison.OrdinalIgnoreCase);
                result.Add(AlfRule(pending, block));
                pending = null;
                continue;
            }

            var match = AlfAppLine.Match(line);
            if (match.Success) pending = match.Groups["path"].Value.Trim();
        }

        return result;
    }

    private static FirewallRuleInfo AlfRule(string path, bool block)
    {
        var app = Path.GetFileName(path.TrimEnd('/'));
        if (app.Length == 0) app = path;

        return new FirewallRuleInfo
        {
            Name = app,
            Label = app,
            Description = $"{(block ? "Block" : "Allow")} incoming connections to {path}",
            Enabled = true,
            IsBlock = block,
            Direction = FirewallDirection.Inbound,
            RemoteAddresses = FirewallRuleSpecs.AnyAddressText,
            LocalPorts = "",
            Protocol = FirewallRuleSpecs.ProtocolAny,
            Kind = FirewallRuleKind.Other,
            Backend = "alf",
            Origin = "Application Firewall",
            Table = path,
            IsForeign = true,
            Verdict = block ? "Drop" : "Pass",
            Comment = app
        };
    }

    // ── Listeners ────────────────────────────────────────────────────────

    private static List<HostListener> CollectListeners(List<string> errors)
    {
        if (FirewallService.ReadCommandExists(Lsof))
        {
            var listeners = new List<HostListener>();

            var tcp = FirewallService.ReadCommand(Lsof, "-nP", "-iTCP", "-sTCP:LISTEN");
            if (tcp.StdOut.Trim().Length > 0) listeners.AddRange(ParseLsof(tcp.StdOut));

            var udp = FirewallService.ReadCommand(Lsof, "-nP", "-iUDP");
            if (udp.StdOut.Trim().Length > 0) listeners.AddRange(ParseLsof(udp.StdOut));

            if (listeners.Count > 0) return Dedupe(listeners);
            if (!string.IsNullOrWhiteSpace(tcp.StdErr)) errors.Add("lsof: " + FirstLine(tcp.StdErr));
        }

        if (FirewallService.ReadCommandExists(Netstat))
        {
            var netstat = FirewallService.ReadCommand(Netstat, "-an");
            if (netstat.StdOut.Trim().Length > 0) return Dedupe(ParseNetstat(netstat.StdOut));
            if (!string.IsNullOrWhiteSpace(netstat.StdErr)) errors.Add("netstat: " + FirstLine(netstat.StdErr));
        }

        return new List<HostListener>();
    }

    /// <summary>
    /// Parses <c>lsof -nP -iTCP -sTCP:LISTEN</c> / <c>-iUDP</c>. The protocol
    /// column is found by value rather than by index: a command name can carry a
    /// space, which shifts every field after it.
    /// </summary>
    internal static List<HostListener> ParseLsof(string text)
    {
        var result = new List<HostListener>();

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("COMMAND", StringComparison.Ordinal)) continue;

            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3) continue;

            var protocolIndex = Array.FindIndex(parts, p => p is "TCP" or "UDP");
            if (protocolIndex < 0 || protocolIndex + 1 >= parts.Length) continue;

            var protocol = parts[protocolIndex];
            var name = parts[protocolIndex + 1];

            // "10.0.0.2:52000->93.184.216.34:443" is an established connection, not
            // a listener; UDP has no state column to filter on, so it is filtered here.
            if (name.Contains("->", StringComparison.Ordinal)) continue;

            var (address, port) = SplitHostPort(name);
            if (port.Length == 0 || port == "*") continue;

            var state = protocol == "TCP" ? "LISTEN" : "—";
            var explicitState = parts.FirstOrDefault(p => p.StartsWith('(') && p.EndsWith(')'));
            if (explicitState != null) state = explicitState.Trim('(', ')');

            result.Add(new HostListener
            {
                Protocol = protocol,
                Address = address,
                Port = port,
                Process = parts[0],
                State = state
            });
        }

        return result;
    }

    /// <summary>
    /// Parses <c>netstat -an</c>, the fallback when lsof is missing. BSD netstat
    /// separates the port with a dot rather than a colon and carries no process,
    /// which is the whole reason lsof is tried first.
    /// </summary>
    internal static List<HostListener> ParseNetstat(string text)
    {
        var result = new List<HostListener>();

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;

            var proto = parts[0].ToLowerInvariant();
            var isTcp = proto.StartsWith("tcp", StringComparison.Ordinal);
            var isUdp = proto.StartsWith("udp", StringComparison.Ordinal);
            if (!isTcp && !isUdp) continue;

            // Only sockets nothing is connected to: LISTEN for TCP, and for UDP the
            // rows whose foreign address is still the wildcard.
            if (isTcp && !parts.Contains("LISTEN")) continue;

            var local = parts[3];
            var (address, port) = SplitDotHostPort(local);
            if (port.Length == 0 || port == "*") continue;

            result.Add(new HostListener
            {
                Protocol = isTcp ? "TCP" : "UDP",
                Address = address,
                Port = port,
                Process = "—",
                State = isTcp ? "LISTEN" : "—"
            });
        }

        return result;
    }

    private static (string Address, string Port) SplitHostPort(string value)
    {
        var text = (value ?? "").Trim();
        var colon = text.LastIndexOf(':');
        if (colon < 0) return (NormalizeWildcard(text), "");
        return (NormalizeWildcard(text[..colon].Trim('[', ']')), text[(colon + 1)..]);
    }

    private static (string Address, string Port) SplitDotHostPort(string value)
    {
        var text = (value ?? "").Trim();
        var dot = text.LastIndexOf('.');
        if (dot < 0) return (NormalizeWildcard(text), "");
        return (NormalizeWildcard(text[..dot].Trim('[', ']')), text[(dot + 1)..]);
    }

    private static string NormalizeWildcard(string address) => address switch
    {
        "*" or "0.0.0.0" => "0.0.0.0",
        "[::]" or "::" or "*.*" => "::",
        _ => address
    };

    private static List<HostListener> Dedupe(IEnumerable<HostListener> listeners)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<HostListener>();
        foreach (var listener in listeners)
        {
            var key = $"{listener.Protocol}|{listener.Address}|{listener.Port}|{listener.Process}";
            if (seen.Add(key)) result.Add(listener);
        }
        return result;
    }

    /// <summary>
    /// Marks each listener with what the inbound rules do to it. A socket bound
    /// to loopback is unreachable regardless; one that no Pass rule matches is
    /// listening into a closed door, which is worth seeing next to the rule list.
    ///
    /// PF's own default is to pass what no rule matches, so an enabled firewall
    /// with no catch-all block still leaves a port reachable — that is why the
    /// verdict is drawn from the rules rather than from "the firewall is on".
    /// </summary>
    internal static void AnnotateCoverage(
        IReadOnlyList<HostListener> listeners, IReadOnlyList<FirewallRuleInfo> inbound, bool firewallEnabled)
    {
        var accepts = inbound
            .Where(r => !r.IsBlock && !r.Verdict.Equals("Log", StringComparison.OrdinalIgnoreCase))
            .Select(r => (
                WideOpen: MatchesEveryAddress(r.AddressListText),
                Protocol: r.ProtocolText.ToUpperInvariant(),
                Ports: new HashSet<string>(Regex.Matches(r.LocalPorts, @"\d+").Select(m => m.Value))))
            .ToList();

        foreach (var socket in listeners)
        {
            if (socket.Address is "127.0.0.1" or "::1")
            {
                socket.Covered = "Local only";
                continue;
            }
            if (!firewallEnabled || accepts.Count == 0)
            {
                socket.Covered = firewallEnabled ? "Not allowed" : "No firewall";
                continue;
            }

            var matched = false;
            var restricted = false;
            foreach (var (wideOpen, protocol, ports) in accepts)
            {
                var protocolOk = protocol is "ANY" or "IP" || protocol == socket.Protocol;
                var portOk = ports.Count == 0 || ports.Contains(socket.Port);
                if (!protocolOk || !portOk) continue;

                matched = true;
                if (!wideOpen) restricted = true;
            }

            socket.Covered = matched ? (restricted ? "Restricted" : "Open") : "Not allowed";
        }
    }

    // ── Folding helpers ──────────────────────────────────────────────────

    /// <summary>
    /// The boilerplate every macOS ruleset opens with. These are real rules, but
    /// listing them puts a screen of plumbing above the two rules somebody
    /// actually chose.
    /// </summary>
    internal static bool IsPlumbing(FirewallRuleInfo rule)
    {
        // Loopback passes: pf.conf and several Apple anchors open with one, and a
        // rule about lo0 answers no question anybody asked of this view.
        var iface = rule.Chain.ToLowerInvariant();
        if (iface is "lo0" or "lo") return true;

        // A bare pass with no port, no protocol, no address and no label is the
        // "pass all" every permissive ruleset starts with — not a decision anybody
        // made. A label means somebody named it, so it stays.
        var bare = string.IsNullOrWhiteSpace(rule.LocalPorts)
                   && rule.ProtocolText.Equals(FirewallRuleSpecs.ProtocolAny, StringComparison.OrdinalIgnoreCase)
                   && MatchesEveryAddress(rule.AddressListText);
        if (bare && !rule.IsBlock && string.IsNullOrWhiteSpace(rule.Comment)) return true;

        return false;
    }

    /// <summary>True when a rule matches every address and every port in its direction.</summary>
    private static bool IsCatchAllRule(FirewallRuleInfo rule)
        => string.IsNullOrWhiteSpace(rule.LocalPorts)
           && MatchesEveryAddress(rule.AddressListText)
           && rule.ProtocolText.Equals(FirewallRuleSpecs.ProtocolAny, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when an address field admits every address. Token-wise, not by
    /// substring: "10.0.0.0/8" contains the characters "0.0.0.0" while admitting
    /// only a LAN, and reading that as wide open marks a restricted port Open.
    /// </summary>
    internal static bool MatchesEveryAddress(string addresses)
    {
        var tokens = (addresses ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length == 0) return true;
        return tokens.All(t =>
            t.Equals("All IPv4", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("All IPv6", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("Anywhere", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("any", StringComparison.OrdinalIgnoreCase) ||
            t is "0.0.0.0/0" or "::/0");
    }

    internal static List<FirewallRuleInfo> Dedupe(IEnumerable<FirewallRuleInfo> rules)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<FirewallRuleInfo>();
        foreach (var rule in rules)
        {
            var key = string.Join("|",
                rule.ActionText, rule.ProtocolText, rule.LocalPorts, rule.RemoteAddresses,
                rule.Direction, rule.Label);
            if (seen.Add(key)) result.Add(rule);
        }
        return result;
    }

    /// <summary>
    /// Re-attributes rules this app wrote. They come back from the anchor looking
    /// like any other pf rule; the label Network Sentinel stamps on them is what
    /// tells the Created by column who is responsible for the row.
    /// </summary>
    private void AttributeOwnRules(List<FirewallRuleInfo> rules)
    {
        var ledger = _firewall.GetConfigRules();
        if (ledger.Count == 0) return;
        var byName = ledger.ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < rules.Count; i++)
        {
            var scanned = rules[i];
            // The comment, not the label: Label is the cleaned-and-truncated form,
            // so a long rule name would not match the ledger key it came from.
            var stamp = scanned.Comment;
            if (stamp.Length == 0 || !byName.TryGetValue(stamp, out var owned)) continue;

            rules[i] = Clone(scanned, origin: owned.OriginText, kind: owned.Kind, label: owned.LabelText);
        }
    }

    // ── Rule construction ────────────────────────────────────────────────

    private static FirewallRuleInfo BuildRule(
        string action, string protocol, string ports, string addresses, bool outbound,
        string origin, string backend, string table, string chain, string family,
        string comment, string handle)
    {
        var isBlock = action is "Drop" or "Reject";
        var label = comment.Length > 0
            ? FirewallRuleSpecs.CleanLabel(comment)
            : FirewallRuleSpecs.AutoLabel(
                isBlock ? FirewallRuleSpecs.ActionBlock : FirewallRuleSpecs.ActionAllow,
                outbound ? FirewallRuleSpecs.DirectionOutbound : FirewallRuleSpecs.DirectionInbound,
                protocol,
                Regex.Matches(ports, @"\d+(?:[-:]\d+)?").Select(m => m.Value.Replace('-', ':')).ToList());

        return new FirewallRuleInfo
        {
            Name = label,
            Label = label,
            Description = $"{action} {protocol} {(ports.Length > 0 ? ports : "all ports")} " +
                          $"{(outbound ? "to" : "from")} {addresses}" +
                          (chain.Length > 0 ? $" on {chain}" : ""),
            Enabled = true,
            IsBlock = isBlock,
            Direction = outbound ? FirewallDirection.Outbound : FirewallDirection.Inbound,
            RemoteAddresses = addresses,
            LocalPorts = ports,
            Protocol = protocol,
            Kind = FirewallRuleKind.Other,
            Backend = backend,
            Origin = origin,
            Handle = handle,
            Table = table,
            Chain = chain,
            Family = family,
            IsForeign = true,
            Verdict = action,
            Comment = comment
        };
    }

    private static FirewallRuleInfo Clone(
        FirewallRuleInfo rule, string? origin = null, FirewallRuleKind? kind = null,
        string? label = null, bool? isBlock = null, string? verdict = null) => new()
    {
        Name = rule.Name,
        Label = label ?? rule.Label,
        Description = rule.Description,
        Enabled = rule.Enabled,
        IsBlock = isBlock ?? rule.IsBlock,
        Direction = rule.Direction,
        RemoteAddresses = rule.RemoteAddresses,
        LocalPorts = rule.LocalPorts,
        Protocol = rule.Protocol,
        Kind = kind ?? rule.Kind,
        Backend = rule.Backend,
        ExpiresUtc = rule.ExpiresUtc,
        Origin = origin ?? rule.Origin,
        Handle = rule.Handle,
        Table = rule.Table,
        Chain = rule.Chain,
        Family = rule.Family,
        IsForeign = rule.IsForeign,
        Verdict = verdict ?? rule.Verdict,
        Comment = rule.Comment
    };

    // ── Small shared helpers ─────────────────────────────────────────────

    private static string JoinSources(List<string> sources, string family)
    {
        var cleaned = sources
            .Where(s => s.Length > 0 && s is not ("0.0.0.0/0" or "::/0" or "anywhere" or "any"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (cleaned.Count > 0) return string.Join(", ", cleaned);
        return family.ToLowerInvariant() switch
        {
            "inet" or "ip" or "ipv4" => "All IPv4",
            "inet6" or "ip6" or "ipv6" => "All IPv6",
            _ => FirewallRuleSpecs.AnyAddressText
        };
    }

    private static string MergePorts(string existing, string addition)
    {
        if (addition.Length == 0) return existing;
        if (existing.Length == 0) return addition;
        return existing.Contains(addition, StringComparison.Ordinal) ? existing : $"{existing}, {addition}";
    }

    private static string NormalizeProtocolWord(string value) => value.ToLowerInvariant() switch
    {
        "tcp" => "TCP",
        "udp" => "UDP",
        "icmp" or "icmpv6" or "icmp6" or "ipv6-icmp" => "ICMP",
        "all" or "any" => FirewallRuleSpecs.ProtocolAny,
        _ => value.ToUpperInvariant()
    };

    private static string Capitalize(string value) =>
        value.Length == 0 ? value : char.ToUpperInvariant(value[0]) + value[1..].ToLowerInvariant();

    private static string FirstLine(string text)
    {
        var line = (text ?? "").Trim().Split('\n').FirstOrDefault() ?? "";
        return line.Length > 200 ? line[..200] : line;
    }
}
