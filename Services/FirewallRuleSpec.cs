using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>
/// One firewall rule as the operator writes it: an action, a direction, a
/// protocol, a port range and a set of addresses — the same six fields the
/// Linode Cloud Manager firewall page asks for, and the shape
/// <see href="https://github.com/davidfweiser/FireWallConfig">FireWallConfig</see>
/// uses on Ubuntu.
///
/// The fields are strings because they come straight from text boxes and combo
/// boxes; <see cref="FirewallRuleSpecs.Normalize"/> canonicalises them and
/// <see cref="FirewallRuleSpecs.Validate"/> refuses the ones PF would reject or
/// that would quietly do something enormous.
/// </summary>
public sealed class FirewallRuleSpec
{
    public string Label { get; set; } = "";

    /// <summary>Allow or Block. FireWallConfig's Accept/Drop, in PF's vocabulary.</summary>
    public string Action { get; set; } = FirewallRuleSpecs.ActionBlock;

    public string Direction { get; set; } = FirewallRuleSpecs.DirectionInbound;

    /// <summary>TCP, UDP, ICMP or Any.</summary>
    public string Protocol { get; set; } = "TCP";

    /// <summary>"22", "8000-8001", "80, 443", or empty for every port.</summary>
    public string PortRange { get; set; } = "";

    /// <summary>
    /// Comma-separated addresses or CIDR blocks. Empty (or "any") means every
    /// address — the source for an inbound rule, the destination for an outbound
    /// one.
    /// </summary>
    public string Addresses { get; set; } = "";

    public FirewallRuleSpec Clone() => new()
    {
        Label = Label,
        Action = Action,
        Direction = Direction,
        Protocol = Protocol,
        PortRange = PortRange,
        Addresses = Addresses
    };
}

/// <summary>
/// Parsing, validation and PF rendering for <see cref="FirewallRuleSpec"/>.
/// Kept apart from <see cref="FirewallService"/> because it is pure text work
/// with no privilege and no I/O, which is what makes it testable.
/// </summary>
public static class FirewallRuleSpecs
{
    public const string ActionAllow = "Allow";
    public const string ActionBlock = "Block";
    public const string DirectionInbound = "Inbound";
    public const string DirectionOutbound = "Outbound";
    public const string ProtocolAny = "Any";

    /// <summary>What the grid and the editor show for "no address filter".</summary>
    public const string AnyAddressText = "All IPv4, All IPv6";

    public static readonly string[] Actions = { ActionAllow, ActionBlock };
    public static readonly string[] Directions = { DirectionInbound, DirectionOutbound };
    public static readonly string[] Protocols = { "TCP", "UDP", "ICMP", ProtocolAny };

    private static readonly Regex PortToken = new(@"^(\d{1,5})(?:\s*[-:]\s*(\d{1,5}))?$", RegexOptions.Compiled);

    private static readonly HashSet<string> AnyAddressWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "any", "anywhere", "all", "all ipv4", "all ipv6", "all ipv4, all ipv6",
        "0.0.0.0/0", "::/0"
    };

    /// <summary>
    /// Splits a port field into PF tokens: "22" stays, "8000-8001" becomes
    /// "8000:8001" (PF's range syntax). An empty field means every port.
    /// </summary>
    public static bool TryParsePorts(string? text, out List<string> ports, out string error)
    {
        ports = new List<string>();
        error = "";

        var raw = (text ?? "").Trim();
        if (raw.Length == 0) return true;

        foreach (var token in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var match = PortToken.Match(token);
            if (!match.Success)
            {
                error = $"Invalid port: {token}";
                ports.Clear();
                return false;
            }

            var start = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
            int? end = match.Groups[2].Success
                ? int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture)
                : null;

            if (start is < 1 or > 65535 || end is < 1 or > 65535)
            {
                error = $"Port out of range: {token}";
                ports.Clear();
                return false;
            }
            if (end.HasValue && start > end.Value)
            {
                error = $"Port range starts after it ends: {token}";
                ports.Clear();
                return false;
            }

            ports.Add(end.HasValue ? $"{start}:{end.Value}" : start.ToString(CultureInfo.InvariantCulture));
        }

        return true;
    }

    /// <summary>
    /// Splits an address field into IPs and CIDR blocks. An empty list means
    /// "any" — the caller renders that as PF's <c>any</c> keyword.
    /// </summary>
    public static bool TryParseAddresses(string? text, out List<string> addresses, out string error)
    {
        addresses = new List<string>();
        error = "";

        var raw = (text ?? "").Trim();
        if (AnyAddressWords.Contains(raw)) return true;

        foreach (var token in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (AnyAddressWords.Contains(token))
            {
                // One "any" in the list makes the whole list "any".
                addresses.Clear();
                return true;
            }

            if (token.Contains('/'))
            {
                if (!TryNormalizeCidr(token, out var cidr))
                {
                    error = $"Invalid network: {token}";
                    addresses.Clear();
                    return false;
                }
                addresses.Add(cidr);
                continue;
            }

            if (!FirewallService.TryNormalizeIp(token, out var ip, out _))
            {
                error = $"Invalid address: {token}";
                addresses.Clear();
                return false;
            }
            addresses.Add(ip);
        }

        return true;
    }

    private static bool TryNormalizeCidr(string token, out string cidr)
    {
        cidr = "";
        var parts = token.Split('/', 2);
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0].Trim(), out var address)) return false;
        if (!int.TryParse(parts[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var prefix))
            return false;

        var max = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        if (prefix < 0 || prefix > max) return false;

        cidr = $"{address}/{prefix}";
        return true;
    }

    /// <summary>
    /// Canonical form: trimmed, cased the way the combo boxes offer, ports and
    /// addresses re-rendered from what parsed, and a minted label when the
    /// operator left it blank.
    /// </summary>
    public static FirewallRuleSpec Normalize(FirewallRuleSpec spec)
    {
        var action = Match(spec.Action, Actions, ActionBlock);
        var direction = Match(spec.Direction, Directions, DirectionInbound);
        var protocol = Match(spec.Protocol, Protocols, "TCP");

        TryParsePorts(spec.PortRange, out var ports, out _);
        TryParseAddresses(spec.Addresses, out var addresses, out _);

        var portText = string.Join(", ", ports.Select(p => p.Replace(':', '-')));
        var addressText = addresses.Count == 0 ? AnyAddressText : string.Join(", ", addresses);

        return new FirewallRuleSpec
        {
            Label = CleanLabel(spec.Label) is { Length: > 0 } clean
                ? clean
                : AutoLabel(action, direction, protocol, ports),
            Action = action,
            Direction = direction,
            Protocol = protocol,
            PortRange = portText,
            Addresses = addressText
        };
    }

    /// <summary>Empty string when the spec is usable; the reason when it is not.</summary>
    public static string Validate(FirewallRuleSpec spec)
    {
        if (!Actions.Contains(spec.Action, StringComparer.OrdinalIgnoreCase))
            return $"Unknown action: {Blank(spec.Action)}";
        if (!Directions.Contains(spec.Direction, StringComparer.OrdinalIgnoreCase))
            return $"Unknown direction: {Blank(spec.Direction)}";
        if (!Protocols.Contains(spec.Protocol, StringComparer.OrdinalIgnoreCase))
            return $"Unknown protocol: {Blank(spec.Protocol)}";

        if (!TryParsePorts(spec.PortRange, out var ports, out var portError))
            return portError;
        if (!TryParseAddresses(spec.Addresses, out var addresses, out var addressError))
            return addressError;

        if (ports.Count > 0 && spec.Protocol.Equals("ICMP", StringComparison.OrdinalIgnoreCase))
            return "ICMP has no ports — clear the port range or pick TCP/UDP.";

        // The one shape that is always a mistake: a pass rule with no protocol,
        // no port and no address punches a hole for everything.
        if (spec.Action.Equals(ActionAllow, StringComparison.OrdinalIgnoreCase) &&
            spec.Protocol.Equals(ProtocolAny, StringComparison.OrdinalIgnoreCase) &&
            ports.Count == 0 && addresses.Count == 0)
        {
            return "An Allow rule with protocol Any, no port and no address would allow all traffic. " +
                   "Set a port, a protocol, or an address.";
        }

        return "";
    }

    /// <summary>
    /// True when the rule matches every address and every port in its direction —
    /// a block like that cuts the machine off, so the console confirms first.
    /// </summary>
    public static bool IsCatchAll(FirewallRuleSpec spec)
    {
        TryParsePorts(spec.PortRange, out var ports, out _);
        TryParseAddresses(spec.Addresses, out var addresses, out _);
        return ports.Count == 0 && addresses.Count == 0;
    }

    /// <summary>True when the rule's port range covers <paramref name="port"/>.</summary>
    public static bool CoversPort(FirewallRuleSpec spec, int port)
    {
        if (!TryParsePorts(spec.PortRange, out var ports, out _))
            return false;
        if (ports.Count == 0)
            return true; // every port

        foreach (var token in ports)
        {
            var range = token.Split(':', 2);
            if (!int.TryParse(range[0], out var start)) continue;
            var end = range.Length == 2 && int.TryParse(range[1], out var parsed) ? parsed : start;
            if (port >= start && port <= end) return true;
        }
        return false;
    }

    /// <summary>
    /// Mints a Linode-style label — <c>block-inbound-ssh</c> — when the operator
    /// leaves the field blank, so every rule has a name to refer to.
    /// </summary>
    public static string AutoLabel(string action, string direction, string protocol, IReadOnlyList<string> ports)
    {
        var verb = action.Equals(ActionAllow, StringComparison.OrdinalIgnoreCase) ? "allow" : "block";
        var side = direction.Equals(DirectionOutbound, StringComparison.OrdinalIgnoreCase) ? "outbound" : "inbound";

        var slugs = new List<string>();
        foreach (var token in ports.Take(3))
        {
            var first = token.Split(':', 2)[0];
            if (!int.TryParse(first, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port)) continue;
            var slug = ServiceSlug(port);
            if (!slugs.Contains(slug)) slugs.Add(slug);
        }

        if (slugs.Count > 0)
            return $"{verb}-{side}-{string.Join("-", slugs)}";

        if (!protocol.Equals(ProtocolAny, StringComparison.OrdinalIgnoreCase))
            return $"{verb}-{side}-{protocol.ToLowerInvariant()}";

        return $"{verb}-{side}-all";
    }

    /// <summary>
    /// Well-known service name for a port, lower-cased for use in a label. Falls
    /// back to the port number, which is exactly what an unknown port deserves.
    /// </summary>
    private static string ServiceSlug(int port)
    {
        var hint = PortCatalog.GetHint(port, "TCP");
        if (hint is "Custom / unknown" or "UDP service")
            return port.ToString(CultureInfo.InvariantCulture);

        var slug = Regex.Replace(hint.ToLowerInvariant(), @"[^a-z0-9]+", "-").Trim('-');
        return slug.Length > 0 ? slug : port.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Strips whitespace and anything a PF comment or a rule name cannot carry.</summary>
    public static string CleanLabel(string? label)
    {
        var text = (label ?? "").Trim();
        if (text.Length == 0) return "";
        text = Regex.Replace(text, @"\s+", "-");
        text = Regex.Replace(text, @"[^A-Za-z0-9_.:\-]+", "");
        return text.Length > 48 ? text[..48] : text;
    }

    /// <summary>Ledger form of a validated spec. The caller supplies the unique name.</summary>
    public static FirewallRuleInfo ToRule(FirewallRuleSpec spec, string name, bool enabled = true)
    {
        var normalized = Normalize(spec);
        TryParseAddresses(normalized.Addresses, out var addresses, out _);

        return new FirewallRuleInfo
        {
            Name = name,
            Label = normalized.Label,
            Description = $"{normalized.Action} {normalized.Protocol} " +
                          $"{(normalized.PortRange.Length > 0 ? normalized.PortRange : "all ports")} " +
                          $"{(normalized.Direction == DirectionInbound ? "from" : "to")} {normalized.Addresses}",
            Enabled = enabled,
            IsBlock = normalized.Action.Equals(ActionBlock, StringComparison.OrdinalIgnoreCase),
            Direction = normalized.Direction.Equals(DirectionOutbound, StringComparison.OrdinalIgnoreCase)
                ? FirewallDirection.Outbound
                : FirewallDirection.Inbound,
            RemoteAddresses = string.Join(", ", addresses),
            LocalPorts = normalized.PortRange,
            Protocol = normalized.Protocol,
            Kind = FirewallRuleKind.Custom
        };
    }

    /// <summary>Editor form of a stored rule, for the Edit button.</summary>
    public static FirewallRuleSpec FromRule(FirewallRuleInfo rule) => new()
    {
        Label = rule.Label.Length > 0 ? rule.Label : rule.Name,
        Action = rule.IsBlock ? ActionBlock : ActionAllow,
        Direction = rule.Direction == FirewallDirection.Outbound ? DirectionOutbound : DirectionInbound,
        Protocol = string.IsNullOrWhiteSpace(rule.Protocol) ? ProtocolAny : rule.Protocol,
        PortRange = rule.LocalPorts,
        Addresses = rule.RemoteAddresses
    };

    /// <summary>
    /// Renders one custom rule as a PF line.
    ///
    /// Inbound rules filter on the source address and the local (destination)
    /// port; outbound rules filter on the destination address and the remote
    /// (destination) port — "outbound to port 443" means the service being
    /// reached, which is what an operator means and what UFW's
    /// <c>allow out … port 443</c> does. That differs from the legacy
    /// port-block rules, which match the local source port on the way out.
    ///
    /// Every rule is <c>quick</c>, so the list is first-match-wins like UFW and
    /// the Linode firewall.
    /// </summary>
    public static string BuildPfLine(FirewallRuleInfo rule)
    {
        var sb = new StringBuilder();
        sb.Append(rule.IsBlock ? "block drop " : "pass ");
        sb.Append(rule.Direction == FirewallDirection.Outbound ? "out " : "in ");
        sb.Append("quick ");

        var protocol = (rule.Protocol ?? ProtocolAny).Trim();
        if (!protocol.Equals(ProtocolAny, StringComparison.OrdinalIgnoreCase) && protocol.Length > 0)
            sb.Append("proto ").Append(protocol.ToLowerInvariant()).Append(' ');

        TryParseAddresses(rule.RemoteAddresses, out var addresses, out _);
        var addressText = PfList(addresses);

        if (rule.Direction == FirewallDirection.Outbound)
            sb.Append("from any to ").Append(addressText);
        else
            sb.Append("from ").Append(addressText).Append(" to any");

        if (TryParsePorts(rule.LocalPorts, out var ports, out _) && ports.Count > 0)
            sb.Append(" port ").Append(PfList(ports));

        return sb.ToString();
    }

    /// <summary>PF takes a bare token or a braced list; "any" when there is nothing to match.</summary>
    private static string PfList(IReadOnlyList<string> items) => items.Count switch
    {
        0 => "any",
        1 => items[0],
        _ => "{ " + string.Join(", ", items) + " }"
    };

    private static string Match(string? value, IReadOnlyList<string> options, string fallback)
    {
        foreach (var option in options)
        {
            if (string.Equals(value?.Trim(), option, StringComparison.OrdinalIgnoreCase))
                return option;
        }
        return fallback;
    }

    private static string Blank(string? value) => string.IsNullOrWhiteSpace(value) ? "(empty)" : value.Trim();
}
