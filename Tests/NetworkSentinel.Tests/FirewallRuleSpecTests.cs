using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The Firewall Config rule pipeline: what the operator types, what PF is asked
/// to load, and what the console refuses to write in the first place.
/// </summary>
public class FirewallRuleSpecTests
{
    private static FirewallRuleSpec Spec(
        string action = FirewallRuleSpecs.ActionBlock,
        string direction = FirewallRuleSpecs.DirectionInbound,
        string protocol = "TCP",
        string ports = "22",
        string addresses = "",
        string label = "") => new()
    {
        Action = action,
        Direction = direction,
        Protocol = protocol,
        PortRange = ports,
        Addresses = addresses,
        Label = label
    };

    private static FirewallRuleInfo Rule(FirewallRuleSpec spec)
        => FirewallRuleSpecs.ToRule(spec, "NetworkSentinel-Rule-test");

    // ── Ports ────────────────────────────────────────────────────────────

    [Fact]
    public void PortListAndRangeBecomePfTokens()
    {
        Assert.True(FirewallRuleSpecs.TryParsePorts("80, 443", out var list, out _));
        Assert.Equal(new[] { "80", "443" }, list);

        // PF spells a range with a colon; the form takes the friendlier dash.
        Assert.True(FirewallRuleSpecs.TryParsePorts("8000-8001", out var range, out _));
        Assert.Equal(new[] { "8000:8001" }, range);
    }

    [Fact]
    public void EmptyPortFieldMeansEveryPort()
    {
        Assert.True(FirewallRuleSpecs.TryParsePorts("", out var ports, out _));
        Assert.Empty(ports);
    }

    [Theory]
    [InlineData("http")]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("443-80")]
    public void BadPortsAreRejectedWithAReason(string text)
    {
        Assert.False(FirewallRuleSpecs.TryParsePorts(text, out _, out var error));
        Assert.NotEqual("", error);
    }

    // ── Addresses ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("any")]
    [InlineData("All IPv4, All IPv6")]
    [InlineData("0.0.0.0/0")]
    public void AnyAddressParsesToAnEmptyList(string text)
    {
        Assert.True(FirewallRuleSpecs.TryParseAddresses(text, out var addresses, out _));
        Assert.Empty(addresses);
    }

    [Fact]
    public void AddressesAndNetworksSurviveNormalization()
    {
        Assert.True(FirewallRuleSpecs.TryParseAddresses("10.0.0.0/8, 203.0.113.5", out var addresses, out _));
        Assert.Equal(new[] { "10.0.0.0/8", "203.0.113.5" }, addresses);
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.1/abc")]
    public void BadAddressesAreRejected(string text)
    {
        Assert.False(FirewallRuleSpecs.TryParseAddresses(text, out _, out var error));
        Assert.NotEqual("", error);
    }

    // ── Labels ───────────────────────────────────────────────────────────

    [Fact]
    public void BlankLabelIsMintedFromTheService()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(ports: "22"));
        Assert.Equal("block-inbound-ssh", spec.Label);
    }

    [Fact]
    public void MintedLabelFallsBackToThePortNumber()
    {
        var spec = FirewallRuleSpecs.Normalize(
            Spec(action: FirewallRuleSpecs.ActionAllow,
                 direction: FirewallRuleSpecs.DirectionOutbound, ports: "9999"));
        Assert.Equal("allow-outbound-9999", spec.Label);
    }

    [Fact]
    public void OperatorLabelIsKeptButStrippedOfWhitespaceAndPunctuation()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(label: "office VPN (only)"));
        Assert.Equal("office-VPN-only", spec.Label);
    }

    // ── Validation ───────────────────────────────────────────────────────

    [Fact]
    public void AValidRulePassesValidation()
        => Assert.Equal("", FirewallRuleSpecs.Validate(FirewallRuleSpecs.Normalize(Spec())));

    [Fact]
    public void AllowEverythingIsRefused()
    {
        // Protocol Any, no port, no address: a pass rule that matches all traffic.
        var spec = FirewallRuleSpecs.Normalize(
            Spec(action: FirewallRuleSpecs.ActionAllow, protocol: "Any", ports: "", addresses: ""));
        Assert.Contains("allow all traffic", FirewallRuleSpecs.Validate(spec));
    }

    [Fact]
    public void BlockEverythingIsAllowedButFlaggedAsCatchAll()
    {
        // The same shape as a block is legitimate (and drastic) — it validates, and
        // the view model confirms it with the operator instead.
        var spec = FirewallRuleSpecs.Normalize(Spec(protocol: "Any", ports: "", addresses: ""));
        Assert.Equal("", FirewallRuleSpecs.Validate(spec));
        Assert.True(FirewallRuleSpecs.IsCatchAll(spec));
    }

    [Fact]
    public void IcmpWithPortsIsRefused()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(protocol: "ICMP", ports: "22"));
        Assert.Contains("ICMP has no ports", FirewallRuleSpecs.Validate(spec));
    }

    [Fact]
    public void PortRangeCoverageIsInclusive()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(ports: "20-25"));
        Assert.True(FirewallRuleSpecs.CoversPort(spec, 22));
        Assert.True(FirewallRuleSpecs.CoversPort(spec, 20));
        Assert.True(FirewallRuleSpecs.CoversPort(spec, 25));
        Assert.False(FirewallRuleSpecs.CoversPort(spec, 26));

        // No port range at all means every port, SSH included.
        Assert.True(FirewallRuleSpecs.CoversPort(FirewallRuleSpecs.Normalize(Spec(ports: "")), 22));
    }

    // ── PF rendering ─────────────────────────────────────────────────────

    [Fact]
    public void InboundBlockFiltersOnTheSourceAndTheLocalPort()
    {
        var line = FirewallRuleSpecs.BuildPfLine(Rule(Spec(addresses: "203.0.113.5")));
        Assert.Equal("block drop in quick proto tcp from 203.0.113.5 to any port 22", line);
    }

    [Fact]
    public void OutboundRuleFiltersOnTheDestinationAndTheRemotePort()
    {
        // "Outbound to port 443" means the service being reached, which is what UFW's
        // `allow out … port 443` does — not the local source port.
        var line = FirewallRuleSpecs.BuildPfLine(Rule(Spec(
            action: FirewallRuleSpecs.ActionAllow,
            direction: FirewallRuleSpecs.DirectionOutbound,
            ports: "443",
            addresses: "198.51.100.7")));
        Assert.Equal("pass out quick proto tcp from any to 198.51.100.7 port 443", line);
    }

    [Fact]
    public void ListsAreBracedAndSingleValuesAreNot()
    {
        var line = FirewallRuleSpecs.BuildPfLine(Rule(Spec(ports: "80, 443", addresses: "10.0.0.0/8, 192.168.1.5")));
        Assert.Equal(
            "block drop in quick proto tcp from { 10.0.0.0/8, 192.168.1.5 } to any port { 80, 443 }",
            line);
    }

    [Fact]
    public void AnyProtocolAndAnyAddressDropTheirClauses()
    {
        var line = FirewallRuleSpecs.BuildPfLine(Rule(Spec(protocol: "Any", ports: "", addresses: "")));
        Assert.Equal("block drop in quick from any to any", line);
    }

    [Fact]
    public void IcmpRuleCarriesNoPortClause()
    {
        var line = FirewallRuleSpecs.BuildPfLine(Rule(Spec(protocol: "ICMP", ports: "")));
        Assert.Equal("block drop in quick proto icmp from any to any", line);
    }

    [Fact]
    public void RangesUsePfColonSyntaxInTheRule()
    {
        var line = FirewallRuleSpecs.BuildPfLine(Rule(Spec(ports: "8000-8001")));
        Assert.Contains("port 8000:8001", line);
    }

    // ── Round trip ───────────────────────────────────────────────────────

    [Fact]
    public void EditingARuleRecoversTheFormItWasWrittenFrom()
    {
        var original = FirewallRuleSpecs.Normalize(Spec(
            action: FirewallRuleSpecs.ActionAllow,
            direction: FirewallRuleSpecs.DirectionOutbound,
            protocol: "UDP",
            ports: "51820",
            addresses: "198.51.100.7",
            label: "wireguard-peer"));

        var restored = FirewallRuleSpecs.FromRule(Rule(original));

        Assert.Equal(original.Label, restored.Label);
        Assert.Equal(original.Action, restored.Action);
        Assert.Equal(original.Direction, restored.Direction);
        Assert.Equal(original.Protocol, restored.Protocol);
        Assert.Equal(original.PortRange, restored.PortRange);
        Assert.Equal(original.Addresses, restored.Addresses);
    }

    // ── Ruleset ordering ─────────────────────────────────────────────────

    [Fact]
    public void AppMintedBlocksAreLoadedBeforeConfigRules()
    {
        // Every rule is `quick`, so order is precedence: a config Allow rule must
        // not be able to reopen an address auto-block just shut.
        var ledger = new List<FirewallRuleInfo>
        {
            FirewallRuleSpecs.ToRule(
                Spec(action: FirewallRuleSpecs.ActionAllow, ports: "443", label: "allow-https"),
                "NetworkSentinel-Rule-allow-https"),
            new()
            {
                Name = "NetworkSentinel-IP-203.0.113.9-In",
                Enabled = true,
                IsBlock = true,
                Direction = FirewallDirection.Inbound,
                RemoteAddresses = "203.0.113.9",
                Kind = FirewallRuleKind.IpBlock
            }
        };

        var ruleset = FirewallService.BuildPfRuleset(ledger);

        var blockAt = ruleset.IndexOf("block drop in quick from 203.0.113.9", StringComparison.Ordinal);
        var passAt = ruleset.IndexOf("pass in quick proto tcp", StringComparison.Ordinal);
        Assert.True(blockAt >= 0, "the auto-block rule should be in the ruleset");
        Assert.True(passAt >= 0, "the config rule should be in the ruleset");
        Assert.True(blockAt < passAt, "auto-block must be evaluated before config rules");
    }

    [Fact]
    public void DisabledAndExpiredRulesAreNotLoaded()
    {
        var ledger = new List<FirewallRuleInfo>
        {
            FirewallRuleSpecs.ToRule(Spec(label: "off"), "NetworkSentinel-Rule-off", enabled: false),
            new()
            {
                Name = "NetworkSentinel-IP-203.0.113.9-In",
                Enabled = true,
                IsBlock = true,
                Direction = FirewallDirection.Inbound,
                RemoteAddresses = "203.0.113.9",
                Kind = FirewallRuleKind.IpBlock,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(-1)
            }
        };

        var ruleset = FirewallService.BuildPfRuleset(ledger);

        Assert.DoesNotContain("203.0.113.9", ruleset);
        Assert.DoesNotContain("port 22", ruleset);
    }
}
