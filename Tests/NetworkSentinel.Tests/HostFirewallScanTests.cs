using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The host firewall scan: what pfctl, socketfilterfw and lsof actually print,
/// and what the Firewall Config view makes of it.
///
/// Every fixture below is real output, because the whole point of the scan is
/// that the page shows the firewall the machine has rather than the ledger this
/// app keeps. A parser that only handles output we invented would put us back
/// where we started, with a confident list that is not the firewall.
///
/// The PF rules were produced by <c>pfctl -nvf</c>, which is the same normaliser
/// <c>pfctl -sr</c> prints through — so the fixtures carry pfctl's own rewrites
/// rather than the shorthand a person would have typed: a braced port list comes
/// back as one rule per port, "from any to any" collapses to <c>all</c>, and
/// every port match grows an explicit <c>=</c>.
/// </summary>
public class HostFirewallScanTests
{
    // ── pfctl -sr ────────────────────────────────────────────────────────

    private const string PfRules = """
set skip on { lo0 }
block drop in all
pass in quick proto tcp from any to any port = 22 flags S/SA keep state
pass in proto tcp from any to any port = 80 flags S/SA keep state
pass in proto tcp from any to any port = 443 flags S/SA keep state
pass in inet proto tcp from 10.0.0.0/8 to any port = 3306 flags S/SA keep state label "mysql-lan"
block drop in quick inet proto tcp from 203.0.113.44 to any
pass out proto udp from any to any port = 53 keep state
block drop out quick inet proto tcp from any to 198.51.100.7 port 8000:8001 label "no-egress"
pass in on en0 inet proto icmp all keep state
pass in log proto tcp all flags S/SA no state
""";

    private static BackendRules ParsePf(string text = PfRules)
        => HostFirewallScanner.ParsePfRules(text, origin: "PF", anchor: "");

    [Fact]
    public void PfRules_SplitsRulesByDirection()
    {
        var scan = ParsePf();

        // Everything but the two `out` rules; `set skip` is not a rule at all.
        Assert.Equal(8, scan.Inbound.Count);
        Assert.Equal(2, scan.Outbound.Count);
    }

    [Fact]
    public void PfRules_ReadsPortProtocolAndSource()
    {
        var rule = ParsePf().Inbound.Single(r => r.LocalPorts == "3306");

        Assert.Equal("TCP", rule.ProtocolText);
        Assert.Equal("10.0.0.0/8", rule.RemoteAddresses);
        Assert.False(rule.IsBlock);
        Assert.Equal("mysql-lan", rule.Comment);
    }

    [Fact]
    public void PfRules_TheEqualsOperatorIsNotMistakenForThePort()
    {
        // pfctl prints "port = 22", so a parser that took the token after "port"
        // would record the port as "=" and match nothing ever again.
        Assert.Contains(ParsePf().Inbound, r => r.LocalPorts == "22");
    }

    [Fact]
    public void PfRules_DropRuleIsABlock()
    {
        var rule = ParsePf().Inbound.Single(r => r.RemoteAddresses == "203.0.113.44");

        Assert.True(rule.IsBlock);
        Assert.Equal("Drop", rule.Verdict);
    }

    [Fact]
    public void PfRules_AnOutboundRuleIsAboutItsDestination()
    {
        // "block out ... to 198.51.100.7 port 8000:8001" — the address an operator
        // means for an outbound rule is where it is going, not where it came from.
        var rule = ParsePf().Outbound.Single(r => r.IsBlock);

        Assert.Equal("198.51.100.7", rule.RemoteAddresses);
        Assert.Equal("8000-8001", rule.LocalPorts);
        Assert.Equal("no-egress", rule.Comment);
    }

    [Fact]
    public void PfRules_ASourcePortIsNotReadAsTheRulesPort()
    {
        // PF writes both ends: "from any port 1024:65535 to any port 22". The port
        // the rule is about is the one being reached.
        var rule = HostFirewallScanner.ParsePfLine(
            "pass in proto tcp from any port 1024:65535 to any port = 22", "PF", "")!;

        Assert.Equal("22", rule.LocalPorts);
    }

    [Fact]
    public void PfRules_AnInterfaceIsKept()
    {
        var rule = ParsePf().Inbound.Single(r => r.ProtocolText == "ICMP");

        Assert.Equal("en0", rule.Chain);
        Assert.Equal("inet", rule.Family);
    }

    [Fact]
    public void PfRules_ABracedAddressListKeepsEveryMember()
    {
        // pfctl expands braced *port* lists into separate rules but prints address
        // tables inline, so the brace handling has to survive the tokeniser.
        var rule = HostFirewallScanner.ParsePfLine(
            "block drop in proto tcp from { 203.0.113.5 203.0.113.6 } to any port = 22", "PF", "")!;

        Assert.Equal("203.0.113.5, 203.0.113.6", rule.RemoteAddresses);
    }

    [Fact]
    public void PfRules_AReturnRuleIsAReject()
    {
        var rule = HostFirewallScanner.ParsePfLine(
            "block return-rst in quick proto tcp from any to any port = 25", "PF", "")!;

        Assert.True(rule.IsBlock);
        Assert.Equal("Reject", rule.Verdict);
    }

    [Fact]
    public void PfRules_SetAndScrubLinesAreNotRules()
    {
        Assert.Null(HostFirewallScanner.ParsePfLine("set skip on { lo0 }", "PF", ""));
        Assert.Null(HostFirewallScanner.ParsePfLine("scrub-anchor \"com.apple/*\" all fragment reassemble", "PF", ""));
        Assert.Null(HostFirewallScanner.ParsePfLine("anchor \"com.apple/*\" all", "PF", ""));
        Assert.Null(HostFirewallScanner.ParsePfLine("# a comment", "PF", ""));
    }

    [Fact]
    public void PfRules_ACatchAllBlockBecomesTheDefaultPolicy()
    {
        var rule = ParsePf().Inbound.Single(r => r.IsBlock && r.RemoteAddresses == FirewallRuleSpecs.AnyAddressText
                                                          && r.LocalPorts.Length == 0);

        // "block drop in all" is the deny-by-default line, and it has to survive
        // the plumbing filter or the view reports a firewall with no policy.
        Assert.False(HostFirewallScanner.IsPlumbing(rule));
    }

    [Fact]
    public void PfRules_TheAnchorIsCarriedForTheDelete()
    {
        var rule = HostFirewallScanner.ParsePfLine(
            "block drop in quick proto tcp from 203.0.113.9 to any", "Network Sentinel",
            FirewallService.PfAnchorName)!;

        // pf has no rule handles, so the anchor is the only thing a delete can aim at.
        Assert.Equal(FirewallService.PfAnchorName, rule.Handle);
        Assert.Equal("Network Sentinel", rule.Origin);
        Assert.True(rule.IsForeign);
    }

    // ── pfctl -si / -sA ──────────────────────────────────────────────────

    [Fact]
    public void PfStatus_ReadsEnabled()
    {
        var (enabled, status) = HostFirewallScanner.ParsePfStatus(
            "Status: Enabled for 0 days 00:12:33           Debug: Urgent\n\nInterface Stats for en0");

        Assert.True(enabled);
        Assert.Equal("Enabled", status);
    }

    [Fact]
    public void PfStatus_ReadsDisabled()
    {
        var (enabled, status) = HostFirewallScanner.ParsePfStatus("Status: Disabled                Debug: Urgent");

        Assert.False(enabled);
        Assert.Equal("Disabled", status);
    }

    [Fact]
    public void AnchorList_DropsWildcardParents()
    {
        // Real `pfctl -sA` output: indented, and the wildcard parent is a reference
        // to the children rather than an anchor with rules of its own.
        var anchors = HostFirewallScanner.ParseAnchorList("""
  com.apple
  com.apple/200.AirDrop
  com.apple/250.ApplicationFirewall
  com.apple/*
  com.networksentinel
""").ToList();

        Assert.Equal(new[] { "com.apple", "com.apple/200.AirDrop", "com.apple/250.ApplicationFirewall", "com.networksentinel" },
                     anchors);
    }

    [Fact]
    public void PfConf_YieldsTheAnchorsToWalkWhenPfctlIsDenied()
    {
        // The unprivileged path. This is the stock /etc/pf.conf with the hook this
        // app appends — the one file that still names our own rules to a normal user.
        var names = HostFirewallScanner.ParseAnchorList(HostFirewallScanner.ExtractAnchorNames("""
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"

# Network Sentinel
anchor "com.networksentinel"
load anchor "com.networksentinel" from "/etc/pf.anchors/com.networksentinel"
""")).ToList();

        Assert.Equal(new[] { "com.apple", "com.networksentinel" }, names);
    }

    [Fact]
    public void PfAnchorFile_OurOwnRulesAreReadableWithoutRoot()
    {
        // /etc/pf.anchors/com.networksentinel, verbatim. pfctl needs root; this
        // file does not, which is what keeps the unprivileged list useful.
        var scan = HostFirewallScanner.ParsePfRules("""
# Network Sentinel PF anchor — managed rules (do not edit by hand)
# Generated 2026-08-17 21:49:53Z

# NetworkSentinel-ProbeLog
pass in log proto tcp from any to any flags S/SA no state
""", origin: "Network Sentinel", anchor: FirewallService.PfAnchorName);

        var rule = Assert.Single(scan.Inbound);
        Assert.Equal("Network Sentinel", rule.Origin);
        Assert.Equal("TCP", rule.ProtocolText);
    }

    // ── socketfilterfw ───────────────────────────────────────────────────

    private const string AlfApps = """
Total number of apps = 4
1 : /usr/libexec/remoted
             (Allow incoming connections)
2 : /usr/sbin/cupsd
             (Allow incoming connections)
3 : /Applications/Some App.app/Contents/MacOS/Some App
             (Block incoming connections)
4 : /usr/sbin/smbd
             (Allow incoming connections)
""";

    [Fact]
    public void Alf_ReadsEachAppAndItsVerdict()
    {
        var apps = HostFirewallScanner.ParseAlfApps(AlfApps);

        Assert.Equal(4, apps.Count);
        Assert.All(apps, a => Assert.Equal(FirewallDirection.Inbound, a.Direction));
        Assert.All(apps, a => Assert.Equal("Application Firewall", a.Origin));
    }

    [Fact]
    public void Alf_TheVerdictOnTheSecondLineBelongsToTheAppAbove()
    {
        var apps = HostFirewallScanner.ParseAlfApps(AlfApps);

        // The listing spans two lines per entry, so a parser that read them
        // independently would attach every verdict to the wrong binary.
        Assert.True(apps.Single(a => a.Label == "Some App").IsBlock);
        Assert.False(apps.Single(a => a.Label == "cupsd").IsBlock);
    }

    [Fact]
    public void Alf_AnAppPathWithSpacesSurvives()
    {
        var app = HostFirewallScanner.ParseAlfApps(AlfApps).Single(a => a.IsBlock);

        Assert.Equal("/Applications/Some App.app/Contents/MacOS/Some App", app.Table);
    }

    [Fact]
    public void Alf_ReadsGlobalState()
    {
        Assert.True(HostFirewallScanner.ParseAlfEnabled("Firewall is enabled. (State = 1)"));
        Assert.False(HostFirewallScanner.ParseAlfEnabled("Firewall is disabled. (State = 0)"));
    }

    [Fact]
    public void Alf_BlockAllIsReadFromTheValueNotTheSentence()
    {
        // "Firewall has block all state set to disabled." contains the word
        // "enabled" nowhere, but the sentence names the setting before its value —
        // so a substring search for "block all" plus "enabled" would misread it.
        Assert.False(HostFirewallScanner.ParseAlfBlockAll("Firewall has block all state set to disabled."));
        Assert.True(HostFirewallScanner.ParseAlfBlockAll("Firewall has block all state set to enabled."));
    }

    // ── lsof / netstat ───────────────────────────────────────────────────

    private const string LsofOutput = """
COMMAND   PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
rapportd  627 david   14u  IPv4  0x8d67a17190bd79a      0t0  TCP *:64344 (LISTEN)
rapportd  627 david   15u  IPv6 0x1c735d43a7318a65      0t0  TCP *:64344 (LISTEN)
Python   7755 david    3u  IPv4 0x52ca699d4a3c9c28      0t0  TCP 127.0.0.1:50059 (LISTEN)
sshd      412  root    4u  IPv4 0x11119cb7821f4b32      0t0  TCP *:22 (LISTEN)
mysqld    998 _mysql    5u  IPv4 0x2229cb7821f4b111     0t0  TCP 127.0.0.1:3306 (LISTEN)
""";

    [Fact]
    public void Lsof_ReadsProcessAddressAndPort()
    {
        var listeners = HostFirewallScanner.ParseLsof(LsofOutput);

        var ssh = listeners.Single(l => l.Port == "22");
        Assert.Equal("sshd", ssh.Process);
        Assert.Equal("0.0.0.0", ssh.Address);
        Assert.Equal("TCP", ssh.Protocol);
        Assert.Equal("LISTEN", ssh.State);
    }

    [Fact]
    public void Lsof_DropsTheHeaderRow()
        => Assert.DoesNotContain(HostFirewallScanner.ParseLsof(LsofOutput), l => l.Process == "COMMAND");

    [Fact]
    public void Lsof_AnEstablishedConnectionIsNotAListener()
    {
        // -iUDP has no state filter, so the connected rows arrive mixed in.
        var listeners = HostFirewallScanner.ParseLsof(
            "firefox 100 david 50u IPv4 0x1 0t0 TCP 10.0.0.2:52000->93.184.216.34:443 (ESTABLISHED)");

        Assert.Empty(listeners);
    }

    [Fact]
    public void Netstat_ReadsTheDotSeparatedPortForm()
    {
        // BSD netstat writes "*.22", not "*:22" — the fallback parser exists
        // because that one character changes everything.
        var listeners = HostFirewallScanner.ParseNetstat("""
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.3306         *.*                    LISTEN
tcp4       0      0  10.0.0.2.52000         93.184.216.34.443      ESTABLISHED
""");

        Assert.Equal(2, listeners.Count);
        Assert.Equal("0.0.0.0", listeners[0].Address);
        Assert.Equal("22", listeners[0].Port);
        Assert.Equal("127.0.0.1", listeners[1].Address);
    }

    // ── Coverage ─────────────────────────────────────────────────────────

    [Fact]
    public void Coverage_MarksAnAdmittedPortOpen()
    {
        var listeners = HostFirewallScanner.ParseLsof(LsofOutput);
        HostFirewallScanner.AnnotateCoverage(listeners, ParsePf().Inbound, firewallEnabled: true);

        Assert.Equal("Open", listeners.Single(l => l.Port == "22").Covered);
    }

    [Fact]
    public void Coverage_MarksALoopbackSocketLocalOnly()
    {
        var listeners = HostFirewallScanner.ParseLsof(LsofOutput);
        HostFirewallScanner.AnnotateCoverage(listeners, ParsePf().Inbound, firewallEnabled: true);

        // MySQL binds 127.0.0.1, so the 3306 pass rule above is beside the point.
        Assert.Equal("Local only", listeners.Single(l => l.Port == "3306").Covered);
    }

    [Fact]
    public void Coverage_MarksAnUnadmittedListenerNotAllowed()
    {
        var listeners = HostFirewallScanner.ParseLsof(LsofOutput);
        HostFirewallScanner.AnnotateCoverage(listeners, ParsePf().Inbound, firewallEnabled: true);

        // Nothing in the rule set admits 64344 — rapportd is listening into a
        // closed door, which is exactly what this column exists to say.
        Assert.Equal("Not allowed", listeners.First(l => l.Port == "64344").Covered);
    }

    [Fact]
    public void Coverage_OurOwnProbeLogRuleDoesNotMarkEveryPortOpen()
    {
        // The probe-log rule this app writes is `pass in log proto tcp all ... no
        // state`: it passes every TCP SYN so it can see scans of closed ports. Read
        // as an admission it matches every listener on the machine, so switching
        // probe logging on would turn the whole column Open — a firewall report
        // that says "everything is reachable" because we asked to watch the door.
        var probeLog = HostFirewallScanner.ParsePfLine(
            "pass in log proto tcp all flags S/SA no state", "Network Sentinel", FirewallService.PfAnchorName)!;

        Assert.Equal("Log", probeLog.Verdict);
        Assert.False(probeLog.IsBlock);
        // And it is not listed as an Allow either, which would read as a rule
        // somebody wrote to open every TCP port on the machine.
        Assert.Equal("Log", probeLog.ActionText);

        var listeners = HostFirewallScanner.ParseLsof(LsofOutput);
        HostFirewallScanner.AnnotateCoverage(listeners, new[] { probeLog }, firewallEnabled: true);

        Assert.Equal("Not allowed", listeners.Single(l => l.Port == "22").Covered);
    }

    [Fact]
    public void Coverage_MarksASourceScopedRuleRestricted()
    {
        var listeners = HostFirewallScanner.ParseLsof(
            "mysqld 998 _mysql 5u IPv4 0x1 0t0 TCP *:3306 (LISTEN)");
        HostFirewallScanner.AnnotateCoverage(listeners, ParsePf().Inbound, firewallEnabled: true);

        // 3306 is passed, but only from 10.0.0.0/8.
        Assert.Equal("Restricted", listeners[0].Covered);
    }

    [Fact]
    public void Coverage_ALanScopedRuleIsNotReadAsWideOpen()
    {
        // "10.0.0.0/8" contains the characters "0.0.0.0". Comparing by substring
        // marks a LAN-only port Open, which is the one mistake this column must
        // never make.
        Assert.False(HostFirewallScanner.MatchesEveryAddress("10.0.0.0/8"));
        Assert.True(HostFirewallScanner.MatchesEveryAddress("0.0.0.0/0"));
        Assert.True(HostFirewallScanner.MatchesEveryAddress("All IPv4"));
    }

    [Fact]
    public void Coverage_SaysSoWhenThereIsNoFirewall()
    {
        var listeners = HostFirewallScanner.ParseLsof(LsofOutput);
        HostFirewallScanner.AnnotateCoverage(listeners, ParsePf().Inbound, firewallEnabled: false);

        // macOS ships with PF loaded but disabled, so this is the common case and
        // "Not allowed" would be a lie: nothing is filtering at all.
        Assert.Equal("No firewall", listeners.Single(l => l.Port == "22").Covered);
    }

    // ── Folding ──────────────────────────────────────────────────────────

    [Fact]
    public void Dedupe_DropsTheSameRuleSeenThroughTwoAnchors()
    {
        var once = HostFirewallScanner.ParsePfLine("pass in proto tcp from any to any port = 22", "PF", "")!;
        var twin = HostFirewallScanner.ParsePfLine("pass in proto tcp from any to any port = 22", "PF", "com.apple")!;

        Assert.Single(HostFirewallScanner.Dedupe(new[] { once, twin }));
    }

    [Fact]
    public void Plumbing_ALoopbackRuleIsNoise()
    {
        var rule = HostFirewallScanner.ParsePfLine("pass in quick on lo0 all", "PF", "")!;

        Assert.True(HostFirewallScanner.IsPlumbing(rule));
    }

    [Fact]
    public void Plumbing_ABarePassIsNoise()
    {
        var rule = HostFirewallScanner.ParsePfLine("pass in all", "PF", "")!;

        Assert.True(HostFirewallScanner.IsPlumbing(rule));
    }

    [Fact]
    public void Plumbing_ALabelledRuleIsSomebodysDecision()
    {
        // A label means a person named it, so it stays however bare it looks.
        var rule = HostFirewallScanner.ParsePfLine("pass in all label \"trust-everything\"", "PF", "")!;

        Assert.False(HostFirewallScanner.IsPlumbing(rule));
    }

    [Fact]
    public void Plumbing_ARealRuleIsNotNoise()
    {
        var rule = HostFirewallScanner.ParsePfLine("pass in proto tcp from any to any port = 22", "PF", "")!;

        Assert.False(HostFirewallScanner.IsPlumbing(rule));
    }

    // ── Round trip: what we write is what we read back ───────────────────

    [Fact]
    public void OurOwnAnchorRoundTripsItsLedgerNamesThroughPfctl()
    {
        // The fixture is real `pfctl -nvf` output for a ruleset BuildPfRuleset
        // generated, so it carries pfctl's normalisation: the braced address and
        // port lists have been expanded into one rule per combination, and each
        // one kept the label.
        //
        // This is the invariant Delete and Edit stand on. Comments do not survive
        // into the kernel and labels do, so if the label were dropped a rescanned
        // rule could not be matched to the ledger entry that owns it, and the
        // buttons on those rows would act on nothing.
        var scan = HostFirewallScanner.ParsePfRules("""
block drop in quick inet from 203.0.113.9 to any label "NetworkSentinel-IP-203.0.113.9-In"
block drop out quick inet from any to 203.0.113.9 label "NetworkSentinel-IP-203.0.113.9-Out"
block drop in quick proto tcp from any to any port = 8080 label "NetworkSentinel-Port-8080-In"
block drop in quick inet proto tcp from 10.0.0.0/8 to any port = 80 label "NetworkSentinel-Rule-block-inbound-web"
block drop in quick inet proto tcp from 192.168.1.5 to any port = 443 label "NetworkSentinel-Rule-block-inbound-web"
pass out quick proto udp from any to any port = 53 keep state label "NetworkSentinel-Rule-allow-outbound-dns"
pass in log proto tcp all flags S/SA no state label "NetworkSentinel-ProbeLog"
""", origin: "Network Sentinel", anchor: FirewallService.PfAnchorName);

        var comments = scan.Inbound.Concat(scan.Outbound).Select(r => r.Comment).Distinct().ToList();

        Assert.Contains("NetworkSentinel-IP-203.0.113.9-In", comments);
        Assert.Contains("NetworkSentinel-IP-203.0.113.9-Out", comments);
        Assert.Contains("NetworkSentinel-Port-8080-In", comments);
        Assert.Contains("NetworkSentinel-Rule-block-inbound-web", comments);
        Assert.Contains("NetworkSentinel-Rule-allow-outbound-dns", comments);
        Assert.Contains("NetworkSentinel-ProbeLog", comments);
    }

    [Fact]
    public void AnOutboundIpBlockIsReadBackAsOutbound()
    {
        // "block drop out ... from any to 203.0.113.9" — writing it inbound and
        // reading it back outbound (or the reverse) would put every paired block
        // in the wrong list.
        var rule = HostFirewallScanner.ParsePfLine(
            "block drop out quick inet from any to 203.0.113.9 label \"NetworkSentinel-IP-203.0.113.9-Out\"",
            "Network Sentinel", FirewallService.PfAnchorName)!;

        Assert.Equal(FirewallDirection.Outbound, rule.Direction);
        Assert.Equal("203.0.113.9", rule.RemoteAddresses);
        Assert.True(rule.IsBlock);
    }
}
