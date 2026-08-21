using NetworkSentinel.Models;
using NetworkSentinel.Services;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The identity the web console uses to say which firewall row a Delete or an Edit
/// meant.
///
/// It used to be built from the rule's shape alone — direction, action, protocol,
/// ports, sources, label, origin. Adding the same rule twice, which the page allows
/// and which an operator retrying a failed delete does naturally, produced two rows
/// that shape could not tell apart: the lookup found two matches for either row's
/// key and refused both, so neither could be deleted or edited again.
///
/// PF holds no rule handles, so the separators here are the ledger name and the
/// anchor a rule lives in.
/// </summary>
public class ScannedRuleKeyTests
{
    private static FirewallRuleInfo Rule(
        string name, string label, string anchor = "com.networksentinel", string ports = "4822") => new()
    {
        Name = name,
        Label = label,
        Enabled = true,
        IsBlock = false,
        Direction = FirewallDirection.Inbound,
        RemoteAddresses = "",
        LocalPorts = ports,
        Protocol = "TCP",
        Kind = FirewallRuleKind.Custom,
        Backend = "pf",
        Origin = "Firewall config",
        Handle = anchor,
        Table = anchor,
        Chain = "",
        Family = "inet",
        Verdict = "Pass"
    };

    /// <summary>
    /// Two adds of the same rule: same label, same everything an operator can see.
    /// The ledger names differ ("…-2"), and so must the keys.
    /// </summary>
    [Fact]
    public void TwoRulesOfTheSameShape_GetDifferentKeys()
    {
        var first = Rule("NetworkSentinel-Rule-allow-inbound-4822", "allow-inbound-4822");
        var second = Rule("NetworkSentinel-Rule-allow-inbound-4822-2", "allow-inbound-4822");

        Assert.NotEqual(WebApp.ScannedRuleKey(first), WebApp.ScannedRuleKey(second));
    }

    /// <summary>
    /// Even were the names to agree, the anchor holding the rule still separates
    /// them — this app's own anchor from one the host or a VPN client installed.
    /// </summary>
    [Fact]
    public void SameNameDifferentAnchor_GetsDifferentKeys()
    {
        var ours = Rule("NetworkSentinel-Rule-SSH", "SSH");
        var theirs = Rule("NetworkSentinel-Rule-SSH", "SSH", anchor: "com.apple/250.ApplicationFirewall");

        Assert.NotEqual(WebApp.ScannedRuleKey(ours), WebApp.ScannedRuleKey(theirs));
    }

    /// <summary>
    /// The key must still be stable across rescans, or every Delete would land on
    /// "the list has moved on" — it is computed from the rule, not from its position.
    /// </summary>
    [Fact]
    public void TheSameRuleScannedTwice_KeepsItsKey()
    {
        var scanned = Rule("NetworkSentinel-Rule-SSH", "SSH");
        var rescanned = Rule("NetworkSentinel-Rule-SSH", "SSH");

        Assert.Equal(WebApp.ScannedRuleKey(scanned), WebApp.ScannedRuleKey(rescanned));
    }

    /// <summary>
    /// Shape stays part of the key, so a key cannot follow a rule that was edited
    /// into something else between the page rendering and the click arriving.
    /// </summary>
    [Fact]
    public void ARuleEditedToADifferentPort_NoLongerMatchesItsOldKey()
    {
        var before = Rule("NetworkSentinel-Rule-SSH", "SSH");
        var after = Rule("NetworkSentinel-Rule-SSH", "SSH", ports: "22");

        Assert.NotEqual(WebApp.ScannedRuleKey(before), WebApp.ScannedRuleKey(after));
    }
}
