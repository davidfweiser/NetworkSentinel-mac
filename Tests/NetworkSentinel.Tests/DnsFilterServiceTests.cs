using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The switch for the filtering resolver, which is the only control in this app that
/// can stop a connection before it is attempted.
///
/// Two things are pinned here because getting either wrong is silent. The address
/// parse decides whether the switch reaches the resolver at all — a typo that
/// normalizes to something plausible would leave a switch that looks configured and
/// changes nothing. And the state parse decides what the switch *reports*: unknown
/// must never collapse into "off", because "I cannot reach the resolver" and
/// "filtering is deliberately off" need opposite responses from whoever is reading.
/// </summary>
public class DnsFilterServiceTests
{
    [Theory]
    [InlineData("10.8.0.1:3000", "http://10.8.0.1:3000")]
    [InlineData("http://10.8.0.1:3000", "http://10.8.0.1:3000")]
    [InlineData("http://10.8.0.1:3000/", "http://10.8.0.1:3000")]
    [InlineData("  http://10.8.0.1:3000  ", "http://10.8.0.1:3000")]
    [InlineData("https://dns.example.org:8443", "https://dns.example.org:8443")]
    // A scheme with no port: the colon in "http://" must not be read as a port having
    // been given, which is what sent this to port 80 and made the switch unreachable.
    [InlineData("http://10.8.0.1", "http://10.8.0.1:3000")]
    [InlineData("http://10.8.0.1/", "http://10.8.0.1:3000")]
    // https without a port means a proxy in front, where 443 is the sensible reading.
    [InlineData("https://dns.example.org", "https://dns.example.org:443")]
    // An explicit port always wins, including one that equals the scheme default.
    [InlineData("http://10.8.0.1:80", "http://10.8.0.1:80")]
    [InlineData("http://[fd00::1]:3000", "http://[fd00::1]:3000")]
    [InlineData("http://[fd00::1]", "http://[fd00::1]:3000")]
    public void KnownForms_NormalizeToAnOrigin(string raw, string expected)
    {
        Assert.Equal(expected, DnsFilterService.NormalizeBaseUrl(raw));
    }

    /// <summary>A bare host is the likeliest thing to be typed; it must reach the UI port.</summary>
    [Fact]
    public void BareHost_GetsTheAdGuardUiPort()
    {
        Assert.Equal("http://10.8.0.1:3000", DnsFilterService.NormalizeBaseUrl("10.8.0.1"));
    }

    /// <summary>An explicit port is never overridden by the default.</summary>
    [Fact]
    public void ExplicitPort_IsKept()
    {
        Assert.Equal("http://10.8.0.1:8080", DnsFilterService.NormalizeBaseUrl("10.8.0.1:8080"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Empty_MeansUnconfigured(string? raw)
    {
        Assert.Equal("", DnsFilterService.NormalizeBaseUrl(raw));
    }

    /// <summary>
    /// A scheme this cannot speak must be refused rather than coerced. Silently
    /// rewriting ftp:// to http:// would point the switch somewhere the user did
    /// not ask for.
    /// </summary>
    [Theory]
    [InlineData("ftp://10.8.0.1")]
    [InlineData("file:///etc/passwd")]
    public void NonHttpSchemes_AreRefused(string raw)
    {
        Assert.Equal("", DnsFilterService.NormalizeBaseUrl(raw));
    }

    [Fact]
    public void StatusDocument_YieldsProtectionAndVersion()
    {
        const string json = """
            {"protection_enabled":true,"running":true,"version":"v0.107.52","dns_port":53}
            """;
        Assert.True(DnsFilterService.TryParseProtection(json, out var enabled, out var version));
        Assert.True(enabled);
        Assert.Equal("v0.107.52", version);
    }

    [Fact]
    public void ProtectionOff_ParsesAsOff()
    {
        Assert.True(DnsFilterService.TryParseProtection("""{"protection_enabled":false}""", out var enabled, out _));
        Assert.False(enabled);
    }

    /// <summary>
    /// Anything that is not an explicit true/false is "cannot tell", not "off" — a
    /// resolver that answered something unexpected must not read as unprotected.
    /// </summary>
    [Theory]
    [InlineData("""{"running":true}""")]
    [InlineData("""{"protection_enabled":"yes"}""")]
    [InlineData("""{"protection_enabled":null}""")]
    [InlineData("not json at all")]
    [InlineData("[]")]
    [InlineData("")]
    public void MissingOrOddState_IsNotReadAsOff(string json)
    {
        Assert.False(DnsFilterService.TryParseProtection(json, out _, out _));
    }

    /// <summary>The three states must be distinguishable in the sentence the user reads.</summary>
    [Fact]
    public void Describe_SeparatesUnconfiguredOffAndUnreachable()
    {
        var unconfigured = DnsFilterService.Describe(false, null, "");
        var filtering = DnsFilterService.Describe(true, true, "");
        var off = DnsFilterService.Describe(true, false, "");
        var unreachable = DnsFilterService.Describe(true, null, "no answer within 6s");

        Assert.Contains("not configured", unconfigured);
        Assert.Contains("UNFILTERED", off);
        Assert.Contains("unreachable", unreachable);
        Assert.Contains("no answer within 6s", unreachable);

        Assert.NotEqual(filtering, off);
        Assert.NotEqual(off, unreachable);
        Assert.NotEqual(filtering, unreachable);
    }

    /// <summary>An unconfigured switch reports that, and never claims to have acted.</summary>
    [Fact]
    public void Unconfigured_RefusesToPretendItActed()
    {
        using var service = new DnsFilterService();
        Assert.False(service.Configured);
        Assert.Null(service.ProtectionEnabled);

        var (ok, message) = service.SetProtection(true);
        Assert.False(ok);
        // macOS does not install the resolver, so the unconfigured message points at the
        // panel where its address is typed rather than at Linux's setup script.
        Assert.Contains("not configured", message);
        Assert.Contains(DnsFilterService.ConfigureHint, message);
    }

    /// <summary>Pointing the switch somewhere else must drop the state read from the old resolver.</summary>
    [Fact]
    public void Reconfiguring_ForgetsThePreviousState()
    {
        using var service = new DnsFilterService();
        service.Configure("10.8.0.1:3000", "admin", "pw");
        Assert.True(service.Configured);
        Assert.Equal("http://10.8.0.1:3000", service.BaseUrl);
        Assert.Null(service.ProtectionEnabled);

        service.Configure("", "", "");
        Assert.False(service.Configured);
        Assert.Null(service.ProtectionEnabled);
        Assert.Contains("not configured", service.Status);
    }

    /// <summary>
    /// AdGuard Home compares the Content-Type header instead of parsing it, so the
    /// "; charset=utf-8" that StringContent adds by default earns a 415 — with the
    /// resolver reachable and the credentials accepted, which is the hardest kind of
    /// failure to place. Exactly "application/json", or the switch does nothing.
    /// </summary>
    [Fact]
    public void JsonBody_SendsNoCharsetParameter()
    {
        using var content = DnsFilterService.JsonBody("{\"enabled\":true}");
        Assert.Equal("application/json", content.Headers.ContentType?.ToString());
    }

    /// <summary>
    /// The blocked-sites view is only as honest as this parse. AdGuard has shipped
    /// both question.name and question.host across 0.107 releases, and the rule can
    /// arrive as a scalar or inside a rules[] array — a view that renders blank rows
    /// for the shape it did not expect would read as "nothing was blocked".
    /// </summary>
    [Fact]
    public void BlockedEntries_ReadBothQuestionShapes()
    {
        const string json = """
        {"data":[
          {"time":"2026-08-22T14:50:01.123Z","client":"10.87.0.2",
           "question":{"class":"IN","name":"doubleclick.net","type":"A"},
           "reason":"FilteredBlackList","rule":"||doubleclick.net^"},
          {"time":"2026-08-22T14:50:09.500Z","client":"10.87.0.3",
           "question":{"class":"IN","host":"ads.example.org","type":"A"},
           "reason":"FilteredSafeBrowsing",
           "rules":[{"filter_list_id":2,"text":"||ads.example.org^"}]}
        ],"oldest":"2026-08-22T14:00:00Z"}
        """;

        Assert.True(DnsFilterService.TryParseBlocked(json, out var entries));
        Assert.Equal(2, entries.Count);

        Assert.Equal("doubleclick.net", entries[0].Domain);
        Assert.Equal("10.87.0.2", entries[0].Client);
        Assert.Equal("Blocklist", entries[0].Reason);
        Assert.Equal("||doubleclick.net^", entries[0].Rule);

        Assert.Equal("ads.example.org", entries[1].Domain);
        Assert.Equal("Safe browsing", entries[1].Reason);
        Assert.Equal("||ads.example.org^", entries[1].Rule);
    }

    /// <summary>
    /// A resolver that ignores response_status=blocked must not have its ordinary
    /// traffic listed as blocked — the whole point of the view is what was refused.
    /// </summary>
    [Fact]
    public void BlockedEntries_SkipQueriesThatWereNotFiltered()
    {
        const string json = """
        {"data":[
          {"time":"2026-08-22T14:50:01Z","client":"10.87.0.2",
           "question":{"name":"example.com","type":"A"},"reason":"NotFilteredNotFound"},
          {"time":"2026-08-22T14:50:02Z","client":"10.87.0.2",
           "question":{"name":"tracker.example","type":"A"},"reason":"FilteredBlackList"}
        ]}
        """;

        Assert.True(DnsFilterService.TryParseBlocked(json, out var entries));
        Assert.Single(entries);
        Assert.Equal("tracker.example", entries[0].Domain);
    }

    /// <summary>An empty log is a valid answer, not a parse failure.</summary>
    [Theory]
    [InlineData("""{"data":[]}""")]
    [InlineData("""{"data":null}""")]
    public void BlockedEntries_EmptyLogParsesToNothing(string json)
    {
        Assert.True(DnsFilterService.TryParseBlocked(json, out var entries));
        Assert.Empty(entries);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"unexpected":true}""")]
    public void BlockedEntries_RejectWhatItCannotRead(string json)
    {
        Assert.False(DnsFilterService.TryParseBlocked(json, out var entries));
        Assert.Empty(entries);
    }

    /// <summary>An unknown reason code shows as itself rather than as a blank column.</summary>
    [Fact]
    public void UnknownReason_PassesThrough()
    {
        Assert.Equal("Blocklist", DnsFilterService.DescribeReason("FilteredBlackList"));
        Assert.Equal("FilteredSomethingNew", DnsFilterService.DescribeReason("FilteredSomethingNew"));
    }
}
