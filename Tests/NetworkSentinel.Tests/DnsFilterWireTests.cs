using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The bytes actually exchanged with AdGuard Home, against a stand-in that speaks its
/// API. The parsing tests next door cannot catch a wrong path, a missing
/// Authorization header, or a success reported for a request the resolver refused —
/// and each of those fails the same silent way: a switch that moves in the UI while
/// the resolver keeps doing what it was doing.
/// </summary>
public class DnsFilterWireTests
{
    /// <summary>A minimal AdGuard Home: records what it was asked, answers how it is told to.</summary>
    private sealed class FakeResolver : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly Task _loop;

        public List<string> Paths { get; } = new();
        public List<string> Bodies { get; } = new();
        public List<string> Queries { get; } = new();
        public List<string> ContentTypes { get; } = new();
        public string? LastAuthorization { get; private set; }

        /// <summary>Status code to answer per path; anything unlisted gets 404.</summary>
        public Dictionary<string, (int Status, string Body)> Routes { get; } = new();

        public string BaseUrl { get; }

        public FakeResolver()
        {
            var port = FreePort();
            BaseUrl = $"http://127.0.0.1:{port}";
            _listener.Prefixes.Add($"{BaseUrl}/");
            _listener.Start();
            _loop = Task.Run(Serve);
        }

        private static int FreePort()
        {
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }

        private async Task Serve()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { return; }

                var path = ctx.Request.Url?.AbsolutePath ?? "";
                Paths.Add(path);
                Queries.Add(ctx.Request.Url?.Query ?? "");
                ContentTypes.Add(ctx.Request.ContentType ?? "");
                LastAuthorization = ctx.Request.Headers["Authorization"];
                using (var reader = new StreamReader(ctx.Request.InputStream))
                    Bodies.Add(await reader.ReadToEndAsync());

                var (status, body) = Routes.TryGetValue(path, out var r) ? r : (404, "");
                ctx.Response.StatusCode = status;
                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* already down */ }
            try { _loop.Wait(TimeSpan.FromSeconds(2)); } catch { /* nothing to salvage */ }
            // Guarded, unlike the Linux original. macOS has no http.sys, so HttpListener
            // is the managed implementation, and Close() walks back through the endpoint
            // manager to unregister the prefix — which throws "Address already in use"
            // when another test's listener has since taken that ephemeral port. The
            // assertions have all run by here; a teardown throw would fail a test that
            // passed, intermittently and never the same one twice.
            try { _listener.Close(); } catch (HttpListenerException) { /* prefix already gone */ }
        }
    }

    [Fact]
    public async Task Refresh_ReadsLiveStateAndSendsCredentials()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/status"] = (200, """{"protection_enabled":true,"version":"v0.107.52"}""");

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "hunter2");

        Assert.True(await service.RefreshAsync());
        Assert.True(service.ProtectionEnabled);
        Assert.Contains("/control/status", resolver.Paths);

        // Basic admin:hunter2 — without this the resolver answers 401 and the switch
        // silently stops working the moment a password is set on it.
        var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:hunter2"));
        Assert.Equal(expected, resolver.LastAuthorization);
    }

    [Fact]
    public async Task SettingProtection_PostsTheCurrentEndpoint()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/protection"] = (200, "");

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "pw");

        var (ok, message) = await service.SetProtectionAsync(false);
        Assert.True(ok);
        Assert.Contains("/control/protection", resolver.Paths);
        Assert.Contains("\"enabled\":false", resolver.Bodies[0]);
        // The message must make an off switch unmistakable — "off" alone reads as
        // routine, and this one means every client is now resolving unfiltered.
        Assert.Contains("OFF", message);
        Assert.Contains("nothing is filtered", message);
        Assert.False(service.ProtectionEnabled);
    }

    /// <summary>
    /// Older AdGuard Home builds have no /control/protection. Falling back rather than
    /// failing is what keeps the switch working on a resolver someone installed a year ago.
    /// </summary>
    [Fact]
    public async Task OlderBuild_FallsBackToTheDnsConfigEndpoint()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/dns_config"] = (200, "");

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "pw");

        var (ok, _) = await service.SetProtectionAsync(true);
        Assert.True(ok);
        Assert.Contains("/control/protection", resolver.Paths);
        Assert.Contains("/control/dns_config", resolver.Paths);
        Assert.Contains("\"protection_enabled\":true", resolver.Bodies[^1]);
    }

    /// <summary>Wrong credentials must say so — not report a change that never happened.</summary>
    [Fact]
    public async Task RejectedCredentials_ReportFailureNotSuccess()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/protection"] = (401, "");

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "wrong");

        var (ok, message) = await service.SetProtectionAsync(true);
        Assert.False(ok);
        Assert.Contains("credentials", message);
        Assert.Null(service.ProtectionEnabled);
    }

    /// <summary>
    /// A resolver that is not running must leave the state unknown. Reporting it as
    /// "off" would send someone hunting for a setting when the service is simply down.
    /// </summary>
    [Fact]
    public async Task UnreachableResolver_LeavesStateUnknown()
    {
        string deadUrl;
        using (var resolver = new FakeResolver()) deadUrl = resolver.BaseUrl;

        using var service = new DnsFilterService();
        service.Configure(deadUrl, "admin", "pw");

        Assert.False(await service.RefreshAsync());
        Assert.Null(service.ProtectionEnabled);
        Assert.Contains("unreachable", service.Status);
    }

    /// <summary>
    /// The header AdGuard Home refuses. It compares Content-Type rather than parsing
    /// it, so the "; charset=utf-8" that StringContent writes by default came back as
    /// 415 — with the resolver running, reachable and authenticated, which is the
    /// hardest failure of all to place from the outside.
    /// </summary>
    [Fact]
    public async Task SettingProtection_SendsBareApplicationJson()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/protection"] = (200, "");

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "pw");

        Assert.True((await service.SetProtectionAsync(true)).Ok);
        Assert.Equal("application/json", resolver.ContentTypes[0]);
    }

    /// <summary>
    /// The blocked-sites view. Asking for the whole query log and filtering here would
    /// pull megabytes off a resolver every tunnel client depends on, so the filter and
    /// the limit go in the query string — and the credentials must ride along, or the
    /// view is empty on exactly the resolvers that have a password.
    /// </summary>
    [Fact]
    public async Task BlockedSites_AskTheResolverForBlockedOnly()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/querylog"] = (200, """
        {"data":[{"time":"2026-08-22T14:50:01Z","client":"10.87.0.2",
                  "question":{"name":"doubleclick.net","type":"A"},
                  "reason":"FilteredBlackList","rule":"||doubleclick.net^"}]}
        """);

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "pw");

        var (ok, message, entries) = await service.GetBlockedAsync(25);
        Assert.True(ok);
        Assert.Single(entries);
        Assert.Equal("doubleclick.net", entries[0].Domain);
        Assert.Contains("1 blocked", message);

        Assert.Contains("/control/querylog", resolver.Paths);
        Assert.Contains("response_status=blocked", resolver.Queries[0]);
        Assert.Contains("limit=25", resolver.Queries[0]);
        var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:pw"));
        Assert.Equal(expected, resolver.LastAuthorization);
    }

    /// <summary>
    /// An unconfigured resolver, a refused login and an empty log are three different
    /// answers. Collapsing any of them into "nothing was blocked" would report a view
    /// that could not be read as a resolver with nothing to report.
    /// </summary>
    [Fact]
    public async Task BlockedSites_SeparateEmptyFromUnreadable()
    {
        using var resolver = new FakeResolver();
        resolver.Routes["/control/querylog"] = (200, """{"data":[]}""");

        using var service = new DnsFilterService();
        service.Configure(resolver.BaseUrl, "admin", "pw");

        var empty = await service.GetBlockedAsync();
        Assert.True(empty.Ok);
        Assert.Empty(empty.Entries);
        Assert.Contains("Nothing blocked yet", empty.Message);

        resolver.Routes["/control/querylog"] = (401, "");
        var refused = await service.GetBlockedAsync();
        Assert.False(refused.Ok);
        Assert.Contains("credentials", refused.Message);

        using var unconfigured = new DnsFilterService();
        var none = await unconfigured.GetBlockedAsync();
        Assert.False(none.Ok);
        Assert.Contains("not configured", none.Message);
    }
}
