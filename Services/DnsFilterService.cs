using System;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace NetworkSentinel.Services;

/// <summary>
/// The on/off switch for a filtering resolver — an AdGuard Home reachable from this
/// Mac, which on the arrangement this app is built around is the one running on the
/// VPN gateway that serves the tunnel's clients.
///
/// **The resolver is not installed from here.** The Linux build ships
/// <c>scripts/setup-dns-filter.sh</c> to stand one up on the node it configures;
/// macOS is the console side of that, so the address and credentials are typed into
/// Settings → DNS filtering and everything below talks to a resolver someone else's
/// machine is hosting. Nothing here writes to it beyond the protection switch.
///
/// This is the one control in the app that can stop a connection from ever being
/// attempted. Everything else here acts on a flow that already exists: the
/// prevention engine writes a rule for an address the socket tables have already
/// seen, which on a VPN gateway never includes a client's forwarded traffic at all.
/// A resolver refuses to answer, so the client learns no address and dials nothing.
///
/// **It toggles filtering, not the resolver.** Stopping the service would take DNS
/// away from every tunnel client at once — an outage, not "filtering off". Switching
/// protection off leaves the resolver answering normally, unfiltered, which is what
/// AdGuard Home's own "Disable protection" does and the only reading of this switch
/// that cannot strand a client.
///
/// The live state is read back from AdGuard rather than mirrored into settings.json.
/// A persisted bool drifts the moment anyone touches the AdGuard UI, and a switch
/// that reports "on" while nothing is being filtered is worse than no switch — the
/// same reason the auto-block status comes from the engine instead of the settings.
/// </summary>
public sealed class DnsFilterService : IDisposable
{
    /// <summary>How stale a cached protection state may get before a read refreshes it.</summary>
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(6) };
    private readonly object _gate = new();

    private string _baseUrl = "";
    private string _username = "";
    private string _password = "";
    private bool? _protection;
    private DateTime _checkedUtc = DateTime.MinValue;
    private Task? _refreshTask;
    private volatile string _status = "DNS filtering not configured";

    /// <summary>Where the AdGuard Home API lives, normalized. Empty when unconfigured.</summary>
    public string BaseUrl { get { lock (_gate) return _baseUrl; } }

    /// <summary>True once an address is set — i.e. the setup script has been run.</summary>
    public bool Configured { get { lock (_gate) return _baseUrl.Length > 0; } }

    /// <summary>
    /// Last known filtering state: true = filtering, false = resolving unfiltered,
    /// null = never successfully reached. Null is deliberately distinct from false;
    /// "cannot tell" must not render as "off".
    /// </summary>
    public bool? ProtectionEnabled { get { lock (_gate) return _protection; } }

    public string Status => _status;

    /// <summary>Points the switch at a resolver. Empty <paramref name="url"/> unconfigures it.</summary>
    public void Configure(string? url, string? username, string? password)
    {
        var normalized = NormalizeBaseUrl(url);
        lock (_gate)
        {
            var changed = normalized != _baseUrl;
            _baseUrl = normalized;
            _username = username?.Trim() ?? "";
            _password = password ?? "";
            if (changed)
            {
                _protection = null;
                _checkedUtc = DateTime.MinValue;
            }
        }
        _status = normalized.Length == 0
            ? $"DNS filtering not configured — {ConfigureHint}"
            : $"Resolver at {normalized}, state not read yet";
    }

    /// <summary>
    /// Accepts what a person would actually type — "10.8.0.1", "10.8.0.1:3000",
    /// "http://10.8.0.1:3000/" — and returns a canonical origin, or "" if it is not
    /// usable. The default port is AdGuard Home's UI port, which is what the setup
    /// script binds.
    /// </summary>
    public static string NormalizeBaseUrl(string? raw)
    {
        var text = raw?.Trim() ?? "";
        if (text.Length == 0) return "";

        if (!text.Contains("://", StringComparison.Ordinal))
            text = "http://" + text;

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) return "";
        if (uri.Scheme is not ("http" or "https")) return "";
        if (uri.Host.Length == 0) return "";

        // Whether a port was typed cannot be answered by looking for a colon in the
        // whole string — "http://10.8.0.1" has one, in the scheme. That read every
        // scheme-qualified address without a port as port 80, so the switch pointed
        // at nothing and reported only that the resolver could not be reached. Ask
        // the authority instead, past any IPv6 brackets.
        // Read the text, not the parsed Uri: Uri fills in a default port either way,
        // so it cannot say whether one was typed — which is the only question here.
        var afterScheme = text[(text.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var pathStart = afterScheme.IndexOfAny(new[] { '/', '?', '#' });
        var authority = pathStart >= 0 ? afterScheme[..pathStart] : afterScheme;
        var portGiven = authority.LastIndexOf(':') > authority.LastIndexOf(']');

        // No port typed: http means the resolver's own admin UI, which is where the
        // setup script puts it. https means something is proxying it, and the proxy's
        // default port is the sensible reading.
        var port = portGiven
            ? uri.Port
            : uri.Scheme == "https" ? 443 : 3000;
        return $"{uri.Scheme}://{uri.Host}:{port}";
    }

    /// <summary>
    /// Reads <c>protection_enabled</c> out of AdGuard Home's /control/status document.
    /// Split out from the request so the parsing is testable without a resolver.
    /// </summary>
    public static bool TryParseProtection(string json, out bool enabled, out string version)
    {
        enabled = false;
        version = "";
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            if (root.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String)
                version = v.GetString() ?? "";
            if (!root.TryGetProperty("protection_enabled", out var p)) return false;
            if (p.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
            enabled = p.GetBoolean();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Human-readable state for a status line, in the same voice as the other services.</summary>
    public static string Describe(bool configured, bool? protection, string detail)
    {
        if (!configured) return $"DNS filtering not configured — {ConfigureHint}";
        return protection switch
        {
            true  => $"Filtering names at the resolver{Suffix(detail)}",
            false => $"Resolver answering UNFILTERED — protection is off{Suffix(detail)}",
            _     => $"Resolver unreachable{Suffix(detail)}"
        };

        static string Suffix(string d) => string.IsNullOrWhiteSpace(d) ? "" : $" ({d})";
    }

    /// <summary>
    /// Kicks off a background read when the cached state is stale. Safe to call from a
    /// property getter on every render; only one request is ever in flight.
    /// </summary>
    public void EnsureFresh()
    {
        lock (_gate)
        {
            if (_baseUrl.Length == 0) return;
            if (_refreshTask is { IsCompleted: false }) return;
            if (DateTime.UtcNow - _checkedUtc < RefreshInterval) return;
            _refreshTask = Task.Run(() => RefreshAsync());
        }
    }

    /// <summary>Reads the current filtering state. Never throws.</summary>
    public async Task<bool> RefreshAsync(CancellationToken ct = default)
    {
        string url;
        lock (_gate) url = _baseUrl;
        if (url.Length == 0) return false;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{url}/control/status");
            Authorize(request);
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                Fail(response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                    ? "the resolver rejected the credentials"
                    : $"the resolver answered {(int)response.StatusCode}");
                return false;
            }

            if (!TryParseProtection(body, out var enabled, out var version))
            {
                Fail("the resolver's status document had no protection state");
                return false;
            }

            lock (_gate)
            {
                _protection = enabled;
                _checkedUtc = DateTime.UtcNow;
            }
            _status = Describe(true, enabled, version.Length > 0 ? $"AdGuard Home {version}" : "");
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            Fail(ex is TaskCanceledException ? "no answer within 6s" : "could not be reached");
            return false;
        }
    }

    /// <summary>
    /// Turns filtering on or off at the resolver. Returns the outcome and a sentence
    /// fit to show the user — a failure must say what stopped it, never just revert
    /// the switch and stay quiet.
    /// </summary>
    public async Task<(bool Ok, string Message)> SetProtectionAsync(bool enabled, CancellationToken ct = default)
    {
        string url;
        lock (_gate) url = _baseUrl;
        if (url.Length == 0)
            return (false, $"DNS filtering is not configured — {ConfigureHint}");

        // /control/protection is the current endpoint; older AdGuard Home builds only
        // accept the whole DNS config. Try both before reporting a failure.
        var attempts = new (string Path, string Body)[]
        {
            ("/control/protection", $"{{\"enabled\":{(enabled ? "true" : "false")}}}"),
            ("/control/dns_config", $"{{\"protection_enabled\":{(enabled ? "true" : "false")}}}")
        };

        string lastError = "no response";
        foreach (var (path, body) in attempts)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url + path)
                {
                    Content = JsonBody(body)
                };
                Authorize(request);
                using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

                if (response.IsSuccessStatusCode)
                {
                    lock (_gate)
                    {
                        _protection = enabled;
                        _checkedUtc = DateTime.UtcNow;
                    }
                    _status = Describe(true, enabled, "");
                    return (true, enabled
                        ? "DNS filtering: on — bad names are refused before anything connects"
                        : "DNS filtering: OFF — the resolver still answers, but nothing is filtered");
                }

                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    Fail("the resolver rejected the credentials");
                    return (false, "The resolver rejected the credentials — check the DNS filter username and password");
                }

                lastError = $"the resolver answered {(int)response.StatusCode}";
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                lastError = ex is TaskCanceledException ? "no answer within 6s" : "could not be reached";
            }
        }

        Fail(lastError);
        return (false, $"Could not change DNS filtering — {lastError}");
    }

    /// <summary>
    /// What to tell someone who has not pointed this anywhere yet. On Linux this names
    /// the setup script, because there the app can install the resolver it then talks
    /// to. Here it names the panel: the resolver is on another machine, and the only
    /// thing missing is its address.
    /// </summary>
    internal const string ConfigureHint = "enter its admin address in Settings → DNS filtering";

    /// <summary>Blocking wrapper for the synchronous settings paths in the TUI, GUI and web console.</summary>
    public (bool Ok, string Message) SetProtection(bool enabled)
        => Task.Run(() => SetProtectionAsync(enabled)).GetAwaiter().GetResult();

    /// <summary>
    /// One query the resolver refused. What the blocked-sites view is made of, and
    /// deliberately only what a person reading that view needs: which name, from
    /// which client, why, and under which rule.
    /// </summary>
    public sealed record BlockedQuery
    {
        public DateTime Time { get; init; }
        public string Domain { get; init; } = "";
        public string Client { get; init; } = "";
        public string Reason { get; init; } = "";
        public string Rule { get; init; } = "";

        public string TimeText => Time == default ? "" : Time.ToString("HH:mm:ss");
    }

    /// <summary>
    /// AdGuard's reason codes, in words. The raw value is passed through when it is
    /// one this does not know: a new filtering source should show up as its own name
    /// rather than as a blank column.
    /// </summary>
    public static string DescribeReason(string raw) => raw switch
    {
        "FilteredBlackList"     => "Blocklist",
        "FilteredSafeBrowsing"  => "Safe browsing",
        "FilteredParental"      => "Parental",
        "FilteredBlockedService" => "Blocked service",
        "FilteredSafeSearch"    => "Safe search",
        "FilteredInvalid"       => "Invalid query",
        "Rewrite"               => "Rewritten",
        "RewriteEtcHosts"       => "Rewritten (hosts)",
        _ => raw
    };

    /// <summary>
    /// Reads the blocked entries out of a /control/querylog document. Split from the
    /// request so it is testable without a resolver, like the status parse.
    ///
    /// Two shapes are accepted for the queried name: AdGuard has used both
    /// <c>question.name</c> and <c>question.host</c> across 0.107 releases, and a view
    /// that silently lists blank domains is worse than one that does not load.
    /// </summary>
    public static bool TryParseBlocked(string json, out IReadOnlyList<BlockedQuery> entries)
    {
        var list = new List<BlockedQuery>();
        entries = list;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return false;
            if (!doc.RootElement.TryGetProperty("data", out var data)) return false;
            if (data.ValueKind == JsonValueKind.Null) return true;   // no entries yet
            if (data.ValueKind != JsonValueKind.Array) return false;

            foreach (var row in data.EnumerateArray())
            {
                if (row.ValueKind != JsonValueKind.Object) continue;

                var reason = Text(row, "reason");
                // The query is filtered server-side, but a resolver that ignores the
                // parameter must not fill the view with things it did *not* block.
                if (reason.StartsWith("NotFiltered", StringComparison.Ordinal)) continue;

                var domain = "";
                if (row.TryGetProperty("question", out var q) && q.ValueKind == JsonValueKind.Object)
                {
                    domain = Text(q, "name");
                    if (domain.Length == 0) domain = Text(q, "host");
                }
                if (domain.Length == 0) continue;

                var rule = Text(row, "rule");
                if (rule.Length == 0 &&
                    row.TryGetProperty("rules", out var rules) &&
                    rules.ValueKind == JsonValueKind.Array)
                {
                    foreach (var r in rules.EnumerateArray())
                    {
                        rule = Text(r, "text");
                        if (rule.Length > 0) break;
                    }
                }

                var time = default(DateTime);
                var timeText = Text(row, "time");
                if (timeText.Length > 0 &&
                    DateTime.TryParse(timeText, CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind, out var parsed))
                {
                    time = parsed.Kind == DateTimeKind.Utc ? parsed.ToLocalTime() : parsed;
                }

                list.Add(new BlockedQuery
                {
                    Time = time,
                    Domain = domain,
                    Client = Text(row, "client"),
                    Reason = DescribeReason(reason),
                    Rule = rule
                });
            }
            return true;
        }
        catch (JsonException)
        {
            return false;
        }

        static string Text(JsonElement parent, string name)
            => parent.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() ?? ""
                : "";
    }

    /// <summary>
    /// The most recent names this resolver refused. Read on demand — opening the view
    /// or pressing refresh — never on the dashboard poll: the query log is the busiest
    /// thing AdGuard serves, and a console polling it every two seconds would be a
    /// load on the resolver every client depends on.
    /// </summary>
    public async Task<(bool Ok, string Message, IReadOnlyList<BlockedQuery> Entries)> GetBlockedAsync(
        int limit = 100, CancellationToken ct = default)
    {
        var none = (IReadOnlyList<BlockedQuery>)Array.Empty<BlockedQuery>();
        string url;
        lock (_gate) url = _baseUrl;
        if (url.Length == 0)
            return (false, $"DNS filtering is not configured — {ConfigureHint}", none);

        limit = Math.Clamp(limit, 1, 500);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"{url}/control/querylog?response_status=blocked&limit={limit}");
            Authorize(request);
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return (false, response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                    ? "The resolver rejected the credentials — check the DNS filter username and password"
                    : $"The resolver answered {(int)response.StatusCode}", none);

            if (!TryParseBlocked(body, out var parsed))
                return (false, "The resolver's query log could not be read", none);

            return (true, parsed.Count == 0
                ? "Nothing blocked yet — the log is empty, or the query log is switched off in AdGuard"
                : $"{parsed.Count} blocked", parsed);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return (false, ex is TaskCanceledException
                ? "The resolver did not answer within 6s"
                : "The resolver could not be reached", none);
        }
    }

    /// <summary>
    /// A JSON body whose Content-Type is exactly <c>application/json</c>.
    ///
    /// StringContent's (string, Encoding, string) constructor appends
    /// <c>; charset=utf-8</c>, and AdGuard Home compares the header rather than
    /// parsing it: the request is refused with 415 before it reaches the handler.
    /// The switch then failed against a resolver that was running, reachable and
    /// authenticated — the one case where every other check says everything is fine.
    /// The body is still UTF-8; only the parameter is dropped.
    /// </summary>
    public static StringContent JsonBody(string json)
    {
        var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private void Authorize(HttpRequestMessage request)
    {
        string user, pass;
        lock (_gate) { user = _username; pass = _password; }
        if (user.Length == 0) return;
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pass}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", token);
    }

    private void Fail(string detail)
    {
        lock (_gate)
        {
            _protection = null;
            _checkedUtc = DateTime.UtcNow;
        }
        _status = Describe(true, null, detail);
    }

    public void Dispose() => _http.Dispose();
}
