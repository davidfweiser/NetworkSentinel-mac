using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;

namespace NetworkSentinel.Services;

public sealed class GeoIpService : IDisposable
{
    private readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(4)
    };

    private readonly ConcurrentDictionary<string, GeoResult> _cache = new();
    private readonly ConcurrentDictionary<string, DateTime> _failedAt = new();
    private readonly ConcurrentDictionary<string, byte> _inFlight = new();
    private static readonly TimeSpan FailureRetryAfter = TimeSpan.FromMinutes(10);

    /// <summary>
    /// When false, the external geo web lookup is skipped entirely (reverse
    /// DNS still runs). Lookups go to ipwho.is first, falling back to ipapi.co —
    /// both over HTTPS, so the peer IPs this IDS observes are never broadcast in
    /// cleartext and an on-path attacker can't spoof the origin strings.
    /// </summary>
    public bool LookupsEnabled { get; set; } = true;

    public GeoIpService()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetworkSentinel/1.0");
    }

    public async Task<GeoResult> LookupAsync(string ip, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ip) || IsNonPublic(ip))
        {
            return new GeoResult
            {
                Ip = ip,
                HostName = IsLoopback(ip) ? "localhost" : "Private / local network",
                Country = IsLoopback(ip) ? "Localhost" : "LAN",
                City = "",
                Isp = "Private address space",
                Summary = IsLoopback(ip) ? "This computer" : "Private / local network"
            };
        }

        if (_cache.TryGetValue(ip, out var cached))
        {
            // Transient failures are retried after a cooldown instead of
            // pinning "lookup unavailable" for the rest of the session.
            if (_failedAt.TryGetValue(ip, out var failedAt))
            {
                if (DateTime.UtcNow - failedAt < FailureRetryAfter)
                    return cached;
                _cache.TryRemove(ip, out _);
                _failedAt.TryRemove(ip, out _);
            }
            else
            {
                return cached;
            }
        }

        if (!_inFlight.TryAdd(ip, 0))
        {
            // Another lookup is running; wait briefly for cache.
            for (int i = 0; i < 20 && !_cache.ContainsKey(ip); i++)
                await Task.Delay(100, ct);
            return _cache.TryGetValue(ip, out cached)
                ? cached
                : new GeoResult { Ip = ip, Summary = "Resolving…" };
        }

        try
        {
            string hostName = await ResolveHostNameAsync(ip, ct);

            if (!LookupsEnabled)
            {
                var dnsOnly = new GeoResult
                {
                    Ip = ip,
                    HostName = hostName,
                    Summary = string.IsNullOrWhiteSpace(hostName)
                        ? "Geo lookup disabled"
                        : $"Host: {hostName}"
                };
                _cache[ip] = dnsOnly;
                return dnsOnly;
            }

            var geo = await QueryGeoAsync(ip, ct);

            var result = new GeoResult
            {
                Ip = ip,
                HostName = hostName,
                Country = geo.Country,
                City = geo.City,
                Isp = geo.Isp,
                Lat = geo.Lat,
                Lon = geo.Lon,
                Summary = BuildSummary(geo.City, geo.Country, geo.Isp, hostName)
            };

            _cache[ip] = result;
            return result;
        }
        catch
        {
            string hostName = await ResolveHostNameAsync(ip, ct);
            var fallback = new GeoResult
            {
                Ip = ip,
                HostName = hostName,
                Summary = string.IsNullOrWhiteSpace(hostName)
                    ? "Location lookup unavailable"
                    : $"Host: {hostName}"
            };
            _cache[ip] = fallback;
            _failedAt[ip] = DateTime.UtcNow;
            return fallback;
        }
        finally
        {
            _inFlight.TryRemove(ip, out _);
        }
    }

    private async Task<(string Country, string City, string Isp, double Lat, double Lon)> QueryGeoAsync(
        string ip, CancellationToken ct)
    {
        // Both endpoints are HTTPS: a plain-HTTP fallback would broadcast every peer
        // IP this IDS observes and let an on-path attacker forge the origin strings
        // that land in threat alerts.
        try
        {
            return await QueryIpWhoIsAsync(ip, ct);
        }
        catch
        {
            return await QueryIpApiCoAsync(ip, ct);
        }
    }

    private async Task<(string Country, string City, string Isp, double Lat, double Lon)> QueryIpWhoIsAsync(
        string ip, CancellationToken ct)
    {
        // Free endpoint, no key, supports HTTPS. Rate-limited; we cache aggressively.
        var url = $"https://ipwho.is/{ip}?fields=success,country,city,connection.isp,latitude,longitude";
        using var response = await _http.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var root = doc.RootElement;

        if (!root.TryGetProperty("success", out var success) || !success.GetBoolean())
            throw new InvalidOperationException("ipwho.is lookup unsuccessful");

        string country = root.TryGetProperty("country", out var c) ? c.GetString() ?? "" : "";
        string city = root.TryGetProperty("city", out var ci) ? ci.GetString() ?? "" : "";
        string isp = root.TryGetProperty("connection", out var conn) &&
                     conn.ValueKind == JsonValueKind.Object &&
                     conn.TryGetProperty("isp", out var i)
            ? i.GetString() ?? ""
            : "";
        double lat = root.TryGetProperty("latitude", out var la) ? la.GetDouble() : 0;
        double lon = root.TryGetProperty("longitude", out var lo) ? lo.GetDouble() : 0;
        return (country, city, isp, lat, lon);
    }

    private async Task<(string Country, string City, string Isp, double Lat, double Lon)> QueryIpApiCoAsync(
        string ip, CancellationToken ct)
    {
        // Free endpoint, no key, HTTPS — ip-api.com only serves TLS on its paid tier,
        // which is why the old fallback there was plaintext. Rate-limited; we cache
        // aggressively.
        var url = $"https://ipapi.co/{ip}/json/";
        using var response = await _http.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var root = doc.RootElement;

        // Errors come back as 200 with {"error": true, "reason": ...}.
        if (root.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.True)
            throw new InvalidOperationException("ipapi.co lookup unsuccessful");

        // Full payloads carry country_name; abbreviated ones only the country code.
        string country = root.TryGetProperty("country_name", out var cn) ? cn.GetString() ?? "" : "";
        if (country.Length == 0 && root.TryGetProperty("country", out var cc))
            country = cc.GetString() ?? "";
        string city = root.TryGetProperty("city", out var ci) ? ci.GetString() ?? "" : "";
        string isp = root.TryGetProperty("org", out var i) ? i.GetString() ?? "" : "";
        // Latitude/longitude are null (not absent) for anonymized ranges.
        double lat = root.TryGetProperty("latitude", out var la) && la.ValueKind == JsonValueKind.Number ? la.GetDouble() : 0;
        double lon = root.TryGetProperty("longitude", out var lo) && lo.ValueKind == JsonValueKind.Number ? lo.GetDouble() : 0;
        return (country, city, isp, lat, lon);
    }

    private static async Task<string> ResolveHostNameAsync(string ip, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var entry = await Dns.GetHostEntryAsync(ip, cts.Token);
            return entry.HostName ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static string BuildSummary(string city, string country, string isp, string host)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(city)) parts.Add(city);
        if (!string.IsNullOrWhiteSpace(country)) parts.Add(country);
        if (!string.IsNullOrWhiteSpace(isp)) parts.Add(isp);
        if (parts.Count == 0 && !string.IsNullOrWhiteSpace(host))
            return $"Host: {host}";
        if (parts.Count == 0) return "Location unknown";
        return string.Join(" · ", parts);
    }

    public static bool IsNonPublic(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return true;
        // lsof and netstat report peers of dual-stack sockets as ::ffff:a.b.c.d, so an
        // unmapped check would call every LAN peer of an IPv6 listener public — geo-
        // looked-up, and eligible for auto-block.
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return true;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 10) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            if (bytes[0] == 0) return true;
            // 100.64.0.0/10 (RFC 6598 CGNAT) — Tailscale and many VPN tunnel subnets
            // live here. Not routable on the public internet, so blocking it would only
            // ever cut off a tunnel peer.
            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return true;
            // Multicast / reserved / broadcast — not a peer anything could block.
            if (bytes[0] >= 224) return true;
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
                return true;
            if (address.IsIPv6Multicast) return true;
            if (address.Equals(IPAddress.IPv6Any)) return true;
        }
        return false;
    }

    /// <summary>
    /// 100.64.0.0/10 (RFC 6598). Kept out of <em>auto</em>-block by
    /// <see cref="IsNonPublic"/>, but a real host lives at the other end — a tailnet
    /// peer or a subscriber behind carrier NAT — so a manual block must still be
    /// possible. Unlike a LAN address, firewalling one cannot cut the machine off
    /// from its own network.
    /// </summary>
    public static bool IsCarrierGradeNat(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127;
    }

    /// <summary>Multicast / broadcast destinations (mDNS, SSDP, …) — noise, not peers.</summary>
    public static bool IsMulticastOrBroadcast(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] >= 224; // 224–239 multicast, 240+ reserved, 255 broadcast
        }
        return address.IsIPv6Multicast;
    }

    private static bool IsLoopback(string ip)
        => IPAddress.TryParse(ip, out var a) && IPAddress.IsLoopback(a);

    public void Dispose() => _http.Dispose();
}

public sealed class GeoResult
{
    public string Ip { get; init; } = "";
    public string HostName { get; init; } = "";
    public string Country { get; init; } = "";
    public string City { get; init; } = "";
    public string Isp { get; init; } = "";
    public double Lat { get; init; }
    public double Lon { get; init; }
    public string Summary { get; init; } = "";
}
