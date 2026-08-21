using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetworkSentinel.Models;
using NetworkSentinel.Services;

namespace NetworkSentinel.Web;

/// <summary>
/// Headless web UI for Network Sentinel — same monitoring / firewall services as the TUI/GUI.
/// Launch with <c>-w</c> / <c>--web</c>. Serves a browser dashboard on an uncommon free port.
/// </summary>
public sealed class WebApp : IDisposable
{
    /// <summary>
    /// High ports that common servers (HTTP, DBs, game/dev stacks) almost never claim.
    /// First free candidate wins; falls back to an OS-assigned ephemeral port.
    /// </summary>
    private static readonly int[] PreferredPorts =
    [
        18765, 18766, 18767, 27654, 31415, 41927, 47293, 52891, 58347, 61903
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    // The shared graph is built and cross-wired by SentinelCore; these are views
    // onto it so the rest of this class reads unchanged.
    private readonly SentinelCore _core = new();
    private readonly NetworkMonitorService _monitor;
    private readonly FirewallService _firewall;
    private readonly AllowlistService _allowlist;

    // ── Host firewall scan ───────────────────────────────────────────────
    //
    // The Firewall Config tab lists the whole host firewall, which means shelling
    // out to pfctl, socketfilterfw and lsof. /api/state is polled every 2.5s, so the
    // scan is cached and only re-run on demand — the tab's Refresh button, and
    // after any write — with a TTL as a backstop so a stale page self-heals.

    private HostFirewallScanner? _hostScanner;
    private HostFirewallSnapshot? _hostScan;
    private DateTime _hostScanAtUtc = DateTime.MinValue;
    private readonly object _hostScanGate = new();
    private static readonly TimeSpan HostScanTtl = TimeSpan.FromSeconds(60);

    private HostFirewallSnapshot HostScan(bool force = false)
    {
        lock (_hostScanGate)
        {
            if (!force && _hostScan != null && DateTime.UtcNow - _hostScanAtUtc < HostScanTtl)
                return _hostScan;

            _hostScanner ??= new HostFirewallScanner(_firewall);
            try
            {
                _hostScan = _hostScanner.Scan();
            }
            catch (Exception ex)
            {
                _hostScan = HostFirewallSnapshot.Unreadable(
                    "The host firewall scan failed.", new[] { ex.Message });
            }
            _hostScanAtUtc = DateTime.UtcNow;
            return _hostScan;
        }
    }

    /// <summary>Drops the cached scan so the next state request re-reads the kernel.</summary>
    private void InvalidateHostScan()
    {
        lock (_hostScanGate) _hostScanAtUtc = DateTime.MinValue;
    }

    /// <summary>
    /// Stable identity for a scanned rule, so a Delete pressed in the browser acts
    /// on the row that was displayed. Rule names are not unique across the host —
    /// two pf anchors can both hold an allow-inbound-ssh — so the key is the rule's
    /// whole shape, and an ambiguous match is refused rather than guessed at.
    /// </summary>
    private static string ScannedRuleKey(FirewallRuleInfo r) => string.Join("|",
        r.IsInbound ? "in" : "out", r.ActionText, r.ProtocolText,
        r.PortRangeText, r.AddressListText, r.LabelText, r.Origin);

    private FirewallRuleInfo? FindScannedRule(string key, out string problem)
    {
        problem = "";
        var scan = HostScan();
        var matches = scan.Inbound.Concat(scan.Outbound)
            .Where(r => string.Equals(ScannedRuleKey(r), key, StringComparison.Ordinal))
            .ToList();

        if (matches.Count == 1) return matches[0];
        problem = matches.Count == 0
            ? "That rule is no longer in the host firewall — the list has moved on. Refresh and try again."
            : "Several rules on this host have exactly that shape, so it is not clear which one to remove. " +
              "Give them distinct labels, or remove it where it was created.";
        return null;
    }
    private readonly WebAuthStore _auth = new();
    private readonly AppSettings _settings;
    // The blocked set, the retry backoff and the suppression list all live in
    // PreventionService now — this class kept its own copies of all three, and was the
    // only frontend whose copy honoured suppression.
    private readonly PreventionService _prevention;
    /// <summary>
    /// IPs the user explicitly unblocked/removed. Auto-block must not recreate rules for these
    /// until the user manually blocks again (or the suppress window expires).
    /// </summary>
    private readonly Dictionary<string, DateTime> _autoBlockSuppressedUntil = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Interface byte counters behind the dashboard's data-flow card. Started by
    /// <see cref="SentinelCore"/>, so the daily history has been recording since
    /// 0.7.0 — the desktop GUI drew it, this console had no chart for it.
    /// </summary>
    private readonly TrafficMeterService _traffic;

    /// <summary>Stand-in shown in the settings page where a DuckDNS token is stored but must not be sent.</summary>
    private const string TokenPlaceholder = "••••••••";

    private static readonly TimeSpan AutoBlockRetryAfter = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ManualUnblockSuppressFor = TimeSpan.FromHours(24);

    private readonly int _port;
    private readonly bool _bindAll;
    private bool _listeningLocalOnly;
    private WebApplication? _host;
    private readonly LoginThrottle _loginThrottle = new();
    private readonly DuckDnsUpdater _duckDns = new();
    private TlsCertificateProvider? _tls;
    private int _httpsPort;
    private bool _httpsActive;
    private bool _httpOff;
    private CancellationTokenSource? _cts;
    private string _statusMessage = "Web UI ready — monitoring started.";
    private bool _autoBlockEnabled;
    private string _autoBlockMinLevel;
    private bool _blockInbound;
    private bool _blockOutbound;
    private readonly string _appVersion = FormatAppVersion();

    public int Port => _port;

    /// <summary>HTTPS port actually in use, or 0 when TLS is off.</summary>
    public int HttpsPort => _httpsActive ? _httpsPort : 0;

    public WebApp(int? requestedPort = null, bool bindAll = true, WebTlsOptions? tlsOverrides = null)
    {
        _bindAll = bindAll;
        _port = ResolvePort(requestedPort);
        _settings = _core.Settings;
        _monitor = _core.Monitor;
        _firewall = _core.Firewall;
        _allowlist = _core.Allowlist;
        _prevention = _core.Prevention;
        _traffic = _core.Traffic;
        ApplyTlsOverrides(tlsOverrides);
        _autoBlockEnabled = _settings.AutoBlockEnabled;
        _autoBlockMinLevel = _settings.AutoBlockMinLevel;
        if (_autoBlockMinLevel is not (nameof(ThreatLevel.Medium) or nameof(ThreatLevel.High) or nameof(ThreatLevel.Critical)))
            _autoBlockMinLevel = nameof(ThreatLevel.High);
        _blockInbound = _settings.AutoBlockInbound;
        _blockOutbound = _settings.AutoBlockOutbound;

        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
    }

    /// <summary>Command-line TLS flags win over the persisted settings, without overwriting them.</summary>
    private void ApplyTlsOverrides(WebTlsOptions? o)
    {
        if (o == null)
            return;
        if (o.Enabled.HasValue) _settings.WebHttpsEnabled = o.Enabled.Value;
        if (o.Port.HasValue) _settings.WebHttpsPort = o.Port.Value;
        if (!string.IsNullOrWhiteSpace(o.CertPath)) _settings.WebTlsCertPath = o.CertPath!.Trim();
        if (!string.IsNullOrWhiteSpace(o.KeyPath)) _settings.WebTlsKeyPath = o.KeyPath!.Trim();
        if (!string.IsNullOrWhiteSpace(o.PfxPassword)) _settings.WebTlsPfxPassword = o.PfxPassword!;
    }

    public async Task RunAsync()
    {
        _cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _cts.Cancel();
        };

        Console.WriteLine("Network Sentinel — headless web UI");
        Console.WriteLine("Loading allowlist…");

        try
        {
            await _allowlist.InitializeAsync(_cts.Token);
            _statusMessage = _allowlist.StatusText;
        }
        catch (Exception ex)
        {
            _statusMessage = $"Allowlist load error: {ex.Message}";
            Console.Error.WriteLine(_statusMessage);
        }

        // The clamp above can change the level, so push it to the engine explicitly.
        // Persisted suppressions are loaded by PreventionService itself.
        _prevention.MinLevel = Enum.TryParse<ThreatLevel>(_autoBlockMinLevel, true, out var lvl)
            ? lvl
            : ThreatLevel.High;
        RefreshBlockedIps(force: true);
        _monitor.Start();
        StartDuckDns();

        _host = BuildHost();

        try
        {
            await _host.StartAsync(_cts.Token);
        }
        catch (Exception ex)
        {
            // ResolvePort only guarantees the HTTP port is free — the HTTPS port is whatever
            // was configured, so name both rather than blaming the one that is probably fine.
            var ports = _httpOff ? $"port {_httpsPort} (HTTPS)"
                : _httpsActive ? $"port {_port} (HTTP) or {_httpsPort} (HTTPS)"
                : $"port {_port}";
            throw new InvalidOperationException(
                $"Failed to bind web UI on {ports}. Try another port with -w PORT " +
                (_httpsActive ? "or --https-port PORT " : "") +
                $"(ports below 1024 need root). Detail: {ex.Message}", ex);
        }

        PrintListenBanner();

        try
        {
            await _host.WaitForShutdownAsync(_cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Ctrl+C — normal shutdown.
        }
        finally
        {
            _monitor.Stop();
            _duckDns.Stop();
            try { await _host.StopAsync(TimeSpan.FromSeconds(3)); } catch { /* ignore */ }
            Console.WriteLine("Network Sentinel web UI stopped.");
        }
    }

    /// <summary>
    /// Kestrel serves the console: unlike HttpListener it terminates TLS on macOS, and it
    /// hands us the real client address for login throttling.
    /// </summary>
    private WebApplication BuildHost()
    {
        var builder = WebApplication.CreateBuilder();
        // Kestrel's own logs would interleave with the console banner and alert output.
        builder.Logging.ClearProviders();

        var bindAddress = _bindAll ? IPAddress.Any : IPAddress.Loopback;
        _listeningLocalOnly = !_bindAll;

        var tlsError = ConfigureTls();

        // HTTPS-only skips the plain-HTTP listener — but only when TLS actually came up.
        // A certificate problem must degrade to HTTP with a warning, never to no console.
        _httpOff = _settings.WebHttpsOnly && _httpsActive;

        builder.WebHost.ConfigureKestrel(options =>
        {
            // The request handler writes responses synchronously (Stream.Write / ReadToEnd).
            options.AllowSynchronousIO = true;
            // Nothing here accepts uploads; a small cap blunts memory-pressure probing.
            options.Limits.MaxRequestBodySize = 1 * 1024 * 1024;
            options.AddServerHeader = false;

            if (!_httpOff)
                options.Listen(bindAddress, _port);

            if (_httpsActive && _tls != null)
            {
                options.Listen(bindAddress, _httpsPort, listen =>
                    listen.UseHttps(httpsOptions =>
                    {
                        // Re-read on each connection so an ACME renewal applies without a restart.
                        httpsOptions.ServerCertificateSelector = (_, _) => _tls.Current;
                    }));
            }
        });

        var app = builder.Build();
        app.Run(ctx =>
        {
            HandleRequestSafe(ctx);
            return Task.CompletedTask;
        });

        if (tlsError != null)
            Console.Error.WriteLine($"HTTPS disabled: {tlsError}");
        if (_settings.WebHttpsOnly && !_httpOff)
            Console.Error.WriteLine("HTTPS-only is set, but HTTPS is not running — serving plain HTTP so the console stays reachable.");

        return app;
    }

    /// <summary>Loads the certificate if HTTPS is switched on. Returns an error string when it cannot be used.</summary>
    private string? ConfigureTls()
    {
        _httpsActive = false;
        if (!_settings.WebHttpsEnabled)
            return null;

        _httpsPort = _settings.WebHttpsPort is >= 1 and <= 65535 ? _settings.WebHttpsPort : 18443;
        if (_httpsPort == _port)
            return $"HTTPS port {_httpsPort} is the same as the HTTP port — set a different --https-port.";

        if (!TlsCertificateProvider.TryLoad(_settings.WebTlsCertPath, _settings.WebTlsKeyPath,
                _settings.WebTlsPfxPassword, out var cert, out var error))
        {
            return error;
        }

        cert?.Dispose();
        _tls = new TlsCertificateProvider(_settings.WebTlsCertPath, _settings.WebTlsKeyPath, _settings.WebTlsPfxPassword);
        _ = _tls.Current; // populate Status for the banner and settings page
        _httpsActive = true;
        return null;
    }

    private void StartDuckDns()
    {
        try
        {
            _duckDns.Start();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"DuckDNS updater failed to start: {ex.Message}");
        }
    }

    private void PrintListenBanner()
    {
        Console.WriteLine();
        var scope = _listeningLocalOnly ? "localhost only" : (_bindAll ? "all interfaces" : "localhost only");
        if (_httpOff)
        {
            // No HTTP listener at all, so the banner has to hand out working HTTPS URLs —
            // the bare-IP ones get a certificate warning, but they connect encrypted.
            Console.WriteLine($"  Listening on port {_httpsPort}  ({scope}) — HTTPS only, plain HTTP is off");
            Console.WriteLine($"  Local:   https://127.0.0.1:{_httpsPort}/");
            if (_bindAll && !_listeningLocalOnly)
            {
                foreach (var ip in GetLanIpv4Addresses().Take(4))
                    Console.WriteLine($"  Network: https://{ip}:{_httpsPort}/");
            }
        }
        else
        {
            Console.WriteLine($"  Listening on port {_port}  ({scope})");
            Console.WriteLine($"  Local:   http://127.0.0.1:{_port}/");
            if (_bindAll && !_listeningLocalOnly)
            {
                foreach (var ip in GetLanIpv4Addresses().Take(4))
                    Console.WriteLine($"  Network: http://{ip}:{_port}/");
            }
        }

        if (_httpsActive)
        {
            Console.WriteLine();
            Console.WriteLine($"  HTTPS on port {_httpsPort}");
            var hostname = _duckDns.Hostname;
            if (!string.IsNullOrEmpty(hostname))
                Console.WriteLine($"  Secure:  https://{hostname}:{_httpsPort}/");
            Console.WriteLine($"  {_tls?.Status}");
        }

        if (_duckDns.Config.IsUsable)
            Console.WriteLine($"  {_duckDns.Status}");

        Console.WriteLine();
        Console.WriteLine("  Open the URL above in your browser.");
        if (_auth.IsConfigured)
        {
            Console.WriteLine("  Master password required on every login.");
        }
        else
        {
            Console.WriteLine("  First visit: create a master password in the browser.");
            Console.WriteLine($"  Setup code (asked for when setting up from another machine): {_setupCode}");
        }
        Console.WriteLine("  Press Ctrl+C to stop.");
        Console.WriteLine();
    }

    private static IEnumerable<string> GetLanIpv4Addresses()
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback)
                    continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        list.Add(ua.Address.ToString());
                }
            }
        }
        catch
        {
            // best-effort only
        }
        return list;
    }

    private void HandleRequestSafe(HttpContext ctx)
    {
        try
        {
            HandleRequest(ctx);
        }
        catch (Exception ex)
        {
            try
            {
                // Exception text can name paths, hosts, or backend detail — an
                // authenticated admin may see it, an anonymous client gets a
                // generic body.
                var authed = false;
                try { authed = _auth.IsSessionValid(GetSessionToken(ctx.Request)); } catch { /* treat as anonymous */ }
                WriteJson(ctx.Response, 500, new { ok = false, message = authed ? ex.Message : "Internal error." });
            }
            catch
            {
                try { ctx.Abort(); } catch { /* ignore */ }
            }
        }
    }

    private void HandleRequest(HttpContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        res.Headers["Cache-Control"] = "no-store";
        res.Headers["X-Content-Type-Options"] = "nosniff";
        res.Headers["Referrer-Policy"] = "same-origin";
        // An admin console has no business inside a frame — every action is one click.
        res.Headers["X-Frame-Options"] = "DENY";
        if (req.IsHttps)
            res.Headers["Strict-Transport-Security"] = "max-age=31536000";

        if (TryRedirectToHttps(ctx))
            return;

        var path = (req.Path.Value ?? "").TrimEnd('/');
        if (path.Length == 0)
            path = "/";

        if (req.Method == "GET" && (path is "/" or "/index.html"))
        {
            WriteHtml(res, PageHtml());
            return;
        }

        // --- Auth endpoints (public) ---
        if (req.Method == "GET" && path == "/api/auth/status")
        {
            var authed = _auth.IsSessionValid(GetSessionToken(req));
            WriteJson(res, 200, new
            {
                ok = true,
                configured = _auth.IsConfigured,
                authenticated = authed,
                minPasswordLength = WebAuthStore.MinPasswordLength,
                setupCodeRequired = !_auth.IsConfigured && !IsLoopbackClient(ctx)
            });
            return;
        }

        if (req.Method == "POST" && path == "/api/auth/setup")
        {
            var body = ReadBody(req);
            var authReq = DeserializeAuth(body);
            if (authReq == null)
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            if (IsLockedOut(ctx, res))
                return;

            // Remote first-visit setup must quote the code printed on the server
            // console; without it, the first scanner to find the port would claim
            // the master password. Local setup needs nothing.
            if (!IsLoopbackClient(ctx) && !SetupCodeMatches(authReq.SetupCode))
            {
                Thread.Sleep(400);
                _loginThrottle.RecordFailure(ClientAddress(ctx));
                WriteJson(res, 403, new
                {
                    ok = false,
                    message = "Setup code required (or wrong). It is printed where the console runs — " +
                              "the terminal, or `log show --predicate 'process == \"NetworkSentinel\"'` " +
                              "when it runs as a launchd service."
                });
                return;
            }

            if (!_auth.TrySetup(authReq.Password ?? "", authReq.Confirm ?? authReq.Password ?? "", out var setupMsg))
            {
                // Slow down scripted setup attempts.
                Thread.Sleep(400);
                _loginThrottle.RecordFailure(ClientAddress(ctx));
                WriteJson(res, 400, new { ok = false, message = setupMsg });
                return;
            }

            _loginThrottle.RecordSuccess(ClientAddress(ctx));
            var token = _auth.CreateSession();
            SetSessionCookie(ctx, token);
            WriteJson(res, 200, new { ok = true, message = setupMsg, authenticated = true });
            return;
        }

        if (req.Method == "POST" && path == "/api/auth/login")
        {
            var body = ReadBody(req);
            var authReq = DeserializeAuth(body);
            if (authReq == null)
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            if (!_auth.IsConfigured)
            {
                WriteJson(res, 400, new { ok = false, message = "Master password not set yet. Use setup." });
                return;
            }

            if (IsLockedOut(ctx, res))
                return;

            // Delay blunts a serial guesser; the lockout is what stops a parallel one.
            if (!_auth.VerifyPassword(authReq.Password ?? ""))
            {
                Thread.Sleep(600);
                var lockout = _loginThrottle.RecordFailure(ClientAddress(ctx));
                WriteJson(res, 401, new
                {
                    ok = false,
                    message = lockout > TimeSpan.Zero
                        ? $"Incorrect master password. Too many attempts — locked out for {LoginThrottle.Describe(lockout)}."
                        : "Incorrect master password."
                });
                return;
            }

            _loginThrottle.RecordSuccess(ClientAddress(ctx));
            var token = _auth.CreateSession();
            SetSessionCookie(ctx, token);
            WriteJson(res, 200, new { ok = true, message = "Signed in.", authenticated = true });
            return;
        }

        if (req.Method == "POST" && path == "/api/auth/logout")
        {
            _auth.RevokeSession(GetSessionToken(req));
            ClearSessionCookie(ctx);
            WriteJson(res, 200, new { ok = true, message = "Signed out." });
            return;
        }

        // --- Protected API ---
        if (!_auth.IsSessionValid(GetSessionToken(req)))
        {
            WriteJson(res, 401, new
            {
                ok = false,
                message = "Authentication required.",
                configured = _auth.IsConfigured,
                authenticated = false
            });
            return;
        }

        if (req.Method == "POST" && path == "/api/auth/change-password")
        {
            var body = ReadBody(req);
            var authReq = DeserializeAuth(body);
            if (authReq == null)
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            var current = authReq.CurrentPassword ?? authReq.Password ?? "";
            var next = authReq.NewPassword ?? "";
            var confirm = authReq.Confirm ?? "";
            var session = GetSessionToken(req);

            if (IsLockedOut(ctx, res))
                return;

            if (!_auth.TryChangePassword(current, next, confirm, session, out var changeMsg))
            {
                Thread.Sleep(600);
                _loginThrottle.RecordFailure(ClientAddress(ctx));
                WriteJson(res, 400, new { ok = false, message = changeMsg });
                return;
            }

            _loginThrottle.RecordSuccess(ClientAddress(ctx));

            WriteJson(res, 200, new { ok = true, message = changeMsg });
            return;
        }

        if (req.Method == "GET" && path == "/api/state")
        {
            WriteJson(res, 200, BuildState());
            return;
        }

        if (req.Method == "POST" && path == "/api/action")
        {
            var body = ReadBody(req);
            ActionRequest? actionReq = null;
            try
            {
                actionReq = JsonSerializer.Deserialize<ActionRequest>(body, JsonOptions);
            }
            catch
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            if (actionReq == null || string.IsNullOrWhiteSpace(actionReq.Action))
            {
                WriteJson(res, 400, new { ok = false, message = "Missing action." });
                return;
            }

            var result = RunAction(actionReq);
            WriteJson(res, result.Ok ? 200 : 400, result);
            return;
        }

        WriteJson(res, 404, new { ok = false, message = "Not found." });
    }

    private static string ReadBody(HttpRequest req)
    {
        // Kestrel exposes the body as UTF-8 bytes; the console only ever posts JSON.
        using var reader = new StreamReader(req.Body, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private AuthBody? DeserializeAuth(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<AuthBody>(body, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private static string? GetSessionToken(HttpRequest req)
    {
        try
        {
            if (req.Cookies.TryGetValue(WebAuthStore.CookieName, out var cookie) && !string.IsNullOrEmpty(cookie))
                return cookie;
        }
        catch
        {
            // ignore
        }

        // Also accept Authorization: Bearer <token> for non-browser clients.
        var authHeader = req.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) &&
            authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return authHeader["Bearer ".Length..].Trim();

        return null;
    }

    private static void SetSessionCookie(HttpContext ctx, string token)
    {
        // Session cookie (no Max-Age): browser discards on close → login again next visit.
        // HttpOnly so JS cannot read it; SameSite=Strict for CSRF-ish protection on POST.
        // Secure only over TLS — setting it on plain HTTP would make the cookie unusable.
        ctx.Response.Cookies.Append(WebAuthStore.CookieName, token, new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = ctx.Request.IsHttps
        });
    }

    private static void ClearSessionCookie(HttpContext ctx)
    {
        ctx.Response.Cookies.Delete(WebAuthStore.CookieName, new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = ctx.Request.IsHttps
        });
    }

    // ── Certificate issuance ───────────────────────────────────────────────────
    // Issuance takes minutes (DNS propagation), far longer than a request should
    // hold, so the action starts it and the page polls certIssueBusy for the result.
    private int _certIssueBusy;
    private string _certIssueMessage = "";
    private bool _certIssueOk;

    /// <summary>
    /// Kick off a Let's Encrypt issuance for the saved DuckDNS name. Requires an
    /// authenticated session like every other action, and runs one at a time —
    /// concurrent ACME runs for the same name fight over the same TXT record.
    /// </summary>
    private ActionResultDto StartCertIssuance()
    {
        var domain = DuckDnsUpdater.NormalizeDomain(_duckDns.Config.Domain);
        var token = _duckDns.Config.Token;

        if (domain.Length == 0 || token.Length == 0)
            return ActionResultDto.Fail("Save the DuckDNS subdomain and token first — issuance proves control through them.");

        if (CertIssuanceService.FindScript() == null)
            return ActionResultDto.Fail("Could not find issue-duckdns-cert.sh on this Mac.");

        if (Interlocked.CompareExchange(ref _certIssueBusy, 1, 0) != 0)
            return ActionResultDto.Fail("A certificate is already being issued.");

        _certIssueOk = false;
        _certIssueMessage = $"Issuing a certificate for {domain}.duckdns.org — this waits on DNS propagation and can take a few minutes…";
        _statusMessage = _certIssueMessage;

        _ = Task.Run(async () =>
        {
            try
            {
                var result = await CertIssuanceService.IssueAsync(domain, token, _settings.AcmeAccountEmail);
                if (result.Success)
                {
                    // Same as the desktop app: point the console at what was produced.
                    // Takes effect at the next console start, like any other TLS change.
                    _settings.WebTlsCertPath = result.CertPath;
                    if (result.KeyPath.Length > 0)
                        _settings.WebTlsKeyPath = result.KeyPath;
                    _settings.Save();
                    _certIssueOk = true;
                    _certIssueMessage = $"{result.Message} Paths filled in — switch HTTPS on, then restart the console.";
                }
                else
                {
                    _certIssueMessage = result.Message;
                }
            }
            catch (Exception ex)
            {
                _certIssueMessage = $"Certificate issuance failed: {ex.Message}";
            }
            finally
            {
                _statusMessage = _certIssueMessage;
                Volatile.Write(ref _certIssueBusy, 0);
            }
        });

        return ActionResultDto.Success(_certIssueMessage);
    }

    private string HttpsStatusText()
    {
        if (_httpsActive)
        {
            var status = _tls?.Status ?? $"HTTPS: serving on port {_httpsPort}";
            return _httpOff ? $"{status} Plain HTTP is off — this console is HTTPS-only." : status;
        }
        if (!_settings.WebHttpsEnabled)
            return "HTTPS: off — this page is served over plain HTTP.";
        return _settings.WebHttpsOnly
            ? "HTTPS: enabled in settings but not running — plain HTTP stays on so this page is reachable. Restart the web console."
            : "HTTPS: enabled in settings but not running — restart the web console.";
    }

    /// <summary>Copy of the live DuckDNS config so a partial edit keeps the fields it did not touch.</summary>
    private DuckDnsConfig CloneDuckDns() => new()
    {
        Enabled = _duckDns.Config.Enabled,
        Domain = _duckDns.Config.Domain,
        Token = _duckDns.Config.Token,
        IntervalMinutes = _duckDns.Config.IntervalMinutes
    };

    private static string DescribeProbe(System.Security.Cryptography.X509Certificates.X509Certificate2? cert)
    {
        if (cert == null)
            return "";
        var name = cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.DnsName, false);
        return $"{(string.IsNullOrEmpty(name) ? cert.Subject : name)}, expires {cert.NotAfter:yyyy-MM-dd}.";
    }

    /// <summary>Remote address for throttling. Kestrel gives the real peer — no proxy is assumed.</summary>
    private static string ClientAddress(HttpContext ctx)
        => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    /// <summary>IsLoopback handles the IPv4-mapped form Kestrel reports for dual-stack sockets.</summary>
    private static bool IsLoopbackClient(HttpContext ctx)
        => ctx.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip);

    /// <summary>
    /// One-time code for first-visit password setup from a non-loopback client.
    /// The console binds all interfaces before any password exists, so without
    /// this, whoever reached the port first owned the box — full firewall control
    /// behind a password *they* chose. The code is printed where the console runs
    /// (terminal / unified log), which only the machine's operator can read; setup
    /// from localhost needs nothing.
    /// </summary>
    private readonly string _setupCode = GenerateSetupCode();

    private static string GenerateSetupCode()
    {
        var raw = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4));
        return $"{raw[..4]}-{raw[4..]}";
    }

    private bool SetupCodeMatches(string? supplied)
    {
        var a = Encoding.UTF8.GetBytes((supplied ?? "").Trim().Replace("-", "").ToUpperInvariant());
        var b = Encoding.UTF8.GetBytes(_setupCode.Replace("-", "").ToUpperInvariant());
        return a.Length == b.Length && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>Writes a 429 and returns true when this client is currently locked out.</summary>
    private bool IsLockedOut(HttpContext ctx, HttpResponse res)
    {
        if (!_loginThrottle.IsLocked(ClientAddress(ctx), out var retryAfter))
            return false;

        res.Headers["Retry-After"] = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
        WriteJson(res, 429, new
        {
            ok = false,
            message = $"Too many failed attempts. Try again in {LoginThrottle.Describe(retryAfter)}."
        });
        return true;
    }

    /// <summary>
    /// Sends hostname-based HTTP traffic to the HTTPS endpoint. Requests to a bare IP are left
    /// on HTTP: the certificate covers the DuckDNS name, so redirecting an IP would only produce
    /// a certificate warning.
    /// </summary>
    private bool TryRedirectToHttps(HttpContext ctx)
    {
        if (!_httpsActive || !_settings.WebHttpsRedirect || ctx.Request.IsHttps)
            return false;

        var host = ctx.Request.Host.Host;
        if (string.IsNullOrEmpty(host) || IPAddress.TryParse(host, out _))
            return false;

        var target = $"https://{host}:{_httpsPort}{ctx.Request.Path}{ctx.Request.QueryString}";
        ctx.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
        ctx.Response.Headers.Location = target;
        return true;
    }

    /// <summary>
    /// Sleep / wake for the whole console. Stopping the monitor also stops every watcher it
    /// owns (auth log, probe log, ARP, startup items, exfiltration, honeypot), so asleep really
    /// means "nothing is being observed" rather than "the dashboard stopped updating".
    /// Firewall rules are deliberately left in force — sleeping stops watching, it does not
    /// unblock addresses the machine is already protected from.
    /// </summary>
    private ActionResultDto SetMonitoring(bool on)
    {
        if (on == _monitor.Stats.IsMonitoring)
        {
            _statusMessage = on
                ? "Already awake — monitoring is running."
                : "Already asleep — monitoring is stopped.";
            return ActionResultDto.Success(_statusMessage);
        }

        if (on)
        {
            _monitor.Start();
            _statusMessage = "Awake — monitoring resumed.";
        }
        else
        {
            _monitor.Stop();
            _monitor.Stats.StatusText = "Asleep — monitoring stopped";
            _statusMessage = "Asleep — monitoring stopped. Firewall blocks stay in force.";
        }

        return ActionResultDto.Success(_statusMessage);
    }

    private ActionResultDto RunAction(ActionRequest req)
    {
        try
        {
            switch (req.Action.Trim().ToLowerInvariant())
            {
                case "pause":
                case "sleep":
                    return SetMonitoring(false);

                case "resume":
                case "wake":
                    return SetMonitoring(true);

                case "toggle_monitor":
                case "toggle_sleep":
                    return SetMonitoring(!_monitor.Stats.IsMonitoring);

                case "toggle_autoblock":
                    _autoBlockEnabled = !_autoBlockEnabled;
                    _prevention.Enabled = _autoBlockEnabled;
                    _settings.AutoBlockEnabled = _autoBlockEnabled;
                    _settings.Save();
                    _statusMessage = _autoBlockEnabled
                        ? $"Auto-block ON (≥ {_autoBlockMinLevel})" +
                          (_firewall.IsAdministrator ? "" : " — need admin rights for firewall changes")
                        : "Auto-block OFF";
                    return ActionResultDto.Success(_statusMessage);

                case "cycle_min_level":
                    _autoBlockMinLevel = _autoBlockMinLevel switch
                    {
                        nameof(ThreatLevel.Medium) => nameof(ThreatLevel.High),
                        nameof(ThreatLevel.High) => nameof(ThreatLevel.Critical),
                        _ => nameof(ThreatLevel.Medium)
                    };
                    _prevention.MinLevel = ParseLevel(_autoBlockMinLevel);
                    _settings.AutoBlockMinLevel = _autoBlockMinLevel;
                    _settings.Save();
                    _statusMessage = $"Auto-block minimum severity: {_autoBlockMinLevel}";
                    return ActionResultDto.Success(_statusMessage);

                case "set_min_level":
                {
                    var level = (req.Value ?? "").Trim();
                    if (level is not (nameof(ThreatLevel.Medium) or nameof(ThreatLevel.High) or nameof(ThreatLevel.Critical)))
                        return ActionResultDto.Fail("Level must be Medium, High, or Critical.");
                    _autoBlockMinLevel = level;
                    _prevention.MinLevel = ParseLevel(level);
                    _settings.AutoBlockMinLevel = level;
                    _settings.Save();
                    _statusMessage = $"Auto-block minimum severity: {_autoBlockMinLevel}";
                    return ActionResultDto.Success(_statusMessage);
                }

                case "clear_threats":
                    _monitor.ClearThreats();
                    _statusMessage = "Threat alerts cleared.";
                    return ActionResultDto.Success(_statusMessage);

                case "set_setting":
                {
                    var key = (req.Name ?? "").Trim();
                    var raw = (req.Value ?? "").Trim();
                    var on = raw.Equals("true", StringComparison.OrdinalIgnoreCase) || raw == "1";
                    string label;
                    switch (key)
                    {
                        case "autoBlockEnabled":
                            _autoBlockEnabled = on;
                            _prevention.Enabled = on;
                            _settings.AutoBlockEnabled = on;
                            label = on ? $"Auto-block ON (≥ {_autoBlockMinLevel})" : "Auto-block OFF";
                            break;
                        case "flowEventsEnabled":
                            _monitor.FlowEventsEnabled = on;
                            _settings.FlowEventsEnabled = on;
                            label = on ? $"PF flow events: on ({_monitor.FlowEventsStatus})" : "PF flow events: off";
                            break;
                        case "dnsHygieneEnabled":
                            _settings.DnsHygieneEnabled = on;
                            _monitor.DnsHygieneEnabled = on;
                            // DNS hygiene has no input without the flow source, so turning
                            // it on turns that on too rather than looking silently broken.
                            if (on && !_settings.FlowEventsEnabled)
                            {
                                _settings.FlowEventsEnabled = true;
                                _monitor.FlowEventsEnabled = true;
                            }
                            label = on ? $"DNS hygiene: on ({_monitor.DnsHygieneStatus})" : "DNS hygiene: off";
                            break;
                        case "wireGuardMonitorEnabled":
                            _monitor.WireGuardMonitorEnabled = on;
                            _settings.WireGuardMonitorEnabled = on;
                            label = on ? $"WireGuard peer monitoring: on ({_monitor.WireGuardStatus})" : "WireGuard peer monitoring: off";
                            break;
                        case "suricataEnabled":
                            _monitor.SuricataEnabled = on;
                            _settings.SuricataEnabled = on;
                            label = on ? $"Suricata ingestion: on ({_monitor.SuricataStatus})" : "Suricata ingestion: off";
                            break;
                        case "preventionDryRun":
                            _prevention.DryRun = on;
                            _settings.PreventionDryRun = on;
                            label = on
                                ? "Dry run on — auto-block reports what it would drop, without writing rules"
                                : "Dry run off — auto-block writes PF rules";
                            break;
                        case "blockInbound":
                            _blockInbound = on;
                            _prevention.BlockInbound = on;
                            _settings.AutoBlockInbound = on;
                            label = $"Block inbound: {(on ? "on" : "off")}";
                            break;
                        case "blockOutbound":
                            _blockOutbound = on;
                            _prevention.BlockOutbound = on;
                            _settings.AutoBlockOutbound = on;
                            label = $"Block outbound: {(on ? "on" : "off")}";
                            break;
                        case "geoLookupEnabled":
                            _monitor.GeoLookupsEnabled = on;
                            _settings.GeoLookupEnabled = on;
                            label = $"Geo lookups: {(on ? "on" : "off")}";
                            break;
                        case "authLogMonitorEnabled":
                            _monitor.AuthMonitoringEnabled = on;
                            _settings.AuthLogMonitorEnabled = on;
                            label = on ? $"Auth-log monitoring: on ({_monitor.AuthLogStatus})" : "Auth-log monitoring: off";
                            break;
                        case "probeLogEnabled":
                        {
                            _settings.ProbeLogEnabled = on;
                            var fw = on ? _firewall.EnableProbeLogging() : _firewall.DisableProbeLogging();
                            _monitor.ProbeMonitoringEnabled = on && fw.Success;
                            label = on
                                ? (fw.Success
                                    ? "Closed-port scan detection: on (probe-log firewall rule installed)"
                                    : $"Closed-port scan detection: could not install firewall rule — {fw.Message}")
                            : "Closed-port scan detection: off";
                            break;
                        }
                        case "allowlistUseRemoteFeed":
                            _allowlist.UseRemoteFeed = on;
                            _settings.AllowlistUseRemoteFeed = on;
                            label = $"Allowlist remote feed: {(on ? "on" : "off")}";
                            break;
                        case "trafficMeterEnabled":
                            _settings.TrafficMeterEnabled = on;
                            // Takes effect now rather than at the next restart: the
                            // counters are cumulative, so a meter that stops and starts
                            // still reports the traffic in between as one catch-up delta.
                            if (on) _traffic.Start(); else _traffic.Stop();
                            label = $"Traffic metering: {(on ? "on" : "off")}";
                            break;
                        case "criticalAlertsEnabled":
                            _settings.CriticalAlertsEnabled = on;
                            label = $"Critical threat alerts: {(on ? "on" : "off")}";
                            break;
                        case "threatIntelEnabled":
                            _monitor.ThreatIntelEnabled = on;
                            _settings.ThreatIntelEnabled = on;
                            label = on ? $"Threat-intel feeds: on ({_monitor.ThreatIntelStatus})" : "Threat-intel feeds: off";
                            break;
                        case "processReputationEnabled":
                            _monitor.ProcessReputationEnabled = on;
                            _settings.ProcessReputationEnabled = on;
                            label = $"Process reputation checks: {(on ? "on" : "off")}";
                            break;
                        case "newListenerAlertsEnabled":
                            _monitor.NewListenerAlertsEnabled = on;
                            _settings.NewListenerAlertsEnabled = on;
                            label = $"New-listener alerts: {(on ? "on" : "off")}";
                            break;
                        case "arpWatchEnabled":
                            _monitor.ArpWatchEnabled = on;
                            _settings.ArpWatchEnabled = on;
                            label = on ? $"ARP / gateway watch: on ({_monitor.ArpWatchStatus})" : "ARP / gateway watch: off";
                            break;
                        case "launchItemWatchEnabled":
                            _monitor.LaunchWatchEnabled = on;
                            _settings.LaunchItemWatchEnabled = on;
                            label = on ? $"Launch-item watch: on ({_monitor.LaunchWatchStatus})" : "Launch-item watch: off";
                            break;
                        case "exfilMonitorEnabled":
                            _monitor.ExfilMonitorEnabled = on;
                            _settings.ExfilMonitorEnabled = on;
                            label = on ? $"Exfiltration monitor: on ({_monitor.ExfilStatus})" : "Exfiltration monitor: off";
                            break;
                        case "exfilMbPer10Min":
                            if (!int.TryParse(raw, out var mb) || mb < 10)
                                return ActionResultDto.Fail("Exfiltration threshold must be a number ≥ 10 (MB per 10 minutes).");
                            _monitor.ExfilThresholdMb = mb;
                            _settings.ExfilMbPer10Min = mb;
                            label = $"Exfiltration alert threshold: {mb} MB / 10 min";
                            break;
                        case "honeypotEnabled":
                            _monitor.HoneypotPorts = HoneypotService.ParsePorts(_settings.HoneypotPorts);
                            _monitor.HoneypotEnabled = on;
                            _settings.HoneypotEnabled = on;
                            label = on ? _monitor.HoneypotStatus : "Honeypot: off";
                            break;
                        case "suricataEvePath":
                        {
                            var path = string.IsNullOrWhiteSpace(raw) ? SuricataService.DefaultEvePath : raw;
                            _settings.SuricataEvePath = path;
                            _monitor.SuricataEvePath = path;
                            label = _settings.SuricataEnabled
                                ? _monitor.SuricataStatus
                                : $"Suricata EVE path saved ({path}) — enable ingestion to read it.";
                            break;
                        }
                        case "dnsApprovedResolvers":
                        {
                            _settings.DnsApprovedResolvers = raw;
                            _monitor.DnsApprovedResolvers = raw;
                            label = string.IsNullOrWhiteSpace(raw)
                                ? "Approved resolver list cleared — DoH endpoints can no longer be recognised."
                                : $"Approved resolvers: {raw}";
                            break;
                        }
                        case "wireGuardPeerMbPer10Min":
                        {
                            if (!int.TryParse(raw, out var wgMb) || wgMb < 0)
                                return ActionResultDto.Fail("Per-peer transfer threshold must be 0 or more megabytes (0 = off).");
                            _settings.WireGuardPeerMbPer10Min = wgMb;
                            _monitor.WireGuardPeerMbPer10Min = wgMb;
                            label = wgMb == 0
                                ? "Per-peer transfer alerts off."
                                : $"Per-peer transfer threshold: {wgMb} MB / 10 min";
                            break;
                        }
                        case "suricataMaxSeverity":
                        {
                            if (!int.TryParse(raw, out var sev) || sev is < 1 or > 4)
                                return ActionResultDto.Fail("Suricata severity must be 1-4 (Suricata counts down, so 1 is most severe).");
                            _settings.SuricataMaxSeverity = sev;
                            _monitor.SuricataMaxSeverity = sev;
                            label = $"Suricata max severity: {sev}";
                            break;
                        }
                        case "suricataIgnoredSids":
                        {
                            _settings.SuricataIgnoredSids = raw;
                            _monitor.SuricataIgnoredSids = raw;
                            label = string.IsNullOrWhiteSpace(raw)
                                ? "Suricata SID mute list cleared."
                                : $"Suricata SIDs ignored: {string.Join(",", SuricataService.ParseSids(raw))}";
                            break;
                        }
                        case "honeypotPorts":
                        {
                            var ports = HoneypotService.ParsePorts(raw);
                            if (ports.Count == 0)
                                return ActionResultDto.Fail("Enter decoy ports as a comma-separated list, e.g. 2323,3389,5900.");
                            if (ports.Contains(_port))
                                return ActionResultDto.Fail($"Port {_port} serves this web console — pick different decoy ports.");
                            _settings.HoneypotPorts = string.Join(",", ports);
                            _monitor.HoneypotPorts = ports;
                            label = _settings.HoneypotEnabled
                                ? _monitor.HoneypotStatus
                                : $"Decoy ports saved ({_settings.HoneypotPorts}) — enable the honeypot to arm them.";
                            break;
                        }
                        case "webhookUrl":
                            _monitor.WebhookUrl = raw;
                            _settings.WebhookUrl = raw;
                            label = string.IsNullOrEmpty(raw)
                                ? "Webhook alerts: off"
                                : $"Webhook alerts: Critical threats will POST to {raw}";
                            break;
                        case "autoBlockExpiryMinutes":
                            if (!int.TryParse(raw, out var minutes) || minutes < 0)
                                return ActionResultDto.Fail("Expiry must be a number of minutes (0 = never).");
                            _settings.AutoBlockExpiryMinutes = minutes;
                            _firewall.AutoBlockExpiry = minutes > 0 ? TimeSpan.FromMinutes(minutes) : null;
                            label = minutes == 0
                                ? "Auto-block rules are permanent until removed."
                                : $"New auto-block rules expire after {minutes} minutes.";
                            break;
                        // --- HTTPS ---
                        // Kestrel binds its endpoints at startup, so TLS changes are saved
                        // here but only take effect when the console is restarted.
                        case "httpsEnabled":
                            if (on && string.IsNullOrWhiteSpace(_settings.WebTlsCertPath))
                                return ActionResultDto.Fail(
                                    "Set the certificate path first — see scripts/issue-duckdns-cert.sh for a Let's Encrypt certificate.");
                            _settings.WebHttpsEnabled = on;
                            label = on
                                ? $"HTTPS enabled on port {_settings.WebHttpsPort} — restart the web console to apply."
                                : "HTTPS disabled — restart the web console to apply.";
                            break;
                        case "httpsPort":
                            if (!int.TryParse(raw, out var httpsPort) || httpsPort is < 1 or > 65535)
                                return ActionResultDto.Fail("HTTPS port must be between 1 and 65535.");
                            if (httpsPort == _port)
                                return ActionResultDto.Fail($"Port {_port} already serves the HTTP console — pick a different HTTPS port.");
                            _settings.WebHttpsPort = httpsPort;
                            label = $"HTTPS port set to {httpsPort} — restart the web console to apply.";
                            break;
                        case "tlsCertPath":
                        case "tlsKeyPath":
                        {
                            if (raw.Length > 0 && !File.Exists(raw))
                                return ActionResultDto.Fail($"File not found: {raw}");
                            if (key == "tlsCertPath") _settings.WebTlsCertPath = raw;
                            else _settings.WebTlsKeyPath = raw;

                            var certPath = _settings.WebTlsCertPath;
                            if (certPath.Length == 0)
                            {
                                label = "Certificate path cleared — HTTPS cannot start without it.";
                                break;
                            }

                            // Validate now: a bad path found at restart means no console at all.
                            label = TlsCertificateProvider.TryLoad(certPath, _settings.WebTlsKeyPath,
                                _settings.WebTlsPfxPassword, out var probe, out var probeError)
                                ? $"Certificate OK — {DescribeProbe(probe)} Restart the web console to apply."
                                : $"Saved, but the certificate cannot be loaded yet: {probeError}";
                            probe?.Dispose();
                            break;
                        }
                        case "acmeEmail":
                            _settings.AcmeAccountEmail = raw;
                            label = raw.Length == 0
                                ? "Let's Encrypt account email cleared."
                                : $"Let's Encrypt account email set to {raw}.";
                            break;
                        case "httpsRedirect":
                            _settings.WebHttpsRedirect = on;
                            label = on
                                ? "Hostname requests over plain HTTP will redirect to HTTPS."
                                : "HTTP requests are served as-is (no HTTPS redirect).";
                            break;
                        case "httpsOnly":
                            if (on && !_settings.WebHttpsEnabled)
                                return ActionResultDto.Fail(
                                    "Switch HTTPS on first — turning off plain HTTP without it would leave no console at all.");
                            _settings.WebHttpsOnly = on;
                            label = on
                                ? "Plain HTTP will be off (HTTPS only) — restart the web console to apply. If the certificate fails to load at startup, HTTP stays on so you aren't locked out."
                                : "Plain HTTP will be served alongside HTTPS — restart the web console to apply.";
                            break;

                        // --- DuckDNS (stored separately in duckdns.json, mode 0600) ---
                        case "duckDnsEnabled":
                        {
                            var cfg = CloneDuckDns();
                            cfg.Enabled = on;
                            if (on && (cfg.Domain.Length == 0 || cfg.Token.Length == 0))
                                return ActionResultDto.Fail("Enter the DuckDNS subdomain and token first.");
                            label = _duckDns.Apply(cfg);
                            break;
                        }
                        case "duckDnsDomain":
                        {
                            var cfg = CloneDuckDns();
                            cfg.Domain = DuckDnsUpdater.NormalizeDomain(raw);
                            if (raw.Length > 0 && cfg.Domain.Length == 0)
                                return ActionResultDto.Fail("Enter the subdomain label, e.g. myhost (or myhost.duckdns.org).");
                            _duckDns.Apply(cfg);
                            label = cfg.Domain.Length == 0
                                ? "DuckDNS subdomain cleared."
                                : $"DuckDNS subdomain set to {cfg.Domain}.duckdns.org — {_duckDns.Status}";
                            break;
                        }
                        case "duckDnsToken":
                        {
                            // The page renders a bullet placeholder for a stored token so the user
                            // can empty the field to clear it; echoing it back unchanged is a no-op.
                            if (raw == TokenPlaceholder)
                                return ActionResultDto.Success(_duckDns.Status);
                            var cfg = CloneDuckDns();
                            cfg.Token = raw;
                            _duckDns.Apply(cfg);
                            label = raw.Length == 0
                                ? "DuckDNS token cleared."
                                : $"DuckDNS token saved — {_duckDns.Status}";
                            break;
                        }

                        default:
                            return ActionResultDto.Fail($"Unknown setting: {key}");
                    }
                    _settings.Save();
                    _statusMessage = label;
                    return ActionResultDto.Success(label);
                }

                case "issue_cert":
                    return StartCertIssuance();

                case "block_port":
                {
                    if (!int.TryParse((req.Value ?? "").Trim(), out var port) || port is < 1 or > 65535)
                        return ActionResultDto.Fail("Enter a valid port number (1–65535).");
                    if (port == _port)
                        return ActionResultDto.Fail(
                            $"Port {port} serves this web console — blocking it would cut off this page. Choose another port.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot block — run the web service as root, or allow the Mac password prompt.");

                    var proto = (req.Kind ?? "TCP").Trim().ToUpperInvariant();
                    var dir = (req.Direction ?? "Inbound").Trim() switch
                    {
                        "Outbound" => FirewallDirection.Outbound,
                        "Both" => FirewallDirection.Both,
                        _ => FirewallDirection.Inbound
                    };
                    var r = _firewall.BlockPort(port, proto, dir, $"Web UI port block · {proto}/{port}");
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "unblock_port":
                {
                    if (!int.TryParse((req.Value ?? "").Trim(), out var port) || port is < 1 or > 65535)
                        return ActionResultDto.Fail("Enter a valid port number (1–65535).");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot unblock — run the web service as root, or allow the Mac password prompt.");
                    var r = _firewall.UnblockPort(port, (req.Kind ?? "TCP").Trim());
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "remove_all_rules":
                {
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot remove rules — run the web service as root, or allow the Mac password prompt.");

                    // Suppress auto-block for every removed IP so nothing "comes back".
                    var blockedBefore = _firewall.GetBlockedIps();
                    var r = _firewall.RemoveAllManagedRules(rule => IsOwnWebRule(rule.Name));
                    if (r.Success)
                    {
                        foreach (var ip in blockedBefore)
                            _prevention.NoteUnblocked(ip);
                        RefreshBlockedIps(force: true);
                    }
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "authorize":
                {
                    var r = _firewall.AuthorizeElevation();
                    if (r.Success)
                    {
                        // Lifts the auto-block stand-down, which was otherwise cleared
                        // only by time — so authorizing successfully changed nothing for
                        // five minutes while the console kept reporting it as paused.
                        _prevention.NoteElevationAuthorized();
                        if (_settings.ProbeLogEnabled)
                            _firewall.EnableProbeLogging();
                    }
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "block":
                {
                    var ip = (req.Ip ?? req.Value ?? "").Trim();
                    if (string.IsNullOrEmpty(ip))
                        return ActionResultDto.Fail("IP required.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot block — need root or admin rights (use authorize first).");
                    var r = _firewall.BlockIp(ip, ResolveDirection(), $"Web UI block · {ip}");
                    if (r.Success)
                    {
                        var key = FirewallService.TryNormalizeIp(ip, out var normalized, out _) ? normalized : ip;
                        // Blocking by hand is an explicit reversal of an earlier release.
                        _prevention.ClearSuppression(key);
                        _prevention.NoteBlocked(key);
                        RefreshBlockedIps(force: true);
                    }
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "unblock":
                {
                    var ip = (req.Ip ?? req.Value ?? "").Trim();
                    if (string.IsNullOrEmpty(ip))
                        return ActionResultDto.Fail("IP required.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot unblock — need root or admin rights (use authorize first).");
                    var r = _firewall.UnblockIp(ip);
                    if (r.Success)
                    {
                        if (FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                            _prevention.NoteUnblocked(normalized);
                        RefreshBlockedIps(force: true);
                    }
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "add_allowlist":
                {
                    var value = (req.Value ?? "").Trim();
                    if (string.IsNullOrEmpty(value))
                        return ActionResultDto.Fail("Domain or IP required.");
                    bool ok;
                    string message;
                    if (value.Contains('.') && !IPAddress.TryParse(value, out _) &&
                        value.Any(c => char.IsLetter(c)))
                        ok = _allowlist.TryAddDomain(value, out message);
                    else if (IPAddress.TryParse(value, out _))
                        ok = _allowlist.TryAddIp(value, out message);
                    else
                        ok = _allowlist.TryAddDomain(value, out message);
                    _statusMessage = message;
                    return ok ? ActionResultDto.Success(message) : ActionResultDto.Fail(message);
                }

                case "remove_allowlist":
                {
                    var value = (req.Value ?? "").Trim();
                    var kind = (req.Kind ?? "").Trim();
                    if (string.IsNullOrEmpty(value))
                        return ActionResultDto.Fail("Value required.");
                    if (string.IsNullOrEmpty(kind))
                        kind = IPAddress.TryParse(value, out _) ? "IP" : "Domain";
                    var ok = _allowlist.TryRemove(value, kind, out var message);
                    _statusMessage = message;
                    return ok ? ActionResultDto.Success(message) : ActionResultDto.Fail(message);
                }

                case "refresh_allowlist":
                {
                    try
                    {
                        _allowlist.RefreshAsync().GetAwaiter().GetResult();
                        _statusMessage = _allowlist.StatusText;
                        return ActionResultDto.Success(_statusMessage);
                    }
                    catch (Exception ex)
                    {
                        _statusMessage = $"Allowlist refresh failed: {ex.Message}";
                        return ActionResultDto.Fail(_statusMessage);
                    }
                }

                case "restore_allowlisted":
                {
                    var r = _firewall.UnblockAllowlistedAddresses();
                    _statusMessage = r.Message;
                    if (r.Success) RefreshBlockedIps(force: true);
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "save_config_rule":
                {
                    // Validate before normalising — see FirewallRuleSpecs.TryPrepare.
                    // A port range the parser rejects would otherwise be dropped, and
                    // an empty port field means every port, so a typo would arrive
                    // here as a catch-all block.
                    var typed = new FirewallRuleSpec
                    {
                        Label = req.Label ?? "",
                        Action = req.RuleAction ?? FirewallRuleSpecs.ActionBlock,
                        Direction = req.Direction ?? FirewallRuleSpecs.DirectionInbound,
                        Protocol = req.Protocol ?? "TCP",
                        PortRange = req.Ports ?? "",
                        Addresses = req.Addresses ?? ""
                    };

                    if (!FirewallRuleSpecs.TryPrepare(typed, out var spec, out var invalid))
                        return ActionResultDto.Fail(invalid);

                    // The GUI asks the operator to confirm a rule that takes the
                    // machine off the network. Over the web there is no one to ask —
                    // the request that applies the rule is carried by the very
                    // connection the rule would cut, so the answer would never arrive.
                    // Refusing outright matches how block_port already treats this port.
                    var guard = ConsoleSelfBlockReason(spec);
                    if (guard != null)
                        return ActionResultDto.Fail(guard);

                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot write rules — run the web service as root, or where sudo works without a password.");

                    var replace = string.IsNullOrWhiteSpace(req.Replace)
                        ? null
                        : System.Net.WebUtility.HtmlDecode(req.Replace.Trim());

                    // Editing a rule the host owns rather than one of ours: remove the
                    // original where it lives first. PF has no in-place edit, and
                    // writing the replacement on top would leave both in force.
                    if (!string.IsNullOrWhiteSpace(req.Key))
                    {
                        var original = FindScannedRule(req.Key!.Trim(), out var lookupProblem);
                        if (original == null) return ActionResultDto.Fail(lookupProblem);
                        if (IsOwnWebRule(original.Name))
                            return ActionResultDto.Fail(SelfRuleRefusal(original.Name));

                        var dropped = _firewall.DeleteHostRule(original);
                        if (!dropped.Success)
                        {
                            _statusMessage = $"The original rule could not be removed, so it was not replaced: {dropped.Message}";
                            return ActionResultDto.Fail(_statusMessage);
                        }
                        InvalidateHostScan();
                    }

                    var saved = _firewall.SaveCustomRule(spec, replace);
                    _statusMessage = saved.Message;
                    if (saved.Success) InvalidateHostScan();
                    return saved.Success
                        ? ActionResultDto.Success(saved.Message)
                        : ActionResultDto.Fail(saved.Message);
                }

                case "rescan_firewall":
                {
                    var scan = HostScan(force: true);
                    _statusMessage = $"{scan.HostLabel}: {scan.Backend} · {scan.Status} · {scan.RulesSummary}.";
                    return ActionResultDto.Success(_statusMessage);
                }

                case "delete_host_rule":
                {
                    var key = (req.Key ?? "").Trim();
                    if (key.Length == 0) return ActionResultDto.Fail("Rule identity required.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot remove rules — run the web service as root, or where sudo works without a password.");

                    var target = FindScannedRule(key, out var problem);
                    if (target == null) return ActionResultDto.Fail(problem);
                    if (IsOwnWebRule(target.Name))
                        return ActionResultDto.Fail(SelfRuleRefusal(target.Name));

                    FirewallOperationResult dropped;
                    try { dropped = _firewall.DeleteHostRule(target); }
                    catch (Exception ex)
                    {
                        _statusMessage = $"Remove failed: {ex.Message}";
                        return ActionResultDto.Fail(_statusMessage);
                    }

                    _statusMessage = dropped.Message;
                    if (dropped.Success)
                    {
                        InvalidateHostScan();
                        if (FirewallService.TryExtractIpFromManagedRule(target.Name, target.RemoteAddresses, out var freedIp))
                            _prevention.NoteUnblocked(freedIp);
                        try { RefreshBlockedIps(force: true); } catch { /* ignore */ }
                    }
                    return dropped.Success
                        ? ActionResultDto.Success(dropped.Message)
                        : ActionResultDto.Fail(dropped.Message);
                }

                case "remove_rule":
                {
                    // Decode HTML entities if the browser sent an attribute-escaped name.
                    var name = System.Net.WebUtility.HtmlDecode((req.Value ?? req.Name ?? "").Trim());
                    if (string.IsNullOrEmpty(name))
                        return ActionResultDto.Fail("Rule name required.");
                    if (IsOwnWebRule(name))
                        return ActionResultDto.Fail(SelfRuleRefusal(name));
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot remove rules — run the web service as root, or allow the Mac password prompt.");

                    FirewallOperationResult r;
                    try
                    {
                        r = _firewall.RemoveRule(name);
                    }
                    catch (Exception ex)
                    {
                        _statusMessage = $"Remove failed: {ex.Message}";
                        return ActionResultDto.Fail(_statusMessage);
                    }

                    _statusMessage = r.Message;
                    if (r.Success)
                    {
                        // Keep auto-block from immediately recreating the same IP block.
                        if (FirewallService.TryExtractIpFromManagedRule(name, null, out var removedIp))
                            _prevention.NoteUnblocked(removedIp);

                        InvalidateHostScan();
                        try { RefreshBlockedIps(force: true); }
                        catch { /* ignore */ }
                    }
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                default:
                    return ActionResultDto.Fail($"Unknown action: {req.Action}");
            }
        }
        catch (Exception ex)
        {
            _statusMessage = $"Action failed: {ex.Message}";
            return ActionResultDto.Fail(_statusMessage);
        }
    }

    private object BuildState()
    {
        RefreshBlockedIps(force: false);
        var blocked = _prevention.BlockedIps;
        var stats = _monitor.Stats;
        var hostScan = HostScan();

        return new
        {
            ok = true,
            version = _appVersion,
            clock = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss"),
            statusMessage = _statusMessage,
            // Hero subtitle on both front-ends counts the same thing.
            blockedCount = blocked.Count,
            firewall = new
            {
                isAdmin = _firewall.IsAdministrator,
                isRoot = _firewall.IsRoot,
                privilegeText = _firewall.PrivilegeText
            },
            settings = new
            {
                autoBlockEnabled = _autoBlockEnabled,
                autoBlockMinLevel = _autoBlockMinLevel,
                // The engine's own wording for the status block — the only form that
                // distinguishes armed from dry run.
                autoBlockSummary = _prevention.Describe(),
                preventionDryRun = _prevention.DryRun,
                blockInbound = _blockInbound,
                blockOutbound = _blockOutbound,
                geoLookupEnabled = _settings.GeoLookupEnabled,
                authLogMonitorEnabled = _settings.AuthLogMonitorEnabled,
                authLogStatus = _monitor.AuthLogStatus,
                probeLogEnabled = _settings.ProbeLogEnabled,
                probeLogStatus = _monitor.ProbeLogStatus,
                allowlistUseRemoteFeed = _settings.AllowlistUseRemoteFeed,
                trafficMeterEnabled = _settings.TrafficMeterEnabled,
                trafficStatus = _traffic.Status,
                criticalAlertsEnabled = _settings.CriticalAlertsEnabled,
                threatIntelEnabled = _settings.ThreatIntelEnabled,
                threatIntelStatus = _monitor.ThreatIntelStatus,
                processReputationEnabled = _settings.ProcessReputationEnabled,
                newListenerAlertsEnabled = _settings.NewListenerAlertsEnabled,
                arpWatchEnabled = _settings.ArpWatchEnabled,
                arpWatchStatus = _monitor.ArpWatchStatus,
                launchItemWatchEnabled = _settings.LaunchItemWatchEnabled,
                launchWatchStatus = _monitor.LaunchWatchStatus,
                exfilMonitorEnabled = _settings.ExfilMonitorEnabled,
                exfilMbPer10Min = _settings.ExfilMbPer10Min,
                exfilStatus = _monitor.ExfilStatus,
                honeypotEnabled = _settings.HoneypotEnabled,
                honeypotPorts = _settings.HoneypotPorts,
                honeypotStatus = _monitor.HoneypotStatus,
                suricataEnabled = _settings.SuricataEnabled,
                suricataEvePath = _settings.SuricataEvePath,
                suricataMaxSeverity = _settings.SuricataMaxSeverity,
                suricataIgnoredSids = _settings.SuricataIgnoredSids,
                suricataStatus = _monitor.SuricataStatus,
                wireGuardMonitorEnabled = _settings.WireGuardMonitorEnabled,
                wireGuardPeerMbPer10Min = _settings.WireGuardPeerMbPer10Min,
                wireGuardStatus = _monitor.WireGuardStatus,
                flowEventsEnabled = _settings.FlowEventsEnabled,
                flowEventsStatus = _monitor.FlowEventsStatus,
                dnsHygieneEnabled = _settings.DnsHygieneEnabled,
                dnsApprovedResolvers = _settings.DnsApprovedResolvers,
                dnsHygieneStatus = _monitor.DnsHygieneStatus,
                webhookUrl = _settings.WebhookUrl,
                webhookStatus = _monitor.WebhookStatus,
                autoBlockExpiryMinutes = _settings.AutoBlockExpiryMinutes,
                httpsEnabled = _settings.WebHttpsEnabled,
                httpsActive = _httpsActive,
                httpsPort = _settings.WebHttpsPort,
                httpsRedirect = _settings.WebHttpsRedirect,
                httpsOnly = _settings.WebHttpsOnly,
                httpsStatus = HttpsStatusText(),
                tlsCertPath = _settings.WebTlsCertPath,
                tlsKeyPath = _settings.WebTlsKeyPath,
                acmeEmail = _settings.AcmeAccountEmail,
                certIssueBusy = Volatile.Read(ref _certIssueBusy) == 1,
                certIssueMessage = _certIssueMessage,
                certIssueOk = _certIssueOk,
                duckDnsEnabled = _duckDns.Config.Enabled,
                duckDnsDomain = _duckDns.Config.Domain,
                // The token itself is never sent to the browser — only whether one is stored.
                duckDnsTokenSet = _duckDns.Config.Token.Length > 0,
                duckDnsStatus = _duckDns.Status,
                isMonitoring = stats.IsMonitoring
            },
            stats = new
            {
                listeningPorts = stats.ListeningPorts,
                activeConnections = stats.ActiveConnections,
                remoteHosts = stats.RemoteHosts,
                threatsToday = stats.ThreatsToday,
                highThreats = stats.HighThreats,
                statusText = stats.StatusText,
                isMonitoring = stats.IsMonitoring
            },
            allowlistStatus = _allowlist.StatusText,
            connections = _monitor.Connections.Take(250).Select(c => new
            {
                protocol = c.Protocol,
                local = c.DisplayLocal,
                remote = c.DisplayRemote,
                remoteAddress = c.RemoteAddress,
                remotePort = c.RemotePort,
                state = c.StateText,
                process = c.ProcessName,
                pid = c.ProcessId,
                geo = c.GeoSummary,
                lastSeen = c.LastSeen.ToString("HH:mm:ss")
            }),
            hosts = _monitor.RemoteHosts.Take(250).Select(h => new
            {
                ip = h.IpAddress,
                name = h.DisplayName,
                hostName = h.HostName,
                geo = h.GeoSummary,
                active = h.ActiveConnections,
                total = h.TotalConnections,
                ports = h.PortsTouched,
                threat = h.ThreatText,
                threatLevel = (int)h.ThreatLevel,
                status = h.Status,
                blocked = blocked.Contains(h.IpAddress) || h.IsBlocked,
                lastSeen = h.LastSeenText
            }),
            threats = _monitor.Threats.Take(200).Select(t => new
            {
                ts = t.Timestamp.ToString("o"),
                time = t.TimeText,
                level = t.LevelText,
                levelNum = (int)t.Level,
                type = t.TypeText,
                sourceIp = t.SourceIp,
                title = t.Title,
                detail = t.Detail,
                origin = t.Origin,
                method = t.Method
            }),
            ports = _monitor.ListeningPorts.Select(p => new
            {
                protocol = p.Protocol,
                endpoint = p.DisplayEndpoint,
                port = p.Port,
                process = p.ProcessName,
                pid = p.ProcessId,
                hint = p.ServiceHint
            }),
            firewallRules = _firewall.GetManagedRules().Select(r => new
            {
                name = r.Name,
                isProtected = IsOwnWebRule(r.Name),
                kind = r.KindText,
                // Explicit address field so the UI always has an IP column even if target is a port.
                address = string.IsNullOrWhiteSpace(r.AddressText) ? r.TargetText : r.AddressText,
                target = r.TargetText,
                ports = r.LocalPorts,
                direction = r.DirectionText,
                protocol = r.Protocol,
                enabled = r.Enabled,
                action = r.ActionText,
                description = r.Description
            }),
            allowlist = _allowlist.GetEntries().Select(e => new
            {
                kind = e.Kind,
                value = e.Value,
                detail = e.Detail
            }),
            activity = _monitor.Activity.Select(a => new
            {
                time = a.Time.ToString("HH:mm:ss"),
                connections = a.ConnectionCount,
                threats = a.ThreatCount,
                hosts = a.RemoteHostCount
            }),
            traffic = TrafficSnapshot(),
            // The whole host firewall as the machine holds it — the pf ruleset, the
            // Application Firewall's entries, this app's own rules and everyone
            // else's — in evaluation order, so precedence is
            // visible rather than implied. Cached; the tab's Refresh forces a rescan.
            configRules = hostScan.Inbound.Concat(hostScan.Outbound).Select(r => new
            {
                name = r.Name,
                key = ScannedRuleKey(r),
                label = r.LabelText,
                isProtected = IsOwnWebRule(r.Name),
                isCustom = r.IsCustom,
                isForeign = r.IsForeign && r.Kind == FirewallRuleKind.Other,
                inbound = r.IsInbound,
                action = r.ActionText,
                direction = r.DirectionText,
                protocol = r.ProtocolText,
                ports = r.PortRangeText,
                addresses = r.AddressListText,
                origin = r.OriginText,
                expiry = r.ExpiryText
            }),
            hostFirewall = new
            {
                host = hostScan.HostLabel,
                backend = hostScan.Backend,
                status = hostScan.Status,
                enabled = hostScan.Enabled,
                defaultInbound = hostScan.DefaultInbound,
                defaultOutbound = hostScan.DefaultOutbound,
                description = hostScan.Description,
                privilegeNote = hostScan.PrivilegeNote,
                rulesSummary = hostScan.RulesSummary,
                backendsSeen = hostScan.BackendsSeen,
                errors = hostScan.Errors,
                scannedAt = hostScan.ScannedUtc.ToLocalTime().ToString("HH:mm:ss")
            },
            listeners = hostScan.Listeners.Select(l => new
            {
                protocol = l.Protocol,
                address = l.Address,
                port = l.Port,
                service = l.ServiceName,
                process = l.Process,
                covered = l.Covered
            })
        };
    }

    /// <summary>
    /// Everything the data-flow card draws: the live rate series, the legends and
    /// the month/12-month bars. Sent whole rather than as a delta — the series is
    /// capped at 120 samples, so it costs less than the connection table.
    /// </summary>
    private object TrafficSnapshot()
    {
        var live = _traffic.Live;
        var month = _traffic.MonthTotal(DateTime.Today);
        var last = live.Count > 0 ? live[^1] : null;

        var window = "measuring…";
        if (live.Count >= 2)
        {
            var span = live[^1].Time - live[0].Time;
            window = span.TotalMinutes >= 1
                ? $"last {Math.Round(span.TotalMinutes)} min"
                : $"last {Math.Max(1, (int)span.TotalSeconds)} s";
        }
        else if (!_settings.TrafficMeterEnabled)
        {
            window = "meter off";
        }

        return new
        {
            enabled = _settings.TrafficMeterEnabled,
            status = _traffic.Status,
            window,
            inRate = last != null ? ByteSize.FormatRate(last.BytesInPerSecond) : "—",
            outRate = last != null ? ByteSize.FormatRate(last.BytesOutPerSecond) : "—",
            monthLabel = month.Label,
            monthIn = month.InText,
            monthOut = month.OutText,
            monthTotal = month.TotalText,
            monthDailyAverage = DateTime.Today.Day > 0
                ? $"{ByteSize.Format(month.BytesTotal / (double)DateTime.Today.Day)} per day so far"
                : "",
            live = live.Select(s => new { inBps = s.BytesInPerSecond, outBps = s.BytesOutPerSecond }),
            days = _traffic.DailyBuckets(DateTime.Today).Select(b => new
            {
                label = b.Label,
                bytesIn = b.BytesIn,
                bytesOut = b.BytesOut,
                inText = b.InText,
                outText = b.OutText
            }),
            months = _traffic.MonthlyBuckets(12).Select(b => new
            {
                label = b.Label,
                bytesIn = b.BytesIn,
                bytesOut = b.BytesOut,
                inText = b.InText,
                outText = b.OutText
            })
        };
    }

    /// <summary>
    /// The inbound allow rule for THIS console's port. Removing it over the web kills the
    /// user's own browser connection mid-request — indistinguishable from a server crash.
    /// </summary>
    private bool IsOwnWebRule(string name)
        => string.Equals(name, $"{FirewallService.RulePrefix}-Web-{_port}", StringComparison.OrdinalIgnoreCase);

    /// <summary>Why the console will not remove the rule that carries this page.</summary>
    private static string SelfRuleRefusal(string name)
        => $"\"{name}\" is the allow rule that lets your browser reach this console — " +
           "removing it from here would instantly cut off this page (it looks like a crash). " +
           "To remove web access, stop or uninstall the web service on the server.";

    /// <summary>
    /// Why a Firewall Config rule cannot be written from this console, or null when
    /// it is safe. An inbound Block that covers the console's own port takes the page
    /// down mid-request, which is indistinguishable from a crash — and unlike the GUI
    /// there is no dialog that could warn first, because the warning would travel over
    /// the connection being cut.
    ///
    /// Only rules that match <i>every</i> source are refused. A rule scoped to named
    /// addresses is allowed through: the Firewall tab's Block IP button already blocks
    /// a chosen address on every port, so refusing the same thing here would be an
    /// inconsistency rather than a safeguard — and an operator who blocks the address
    /// they are browsing from has done something they explicitly asked for.
    /// </summary>
    private string? ConsoleSelfBlockReason(FirewallRuleSpec spec)
    {
        if (!spec.Action.Equals(FirewallRuleSpecs.ActionBlock, StringComparison.OrdinalIgnoreCase))
            return null;
        if (!spec.Direction.Equals(FirewallRuleSpecs.DirectionInbound, StringComparison.OrdinalIgnoreCase))
            return null;

        // Scoped to specific sources — not a blanket self-block. See above.
        if (FirewallRuleSpecs.TryParseAddresses(spec.Addresses, out var addresses, out _) && addresses.Count > 0)
            return null;

        if (FirewallRuleSpecs.IsCatchAll(spec))
        {
            return "That rule blocks every inbound connection on every port, which includes this console — " +
                   "the page would go down as the rule loaded and look like a crash. Write it from the " +
                   "desktop GUI or the TUI on this Mac itself.";
        }

        var ports = new List<int> { _port };
        if (_httpsActive) ports.Add(_httpsPort);

        foreach (var port in ports)
        {
            if (FirewallRuleSpecs.CoversPort(spec, port))
            {
                return $"That rule blocks inbound port {port}, which serves this web console — " +
                       "applying it would cut off this page mid-request. Choose another port, or write " +
                       "the rule from the desktop GUI or the TUI on this Mac itself.";
            }
        }

        return null;
    }

    private FirewallDirection ResolveDirection()
    {
        if (_blockInbound && _blockOutbound) return FirewallDirection.Both;
        if (_blockInbound) return FirewallDirection.Inbound;
        if (_blockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Both;
    }

    private void OnMonitorUpdated() => RefreshBlockedIps(force: false);

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (!_autoBlockEnabled || threats.Count == 0)
            return;

        _ = Task.Run(() =>
        {
            try { ProcessAutoBlocks(threats); }
            catch (Exception ex) { _statusMessage = $"Auto-block error: {ex.Message}"; }
        });
    }

    /// <summary>
    /// Every gate and every rule write lives in PreventionService now. This console was
    /// the only one of the three frontends that honoured the manual-unblock suppression
    /// list; the engine gives the GUI and TUI the same behaviour instead of this one
    /// keeping its own copy of it.
    /// </summary>
    private void ProcessAutoBlocks(IReadOnlyList<ThreatEvent> threats)
    {
        var result = _prevention.Apply(threats);
        if (!result.HasMessages)
            return;

        _statusMessage = result.Summary;
        if (result.RulesChanged)
            RefreshBlockedIps(force: true);
    }

    private static ThreatLevel ParseLevel(string value)
        => Enum.TryParse<ThreatLevel>(value, true, out var level) ? level : ThreatLevel.High;

    private void RefreshBlockedIps(bool force)
        => _prevention.RefreshBlockedIps(force, set =>
        {
            foreach (var host in _monitor.RemoteHosts)
                host.IsBlocked = set.Contains(host.IpAddress);
        });

    /// <summary>
    /// Picks a free port from preferred uncommon high ports, or an OS ephemeral port.
    /// If <paramref name="requested"/> is set, that port is required (throws if taken).
    /// </summary>
    public static int ResolvePort(int? requested)
    {
        if (requested is int p)
        {
            if (p is < 1 or > 65535)
                throw new ArgumentOutOfRangeException(nameof(requested), "Port must be 1–65535.");
            if (!IsPortAvailable(p))
                throw new InvalidOperationException($"Port {p} is already in use. Choose another with -w PORT.");
            return p;
        }

        foreach (var candidate in PreferredPorts)
        {
            if (IsPortAvailable(candidate))
                return candidate;
        }

        // Last resort: let the OS assign any free port.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static bool IsPortAvailable(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// The console page with this build's version stamped into it, so the script
    /// can tell that the server it is talking to has since been upgraded. Rebuilt
    /// per request rather than cached: a page load is rare next to the state poll,
    /// and one string replace is cheaper than reasoning about when to invalidate.
    /// </summary>
    private string PageHtml() => IndexHtml.Replace("__NS_VERSION__", _appVersion);

    private static void WriteHtml(HttpResponse res, string html)
    {
        var bytes = Encoding.UTF8.GetBytes(html);
        res.StatusCode = 200;
        res.ContentType = "text/html; charset=utf-8";
        res.ContentLength = bytes.Length;
        res.Body.Write(bytes, 0, bytes.Length);
    }

    private static void WriteJson(HttpResponse res, int status, object payload)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        res.StatusCode = status;
        res.ContentType = "application/json; charset=utf-8";
        res.ContentLength = bytes.Length;
        res.Body.Write(bytes, 0, bytes.Length);
    }

    private static string FormatAppVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v == null ? "0.0.0" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _host?.StopAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult(); } catch { /* ignore */ }
        try { (_host as IDisposable)?.Dispose(); } catch { /* ignore */ }
        _duckDns.Dispose();
        _tls?.Dispose();
        _core.Dispose();
        _cts?.Dispose();
    }

    private sealed class ActionRequest
    {
        public string Action { get; set; } = "";
        public string? Ip { get; set; }
        public string? Value { get; set; }
        public string? Name { get; set; }
        public string? Kind { get; set; }
        public string? Direction { get; set; }

        // Firewall Config rule fields. Separate from Kind/Value because a rule
        // carries six of them at once and reusing the generic slots would make
        // the handler unreadable.
        public string? Label { get; set; }
        public string? RuleAction { get; set; }
        public string? Protocol { get; set; }
        public string? Ports { get; set; }
        public string? Addresses { get; set; }

        /// <summary>Name of the rule being replaced, when the form is editing rather than adding.</summary>
        public string? Replace { get; set; }

        /// <summary>
        /// Whole-shape identity of a scanned host rule (see ScannedRuleKey). Rule
        /// names repeat across a host, so a delete names the shape, not the label.
        /// </summary>
        public string? Key { get; set; }
    }

    private sealed class AuthBody
    {
        public string? Password { get; set; }
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
        public string? Confirm { get; set; }
        public string? SetupCode { get; set; }
    }

    private sealed class ActionResultDto
    {
        public bool Ok { get; init; }
        public string Message { get; init; } = "";

        public static ActionResultDto Success(string message) => new() { Ok = true, Message = message };
        public static ActionResultDto Fail(string message) => new() { Ok = false, Message = message };
    }

    private const string IndexHtml =
"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Network Sentinel</title>
<style>
  :root {
    --bg-deep: #0a0e14;
    --bg-panel: #10141c;
    --bg-card: #161b26;
    --bg-hover: #1e2534;
    --stroke: rgba(255,255,255,.10);
    --stroke-strong: rgba(74,158,255,.40);
    --text: #edf1f7;
    --text2: #8a94a6;
    --muted: #636b78;
    --cyan: #3bc8b4;
    --blue: #4a9eff;
    --amber: #f5b93b;
    --danger: #ff5d78;
    --sev-low: #59bff2;
    --sev-medium: #f2bf40;
    --sev-high: #fa7340;
    --sev-critical: #f24059;
    --success: #4dd18c;
    --font: "Segoe UI", system-ui, -apple-system, sans-serif;
    --mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    font-family: var(--font); color: var(--text);
    background:
      radial-gradient(1200px 600px at 10% -10%, rgba(61,231,200,.08), transparent 50%),
      radial-gradient(900px 500px at 90% 0%, rgba(74,158,255,.1), transparent 45%),
      var(--bg-deep);
  }
  /* Shell — a 230px navigation rail and a scrolling main column, laid out like
     the desktop window. The web console and the desktop app are the same
     product; the menus should not be a different shape in each. */
  #appShell { display: flex; align-items: flex-start; gap: 14px; padding: 18px; min-height: 100vh; }
  .sidebar {
    flex: 0 0 230px; width: 230px;
    /* Full window height, not content height: the status block belongs at the
       foot of the rail the way it does on the desktop, not floating mid-page. */
    position: sticky; top: 18px; height: calc(100vh - 36px);
    display: flex; flex-direction: column;
    background: var(--bg-card); border: 1px solid var(--stroke);
    border-radius: 18px; padding: 16px;
  }
  .shell-main { flex: 1 1 auto; min-width: 0; }

  .brand { display: flex; align-items: center; gap: 12px; margin: 4px 4px 18px; }
  .brand .mark {
    width: 42px; height: 42px; border-radius: 10px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, var(--cyan), var(--blue));
  }
  .brand .mark svg { width: 23px; height: 23px; display: block; }
  .brand h1 { margin: 0; font-size: 1rem; font-weight: 700; letter-spacing: .01em; }
  .brand .sub { color: var(--muted); font-size: .69rem; line-height: 1.55; }
  .brand .sub.tint { color: var(--cyan); }

  nav { display: flex; flex-direction: column; overflow-y: auto; min-height: 0; }
  .nav-cap { font-size: .62rem; font-weight: 700; letter-spacing: .09em; color: var(--muted); margin: 0 0 8px 8px; }
  nav button {
    appearance: none; display: block; width: 100%; text-align: left;
    background: transparent; border: 1px solid transparent; border-radius: 10px;
    color: var(--text2); font: inherit; font-size: .84rem; font-weight: 600;
    padding: 11px 14px; margin: 3px 0; cursor: pointer; transition: .15s ease;
  }
  nav button:hover { background: rgba(255,255,255,.05); color: var(--text); }
  nav button.active { background: rgba(74,158,255,.15); color: var(--text); }
  /* Submenu entry: indented under its parent and a shade quieter, so the rail
     reads as a hierarchy rather than a longer flat list. */
  nav button.sub { padding: 8px 14px 8px 30px; font-size: .79rem; font-weight: 400; margin: 0 0 3px; }

  /* Status block pinned to the foot of the rail, as on the desktop: what the
     monitor is doing, whether the firewall can be written, and the one toggle
     that decides whether detections turn into kernel rules. */
  .side-status { margin-top: auto; padding-top: 16px; }
  .side-status .box {
    background: rgba(255,255,255,.05); border: 1px solid var(--stroke);
    border-radius: 14px; padding: 12px;
  }
  .side-cap { font-size: .62rem; font-weight: 700; letter-spacing: .09em; color: var(--muted); }
  .side-status .txt { color: var(--text2); font-size: .77rem; line-height: 1.45; margin-top: 6px; }
  .side-status .line { display: flex; align-items: center; gap: 8px; margin-top: 10px; color: var(--text2); font-size: .77rem; }
  .side-status .ab {
    margin-top: 12px; padding: 10px; border-radius: 10px;
    border: 1px solid var(--stroke); background: rgba(255,255,255,.05);
  }
  .side-status .ab label {
    display: flex; align-items: center; gap: 8px; margin-top: 8px;
    color: var(--text2); font-size: .8rem; cursor: pointer;
  }
  .side-status .ab input { accent-color: var(--blue); width: 15px; height: 15px; cursor: pointer; flex-shrink: 0; }
  .side-status .ab .txt { margin-top: 8px; font-size: .72rem; }

  /* Sticky, as the old top header was: Sleep, Clear alerts and Authorize have to
     stay reachable from the bottom of a long table. Padded out to the right edge
     so rows scrolling underneath do not show through beside it. */
  .hero {
    position: sticky; top: 0; z-index: 5;
    margin: -18px -18px 14px 0; padding: 18px 18px 12px 0;
    background: linear-gradient(180deg, rgba(10,14,20,.97) 65%, rgba(10,14,20,.85));
    backdrop-filter: blur(6px);
  }
  .hero .clock { color: var(--muted); font-size: .78rem; font-family: var(--mono); }
  .hero h1 { margin: 2px 0 0; font-size: 1.4rem; font-weight: 700; }
  .hero .lead { color: var(--text2); font-size: .8rem; margin: 4px 0 10px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .actions button, .row-actions button, .toolbar button {
    appearance: none; border: 1px solid var(--stroke); background: var(--bg-card);
    color: var(--text2); border-radius: 8px; padding: 7px 12px; cursor: pointer;
    font: inherit; font-size: .82rem; transition: .15s ease;
  }
  .actions button:hover, .row-actions button:hover, .toolbar button:hover {
    background: var(--bg-hover); color: var(--text); border-color: var(--stroke-strong);
  }
  .actions button.primary {
    color: var(--bg-deep); font-weight: 600;
    background: linear-gradient(135deg, var(--cyan), var(--blue));
    border: none;
  }
  .actions button.danger { border-color: rgba(255,93,120,.4); color: #ffa8b6; }
  /* Same emphasis inside a toolbar — the Firewall Config editor's save button is
     the one press that writes a kernel rule, so it should not look like Cancel. */
  .toolbar button.primary {
    color: var(--bg-deep); font-weight: 600;
    background: linear-gradient(135deg, var(--cyan), var(--blue));
    border: none;
  }
  /* Wake reads as the one thing worth pressing while the console is asleep. */
  .actions button.wake {
    color: var(--bg-deep); font-weight: 600;
    background: linear-gradient(135deg, var(--amber), #f5843b);
    border: none;
  }
  .sleep-banner {
    display: flex; flex-wrap: wrap; align-items: center; gap: 10px 16px;
    margin-bottom: 14px; padding: 12px 16px; border-radius: 10px;
    background: rgba(245,185,59,.08); border: 1px solid rgba(245,185,59,.45);
    color: #f6d089; font-size: .88rem;
  }
  .sleep-banner strong { color: var(--amber); letter-spacing: .04em; text-transform: uppercase; font-size: .78rem; }
  /* An upgrade is news, not a warning — same shape as the sleep banner, cyan
     rather than amber, so it does not read as something being wrong. */
  .sleep-banner.upgrade {
    background: rgba(59,200,180,.08); border-color: rgba(59,200,180,.45); color: #a9e7dd;
  }
  .sleep-banner.upgrade strong { color: var(--cyan); }
  .sleep-banner.upgrade button { background: linear-gradient(135deg, var(--cyan), var(--blue)); }
  .sleep-banner .spacer { flex: 1; }
  .sleep-banner button {
    appearance: none; border: none; border-radius: 8px; padding: 7px 14px; cursor: pointer;
    font: inherit; font-size: .82rem; font-weight: 600; color: var(--bg-deep);
    background: linear-gradient(135deg, var(--amber), #f5843b);
  }
  /* Dim the live data while asleep so stale rows can't be read as current traffic.
     Settings stays at full strength — it holds the other way to wake the console. */
  body.asleep main > section:not(#tab-settings) { opacity: .42; filter: grayscale(.55); }
  main { padding: 0 0 40px; }
  .status {
    margin-bottom: 14px; padding: 10px 14px; border-radius: 10px;
    background: var(--bg-panel); border: 1px solid var(--stroke);
    color: var(--text2); font-size: .88rem;
  }
  .status.err { border-color: rgba(255,93,120,.45); color: #ffa8b6; }
  .status.good { border-color: rgba(77,209,140,.4); color: #a6e6c4; }
  .cards {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px; margin-bottom: 16px;
  }
  .card {
    background: var(--bg-card); border: 1px solid var(--stroke);
    border-radius: 12px; padding: 14px 16px;
  }
  .card .label { color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; }
  .card .value { font-size: 1.55rem; font-weight: 650; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .card .value.cyan { color: var(--cyan); }
  .card .value.amber { color: var(--amber); }
  .card .value.danger { color: var(--danger); }
  .toolbar {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
    margin-bottom: 12px;
  }
  .toolbar input, .toolbar select, .modal input {
    background: var(--bg-deep); border: 1px solid var(--stroke); color: var(--text);
    border-radius: 8px; padding: 8px 12px; font: inherit; font-size: .88rem;
    min-width: 180px;
  }
  .toolbar input:focus, .modal input:focus { outline: 1px solid var(--blue); }
  table {
    width: 100%; border-collapse: collapse; font-size: .84rem;
    background: var(--bg-panel); border: 1px solid var(--stroke); border-radius: 12px;
    overflow: hidden;
  }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--stroke); vertical-align: top; }
  th {
    color: var(--muted); font-weight: 600; font-size: .72rem;
    text-transform: uppercase; letter-spacing: .05em; background: #12161f;
    position: sticky; top: 0;
  }
  tbody tr:nth-child(even) td { background: rgba(255,255,255,.02); }
  tr:hover td { background: rgba(24,36,63,.55); }
  tr:last-child td { border-bottom: none; }
  [data-scroll] { scrollbar-width: thin; scrollbar-color: rgba(124,249,255,.25) transparent; }
  [data-scroll]::-webkit-scrollbar { width: 9px; height: 9px; }
  [data-scroll]::-webkit-scrollbar-thumb { background: rgba(124,249,255,.2); border-radius: 6px; }
  [data-scroll]::-webkit-scrollbar-thumb:hover { background: rgba(124,249,255,.35); }
  [data-scroll]::-webkit-scrollbar-track { background: transparent; }
  /* Keep the actions column visible when wide tables scroll horizontally. */
  td.row-actions {
    position: sticky; right: 0; background: var(--bg-panel);
    white-space: nowrap; box-shadow: -10px 0 12px -10px rgba(0,0,0,.7);
  }
  table:has(td.row-actions) th:last-child {
    position: sticky; right: 0; z-index: 2;
    box-shadow: -10px 0 12px -10px rgba(0,0,0,.7);
  }
  tbody tr:nth-child(even) td.row-actions { background: #141922; }
  tr:hover td.row-actions { background: var(--bg-hover); }
  /* IPs, ports, and timestamps must never break mid-value — wide tables
     scroll horizontally instead (the actions column stays pinned). */
  td.mono { white-space: nowrap; }
  .chart-card {
    background: var(--bg-panel); border: 1px solid var(--stroke);
    border-radius: 12px; padding: 12px 14px 8px;
  }
  .chart-card svg { display: block; width: 100%; height: 170px; }
  .chart-meta {
    display: flex; justify-content: space-between; gap: 12px;
    color: var(--muted); font-size: .74rem; padding: 6px 2px 2px;
  }
  /* DASHBOARD ROWS — a wide chart beside the one number that summarises it,
     the pairing the desktop window uses. Under 900px the panel drops below the
     chart rather than squeezing two unreadable columns onto a phone. */
  .dash-row {
    display: grid; grid-template-columns: 2fr 1fr; gap: 12px; align-items: stretch;
  }
  @media (max-width: 900px) { .dash-row { grid-template-columns: 1fr; } }
  .side-panel {
    background: var(--bg-panel); border: 1px solid var(--stroke);
    border-radius: 12px; padding: 14px 16px;
    display: flex; flex-direction: column; justify-content: center;
  }
  .side-panel.intensity {
    align-items: center; text-align: center;
    background: linear-gradient(150deg, rgba(59,200,180,.10), rgba(74,158,255,.05) 60%, transparent);
  }
  .side-panel .pulse {
    width: 72px; height: 72px; border-radius: 50%; margin-bottom: 12px;
    border: 2px solid var(--cyan); background: rgba(59,200,180,.15);
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: .95rem; color: var(--cyan); letter-spacing: .04em;
  }
  /* Asleep must not read as LIVE — the number below it is then a stale count. */
  .side-panel .pulse.idle {
    border-color: var(--muted); color: var(--muted); background: rgba(255,255,255,.04);
  }
  .side-panel .side-title { font-weight: 650; }
  .side-panel .side-sub { color: var(--text2); font-size: .78rem; }
  .side-panel .side-kicker {
    color: var(--muted); font-size: .68rem; font-weight: 700; letter-spacing: .06em;
  }
  .side-panel .side-month { font-size: .95rem; font-weight: 600; margin-bottom: 8px; }
  .side-panel .big {
    font-size: 1.75rem; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1.15;
  }
  .side-panel .big.danger { color: var(--danger); }
  .side-panel .big.blue { color: var(--blue); }
  .side-panel .big.cyan { color: var(--cyan); }
  .side-panel .side-foot { font-size: .74rem; color: var(--text2); }
  .side-panel .side-foot.dim { color: var(--muted); }
  .chip {
    display: inline-block; padding: 1px 8px; border-radius: 999px; margin-right: 4px;
    font-size: .72rem; font-weight: 600;
    background: rgba(74,158,255,.16); color: #a8cfff; border: 1px solid rgba(74,158,255,.25);
  }
  .row-actions button.rm, .toolbar button.rm, button.rm-lg {
    border-color: rgba(255,93,120,.4); color: #ffa8b6;
  }
  .row-actions button.rm:hover, .toolbar button.rm:hover, button.rm-lg:hover {
    background: rgba(255,93,120,.12); border-color: rgba(255,93,120,.65); color: #ffd0d8;
  }
  .row-actions button:disabled { opacity: .55; cursor: wait; }
  button.rm-lg {
    appearance: none; font: inherit; font-size: .85rem; cursor: pointer;
    padding: 8px 14px; border-radius: 8px; background: var(--bg-card);
    border: 1px solid rgba(255,93,120,.4); transition: .15s ease; flex-shrink: 0;
  }
  .setting-row {
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
    padding: 14px 16px; background: var(--bg-card); border: 1px solid var(--stroke);
    border-radius: 12px; margin-bottom: 10px; max-width: 760px;
  }
  .setting-row .info h4 { margin: 0 0 3px; font-size: .92rem; font-weight: 600; }
  .setting-row .info p { margin: 0; color: var(--muted); font-size: .8rem; line-height: 1.45; }
  .setting-row select {
    background: var(--bg-deep); border: 1px solid var(--stroke); color: var(--text);
    border-radius: 8px; padding: 7px 10px; font: inherit; font-size: .85rem;
  }
  .settings-group h3 {
    margin: 22px 0 10px; font-size: .8rem; color: var(--muted);
    text-transform: uppercase; letter-spacing: .07em;
  }
  .settings-group:first-child h3 { margin-top: 0; }
  .settings-note {
    max-width: 760px; margin: 0 0 10px; padding: 9px 12px;
    background: var(--bg-card); border: 1px solid var(--stroke);
    border-radius: 8px; color: var(--muted); font-size: .8rem; line-height: 1.5;
  }
  .pw-change {
    max-width: 760px; padding: 16px; background: var(--bg-card);
    border: 1px solid var(--stroke); border-radius: 12px;
  }
  .pw-change p.desc {
    margin: 0 0 14px; color: var(--muted); font-size: .82rem; line-height: 1.45;
  }
  .pw-change label {
    display: block; color: var(--muted); font-size: .75rem;
    text-transform: uppercase; letter-spacing: .05em; margin: 0 0 6px;
  }
  .pw-change input[type="password"] {
    width: 100%; max-width: 360px; background: var(--bg-deep);
    border: 1px solid var(--stroke); color: var(--text);
    border-radius: 8px; padding: 10px 12px; font: inherit; font-size: .92rem;
    margin-bottom: 12px;
  }
  .pw-change input[type="password"]:focus {
    outline: 1px solid var(--blue); border-color: var(--blue);
  }
  .pw-change .pw-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-top: 4px; }
  .pw-change button[type="submit"] {
    appearance: none; font: inherit; font-size: .85rem; font-weight: 600; cursor: pointer;
    padding: 9px 16px; border-radius: 8px; border: none; color: var(--bg-deep);
    background: linear-gradient(135deg, var(--cyan), var(--blue));
  }
  .pw-change button[type="submit"]:disabled { opacity: .55; cursor: wait; }
  .pw-change .pw-msg { font-size: .85rem; min-height: 1.2em; margin: 0; }
  .pw-change .pw-msg.err { color: #ffa8b6; }
  .pw-change .pw-msg.ok { color: var(--success); }
  .switch { position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .switch .slider {
    position: absolute; inset: 0; cursor: pointer; border-radius: 999px;
    background: var(--bg-hover); border: 1px solid var(--stroke); transition: .2s ease;
  }
  .switch .slider:before {
    content: ""; position: absolute; height: 18px; width: 18px; left: 2px; top: 2px;
    background: var(--muted); border-radius: 50%; transition: .2s ease;
  }
  .switch input:checked + .slider {
    background: linear-gradient(135deg, rgba(61,231,200,.5), rgba(74,158,255,.55));
    border-color: transparent;
  }
  .switch input:checked + .slider:before { transform: translateX(20px); background: #fff; }
  .mono { font-family: var(--mono); font-size: .8rem; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: .72rem; font-weight: 600; letter-spacing: .02em;
  }
  .lvl-info, .lvl-low { background: rgba(89,191,242,.18); color: var(--sev-low); }
  .lvl-medium { background: rgba(242,191,64,.18); color: var(--sev-medium); }
  .lvl-high { background: rgba(250,115,64,.18); color: var(--sev-high); }
  .lvl-critical { background: rgba(242,64,89,.35); color: #fff; }
  .blocked { color: var(--danger); font-weight: 600; }
  .ok { color: var(--success); }
  .muted { color: var(--muted); }
  .empty { padding: 28px; text-align: center; color: var(--muted); }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .dot.on { background: var(--success); box-shadow: 0 0 8px rgba(77,209,140,.6); }
  .dot.off { background: var(--amber); }
  .help { color: var(--text2); line-height: 1.55; max-width: 720px; }
  .help code {
    font-family: var(--mono); background: var(--bg-card); padding: 1px 6px;
    border-radius: 4px; font-size: .85em; border: 1px solid var(--stroke);
  }
  .modal-backdrop {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,.55);
    z-index: 50; align-items: center; justify-content: center; padding: 16px;
  }
  .modal-backdrop.show { display: flex; }
  .modal {
    background: var(--bg-panel); border: 1px solid var(--stroke-strong);
    border-radius: 14px; padding: 20px; width: min(420px, 100%);
    box-shadow: 0 20px 60px rgba(0,0,0,.45);
  }
  .modal h3 { margin: 0 0 8px; font-size: 1rem; }
  .modal p { margin: 0 0 14px; color: var(--text2); font-size: .88rem; }
  .modal .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
  .hidden { display: none !important; }
  #authGate {
    position: fixed; inset: 0; z-index: 100;
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
    background:
      radial-gradient(900px 500px at 20% 0%, rgba(61,231,200,.1), transparent 50%),
      radial-gradient(800px 400px at 90% 20%, rgba(74,158,255,.12), transparent 45%),
      rgba(7,11,22,.96);
  }
  #authGate.hidden { display: none !important; }
  .auth-card {
    width: min(420px, 100%);
    background: var(--bg-panel);
    border: 1px solid var(--stroke-strong);
    border-radius: 16px;
    padding: 28px 26px 24px;
    box-shadow: 0 24px 70px rgba(0,0,0,.5);
  }
  .auth-card h1 {
    margin: 0 0 6px; font-size: 1.25rem;
    background: linear-gradient(90deg, var(--cyan), var(--blue));
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .auth-card .lead { color: var(--text2); font-size: .9rem; margin: 0 0 18px; line-height: 1.45; }
  .auth-card label {
    display: block; color: var(--muted); font-size: .75rem;
    text-transform: uppercase; letter-spacing: .05em; margin: 0 0 6px;
  }
  .auth-card input {
    width: 100%; background: var(--bg-deep); border: 1px solid var(--stroke);
    color: var(--text); border-radius: 8px; padding: 10px 12px;
    font: inherit; font-size: .95rem; margin-bottom: 14px;
  }
  .auth-card input:focus { outline: 1px solid var(--blue); border-color: var(--blue); }
  .auth-card .auth-error {
    color: #ffa8b6; font-size: .85rem; min-height: 1.2em; margin: 0 0 12px;
  }
  .auth-card button.submit {
    width: 100%; appearance: none; border: none; border-radius: 10px;
    padding: 11px 14px; font: inherit; font-weight: 650; font-size: .95rem;
    cursor: pointer; color: var(--bg-deep);
    background: linear-gradient(135deg, var(--cyan), var(--blue));
  }
  .auth-card button.submit:disabled { opacity: .55; cursor: wait; }
  .auth-card .hint { color: var(--muted); font-size: .78rem; margin: 14px 0 0; line-height: 1.4; }
  #appShell.hidden { display: none !important; }
  /* Under ~900px the rail cannot hold its width and the content column at the
     same time, so it folds into a wrapping row above the content. */
  @media (max-width: 900px) {
    #appShell { flex-direction: column; gap: 12px; padding: 12px; }
    .sidebar { flex: none; width: auto; position: static; height: auto; }
    nav { flex-direction: row; flex-wrap: wrap; gap: 4px; overflow: visible; }
    .nav-cap { width: 100%; margin-bottom: 2px; }
    nav button { width: auto; margin: 0; }
    nav button.sub { padding-left: 14px; }
    .side-status { margin-top: 14px; padding-top: 0; }
    .hero { position: static; margin: 0 0 14px; padding: 0; background: none; backdrop-filter: none; }
  }
  @media (max-width: 720px) {
    th, td { padding: 8px; }
  }
</style>
</head>
<body>

<div id="authGate">
  <div class="auth-card">
    <h1>Network Sentinel</h1>
    <p class="lead" id="authLead">Checking session…</p>
    <form id="authForm" autocomplete="on">
      <label for="pw" id="pwLabel">Master password</label>
      <input id="pw" type="password" name="password" autocomplete="current-password" required minlength="8" autofocus />
      <div id="setupFields" class="hidden">
        <label for="pwConfirm">Confirm master password</label>
        <input id="pwConfirm" type="password" name="confirm" autocomplete="new-password" minlength="8" />
        <div id="setupCodeField" class="hidden">
          <label for="setupCode">Setup code</label>
          <input id="setupCode" type="text" name="setupCode" autocomplete="one-time-code" spellcheck="false" placeholder="XXXX-XXXX" />
        </div>
      </div>
      <p class="auth-error" id="authError"></p>
      <button type="submit" class="submit" id="authSubmit">Continue</button>
    </form>
    <p class="hint" id="authHint"></p>
  </div>
</div>

<div id="appShell" class="hidden">
<aside class="sidebar">
  <div class="brand">
    <div class="mark">
      <svg viewBox="0 0 24 24" fill="none" stroke="#0a0e14" stroke-width="2"
           stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M12 2 4 5.5V11c0 5 3.4 9.1 8 10.5 4.6-1.4 8-5.5 8-10.5V5.5L12 2Z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    </div>
    <div>
      <h1>Network Sentinel</h1>
      <div class="sub">Port &amp; intrusion watch</div>
      <div class="sub" id="ver">—</div>
      <div class="sub tint">Web console</div>
    </div>
  </div>

  <nav id="nav">
    <div class="nav-cap">NAVIGATION</div>
    <button data-tab="dashboard" class="active">Dashboard</button>
    <button data-tab="connections">Live Connections</button>
    <button data-tab="hosts">Remote Computers</button>
    <button data-tab="threats">Break-in Attempts</button>
    <button data-tab="ports">Open Ports</button>
    <button data-tab="firewall">Firewall &amp; Block</button>
    <button data-tab="fwconfig" class="sub" title="Add, edit and delete inbound and outbound rules">Firewall Config</button>
    <button data-tab="allowlist" class="sub" title="Domains and IPs that are never blocked">Allowlist</button>
    <button data-tab="settings">Settings</button>
    <button data-tab="help" class="sub">Help</button>
  </nav>

  <div class="side-status">
    <div class="box">
      <div class="side-cap">STATUS</div>
      <div class="txt" id="sideStatus">Connecting…</div>
      <div class="line"><span class="dot" id="monDot"></span> <span id="monLabel">—</span></div>
      <div class="line" id="fwPill">—</div>
      <div class="ab">
        <div class="side-cap">AUTO-BLOCK</div>
        <label><input type="checkbox" id="chkAuto"/> <span>Enable auto-block</span></label>
        <div class="txt" id="abPill">—</div>
      </div>
    </div>
  </div>
</aside>

<div class="shell-main">
<div class="hero">
  <div class="clock" id="clock">—</div>
  <h1>Network Defense Console</h1>
  <div class="lead" id="heroLead">—</div>
  <div class="actions">
    <button id="btnSleep" class="primary" title="Stop monitoring and put Network Sentinel to sleep">Sleep</button>
    <button id="btnAuto">Auto-block</button>
    <button id="btnLevel">Min: High</button>
    <button id="btnAuth">Authorize firewall</button>
    <button id="btnClear" class="danger">Clear alerts</button>
    <button id="btnLogout">Sign out</button>
  </div>
</div>
<main>
  <div class="status" id="status">Connecting…</div>
  <div class="sleep-banner hidden" id="sleepBanner">
    <strong>Asleep</strong>
    <span>Monitoring is stopped — no connections, ports, or threats are being watched. Firewall blocks stay in force.</span>
    <span class="spacer"></span>
    <button type="button" id="btnWakeBanner">Wake up</button>
  </div>
  <!-- Shown when the server has been upgraded under an open tab. The page only
       ever re-fetches /api/state, never its own HTML, so no cache header can get
       the new markup in here — only a reload can. -->
  <div class="sleep-banner upgrade hidden" id="upgradeBanner">
    <strong>Updated</strong>
    <span id="upgradeText">The server is running a newer version than this page.</span>
    <span class="spacer"></span>
    <button type="button" id="btnReloadPage">Reload</button>
  </div>

  <section id="tab-dashboard">
    <div class="cards" id="cards"></div>
    <h3 style="margin:18px 0 8px;font-size:.95rem;color:var(--text2)">Activity — last 5 minutes</h3>
    <div class="dash-row">
      <div class="chart-card" id="dash-chart"></div>
      <!-- The desktop's threat-intensity hero: the high/critical count on its own,
           away from the four tiles it otherwise hides among. -->
      <div class="side-panel intensity">
        <div class="pulse" id="intensityPulse">LIVE</div>
        <div class="side-title">Threat intensity</div>
        <div class="big danger" id="intensityValue">0</div>
        <div class="side-sub">high-severity signals</div>
      </div>
    </div>
    <h3 style="margin:18px 0 8px;font-size:.95rem;color:var(--text2)">
      Data flow <span class="muted" id="traffic-window" style="font-weight:400"></span>
    </h3>
    <div class="dash-row">
      <div class="chart-card" id="dash-traffic"></div>
      <!-- The running month's totals, which the data-flow footer states in a
           sentence too long to read at a glance. -->
      <div class="side-panel">
        <div class="side-kicker">THIS MONTH</div>
        <div class="side-month" id="monthLabel">—</div>
        <div class="side-sub">Data in</div>
        <div class="big blue" id="monthIn">—</div>
        <div class="side-sub" style="margin-top:6px">Data out</div>
        <div class="big cyan" id="monthOut">—</div>
        <div class="side-foot" style="margin-top:10px" id="monthTotal"></div>
        <div class="side-foot dim" id="monthAvg"></div>
      </div>
    </div>
    <h3 style="margin:18px 0 4px;font-size:.95rem;color:var(--text2)">Monthly data in and out</h3>
    <div class="toolbar" style="margin-top:6px">
      <span class="muted" style="font-size:.85rem">Totals by</span>
      <select id="trafficRange">
        <option value="days">This month, by day</option>
        <option value="months">Last 12 months</option>
      </select>
      <span class="muted" id="traffic-summary" style="font-size:.85rem"></span>
    </div>
    <div class="chart-card" id="dash-traffic-bars"></div>
    <h3 style="margin:18px 0 8px;font-size:.95rem;color:var(--text2)">Recent threats</h3>
    <div id="dash-threats"></div>
  </section>

  <section id="tab-connections" class="hidden">
    <div class="toolbar">
      <input id="filterConn" placeholder="Filter connections…" />
    </div>
    <div id="tbl-connections"></div>
  </section>

  <section id="tab-hosts" class="hidden">
    <div class="toolbar">
      <input id="filterHosts" placeholder="Filter hosts…" />
      <input id="blockIp" placeholder="IP to block/unblock" class="mono" />
      <button id="btnBlock">Block IP</button>
      <button id="btnUnblock">Unblock IP</button>
    </div>
    <div id="tbl-hosts"></div>
  </section>

  <section id="tab-threats" class="hidden">
    <div class="toolbar">
      <input id="filterThreats" placeholder="Filter threats…" />
    </div>
    <div id="tbl-threats"></div>
  </section>

  <section id="tab-ports" class="hidden">
    <div id="tbl-ports"></div>
  </section>

  <section id="tab-firewall" class="hidden">
    <div class="toolbar">
      <input id="fwIp" placeholder="IP to block" class="mono" style="min-width:160px" />
      <button id="btnFwBlockIp">Block IP</button>
      <input id="fwPort" placeholder="Port" class="mono" style="min-width:80px;max-width:100px" />
      <select id="fwProto"><option>TCP</option><option>UDP</option></select>
      <button id="btnFwBlockPort">Block port</button>
      <button id="btnRestore">Restore allowlisted</button>
      <button id="btnRefreshFw">Refresh list</button>
    </div>
    <p class="muted" id="fwHint" style="margin:0 0 10px;font-size:.85rem">Each row is one block — Remove deletes its inbound and outbound rules together and keeps auto-block from re-adding it for 24h. Live refresh is off on this tab; click Refresh list to update. Requires root or admin rights.</p>
    <div id="tbl-firewall"></div>
  </section>

  <section id="tab-fwconfig" class="hidden">
    <div class="toolbar">
      <button id="btnAddInbound">Add an Inbound Rule</button>
      <button id="btnAddOutbound">Add an Outbound Rule</button>
      <button id="btnRefreshFwCfg">Rescan the host firewall</button>
    </div>
    <!-- Summary, then listeners, then policy — the same three lines in the same
         order as the desktop page's header card. -->
    <p class="muted" id="fwCfgSummary" style="margin:0 0 6px;font-size:.85rem"></p>
    <p class="muted" id="fwCfgListeners" style="margin:0 0 6px;font-size:.85rem"></p>
    <p class="muted" id="fwCfgPolicy" style="margin:0 0 10px;font-size:.85rem"></p>

    <div id="ruleEditor" class="settings-group hidden" style="margin-bottom:14px">
      <h3 id="ruleEditorTitle" style="margin:0 0 4px;font-size:.95rem">Add an Inbound Rule</h3>
      <p class="muted" id="ruleEditorNote" style="margin:0 0 10px;font-size:.85rem"></p>
      <div class="toolbar" style="flex-wrap:wrap">
        <select id="rulePreset" title="Fill protocol and port from a well-known service">
          <option value="">Custom</option>
        </select>
        <select id="ruleAction"><option>Block</option><option>Allow</option></select>
        <select id="ruleDirection"><option>Inbound</option><option>Outbound</option></select>
        <select id="ruleProtocol">
          <option>TCP</option><option>UDP</option><option>ICMP</option><option>Any</option>
        </select>
      </div>
      <div class="toolbar" style="flex-wrap:wrap">
        <input id="ruleLabel" placeholder="Label (optional — named from the port if left empty)" style="min-width:260px" />
        <input id="rulePorts" class="mono" placeholder="22   or  8000-8001   or  80, 443" style="min-width:200px" />
        <input id="ruleAddresses" class="mono" placeholder="All IPv4, All IPv6   or  10.0.0.0/8" style="min-width:220px" />
      </div>
      <p class="muted" id="ruleAddrHint" style="margin:0 0 8px;font-size:.8rem">Sources — leave empty for every address.</p>
      <p id="ruleEditorError" class="muted" style="margin:0 0 8px;font-size:.85rem;color:var(--danger)"></p>
      <div class="toolbar">
        <button id="btnSaveRule" class="primary">Add Rule</button>
        <button id="btnCancelRule">Cancel</button>
      </div>
    </div>

    <h3 style="margin:14px 0 8px;font-size:.95rem;color:var(--text2)">Inbound rules <span class="muted" id="inboundCount"></span></h3>
    <div id="tbl-fwconfig-in"></div>
    <h3 style="margin:18px 0 8px;font-size:.95rem;color:var(--text2)">Outbound rules <span class="muted" id="outboundCount"></span></h3>
    <div id="tbl-fwconfig-out"></div>
    <!-- A rule list alone does not answer "is this port actually reachable" —
         the listeners and the rules above them together do. -->
    <h3 style="margin:18px 0 8px;font-size:.95rem;color:var(--text2)">Listening services <span class="muted" id="listenerCount"></span></h3>
    <p class="muted" id="listenHint" style="margin:0 0 10px;font-size:.85rem"></p>
    <div id="tbl-fwconfig-listeners"></div>
  </section>

  <section id="tab-allowlist" class="hidden">
    <div class="toolbar">
      <input id="allowInput" placeholder="Domain or IP to allowlist" autocomplete="off" />
      <button id="btnAddAllow">Add</button>
      <button id="btnRefreshAllow">Refresh feed + list</button>
    </div>
    <p class="muted" id="allowStatus" style="margin:0 0 10px;font-size:.85rem"></p>
    <p class="muted" id="allowHint" style="margin:0 0 10px;font-size:.85rem">Live UI refresh is off on this tab so you can scroll the full list. Click Refresh feed + list to update.</p>
    <div id="tbl-allowlist"></div>
  </section>

  <section id="tab-settings" class="hidden">
    <div id="settingsPanel"></div>
    <div class="settings-group">
      <h3>Master password</h3>
      <form id="changePasswordForm" class="pw-change" autocomplete="off">
        <p class="desc">Change the password required to open this web console. It is stored only as a one-way PBKDF2-SHA256 hash with a random salt on this machine — never as plain text.</p>
        <label for="pwCurrent">Current master password</label>
        <input id="pwCurrent" type="password" name="current" autocomplete="current-password" required minlength="8" />
        <label for="pwNew">New master password</label>
        <input id="pwNew" type="password" name="new" autocomplete="new-password" required minlength="8" />
        <label for="pwNewConfirm">Confirm new password</label>
        <input id="pwNewConfirm" type="password" name="confirm" autocomplete="new-password" required minlength="8" />
        <div class="pw-actions">
          <button type="submit" id="btnChangePassword">Update password</button>
          <p class="pw-msg" id="pwChangeMsg" aria-live="polite"></p>
        </div>
      </form>
    </div>
  </section>

  <section id="tab-help" class="hidden">
    <div class="help">
      <p><strong>Network Sentinel</strong> headless web UI — same monitoring and firewall stack as the desktop and TUI apps.</p>
      <p>Start with <code>NetworkSentinel -w</code> (optional port: <code>-w 18765</code>). The process picks a free high port when you omit one.</p>
      <ul>
        <li><strong>Dashboard</strong> — live counters, activity and data-flow charts, recent threats</li>
        <li><strong>Live Connections / Break-in Attempts</strong> — live traffic with per-row Block buttons</li>
        <li><strong>Remote Computers</strong> — remote peers; block/unblock IPs</li>
        <li><strong>Open Ports</strong> — local listeners; block a port with one click</li>
        <li><strong>Firewall &amp; Block</strong> — managed rules, manual IP/port blocking, remove rules</li>
        <li><strong>Firewall Config</strong> — add, edit and delete inbound and outbound rules</li>
        <li><strong>Allowlist</strong> — domains/IPs that are never blocked</li>
        <li><strong>Settings</strong> — auto-block behavior, block direction, geo lookups, refresh speed, and master password</li>
      </ul>
      <p><strong>Sleep / Wake</strong> — the first button in the header stops every watcher (connections, listening ports, auth log, port-scan probes, ARP, startup items, exfiltration, honeypot) and parks the console. Press it again to wake up and start monitoring from live data. Firewall blocks stay in force while asleep — sleeping stops watching, it does not unblock anything. Sleep applies to this web service; a desktop or TUI instance is a separate process and keeps running.</p>
      <p class="muted">Firewall actions need root or admin rights (Mac password dialog or sudo). Prefer running the web service as root once rather than elevating per action.</p>
      <p class="muted">Web access is gated by a master password (set on first visit; change it anytime under Settings). The password is stored only as a salted one-way hash. Sign out or close the browser to require it again.</p>
    </div>
  </section>
</main>
</div>
</div>

<script>
(() => {
  // Stamped into the page when it is served, so it records the build this markup
  // came from. state.version is whatever the server is running now; the two
  // diverge exactly when the service has been upgraded under an open tab.
  const BUILD_VERSION = '__NS_VERSION__';

  let state = null;
  let tab = 'dashboard';
  let lastError = '';
  let authMode = 'check'; // check | setup | login | ok
  let needSetupCode = false;
  let pollTimer = null;
  let sleepTimer = null;

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
    { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]
  ));

  function setStatus(msg, err, good) {
    const el = $('status');
    el.textContent = msg || '';
    el.classList.toggle('err', !!err);
    el.classList.toggle('good', !err && !!good);
  }

  function showAuth(mode, message) {
    authMode = mode;
    const gate = $('authGate');
    const shell = $('appShell');
    if (mode === 'ok') {
      gate.classList.add('hidden');
      shell.classList.remove('hidden');
      return;
    }
    gate.classList.remove('hidden');
    shell.classList.add('hidden');
    const setup = mode === 'setup';
    $('setupFields').classList.toggle('hidden', !setup);
    $('setupCodeField').classList.toggle('hidden', !(setup && needSetupCode));
    $('authLead').textContent = setup
      ? 'Create a master password to protect this console. You will need it every time you open the web UI.'
      : 'Enter the master password to continue.';
    $('pwLabel').textContent = setup ? 'New master password' : 'Master password';
    $('pw').autocomplete = setup ? 'new-password' : 'current-password';
    $('authSubmit').textContent = setup ? 'Create password & sign in' : 'Sign in';
    $('authHint').textContent = setup
      ? (needSetupCode
          ? 'Minimum 8 characters. The setup code is printed where the console runs (the terminal, or the unified log under launchd).'
          : 'Minimum 8 characters. Stored only as a one-way hash on this machine.')
      : 'Session ends when you sign out, close the browser, or after 12 hours idle.';
    $('authError').textContent = message || '';
    $('pw').value = '';
    $('pwConfirm').value = '';
    setTimeout(() => $('pw').focus(), 50);
  }

  function lvlClass(level) {
    const l = String(level || '').toLowerCase();
    if (l === 'critical') return 'lvl-critical';
    if (l === 'high') return 'lvl-high';
    if (l === 'medium') return 'lvl-medium';
    return 'lvl-info';
  }

  function badge(level) {
    return `<span class="badge ${lvlClass(level)}">${esc(level)}</span>`;
  }

  function matchFilter(q, ...parts) {
    if (!q) return true;
    const s = parts.join(' ').toLowerCase();
    return s.includes(q.toLowerCase());
  }

  function table(headers, rowsHtml) {
    if (!rowsHtml) return `<div class="empty">No rows.</div>`;
    return `<div data-scroll style="overflow:auto;max-height:calc(100vh - 220px)"><table>
      <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table></div>`;
  }

  async function ensureAuth() {
    try {
      const res = await fetch('/api/auth/status', { cache: 'no-store', credentials: 'same-origin' });
      const data = await res.json();
      needSetupCode = !!data.setupCodeRequired;
      if (!data.configured) {
        showAuth('setup');
        return false;
      }
      if (!data.authenticated) {
        showAuth('login');
        return false;
      }
      showAuth('ok');
      return true;
    } catch (e) {
      showAuth('login', 'Cannot reach server: ' + (e.message || e));
      return false;
    }
  }

  let statusHoldUntil = 0;
  // Allowlist / Firewall / Settings tabs freeze live redraw so you can scroll and act
  // on rows. Dashboard/connections/etc. keep the periodic poll.
  function isFrozenTab() {
    // Firewall Config joins them: a redraw mid-edit would wipe the form, and the
    // rule tables are something you read and act on rather than watch.
    return tab === 'allowlist' || tab === 'firewall' || tab === 'settings' || tab === 'fwconfig';
  }

  function getRefreshMs() {
    const v = parseInt(localStorage.getItem('ns-refresh') || '2500', 10);
    return Number.isFinite(v) && v >= 1000 ? v : 2500;
  }

  async function fetchState() {
    const res = await fetch('/api/state', { cache: 'no-store', credentials: 'same-origin' });
    if (res.status === 401) {
      stopAllTimers();
      const body = await res.json().catch(() => ({}));
      showAuth(body.configured === false ? 'setup' : 'login', 'Sign in required.');
      return false;
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    state = await res.json();
    lastError = '';
    return true;
  }

  async function apiAction(action, extra = {}) {
    const res = await fetch('/api/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ action, ...extra })
    });
    if (res.status === 401) {
      stopAllTimers();
      showAuth('login', 'Session expired. Sign in again.');
      return { ok: false, message: 'Authentication required.' };
    }
    const data = await res.json().catch(() => ({ ok: false, message: 'Bad response' }));
    if (data.message) {
      statusHoldUntil = Date.now() + 12000;
      setStatus(data.message, !data.ok, data.ok);
    }
    // Always pull once after an action so Add/Remove show up even on frozen tabs.
    try {
      if (await fetchState()) render({ forceLists: true });
    } catch { /* ignore */ }
    return data;
  }

  async function refresh() {
    // Frozen tabs: do not auto-redraw (scroll position + readability).
    if (isFrozenTab()) return;
    try {
      if (await fetchState()) render({ forceLists: true });
    } catch (e) {
      lastError = e.message || String(e);
      setStatus('Lost connection to Network Sentinel: ' + lastError, true);
    }
  }

  async function refreshFrozenTab() {
    try {
      if (await fetchState()) render({ forceLists: true });
      setStatus('List updated.', false);
      statusHoldUntil = Date.now() + 4000;
    } catch (e) {
      setStatus('Refresh failed: ' + (e.message || e), true);
    }
  }

  function startPolling() {
    stopPolling();
    if (!isFrozenTab()) {
      refresh();
      pollTimer = setInterval(refresh, getRefreshMs());
    } else {
      refreshFrozenTab();
    }
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function stopSleepBeat() {
    if (sleepTimer) { clearInterval(sleepTimer); sleepTimer = null; }
  }

  function stopAllTimers() {
    stopPolling();
    stopSleepBeat();
  }

  // Unknown state (nothing fetched yet) counts as awake — never park the page on a guess.
  function isAsleep() {
    return !!(state && state.settings && !state.settings.isMonitoring);
  }

  // Asleep, the server observes nothing, so there is no new data to draw: drop the fast
  // poll. A slow heartbeat stays behind so a wake triggered elsewhere — another browser,
  // a second tab, an API client — still reaches this page.
  function syncSleepMode() {
    if (isAsleep()) {
      stopPolling();
      if (!sleepTimer) sleepTimer = setInterval(sleepHeartbeat, 30000);
    } else {
      stopSleepBeat();
      if (!pollTimer && !isFrozenTab()) startPolling();
    }
  }

  async function sleepHeartbeat() {
    if (isFrozenTab()) return;
    try {
      if (await fetchState()) render({ forceLists: true });
    } catch { /* quiet while asleep — a lost server is not news here */ }
  }

  async function toggleSleep(force) {
    const wantSleep = force === undefined ? !isAsleep() : !!force;
    const btn = $('btnSleep');
    btn.disabled = true;
    try {
      await apiAction(wantSleep ? 'sleep' : 'wake');
      statusHoldUntil = Date.now() + 8000;
    } finally {
      btn.disabled = false;
    }
    syncSleepMode();
  }

  function saveScroll(id) {
    const el = document.getElementById(id);
    if (!el) return 0;
    const sc = el.querySelector('[data-scroll]');
    return sc ? sc.scrollTop : 0;
  }
  function restoreScroll(id, top) {
    const el = document.getElementById(id);
    if (!el) return;
    const sc = el.querySelector('[data-scroll]');
    if (sc) sc.scrollTop = top || 0;
  }

  // Inline-SVG activity chart: connection-count area/line, red columns where
  // threats were detected in that sample. No libraries, no external requests.
  function chartHtml(act) {
    if (!act || act.length < 2)
      return '<div class="chart-meta" style="padding:26px 4px">Collecting samples… the chart appears after a few seconds of monitoring.</div>';
    const W = 1000, H = 170, padT = 12, padB = 6;
    const ih = H - padT - padB;
    const maxC = Math.max(1, ...act.map(a => a.connections));
    const x = i => (W * i / (act.length - 1));
    const y = v => padT + ih * (1 - v / maxC);
    const pts = act.map((a, i) => `${x(i).toFixed(1)},${y(a.connections).toFixed(1)}`).join(' ');
    const area = `0,${H - padB} ${pts} ${W},${H - padB}`;
    const grid = [0.25, 0.5, 0.75].map(f =>
      `<line x1="0" y1="${(padT + ih * f).toFixed(1)}" x2="${W}" y2="${(padT + ih * f).toFixed(1)}" stroke="rgba(255,255,255,.07)" stroke-width="1"/>`).join('');
    const threats = act.map((a, i) => a.threats > 0
      ? `<rect x="${(x(i) - 2).toFixed(1)}" y="${padT}" width="4" height="${ih}" fill="rgba(255,93,120,.30)" rx="2"/>`
      : '').join('');
    const last = act[act.length - 1];
    const threatTotal = act.reduce((n, a) => n + a.threats, 0);
    return `
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Connection activity chart">
        ${grid}
        <polygon points="${area}" fill="rgba(61,231,200,.13)"/>
        ${threats}
        <polyline points="${pts}" fill="none" stroke="#3bc8b4" stroke-width="2"
          vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/>
        <circle cx="${x(act.length - 1).toFixed(1)}" cy="${y(last.connections).toFixed(1)}" r="3.5" fill="#3bc8b4"/>
      </svg>
      <div class="chart-meta">
        <span>${esc(act[0].time)}</span>
        <span><span style="color:#3bc8b4">●</span> connections (now ${esc(last.connections)}, peak ${esc(maxC)})
          &nbsp; <span style="color:#ff5d78">▮</span> threat detected${threatTotal ? ` (${esc(threatTotal)} in window)` : ' (none in window)'}</span>
        <span>${esc(last.time)}</span>
      </div>`;
  }

  // ── Upgrade detection ─────────────────────────────────────────────────────
  // A tab left open across an upgrade keeps its old markup: the page polls
  // /api/state but never re-requests its own HTML, so no cache header can
  // deliver the new UI. The features simply appear to be missing, which is
  // exactly how it looked the first time. Offer the reload instead.
  //
  // Never reload automatically — an operator may be mid-rule in the Firewall
  // Config form, and throwing that away to pick up a cosmetic change would be a
  // worse bug than the one this fixes.

  function checkForUpgrade() {
    const running = state && state.version;
    // The placeholder survives only if the page was served by a build that does
    // not stamp it; treat that as "cannot tell" rather than "upgraded".
    if (!running || BUILD_VERSION.startsWith('__')) return;
    if (running === BUILD_VERSION) return;

    $('upgradeText').textContent =
      `This page was loaded from v${BUILD_VERSION}; the server is now running v${running}. ` +
      'Reload to pick up the new console.';
    $('upgradeBanner').classList.remove('hidden');
  }

  // ── Data flow ─────────────────────────────────────────────────────────────
  // Both directions share one zero-based scale. Two independent scales would draw
  // a trickle of uploads at the same height as a saturated download, which is the
  // one thing this card exists to tell apart.

  function trafficChartHtml(tr) {
    const live = (tr && tr.live) || [];
    if (!tr || !tr.enabled)
      return '<div class="chart-meta" style="padding:26px 4px">Traffic metering is off — turn it on in Settings.</div>';
    if (live.length < 2)
      return '<div class="chart-meta" style="padding:26px 4px">Measuring… the chart appears after a few samples (5s each).</div>';

    const W = 1000, H = 170, padT = 12, padB = 6;
    const ih = H - padT - padB;
    const peak = Math.max(1, ...live.map(s => Math.max(s.inBps, s.outBps)));
    const x = i => (W * i / (live.length - 1));
    const y = v => padT + ih * (1 - v / peak);
    const line = key => live.map((s, i) => `${x(i).toFixed(1)},${y(s[key]).toFixed(1)}`).join(' ');
    const inPts = line('inBps'), outPts = line('outBps');
    const grid = [0.25, 0.5, 0.75].map(f =>
      `<line x1="0" y1="${(padT + ih * f).toFixed(1)}" x2="${W}" y2="${(padT + ih * f).toFixed(1)}" stroke="rgba(255,255,255,.07)" stroke-width="1"/>`).join('');

    return `
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Data in and out">
        ${grid}
        <polygon points="0,${H - padB} ${inPts} ${W},${H - padB}" fill="rgba(74,158,255,.13)"/>
        <polyline points="${inPts}" fill="none" stroke="#4a9eff" stroke-width="2"
          vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/>
        <polyline points="${outPts}" fill="none" stroke="#3bc8b4" stroke-width="2"
          vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/>
      </svg>
      <div class="chart-meta">
        <span><span style="color:#4a9eff">●</span> in ${esc(tr.inRate)}
          &nbsp; <span style="color:#3bc8b4">●</span> out ${esc(tr.outRate)}</span>
        <span>${esc(tr.monthLabel)}: ${esc(tr.monthIn)} in / ${esc(tr.monthOut)} out
          · ${esc(tr.monthTotal)} total · ${esc(tr.monthDailyAverage || '')}</span>
        <span class="muted">${esc(tr.status || '')}</span>
      </div>`;
  }

  // Bars, not a line: these are totals over discrete periods, and a line between
  // two days implies a value at 12:00 that nothing measured.
  function trafficBarsHtml(buckets) {
    if (!buckets || !buckets.length)
      return '<div class="chart-meta" style="padding:26px 4px">No history yet.</div>';

    const W = 1000, H = 170, padT = 10, padB = 20;
    const ih = H - padT - padB;
    const peak = Math.max(1, ...buckets.map(b => Math.max(b.bytesIn, b.bytesOut)));
    const slot = W / buckets.length;
    const bw = Math.max(1.5, Math.min(14, slot / 2.6));

    const bars = buckets.map((b, i) => {
      const cx = slot * (i + 0.5);
      const hIn = ih * (b.bytesIn / peak), hOut = ih * (b.bytesOut / peak);
      const title = `${b.label}: ${b.inText} in / ${b.outText} out`;
      return `<g><title>${esc(title)}</title>` +
        `<rect x="${(cx - bw - 1).toFixed(1)}" y="${(padT + ih - hIn).toFixed(1)}" width="${bw.toFixed(1)}" height="${hIn.toFixed(1)}" fill="#4a9eff" rx="1"/>` +
        `<rect x="${(cx + 1).toFixed(1)}" y="${(padT + ih - hOut).toFixed(1)}" width="${bw.toFixed(1)}" height="${hOut.toFixed(1)}" fill="#3bc8b4" rx="1"/>` +
        `</g>`;
    }).join('');

    // Label every bar when they fit, otherwise roughly every fifth.
    const step = buckets.length > 16 ? Math.ceil(buckets.length / 12) : 1;
    const labels = buckets.map((b, i) => (i % step === 0)
      ? `<text x="${(slot * (i + 0.5)).toFixed(1)}" y="${H - 6}" fill="rgba(255,255,255,.45)" font-size="11" text-anchor="middle">${esc(b.label)}</text>`
      : '').join('');

    return `
      <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Data in and out per period">
        ${bars}${labels}
      </svg>
      <div class="chart-meta">
        <span><span style="color:#4a9eff">▮</span> data in &nbsp; <span style="color:#3bc8b4">▮</span> data out</span>
      </div>`;
  }

  function renderTraffic() {
    const tr = state.traffic || {};
    $('dash-traffic').innerHTML = trafficChartHtml(tr);
    $('traffic-window').textContent = tr.window ? '— ' + tr.window : '';

    // The same five month fields the footer sentence uses, given room to be read.
    // Em dashes rather than zeros while the meter is off: nothing was measured.
    const metered = tr.enabled !== false;
    $('monthLabel').textContent = tr.monthLabel || '—';
    $('monthIn').textContent = metered ? (tr.monthIn || '—') : '—';
    $('monthOut').textContent = metered ? (tr.monthOut || '—') : '—';
    $('monthTotal').textContent = metered
      ? (tr.monthTotal ? tr.monthTotal + ' total' : '')
      : 'Traffic metering is off';
    $('monthAvg').textContent = metered ? (tr.monthDailyAverage || '') : '';

    const useMonths = $('trafficRange').value === 'months';
    const buckets = (useMonths ? tr.months : tr.days) || [];
    $('dash-traffic-bars').innerHTML = trafficBarsHtml(buckets);

    let totalIn = 0, totalOut = 0;
    for (const b of buckets) { totalIn += b.bytesIn; totalOut += b.bytesOut; }
    const scope = useMonths ? '12 months' : (tr.monthLabel || 'this month');
    $('traffic-summary').textContent = buckets.length
      ? `${scope} · ${fmtBytes(totalIn)} in · ${fmtBytes(totalOut)} out` : '';
  }

  // Decimal (SI) units, matching Services/ByteSize on the server — the convention
  // link speeds and data caps use, so 1 GB is 1,000,000,000 bytes.
  function fmtBytes(n) {
    if (!n || n <= 0) return '0 B';
    const units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
    let u = 0;
    while (n >= 1000 && u < units.length - 1) { n /= 1000; u++; }
    const digits = u <= 1 ? 0 : (n >= 100 ? 0 : 1);
    return n.toFixed(digits) + ' ' + units[u];
  }

  // ── Firewall Config ───────────────────────────────────────────────────────

  const RULE_PRESETS = {
    'SSH (22/tcp)': ['TCP', '22'],
    'HTTP (80/tcp)': ['TCP', '80'],
    'HTTPS (443/tcp)': ['TCP', '443'],
    'DNS (53/udp)': ['UDP', '53'],
    'MySQL (3306/tcp)': ['TCP', '3306'],
    'PostgreSQL (5432/tcp)': ['TCP', '5432'],
    'WireGuard (51820/udp)': ['UDP', '51820'],
    'ICMP (ping)': ['ICMP', '']
  };

  let editingRuleName = '';
  // Identity of a scanned host rule being edited. Rule names repeat across a
  // host, so the server matches on the rule's whole shape, not on its label.
  let editingRuleKey = '';

  const COVERED_CLASS = {
    'Open': 'warn',
    'Restricted': 'ok',
    'Not allowed': 'muted',
    'Local only': 'muted',
    'No firewall': 'blocked'
  };

  function renderFirewallConfig() {
    const rules = state.configRules || [];
    const fw = state.hostFirewall || {};
    const inbound = rules.filter(r => r.inbound);
    const outbound = rules.filter(r => !r.inbound);
    const mine = rules.filter(r => !r.isForeign).length;
    const listeners = state.listeners || [];

    // Every sentence here is built the same way in the GUI's ApplyHostScan, from the
    // same fields, so an operator moving between the two front-ends reads the same
    // page about the same firewall.
    const dropsByDefault = (fw.defaultInbound || '').toLowerCase() !== 'accept';
    $('fwCfgPolicy').textContent =
      `Default policy: ${fw.defaultInbound || '?'} inbound, ${fw.defaultOutbound || '?'} outbound. ` +
      (dropsByDefault
        ? 'Inbound traffic no rule matches is dropped, so a service is only reachable if a rule admits it. '
        : 'Inbound traffic no rule matches is accepted, so an Allow rule opens a path through the rules ' +
          'above it rather than granting access on its own. ') +
      'Rules match in order, first match wins. ' + (fw.privilegeNote || '');
    $('fwCfgSummary').textContent =
      `${fw.host || ''} · ${fw.backend || '?'} · ${fw.status || '?'} · ${fw.rulesSummary || 'No rules'} ` +
      `(${mine} from Network Sentinel, ${rules.length - mine} from the rest of the host)` +
      ` · Scanned ${fw.scannedAt || '—'}, not live — Rescan to re-read the kernel.` +
      ((fw.errors && fw.errors.length) ? '  ' + fw.errors.join('  ') : '');
    const openCount = listeners.filter(l => l.covered === 'Open').length;
    $('fwCfgListeners').textContent = listeners.length === 0
      ? 'No listening sockets were readable.'
      : `${listeners.length} listening socket${listeners.length === 1 ? '' : 's'} · ` +
        `${openCount} reachable from anywhere`;
    $('inboundCount').textContent = `(${inbound.length})`;
    $('outboundCount').textContent = `(${outbound.length})`;
    $('listenerCount').textContent = `(${listeners.length})`;

    const rows = (list, addrHeader) => table(
      ['Label', 'Action', 'Protocol', 'Port range', addrHeader, 'Created by', ''],
      list.map(r => `<tr>
        <td class="mono">${esc(r.label)}</td>
        <td class="${r.action === 'Block' ? 'blocked' : ''}">${esc(r.action)}</td>
        <td>${esc(r.protocol)}</td>
        <td class="mono">${esc(r.ports)}</td>
        <td class="mono">${esc(r.addresses)}</td>
        <td class="muted">${esc(r.origin)}</td>
        <td class="row-actions">${r.isProtected
          ? '<span class="muted" title="The allow rule that lets your browser reach this console">console</span>'
          : `<button data-editrule="${esc(r.key)}">Edit</button> ` +
            `<button data-delrule="${esc(r.key)}">Delete</button>`}</td>
      </tr>`).join('')
    );

    $('tbl-fwconfig-in').innerHTML = rows(inbound, 'Sources');
    $('tbl-fwconfig-out').innerHTML = rows(outbound, 'Destinations');

    // The sockets a rule here is written against, and what the rules above do to
    // them. Without this you read `lsof -nP -iTCP -sTCP:LISTEN` in a terminal and
    // retype the port, which is how ports and bind addresses go missing from the
    // rule set.
    // Same two lines the GUI's Listening services card carries, in the same order:
    // the count and reachability, then what the table is.
    $('listenHint').textContent =
      ($('fwCfgListeners').textContent ? $('fwCfgListeners').textContent + ' — ' : '') +
      'The same set “lsof -nP -iTCP -sTCP:LISTEN” prints, with what the inbound rules above ' +
      'do to each one. “New rule” fills the form above in with that socket’s protocol and port.';
    $('tbl-fwconfig-listeners').innerHTML = table(
      ['Process', 'Protocol', 'Port', 'Service', 'Bind address', 'Firewall', ''],
      listeners.map(l => `<tr>
        <td>${esc(l.process)}</td>
        <td>${esc(l.protocol)}</td>
        <td class="mono">${esc(l.port)}</td>
        <td class="muted">${esc(l.service)}</td>
        <td class="mono">${esc(l.address)}</td>
        <td class="${COVERED_CLASS[l.covered] || ''}">${esc(l.covered)}</td>
        <td class="row-actions"><button data-portrule="${esc(l.port)}" data-proto="${esc(l.protocol)}"
            data-endpoint="${esc(l.address ? l.address + ':' + l.port : 'port ' + l.port)}"
            data-process="${esc(l.process)}">New rule</button></td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">No listening sockets reported.</td></tr>'
    );
  }

  // Protocol and port carry over from the socket; the bind address deliberately
  // does not. Sources matches the far end of a connection, so seeding it with
  // 0.0.0.0, :: or this Mac's own LAN address would match nothing an attacker sends.
  function openRuleEditorForPort(port, proto, endpoint, process) {
    // A scan row whose port is not a plain number has nothing to prefill.
    if (!/^\d+$/.test(String(port))) {
      setStatus(`"${port}" is not a single port number, so there is nothing to prefill — ` +
                'write the rule by hand with Add an Inbound Rule.', true);
      return;
    }
    openRuleEditor(null, 'Inbound');
    $('ruleProtocol').value = String(proto).toUpperCase() === 'UDP' ? 'UDP' : 'TCP';
    $('rulePorts').value = String(port);
    // Same sentence the GUI's MainViewModel.DescribeListener builds, so an operator
    // moving between the two front-ends reads the same note about the same socket.
    const who = !process || process.trim() === '' || process.trim() === '—'
      ? 'an unidentified process'
      : process;
    $('ruleEditorNote').textContent =
      `Writes a rule for ${$('ruleProtocol').value} port ${port}, which ${who} on ${endpoint} is listening on. ` +
      'Sources is left empty (every address) — it matches the remote end, not the address the service is ' +
      'bound to. The web service needs root, or sudo without a password.';
    $('ruleEditor').scrollIntoView({ block: 'nearest' });
  }

  function openRuleEditor(rule, direction) {
    // A rule the host owns is replaced, not edited in place: the server deletes it
    // where it lives and writes the new values. Only our own ledger rules can be
    // edited by name.
    editingRuleName = rule && !rule.isForeign ? rule.name : '';
    editingRuleKey = rule && rule.isForeign ? (rule.key || '') : '';
    $('ruleLabel').value = rule ? rule.label : '';
    $('ruleAction').value = rule ? rule.action : 'Block';
    $('ruleDirection').value = rule ? (rule.inbound ? 'Inbound' : 'Outbound') : direction;
    $('ruleProtocol').value = rule ? rule.protocol : 'TCP';
    // "All ports" / "All IPv4, All IPv6" are display forms; the form wants the
    // raw field back, and empty means the same thing to the parser.
    $('rulePorts').value = rule && rule.ports !== 'All ports' ? rule.ports : '';
    $('ruleAddresses').value = rule && rule.addresses !== 'All IPv4, All IPv6' ? rule.addresses : '';
    $('rulePreset').value = '';
    $('ruleEditorError').textContent = '';
    $('ruleEditorTitle').textContent =
      (rule ? 'Edit an ' : 'Add an ') + $('ruleDirection').value + ' Rule';
    $('ruleEditorNote').textContent = rule
      ? (rule.isForeign
          ? `“${rule.label}” was created by ${rule.origin}. Saving removes it there and writes these ` +
            'values as a new rule — PF has no in-place edit, so this is what editing one means.'
          : 'Replaces the loaded rule with these values.')
      : 'Writes a PF rule into this Mac’s Network Sentinel anchor. The web service needs root, or sudo without a password.';
    $('btnSaveRule').textContent = rule ? 'Save Rule' : 'Add Rule';
    updateRuleAddrHint();
    $('ruleEditor').classList.remove('hidden');
  }

  function closeRuleEditor() {
    editingRuleName = '';
    editingRuleKey = '';
    $('ruleEditor').classList.add('hidden');
    $('ruleEditorError').textContent = '';
  }

  function updateRuleAddrHint() {
    const out = $('ruleDirection').value === 'Outbound';
    $('ruleAddrHint').textContent = out
      ? 'Destinations — leave empty for every address.'
      : 'Sources — leave empty for every address.';
    $('ruleEditorTitle').textContent =
      (editingRuleName || editingRuleKey ? 'Edit an ' : 'Add an ') + $('ruleDirection').value + ' Rule';
  }

  // ── Critical-threat warnings: tab-title badge + browser notification ───────
  // The badge always tracks live Critical rows; notifications additionally need
  // the criticalAlertsEnabled setting AND granted browser permission.
  const seenCritical = new Set();
  let criticalPrimed = false;
  function criticalKey(t) {
    return (t.ts || t.time) + '|' + (t.sourceIp || '') + '|' + (t.title || '');
  }
  function updateCriticalAlerts() {
    const crit = (state.threats || []).filter(t => t.levelNum >= 4);
    document.title = crit.length
      ? '⚠ ' + crit.length + ' · Network Sentinel'
      : 'Network Sentinel';

    if (seenCritical.size > 2000) {
      // Prune runaway growth on very long sessions; re-seed silently.
      seenCritical.clear();
      crit.forEach(t => seenCritical.add(criticalKey(t)));
      return;
    }
    const fresh = crit.filter(t => !seenCritical.has(criticalKey(t)));
    fresh.forEach(t => seenCritical.add(criticalKey(t)));
    // First poll after page load: everything is "new" — seed silently so a
    // reload does not replay alerts for old events.
    if (!criticalPrimed) { criticalPrimed = true; return; }
    if (!fresh.length || !state.settings?.criticalAlertsEnabled) return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    const head = fresh.length === 1
      ? 'Critical threat: ' + (fresh[0].type || 'threat detected')
      : fresh.length + ' critical threats detected';
    const body = fresh.slice(0, 4)
      .map(t => t.title + (t.sourceIp ? ' — ' + t.sourceIp : '')).join('\n');
    try { new Notification(head, { body, tag: 'ns-critical' }); } catch { /* blocked */ }
  }

  function render(opts) {
    opts = opts || {};
    if (!state) return;
    updateCriticalAlerts();
    const forceLists = !!opts.forceLists;
    $('ver').textContent = 'v' + (state.version || '?');
    $('clock').textContent = state.clock || '';
    checkForUpgrade();
    // Don't overwrite a recent action result (add/remove/block) with the generic status.
    if (state.statusMessage && Date.now() > statusHoldUntil)
      setStatus(state.statusMessage, false);

    const mon = !!(state.settings && state.settings.isMonitoring);
    const btnSleep = $('btnSleep');
    btnSleep.textContent = mon ? 'Sleep' : 'Wake';
    btnSleep.title = mon
      ? 'Stop monitoring and put Network Sentinel to sleep'
      : 'Wake Network Sentinel and start monitoring again';
    btnSleep.classList.toggle('wake', !mon);
    document.body.classList.toggle('asleep', !mon);
    $('sleepBanner').classList.toggle('hidden', mon);
    $('monDot').className = 'dot ' + (mon ? 'on' : 'off');
    $('monLabel').textContent = mon ? 'Monitoring' : 'Asleep';
    $('fwPill').textContent = state.firewall?.isAdmin ? 'Firewall: ready' : 'Firewall: needs elevation';
    $('fwPill').title = state.firewall?.privilegeText || '';
    $('sideStatus').textContent = state.stats?.statusText || '';
    const ab = state.settings?.autoBlockEnabled;
    // Straight from the engine, so it says DRY RUN when nothing is being written.
    const abSummary = state.settings?.autoBlockSummary
      || (ab ? `Auto-block ≥ ${state.settings.autoBlockMinLevel}` : 'Auto-block off');
    $('abPill').textContent = abSummary;
    $('chkAuto').checked = !!ab;
    $('btnAuto').textContent = ab
      ? (state.settings?.preventionDryRun ? 'Auto-block DRY RUN' : 'Auto-block ON')
      : 'Auto-block OFF';
    $('btnLevel').textContent = 'Min: ' + (state.settings?.autoBlockMinLevel || 'High');

    const s = state.stats || {};
    // Same sentence the desktop hero carries, from the same three numbers.
    const highNow = s.highThreats || 0, blockedNow = state.blockedCount || 0;
    $('heroLead').textContent = highNow > 0
      ? `${highNow} high/critical · ${blockedNow} blocked · ${abSummary}`
      : `${blockedNow} IPs blocked · ${abSummary}`;
    $('cards').innerHTML = [
      ['Listening', s.listeningPorts, 'cyan'],
      ['Connections', s.activeConnections, 'cyan'],
      ['Remote hosts', s.remoteHosts, ''],
      ['Threats today', s.threatsToday, 'amber'],
      ['High / critical', s.highThreats, 'danger']
    ].map(([label, val, cls]) => `
      <div class="card">
        <div class="label">${esc(label)}</div>
        <div class="value ${cls}">${esc(val ?? 0)}</div>
      </div>`).join('');

    $('dash-chart').innerHTML = chartHtml(state.activity || []);

    // Threat intensity reads LIVE only while something is actually watching;
    // asleep, the count below it is a leftover, not a measurement.
    const watching = !!(state.settings && state.settings.isMonitoring);
    const pulse = $('intensityPulse');
    pulse.textContent = watching ? 'LIVE' : 'IDLE';
    pulse.classList.toggle('idle', !watching);
    pulse.title = watching
      ? 'Monitoring — high and critical signals are being counted live'
      : 'Asleep — this count is the last one measured';
    $('intensityValue').textContent = s.highThreats ?? 0;

    renderTraffic();

    const threats = state.threats || [];
    $('dash-threats').innerHTML = table(
      ['Time', 'Level', 'Type', 'Source', 'Title', 'Origin'],
      threats.slice(0, 12).map(t => `<tr>
        <td class="mono">${esc(t.time)}</td>
        <td>${badge(t.level)}</td>
        <td>${esc(t.type)}</td>
        <td class="mono">${esc(t.sourceIp)}</td>
        <td>${esc(t.title)}</td>
        <td class="muted">${esc(t.origin)}</td>
      </tr>`).join('')
    );

    const fq = $('filterConn').value.trim();
    const blockable = (ip) => ip && ip !== '0.0.0.0' && ip !== '::' && ip !== '*';
    $('tbl-connections').innerHTML = table(
      ['Proto', 'Local', 'Remote', 'State', 'Process', 'Geo', 'Last', ''],
      (state.connections || []).filter(c => matchFilter(fq, c.protocol, c.local, c.remote, c.state, c.process, c.geo))
        .map(c => `<tr>
          <td>${esc(c.protocol)}</td>
          <td class="mono">${esc(c.local)}</td>
          <td class="mono">${esc(c.remote)}</td>
          <td>${esc(c.state)}</td>
          <td>${esc(c.process)} <span class="muted">#${esc(c.pid)}</span></td>
          <td class="muted">${esc(c.geo)}</td>
          <td class="mono">${esc(c.lastSeen)}</td>
          <td class="row-actions">${blockable(c.remoteAddress)
            ? `<button data-block="${esc(c.remoteAddress)}">Block</button>` : ''}</td>
        </tr>`).join('')
    );

    const hq = $('filterHosts').value.trim();
    $('tbl-hosts').innerHTML = table(
      ['Host', 'Geo', 'Active', 'Total', 'Ports', 'Threat', 'Status', ''],
      (state.hosts || []).filter(h => matchFilter(hq, h.name, h.ip, h.geo, h.threat, h.status))
        .map(h => `<tr>
          <td class="mono">${esc(h.name)}</td>
          <td class="muted">${esc(h.geo)}</td>
          <td>${esc(h.active)}</td>
          <td>${esc(h.total)}</td>
          <td>${esc(h.ports)}</td>
          <td>${badge(h.threat)}</td>
          <td class="${h.blocked ? 'blocked' : 'ok'}">${h.blocked ? 'Blocked' : esc(h.status)}</td>
          <td class="row-actions">
            ${h.blocked
              ? `<button data-unblock="${esc(h.ip)}">Unblock</button>`
              : `<button data-block="${esc(h.ip)}">Block</button>`}
          </td>
        </tr>`).join('')
    );

    const tq = $('filterThreats').value.trim();
    $('tbl-threats').innerHTML = table(
      ['Time', 'Level', 'Type', 'Source', 'Title', 'Detail', 'Origin', ''],
      (state.threats || []).filter(t => matchFilter(tq, t.level, t.type, t.sourceIp, t.title, t.detail, t.origin))
        .map(t => `<tr>
          <td class="mono">${esc(t.time)}</td>
          <td>${badge(t.level)}</td>
          <td>${esc(t.type)}</td>
          <td class="mono">${esc(t.sourceIp)}</td>
          <td>${esc(t.title)}</td>
          <td class="muted">${esc(t.detail)}</td>
          <td class="muted">${esc(t.origin)}</td>
          <td class="row-actions">${blockable(t.sourceIp)
            ? `<button data-block="${esc(t.sourceIp)}">Block</button>` : ''}</td>
        </tr>`).join('')
    );

    $('tbl-ports').innerHTML = table(
      ['Proto', 'Endpoint', 'Process', 'Hint', ''],
      (state.ports || []).map(p => `<tr>
        <td>${esc(p.protocol)}</td>
        <td class="mono">${esc(p.endpoint)}</td>
        <td>${esc(p.process)} <span class="muted">#${esc(p.pid)}</span></td>
        <td class="muted">${esc(p.hint)}</td>
        <td class="row-actions">
          <button class="rm" data-block-port="${esc(p.port)}" data-proto="${esc(p.protocol)}">Block port</button>
        </td>
      </tr>`).join('')
    );

    // Heavy lists: only redraw when forced (tab open, action, manual refresh).
    // Auto-poll never redraws allowlist/firewall — that was resetting scroll every 2s.
    if (forceLists || !isFrozenTab()) {
      const fwScroll = saveScroll('tbl-firewall');
      const alScroll = saveScroll('tbl-allowlist');

      // One row per block: -In/-Out siblings are grouped, and Remove deletes the pair.
      const rules = state.firewallRules || [];
      const groups = new Map();
      rules.forEach((r, i) => {
        const m = /^(.*)-(In|Out)$/i.exec(r.name || '');
        const key = m ? m[1] : (r.name || 'rule-' + i);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(r);
      });
      $('tbl-firewall').innerHTML = table(
        ['Address / target', 'Kind', 'Directions', 'Proto', 'Action', 'Enabled', 'Rule', ''],
        [...groups.values()].map(pair => {
          const r = pair[0];
          const addr = r.address || r.target || '';
          const dirs = pair.map(x => `<span class="chip">${esc(x.direction || '?')}</span>`).join('');
          const baseName = (r.name || '').replace(/-(In|Out)$/i, '');
          const action = pair.some(x => x.isProtected)
            ? `<span class="chip" title="This rule lets your browser reach this console. Removing it would cut off this page. Stop or uninstall the web service instead.">this console</span>`
            : `<button type="button" class="rm" data-rm-rule="${esc(r.name || '')}">Remove</button>`;
          return `<tr>
            <td class="mono"><strong>${esc(addr)}</strong></td>
            <td>${esc(r.kind || '')}</td>
            <td>${dirs}</td>
            <td>${esc(r.protocol || '')}</td>
            <td>${esc(r.action || '')}</td>
            <td>${pair.some(x => x.enabled) ? 'On' : 'Off'}</td>
            <td class="mono muted" style="font-size:.8rem">${esc(baseName)}</td>
            <td class="row-actions">${action}</td>
          </tr>`;
        }).join('') || '<tr><td colspan="8" class="muted">No managed IP/port rules yet.</td></tr>'
      );

      $('allowStatus').textContent = state.allowlistStatus || '';
      const allowRows = (state.allowlist || []).slice().sort((a, b) => {
        const rank = k => k === 'Domain' || k === 'IP' ? 0 : k === 'CIDR' ? 1 : 2;
        return rank(a.kind) - rank(b.kind) || String(a.value).localeCompare(String(b.value));
      });
      $('tbl-allowlist').innerHTML = table(
        ['Kind', 'Value', 'Detail', ''],
        allowRows.map(e => `<tr>
          <td>${esc(e.kind || '')}</td>
          <td class="mono">${esc(e.value || '')}</td>
          <td class="muted">${esc(e.detail || '')}</td>
          <td class="row-actions">${
            (e.kind === 'Domain' || e.kind === 'IP')
              ? `<button type="button" class="rm" data-rm-allow="${esc(e.value || '')}" data-kind="${esc(e.kind || '')}">Remove</button>`
              : '<span class="muted">built-in</span>'
          }</td>
        </tr>`).join('') || '<tr><td colspan="4" class="muted">No allowlist entries loaded.</td></tr>'
      );

      restoreScroll('tbl-firewall', fwScroll);
      restoreScroll('tbl-allowlist', alScroll);
      renderSettings();

      // Never while the editor is open: redrawing the tables is harmless, but the
      // operator is mid-rule and a refresh that reset the form would lose it.
      if ($('ruleEditor').classList.contains('hidden')) {
        const cfgIn = saveScroll('tbl-fwconfig-in');
        const cfgOut = saveScroll('tbl-fwconfig-out');
        renderFirewallConfig();
        restoreScroll('tbl-fwconfig-in', cfgIn);
        restoreScroll('tbl-fwconfig-out', cfgOut);
      }
    }

    // Every state update funnels through here, so this is where the page learns it is
    // asleep — including a reload while asleep, or a sleep triggered from another tab.
    syncSleepMode();
  }

  function notifPermText() {
    if (!('Notification' in window)) return 'This browser does not support notifications.';
    if (Notification.permission === 'granted') return 'Browser permission: granted.';
    if (Notification.permission === 'denied') return 'Browser permission: blocked — allow notifications for this site in your browser settings.';
    return '';
  }

  function renderSettings() {
    const s = state.settings || {};
    const row = (label, desc, control) => `
      <div class="setting-row">
        <div class="info"><h4>${esc(label)}</h4><p>${esc(desc)}</p></div>
        ${control}
      </div>`;
    const sw = (key, checked) =>
      `<label class="switch"><input type="checkbox" data-setting="${key}" ${checked ? 'checked' : ''}/><span class="slider"></span></label>`;
    const txt = (key, value, ph) =>
      `<input type="text" data-setting-text="${key}" value="${esc(String(value ?? ''))}" placeholder="${esc(ph)}" style="min-width:180px"/>`;
    const levelSel = `<select data-set-level>${['Medium', 'High', 'Critical']
      .map(l => `<option ${s.autoBlockMinLevel === l ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
    const refreshSel = `<select data-set-refresh>${[['1000', '1 second'], ['2500', '2.5 seconds'], ['5000', '5 seconds'], ['10000', '10 seconds']]
      .map(([v, l]) => `<option value="${v}" ${String(getRefreshMs()) === v ? 'selected' : ''}>${l}</option>`).join('')}</select>`;

    $('settingsPanel').innerHTML = `
      <div class="settings-group"><h3>Monitoring</h3>
        ${row('Live monitoring', 'Watch connections, listening ports, and threats in real time. Switching this off is the same as the Sleep button in the header — every watcher stops until you wake it again. Firewall blocks stay in force either way.', sw('monitoring', s.isMonitoring))}
        ${row('Page refresh speed', 'How often live tabs (Dashboard, Connections, Hosts…) update in this browser.', refreshSel)}
        ${row('Geo lookups', 'Resolve country and city for remote IPs (ipwho.is, ipapi.co fallback — both over HTTPS).', sw('geoLookupEnabled', s.geoLookupEnabled))}
        ${row('Auth-log monitoring', 'Watch the macOS unified log (sshd, sudo, login, Screen Sharing) for failed logons and alert on brute-force bursts. ' + (s.authLogStatus || ''), sw('authLogMonitorEnabled', s.authLogMonitorEnabled))}
        ${row('Closed-port scan detection', 'Install a PF SYN-log rule and decode pflog0 (needs admin rights) — catches port scans of closed ports that never appear as connections. ' + (s.probeLogStatus || ''), sw('probeLogEnabled', s.probeLogEnabled))}
        ${row('Traffic metering', 'Sample the interface byte counters (netstat -ib) for the dashboard\'s data-flow charts and the monthly in/out history. Physical interfaces only, so VPN and container traffic is counted once. ' + (s.trafficStatus || ''), sw('trafficMeterEnabled', s.trafficMeterEnabled))}
        ${row('Critical threat alerts', 'Badge the tab title and pop a browser notification when a Critical-level threat appears. Your browser asks for notification permission when you switch this on. ' + notifPermText(), sw('criticalAlertsEnabled', s.criticalAlertsEnabled))}
      </div>
      <div class="settings-group"><h3>Intrusion detection</h3>
        ${row('Threat-intel blocklists', 'Check remote IPs against FireHOL level1 and Spamhaus DROP — a match is an instant Critical alert. ' + (s.threatIntelStatus || ''), sw('threatIntelEnabled', s.threatIntelEnabled))}
        ${row('New-listener alerts', 'Alert when a new port starts listening after the baseline, or a known port changes owner process (backdoor signature).', sw('newListenerAlertsEnabled', s.newListenerAlertsEnabled))}
        ${row('Process reputation', 'Flag unsigned/quarantined binaries talking to public hosts, executables in temp/download folders, and shells with outbound connections (reverse-shell signature).', sw('processReputationEnabled', s.processReputationEnabled))}
        ${row('ARP / gateway watch', 'Alert when the default gateway MAC address changes — the standard LAN man-in-the-middle opener. ' + (s.arpWatchStatus || ''), sw('arpWatchEnabled', s.arpWatchEnabled))}
        ${row('Launch-item watch', 'Watch LaunchAgents / LaunchDaemons for new or modified startup items — how malware persists across reboots. ' + (s.launchWatchStatus || ''), sw('launchItemWatchEnabled', s.launchItemWatchEnabled))}
        ${row('Exfiltration monitor', 'Alert when outbound traffic to one non-allowlisted public host exceeds the threshold within 10 minutes (nettop byte counters). ' + (s.exfilStatus || ''), sw('exfilMonitorEnabled', s.exfilMonitorEnabled))}
        ${row('Exfiltration threshold (MB / 10 min)', 'Outbound megabytes to a single host before the alert fires.', txt('exfilMbPer10Min', s.exfilMbPer10Min ?? 250, '250'))}
        ${row('Honeypot decoy ports', 'Listen on decoy TCP ports nothing legitimate uses — any completed connection is a zero-false-positive Critical alert. ' + (s.honeypotStatus || ''), sw('honeypotEnabled', s.honeypotEnabled))}
        ${row('Decoy port list', 'Comma-separated TCP ports to bind as decoys. Ports already in use are skipped.', txt('honeypotPorts', s.honeypotPorts || '', '2323,3389,5900'))}
        ${row('Suricata alerts', 'Ingest Suricata\'s EVE JSON as threat events — signature and payload inspection this app cannot do itself. Install with `brew install suricata`; the console only reads the log. ' + (s.suricataStatus || ''), sw('suricataEnabled', s.suricataEnabled))}
        ${row('Suricata EVE log path', 'Full path to eve.json. Defaults to the Homebrew location for this Mac.', txt('suricataEvePath', s.suricataEvePath || '', '/opt/homebrew/var/log/suricata/eve.json'))}
        ${row('Suricata max severity', 'Highest severity number to accept. Suricata counts down, so 1 is most severe and 3 keeps informational noise out.', txt('suricataMaxSeverity', s.suricataMaxSeverity ?? 3, '3'))}
        ${row('Suricata ignored SIDs', 'Comma-separated signature IDs to drop entirely — the per-rule mute for a known false positive.', txt('suricataIgnoredSids', s.suricataIgnoredSids || '', '2001219,2010935'))}
        ${row('WireGuard peer watch', 'Track WireGuard peers via `wg show` — new peers, handshakes going stale, and per-peer transfer volume. WireGuard\'s unconnected UDP socket is never a tracked connection, so on a VPN server this is the only view of who is attached. Needs root and wireguard-tools. ' + (s.wireGuardStatus || ''), sw('wireGuardMonitorEnabled', s.wireGuardMonitorEnabled))}
        ${row('Per-peer transfer alert (MB / 10 min)', 'Megabytes sent to one peer within 10 minutes before alerting. 0 turns per-peer volume alerts off.', txt('wireGuardPeerMbPer10Min', s.wireGuardPeerMbPer10Min ?? 0, '0'))}
        ${row('PF flow events', 'Read PF\'s state table for flow events — the only view of UDP traffic and of traffic this Mac forwards. Needs PF enabled (`pfctl -e`) and root. ' + (s.flowEventsStatus || ''), sw('flowEventsEnabled', s.flowEventsEnabled))}
        ${row('DNS hygiene', 'Watch how this Mac resolves names: plaintext DNS leaving the machine, encrypted DNS silently falling back to plaintext, queries to resolvers you did not approve, VPN clients bypassing the resolver, and allowlisted domains being poisoned. Needs PF flow events. ' + (s.dnsHygieneStatus || ''), sw('dnsHygieneEnabled', s.dnsHygieneEnabled))}
        ${row('Approved resolvers', 'Comma-separated resolver addresses this Mac is meant to use. Also what identifies a DoH endpoint on port 443 — without this list a DoH setup looks like no DNS at all rather than a leak.', txt('dnsApprovedResolvers', s.dnsApprovedResolvers || '', '1.1.1.1, 9.9.9.9'))}
      </div>
      <div class="settings-group"><h3>Alerting</h3>
        ${row('Webhook URL', 'POST Critical threats to a webhook — ntfy, Slack, and Discord formats are detected automatically; anything else gets generic JSON. Empty = off. ' + (s.webhookStatus && s.webhookUrl ? s.webhookStatus : ''), txt('webhookUrl', s.webhookUrl || '', 'https://ntfy.sh/your-topic'))}
      </div>
      <div class="settings-group"><h3>Remote access</h3>
        <div class="settings-note">${esc(s.httpsStatus || '')}${s.duckDnsStatus ? ' · ' + esc(s.duckDnsStatus) : ''}</div>
        ${row('HTTPS', 'Serve this console over TLS as well as plain HTTP. Needs a certificate below. Takes effect when the web console restarts.', sw('httpsEnabled', s.httpsEnabled))}
        ${row('HTTPS port', 'TCP port for the TLS endpoint (ports below 1024 need root). Forward this port on your router if you want access from outside the LAN.', txt('httpsPort', s.httpsPort ?? 18443, '18443'))}
        ${row('Issue certificate',
          'Get a free trusted Let\'s Encrypt certificate for the DuckDNS name above and fill in the two paths below. Proves control through the saved token, so nothing needs to be reachable on port 80. Takes a few minutes waiting on DNS. The email is used only the first time, to register the account when acme.sh is installed. '
            + (s.certIssueMessage || ''),
          `<input type="text" data-setting-text="acmeEmail" value="${esc(String(s.acmeEmail ?? ''))}" placeholder="you@example.com" style="min-width:180px"/>
           <button type="button" data-issue-cert ${s.certIssueBusy ? 'disabled' : ''}>${s.certIssueBusy ? 'Issuing…' : 'Issue certificate'}</button>`)}
        ${row('Certificate (PEM fullchain or .pfx)', 'Filled in by Issue certificate; edit it if the certificate lives somewhere else.', txt('tlsCertPath', s.tlsCertPath || '', '…/tls/myhost.duckdns.org.fullchain.cer'))}
        ${row('Private key (PEM)', 'Full path to the private key. Leave empty when the certificate is a .pfx bundle.', txt('tlsKeyPath', s.tlsKeyPath || '', '/etc/networksentinel/privkey.key'))}
        ${row('Redirect HTTP to HTTPS', 'Requests that arrive by hostname get sent to the TLS port. Requests to a bare IP stay on HTTP — the certificate only covers the name.', sw('httpsRedirect', s.httpsRedirect))}
        ${row('HTTPS only (turn off plain HTTP)', 'Skip the plain-HTTP listener entirely, so the master password can only cross the wire encrypted. Needs HTTPS on with a working certificate — if the certificate fails to load at startup, plain HTTP stays on so this console is not locked out. Takes effect when the web console restarts.', sw('httpsOnly', s.httpsOnly))}
        ${row('DuckDNS dynamic DNS', 'Keep a free duckdns.org hostname pointed at this machine so it stays reachable when your ISP changes your IP.', sw('duckDnsEnabled', s.duckDnsEnabled))}
        ${row('DuckDNS subdomain', 'Just the label — "myhost" for myhost.duckdns.org.', txt('duckDnsDomain', s.duckDnsDomain || '', 'myhost'))}
        ${row('DuckDNS token', 'Account token from duckdns.org. Stored owner-only on disk and never sent back to this page. ' + (s.duckDnsTokenSet ? 'A token is saved — replace the placeholder to change it, or empty the field to remove it.' : 'No token saved yet.'), txt('duckDnsToken', s.duckDnsTokenSet ? '••••••••' : '', 'paste token'))}
        <div class="settings-note">Exposing this console to the internet gives anyone who guesses the master password control of this Mac's firewall. Prefer a VPN or Tailscale; if you do forward a port, forward only the HTTPS one and use a long unique password.</div>
      </div>
      <div class="settings-group"><h3>Auto-block</h3>
        ${row('Auto-block threats', 'Automatically create firewall rules when threats are detected.', sw('autoBlockEnabled', s.autoBlockEnabled))}
        ${row('Minimum severity', 'Only auto-block threats at or above this level.', levelSel)}
        ${row('Dry run', 'Decide and report auto-blocks without writing any PF rule. Every gate still runs and the status line still names what would have been blocked — the safe way to try a noisy new detection source before letting it drop traffic.', sw('preventionDryRun', s.preventionDryRun))}
        ${row('Block inbound', 'New block rules stop traffic coming in to this machine.', sw('blockInbound', s.blockInbound))}
        ${row('Block outbound', 'New block rules stop traffic going out from this machine.', sw('blockOutbound', s.blockOutbound))}
        ${row('Auto-block expiry (minutes)', 'Automatically remove auto-created block rules after this many minutes (0 = never). Cleanup is silent when possible, otherwise happens at the next firewall change.', txt('autoBlockExpiryMinutes', s.autoBlockExpiryMinutes ?? 0, '0'))}
      </div>
      <div class="settings-group"><h3>Allowlist</h3>
        ${row('Remote allowlist feed', 'Refresh the known-good domain/IP list from the online feed.', sw('allowlistUseRemoteFeed', s.allowlistUseRemoteFeed))}
      </div>
      <div class="settings-group"><h3>Danger zone</h3>
        ${row('Remove all firewall rules',
             'Deletes every Network Sentinel block rule (the access rule for this console is kept) and stops auto-block from re-adding them for 24h.',
             '<button type="button" class="rm-lg" data-remove-all>Remove all rules</button>')}
      </div>`;
  }

  document.getElementById('nav').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    tab = btn.dataset.tab;
    document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.querySelectorAll('main > section').forEach(sec => {
      sec.classList.toggle('hidden', sec.id !== 'tab-' + tab);
    });
    // Freeze live poll on allowlist/firewall so lists stay readable.
    if (isFrozenTab()) {
      stopPolling();
      refreshFrozenTab();
    } else {
      syncSleepMode();
    }
  });

  $('btnSleep').onclick = () => toggleSleep();
  $('btnWakeBanner').onclick = () => toggleSleep(false);
  // true: bypass the bfcache, which would otherwise hand back the very markup
  // this banner exists to replace.
  $('btnReloadPage').onclick = () => location.reload(true);
  $('btnAuto').onclick = () => apiAction('toggle_autoblock');
  // Same action as the header button — render() writes .checked back from the
  // engine, so a refused toggle snaps the box back rather than lying about it.
  $('chkAuto').onchange = () => apiAction('toggle_autoblock');
  $('btnLevel').onclick = () => apiAction('cycle_min_level');
  $('btnAuth').onclick = () => apiAction('authorize');
  $('btnClear').onclick = () => apiAction('clear_threats');
  $('btnLogout').onclick = async () => {
    stopAllTimers();
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    state = null;
    showAuth('login', 'Signed out.');
  };
  $('btnBlock').onclick = () => {
    const ip = $('blockIp').value.trim();
    if (ip) apiAction('block', { ip });
  };
  $('btnUnblock').onclick = () => {
    const ip = $('blockIp').value.trim();
    if (ip) apiAction('unblock', { ip });
  };
  // ── Firewall Config controls ──────────────────────────────────────────────
  (() => {
    const preset = $('rulePreset');
    for (const name of Object.keys(RULE_PRESETS)) {
      const opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name;
      preset.appendChild(opt);
    }
    preset.onchange = () => {
      const p = RULE_PRESETS[preset.value];
      if (!p) return;
      $('ruleProtocol').value = p[0];
      $('rulePorts').value = p[1];
      $('ruleEditorError').textContent = '';
    };
  })();

  $('btnAddInbound').onclick = () => openRuleEditor(null, 'Inbound');
  $('btnAddOutbound').onclick = () => openRuleEditor(null, 'Outbound');
  // Forces a fresh read of pfctl/socketfilterfw/lsof — the cached scan behind
  // /api/state is what keeps the 2.5s poll from shelling out four times a second.
  $('btnRefreshFwCfg').onclick = async () => {
    await apiAction('rescan_firewall');
    refreshFrozenTab();
  };
  $('btnCancelRule').onclick = () => closeRuleEditor();
  $('ruleDirection').onchange = () => updateRuleAddrHint();
  $('trafficRange').onchange = () => { if (state) renderTraffic(); };

  $('btnSaveRule').onclick = async () => {
    const btn = $('btnSaveRule');
    const payload = {
      label: $('ruleLabel').value.trim(),
      ruleAction: $('ruleAction').value,
      direction: $('ruleDirection').value,
      protocol: $('ruleProtocol').value,
      ports: $('rulePorts').value.trim(),
      addresses: $('ruleAddresses').value.trim(),
      replace: editingRuleName || '',
      key: editingRuleKey || ''
    };

    // The blunt ones get a confirm here too. The server refuses anything that would
    // cut this console off, so this only covers the drastic-but-permitted cases.
    if (payload.ruleAction === 'Block' && !payload.ports && !payload.addresses) {
      const side = payload.direction.toLowerCase();
      if (!confirm(`This rule blocks every ${side} connection on every port, from every address.\n\nAdd it anyway?`))
        return;
    }

    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = 'Applying…';
    try {
      const r = await apiAction('save_config_rule', payload);
      if (r.ok) closeRuleEditor();
      else $('ruleEditorError').textContent = r.message || 'The rule was not applied.';
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  };

  $('btnAddAllow').onclick = () => {
    const value = $('allowInput').value.trim();
    if (value) apiAction('add_allowlist', { value }).then(r => { if (r.ok) $('allowInput').value = ''; });
  };
  $('btnRefreshAllow').onclick = async () => {
    await apiAction('refresh_allowlist');
  };
  $('btnRefreshFw').onclick = () => refreshFrozenTab();
  $('btnRestore').onclick = () => apiAction('restore_allowlisted');
  $('btnFwBlockIp').onclick = () => {
    const ip = $('fwIp').value.trim();
    if (ip) apiAction('block', { ip }).then(r => { if (r.ok) $('fwIp').value = ''; });
  };
  $('btnFwBlockPort').onclick = () => {
    const port = $('fwPort').value.trim();
    if (!port) { setStatus('Enter a port number to block.', true); return; }
    apiAction('block_port', { value: port, kind: $('fwProto').value })
      .then(r => { if (r.ok) $('fwPort').value = ''; });
  };
  $('fwIp').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $('btnFwBlockIp').click(); }
  });
  $('fwPort').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $('btnFwBlockPort').click(); }
  });

  $('settingsPanel').addEventListener('change', (e) => {
    const t = e.target;
    if (t.matches('[data-setting]')) {
      const key = t.dataset.setting;
      if (key === 'criticalAlertsEnabled' && t.checked &&
          'Notification' in window && Notification.permission === 'default')
        Notification.requestPermission().then(() => renderSettings());
      if (key === 'monitoring') toggleSleep(!t.checked);
      else apiAction('set_setting', { name: key, value: t.checked ? 'true' : 'false' });
      return;
    }
    if (t.matches('[data-setting-text]')) {
      apiAction('set_setting', { name: t.dataset.settingText, value: t.value.trim() });
      return;
    }
    if (t.matches('[data-set-level]')) { apiAction('set_min_level', { value: t.value }); return; }
    if (t.matches('[data-set-refresh]')) {
      localStorage.setItem('ns-refresh', t.value);
      setStatus('Page refresh speed set to ' + (parseInt(t.value, 10) / 1000) + 's.', false, true);
      statusHoldUntil = Date.now() + 5000;
      if (!isFrozenTab()) startPolling();
    }
  });
  $('settingsPanel').addEventListener('click', async (e) => {
    const issue = e.target.closest('[data-issue-cert]');
    if (issue) {
      issue.disabled = true;
      issue.textContent = 'Issuing…';
      const started = await apiAction('issue_cert');
      // The Settings tab freezes the periodic poll, so drive our own until the
      // run finishes — then redraw to pick up the filled-in certificate paths.
      if (started && started.ok) {
        const tick = setInterval(async () => {
          try {
            if (!(await fetchState())) return;
            if (state.settings && state.settings.certIssueBusy) {
              setStatus(state.settings.certIssueMessage || 'Issuing…', false, false);
              return;
            }
            clearInterval(tick);
            const msg = (state.settings && state.settings.certIssueMessage) || '';
            const ok = !!(state.settings && state.settings.certIssueOk);
            setStatus(msg, !ok, ok);
            statusHoldUntil = Date.now() + 15000;
            render({ forceLists: true });
          } catch { /* keep polling; a transient failure is not the end of the run */ }
        }, 5000);
      } else if (issue.isConnected) {
        issue.disabled = false;
        issue.textContent = 'Issue certificate';
      }
      return;
    }

    const btn = e.target.closest('[data-remove-all]');
    if (!btn) return;
    if (confirm('Remove ALL Network Sentinel firewall rules?\n\nEvery IP and port block will be deleted (the web console access rule is kept). Auto-block will not re-add them for 24 hours.')) {
      btn.disabled = true;
      btn.textContent = 'Removing…';
      apiAction('remove_all_rules').finally(() => {
        if (btn.isConnected) { btn.disabled = false; btn.textContent = 'Remove all rules'; }
      });
    }
  });

  $('changePasswordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = $('pwCurrent').value;
    const newPassword = $('pwNew').value;
    const confirm = $('pwNewConfirm').value;
    const msg = $('pwChangeMsg');
    const btn = $('btnChangePassword');
    msg.textContent = '';
    msg.classList.remove('err', 'ok');
    if (newPassword !== confirm) {
      msg.textContent = 'New passwords do not match.';
      msg.classList.add('err');
      return;
    }
    if (newPassword.length < 8) {
      msg.textContent = 'New password must be at least 8 characters.';
      msg.classList.add('err');
      return;
    }
    btn.disabled = true;
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword, confirm })
      });
      if (res.status === 401) {
        stopAllTimers();
        showAuth('login', 'Session expired. Sign in again.');
        return;
      }
      const data = await res.json().catch(() => ({ ok: false, message: 'Bad response' }));
      if (!res.ok || !data.ok) {
        msg.textContent = data.message || 'Could not update password.';
        msg.classList.add('err');
        return;
      }
      $('pwCurrent').value = '';
      $('pwNew').value = '';
      $('pwNewConfirm').value = '';
      msg.textContent = data.message || 'Master password updated.';
      msg.classList.add('ok');
      statusHoldUntil = Date.now() + 10000;
      setStatus(data.message || 'Master password updated.', false, true);
    } catch (err) {
      msg.textContent = err.message || String(err);
      msg.classList.add('err');
    } finally {
      btn.disabled = false;
    }
  });

  $('allowInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $('btnAddAllow').click(); }
  });

  document.body.addEventListener('click', (e) => {
    const b = e.target.closest('[data-block]');
    if (b) { apiAction('block', { ip: b.dataset.block }); return; }
    const u = e.target.closest('[data-unblock]');
    if (u) { apiAction('unblock', { ip: u.dataset.unblock }); return; }
    const r = e.target.closest('[data-rm-allow]');
    if (r) {
      apiAction('remove_allowlist', { value: r.dataset.rmAllow, kind: r.dataset.kind });
      return;
    }
    const bp = e.target.closest('[data-block-port]');
    if (bp) {
      const port = bp.dataset.blockPort;
      const proto = bp.dataset.proto || 'TCP';
      if (confirm(`Block inbound ${proto} port ${port}?\n\nThis firewalls the local service listening on that port for everyone, including LAN clients.`))
        apiAction('block_port', { value: port, kind: proto, direction: 'Inbound' });
      return;
    }
    const pr = e.target.closest('[data-portrule]');
    if (pr) {
      openRuleEditorForPort(pr.dataset.portrule, pr.dataset.proto || 'TCP',
                            pr.dataset.endpoint || '', pr.dataset.process || '');
      return;
    }
    const er = e.target.closest('[data-editrule]');
    if (er) {
      const key = (er.dataset.editrule || '').trim();
      const rule = (state.configRules || []).find(x => x.key === key);
      if (rule) openRuleEditor(rule, rule.inbound ? 'Inbound' : 'Outbound');
      return;
    }
    const dr = e.target.closest('[data-delrule]');
    if (dr) {
      const key = (dr.dataset.delrule || '').trim();
      const rule = (state.configRules || []).find(x => x.key === key);
      if (!rule) { setStatus('Could not read the rule from the row.', true); return; }
      let warn = '';
      if (rule.isForeign) {
        warn = `\n\nThis rule belongs to ${rule.origin}, not to Network Sentinel. ` +
               'Deleting it removes it from the host firewall for good.';
      } else if (!rule.isCustom) {
        warn = `\n\nThis rule came from ${rule.origin.toLowerCase()}. Deleting it unblocks that traffic ` +
               'until something detects it again.';
      }
      if (rule.action === 'Allow' && /\b22\b/.test(rule.ports || '')) {
        warn += '\n\nThis is the rule that allows SSH — deleting it can end the session you administer ' +
                'this host with.';
      }
      const detail = `${rule.action} · ${rule.direction} · ${rule.protocol} · ${rule.ports} · ${rule.addresses}`;
      if (confirm(`Delete "${rule.label}"?\n\n${detail}${warn}\n\n(Requires root, or sudo without a password)`)) {
        dr.disabled = true;
        dr.textContent = 'Deleting…';
        apiAction('delete_host_rule', { key }).finally(() => {
          if (dr.isConnected) { dr.disabled = false; dr.textContent = 'Delete'; }
        });
      }
      return;
    }
    const fr = e.target.closest('[data-rm-rule]');
    if (fr) {
      // Prefer dataset (decoded) over getAttribute (may still contain entities).
      const name = (fr.dataset.rmRule || fr.getAttribute('data-rm-rule') || '').trim();
      if (!name) {
        setStatus('Could not read rule name from the row.', true);
        return;
      }
      const base = name.replace(/-(In|Out)$/i, '');
      if (confirm('Remove this block (inbound + outbound)?\n\n' + base + '\n\n(Requires root or admin rights)')) {
        fr.disabled = true;
        fr.textContent = 'Removing…';
        apiAction('remove_rule', { value: name, name: name }).finally(() => {
          // Re-render usually replaced the button; restore it if the row survived (failure).
          if (fr.isConnected) { fr.disabled = false; fr.textContent = 'Remove'; }
        });
      }
    }
  });

  ['filterConn', 'filterHosts', 'filterThreats'].forEach(id => {
    $(id).addEventListener('input', () => {
      if (state && !isFrozenTab()) render({ forceLists: true });
    });
  });

  $('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = $('pw').value;
    const confirm = $('pwConfirm').value;
    const setup = authMode === 'setup';
    $('authError').textContent = '';
    $('authSubmit').disabled = true;
    try {
      const res = await fetch(setup ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(setup ? { password, confirm, setupCode: $('setupCode').value } : { password })
      });
      const data = await res.json().catch(() => ({ ok: false, message: 'Bad response' }));
      if (!res.ok || !data.ok) {
        $('authError').textContent = data.message || 'Authentication failed.';
        return;
      }
      showAuth('ok');
      startPolling();
    } catch (err) {
      $('authError').textContent = err.message || String(err);
    } finally {
      $('authSubmit').disabled = false;
    }
  });

  (async () => {
    if (await ensureAuth()) startPolling();
  })();
})();
</script>
</body>
</html>
""";
}
