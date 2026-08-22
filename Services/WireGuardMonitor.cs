using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.Json;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>One WireGuard peer as reported by <c>wg show</c>. Never carries key material beyond the public key.</summary>
public sealed class WireGuardPeer
{
    public required string Interface { get; init; }

    /// <summary>The peer's public key. Public by definition — the private and preshared keys are never read into this object.</summary>
    public required string PublicKey { get; init; }

    /// <summary>"ip:port" as reported, or empty when the peer has never connected.</summary>
    public string Endpoint { get; init; } = "";

    /// <summary>Address part of <see cref="Endpoint"/>, for geo enrichment and display.</summary>
    public string EndpointIp { get; init; } = "";

    public string AllowedIps { get; init; } = "";
    public DateTime? LastHandshake { get; init; }
    public long TransferRx { get; init; }
    public long TransferTx { get; init; }

    /// <summary>Truncated key for table display — a full key is 44 characters and swamps a row.</summary>
    public string ShortKey => PublicKey.Length > 12 ? PublicKey[..12] + "…" : PublicKey;

    public string HandshakeText => LastHandshake is { } h
        ? $"{(DateTime.Now - h).TotalMinutes:0} min ago"
        : "never";
}

/// <summary>
/// Watches WireGuard peers via <c>wg show all dump</c>.
///
/// WireGuard is invisible to the rest of this app. It uses a single *unconnected*
/// UDP socket, so <see cref="Native.LinuxNetTable"/> files it as a listener with no
/// peer (see the remote-address test in ReadUdp) and no VPN client ever becomes a
/// tracked connection. Nothing reaches the intrusion heuristics, the remote-host
/// list, threat intel, or the prevention engine. On a VPN server that is a hole
/// straight through the middle of the monitoring: peers come and go, endpoints move
/// continents, and traffic flows, with none of it visible.
///
/// This closes that hole by reading WireGuard's own state:
///   - a peer public key that was not in the baseline (someone was granted access)
///   - a known peer's endpoint moving to a different address (roaming, or a stolen key)
///   - a peer disappearing from the config
///   - optionally, how much data went to one peer — an accounting note rather than a
///     finding: forwarded tunnel traffic has no local socket, so nothing else counts it
///     at all, but volume through a tunnel is the tunnel doing its job
///
/// Key material: `wg show ... dump` prints the interface PRIVATE key and each peer's
/// preshared key. Those fields are dropped at parse time and never stored, logged,
/// surfaced in a threat, or sent to a webhook. Only public keys leave this class.
///
/// Requires root — `wg show` cannot read device state otherwise. The
/// monitor degrades to an explanatory <see cref="Status"/> rather than failing.
/// </summary>
public sealed class WireGuardMonitor : IDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan TransferWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EndpointCooldown = TimeSpan.FromMinutes(5);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.Ordinal);

    /// <summary>public key → last endpoint seen, persisted so a restart is not a clean slate.</summary>
    private Dictionary<string, string> _baseline = new(StringComparer.Ordinal);

    /// <summary>public key → rolling window of (time, bytes sent to that peer).</summary>
    private readonly Dictionary<string, Queue<(DateTime Time, long Bytes)>> _txWindow = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _lastTx = new(StringComparer.Ordinal);

    private IReadOnlyList<WireGuardPeer> _peers = Array.Empty<WireGuardPeer>();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _firstPass = true;
    private volatile string _status = "WireGuard monitoring not started";

    /// <summary>
    /// Megabytes sent to a single peer within 10 minutes before it is noted. 0 disables it.
    /// Off by default, and informational when on: a VPN user streaming video legitimately
    /// moves gigabytes, so any threshold low enough to catch a slow leak would fire
    /// constantly on normal use. What comes out is a volume notice at the figure you
    /// picked, not a judgement that the traffic was wrong.
    /// </summary>
    public int TransferMbPer10Min { get; set; }

    public string Status => _status;

    /// <summary>Current peers, newest handshake first. Safe to read from any thread.</summary>
    public IReadOnlyList<WireGuardPeer> Peers
    {
        get { lock (_gate) return _peers; }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            LoadBaseline();
            _loop = Task.Run(() => RunAsync(ct), ct);
        }
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        Task? loop;
        lock (_gate)
        {
            cts = _cts;
            loop = _loop;
            _cts = null;
            _loop = null;
        }
        if (cts == null) return;

        cts.Cancel();
        try { loop?.Wait(2000); } catch { /* shutting down */ }
        cts.Dispose();
        SaveBaseline();
        _status = "WireGuard monitoring stopped";
    }

    /// <summary>Returns peer threats raised since the last drain (called from the monitor poll loop).</summary>
    public IReadOnlyList<ThreatEvent> DrainPending()
    {
        lock (_gate)
        {
            if (_pending.Count == 0) return Array.Empty<ThreatEvent>();
            var list = _pending.ToList();
            _pending.Clear();
            return list;
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                SampleOnce(DateTime.Now);
            }
            catch (Exception ex)
            {
                _status = $"WireGuard monitoring error: {ex.Message}";
            }

            try { await Task.Delay(SampleInterval, ct); }
            catch (OperationCanceledException) { return; }
        }
    }

    private void SampleOnce(DateTime now)
    {
        if (!TryRunWgDump(out var output, out var error))
        {
            _status = error;
            return;
        }

        var peers = ParseDump(output);

        lock (_gate)
        {
            _peers = peers
                .OrderByDescending(p => p.LastHandshake ?? DateTime.MinValue)
                .ToList();

            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var peer in peers)
            {
                seen.Add(peer.PublicKey);

                if (!_baseline.TryGetValue(peer.PublicKey, out var knownEndpoint))
                {
                    _baseline[peer.PublicKey] = peer.Endpoint;
                    // The first run after install adopts the existing config silently;
                    // alerting on every configured peer would just train people to ignore this.
                    if (!_firstPass)
                        AddNewPeerThreat(peer, now);
                    continue;
                }

                if (!string.IsNullOrEmpty(peer.Endpoint) && knownEndpoint != peer.Endpoint)
                {
                    _baseline[peer.PublicKey] = peer.Endpoint;
                    if (!string.IsNullOrEmpty(knownEndpoint))
                        AddEndpointChangeThreat(peer, knownEndpoint, now);
                }

                if (TransferMbPer10Min > 0)
                    TrackTransfer(peer, now);
            }

            foreach (var gone in _baseline.Keys.Where(k => !seen.Contains(k)).ToList())
            {
                _baseline.Remove(gone);
                _txWindow.Remove(gone);
                _lastTx.Remove(gone);
                if (!_firstPass)
                    AddPeerRemovedThreat(gone, now);
            }

            _firstPass = false;
            var active = peers.Count(p => p.LastHandshake is { } h && now - h < TimeSpan.FromMinutes(5));
            _status = $"Watching {peers.Count} WireGuard peer(s), {active} active in the last 5 min";
        }

        SaveBaseline();
    }

    private void AddNewPeerThreat(WireGuardPeer peer, DateTime now)
    {
        if (!TryNoteEmit($"new|{peer.PublicKey}", now, EmitCooldown)) return;

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.VpnPeerChange,
            Level = ThreatLevel.High,
            // Endpoint IP where known, so the existing geo enrichment can fill Origin in.
            SourceIp = string.IsNullOrEmpty(peer.EndpointIp) ? "127.0.0.1" : peer.EndpointIp,
            Title = $"New WireGuard peer on {peer.Interface}: {peer.ShortKey}",
            Detail = $"Public key {peer.PublicKey} was added to {peer.Interface} " +
                     $"(allowed IPs {Describe(peer.AllowedIps)}, endpoint {Describe(peer.Endpoint)}). " +
                     "A peer entry grants standing access to this network. If you did not add it, " +
                     "someone with root has edited the WireGuard configuration.",
            Origin = string.IsNullOrEmpty(peer.EndpointIp) ? "This computer" : "Resolving…",
            Method = "WireGuard peer baseline diff"
        });
    }

    private void AddEndpointChangeThreat(WireGuardPeer peer, string previousEndpoint, DateTime now)
    {
        if (!TryNoteEmit($"endpoint|{peer.PublicKey}", now, EndpointCooldown)) return;

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.VpnPeerChange,
            // Roaming between wifi and cellular is ordinary WireGuard behaviour, so this
            // is informational on its own. The geo lookup patched into Origin is what
            // makes it worth reading: the same key appearing from another country is not
            // roaming, it is a key in someone else's hands.
            Level = ThreatLevel.Low,
            SourceIp = string.IsNullOrEmpty(peer.EndpointIp) ? "127.0.0.1" : peer.EndpointIp,
            Title = $"WireGuard peer {peer.ShortKey} moved endpoint",
            Detail = $"Peer {peer.PublicKey} on {peer.Interface} changed endpoint from " +
                     $"{previousEndpoint} to {peer.Endpoint}. Normal when a client roams between " +
                     "networks; check the location if the peer should be stationary.",
            Origin = string.IsNullOrEmpty(peer.EndpointIp) ? "This computer" : "Resolving…",
            Method = "WireGuard endpoint change"
        });
    }

    private void AddPeerRemovedThreat(string publicKey, DateTime now)
    {
        if (!TryNoteEmit($"removed|{publicKey}", now, EmitCooldown)) return;

        var shortKey = publicKey.Length > 12 ? publicKey[..12] + "…" : publicKey;
        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.VpnPeerChange,
            Level = ThreatLevel.Low,
            SourceIp = "127.0.0.1",
            Title = $"WireGuard peer removed: {shortKey}",
            Detail = $"Public key {publicKey} is no longer configured. Expected after revoking " +
                     "access; unexpected removals mean the WireGuard configuration changed underneath you.",
            Origin = "This computer",
            Method = "WireGuard peer baseline diff"
        });
    }

    /// <summary>
    /// Rolling window of bytes sent to one peer. This is the only view of data leaving
    /// through the tunnel — ExfiltrationMonitor reads per-socket counters, and forwarded
    /// VPN traffic has no local socket to count. Counting it is worth doing; calling the
    /// result exfiltration is not, which is why what it emits is Info.
    /// </summary>
    private void TrackTransfer(WireGuardPeer peer, DateTime now)
    {
        if (!_txWindow.TryGetValue(peer.PublicKey, out var window))
        {
            window = new Queue<(DateTime, long)>();
            _txWindow[peer.PublicKey] = window;
        }

        if (_lastTx.TryGetValue(peer.PublicKey, out var previous))
        {
            // Counters reset when the interface restarts; a negative delta is a reset, not traffic.
            var delta = peer.TransferTx - previous;
            if (delta > 0)
                window.Enqueue((now, delta));
        }
        _lastTx[peer.PublicKey] = peer.TransferTx;

        while (window.Count > 0 && now - window.Peek().Time > TransferWindow)
            window.Dequeue();

        var total = window.Sum(e => e.Bytes);
        var thresholdBytes = (long)TransferMbPer10Min * 1_000_000;
        if (total < thresholdBytes)
            return;

        if (!TryNoteEmit($"transfer|{peer.PublicKey}", now, EmitCooldown))
            return;

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.VpnPeerChange,
            // Not exfiltration, and not High. Bytes to a peer are what a tunnel is for: a
            // client pulling a backup or streaming looks exactly like a leak from here,
            // because all this counter sees is encrypted volume. Filing it as a High
            // DataExfiltration also aimed a threat at the peer's endpoint — the one
            // address the prevention engine must never block, and the reason
            // IsWireGuardPeerEndpoint is wired into it. So: an observation, at the
            // figure the operator asked to hear about.
            Level = ThreatLevel.Info,
            SourceIp = string.IsNullOrEmpty(peer.EndpointIp) ? "127.0.0.1" : peer.EndpointIp,
            Title = $"WireGuard peer {peer.ShortKey} moved {total / 1_000_000} MB",
            Detail = $"{total / 1_000_000} MB sent to peer {peer.PublicKey} on {peer.Interface} " +
                     $"in the last {TransferWindow.TotalMinutes:0} minutes, past the {TransferMbPer10Min} MB " +
                     "figure this notice was set to. Ordinary for a tunnel in use — worth reading only if " +
                     "that peer should have been idle. Forwarded VPN traffic has no local socket, so " +
                     "this is the only place it is counted.",
            Origin = string.IsNullOrEmpty(peer.EndpointIp) ? "This computer" : "Resolving…",
            Method = "WireGuard per-peer transfer counter"
        });
    }

    private bool TryNoteEmit(string key, DateTime now, TimeSpan cooldown)
    {
        if (_lastEmit.TryGetValue(key, out var last) && now - last < cooldown)
            return false;
        _lastEmit[key] = now;
        return true;
    }

    private bool TryRunWgDump(out string output, out string error)
    {
        output = "";
        error = "";
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = ResolveWgPath(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            psi.ArgumentList.Add("show");
            psi.ArgumentList.Add("all");
            psi.ArgumentList.Add("dump");

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                error = "Could not start `wg` — install wireguard-tools (`brew install wireguard-tools`)";
                return false;
            }

            // Both pipes drained concurrently. Reading stdout to EOF first deadlocks
            // when the child fills the stderr buffer, and the blocked read means the
            // WaitForExit timeout below never engages — the same bug fixed across the
            // other spawn sites; this file arrived with it.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(5000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                error = "`wg show` timed out";
                return false;
            }

            output = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();

            if (proc.ExitCode != 0)
            {
                error = stderr.Contains("permitted", StringComparison.OrdinalIgnoreCase) ||
                        stderr.Contains("denied", StringComparison.OrdinalIgnoreCase)
                    ? "WireGuard peer monitoring needs root — run the console as root"
                    : $"`wg show` failed: {FirstLine(stderr)}";
                return false;
            }

            if (string.IsNullOrWhiteSpace(output))
            {
                error = "No WireGuard interfaces are up";
                return false;
            }

            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            error = "`wg` not found — install wireguard-tools (`brew install wireguard-tools`) to monitor peers";
            return false;
        }
        catch (Exception ex)
        {
            error = $"WireGuard peer monitoring failed: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Absolute path to `wg`, because PATH is not dependable here: an app launched from
    /// Finder or by launchd does not inherit the shell PATH that puts Homebrew on it, so
    /// a bare "wg" resolves only when the console was started from a terminal. Falls back
    /// to the bare name so a custom install on PATH still works.
    /// </summary>
    private static string ResolveWgPath()
    {
        string[] candidates =
        [
            "/opt/homebrew/bin/wg",   // Apple Silicon Homebrew
            "/usr/local/bin/wg",      // Intel Homebrew
            "/usr/bin/wg"
        ];

        foreach (var candidate in candidates)
        {
            try
            {
                if (File.Exists(candidate))
                    return candidate;
            }
            catch
            {
                // Unreadable path — keep looking.
            }
        }

        return "wg";
    }

    /// <summary>
    /// Parses `wg show all dump`. Internal for tests / replaying captured output.
    ///
    /// Device lines have 5 tab-separated fields, peer lines have 9. Field 1 of a device
    /// line is the interface PRIVATE key and field 2 of a peer line is the PRESHARED key;
    /// both are deliberately never read into a variable.
    /// </summary>
    internal static List<WireGuardPeer> ParseDump(string output)
    {
        var peers = new List<WireGuardPeer>();
        if (string.IsNullOrWhiteSpace(output)) return peers;

        foreach (var line in output.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var f = line.TrimEnd('\r').Split('\t');

            // 5 fields = interface line (iface, private key, public key, port, fwmark). Skipped:
            // it carries the private key and no peer information.
            if (f.Length != 9) continue;

            var iface = f[0];
            var publicKey = f[1];
            // f[2] is the preshared key — intentionally not read.
            var endpoint = Clean(f[3]);
            var allowedIps = Clean(f[4]);

            if (string.IsNullOrEmpty(publicKey) || publicKey == "(none)") continue;

            DateTime? handshake = null;
            if (long.TryParse(f[5], out var epoch) && epoch > 0)
                handshake = DateTimeOffset.FromUnixTimeSeconds(epoch).ToLocalTime().DateTime;

            long.TryParse(f[6], out var rx);
            long.TryParse(f[7], out var tx);

            peers.Add(new WireGuardPeer
            {
                Interface = iface,
                PublicKey = publicKey,
                Endpoint = endpoint,
                EndpointIp = ExtractIp(endpoint),
                AllowedIps = allowedIps,
                LastHandshake = handshake,
                TransferRx = rx,
                TransferTx = tx
            });
        }

        return peers;
    }

    /// <summary>Splits "1.2.3.4:51820" or "[2001:db8::1]:51820" into its address part.</summary>
    internal static string ExtractIp(string endpoint)
    {
        if (string.IsNullOrEmpty(endpoint)) return "";

        if (endpoint.StartsWith('['))
        {
            var close = endpoint.IndexOf(']');
            return close > 1 ? endpoint[1..close] : "";
        }

        var colon = endpoint.LastIndexOf(':');
        var host = colon > 0 ? endpoint[..colon] : endpoint;
        return IPAddress.TryParse(host, out _) ? host : "";
    }

    private static string Clean(string value)
        => value is "(none)" or "off" ? "" : value.Trim();

    private static string Describe(string value)
        => string.IsNullOrEmpty(value) ? "none" : value;

    private static string FirstLine(string text)
    {
        var line = text.Split('\n').FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
        return string.IsNullOrWhiteSpace(line) ? "unknown error" : line.Trim();
    }

    private static string BaselinePath => Path.Combine(AppPaths.DataDirectory, "wireguard-peers.json");

    /// <summary>
    /// Only public keys and endpoints are persisted — the dump's private and preshared
    /// keys never reach this method, so the state file can never leak them.
    /// </summary>
    private void LoadBaseline()
    {
        try
        {
            if (!File.Exists(BaselinePath))
            {
                _firstPass = true;
                return;
            }

            var json = File.ReadAllText(BaselinePath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (loaded is { Count: > 0 })
            {
                _baseline = new Dictionary<string, string>(loaded, StringComparer.Ordinal);
                // A known baseline means a new key really is new, not just the first look.
                _firstPass = false;
            }
        }
        catch
        {
            _firstPass = true;
        }
    }

    private void SaveBaseline()
    {
        try
        {
            Dictionary<string, string> snapshot;
            lock (_gate) snapshot = new Dictionary<string, string>(_baseline, StringComparer.Ordinal);
            AppPaths.WriteAtomic(BaselinePath, JsonSerializer.Serialize(snapshot));
        }
        catch
        {
            // best-effort persistence, same as the other stores
        }
    }

    public void Dispose() => Stop();
}
