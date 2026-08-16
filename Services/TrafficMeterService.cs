using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Measures how much data crosses this Mac's network interfaces, in each
/// direction, and keeps a per-day history so the dashboard can show the month.
///
/// The source is <c>netstat -ib</c>: cumulative per-interface byte counters the
/// kernel maintains, readable without root and without a packet capture. Each
/// sample is diffed against the previous one, so the meter reports traffic, not
/// the counter value.
///
/// Three details the numbers depend on:
///   - <b>One row per interface.</b> netstat prints an interface once per address
///     it holds, repeating the same totals on every row. Only the
///     <c>&lt;Link#n&gt;</c> row is counted; summing all of them would multiply
///     a dual-stack interface's traffic by four or five.
///   - <b>Physical interfaces only.</b> A VPN's utun carries the same bytes that
///     already crossed en0, encapsulated — counting both double-counts every
///     tunnelled byte. Loopback is excluded for the same reason it is excluded
///     from the connection views: it never leaves the machine.
///   - <b>Counters reset.</b> A reboot or an interface bounce restarts them at
///     zero. A counter that moved backwards is treated as a fresh start and its
///     current value is the delta, matching <see cref="ExfiltrationMonitor"/>.
///
/// The daily history persists to <c>traffic-history.json</c>, and so do the last
/// raw counters: on the next launch the diff continues from where it left off,
/// so traffic that crossed the wire while the console was closed still lands in
/// the right day rather than vanishing or arriving as one huge spike.
/// </summary>
public sealed class TrafficMeterService : IDisposable
{
    /// <summary>
    /// Sample cadence. Fast enough for a live rate chart, slow enough that one
    /// short-lived subprocess every few seconds stays invisible.
    /// </summary>
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(5);

    /// <summary>Live samples retained — 120 × 5 s is the last 10 minutes.</summary>
    private const int LiveSampleCap = 120;

    /// <summary>
    /// Days of history kept. 400 covers a 12-month chart plus the running month
    /// with room for the rollover.
    /// </summary>
    private const int RetentionDays = 400;

    /// <summary>
    /// How often the history file is rewritten. Every sample would be a disk
    /// write every 5 s for a file only the charts read; a minute of lost history
    /// after a crash is not worth that.
    /// </summary>
    private static readonly TimeSpan SaveInterval = TimeSpan.FromMinutes(1);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly object _gate = new();
    private readonly List<TrafficSample> _live = new();
    private readonly Dictionary<string, DayTotal> _days = new(StringComparer.Ordinal);
    private readonly Dictionary<string, InterfaceCounter> _counters = new(StringComparer.Ordinal);

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _firstSampleOfRun = true;
    private DateTime _lastSampleTime;
    private DateTime _lastSaveUtc = DateTime.MinValue;
    private volatile string _status = "Traffic meter not started";
    private volatile bool _loaded;

    /// <summary>Raised after each sample so the UI can redraw off the meter's cadence.</summary>
    public event Action? Updated;

    public string Status => _status;

    public bool IsRunning => _loop != null;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            LoadHistory();
            // A restart after the meter was switched off has the same gap as a
            // restart of the app: count the catch-up, do not chart it as a rate.
            _firstSampleOfRun = true;
            _lastSampleTime = default;
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Reading interface byte counters (netstat)";
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }
        if (cts == null) return;

        cts.Cancel();
        try { _loop?.Wait(2000); } catch { /* shutting down */ }
        cts.Dispose();
        _loop = null;
        SaveHistory();
        _status = "Traffic meter stopped";
    }

    /// <summary>Recent throughput readings, oldest first.</summary>
    public IReadOnlyList<TrafficSample> Live
    {
        get { lock (_gate) return _live.ToList(); }
    }

    /// <summary>Bytes in/out so far in the calendar month containing <paramref name="anyDayInMonth"/>.</summary>
    public TrafficBucket MonthTotal(DateTime anyDayInMonth)
    {
        var start = new DateTime(anyDayInMonth.Year, anyDayInMonth.Month, 1);
        long inBytes = 0, outBytes = 0;
        lock (_gate)
        {
            foreach (var (key, total) in _days)
            {
                if (!TryParseDayKey(key, out var day)) continue;
                if (day.Year == start.Year && day.Month == start.Month)
                {
                    inBytes += total.In;
                    outBytes += total.Out;
                }
            }
        }

        return new TrafficBucket
        {
            Start = start,
            Label = start.ToString("MMMM yyyy"),
            BytesIn = inBytes,
            BytesOut = outBytes
        };
    }

    /// <summary>
    /// One bucket per day of the given month, zero-filled through today (or
    /// through the last day, for a month already past) so the chart keeps a
    /// stable x-axis instead of stretching two samples across the card.
    /// </summary>
    public IReadOnlyList<TrafficBucket> DailyBuckets(DateTime anyDayInMonth)
    {
        var start = new DateTime(anyDayInMonth.Year, anyDayInMonth.Month, 1);
        var today = DateTime.Today;
        var lastDay = start.Year == today.Year && start.Month == today.Month
            ? today.Day
            : DateTime.DaysInMonth(start.Year, start.Month);

        var buckets = new List<TrafficBucket>(lastDay);
        lock (_gate)
        {
            for (var day = 1; day <= lastDay; day++)
            {
                var date = start.AddDays(day - 1);
                _days.TryGetValue(DayKey(date), out var total);
                buckets.Add(new TrafficBucket
                {
                    Start = date,
                    Label = day.ToString(CultureInfo.InvariantCulture),
                    BytesIn = total.In,
                    BytesOut = total.Out
                });
            }
        }
        return buckets;
    }

    /// <summary>One bucket per calendar month, ending with the current month.</summary>
    public IReadOnlyList<TrafficBucket> MonthlyBuckets(int months)
    {
        months = Math.Clamp(months, 1, 24);
        var first = new DateTime(DateTime.Today.Year, DateTime.Today.Month, 1).AddMonths(-(months - 1));
        var totals = new Dictionary<DateTime, (long In, long Out)>();

        lock (_gate)
        {
            foreach (var (key, total) in _days)
            {
                if (!TryParseDayKey(key, out var day)) continue;
                var month = new DateTime(day.Year, day.Month, 1);
                if (month < first) continue;
                totals.TryGetValue(month, out var running);
                totals[month] = (running.In + total.In, running.Out + total.Out);
            }
        }

        var buckets = new List<TrafficBucket>(months);
        for (var i = 0; i < months; i++)
        {
            var month = first.AddMonths(i);
            totals.TryGetValue(month, out var total);
            buckets.Add(new TrafficBucket
            {
                Start = month,
                // Single letter would collide (June/July); "Jun" fits the axis.
                Label = month.ToString("MMM"),
                BytesIn = total.In,
                BytesOut = total.Out
            });
        }
        return buckets;
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
                _status = $"Traffic meter error: {ex.Message}";
            }

            try { Updated?.Invoke(); }
            catch { /* a bad handler must not kill the loop */ }

            try { await Task.Delay(SampleInterval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void SampleOnce(DateTime now)
    {
        var output = RunNetstat();
        if (output == null)
        {
            _status = "netstat unavailable — traffic metering off";
            return;
        }

        var current = ParseInterfaceCounters(output);
        if (current.Count == 0)
        {
            _status = "No physical interfaces reporting byte counters";
            return;
        }

        long deltaIn = 0, deltaOut = 0;
        var first = false;

        lock (_gate)
        {
            foreach (var (name, counter) in current)
            {
                if (_counters.TryGetValue(name, out var previous))
                {
                    deltaIn += Delta(previous.In, counter.In);
                    deltaOut += Delta(previous.Out, counter.Out);
                }
                else
                {
                    // An interface seen for the first time in this run has no
                    // baseline to diff against; the next sample is its first
                    // contribution. (A persisted baseline is loaded up front, so
                    // this is a genuinely new interface, not a fresh launch.)
                    first = true;
                }
                _counters[name] = counter;
            }

            // Interfaces that disappeared (VPN down, dock unplugged) are dropped so
            // their stale counters cannot be diffed against a later, unrelated one.
            foreach (var gone in _counters.Keys.Where(k => !current.ContainsKey(k)).ToList())
                _counters.Remove(gone);

            var elapsed = _lastSampleTime == default
                ? SampleInterval
                : now - _lastSampleTime;
            _lastSampleTime = now;

            if (deltaIn > 0 || deltaOut > 0)
                AddToDay(now, deltaIn, deltaOut);

            // The first delta of a run spans however long the console was closed —
            // the persisted counters make that traffic countable, but dividing it by
            // the sample interval would draw a multi-megabyte-per-second spike that
            // never happened, and the shared scale would flatten every real reading
            // after it. It counts toward the day; it does not become a rate.
            var seconds = Math.Max(0.5, elapsed.TotalSeconds);
            _live.Add(new TrafficSample
            {
                Time = now,
                BytesInPerSecond = _firstSampleOfRun ? 0 : deltaIn / seconds,
                BytesOutPerSecond = _firstSampleOfRun ? 0 : deltaOut / seconds
            });
            _firstSampleOfRun = false;
            if (_live.Count > LiveSampleCap)
                _live.RemoveRange(0, _live.Count - LiveSampleCap);

            TrimHistory();
        }

        var month = MonthTotal(now);
        _status = first
            ? $"Metering {current.Count} interface(s) — baselining"
            : $"Metering {current.Count} interface(s) · {month.Label}: {month.InText} in / {month.OutText} out";

        if (DateTime.UtcNow - _lastSaveUtc >= SaveInterval)
            SaveHistory();
    }

    /// <summary>Caller holds <see cref="_gate"/>.</summary>
    private void AddToDay(DateTime when, long bytesIn, long bytesOut)
    {
        var key = DayKey(when);
        _days.TryGetValue(key, out var total);
        _days[key] = new DayTotal(total.In + bytesIn, total.Out + bytesOut);
    }

    /// <summary>Caller holds <see cref="_gate"/>.</summary>
    private void TrimHistory()
    {
        if (_days.Count <= RetentionDays) return;
        var cutoff = DateTime.Today.AddDays(-RetentionDays);
        foreach (var key in _days.Keys.ToList())
        {
            if (TryParseDayKey(key, out var day) && day < cutoff)
                _days.Remove(key);
            else if (!TryParseDayKey(key, out _))
                _days.Remove(key); // hand-edited garbage
        }
    }

    /// <summary>
    /// A counter that went backwards restarted (reboot, interface bounce), so the
    /// current value is itself the traffic since the reset.
    /// </summary>
    internal static long Delta(long previous, long current)
        => current >= previous ? current - previous : Math.Max(0, current);

    /// <summary>
    /// Parses <c>netstat -ib</c> into one entry per physical interface. Internal
    /// so the suite can replay captured output.
    /// </summary>
    internal static Dictionary<string, InterfaceCounter> ParseInterfaceCounters(string output)
    {
        var result = new Dictionary<string, InterfaceCounter>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(output)) return result;

        // Header: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        //
        // Columns are counted from the RIGHT. The Address column is empty on
        // interfaces without a MAC (utun, gif, lo0), so a whitespace split gives
        // those rows one field fewer and every left-anchored index lands on the
        // wrong number. The trailing columns are always present, so Obytes sits a
        // fixed distance from the end — read from the header when it is there,
        // and fall back to the single Coll column macOS always prints.
        var trailing = 1;

        foreach (var raw in output.Split('\n'))
        {
            var fields = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 6) continue;

            if (string.Equals(fields[0], "Name", StringComparison.Ordinal))
            {
                var obytes = Array.LastIndexOf(fields, "Obytes");
                if (obytes >= 0)
                    trailing = fields.Length - 1 - obytes;
                continue;
            }

            // Only the link row: the per-address rows repeat the same totals.
            if (!fields[2].StartsWith("<Link#", StringComparison.Ordinal)) continue;

            // A down interface is printed as "ap1*"; the counters are still valid.
            var name = fields[0].TrimEnd('*');
            if (!IsMeteredInterface(name)) continue;

            // Obytes, then Oerrs and Opkts, then Ibytes — three columns earlier.
            var outIndex = fields.Length - 1 - trailing;
            var inIndex = outIndex - 3;
            if (inIndex < 3) continue;

            if (!long.TryParse(fields[inIndex], NumberStyles.Integer, CultureInfo.InvariantCulture, out var bytesIn))
                continue;
            if (!long.TryParse(fields[outIndex], NumberStyles.Integer, CultureInfo.InvariantCulture, out var bytesOut))
                continue;

            result[name] = new InterfaceCounter(bytesIn, bytesOut);
        }

        return result;
    }

    /// <summary>
    /// Physical links only. Everything else on a Mac either carries bytes that
    /// were already counted on the physical link (utun/ipsec tunnels, bridge
    /// members) or never leaves the machine (lo0, awdl/llw peer-to-peer radios,
    /// anpi service links).
    /// </summary>
    internal static bool IsMeteredInterface(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.StartsWith("en", StringComparison.Ordinal) ||
            name.StartsWith("eth", StringComparison.Ordinal) ||
            name.StartsWith("ppp", StringComparison.Ordinal))
        {
            // enX is also what Apple names the internal bridge members, but those
            // report zero and cost nothing to include. "anpi" and friends do not
            // start with "en", so no extra exclusion is needed here.
            return true;
        }
        return false;
    }

    private static string? RunNetstat()
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/sbin/netstat")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("-ib");

            using var p = Process.Start(psi);
            if (p == null) return null;

            // Both pipes drained concurrently — see ExfiltrationMonitor for why a
            // single blocking read can deadlock against a chatty stderr.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(10_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return null;
            }
            var output = stdoutTask.GetAwaiter().GetResult();
            stderrTask.GetAwaiter().GetResult();
            return output.Length > 0 ? output : null;
        }
        catch
        {
            return null;
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────

    internal static string HistoryPath
        => Path.Combine(AppPaths.DataDirectory, "traffic-history.json");

    private void LoadHistory()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(HistoryPath)) return;
            var store = JsonSerializer.Deserialize<TrafficStore>(File.ReadAllText(HistoryPath), JsonOptions);
            if (store == null) return;

            foreach (var day in store.Days)
            {
                if (string.IsNullOrWhiteSpace(day.Date)) continue;
                _days[day.Date] = new DayTotal(Math.Max(0, day.In), Math.Max(0, day.Out));
            }
            foreach (var (name, counter) in store.Counters)
                _counters[name] = new InterfaceCounter(Math.Max(0, counter.In), Math.Max(0, counter.Out));

            TrimHistory();
        }
        catch
        {
            // A corrupt history costs the chart its past, not the meter its future.
        }
    }

    private void SaveHistory()
    {
        TrafficStore store;
        lock (_gate)
        {
            store = new TrafficStore
            {
                UpdatedUtc = DateTime.UtcNow,
                Days = _days
                    .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                    .Select(kv => new TrafficDayRecord { Date = kv.Key, In = kv.Value.In, Out = kv.Value.Out })
                    .ToList(),
                Counters = _counters.ToDictionary(
                    kv => kv.Key,
                    kv => new TrafficCounterRecord { In = kv.Value.In, Out = kv.Value.Out },
                    StringComparer.Ordinal)
            };
        }

        try
        {
            AppPaths.WriteAtomic(HistoryPath, JsonSerializer.Serialize(store, JsonOptions));
            _lastSaveUtc = DateTime.UtcNow;
        }
        catch
        {
            // best-effort
        }
    }

    private static string DayKey(DateTime when) => when.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static bool TryParseDayKey(string key, out DateTime day)
        => DateTime.TryParseExact(key, "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out day);

    public void Dispose() => Stop();

    internal readonly record struct InterfaceCounter(long In, long Out);

    private readonly record struct DayTotal(long In, long Out);

    private sealed class TrafficStore
    {
        public DateTime UpdatedUtc { get; set; }
        public List<TrafficDayRecord> Days { get; set; } = new();
        public Dictionary<string, TrafficCounterRecord> Counters { get; set; } = new(StringComparer.Ordinal);
    }

    private sealed class TrafficDayRecord
    {
        public string Date { get; set; } = "";
        public long In { get; set; }
        public long Out { get; set; }
    }

    private sealed class TrafficCounterRecord
    {
        public long In { get; set; }
        public long Out { get; set; }
    }
}
