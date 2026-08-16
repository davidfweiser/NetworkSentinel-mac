using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using NetworkSentinel.Models;
using NetworkSentinel.Services;

namespace NetworkSentinel.ViewModels;

/// <summary>
/// Dashboard data-flow charts: the live in/out rate and the month's totals,
/// fed by <see cref="TrafficMeterService"/>.
/// </summary>
public partial class MainViewModel
{
    public const string RangeThisMonth = "This month, by day";
    public const string RangeTwelveMonths = "Last 12 months";

    private TrafficMeterService _traffic = null!;
    private int _trafficRefreshQueued;

    [ObservableProperty] private string _trafficInRateText = "0 B/s";
    [ObservableProperty] private string _trafficOutRateText = "0 B/s";
    [ObservableProperty] private string _trafficWindowText = "measuring…";
    [ObservableProperty] private string _trafficStatusText = "";
    [ObservableProperty] private string _monthLabelText = DateTime.Today.ToString("MMMM yyyy");
    [ObservableProperty] private string _monthInText = "0 B";
    [ObservableProperty] private string _monthOutText = "0 B";
    [ObservableProperty] private string _monthTotalText = "0 B";
    [ObservableProperty] private string _monthDailyAverageText = "";
    [ObservableProperty] private string _trafficRangeSummary = "";
    [ObservableProperty] private string _selectedTrafficRange = RangeThisMonth;
    [ObservableProperty] private bool _trafficMeterEnabled = true;

    /// <summary>Live inbound throughput, bytes/s, oldest first.</summary>
    public ObservableCollection<double> TrafficInSeries { get; } = new();

    /// <summary>Live outbound throughput, bytes/s, oldest first.</summary>
    public ObservableCollection<double> TrafficOutSeries { get; } = new();

    /// <summary>Bars behind the monthly chart — one per day, or one per month.</summary>
    public ObservableCollection<TrafficBucket> TrafficBuckets { get; } = new();

    public ObservableCollection<string> TrafficRangeOptions { get; } = new()
    {
        RangeThisMonth,
        RangeTwelveMonths
    };

    private void InitializeTraffic()
    {
        _traffic = _core.Traffic;
        _traffic.Updated += OnTrafficUpdated;
        RefreshTraffic();
    }

    private void OnTrafficUpdated()
    {
        // The meter samples on its own thread every few seconds. Coalescing the
        // posts keeps a slow UI thread from queueing a backlog of redraws.
        if (Interlocked.CompareExchange(ref _trafficRefreshQueued, 1, 0) != 0)
            return;

        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _trafficRefreshQueued, 0);
            RefreshTraffic();
        }, DispatcherPriority.Background);
    }

    /// <summary>Pulls the meter's current state into the chart series and the legends.</summary>
    private void RefreshTraffic()
    {
        var live = _traffic.Live;

        TrafficInSeries.Clear();
        TrafficOutSeries.Clear();
        foreach (var sample in live)
        {
            TrafficInSeries.Add(sample.BytesInPerSecond);
            TrafficOutSeries.Add(sample.BytesOutPerSecond);
        }

        if (live.Count >= 2)
        {
            var last = live[^1];
            var span = last.Time - live[0].Time;
            TrafficInRateText = $"in {ByteSize.FormatRate(last.BytesInPerSecond)}";
            TrafficOutRateText = $"out {ByteSize.FormatRate(last.BytesOutPerSecond)}";
            TrafficWindowText = span.TotalMinutes >= 1
                ? $"last {Math.Round(span.TotalMinutes)} min"
                : $"last {Math.Max(1, (int)span.TotalSeconds)} s";
        }
        else
        {
            TrafficInRateText = "in —";
            TrafficOutRateText = "out —";
            TrafficWindowText = TrafficMeterEnabled ? "measuring…" : "meter off";
        }

        var month = _traffic.MonthTotal(DateTime.Today);
        MonthLabelText = month.Label;
        MonthInText = month.InText;
        MonthOutText = month.OutText;
        MonthTotalText = month.TotalText;
        MonthDailyAverageText = DateTime.Today.Day > 0
            ? $"{ByteSize.Format(month.BytesTotal / (double)DateTime.Today.Day)} per day so far"
            : "";

        TrafficStatusText = _traffic.Status;
        RefreshTrafficBuckets();
    }

    private void RefreshTrafficBuckets()
    {
        var buckets = SelectedTrafficRange == RangeTwelveMonths
            ? _traffic.MonthlyBuckets(12)
            : _traffic.DailyBuckets(DateTime.Today);

        TrafficBuckets.Clear();
        foreach (var bucket in buckets)
            TrafficBuckets.Add(bucket);

        long totalIn = 0, totalOut = 0;
        foreach (var bucket in buckets)
        {
            totalIn += bucket.BytesIn;
            totalOut += bucket.BytesOut;
        }

        var scope = SelectedTrafficRange == RangeTwelveMonths ? "12 months" : MonthLabelText;
        TrafficRangeSummary = $"{scope} · {ByteSize.Format(totalIn)} in · {ByteSize.Format(totalOut)} out";
    }

    partial void OnSelectedTrafficRangeChanged(string value) => RefreshTrafficBuckets();

    partial void OnTrafficMeterEnabledChanged(bool value)
    {
        _settings.TrafficMeterEnabled = value;
        _settings.Save();

        if (value)
            _traffic.Start();
        else
            _traffic.Stop();

        SettingsMessage = value
            ? "Traffic metering on — dashboard data-flow charts are recording."
            : "Traffic metering off — the daily history is kept, but no longer updated.";
        RefreshTraffic();
    }
}
