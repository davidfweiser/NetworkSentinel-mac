using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Reads `netstat -ib`. Two shapes of the same output decide whether the
/// dashboard's month totals are right: netstat repeats an interface once per
/// address it holds, and it omits the Address column entirely on interfaces
/// without a MAC — so a left-anchored column index reads packet counts as bytes.
/// </summary>
public class TrafficMeterTests
{
    // Captured from a Mac on Wi-Fi with a VPN up. en0 appears four times (link,
    // IPv6 link-local, IPv4, global IPv6) with identical totals on every row.
    private const string Sample = """
        Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
        lo0        16384 <Link#1>                         24249     0  140160314    24249     0  140160314     0
        lo0        16384 127           localhost          24249     -  140160314    24249     -  140160314     -
        gif0*      1280  <Link#2>                             0     0          0        0     0          0     0
        en0        1500  <Link#11>   62:36:37:30:c4:65  6247182     0 7590338536  2530487     0  995552911     0
        en0        1500  davids-macb fe80:b::cdd:f499:  6247182     - 7590338536  2530487     -  995552911     -
        en0        1500  10/24         10.0.0.116       6247182     - 7590338536  2530487     -  995552911     -
        utun4      1420  <Link#19>                       163861     0  197804251    79400     0   27262979     0
        utun4      1420  10.87.0.14/32 10.87.0.14        163861     -  197804251    79400     -   27262979     -
        """;

    [Fact]
    public void CountsEachInterfaceOnceDespiteRepeatedAddressRows()
    {
        var counters = TrafficMeterService.ParseInterfaceCounters(Sample);

        // en0 is printed on three rows; summing them would triple the month.
        var en0 = Assert.Contains("en0", counters);
        Assert.Equal(7590338536L, en0.In);
        Assert.Equal(995552911L, en0.Out);
        Assert.Single(counters);
    }

    [Fact]
    public void SkipsLoopbackAndTunnels()
    {
        var counters = TrafficMeterService.ParseInterfaceCounters(Sample);

        // utun carries the same bytes that already crossed en0, encapsulated.
        Assert.DoesNotContain("utun4", counters.Keys);
        // lo0 never leaves the machine — and its 140 MB would dwarf a quiet day.
        Assert.DoesNotContain("lo0", counters.Keys);
    }

    [Fact]
    public void ReadsRowsWhereTheAddressColumnIsMissing()
    {
        // A wired interface with no MAC printed: one field fewer than the en0 rows
        // above. Column indices counted from the left would land on Opkts.
        const string noMac = """
            Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
            en5        1500  <Link#20>                        11111     0     222222    33333     0     444444     0
            """;

        var counters = TrafficMeterService.ParseInterfaceCounters(noMac);

        var en5 = Assert.Contains("en5", counters);
        Assert.Equal(222222L, en5.In);
        Assert.Equal(444444L, en5.Out);
    }

    [Fact]
    public void DownInterfacesStillCount()
    {
        const string down = """
            Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
            en1*       1500  <Link#8>    36:b6:3b:87:b1:c0      500     0       9000      400     0       8000     0
            """;

        Assert.Contains("en1", TrafficMeterService.ParseInterfaceCounters(down).Keys);
    }

    [Fact]
    public void DeltaIsTheDifferenceWhileTheCounterClimbs()
    {
        Assert.Equal(500L, TrafficMeterService.Delta(1000, 1500));
        Assert.Equal(0L, TrafficMeterService.Delta(1000, 1000));
    }

    [Fact]
    public void CounterResetCountsTheNewValue()
    {
        // A reboot restarts the counters at zero. Subtracting would give a negative
        // delta; treating the reading as "since the reset" is the honest answer.
        Assert.Equal(120L, TrafficMeterService.Delta(9_000_000, 120));
        Assert.Equal(0L, TrafficMeterService.Delta(9_000_000, 0));
    }

    [Theory]
    [InlineData("en0", true)]
    [InlineData("eth0", true)]
    [InlineData("ppp0", true)]
    [InlineData("utun4", false)]
    [InlineData("lo0", false)]
    [InlineData("awdl0", false)]
    [InlineData("bridge0", false)]
    [InlineData("anpi0", false)]
    [InlineData("", false)]
    public void OnlyPhysicalLinksAreMetered(string name, bool metered)
        => Assert.Equal(metered, TrafficMeterService.IsMeteredInterface(name));

    [Theory]
    [InlineData(0d, "0 B")]
    [InlineData(-5d, "0 B")]
    [InlineData(999d, "999 B")]
    [InlineData(1000d, "1 kB")]
    [InlineData(1_500_000d, "1.5 MB")]
    [InlineData(150_000_000d, "150 MB")]
    [InlineData(7_590_338_536d, "7.6 GB")]
    public void BytesAreFormattedInDecimalUnits(double bytes, string expected)
        => Assert.Equal(expected, ByteSize.Format(bytes));

    [Fact]
    public void RatesCarryTheirUnit()
    {
        Assert.Equal("1.2 MB/s", ByteSize.FormatRate(1_200_000));
        Assert.Equal("0 B/s", ByteSize.FormatRate(0));
    }

    [Fact]
    public void EmptyOutputYieldsNoCounters()
    {
        Assert.Empty(TrafficMeterService.ParseInterfaceCounters(""));
        Assert.Empty(TrafficMeterService.ParseInterfaceCounters("netstat: command not found"));
    }
}
