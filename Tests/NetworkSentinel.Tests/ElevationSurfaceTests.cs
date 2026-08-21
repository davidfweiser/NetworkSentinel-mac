using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// What the app says about elevation, and to whom.
///
/// The bug these cover is one an operator hits in a browser: the web console lists
/// the whole host ruleset, offers an Edit button on each row, accepts a change, and
/// then fails the save. <c>CanElevate</c> was a bare <c>true</c> on this platform —
/// right about osascript being installed, wrong about the operator, because the
/// admin dialog it raises is drawn on the Mac running the console and nobody is
/// sitting at it. The console would then hold the request for the full interactive
/// timeout waiting on an answer that could not come.
/// </summary>
public class ElevationSurfaceTests
{
    /// <summary>
    /// <see cref="FirewallService.Surface"/> is process-wide state that the tests
    /// below have to move, so each one puts it back. xUnit runs classes in parallel
    /// but the members of one class in sequence, and this is the only class that
    /// touches it.
    /// </summary>
    private static void WithSurface(FirewallUiSurface surface, Action body)
    {
        var previous = FirewallService.Surface;
        FirewallService.Surface = surface;
        try { body(); }
        finally { FirewallService.Surface = previous; }
    }

    [Fact]
    public void SudoersGrant_NamesThisUserAndAnAbsolutePath()
    {
        var grant = FirewallService.SudoersGrantText();

        Assert.StartsWith(Environment.UserName + " ALL=(root) NOPASSWD: ", grant);

        // visudo rejects a relative path, so every binary listed has to be absolute.
        var binaries = grant.Split("NOPASSWD: ")[1].Split(", ");
        Assert.NotEmpty(binaries);
        Assert.All(binaries, b => Assert.StartsWith("/", b));
    }

    [Fact]
    public void SudoersGrant_IsOneLineSoItCanBeEchoedIntoSudoersD()
    {
        var grant = FirewallService.SudoersGrantText();

        Assert.DoesNotContain("\n", grant);
        // The install command wraps it in single quotes; one inside would end them.
        Assert.DoesNotContain("'", grant);
    }

    [Fact]
    public void InstallCommands_OfferRootFirstAndThenWriteAndVerifyTheGrant()
    {
        var commands = FirewallService.SudoersInstallCommands();

        // Running the console as root is the smaller ask, because the grant this
        // platform needs has to name the shell — see SudoersGrantText.
        Assert.Contains("sudo NetworkSentinel --web", commands);
        Assert.Contains(FirewallService.SudoersGrantText(), commands);
        Assert.Contains("/etc/sudoers.d/networksentinel", commands);
        Assert.Contains("chmod 0440", commands);
        Assert.Contains("visudo -c", commands);

        Assert.True(commands.IndexOf("sudo NetworkSentinel --web", StringComparison.Ordinal)
                    < commands.IndexOf("NOPASSWD", StringComparison.Ordinal),
            "running as root should be offered before a grant equivalent to a root shell");
    }

    [Fact]
    public void HeadlessHelp_SaysTheGrantIsARootShell()
    {
        // PF rules are applied by running a generated script, so the grant names
        // /bin/bash. Printing that without saying what it means would be handing an
        // operator full root under the impression it was scoped to the firewall.
        var help = FirewallService.HeadlessElevationHelp();

        Assert.Contains("/bin/bash", help);
        Assert.Contains("root shell", help);
    }

    [Fact]
    public void HeadlessHelp_CarriesTheCommandsInBothLayouts()
    {
        var block = FirewallService.HeadlessElevationHelp();
        var flowed = FirewallService.HeadlessElevationHelp(asBlock: false);

        Assert.Contains(FirewallService.SudoersInstallCommands(), block);
        Assert.Contains(FirewallService.HeadlessElevationLead, block);
        Assert.Contains(FirewallService.HeadlessElevationTail, block);

        // The flowed form goes into a single-line status, so it cannot wrap.
        Assert.DoesNotContain("\n", flowed);
        Assert.Contains("visudo -c", flowed);
    }

    [Fact]
    public void WebSurface_DoesNotOfferDesktopAdviceForAFailedWrite()
    {
        WithSurface(FirewallUiSurface.Web, () =>
        {
            var service = new FirewallService();

            foreach (var text in new[] { service.ElevationNote, service.PrivilegeText })
            {
                // A dialog on a Mac in another room is not something a browser can
                // answer, so it must never be offered as the way forward.
                Assert.DoesNotContain("osascript admin dialog or sudo", text);
                Assert.DoesNotContain("Allow the password dialog", text);
            }
        });
    }

    [Fact]
    public void DesktopSurface_KeepsThePromptWordingItAlwaysHad()
    {
        WithSurface(FirewallUiSurface.Desktop, () =>
        {
            var note = new FirewallService().ElevationNote;

            // Root and passwordless-sudo hosts are answered before the prompt
            // branches, and CI may run as either, so only assert what holds every
            // way: the desktop is never told to go and edit sudoers by hand.
            Assert.DoesNotContain("/etc/sudoers.d/networksentinel", note);
        });
    }

    [Fact]
    public void WebSurface_CannotPromptEvenWhereAHelperIsInstalled()
    {
        // osascript being installed is what IsAdministrator reports, and on this
        // platform that is always. CanApplyRules is the stronger claim, so it may
        // never be true purely because a helper happens to be present.
        WithSurface(FirewallUiSurface.Web, () =>
        {
            var service = new FirewallService();
            if (!service.IsRoot && !FirewallService.CanElevateSilently())
                Assert.False(service.CanApplyRules);
        });
    }

    [Fact]
    public void RootProcess_CanAlwaysApplyRulesOnEverySurface()
    {
        var service = new FirewallService();
        if (!service.IsRoot) return;   // the suite also runs unprivileged

        foreach (var surface in new[] { FirewallUiSurface.Desktop, FirewallUiSurface.Terminal, FirewallUiSurface.Web })
            WithSurface(surface, () => Assert.True(new FirewallService().CanApplyRules));
    }

    [Fact]
    public void UnsupportedPlatform_RefusesBeforeItAsksForAPassword()
    {
        // The refusal has to name the platform rather than a privilege level: no
        // password on a Linux or Windows host would make pfctl appear.
        if (FirewallService.PlatformSupported) return;

        var service = new FirewallService();
        Assert.False(service.IsAdministrator);
        Assert.False(service.CanApplyRules);
        Assert.Equal(FirewallService.UnsupportedPlatformText, service.PrivilegeText);
    }

    [Fact]
    public void ElevationProbe_CanBeInvalidatedSoAFreshGrantIsSeen()
    {
        // The probe caches, because a refused `sudo -n` lands in the log this very
        // app watches for break-in attempts. An operator who has just written the
        // sudoers file must not have to wait the cache out, so the reset has to be
        // callable and the answer has to survive it unchanged on a host that has
        // not changed.
        var before = FirewallService.CanElevateSilently();
        FirewallService.InvalidateElevationProbe();
        Assert.Equal(before, FirewallService.CanElevateSilently());
    }
}
