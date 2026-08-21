using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// How Network Sentinel decides that sudo, osascript or pfctl is installed.
///
/// This used to be a <c>which</c> subprocess — a process spawned per probe, for an
/// answer this process can work out by walking PATH, and one that
/// <c>IsAdministrator</c> now asks for on every alert. The directories matter as
/// much as the mechanism: a GUI launched from Finder inherits a minimal PATH and a
/// launchd job's is narrower still, while <c>pfctl</c> lives in /sbin, so resolving
/// against PATH alone finds sudo and none of what it would be asked to run.
/// </summary>
public class ExecutableResolutionTests
{
    [Fact]
    public void SearchPathAlwaysCoversTheSbinDirectories()
    {
        var dirs = FirewallService.ExecutableSearchPath().ToList();

        // Present whether or not this process's PATH lists them — that is the point.
        Assert.Contains("/usr/sbin", dirs);
        Assert.Contains("/sbin", dirs);
        Assert.Contains("/usr/local/sbin", dirs);
    }

    [Fact]
    public void SearchPathYieldsEachDirectoryOnce()
    {
        var dirs = FirewallService.ExecutableSearchPath().ToList();

        Assert.Equal(dirs.Count, dirs.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ResolvesAnInstalledCommandToAnAbsolutePath()
    {
        var resolved = FirewallService.ResolveExecutable("sh");

        Assert.NotNull(resolved);
        Assert.True(Path.IsPathRooted(resolved!));
        Assert.True(File.Exists(resolved));
    }

    [Fact]
    public void ReportsAnUninstalledCommandAsMissing()
    {
        Assert.Null(FirewallService.ResolveExecutable("networksentinel-no-such-tool"));
        Assert.False(FirewallService.ReadCommandExists("networksentinel-no-such-tool"));
    }

    [Fact]
    public void FindsACommandUnderADirectoryPathDoesNotName()
    {
        // The Finder-launched case: the tool is installed, PATH does not name its
        // directory, and the app still has to find it.
        if (OperatingSystem.IsWindows()) return;   // Unix modes are the thing under test

        var root = Path.Combine(Path.GetTempPath(), "ns-resolve-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var tool = Path.Combine(root, "ns-fake-pfctl");
            File.WriteAllText(tool, "#!/bin/sh\nexit 0\n");
            File.SetUnixFileMode(tool,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            Assert.True(FirewallService.IsExecutableFile(tool));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void AFileWithoutAnExecuteBitIsNotACommand()
    {
        if (OperatingSystem.IsWindows()) return;   // Unix modes are the thing under test

        var path = Path.Combine(Path.GetTempPath(), "ns-plain-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, "not a program");
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            // Resolving on File.Exists alone would run this as if it were the tool.
            Assert.False(FirewallService.IsExecutableFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ADirectoryNamedLikeTheToolIsNotTheTool()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-dir-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Assert.False(FirewallService.IsExecutableFile(dir));
        }
        finally
        {
            Directory.Delete(dir);
        }
    }

    /// <summary>
    /// An absolute path names the file itself, so it is checked rather than searched
    /// for — but it is still checked. The Linux port passes one straight through;
    /// here the helpers this build reaches for live at fixed paths that are simply
    /// absent on an older or a stripped system (/usr/libexec, /opt/homebrew), and
    /// answering "installed" for a path that is not there is how a probe becomes a
    /// command-not-found at the moment a rule is being written.
    /// </summary>
    [Fact]
    public void AnAbsolutePathIsCheckedRatherThanSearchedFor()
    {
        Assert.Equal("/bin/sh", FirewallService.ResolveExecutable("/bin/sh"));
        Assert.Null(FirewallService.ResolveExecutable("/sbin/networksentinel-no-such-tool"));
    }
}
