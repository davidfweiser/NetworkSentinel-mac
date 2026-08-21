using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Avalonia;
using NetworkSentinel.Services;
using NetworkSentinel.Tui;
using NetworkSentinel.Web;

namespace NetworkSentinel;

internal static class Program
{
    [DllImport("libc")]
    private static extern uint geteuid();

    [DllImport("libc", SetLastError = true)]
    private static extern int chown(string pathname, uint owner, uint group);

    /// <summary>Why this OS cannot run it, in the words the GUI also uses.</summary>
    private static string UnsupportedOsMessage() =>
        $"""
        Network Sentinel (macOS) runs on macOS only.

        It reads listening sockets with lsof and PF's state table, and writes rules
        through pfctl into the com.networksentinel anchor. On
        {RuntimeInformation.OSDescription} none of those exist, so monitoring shows
        nothing and no firewall rule can be applied — running it as root or
        Administrator does not change that.

        Run it on a Mac. The Linux and Windows firewalls are driven by the separate
        ports of this app.

        To start the console modes anyway (they will not be able to do anything
        useful):  NETWORKSENTINEL_ALLOW_UNSUPPORTED_OS=1
        """;

    [STAThread]
    public static void Main(string[] args)
    {
        // Any fatal error must leave evidence: <data dir>/logs/crash.log
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogCrash("unhandled", e.ExceptionObject as Exception);
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            LogCrash("unobserved-task", e.Exception);
            e.SetObserved();
        };

        if (WantsHelp(args))
        {
            PrintUsage();
            return;
        }

        // The GUI, the TUI and the web console all read this Mac's sockets and write
        // PF rules, so none of them has anything to show on another OS. Saying so up
        // front is the difference between "this is a macOS program" and the firewall
        // page's old answer, which was to ask for an admin password that would not
        // have helped.
        //
        // Only the console modes exit on it. The GUI carries the same sentence into
        // the window instead (see MainViewModel's unsupported-platform notice), because
        // exiting here would look like the app failing to start at all.
        if (!OperatingSystem.IsMacOS() &&
            string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NETWORKSENTINEL_ALLOW_UNSUPPORTED_OS")))
        {
            Console.Error.WriteLine(UnsupportedOsMessage());
            if (WantsTui(args) || WantsWeb(args, out _) ||
                WantsSetMasterPassword(args) || WantsSetDuckDns(args))
            {
                Environment.Exit(2);
                return;
            }
        }

        if (WantsSetMasterPassword(args))
        {
            RunSetMasterPassword();
            return;
        }

        if (WantsSetDuckDns(args))
        {
            RunSetDuckDns();
            return;
        }

        if (WantsWeb(args, out var webPort))
        {
            RunWeb(webPort, ParseTlsOptions(args));
            return;
        }

        if (WantsTui(args))
        {
            RunTui();
            return;
        }

        // Prefer elevating only pfctl via osascript while the GUI stays as the user.
        if (IsRunningAsRoot() && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NETWORKSENTINEL_ALLOW_ROOT_GUI")))
        {
            Console.Error.WriteLine(
                """
                Network Sentinel: running GUI as root is not recommended.

                Run as your normal user instead:

                    ./NetworkSentinel
                    # or:  dotnet run -c Release

                For a terminal UI:

                    ./NetworkSentinel --tui

                Firewall changes will prompt for your Mac admin password.
                Set NETWORKSENTINEL_ALLOW_ROOT_GUI=1 to override this warning.
                """);
            // Still allow root GUI on macOS (unlike Wayland) — just warn.
        }

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Network Sentinel GUI failed to start:");
            Console.Error.WriteLine(ex);
            Console.Error.WriteLine(
                """

                Try the terminal UI:

                    ./NetworkSentinel --tui
                    # or:  NETWORKSENTINEL_TUI=1 ./NetworkSentinel
                """);
            Environment.Exit(1);
        }
    }

    private static void RunTui()
    {
        // A TTY can carry sudo's own password prompt, which the GUI's dialog path
        // cannot reach and the web console has no way to show at all.
        FirewallService.Surface = FirewallUiSurface.Terminal;
        try
        {
            using var app = new TuiApp();
            app.RunAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Network Sentinel TUI failed:");
            Console.Error.WriteLine(ex);
            Environment.Exit(1);
        }
    }

    private static void RunWeb(int? port, WebTlsOptions? tls)
    {
        // Nothing here can prompt: the macOS admin dialog is drawn on this Mac's own
        // screen, and the operator is in a browser somewhere else. FirewallService
        // reads this to refuse before the form rather than after it.
        FirewallService.Surface = FirewallUiSurface.Web;
        try
        {
            using var app = new WebApp(port, bindAll: true, tlsOverrides: tls);
            app.RunAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            LogCrash("web-host", ex);
            Console.Error.WriteLine("Network Sentinel web UI failed:");
            Console.Error.WriteLine(ex.Message);
            if (ex.InnerException != null)
                Console.Error.WriteLine(ex.InnerException.Message);
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// TLS flags for the web console. Values given here win over settings.json for this run
    /// but are not persisted, so `--https` is safe to try without committing to it.
    /// </summary>
    private static WebTlsOptions? ParseTlsOptions(string[] args)
    {
        var o = new WebTlsOptions();

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string? Inline(string prefix)
                => a.StartsWith(prefix + "=", StringComparison.Ordinal) ? a[(prefix.Length + 1)..] : null;
            string? Next() => i + 1 < args.Length && !args[i + 1].StartsWith('-') ? args[++i] : null;

            switch (a)
            {
                case "--https":
                    o.Enabled = true;
                    continue;
                case "--no-https":
                    o.Enabled = false;
                    continue;
                case "--https-port":
                    if (int.TryParse(Next(), out var hp) && hp is >= 1 and <= 65535)
                    {
                        o.Enabled ??= true;
                        o.Port = hp;
                    }
                    else
                    {
                        Fail("--https-port needs a port number, e.g. --https-port 18443");
                    }
                    continue;
                case "--tls-cert":
                    o.CertPath = Next() ?? Fail("--tls-cert needs a path to a PEM or .pfx certificate");
                    o.Enabled ??= true;
                    continue;
                case "--tls-key":
                    o.KeyPath = Next() ?? Fail("--tls-key needs a path to the PEM private key");
                    continue;
                case "--tls-password":
                    o.PfxPassword = Next() ?? Fail("--tls-password needs the .pfx password");
                    continue;
            }

            if (Inline("--https-port") is { } hpInline)
            {
                if (int.TryParse(hpInline, out var p) && p is >= 1 and <= 65535)
                {
                    o.Enabled ??= true;
                    o.Port = p;
                }
                else
                {
                    Fail($"Invalid HTTPS port in '{a}'");
                }
            }
            else if (Inline("--tls-cert") is { } cert)
            {
                o.CertPath = cert;
                o.Enabled ??= true;
            }
            else if (Inline("--tls-key") is { } key)
            {
                o.KeyPath = key;
            }
            else if (Inline("--tls-password") is { } pw)
            {
                o.PfxPassword = pw;
            }
        }

        return o.HasAny ? o : null;
    }

    private static string Fail(string message)
    {
        Console.Error.WriteLine(message);
        Environment.Exit(2);
        return "";
    }

    private static bool WantsSetDuckDns(string[] args)
        => args.Any(a => a is "--set-duckdns" or "--duckdns");

    /// <summary>
    /// Interactive DuckDNS setup. The token is prompted for rather than passed as a flag so it
    /// does not end up in shell history or the process list.
    /// </summary>
    private static void RunSetDuckDns()
    {
        try
        {
            var updater = new Services.DuckDnsUpdater();
            var current = updater.Config;

            Console.WriteLine("DuckDNS dynamic DNS — keeps a duckdns.org name pointed at this machine.");
            Console.WriteLine($"Config file: {Path.Combine(Services.AppPaths.DataDirectory, "duckdns.json")}");
            if (current.Domain.Length > 0)
                Console.WriteLine($"Current subdomain: {current.Domain}.duckdns.org");
            Console.WriteLine();

            Console.Write("Subdomain (just the label, e.g. 'myhost'): ");
            var domain = Services.DuckDnsUpdater.NormalizeDomain(Console.ReadLine() ?? "");
            if (domain.Length == 0)
            {
                Console.Error.WriteLine("No subdomain entered — nothing changed.");
                Environment.Exit(1);
                return;
            }

            var token = ReadPassword("DuckDNS token (from duckdns.org, hidden): ");
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token entered — nothing changed.");
                Environment.Exit(1);
                return;
            }

            var status = updater.Apply(new Services.DuckDnsConfig
            {
                Enabled = true,
                Domain = domain,
                Token = token.Trim(),
                IntervalMinutes = current.IntervalMinutes <= 0 ? 5 : current.IntervalMinutes
            });

            Console.WriteLine();
            Console.WriteLine("Testing the update…");
            var ok = updater.UpdateOnceAsync().GetAwaiter().GetResult();
            Console.WriteLine("  " + updater.Status);
            updater.Dispose();

            if (!ok)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("Saved, but DuckDNS rejected the update. Check the subdomain and token.");
                Environment.Exit(1);
                return;
            }

            Console.WriteLine();
            Console.WriteLine($"Saved. The web console refreshes {domain}.duckdns.org every few minutes while it runs.");
            Console.WriteLine("Next: issue a certificate with scripts/issue-duckdns-cert.sh, then start with --https.");
            _ = status;
        }
        catch (Exception ex)
        {
            LogCrash("set-duckdns", ex);
            Console.Error.WriteLine("Failed to configure DuckDNS:");
            Console.Error.WriteLine(ex.Message);
            Environment.Exit(1);
        }
    }

    private static bool WantsSetMasterPassword(string[] args)
        => args.Any(a => a is "--set-master-password" or "--reset-master-password");

    private static void RunSetMasterPassword()
    {
        if (!IsRunningAsRoot())
        {
            Console.Error.WriteLine("--set-master-password requires root — re-run with sudo:");
            Console.Error.WriteLine("  sudo NetworkSentinel --set-master-password");
            Environment.Exit(1);
            return;
        }

        try
        {
            var target = ResolveMasterPasswordTarget();
            var dataDir = Path.Combine(target.Home, "Library", "Application Support", "NetworkSentinel");
            Directory.CreateDirectory(dataDir);
            if (target.NeedsChown)
                TryChown(dataDir, target.Uid, target.Gid);

            var store = new WebAuthStore(dataDir);
            Console.WriteLine(store.IsConfigured
                ? "A master password is already set for this user — this will overwrite it."
                : "No master password is set yet for this user — creating one.");
            Console.WriteLine($"Data directory: {dataDir}");
            Console.WriteLine();

            var password = ReadPassword("New master password (min 8 characters): ");
            var confirm = ReadPassword("Confirm master password: ");

            if (!store.SetPassword(password, confirm, out var message))
            {
                Console.Error.WriteLine($"Failed: {message}");
                Environment.Exit(1);
                return;
            }

            if (target.NeedsChown)
                TryChown(Path.Combine(dataDir, "web-master.json"), target.Uid, target.Gid);

            Console.WriteLine(message);
            Console.WriteLine();
            Console.WriteLine("If the web console is currently running, restart it to pick up the change:");
            Console.WriteLine("  NetworkSentinel --web");
        }
        catch (Exception ex)
        {
            LogCrash("set-master-password", ex);
            Console.Error.WriteLine("Failed to set master password:");
            Console.Error.WriteLine(ex.Message);
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// The web console reads the master-password hash from the *user's* Application
    /// Support directory, so `sudo NetworkSentinel --set-master-password` has to
    /// target SUDO_USER's home — not root's — or the file lands somewhere the
    /// running console never reads.
    /// </summary>
    private static (string Home, uint Uid, uint Gid, bool NeedsChown) ResolveMasterPasswordTarget()
    {
        var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
        if (!string.IsNullOrWhiteSpace(sudoUser) && sudoUser != "root")
        {
            // macOS has no getent; the directory service is the source of truth.
            var home = RunCapture("/usr/bin/dscl", ".", "-read", $"/Users/{sudoUser}", "NFSHomeDirectory");
            var uidText = RunCapture("/usr/bin/id", "-u", sudoUser);
            var gidText = RunCapture("/usr/bin/id", "-g", sudoUser);

            // "NFSHomeDirectory: /Users/david"
            if (!string.IsNullOrWhiteSpace(home))
            {
                var idx = home.IndexOf(':');
                if (idx >= 0)
                    home = home[(idx + 1)..].Trim();
            }

            if (!string.IsNullOrWhiteSpace(home) && Directory.Exists(home) &&
                uint.TryParse(uidText?.Trim(), out var uid) &&
                uint.TryParse(gidText?.Trim(), out var gid))
            {
                return (home, uid, gid, true);
            }

            Console.Error.WriteLine($"Warning: could not resolve home directory for SUDO_USER '{sudoUser}' — falling back to root's own home.");
        }

        var rootHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(rootHome))
            rootHome = "/var/root";
        return (rootHome, 0, 0, false);
    }

    private static string? RunCapture(string file, params string[] args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = file,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            foreach (var a in args)
                psi.ArgumentList.Add(a);

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null)
                return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return proc.ExitCode == 0 ? output.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private static void TryChown(string path, uint uid, uint gid)
    {
        try
        {
            chown(path, uid, gid);
        }
        catch
        {
            // best-effort — worst case the target user needs a manual chown
        }
    }

    /// <summary>Reads a line with each character masked as '*'; falls back to plain ReadLine when input is redirected (e.g. piped/non-interactive).</summary>
    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);

        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? "";

        var buffer = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return buffer.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                {
                    buffer.Length--;
                    Console.Write("\b \b");
                }
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Append(key.KeyChar);
                Console.Write('*');
            }
        }
    }

    private static void LogCrash(string kind, Exception? ex)
    {
        try
        {
            var dir = Path.Combine(Services.AppPaths.DataDirectory, "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "crash.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {kind}:{Environment.NewLine}{ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // never let crash logging crash
        }
    }

    private static bool WantsHelp(string[] args)
        => args.Any(a => a is "-h" or "--help" or "-?" or "help");

    /// <summary>
    /// Headless browser UI when: -w / --web, optional port as -w PORT, -w=PORT, --web=PORT, or --port PORT.
    /// </summary>
    private static bool WantsWeb(string[] args, out int? port)
    {
        port = null;
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];

            if (a is "-w" or "--web" or "web")
            {
                if (i + 1 < args.Length && int.TryParse(args[i + 1], out var p) && p is >= 1 and <= 65535)
                    port = p;
                return true;
            }

            if (a.StartsWith("-w=", StringComparison.Ordinal) ||
                a.StartsWith("--web=", StringComparison.Ordinal))
            {
                var value = a[(a.IndexOf('=') + 1)..];
                if (int.TryParse(value, out var p) && p is >= 1 and <= 65535)
                    port = p;
                else
                {
                    Console.Error.WriteLine($"Invalid web port in '{a}'. Use e.g. -w=18765");
                    Environment.Exit(2);
                }
                return true;
            }

            // -w18765 (no space / equals)
            if (a.Length > 2 && a.StartsWith("-w", StringComparison.Ordinal) &&
                int.TryParse(a.AsSpan(2), out var glued) && glued is >= 1 and <= 65535)
            {
                port = glued;
                return true;
            }
        }

        // --port only counts when web mode is also requested elsewhere — ignore alone.
        // NETWORKSENTINEL_WEB=1 forces web mode.
        var env = Environment.GetEnvironmentVariable("NETWORKSENTINEL_WEB");
        if (string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase))
        {
            for (var i = 0; i < args.Length; i++)
            {
                if ((args[i] is "--port" or "-p") && i + 1 < args.Length &&
                    int.TryParse(args[i + 1], out var p) && p is >= 1 and <= 65535)
                {
                    port = p;
                    break;
                }
            }
            return true;
        }

        return false;
    }

    /// <summary>
    /// TUI when: --tui / -t / tui arg, NETWORKSENTINEL_TUI=1, or no graphical session
    /// and not forced GUI via NETWORKSENTINEL_GUI=1.
    /// </summary>
    private static bool WantsTui(string[] args)
    {
        if (args.Any(a => a is "--tui" or "-t" or "tui" or "--console"))
            return true;

        var env = Environment.GetEnvironmentVariable("NETWORKSENTINEL_TUI");
        if (string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(Environment.GetEnvironmentVariable("NETWORKSENTINEL_GUI"), "1", StringComparison.OrdinalIgnoreCase))
            return false;

        // Auto-select TUI when there is no Aqua session (SSH / headless).
        // On macOS GUI logins, SESSIONTYPE or security session is usually present;
        // also check common SSH indicator.
        var ssh = Environment.GetEnvironmentVariable("SSH_CONNECTION");
        if (!string.IsNullOrEmpty(ssh) && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")))
            return Console.IsInputRedirected == false;

        return false;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            Network Sentinel — macOS network monitor & intrusion awareness

            Usage:
              NetworkSentinel [options]

            Options:
              (default)          Avalonia GUI
              --tui, -t, tui     Terminal UI (Spectre.Console)
              --console          Same as --tui
              -w, --web [PORT]   Headless web UI (browser). Auto-picks a free high port
                                 if PORT is omitted (prefers 18765, then nearby alternatives)
              --set-master-password    Set/reset the web UI master password from the
                                        terminal (no browser needed). Requires root:
                                        sudo NetworkSentinel --set-master-password
                                        Restart the web console afterwards.
              --set-duckdns      Configure DuckDNS dynamic DNS (subdomain + token, prompted).
                                 The web console then keeps the record pointed here.
              -h, --help         Show this help

            Web console over HTTPS (used with -w):
              --https            Serve TLS as well as HTTP (needs a certificate)
              --https-port PORT  TLS port (default 18443; below 1024 needs root)
              --tls-cert PATH    PEM fullchain, or a .pfx / .p12 bundle
              --tls-key PATH     PEM private key (omit for .pfx)
              --tls-password PW  Password for a .pfx / .p12 certificate
              --no-https         Force plain HTTP for this run
                                 Flags override settings.json without overwriting it.
                                 Get a trusted certificate for a duckdns.org name with:
                                 scripts/issue-duckdns-cert.sh

            Environment:
              NETWORKSENTINEL_TUI=1              Force TUI
              NETWORKSENTINEL_WEB=1              Force headless web UI
              NETWORKSENTINEL_GUI=1              Force GUI
              NETWORKSENTINEL_ALLOW_ROOT_GUI=1   Suppress root-GUI warning

            TUI keys (once running):
              1-7 / Tab   views    p pause    a auto-block    b block
              x unblock   u auth   / filter   h help          q quit

            Examples:
              dotnet run -c Release
              dotnet run -c Release -- --tui
              dotnet run -c Release -- -w
              ./NetworkSentinel --tui
              ./NetworkSentinel -w
              ./NetworkSentinel -w 18765
              ./NetworkSentinel -w --https \
                  --tls-cert ~/Library/Application\ Support/NetworkSentinel/tls/myhost.duckdns.org.fullchain.cer \
                  --tls-key  ~/Library/Application\ Support/NetworkSentinel/tls/myhost.duckdns.org.key
            """);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    private static bool IsRunningAsRoot()
    {
        try
        {
            return geteuid() == 0;
        }
        catch
        {
            return false;
        }
    }
}
