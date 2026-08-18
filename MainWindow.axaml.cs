using System;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;
using Avalonia.Threading;
using NetworkSentinel.ViewModels;

namespace NetworkSentinel;

public partial class MainWindow : Window
{
    private TrayIcon? _tray;
    private NativeMenuItem? _menuStatus;
    private NativeMenuItem? _menuSessions;
    private NativeMenuItem? _menuPorts;
    private NativeMenuItem? _menuHosts;
    private NativeMenuItem? _menuThreats;
    private NativeMenuItem? _menuHigh;
    private NativeMenuItem? _menuBlocked;
    private NativeMenuItem? _menuAuto;
    private bool _trayReady;

    public MainWindow()
    {
        InitializeComponent();
        Opened += OnOpened;
        Closing += OnClosing;
        PropertyChanged += OnWindowPropertyChanged;
        Closed += (_, _) =>
        {
            TearDownTray();
            if (DataContext is MainViewModel vm)
                vm.Dispose();
        };
    }

    private void OnOpened(object? sender, EventArgs e)
    {
        if (_trayReady) return;
        SetupTray();
        if (DataContext is MainViewModel vm)
        {
            vm.PropertyChanged += OnViewModelPropertyChanged;
            ApplyTrayFromViewModel(vm);
        }
    }

    private void OnWindowPropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
    {
        if (e.Property != WindowStateProperty) return;

        // Keep the tray icon visible whenever the window is not the focus of the UI.
        if (_tray != null)
            _tray.IsVisible = true;

        if (DataContext is MainViewModel vm)
            vm.UpdateStatusChrome();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not MainViewModel vm) return;
        if (e.PropertyName is nameof(MainViewModel.TrayToolTip)
            or nameof(MainViewModel.TrayStatusLine)
            or nameof(MainViewModel.WindowTitle)
            or nameof(MainViewModel.AutoBlockEnabled)
            or nameof(MainViewModel.AutoBlockMinLevel))
        {
            ApplyTrayFromViewModel(vm);
        }

        // The rule editor sits above the lists, so "New rule" on a listener row near
        // the bottom of a scrolled page would otherwise fill in a form the operator
        // cannot see and read as a button that did nothing. Posted, not called: the
        // Border is still collapsed at the moment IsVisible flips, and a control with
        // no layout slot cannot be scrolled to.
        if (e.PropertyName == nameof(MainViewModel.IsRuleEditorOpen) && vm.IsRuleEditorOpen)
            Dispatcher.UIThread.Post(() => RuleEditorCard?.BringIntoView(), DispatcherPriority.Loaded);
    }

    private void SetupTray()
    {
        try
        {
            var icon = LoadTrayIcon();
            if (icon == null) return;

            _menuStatus = new NativeMenuItem("Network Sentinel") { IsEnabled = false };
            _menuSessions = new NativeMenuItem("Sessions: —") { IsEnabled = false };
            _menuPorts = new NativeMenuItem("Ports: —") { IsEnabled = false };
            _menuHosts = new NativeMenuItem("Remotes: —") { IsEnabled = false };
            _menuThreats = new NativeMenuItem("Events today: —") { IsEnabled = false };
            _menuHigh = new NativeMenuItem("High / critical: —") { IsEnabled = false };
            _menuBlocked = new NativeMenuItem("Blocked IPs: —") { IsEnabled = false };
            _menuAuto = new NativeMenuItem("Auto-block: —") { IsEnabled = false };

            var showItem = new NativeMenuItem("Show Network Sentinel");
            showItem.Click += (_, _) => RestoreFromTray();

            var pauseItem = new NativeMenuItem("Pause / Resume monitoring");
            pauseItem.Click += (_, _) =>
            {
                if (DataContext is MainViewModel vm)
                    vm.ToggleMonitoringCommand.Execute(null);
            };

            var exitItem = new NativeMenuItem("Quit");
            exitItem.Click += (_, _) => QuitApp();

            var menu = new NativeMenu();
            menu.Items.Add(_menuStatus);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(_menuSessions);
            menu.Items.Add(_menuPorts);
            menu.Items.Add(_menuHosts);
            menu.Items.Add(_menuThreats);
            menu.Items.Add(_menuHigh);
            menu.Items.Add(_menuBlocked);
            menu.Items.Add(_menuAuto);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(showItem);
            menu.Items.Add(pauseItem);
            menu.Items.Add(exitItem);

            _tray = new TrayIcon
            {
                Icon = icon,
                ToolTipText = "Network Sentinel",
                IsVisible = true,
                Menu = menu
            };
            _tray.Clicked += (_, _) => RestoreFromTray();

            var icons = new TrayIcons { _tray };
            if (Application.Current != null)
                TrayIcon.SetIcons(Application.Current, icons);

            _trayReady = true;
        }
        catch (Exception ex)
        {
            // Tray is best-effort (some DEs need AppIndicator); app still runs.
            System.Diagnostics.Debug.WriteLine($"Tray setup failed: {ex.Message}");
        }
    }

    private void ApplyTrayFromViewModel(MainViewModel vm)
    {
        if (_tray == null) return;

        Dispatcher.UIThread.Post(() =>
        {
            if (_tray == null) return;
            _tray.ToolTipText = vm.TrayToolTip;
            if (_menuStatus != null) _menuStatus.Header = vm.TrayStatusLine;
            if (_menuSessions != null) _menuSessions.Header = $"TCP sessions: {vm.Stats.ActiveConnections}";
            if (_menuPorts != null) _menuPorts.Header = $"Listening ports: {vm.Stats.ListeningPorts}";
            if (_menuHosts != null) _menuHosts.Header = $"Remote hosts: {vm.Stats.RemoteHosts}";
            if (_menuThreats != null) _menuThreats.Header = $"Events today: {vm.Stats.ThreatsToday}";
            if (_menuHigh != null) _menuHigh.Header = $"High / critical: {vm.Stats.HighThreats}";
            if (_menuBlocked != null)
            {
                // approximate from subtitle / chrome — blocked count is in tooltip
                var line = vm.TrayToolTip.Split('\n')
                    .FirstOrDefault(l => l.StartsWith("Blocked IPs:", StringComparison.Ordinal));
                _menuBlocked.Header = line ?? "Blocked IPs: —";
            }
            if (_menuAuto != null)
            {
                _menuAuto.Header = vm.AutoBlockEnabled
                    ? $"Auto-block: ON (≥ {vm.AutoBlockMinLevel})"
                    : "Auto-block: OFF";
            }
        });
    }

    private static WindowIcon? LoadTrayIcon()
    {
        try
        {
            // Prefer ICO (multi-size); fall back to PNG.
            var ico = AssetLoader.Open(new Uri("avares://NetworkSentinel/Assets/icon.ico"));
            return new WindowIcon(ico);
        }
        catch
        {
            try
            {
                var png = AssetLoader.Open(new Uri("avares://NetworkSentinel/Assets/icon.png"));
                return new WindowIcon(png);
            }
            catch
            {
                return null;
            }
        }
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
        Topmost = true;
        Topmost = false;
    }

    private void QuitApp()
    {
        TearDownTray();
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.Shutdown();
        else
            Close();
    }

    private void OnClosing(object? sender, WindowClosingEventArgs e)
    {
        // Leaving Close as real quit — tray remains only while the process runs.
        TearDownTray();
    }

    private void TearDownTray()
    {
        if (Application.Current != null)
            TrayIcon.SetIcons(Application.Current, null);
        _tray?.Dispose();
        _tray = null;
        _trayReady = false;
    }
}
