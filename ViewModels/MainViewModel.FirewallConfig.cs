using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSentinel.Services;

namespace NetworkSentinel.ViewModels;

/// <summary>
/// The Firewall Config view: add, edit and delete inbound and outbound rules,
/// laid out the way FireWallConfig lays out the Linode Cloud Manager firewall
/// page — one list per direction, Label / Action / Protocol / Port Range /
/// Sources, and one form that both creates and edits.
///
/// The list is the whole host firewall, read back out of the machine by
/// <see cref="HostFirewallScanner"/> — the pf ruleset, Apple's own anchors, the
/// Application Firewall's per-app entries, and this app's own rules, in one
/// list, exactly as FireWallConfig presents them. It used to be this app's JSON
/// ledger and nothing else, which is a near-empty page beside the two firewalls
/// macOS actually runs.
///
/// Writes still go into this app's own PF anchor, because that is the only
/// ruleset it owns: /etc/pf.conf and the Apple anchors are loaded whole, so a
/// line written into one would be restored by the next reload. The default
/// policies shown are the ones PF and the Application Firewall actually hold, so
/// an Allow rule is not described as a permission grant on a firewall that
/// already passes anything no rule matches.
/// </summary>
public partial class MainViewModel
{
    /// <summary>Preset label → (protocol, port range). "Custom" leaves the fields alone.</summary>
    private static readonly Dictionary<string, (string Protocol, string Ports)> RulePresets = new()
    {
        ["SSH (22/tcp)"] = ("TCP", "22"),
        ["HTTP (80/tcp)"] = ("TCP", "80"),
        ["HTTPS (443/tcp)"] = ("TCP", "443"),
        ["DNS (53/udp)"] = ("UDP", "53"),
        ["MySQL (3306/tcp)"] = ("TCP", "3306"),
        ["PostgreSQL (5432/tcp)"] = ("TCP", "5432"),
        ["WireGuard (51820/udp)"] = ("UDP", "51820"),
        ["Web console (18765,18443/tcp)"] = ("TCP", "18765, 18443"),
        ["ICMP (ping)"] = ("ICMP", "")
    };

    private const string PresetCustom = "Custom";

    /// <summary>Name of the rule being edited; empty when the form is creating one.</summary>
    private string _editingRuleName = "";

    /// <summary>Guards the preset combo from re-applying while the form is being filled.</summary>
    private bool _suppressPresetHandler;

    [ObservableProperty] private bool _showFirewallConfig;
    [ObservableProperty] private bool _isRuleEditorOpen;
    [ObservableProperty] private string _ruleEditorTitle = "Add an Inbound Rule";
    [ObservableProperty] private string _ruleEditorNote = "";
    [ObservableProperty] private string _ruleEditorError = "";
    [ObservableProperty] private string _ruleEditorSaveText = "Add Rule";
    [ObservableProperty] private string _firewallConfigMessage = "";
    [ObservableProperty] private string _firewallConfigSummary = "";
    [ObservableProperty] private string _firewallConfigPolicyText = "";

    [ObservableProperty] private string _rulePreset = PresetCustom;
    [ObservableProperty] private string _ruleLabel = "";
    [ObservableProperty] private string _ruleAction = FirewallRuleSpecs.ActionBlock;
    [ObservableProperty] private string _ruleDirection = FirewallRuleSpecs.DirectionInbound;
    [ObservableProperty] private string _ruleProtocol = "TCP";
    [ObservableProperty] private string _rulePortRange = "";
    [ObservableProperty] private string _ruleAddresses = "";

    [ObservableProperty] private FirewallRuleInfo? _selectedInboundRule;
    [ObservableProperty] private FirewallRuleInfo? _selectedOutboundRule;
    [ObservableProperty] private string _firewallConfigListenerText = "";
    [ObservableProperty] private bool _isFirewallConfigScanning;

    private HostFirewallScanner? _hostScanner;

    /// <summary>Built on first use — _firewall is assigned in the constructor, after field initializers run.</summary>
    private HostFirewallScanner HostScanner => _hostScanner ??= new HostFirewallScanner(_firewall);

    /// <summary>Rules PF evaluates on traffic arriving at this Mac.</summary>
    public ObservableCollection<FirewallRuleInfo> InboundRules { get; } = new();

    /// <summary>Rules PF evaluates on traffic this Mac sends.</summary>
    public ObservableCollection<FirewallRuleInfo> OutboundRules { get; } = new();

    public ObservableCollection<string> RuleActionOptions { get; } = new(FirewallRuleSpecs.Actions);
    public ObservableCollection<string> RuleDirectionOptions { get; } = new(FirewallRuleSpecs.Directions);
    public ObservableCollection<string> RuleProtocolOptions { get; } = new(FirewallRuleSpecs.Protocols);

    public ObservableCollection<string> RulePresetOptions { get; } =
        new(new[] { PresetCustom }.Concat(RulePresets.Keys));

    /// <summary>"Sources" reads wrong on an outbound rule, where the field is the far end.</summary>
    public string RuleAddressLabel => RuleDirection == FirewallRuleSpecs.DirectionOutbound
        ? "Destinations"
        : "Sources";

    /// <summary>What is listening on this host, and whether the firewall admits it.</summary>
    public ObservableCollection<HostListener> ListeningServices { get; } = new();

    public string InboundCountText => $"{InboundRules.Count} inbound rule{(InboundRules.Count == 1 ? "" : "s")}";
    public string OutboundCountText => $"{OutboundRules.Count} outbound rule{(OutboundRules.Count == 1 ? "" : "s")}";

    private void InitializeFirewallConfig() => _ = RefreshFirewallConfigAsync();

    /// <summary>
    /// Rescans the host firewall. The scan shells out to pfctl, socketfilterfw
    /// and lsof, so it runs off the UI thread — the old ledger read was a file
    /// load and could afford to be synchronous; this cannot.
    /// </summary>
    [RelayCommand]
    private async Task RefreshFirewallConfig() => await RefreshFirewallConfigAsync();

    private async Task RefreshFirewallConfigAsync()
    {
        if (IsFirewallConfigScanning) return;
        IsFirewallConfigScanning = true;
        try
        {
            var scan = await Task.Run(() => HostScanner.Scan());
            ApplyHostScan(scan);
        }
        catch (Exception ex)
        {
            FirewallConfigMessage = $"Could not read the host firewall: {ex.Message}";
        }
        finally
        {
            IsFirewallConfigScanning = false;
        }

        IsAdmin = _firewall.IsAdministrator;
        OnPropertyChanged(nameof(InboundCountText));
        OnPropertyChanged(nameof(OutboundCountText));
    }

    private void ApplyHostScan(HostFirewallSnapshot scan)
    {
        InboundRules.Clear();
        OutboundRules.Clear();
        foreach (var rule in scan.Inbound) InboundRules.Add(rule);
        foreach (var rule in scan.Outbound) OutboundRules.Add(rule);

        ListeningServices.Clear();
        foreach (var listener in scan.Listeners.OrderBy(l => l.Protocol).ThenBy(l => l.Port.Length).ThenBy(l => l.Port))
            ListeningServices.Add(listener);

        var mine = scan.Inbound.Concat(scan.Outbound).Count(r => !r.IsForeign || r.Kind != FirewallRuleKind.Other);
        var total = scan.Inbound.Count + scan.Outbound.Count;
        FirewallConfigSummary =
            $"{scan.HostLabel} · {scan.Backend} · {scan.Status} · {scan.RulesSummary} " +
            $"({mine} from Network Sentinel, {total - mine} from the rest of the host)";

        var openCount = scan.Listeners.Count(l => l.Covered == "Open");
        FirewallConfigListenerText = scan.Listeners.Count == 0
            ? "No listening sockets were readable."
            : $"{scan.Listeners.Count} listening socket{(scan.Listeners.Count == 1 ? "" : "s")} · " +
              $"{openCount} reachable from anywhere";

        FirewallConfigPolicyText =
            $"Default policy: {scan.DefaultInbound} inbound, {scan.DefaultOutbound} outbound. " +
            (scan.DefaultInbound.Equals("Accept", StringComparison.OrdinalIgnoreCase)
                ? "Inbound traffic no rule matches is accepted, so an Allow rule opens a path through the rules " +
                  "above it rather than granting access on its own. "
                : "Inbound traffic no rule matches is dropped, so a service is only reachable if a rule admits it. ") +
            "Rules match in order, first match wins. " + scan.PrivilegeNote;

        FirewallConfigMessage = scan.Errors.Count > 0
            ? string.Join("  ", scan.Errors)
            : "";
    }

    [RelayCommand]
    private void AddInboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionInbound);

    [RelayCommand]
    private void AddOutboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionOutbound);

    /// <summary>
    /// The rule being edited when it did not come from this app's ledger. PF has
    /// no in-place edit, so — as FireWallConfig does — saving deletes the original
    /// where it lives and writes the new values as a fresh rule. Where the original
    /// cannot be deleted (a pf.conf or Apple-anchor rule, which PF loads whole)
    /// the delete refuses and the save stops rather than leaving both in force.
    /// </summary>
    private FirewallRuleInfo? _editingForeignRule;

    [RelayCommand]
    private void EditConfigRule(FirewallRuleInfo? rule)
    {
        if (rule == null) return;

        OpenRuleEditor(rule, rule.IsInbound
            ? FirewallRuleSpecs.DirectionInbound
            : FirewallRuleSpecs.DirectionOutbound);
    }

    private void OpenRuleEditor(FirewallRuleInfo? existing, string direction)
    {
        _suppressPresetHandler = true;
        try
        {
            _editingRuleName = existing is { IsForeign: false } ? existing.Name : "";
            _editingForeignRule = existing is { IsForeign: true } ? existing : null;
            RulePreset = PresetCustom;

            if (existing != null)
            {
                var spec = FirewallRuleSpecs.FromRule(existing);
                RuleLabel = spec.Label;
                RuleAction = spec.Action;
                RuleDirection = spec.Direction;
                RuleProtocol = spec.Protocol;
                RulePortRange = spec.PortRange;
                RuleAddresses = spec.Addresses;
            }
            else
            {
                RuleLabel = "";
                RuleAction = FirewallRuleSpecs.ActionBlock;
                RuleDirection = direction;
                RuleProtocol = "TCP";
                RulePortRange = "";
                RuleAddresses = "";
            }
        }
        finally
        {
            _suppressPresetHandler = false;
        }

        var editing = existing != null;
        var side = RuleDirection == FirewallRuleSpecs.DirectionOutbound ? "Outbound" : "Inbound";
        RuleEditorTitle = editing ? $"Edit an {side} Rule" : $"Add an {side} Rule";
        RuleEditorSaveText = editing ? "Save Rule" : "Add Rule";
        RuleEditorNote = editing
            ? (_editingForeignRule != null
                ? $"“{existing!.LabelText}” was created by {existing.OriginText}. " +
                  "Saving removes it there and writes these values as a new rule — " +
                  "PF has no in-place edit, so this is what editing one means."
                : "Replaces the loaded PF rule with these values.")
            : "Writes a PF rule into this Mac's Network Sentinel anchor. Applying asks for your Mac password.";
        RuleEditorError = "";
        IsRuleEditorOpen = true;
    }

    [RelayCommand]
    private void CancelRuleEditor()
    {
        IsRuleEditorOpen = false;
        RuleEditorError = "";
        _editingRuleName = "";
        _editingForeignRule = null;
    }

    [RelayCommand]
    private async Task SaveConfigRule()
    {
        // Validate before normalising — see FirewallRuleSpecs.TryPrepare. The other
        // order silently drops a port range the parser rejected, and an empty port
        // field means every port, so "443-80" would arm a catch-all block.
        var typed = new FirewallRuleSpec
        {
            Label = RuleLabel,
            Action = RuleAction,
            Direction = RuleDirection,
            Protocol = RuleProtocol,
            PortRange = RulePortRange,
            Addresses = RuleAddresses
        };

        if (!FirewallRuleSpecs.TryPrepare(typed, out var spec, out var error))
        {
            RuleEditorError = error;
            return;
        }
        RuleEditorError = "";

        if (!IsAdmin)
        {
            await PromptElevation();
            if (!IsAdmin) return;
        }

        if (!await ConfirmRuleImpact(spec))
            return;

        // Editing a rule this app did not write: remove the original where it lives
        // first. If that fails the save stops, because writing the replacement on
        // top would leave both rules in force — the wider of the two winning.
        var foreign = _editingForeignRule;
        if (foreign != null)
        {
            var removed = await Task.Run(() => _firewall.DeleteHostRule(foreign));
            if (!removed.Success)
            {
                RuleEditorError = $"The original rule could not be removed, so it was not replaced: {removed.Message}";
                FirewallConfigMessage = RuleEditorError;
                return;
            }
        }

        var replace = string.IsNullOrEmpty(_editingRuleName) ? null : _editingRuleName;
        var result = await Task.Run(() => _firewall.SaveCustomRule(spec, replace));

        FirewallConfigMessage = foreign != null && result.Success
            ? $"{result.Message} The rule it replaced was removed from {foreign.OriginText}."
            : result.Message;
        if (!result.Success)
        {
            RuleEditorError = foreign != null
                ? $"{result.Message} The original rule was already removed."
                : result.Message;
            return;
        }

        // Reflect the values PF actually took, so the label the operator sees in
        // the list is the one that was minted if they left the field blank.
        IsRuleEditorOpen = false;
        _editingRuleName = "";
        _editingForeignRule = null;
        await RefreshFirewallConfigAsync();
        RefreshFirewallRules();
    }

    /// <summary>
    /// Confirms the two rules that can take the machine off the network: one that
    /// blocks every address on every port, and one that closes remote access.
    /// </summary>
    private async Task<bool> ConfirmRuleImpact(FirewallRuleSpec spec)
    {
        var blocking = spec.Action == FirewallRuleSpecs.ActionBlock;
        var side = spec.Direction.ToLowerInvariant();

        if (blocking && FirewallRuleSpecs.IsCatchAll(spec))
        {
            var proceed = await DialogService.ConfirmAsync(
                $"“{spec.Label}” blocks every {side} connection on every port, from every address.\n\n" +
                (spec.Direction == FirewallRuleSpecs.DirectionInbound
                    ? "Nothing will be able to reach this Mac — including screen sharing and SSH you may be relying on right now.\n\n"
                    : "This Mac will not be able to reach anything — including the internet.\n\n") +
                "Add it anyway?",
                "This rule blocks everything");
            if (!proceed)
            {
                FirewallConfigMessage = "Rule not added.";
                return false;
            }
            return true;
        }

        if (blocking && spec.Direction == FirewallRuleSpecs.DirectionInbound &&
            FirewallRuleSpecs.CoversPort(spec, 22))
        {
            var proceed = await DialogService.ConfirmAsync(
                $"“{spec.Label}” blocks inbound SSH (port 22).\n\n" +
                "If you administer this Mac over SSH, this rule will end that access as soon as it loads.\n\n" +
                "Add it anyway?",
                "This rule blocks SSH");
            if (!proceed)
            {
                FirewallConfigMessage = "Rule not added.";
                return false;
            }
        }

        return true;
    }

    [RelayCommand]
    private async Task DeleteConfigRule(FirewallRuleInfo? rule)
    {
        if (rule == null) return;

        if (!IsAdmin)
        {
            await PromptElevation();
            if (!IsAdmin) return;
        }

        var warning = "";
        if (!rule.IsBlock && FirewallRuleSpecs.CoversPort(FirewallRuleSpecs.FromRule(rule), 22))
        {
            warning = "\n\nThis is the rule that allows SSH — deleting it leaves SSH to whatever the " +
                      "rules above decide, which may be a block. If you administer this host over SSH, " +
                      "that can end the session you are using now.";
        }
        else if (rule.IsForeign && rule.Kind == FirewallRuleKind.Other)
        {
            warning = $"\n\nThis rule belongs to {rule.OriginText}, not to Network Sentinel. " +
                      "Deleting it removes it from the host firewall for good.";
        }
        else if (!rule.IsCustom)
        {
            warning = $"\n\nThis rule came from {rule.OriginText.ToLowerInvariant()}. Deleting it here " +
                      "unblocks that traffic until something detects it again.";
        }

        var confirmed = await DialogService.ConfirmAsync(
            $"Delete “{rule.LabelText}”?\n\n" +
            $"{rule.ActionText} · {rule.DirectionText} · {rule.ProtocolText} · {rule.PortRangeText} · {rule.AddressListText}" +
            warning,
            "Delete rule");
        if (!confirmed) return;

        var result = await Task.Run(() => _firewall.DeleteHostRule(rule));
        FirewallConfigMessage = result.Message;

        // An IP block removed here is a deliberate release, exactly as it is on the
        // Firewall page — without this, auto-block would recreate it on the next hit.
        if (result.Success && rule.Kind == FirewallRuleKind.IpBlock &&
            FirewallService.TryExtractIpFromManagedRule(rule.Name, rule.RemoteAddresses, out var ip))
        {
            _prevention.NoteUnblocked(ip);
        }

        await RefreshFirewallConfigAsync();
        RefreshFirewallRules();
    }

    partial void OnRuleDirectionChanged(string value)
    {
        OnPropertyChanged(nameof(RuleAddressLabel));

        // Retitle a form the operator re-pointed with the Direction combo.
        var side = value == FirewallRuleSpecs.DirectionOutbound ? "Outbound" : "Inbound";
        RuleEditorTitle = string.IsNullOrEmpty(_editingRuleName)
            ? $"Add an {side} Rule"
            : $"Edit an {side} Rule";
    }

    partial void OnRulePresetChanged(string value)
    {
        if (_suppressPresetHandler || value == PresetCustom) return;
        if (!RulePresets.TryGetValue(value, out var preset)) return;

        RuleProtocol = preset.Protocol;
        RulePortRange = preset.Ports;
        RuleEditorError = "";
    }
}
