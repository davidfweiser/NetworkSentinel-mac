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
/// The backend is PF through <see cref="FirewallService"/>, so the rules here
/// live in the same anchor and the same ledger as the app's own blocks. What
/// they cannot do is change PF's default policy: macOS passes anything no rule
/// matches, so an Allow rule is a hole punched through the rules above it, not
/// a permission grant. The view says so rather than implying a deny-by-default
/// firewall that is not there.
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

    public string InboundCountText => $"{InboundRules.Count} inbound rule{(InboundRules.Count == 1 ? "" : "s")}";
    public string OutboundCountText => $"{OutboundRules.Count} outbound rule{(OutboundRules.Count == 1 ? "" : "s")}";

    private void InitializeFirewallConfig() => RefreshFirewallConfig();

    [RelayCommand]
    private void RefreshFirewallConfig()
    {
        try
        {
            var rules = _firewall.GetConfigRules();

            InboundRules.Clear();
            OutboundRules.Clear();
            foreach (var rule in rules)
            {
                if (rule.IsInbound) InboundRules.Add(rule);
                else OutboundRules.Add(rule);
            }

            var custom = rules.Count(r => r.IsCustom);
            FirewallConfigSummary =
                $"{Environment.MachineName} · {rules.Count} rule{(rules.Count == 1 ? "" : "s")} loaded " +
                $"({custom} from this page, {rules.Count - custom} from auto-block and manual blocks)";
        }
        catch (Exception ex)
        {
            FirewallConfigMessage = $"Could not read the rule list: {ex.Message}";
        }

        IsAdmin = _firewall.IsAdministrator;
        FirewallConfigPolicyText =
            "Default policy: PF passes anything no rule matches, so Allow rules open a path through the " +
            "rules above them rather than granting access on their own. Blocks created by auto-block and " +
            "the Firewall page are evaluated first; the rules below then match in order, first match wins.";

        OnPropertyChanged(nameof(InboundCountText));
        OnPropertyChanged(nameof(OutboundCountText));
    }

    [RelayCommand]
    private void AddInboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionInbound);

    [RelayCommand]
    private void AddOutboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionOutbound);

    [RelayCommand]
    private async Task EditConfigRule(FirewallRuleInfo? rule)
    {
        if (rule == null) return;
        if (!rule.IsCustom)
        {
            await DialogService.ShowInfoAsync(
                $"“{rule.LabelText}” was created by {rule.OriginText.ToLowerInvariant()}, not by this page.\n\n" +
                "Remove it from the Firewall page (or let its expiry run out) rather than editing it here — " +
                "rewriting it as a config rule would change what it matches.",
                "Not an editable rule");
            return;
        }

        OpenRuleEditor(rule, rule.IsInbound
            ? FirewallRuleSpecs.DirectionInbound
            : FirewallRuleSpecs.DirectionOutbound);
    }

    private void OpenRuleEditor(FirewallRuleInfo? existing, string direction)
    {
        _suppressPresetHandler = true;
        try
        {
            _editingRuleName = existing?.Name ?? "";
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
            ? "Replaces the loaded PF rule with these values."
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
    }

    [RelayCommand]
    private async Task SaveConfigRule()
    {
        var spec = FirewallRuleSpecs.Normalize(new FirewallRuleSpec
        {
            Label = RuleLabel,
            Action = RuleAction,
            Direction = RuleDirection,
            Protocol = RuleProtocol,
            PortRange = RulePortRange,
            Addresses = RuleAddresses
        });

        var error = FirewallRuleSpecs.Validate(spec);
        if (error.Length > 0)
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

        var replace = string.IsNullOrEmpty(_editingRuleName) ? null : _editingRuleName;
        var result = await Task.Run(() => _firewall.SaveCustomRule(spec, replace));

        FirewallConfigMessage = result.Message;
        if (!result.Success)
        {
            RuleEditorError = result.Message;
            return;
        }

        // Reflect the values PF actually took, so the label the operator sees in
        // the list is the one that was minted if they left the field blank.
        IsRuleEditorOpen = false;
        _editingRuleName = "";
        RefreshFirewallConfig();
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
                      "rules above decide, which may be a block.";
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

        var result = await Task.Run(() => _firewall.RemoveRule(rule.Name));
        FirewallConfigMessage = result.Message;

        // An IP block removed here is a deliberate release, exactly as it is on the
        // Firewall page — without this, auto-block would recreate it on the next hit.
        if (result.Success && rule.Kind == FirewallRuleKind.IpBlock &&
            FirewallService.TryExtractIpFromManagedRule(rule.Name, rule.RemoteAddresses, out var ip))
        {
            _prevention.NoteUnblocked(ip);
        }

        RefreshFirewallConfig();
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
