using BwSshAgent.Core;
using System.Diagnostics;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Audit;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace BwSshAgent.App.Views;

public sealed class AuditRow
{
    public required string Time { get; init; }
    public required string Decision { get; init; }
    public required string Operation { get; init; }
    public required string Process { get; init; }
    public required string Detail { get; init; }
    public required string Glyph { get; init; }
    public required Brush Brush { get; init; }
    public required string SearchText { get; init; }
}

public sealed partial class AuditPage : Page
{
    private static readonly Brush Green = new SolidColorBrush(Colors.SeaGreen);
    private static readonly Brush Red = new SolidColorBrush(Colors.IndianRed);
    private static readonly Brush Grey = new SolidColorBrush(Colors.Gray);

    private MainWindow? _window;
    private List<AuditRow> _rows = [];
    private AppHost Host => _window!.Host;

    public AuditPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        _window = (MainWindow)e.Parameter;
        Host.Audit.EntryAdded += OnEntryAdded;
        RangeBox.SelectedIndex = 1;
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        Host.Audit.EntryAdded -= OnEntryAdded;
    }

    private void OnEntryAdded(AuditEntry entry) => DispatcherQueue.TryEnqueue(Load);

    private int Days => RangeBox.SelectedItem is ComboBoxItem { Tag: string tag } && int.TryParse(tag, out var d) ? d : 7;

    private void Load()
    {
        if (_window == null)
        {
            return;
        }
        var cutoff = DateTimeOffset.Now.Date.AddDays(1 - Days);
        _rows = Host.Audit.ReadRecent(Days)
            .Where(e => e.Time >= cutoff)
            .Select(ToRow)
            .ToList();
        ApplyFilter();
    }

    private static AuditRow ToRow(AuditEntry e)
    {
        // Entries may have been written in either language.
        var failed = Has(e.Decision, "失败", "failed");
        var approved = !failed && Has(e.Decision, "批准", "approved");
        var denied = failed || Has(e.Decision, "拒绝", "denied");
        var details = new List<string> { L.T($"密钥 {e.KeyName}", $"Key {e.KeyName}") };
        if (e.Destination != null)
        {
            details.Add(L.T("目标 ", "to ") + e.Destination);
        }
        else if (e.RemoteUser != null)
        {
            details.Add(L.T("用户 ", "user ") + e.RemoteUser);
        }
        if (e.HostFingerprint != null)
        {
            details.Add(L.T("主机 ", "host ") + e.HostFingerprint);
        }
        if (e.Forwarded)
        {
            details.Add(L.T("⚠ 代理转发", "⚠ agent forwarding"));
        }
        details.Add("PID " + e.Pid);
        var detail = string.Join(" · ", details);
        return new AuditRow
        {
            Time = e.Time.LocalDateTime.ToString("MM-dd HH:mm:ss"),
            Decision = e.Decision,
            Operation = e.Operation,
            Process = e.Process,
            Detail = detail,
            Glyph = approved ? "" : denied ? "" : "",
            Brush = approved ? Green : denied ? Red : Grey,
            SearchText = $"{e.Decision} {e.Operation} {e.Process} {detail}",
        };
    }

    private static bool Has(string text, string zh, string en) =>
        text.Contains(zh, StringComparison.Ordinal) || text.Contains(en, StringComparison.OrdinalIgnoreCase);

    private void ApplyFilter()
    {
        var filter = FilterBox.Text.Trim();
        var rows = filter.Length == 0 ? _rows : _rows.Where(r => r.SearchText.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        EntriesList.ItemsSource = rows;
        EmptyText.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnFilterChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void OnRangeChanged(object sender, SelectionChangedEventArgs e) => Load();

    private void OnRefresh(object sender, RoutedEventArgs e) => Load();

    private void OnOpenFolder(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{Host.Audit.Folder}\"") { UseShellExecute = true });
}
