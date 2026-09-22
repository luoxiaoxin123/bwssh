using BwSshAgent.Core;
using BwSshAgent.App.Services;
using BwSshAgent.Core.Ssh;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace BwSshAgent.App.Views;

public sealed partial class AddKeyDialog : ContentDialog
{
    private const int MaxKeyFileSize = 64 * 1024;
    private readonly AppHost _host;
    private readonly IntPtr _hwnd;

    public AddKeyDialog(AppHost host, IntPtr hwnd)
    {
        _host = host;
        _hwnd = hwnd;
        InitializeComponent();
    }

    /// <summary>Set after a successful save.</summary>
    public string? SavedName { get; private set; }
    public string? SavedPublicKey { get; private set; }

    private bool ImportMode => ModeBar.SelectedItem == ModeBar.Items[1];

    private void OnModeChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
    {
        GeneratePanel.Visibility = ImportMode ? Visibility.Collapsed : Visibility.Visible;
        ImportPanel.Visibility = ImportMode ? Visibility.Visible : Visibility.Collapsed;
        ErrorText.Visibility = Visibility.Collapsed;
    }

    private async void OnPickFile(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, _hwnd);
        StorageFile? file;
        try
        {
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception ex)
        {
            ShowError(L.T("无法打开文件选择器：", "Cannot open the file picker: ") + ex.Message);
            return;
        }
        if (file == null)
        {
            return;
        }
        var props = await file.GetBasicPropertiesAsync();
        if (props.Size > MaxKeyFileSize)
        {
            ShowError(L.T("文件太大，不像是私钥文件。", "The file is too large to be a private key."));
            return;
        }
        KeyBox.Text = await FileIO.ReadTextAsync(file);
        if (string.IsNullOrWhiteSpace(NameBox.Text))
        {
            NameBox.Text = Path.GetFileNameWithoutExtension(file.Name);
        }
    }

    private async void OnSave(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        var deferral = args.GetDeferral();
        try
        {
            args.Cancel = !await SaveAsync();
        }
        finally
        {
            deferral.Complete();
        }
    }

    private async Task<bool> SaveAsync()
    {
        ErrorText.Visibility = Visibility.Collapsed;
        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            ShowError(L.T("请填写名称。", "Enter a name."));
            return false;
        }
        var importing = ImportMode;
        var pem = KeyBox.Text;
        var passphrase = PassphraseBox.Password;
        var typeIndex = TypeBox.SelectedIndex;
        if (importing && string.IsNullOrWhiteSpace(pem))
        {
            ShowError(L.T("请粘贴私钥内容，或从文件读取。", "Paste a private key or read it from a file."));
            return false;
        }

        SetBusy(true);
        SshPrivateKey? key = null;
        try
        {
            key = await Task.Run(() => importing
                ? SshKeyParser.Parse(pem, string.IsNullOrEmpty(passphrase) ? null : passphrase)
                : typeIndex switch
                {
                    1 => SshKeyFactory.GenerateRsa(3072),
                    2 => SshKeyFactory.GenerateRsa(4096),
                    _ => SshKeyFactory.GenerateEd25519(),
                });

            var existing = _host.Session.PublicKeys.FirstOrDefault(k => k.Blob.AsSpan().SequenceEqual(key.PublicBlob));
            if (existing != null)
            {
                ShowError(L.T($"这把密钥已经在密码库里了（“{existing.Name}”）。", $"This key is already in your vault (\"{existing.Name}\")."));
                return false;
            }

            var error = await _host.Accounts.AddSshKeyAsync(name, key);
            if (error != null)
            {
                ShowError(L.T("保存失败：", "Save failed: ") + error);
                return false;
            }
            SavedName = name;
            SavedPublicKey = key.PublicKeyLine(name);
            KeyBox.Text = "";
            PassphraseBox.Password = "";
            return true;
        }
        catch (SshPassphraseRequiredException ex)
        {
            ShowError(ex.Message);
            PassphraseBox.Focus(FocusState.Programmatic);
            return false;
        }
        catch (Exception ex) when (ex is SshWrongPassphraseException or SshFormatException or System.Security.Cryptography.CryptographicException)
        {
            ShowError(ex.Message);
            return false;
        }
        finally
        {
            key?.Dispose();
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        Busy.IsActive = busy;
        IsPrimaryButtonEnabled = !busy;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
