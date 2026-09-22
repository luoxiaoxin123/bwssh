using BwSshAgent.App.Services;
using BwSshAgent.Core;
using Microsoft.UI.Xaml;

namespace BwSshAgent.App;

public partial class App : Application
{
    private readonly bool _background;

    public App(bool background)
    {
        _background = background;
        InitializeComponent();
        // The app lives in the tray; closing the window must not end the process.
        DispatcherShutdownMode = DispatcherShutdownMode.OnExplicitShutdown;
        UnhandledException += (_, e) =>
        {
            Log.Error("Unhandled UI exception", e.Exception);
            e.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Log.Error("Unhandled exception", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Log.Error("Unobserved task exception", e.Exception);
            e.SetObserved();
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        AppHost.Start(_background);
    }
}
