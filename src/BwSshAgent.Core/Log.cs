using BwSshAgent.Core.Storage;

namespace BwSshAgent.Core;

/// <summary>Small diagnostic log. Never pass key material, passwords or vault contents here.</summary>
public static class Log
{
    private static readonly Lock Gate = new();
    private const long MaxSize = 512 * 1024;

    public static void Info(string message) => Write("INFO", message);

    public static void Warn(string message) => Write("WARN", message);

    public static void Error(string message, Exception? ex = null) =>
        Write("ERROR", ex == null ? message : $"{message}: {ex.GetType().Name}: {ex.Message}");

    private static void Write(string level, string message)
    {
        try
        {
            lock (Gate)
            {
                var path = AppPaths.File("app.log");
                var info = new FileInfo(path);
                if (info.Exists && info.Length > MaxSize)
                {
                    File.Move(path, path + ".old", overwrite: true);
                }
                File.AppendAllText(path, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}");
            }
        }
        catch (Exception)
        {
        }
    }
}
