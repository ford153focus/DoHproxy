using System.Text;

namespace DoHproxy.Logging;

/// <summary>
/// Console logger that writes timestamped, colorized, level-tagged lines.
/// (copied from snippets/cs/Helpers/BlueLoggers/BlueLogger2.cs to keep this project self-sufficient)
/// </summary>
public class BlueLogger2
{
    private string Timestamp => DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
    public bool InsertNewLine;
    private static readonly object ConsoleLock = new();


    public void LogTrace(string msg) => Write(ConsoleColor.Black, ConsoleColor.DarkGray, "DEBUG", msg);
    public void LogDebug(string msg) => Write(ConsoleColor.DarkGray, ConsoleColor.Black, "DEBUG", msg);
    public void LogInfo(string msg) => Write(ConsoleColor.White, ConsoleColor.Black, "INFO", msg);
    public void LogSuccess(string msg) => Write(ConsoleColor.Green, ConsoleColor.Black, "SUCCESS", msg);
    public void LogWarning(string msg) => Write(ConsoleColor.Yellow, ConsoleColor.Black, "WARNING", msg);
    public void LogError(string msg) => Write(ConsoleColor.Red, ConsoleColor.Black, "ERROR", msg);
    public void LogCritical(string msg) => Write(ConsoleColor.Red, ConsoleColor.White, "ERROR", msg);

    private void Write(ConsoleColor bg, ConsoleColor fg, string level, string msg)
    {
        lock (ConsoleLock)
        {
            Console.OutputEncoding = Encoding.Default;
            Console.BackgroundColor = bg;
            Console.ForegroundColor = fg;
            Console.Write($"{Timestamp} :: {level} ►");
            Console.ResetColor();
            Console.Write($" {msg}");
            if (InsertNewLine) Console.WriteLine();
        }
    }

    public BlueLogger2(bool insertNewLine = false)
    {
        this.InsertNewLine = insertNewLine;
    }
}
