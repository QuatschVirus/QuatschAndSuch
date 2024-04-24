using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.Marshalling;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

// ASCII Art URl: https://textkool.com/en/ascii-art-generator?hl=default&vl=default&font=DOS%20Rebel&text=

namespace QuatschAndSuch.Logging
{
    public class Logger
    {
        public Logger(string path, bool showInfo = true, bool colorOutput = true)
        {
            LogFile = path;
            ShowInfo = showInfo;
            ColorOutput = colorOutput;
        }

        public readonly bool ShowInfo;
        public readonly bool ColorOutput;
        public readonly List<StreamWriter> streams;
        public readonly List<StreamWriter> errorStreams;
        public readonly string LogFile;

        public event Action BeforeExitOnCritical;

        public void PrintASCIIArt(string art, ConsoleColor? color = null)
        {
            RawWrite(art, color, writeToFileOverride: false);
        }

        public void Info(string message, string origin = "", bool displayTrace = false, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[INFO|{DateTime.Now:HH:mm:ss.fff}]: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", writeToConsoleOverride: ShowInfo);
        }

        public void Warn(string type, string message, string origin="", bool displayTrace = false, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[WARN|{DateTime.Now:HH:mm:ss.fff}]: {type}: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ConsoleColor.Yellow);
        }

        public void Error(string type, string message, string origin="", bool displayTrace = true, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[ERROR|{DateTime.Now:HH:mm:ss.fff}]: {type}: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ConsoleColor.Red, writeToErrorStream: true);
        }

        public void CriticalError(string type, string message, int exitCode = -1, string origin="", bool displayTrace = true, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[CRITICAL ERROR|{DateTime.Now:HH:mm:ss.fff}]: {type}: {message} {(origin == "" ? "" : $" ({origin})")} {(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ConsoleColor.Red, writeToErrorStream: true);
            BeforeExitOnCritical.Invoke();
            Environment.Exit(exitCode);
        }

        public void RawWrite(string content, ConsoleColor? color = null, bool writeToErrorStream = false, bool writeToConsoleOverride = true, bool writeToFileOverride = true)
        {
            
            List<StreamWriter> writers = writeToErrorStream ? errorStreams : streams;
            foreach (StreamWriter writer in writers)
            {

            }
        }

        public static string LogFileName => $"Log-{DateTime.Now:yyyy-MM-dd-HH-mm}.log";
    }

    public class ANSICode
    {
        int primary;
        string content;



        public ANSICode(int number)
        {
            primary = number;
        }

        public ANSICode(string content)
        {
            this.content = content;
        }

        public static implicit operator string(ANSICode code)
        {
            return ;
        }

        public static string FromPrimaryNumber(int number)
        {
            return $"\x1b[{number}m";
        }

        public const string Reset = "\x1b[0m";
    }
}
