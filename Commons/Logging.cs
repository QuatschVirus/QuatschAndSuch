using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

// ASCII Art URl: https://textkool.com/en/ascii-art-generator?hl=default&vl=default&font=DOS%20Rebel&text=

namespace QuatschAndSuch
{
    public class Logging
    {
        public Logging(string path, bool showInfo = true, bool writeToFile = true)
        {
            LogFile = path;
            ShowInfo = showInfo;
            WriteToFile = writeToFile;
        }

        public readonly bool ShowInfo;
        public readonly bool WriteToFile;
        public readonly string LogFile;

        public event Action BeforeExitOnCritical;

        public void PrintASCIIArt(string art, ConsoleColor? color = null)
        {
            RawPrint(art, color, writeToFileOverride: false);
        }

        public void Info(string message, string origin = "", bool displayTrace = false, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawPrint($"[INFO|{DateTime.Now:HH:mm:ss.fff}]: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", writeToConsoleOverride: ShowInfo);
        }

        public void Warn(string type, string message, string origin="", bool displayTrace = false, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawPrint($"[WARN|{DateTime.Now:HH:mm:ss.fff}]: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ConsoleColor.Yellow);
        }

        public void Error(string type, string message, string origin="", bool displayTrace = true, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawPrint($"[ERROR|{DateTime.Now:HH:mm:ss.fff}]: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ConsoleColor.Red);
        }

        public void CriticalError(string type, string message, int exitCode = -1, string origin="", bool displayTrace = true, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawPrint($"[CRITICAL ERROR|{DateTime.Now:HH:mm:ss.fff}]: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}. Terminating process with exit code 0x{exitCode:X} ({exitCode})", ConsoleColor.Red);
            BeforeExitOnCritical.Invoke();
            Environment.Exit(exitCode);
        }

        public void RawPrint(string content, ConsoleColor? color = null, bool writeToConsoleOverride = true, bool writeToFileOverride = true)
        {
            ConsoleColor prev = Console.ForegroundColor;
            if (color != null)
            {
                Console.ForegroundColor = color.Value;
            }
            if (writeToConsoleOverride)Console.WriteLine(content);
            if (WriteToFile && writeToFileOverride)
            {
                File.AppendAllText(LogFile, content);
            }
            Console.ForegroundColor = prev;
        }

        public static string LogFileName => $"Log-{DateTime.Now:yyyy-MM-dd-HH-mm}.log";
    }
}
