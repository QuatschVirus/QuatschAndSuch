using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.Marshalling;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

// ASCII Art URl: https://textkool.com/en/ascii-art-generator?hl=default&vl=default&font=DOS%20Rebel&text=

namespace QuatschAndSuch.Logging
{
    public class Logger
    {
        public Logger(string path, bool showInfo = true, bool colorOutput = true, ANSICode infoColor = null)
        {
            LogFile = path;
            ShowInfo = showInfo;
            ColorOutput = colorOutput;
            InfoColor = infoColor;
        }

        public readonly bool ShowInfo;
        public readonly bool ColorOutput;
        public readonly List<StreamWriter> streams;
        public readonly List<StreamWriter> errorStreams;
        public readonly string LogFile;
        public readonly ANSICode InfoColor;

        public event Action BeforeExitOnCritical;

        public void PrintASCIIArt(string art, ANSICode color = null)
        {
            RawWrite(art, color, writeToFileOverride: false);
        }

        public void Info(string message, string origin = "", bool displayTrace = false, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[INFO|{DateTime.Now:HH:mm:ss.fff}]: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", InfoColor, writeToConsoleOverride: ShowInfo);
        }

        public void Warn(string type, string message, string origin="", bool displayTrace = false, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[WARN|{DateTime.Now:HH:mm:ss.fff}]: {type}: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ANSICode.Yellow);
        }

        public void Error(string type, string message, string origin="", bool displayTrace = true, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[ERROR|{DateTime.Now:HH:mm:ss.fff}]: {type}: {message}{(origin == "" ? "" : $" ({origin})")}{(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ANSICode.Red, writeToErrorStream: true);
        }

        public void CriticalError(string type, string message, int exitCode = -1, string origin="", bool displayTrace = true, [CallerLineNumber] int sourceLine = -1, [CallerFilePath] string sourcePath = "")
        {
            RawWrite($"[CRITICAL ERROR|{DateTime.Now:HH:mm:ss.fff}]: {type}: {message} {(origin == "" ? "" : $" ({origin})")} {(displayTrace ? $" @{sourcePath}:{sourceLine}" : "")}", ANSICode.Red, writeToErrorStream: true);
            BeforeExitOnCritical.Invoke();
            Environment.Exit(exitCode);
        }

        public void RawWrite(string content, ANSICode color = null, bool writeToErrorStream = false, bool writeToConsoleOverride = true, bool writeToFileOverride = true)
        {
            if (color == null) color = ANSICode.Reset;

            List<StreamWriter> writers = writeToErrorStream ? errorStreams : streams;
            foreach (StreamWriter writer in writers)
            {

            }
        }

        public static string LogFileName => $"Log-{DateTime.Now:yyyy-MM-dd-HH-mm}.log";
    }

    public class ANSICode
    {
        int primary = 0;
        int[] parameters;
        string content = "";

        public ANSICode Bright => new(primary + 60);
        public ANSICode Background => new(primary + 10);

        public static ANSICode Black => 30;
        public static ANSICode Red => 31;
        public static ANSICode Green => 32;
        public static ANSICode Yellow => 33;
        public static ANSICode Blue => 34;
        public static ANSICode Magenta => 35;
        public static ANSICode Cyan => 36;
        public static ANSICode White => 37;

        public static ANSICode Palette(byte index)
        {
            return new(38, 5, index);
        }

        public static ANSICode RGB(byte r, byte g, byte b)
        {
            return new(38, 2, r, g, b);
        }

        public static ANSICode RGB(Color c)
        {
            return new(38, 2, c.R, c.G, c.B);
        }

        public ANSICode(int number)
        {
            primary = number;
        }

        public ANSICode(int primary, params int[] parameters)
        {
            this.primary = primary;
            this.parameters = parameters;
        }

        public ANSICode(string content)
        {
            this.content = content;
        }

        public static implicit operator string(ANSICode code)
        {
            string secondary = (code.parameters.Length > 0) ? ";" + string.Join(';', code.parameters) : "";
            return (code.content == "") ? $"\x1b[{code.primary}{secondary}m" : code.content;
        }

        public static implicit operator ANSICode(int i)
        {
            return new(i);
        }

        public static ANSICode Reset => 0;
    }
}
