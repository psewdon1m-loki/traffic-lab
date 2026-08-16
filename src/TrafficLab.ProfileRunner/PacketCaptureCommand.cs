using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Runtime.Versioning;

internal static class PacketCaptureCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (OperatingSystem.IsLinux()) return await RunLinuxAsync(args);
        if (!OperatingSystem.IsWindows() || !File.Exists(Path.Combine(Environment.SystemDirectory, "pktmon.exe")))
        {
            Console.Error.WriteLine("pktmon is not available on this operating system.");
            return 2;
        }
        if (!args.Contains("--i-understand", StringComparer.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Packet capture can include unrelated machine traffic. Re-run with --i-understand after obtaining authorization and closing unrelated applications.");
            return 2;
        }
        if (!IsElevated())
        {
            Console.Error.WriteLine("Packet capture requires an elevated Administrator terminal.");
            return 2;
        }
        var duration = ReadInt(args, "--duration", 30, 1, 300);
        var outputDirectory = Path.GetFullPath(Read(args, "--outdir") ?? "artifacts");
        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var etl = Path.Combine(outputDirectory, $"traffic-capture-{stamp}.etl");
        var pcap = Path.Combine(outputDirectory, $"traffic-capture-{stamp}.pcapng");
        var pktmon = Path.Combine(Environment.SystemDirectory, "pktmon.exe");
        var statusBefore = await RunAsync(pktmon, ["status"], TimeSpan.FromSeconds(10));
        if (statusBefore.Stdout.Contains("Running", StringComparison.OrdinalIgnoreCase)
            || statusBefore.Stdout.Contains("Выполняется", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("pktmon is already active. Traffic Lab will not stop or modify a capture it did not start.");
            return 2;
        }
        var started = false;
        ProcessResultLite? start = null;
        ProcessResultLite? stop = null;
        ProcessResultLite? convert = null;
        try
        {
            start = await RunAsync(pktmon, ["start", "--capture", "--pkt-size", "0", "--file-name", etl], TimeSpan.FromSeconds(15));
            started = start.ExitCode == 0;
            if (!started)
            {
                Console.Error.WriteLine("pktmon start failed: " + ProgramAccess.Truncate(ProgramAccess.Redact(start.Stderr + " " + start.Stdout), 800));
                return 1;
            }
            Console.WriteLine($"Capturing for {duration} seconds. Keep only authorized test traffic active.");
            await Task.Delay(TimeSpan.FromSeconds(duration));
        }
        finally
        {
            if (started) stop = await RunAsync(pktmon, ["stop"], TimeSpan.FromSeconds(15));
        }
        if (File.Exists(etl)) convert = await RunAsync(pktmon, ["etl2pcap", etl, "--out", pcap], TimeSpan.FromSeconds(60));
        var report = new
        {
            schemaVersion = "1.0",
            generatedAt = DateTimeOffset.UtcNow,
            durationSeconds = duration,
            etlPath = etl,
            etlBytes = File.Exists(etl) ? new FileInfo(etl).Length : 0,
            pcapngPath = File.Exists(pcap) ? pcap : null,
            pcapngBytes = File.Exists(pcap) ? new FileInfo(pcap).Length : 0,
            start = Sanitize(start),
            stop = Sanitize(stop),
            conversion = Sanitize(convert),
            privacy = "The capture may contain packet payloads and unrelated traffic. Treat it as sensitive and do not include it in normal JSON/CSV report sharing."
        };
        var json = Path.Combine(outputDirectory, $"traffic-capture-{stamp}.json");
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(report, LabCommands.JsonOptions), new UTF8Encoding(false));
        Console.WriteLine("Capture metadata: " + json);
        if (File.Exists(pcap)) Console.WriteLine("PCAPNG          : " + pcap);
        return File.Exists(pcap) ? 0 : 1;
    }

    private static async Task<int> RunLinuxAsync(string[] args)
    {
        var tcpdump = new[] { "/usr/bin/tcpdump", "/usr/sbin/tcpdump" }.FirstOrDefault(File.Exists);
        if (tcpdump is null)
        {
            Console.Error.WriteLine("tcpdump is not installed. Re-run the Linux bootstrap without --no-packages.");
            return 2;
        }
        if (!args.Contains("--i-understand", StringComparer.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Packet capture can include unrelated machine traffic. Re-run with --i-understand after obtaining authorization and closing unrelated applications.");
            return 2;
        }
        if (!IsLinuxRoot())
        {
            Console.Error.WriteLine("Linux packet capture requires root or equivalent capture capabilities.");
            return 2;
        }

        var duration = ReadInt(args, "--duration", 30, 1, 300);
        var outputDirectory = Path.GetFullPath(Read(args, "--outdir") ?? "artifacts");
        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss");
        var pcap = Path.Combine(outputDirectory, $"traffic-capture-{stamp}.pcap");
        var json = Path.Combine(outputDirectory, $"traffic-capture-{stamp}.json");
        const int packetLimit = 50_000;
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = tcpdump,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        foreach (var argument in new[] { "-i", "any", "-s", "0", "-U", "-c", packetLimit.ToString(), "-w", pcap })
            process.StartInfo.ArgumentList.Add(argument);

        var watch = Stopwatch.StartNew();
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        var durationTask = Task.Delay(TimeSpan.FromSeconds(duration));
        await Task.WhenAny(durationTask, process.WaitForExitAsync());
        if (!process.HasExited)
        {
            await RunAsync("/bin/kill", ["-INT", process.Id.ToString()], TimeSpan.FromSeconds(5));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try { await process.WaitForExitAsync(cancellation.Token); }
            catch (OperationCanceledException) { try { process.Kill(true); } catch { } }
        }
        watch.Stop();
        var standardOutput = await stdout;
        var standardError = await stderr;
        var size = File.Exists(pcap) ? new FileInfo(pcap).Length : 0;
        var report = new
        {
            schemaVersion = "1.0",
            generatedAt = DateTimeOffset.UtcNow,
            platform = "linux",
            captureTool = "tcpdump",
            interfaceName = "any",
            requestedDurationSeconds = duration,
            actualDurationMs = watch.ElapsedMilliseconds,
            packetLimit,
            pcapPath = File.Exists(pcap) ? pcap : null,
            pcapBytes = size,
            exitCode = process.ExitCode,
            stdout = ProgramAccess.Truncate(ProgramAccess.Redact(standardOutput), 1000),
            stderr = ProgramAccess.Truncate(ProgramAccess.Redact(standardError), 1000),
            privacy = "The capture may contain packet payloads and unrelated traffic. It is excluded from normal result ZIPs and must be treated as sensitive."
        };
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(report, LabCommands.JsonOptions), new UTF8Encoding(false));
        Console.WriteLine("Capture metadata: " + json);
        if (File.Exists(pcap)) Console.WriteLine("PCAP            : " + pcap);
        return size > 24 ? 0 : 1;
    }

    private static object? Sanitize(ProcessResultLite? result) => result is null ? null : new { result.ExitCode, stdout = ProgramAccess.Truncate(ProgramAccess.Redact(result.Stdout), 1000), stderr = ProgramAccess.Truncate(ProgramAccess.Redact(result.Stderr), 1000) };

    private static async Task<ProcessResultLite> RunAsync(string file, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo { FileName = file, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);
        try { await process.WaitForExitAsync(cancellation.Token); }
        catch (OperationCanceledException) { try { process.Kill(true); } catch { } return new ProcessResultLite(-1, await stdout, (await stderr) + " timeout"); }
        return new ProcessResultLite(process.ExitCode, await stdout, await stderr);
    }

    [SupportedOSPlatform("windows")]
    private static bool IsElevated()
    {
        try { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }
    private static bool IsLinuxRoot()
    {
        try
        {
            var uid = File.ReadLines("/proc/self/status").FirstOrDefault(line => line.StartsWith("Uid:", StringComparison.Ordinal));
            return uid is not null && uid.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Skip(1).FirstOrDefault() == "0";
        }
        catch { return false; }
    }
    private static string? Read(string[] args, string name) { var index = Array.FindIndex(args, value => value.Equals(name, StringComparison.OrdinalIgnoreCase)); return index >= 0 && index + 1 < args.Length ? args[index + 1] : null; }
    private static int ReadInt(string[] args, string name, int fallback, int minimum, int maximum) => int.TryParse(Read(args, name), out var value) ? Math.Clamp(value, minimum, maximum) : fallback;
}

internal sealed record ProcessResultLite(int ExitCode, string Stdout, string Stderr);
