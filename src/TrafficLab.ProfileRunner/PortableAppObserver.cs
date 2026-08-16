using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

internal static class PortableAppObserver
{
    public static async Task<int> RunAsync(string[] args)
    {
        var processNames = ReadMany(args, "--process");
        if (processNames.Count == 0)
        {
            Console.Error.WriteLine("Pass one or more --process names, for example: observe --process steam --process steamwebhelper");
            return 2;
        }
        var duration = ReadInt(args, "--duration", 30, 1, 3600);
        var interval = ReadInt(args, "--interval", 1, 1, 30);
        var proxyPort = ReadInt(args, "--proxy-port", 0, 0, 65535);
        var outputDirectory = Path.GetFullPath(Read(args, "--outdir") ?? "artifacts");
        Directory.CreateDirectory(outputDirectory);
        var routeBefore = await ExtendedDiagnostics.CaptureRouteSnapshotAsync(TimeSpan.FromSeconds(10));
        var environmentBefore = Program.CaptureNetworkEnvironmentForCommands();
        var observations = new List<AppConnectionObservation>();
        var processInstances = new Dictionary<int, ObservedProcess>();
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(duration))
        {
            var matching = processNames.SelectMany(name => Process.GetProcessesByName(name)).ToArray();
            foreach (var process in matching)
            {
                try
                {
                    processInstances[process.Id] = new ObservedProcess(process.ProcessName, process.Id, Safe(() => process.MainModule?.FileName), SafeDate(() => process.StartTime));
                }
                catch { }
                finally { process.Dispose(); }
            }
            if (processInstances.Count > 0)
            {
                observations.AddRange(await ReadNetstatAsync(processInstances.Keys.ToHashSet(), proxyPort));
            }
            await Task.Delay(TimeSpan.FromSeconds(interval));
        }
        watch.Stop();
        var routeAfter = await ExtendedDiagnostics.CaptureRouteSnapshotAsync(TimeSpan.FromSeconds(10));
        var environmentAfter = Program.CaptureNetworkEnvironmentForCommands();
        var distinctConnections = observations
            .GroupBy(item => new { item.ProcessId, item.Protocol, item.LocalAddress, item.LocalPort, item.RemoteAddress, item.RemotePort, item.State })
            .Select(group => group.OrderBy(item => item.ObservedAt).First() with { SampleCount = group.Count() })
            .OrderBy(item => item.ProcessName)
            .ThenBy(item => item.RemoteAddress)
            .ThenBy(item => item.RemotePort)
            .ToArray();
        var proxyConnections = distinctConnections.Where(item => item.IsExpectedLoopbackProxy).ToArray();
        var externalConnections = distinctConnections.Where(item => item.IsExternal).ToArray();
        var routeChanged = routeBefore.Supported && routeAfter.Supported && !string.Equals(routeBefore.RouteTableSha256, routeAfter.RouteTableSha256, StringComparison.OrdinalIgnoreCase);
        var inferredMode = routeChanged || environmentAfter.PotentialTunnelInterfaces.Except(environmentBefore.PotentialTunnelInterfaces, StringComparer.OrdinalIgnoreCase).Any()
            ? "system-route-or-tun-observed"
            : proxyConnections.Length > 0 && externalConnections.Length > 0 ? "mixed-or-split-observed"
            : proxyConnections.Length > 0 ? "explicit-proxy-observed"
            : externalConnections.Length > 0 ? "direct-observed"
            : "insufficient-traffic";
        var report = new
        {
            schemaVersion = "1.0",
            generatedAt = DateTimeOffset.UtcNow,
            durationSeconds = duration,
            intervalSeconds = interval,
            expectedProxyPort = proxyPort == 0 ? null : (int?)proxyPort,
            processNames,
            processes = processInstances.Values.OrderBy(item => item.ProcessName).ThenBy(item => item.ProcessId).ToArray(),
            environmentBefore,
            environmentAfter,
            routeBefore,
            routeAfter,
            summary = new
            {
                processCount = processInstances.Count,
                distinctConnectionCount = distinctConnections.Length,
                proxyConnectionCount = proxyConnections.Length,
                externalConnectionCount = externalConnections.Length,
                routeChanged,
                inferredMode,
                confidence = distinctConnections.Length > 0 ? "medium" : "low",
                limitation = "Process sockets prove observed paths during the capture window, not every route the application may use. Packet payloads are never captured."
            },
            connections = distinctConnections
        };
        var json = Path.Combine(outputDirectory, $"app-observation-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json");
        var csv = Path.ChangeExtension(json, ".csv");
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(report, LabCommands.JsonOptions), new UTF8Encoding(false));
        await WriteCsvAsync(csv, distinctConnections);
        Console.WriteLine($"Application observation: {json}");
        Console.WriteLine($"CSV                    : {csv}");
        Console.WriteLine($"Mode                   : {inferredMode}");
        Console.WriteLine($"Processes/connections  : {processInstances.Count}/{distinctConnections.Length}");
        return processInstances.Count > 0 ? 0 : 1;
    }

    private static async Task<IReadOnlyList<AppConnectionObservation>> ReadNetstatAsync(HashSet<int> processIds, int proxyPort)
    {
        var observations = new List<AppConnectionObservation>();
        var result = await RunProcessAsync("netstat.exe", "-ano", TimeSpan.FromSeconds(5));
        foreach (var line in result.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = Regex.Split(line.Trim(), @"\s+");
            if (parts.Length < 4 || parts[0] is not ("TCP" or "UDP") || !int.TryParse(parts[^1], out var processId) || !processIds.Contains(processId)) continue;
            var protocol = parts[0];
            var local = ParseEndpoint(parts[1]);
            var remote = ParseEndpoint(parts[2]);
            var state = protocol == "TCP" && parts.Length >= 5 ? parts[3] : null;
            string processName;
            try { using var process = Process.GetProcessById(processId); processName = process.ProcessName; } catch { processName = "unknown"; }
            var loopback = IPAddress.TryParse(remote.address, out var remoteIp) && IPAddress.IsLoopback(remoteIp);
            var external = remoteIp is not null && !loopback && !remoteIp.Equals(IPAddress.Any) && !remoteIp.Equals(IPAddress.IPv6Any);
            observations.Add(new AppConnectionObservation(DateTimeOffset.UtcNow, processName, processId, protocol, local.address, local.port, remote.address, remote.port, state, loopback && proxyPort > 0 && remote.port == proxyPort, external, 1));
        }
        return observations;
    }

    private static (string address, int port) ParseEndpoint(string value)
    {
        var text = value.Trim();
        if (text.StartsWith("[", StringComparison.Ordinal) && text.Contains("]:"))
        {
            var close = text.LastIndexOf("]:", StringComparison.Ordinal);
            return (text[1..close], int.TryParse(text[(close + 2)..], out var ipv6Port) ? ipv6Port : 0);
        }
        var colon = text.LastIndexOf(':');
        return colon > 0 ? (text[..colon], int.TryParse(text[(colon + 1)..], out var parsedPort) ? parsedPort : 0) : (text, 0);
    }

    private static async Task<string> RunProcessAsync(string fileName, string arguments, TimeSpan timeout)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo { FileName = fileName, Arguments = arguments, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);
        try { await process.WaitForExitAsync(cancellation.Token); } catch { try { process.Kill(true); } catch { } }
        return await stdout;
    }

    private static async Task WriteCsvAsync(string path, IReadOnlyList<AppConnectionObservation> observations)
    {
        static string Csv(string? value) => "\"" + (value ?? "").Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        var builder = new StringBuilder("observedAt,processName,processId,protocol,localAddress,localPort,remoteAddress,remotePort,state,isExpectedLoopbackProxy,isExternal,sampleCount\r\n");
        foreach (var item in observations)
        {
            builder.Append(Csv(item.ObservedAt.ToString("O"))).Append(',').Append(Csv(item.ProcessName)).Append(',').Append(item.ProcessId).Append(',')
                .Append(Csv(item.Protocol)).Append(',').Append(Csv(item.LocalAddress)).Append(',').Append(item.LocalPort).Append(',')
                .Append(Csv(item.RemoteAddress)).Append(',').Append(item.RemotePort).Append(',').Append(Csv(item.State)).Append(',')
                .Append(item.IsExpectedLoopbackProxy).Append(',').Append(item.IsExternal).Append(',').Append(item.SampleCount).Append("\r\n");
        }
        await File.WriteAllTextAsync(path, builder.ToString(), new UTF8Encoding(false));
    }

    private static string? Read(string[] args, string name) { var index = Array.FindIndex(args, value => value.Equals(name, StringComparison.OrdinalIgnoreCase)); return index >= 0 && index + 1 < args.Length ? args[index + 1] : null; }
    private static IReadOnlyList<string> ReadMany(string[] args, string name) { var values = new List<string>(); for (var index = 0; index < args.Length - 1; index++) if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase)) values.Add(args[index + 1]); return values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(); }
    private static int ReadInt(string[] args, string name, int fallback, int minimum, int maximum) => int.TryParse(Read(args, name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? Math.Clamp(value, minimum, maximum) : fallback;
    private static string? Safe(Func<string?> value) { try { return value(); } catch { return null; } }
    private static DateTimeOffset? SafeDate(Func<DateTime> value) { try { return value(); } catch { return null; } }
}

internal sealed record ObservedProcess(string ProcessName, int ProcessId, string? Path, DateTimeOffset? StartedAt);
internal sealed record AppConnectionObservation(DateTimeOffset ObservedAt, string ProcessName, int ProcessId, string Protocol, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, string? State, bool IsExpectedLoopbackProxy, bool IsExternal, int SampleCount);
