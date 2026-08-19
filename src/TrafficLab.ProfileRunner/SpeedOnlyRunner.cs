using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal static partial class Program
{
    private static async Task<int> RunSpeedOnlyAsync(
        RunnerInput input,
        RunnerOptions options,
        Action<int, int, string, string, string?> progress,
        CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var networkContext = CaptureNetworkEnvironmentForCommands();
        var runId = $"{startedAt:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..24];
        var total = Math.Min(input.Uris.Count, options.MaxProfiles);
        var results = new List<SpeedOnlyProfileResult>();
        progress(4, 0, "Speed test: preparing matched direct/tunnel measurements", "running", null);
        for (var index = 0; index < total; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var start = 4 + (int)Math.Floor(index * 91d / Math.Max(1, total));
            var end = 4 + (int)Math.Floor((index + 1) * 91d / Math.Max(1, total));
            void ProfileProgress(int percent, string message)
                => progress(start + (int)Math.Round((end - start) * Math.Clamp(percent, 0, 100) / 100d), index, $"profile-{index + 1:00}: {message}", "running", null);
            results.Add(await RunSpeedOnlyProfileAsync(input.Uris[index], index + 1, options, ProfileProgress, cancellationToken));
            progress(end, index + 1, $"profile-{index + 1:00}: speed measurement completed", "running", null);
        }

        var completedAt = DateTimeOffset.UtcNow;
        var passed = results.Count(item => item.Outcome.Outcome == OutcomeClassifier.Pass);
        var runOutcome = passed > 0
            ? SpeedDecision(OutcomeClassifier.Pass, "SPEED_MEASUREMENT_SUCCEEDED", $"{passed}/{results.Count} profiles produced matched tunnel speed measurements.")
            : results.Count > 0 && results.All(item => item.Outcome.Outcome == OutcomeClassifier.TestFailure)
                ? SpeedDecision(OutcomeClassifier.TestFailure, "ALL_PROFILES_TEST_FAILURE", "Every connection was rejected before a fair speed-path measurement could start.")
            : results.Any(item => item.Outcome.Outcome == OutcomeClassifier.UnderlayFail)
                ? SpeedDecision(OutcomeClassifier.UnderlayFail, "DIRECT_CONTROL_UNAVAILABLE", "No profile had a usable matched direct control.")
                : results.Any(item => item.Outcome.Outcome == OutcomeClassifier.ProxyFail)
                    ? SpeedDecision(OutcomeClassifier.ProxyFail, "NO_TUNNEL_SPEED_RESULT", "No authenticated tunnel speed measurement succeeded.")
                    : SpeedDecision(OutcomeClassifier.Unknown, "SPEED_TEST_INCONCLUSIVE", "The speed-only run did not produce a classifiable result.");
        var document = new SpeedOnlyRunDocument
        {
            Run = new SpeedOnlyRunMetadata
            {
                RunId = runId,
                StartedAt = startedAt,
                CompletedAt = completedAt,
                DurationMs = (long)(completedAt - startedAt).TotalMilliseconds,
                TestType = "speed",
                Platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : "other",
                OperatingSystem = RuntimeInformation.OSDescription,
                Architecture = RuntimeInformation.OSArchitecture.ToString(),
                ToolVersion = "3.4.0",
                Connections = total,
                ExecutionOrder = "sequential",
                MeasurementContract = "direct-before and authenticated tunnel 1/4/16-flow matrices -> bounded direct-after 1-flow drift control; adaptive steady-state windows; download/upload; idle and loaded latency",
                NetworkContext = networkContext
            },
            Outcome = runOutcome,
            Profiles = results,
            Limitations =
            [
                "The default public speed endpoint is route-dependent; a controlled primary and neutral twin are required for server-timestamped acceptance measurements.",
                "Client upload timing can include socket buffering. Server acknowledgement is recorded, but exact server receive timing requires a controlled endpoint.",
                "Byte budgets can truncate high-speed paths before the target window; confidence is reduced and byteCapReached is explicit.",
                "The direct-after control intentionally uses only one flow and fewer bytes to bound data use; 4/16-flow ratios use the direct-before matrix and inherit the 1-flow drift confidence."
            ]
        };
        progress(97, total, "Speed test: creating speed.json result archive", "running", null);
        var zipPath = await CreateSpeedOnlyPackageAsync(document, options.OutputDirectory, cancellationToken);
        progress(100, total, $"Speed test completed: {passed}/{total} profiles measured", "completed", zipPath);
        Console.WriteLine($"Speed testing completed: {passed}/{total} profiles measured in {TimeSpan.FromMilliseconds(document.Run.DurationMs):c}");
        Console.WriteLine("Result archive: " + zipPath);
        return 0;
    }

    private static async Task<SpeedOnlyProfileResult> RunSpeedOnlyProfileAsync(
        string raw,
        int ordinal,
        RunnerOptions options,
        Action<int, string> progress,
        CancellationToken cancellationToken)
    {
        var profileId = $"profile-{ordinal:00}";
        var result = new SpeedOnlyProfileResult { ProfileId = profileId, Ordinal = ordinal };
        ConnectionProfile profile;
        try
        {
            profile = ConnectionProfile.Parse(raw);
            result.Name = profile.Name;
            result.Declared = profile.ToDeclaredProfile();
            result.ProfileFingerprint = ExtendedDiagnostics.ComputeProfileFingerprint(result.Declared);
            result.Stages.Add(StageResult.Passed("profile.parse", 0, result.Declared));
        }
        catch (Exception ex)
        {
            result.Name = $"Invalid profile {ordinal}";
            var parseStage = StageResult.Failed("profile.parse", 0, Redact(ex.Message));
            parseStage.Outcome = OutcomeClassifier.TestFailure;
            parseStage.ReasonCode = "PROFILE_PARSE_FAILURE";
            parseStage.Reason = "The supplied connection URI could not be parsed.";
            result.Stages.Add(parseStage);
            result.Outcome = SpeedDecision(OutcomeClassifier.TestFailure, "PROFILE_PARSE_FAILURE", "The supplied connection URI could not be parsed.", "profile.parse");
            return result;
        }

        progress(3, "measuring direct-before speed control");
        using (var directClient = SpeedTestEngine.CreateDirectClient(options.Timeout))
            result.DirectBefore = await SpeedTestEngine.MeasureAsync(directClient, SpeedTestSettings.SpeedOnly, "direct-before", cancellationToken);
        result.Stages.Add(SpeedTestEngine.ToStage("speed.directBefore", result.DirectBefore));

        progress(31, "resolving and connecting to profile endpoint");
        var dnsWatch = Stopwatch.StartNew();
        IPAddress[] addresses;
        try
        {
            addresses = IPAddress.TryParse(profile.Host, out var literal)
                ? [literal]
                : await Dns.GetHostAddressesAsync(profile.Host, cancellationToken);
            dnsWatch.Stop();
            result.EndpointAddresses = addresses.Select(item => item.ToString()).Distinct().ToArray();
            result.Stages.Add(addresses.Length > 0
                ? StageResult.Passed("endpoint.dns", dnsWatch.ElapsedMilliseconds, new { host = profile.Host, addresses = result.EndpointAddresses })
                : StageResult.Failed("endpoint.dns", dnsWatch.ElapsedMilliseconds, "No endpoint address was returned."));
        }
        catch (Exception ex)
        {
            dnsWatch.Stop();
            addresses = [];
            result.Stages.Add(StageResult.Failed("endpoint.dns", dnsWatch.ElapsedMilliseconds, Redact(ex.Message)));
        }

        var tcpRows = new List<object>();
        var tcpAvailable = false;
        foreach (var address in addresses.Take(6))
        {
            var tcpWatch = Stopwatch.StartNew();
            try
            {
                using var tcp = new TcpClient(address.AddressFamily);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(options.Timeout);
                await tcp.ConnectAsync(address, profile.Port, timeout.Token);
                tcpWatch.Stop(); tcpAvailable = true;
                tcpRows.Add(new { address = address.ToString(), connected = true, elapsedMs = tcpWatch.ElapsedMilliseconds, error = (string?)null });
            }
            catch (Exception ex)
            {
                tcpWatch.Stop();
                tcpRows.Add(new { address = address.ToString(), connected = false, elapsedMs = tcpWatch.ElapsedMilliseconds, error = Redact(ex.Message) });
            }
        }
        result.Stages.Add(StageResult.FromStatus("endpoint.tcp", tcpAvailable ? "passed" : "failed", 0, tcpRows, tcpAvailable ? null : "No endpoint TCP connection succeeded."));

        if (tcpAvailable)
        {
            progress(37, "starting isolated Xray for authenticated speed path");
            await MeasureSpeedTunnelAsync(profile, result, options, progress, cancellationToken);
        }
        else
        {
            result.Stages.Add(StageResult.Skipped("tunnel.coreValidation", "Endpoint TCP prerequisite failed."));
            result.Stages.Add(StageResult.Skipped("tunnel.coreStart", "Endpoint TCP prerequisite failed."));
            result.Stages.Add(StageResult.Skipped("tunnel.authenticatedEndToEnd", "Endpoint TCP prerequisite failed."));
            result.Stages.Add(StageResult.Skipped("speed.tunnel", "Endpoint TCP prerequisite failed."));
        }

        progress(79, "measuring direct-after speed control");
        using (var directClient = SpeedTestEngine.CreateDirectClient(options.Timeout))
            result.DirectAfter = await SpeedTestEngine.MeasureAsync(directClient, SpeedTestSettings.DirectAfterControl, "direct-after-control", cancellationToken);
        result.Stages.Add(SpeedTestEngine.ToStage("speed.directAfter", result.DirectAfter));
        if (result.DirectBefore is not null && result.Tunnel is not null && result.DirectAfter is not null)
            result.Comparison = SpeedTestEngine.Compare(result.DirectBefore, result.Tunnel, result.DirectAfter);

        var directAvailable = result.DirectBefore?.Series.Any(item => item.SuccessfulAttempts > 0) == true
            || result.DirectAfter?.Series.Any(item => item.SuccessfulAttempts > 0) == true;
        var tunnelAvailable = result.Tunnel?.Series.Any(item => item.SuccessfulAttempts > 0) == true;
        var authPassed = result.Stages.Any(item => item.Stage == "tunnel.authenticatedEndToEnd" && item.Status == "passed");
        result.Outcome = !directAvailable
            ? SpeedDecision(OutcomeClassifier.UnderlayFail, "DIRECT_CONTROL_UNAVAILABLE", "Matched direct speed controls did not produce a measurement.", "speed.directBefore", "speed.directAfter")
            : !tcpAvailable
                ? SpeedDecision(OutcomeClassifier.ProxyFail, "PROXY_PATH_FAIL", "The profile endpoint was not TCP-reachable.", "endpoint.tcp")
                : !authPassed
                    ? SpeedDecision(OutcomeClassifier.ProxyFail, "PROTOCOL_AUTH_FAIL", "TCP was reachable but the authenticated destination request failed.", "tunnel.authenticatedEndToEnd")
                    : !tunnelAvailable
                        ? SpeedDecision(OutcomeClassifier.Unknown, "SPEED_MEASUREMENT_INCONCLUSIVE", "Authentication succeeded but no complete tunnel speed series was produced.", "speed.tunnel")
                        : SpeedDecision(OutcomeClassifier.Pass, "SPEED_MEASUREMENT_SUCCEEDED", "Matched direct and authenticated tunnel speed measurements completed.", "speed.directBefore", "speed.tunnel", "speed.directAfter");
        foreach (var stage in result.Stages)
        {
            if (stage.Status == "passed")
            {
                stage.Outcome = OutcomeClassifier.Pass; stage.ReasonCode = "STAGE_SUCCEEDED";
                stage.Reason = "The speed-test prerequisite or measurement completed.";
            }
            else if (stage.Status == "skipped")
            {
                stage.Outcome = OutcomeClassifier.Unknown; stage.ReasonCode = "DEPENDENCY_NOT_MET";
                stage.Reason = stage.Error ?? "The stage was not run because a prerequisite failed.";
            }
            else if (stage.Stage == "profile.parse" || stage.Stage is "tunnel.coreValidation" or "tunnel.coreStart")
            {
                stage.Outcome = OutcomeClassifier.TestFailure; stage.ReasonCode = "TESTER_OR_CONFIGURATION_FAILURE";
                stage.Reason = stage.Error ?? "The local test core or profile configuration failed.";
            }
            else if (stage.Stage == "endpoint.dns")
            {
                stage.Outcome = OutcomeClassifier.ProxyFail; stage.ReasonCode = "PROXY_ENDPOINT_DNS_FAIL";
                stage.Reason = stage.Error ?? "The profile endpoint could not be resolved.";
            }
            else if (stage.Stage == "endpoint.tcp")
            {
                stage.Outcome = OutcomeClassifier.ProxyFail; stage.ReasonCode = "PROXY_PATH_FAIL";
                stage.Reason = stage.Error ?? "No endpoint TCP connection succeeded.";
            }
            else if (stage.Stage == "tunnel.authenticatedEndToEnd")
            {
                stage.Outcome = OutcomeClassifier.ProxyFail; stage.ReasonCode = "PROTOCOL_AUTH_FAIL";
                stage.Reason = stage.Error ?? "Endpoint TCP worked but authenticated VLESS traffic did not.";
            }
            else if (stage.Stage.StartsWith("speed.direct", StringComparison.Ordinal))
            {
                stage.Outcome = OutcomeClassifier.UnderlayFail; stage.ReasonCode = "DIRECT_CONTROL_UNAVAILABLE";
                stage.Reason = stage.Error ?? "The direct no-proxy speed control was unavailable.";
            }
            else
            {
                stage.Outcome = OutcomeClassifier.Unknown; stage.ReasonCode = "SPEED_SUBCHECK_INCONCLUSIVE";
                stage.Reason = stage.Error ?? "The speed subcheck was partial or failed without a unique causal attribution.";
            }
        }
        progress(100, "matched speed comparison completed");
        return result;
    }

    private static async Task MeasureSpeedTunnelAsync(
        ConnectionProfile profile,
        SpeedOnlyProfileResult result,
        RunnerOptions options,
        Action<int, string> progress,
        CancellationToken cancellationToken)
    {
        var runtimeDirectory = Path.Combine(Path.GetTempPath(), "loki-traffic-lab-speed", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeDirectory);
        var configPath = Path.Combine(runtimeDirectory, "config.json");
        var accessLog = Path.Combine(runtimeDirectory, "access.log");
        var errorLog = Path.Combine(runtimeDirectory, "error.log");
        var httpPort = options.LocalPort ?? GetFreeTcpPort();
        var socksPort = GetFreeDualPort();
        var quicPort = GetFreeUdpPort();
        await File.WriteAllTextAsync(configPath, BuildXrayConfig(profile, httpPort, socksPort, quicPort, accessLog, errorLog), new UTF8Encoding(false), cancellationToken);
        Process? xray = null;
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        try
        {
            var validation = await RunProcessAsync(options.XrayPath, $"run -test -c \"{configPath}\"", runtimeDirectory, options.Timeout, cancellationToken);
            result.Stages.Add(StageResult.FromProcess("tunnel.coreValidation", validation));
            if (validation.ExitCode != 0) return;
            xray = Process.Start(new ProcessStartInfo
            {
                FileName = options.XrayPath,
                Arguments = $"run -c \"{configPath}\"",
                WorkingDirectory = runtimeDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            if (xray is null)
            {
                result.Stages.Add(StageResult.Failed("tunnel.coreStart", 0, "Failed to start isolated Xray."));
                return;
            }
            stdout = xray.StandardOutput.ReadToEndAsync(); stderr = xray.StandardError.ReadToEndAsync();
            var readyWatch = Stopwatch.StartNew();
            var ready = await WaitForTcpPortAsync(httpPort, TimeSpan.FromSeconds(10), cancellationToken);
            readyWatch.Stop();
            result.Stages.Add(StageResult.FromStatus("tunnel.coreStart", ready ? "passed" : "failed", readyWatch.ElapsedMilliseconds, new { httpPort, processId = xray.Id }, ready ? null : "Xray did not open its loopback HTTP inbound."));
            if (!ready) return;
            using var authClient = CreateProxyHttpClient(httpPort, options.Timeout);
            var auth = await ProbeHttpAsync(authClient, "https://www.gstatic.com/generate_204", options.Timeout, cancellationToken);
            result.Stages.Add(StageResult.FromStatus("tunnel.authenticatedEndToEnd", auth.Success ? "passed" : "failed", auth.ElapsedMs, auth, auth.Success ? null : auth.Error ?? "No authenticated destination response."));
            if (!auth.Success) return;
            progress(43, "measuring authenticated tunnel speed (1/4/16 flows)");
            using var speedClient = SpeedTestEngine.CreateProxyClient(httpPort, options.Timeout);
            result.Tunnel = await SpeedTestEngine.MeasureAsync(speedClient, SpeedTestSettings.SpeedOnly, "tunnel", cancellationToken);
            result.Stages.Add(SpeedTestEngine.ToStage("speed.tunnel", result.Tunnel));
        }
        finally
        {
            if (xray is not null)
            {
                try { if (!xray.HasExited) { xray.Kill(entireProcessTree: true); await xray.WaitForExitAsync(); } } catch { }
                xray.Dispose();
            }
            if (stdout is not null) try { await stdout; } catch { }
            if (stderr is not null) try { await stderr; } catch { }
            try { Directory.Delete(runtimeDirectory, recursive: true); } catch { }
        }
    }

    private static async Task<string> CreateSpeedOnlyPackageAsync(SpeedOnlyRunDocument document, string outputDirectory, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var zipPath = Path.Combine(outputDirectory, $"traffic-lab-speed-results-{stamp}-{document.Run.RunId[^8..]}.zip");
        await using var stream = new FileStream(zipPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false, Encoding.UTF8);
        var jsonEntry = archive.CreateEntry("speed.json", CompressionLevel.Optimal);
        await using (var json = jsonEntry.Open()) await JsonSerializer.SerializeAsync(json, document, JsonOptions, cancellationToken);
        var readmeEntry = archive.CreateEntry("readme.txt", CompressionLevel.Optimal);
        await using (var target = readmeEntry.Open())
        await using (var writer = new StreamWriter(target, new UTF8Encoding(true), leaveOpen: false))
        {
            await writer.WriteAsync(BuildSpeedReadme(document));
        }
        return Path.GetFullPath(zipPath);
    }

    private static string BuildSpeedReadme(SpeedOnlyRunDocument document)
    {
        var builder = new StringBuilder();
        builder.AppendLine("LOKI TRAFFIC LAB - SPEED TEST RESULT PACKAGE");
        builder.AppendLine("=============================================\n");
        builder.AppendLine($"Run ID: {document.Run.RunId}");
        builder.AppendLine($"Test type: SPEED (speed-relevant checks only)");
        builder.AppendLine($"Started UTC: {document.Run.StartedAt:O}");
        builder.AppendLine($"Completed UTC: {document.Run.CompletedAt:O}");
        builder.AppendLine($"Duration: {TimeSpan.FromMilliseconds(document.Run.DurationMs):c}");
        builder.AppendLine($"Platform: {document.Run.Platform}");
        builder.AppendLine($"Operating system: {document.Run.OperatingSystem}");
        builder.AppendLine($"Tool version: {document.Run.ToolVersion}");
        builder.AppendLine($"Connections tested: {document.Run.Connections}");
        builder.AppendLine($"Run outcome: {document.Outcome.Outcome} / {document.Outcome.ReasonCode}\n");
        builder.AppendLine("FILES"); builder.AppendLine("-----");
        builder.AppendLine("speed.json  Raw calibration/measurement samples, 1/4/16-flow download/upload, idle/loaded latency, confidence and matched direct/tunnel comparison.");
        builder.AppendLine("readme.txt  Run metadata, measurement contract and limitations.\n");
        builder.AppendLine("METHOD"); builder.AppendLine("------");
        builder.AppendLine(document.Run.MeasurementContract);
        builder.AppendLine("recommendedMbps is a median of non-calibration payload windows. effectiveMbps includes connection and server acknowledgement overhead.");
        builder.AppendLine("A direct-control drift above 25%, insufficient duration, high sample variation, failed flows, or a reached byte budget lowers confidence.\n");
        builder.AppendLine("DATA BUDGET"); builder.AppendLine("-----------");
        builder.AppendLine("The desktop/Linux worst-case transfer budget is approximately 700 MiB per profile. The direct-after control is one-flow and smaller than the full direct-before/tunnel matrices.\n");
        builder.AppendLine("PRIVACY"); builder.AppendLine("-------");
        builder.AppendLine("The archive never stores raw VLESS URIs, UUIDs, REALITY keys or short IDs. Endpoint hostnames, IP addresses, timings and throughput remain potentially sensitive.");
        return builder.ToString();
    }

    private static OutcomeDecision SpeedDecision(string outcome, string reasonCode, string reason, params string[] evidence)
        => new() { Outcome = outcome, ReasonCode = reasonCode, Reason = reason, Evidence = evidence };
}

internal sealed class SpeedOnlyRunDocument
{
    public string SchemaVersion { get; init; } = "1.0";
    public string OutputType { get; init; } = "speed-test-results";
    public required SpeedOnlyRunMetadata Run { get; init; }
    public required OutcomeDecision Outcome { get; init; }
    public IReadOnlyList<SpeedOnlyProfileResult> Profiles { get; init; } = [];
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

internal sealed class SpeedOnlyRunMetadata
{
    public required string RunId { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset CompletedAt { get; init; }
    public long DurationMs { get; init; }
    public string TestType { get; init; } = "speed";
    public string Platform { get; init; } = "unknown";
    public string OperatingSystem { get; init; } = "unknown";
    public string Architecture { get; init; } = "unknown";
    public string ToolVersion { get; init; } = "unknown";
    public int Connections { get; init; }
    public string ExecutionOrder { get; init; } = "sequential";
    public string MeasurementContract { get; init; } = "unknown";
    public NetworkEnvironment? NetworkContext { get; init; }
}

internal sealed class SpeedOnlyProfileResult
{
    public required string ProfileId { get; init; }
    public int Ordinal { get; init; }
    public string Name { get; set; } = "unknown";
    public string? ProfileFingerprint { get; set; }
    public DeclaredProfile? Declared { get; set; }
    public IReadOnlyList<string> EndpointAddresses { get; set; } = [];
    public List<StageResult> Stages { get; init; } = [];
    public SpeedMeasurementReport? DirectBefore { get; set; }
    public SpeedMeasurementReport? Tunnel { get; set; }
    public SpeedMeasurementReport? DirectAfter { get; set; }
    public SpeedPathComparison? Comparison { get; set; }
    public OutcomeDecision Outcome { get; set; } = new()
    {
        Outcome = OutcomeClassifier.Unknown,
        ReasonCode = "NOT_CLASSIFIED",
        Reason = "Speed profile has not been classified."
    };
}
