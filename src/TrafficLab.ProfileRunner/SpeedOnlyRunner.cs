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
        var runId = startedAt.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture)
            + "-" + Guid.NewGuid().ToString("N")[..8];
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
            results.Add(await RunSpeedOnlyProfileAsync(input.Uris[index], index + 1, runId, options, ProfileProgress, cancellationToken));
            progress(end, index + 1, $"profile-{index + 1:00}: speed measurement completed", "running", null);
        }

        var completedAt = DateTimeOffset.UtcNow;
        var passed = results.Count(item => item.Outcome.Outcome == OutcomeClassifier.Pass);
        var summaries = results.Where(item => item.Tunnel is not null).Select(item =>
        {
            var value = SpeedTestEngine.Summarize(item.Tunnel!);
            return new SpeedOnlyProfileSummary(item.ProfileId, item.Name, value.DownloadMbps, value.UploadMbps,
                value.DownloadFlows, value.UploadFlows, value.Confidence);
        }).ToArray();
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
                ToolVersion = "3.6.0",
                Connections = total,
                ExecutionOrder = "sequential",
                MeasurementContract = "ABBA Direct-Tunnel-Tunnel-Direct matched 1/4/16-flow matrices; synchronized ramp-up and bounded windows; robust three-sample calibration; download/upload; idle and loaded latency; straggler/concurrency classification",
                NetworkContext = networkContext
            },
            Outcome = runOutcome,
            Profiles = results,
            Summary = summaries,
            Limitations =
            [
                "The default public speed endpoint is route-dependent; a controlled primary and neutral twin are required for server-timestamped acceptance measurements.",
                "Client upload timing can include socket buffering. Server acknowledgement is recorded, but exact server receive timing requires a controlled endpoint.",
                "Byte budgets can truncate high-speed paths before the target window; confidence is reduced and byteCapReached is explicit.",
                "Direct and tunnel legs reuse the exact workload plan produced by the first direct calibration; a reached byte cap remains explicit.",
                "Upload samples stopped by the local measurement deadline without a server response are marked UPLOAD_SERVER_ACK_UNAVAILABLE."
            ]
        };
        progress(97, total, "Speed test: creating speed.json result archive", "running", null);
        var zipPath = await CreateSpeedOnlyPackageAsync(document, options.OutputDirectory, cancellationToken);
        var compactSummary = summaries.Length == 1
            ? $"; {new SpeedDisplaySummary(summaries[0].DownloadMbps, summaries[0].UploadMbps, summaries[0].DownloadFlows, summaries[0].UploadFlows, summaries[0].Confidence).ToDisplayString()}"
            : string.Empty;
        progress(100, total, $"Speed test completed: {passed}/{total} profiles measured{compactSummary}", "completed", zipPath);
        Console.WriteLine($"Speed testing completed: {passed}/{total} profiles measured in {TimeSpan.FromMilliseconds(document.Run.DurationMs):c}");
        foreach (var summary in summaries)
            Console.WriteLine($"Speed result [{summary.ProfileId} {summary.Name}]: " +
                new SpeedDisplaySummary(summary.DownloadMbps, summary.UploadMbps, summary.DownloadFlows, summary.UploadFlows, summary.Confidence).ToDisplayString());
        Console.WriteLine("Result archive: " + zipPath);
        return 0;
    }

    private static async Task<SpeedOnlyProfileResult> RunSpeedOnlyProfileAsync(
        string raw,
        int ordinal,
        string runId,
        RunnerOptions options,
        Action<int, string> progress,
        CancellationToken cancellationToken)
    {
        var profileId = $"profile-{ordinal:00}";
        var profileStartedAt = DateTimeOffset.UtcNow;
        var result = new SpeedOnlyProfileResult
        {
            ProfileId = profileId,
            Ordinal = ordinal,
            StartedAt = profileStartedAt,
            CorrelationId = $"tlab-{runId}-{profileId}",
            ServerCorrelationId = $"tlab-{runId}-{profileId}"
        };
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
            CompleteSpeedProfile(result);
            return result;
        }

        progress(3, "measuring direct-before speed control");
        using (var directClient = SpeedTestEngine.CreateDirectClient(options.Timeout))
            result.DirectBefore = await SpeedTestEngine.MeasureAsync(directClient, SpeedTestSettings.SpeedOnly, "direct-before", cancellationToken);
        result.Stages.Add(SpeedTestEngine.ToStage("speed.directBefore", result.DirectBefore));
        var matchedPlan = SpeedTestEngine.CreateMatchedPlan(result.DirectBefore);

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
        var dnsFailed = result.Stages.Any(item => item.Stage == "endpoint.dns" && item.Status == "failed");
        result.Stages.Add(dnsFailed && addresses.Length == 0
            ? StageResult.DependentSkipped("endpoint.tcp", "Endpoint DNS did not produce an address; TCP was not attempted.", "endpoint.dns", "ENDPOINT_DNS_UNRESOLVED")
            : StageResult.FromStatus("endpoint.tcp", tcpAvailable ? "passed" : "failed", 0, tcpRows, tcpAvailable ? null : "No endpoint TCP connection succeeded."));

        if (tcpAvailable)
        {
            progress(37, "starting isolated Xray for authenticated speed path");
            await MeasureSpeedTunnelAsync(profile, result, matchedPlan, options, progress, cancellationToken);
        }
        else
        {
            var rootStage = dnsFailed ? "endpoint.dns" : "endpoint.tcp";
            var rootCode = dnsFailed ? "ENDPOINT_DNS_UNRESOLVED" : "ENDPOINT_TCP_UNREACHABLE";
            result.Stages.Add(StageResult.DependentSkipped("tunnel.coreValidation", "Endpoint transport prerequisite failed.", rootStage, rootCode));
            result.Stages.Add(StageResult.DependentSkipped("tunnel.coreStart", "Endpoint transport prerequisite failed.", rootStage, rootCode));
            result.Stages.Add(StageResult.DependentSkipped("tunnel.authenticatedEndToEnd", "Endpoint transport prerequisite failed.", rootStage, rootCode));
            result.Stages.Add(StageResult.DependentSkipped("speed.tunnel", "Endpoint transport prerequisite failed.", rootStage, rootCode));
        }

        progress(79, "ABBA direct-after matched 1/4/16-flow control");
        using (var directClient = SpeedTestEngine.CreateDirectClient(options.Timeout))
            result.DirectAfter = await SpeedTestEngine.MeasureAsync(directClient, SpeedTestSettings.SpeedOnly, "direct-after", cancellationToken, matchedPlan);
        result.Stages.Add(SpeedTestEngine.ToStage("speed.directAfter", result.DirectAfter));
        if (result.DirectBefore is not null && result.Tunnel is not null && result.DirectAfter is not null)
            result.Comparison = SpeedTestEngine.Compare(result.DirectBefore, result.Tunnel, result.DirectAfter);

        var directAvailable = result.DirectBefore?.Series.Any(item => item.SuccessfulAttempts > 0) == true
            || result.DirectAfter?.Series.Any(item => item.SuccessfulAttempts > 0) == true;
        var tunnelAvailable = result.Tunnel?.Series.Any(item => item.SuccessfulAttempts > 0) == true;
        var authPassed = result.Stages.Any(item => item.Stage == "tunnel.authenticatedEndToEnd" && item.Status == "passed");
        var localCoreFailed = result.Stages.Any(item => item.Status == "failed" && item.Stage is "tunnel.coreValidation" or "tunnel.coreStart");
        result.Outcome = !directAvailable
            ? SpeedDecision(OutcomeClassifier.UnderlayFail, "DIRECT_CONTROL_UNAVAILABLE", "Matched direct speed controls did not produce a measurement.", "speed.directBefore", "speed.directAfter")
            : dnsFailed
                ? SpeedDecision(OutcomeClassifier.ProxyFail, "ENDPOINT_DNS_UNRESOLVED", "The profile endpoint did not resolve.", "endpoint.dns")
            : !tcpAvailable
                ? SpeedDecision(OutcomeClassifier.ProxyFail, "ENDPOINT_TCP_UNREACHABLE", "The profile endpoint was not TCP-reachable.", "endpoint.tcp")
                : localCoreFailed
                    ? SpeedDecision(OutcomeClassifier.TestFailure, "TESTER_OR_CONFIGURATION_FAILURE", "The local Xray core did not validate or start; the proxy speed path was not fairly evaluated.", "tunnel.coreValidation", "tunnel.coreStart")
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
                stage.Outcome = OutcomeClassifier.Unknown;
                if (stage.ReasonCode == "NOT_CLASSIFIED") stage.ReasonCode = "DEPENDENCY_NOT_MET";
                stage.Reason = stage.Error ?? "The stage was not run because a prerequisite failed.";
            }
            else if (stage.Stage == "profile.parse" || stage.Stage is "tunnel.coreValidation" or "tunnel.coreStart")
            {
                stage.Outcome = OutcomeClassifier.TestFailure; stage.ReasonCode = "TESTER_OR_CONFIGURATION_FAILURE";
                stage.Reason = stage.Error ?? "The local test core or profile configuration failed.";
            }
            else if (stage.Stage == "endpoint.dns")
            {
                stage.Outcome = OutcomeClassifier.ProxyFail; stage.ReasonCode = "ENDPOINT_DNS_UNRESOLVED";
                stage.Reason = stage.Error ?? "The profile endpoint could not be resolved.";
            }
            else if (stage.Stage == "endpoint.tcp")
            {
                stage.Outcome = OutcomeClassifier.ProxyFail; stage.ReasonCode = "ENDPOINT_TCP_UNREACHABLE";
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
        CompleteSpeedProfile(result);
        return result;
    }

    private static void CompleteSpeedProfile(SpeedOnlyProfileResult result)
    {
        result.CompletedAt = DateTimeOffset.UtcNow;
        result.DurationMs = (long)(result.CompletedAt.Value - result.StartedAt).TotalMilliseconds;
    }

    private static async Task MeasureSpeedTunnelAsync(
        ConnectionProfile profile,
        SpeedOnlyProfileResult result,
        SpeedMeasurementPlan matchedPlan,
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
            if (validation.ExitCode != 0)
            {
                AddSpeedDependentStages(result, "tunnel.coreValidation");
                return;
            }
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
                AddSpeedDependentStages(result, "tunnel.coreStart");
                return;
            }
            stdout = xray.StandardOutput.ReadToEndAsync(); stderr = xray.StandardError.ReadToEndAsync();
            var readyWatch = Stopwatch.StartNew();
            var ready = await WaitForTcpPortAsync(httpPort, TimeSpan.FromSeconds(10), cancellationToken);
            readyWatch.Stop();
            result.Stages.Add(StageResult.FromStatus("tunnel.coreStart", ready ? "passed" : "failed", readyWatch.ElapsedMilliseconds, new { httpPort, processId = xray.Id }, ready ? null : "Xray did not open its loopback HTTP inbound."));
            if (!ready)
            {
                AddSpeedDependentStages(result, "tunnel.coreStart");
                return;
            }
            using var authClient = CreateProxyHttpClient(httpPort, options.Timeout, result.ServerCorrelationId);
            var auth = await ProbeHttpAsync(authClient, "https://www.gstatic.com/generate_204", options.Timeout, cancellationToken);
            result.Stages.Add(StageResult.FromStatus("tunnel.authenticatedEndToEnd", auth.Success ? "passed" : "failed", auth.ElapsedMs, auth, auth.Success ? null : auth.Error ?? "No authenticated destination response."));
            if (!auth.Success)
            {
                if (!result.Stages.Any(item => item.Stage == "speed.tunnel"))
                    result.Stages.Add(StageResult.DependentSkipped("speed.tunnel", "Authenticated tunnel prerequisite failed.", "tunnel.authenticatedEndToEnd", "PROTOCOL_AUTH_FAIL"));
                return;
            }
            progress(43, "ABBA tunnel leg 1/2 (matched 1/4/16-flow plan)");
            using var speedClient = SpeedTestEngine.CreateProxyClient(httpPort, options.Timeout, result.ServerCorrelationId);
            var tunnelFirst = await SpeedTestEngine.MeasureAsync(speedClient, SpeedTestSettings.SpeedOnly, "tunnel-first", cancellationToken, matchedPlan);
            progress(61, "ABBA tunnel leg 2/2 (matched 1/4/16-flow plan)");
            var tunnelSecond = await SpeedTestEngine.MeasureAsync(speedClient, SpeedTestSettings.SpeedOnly, "tunnel-second", cancellationToken, matchedPlan);
            result.TunnelPasses = [tunnelFirst, tunnelSecond];
            result.Tunnel = SpeedTestEngine.CombineReports("tunnel-abba-combined", tunnelFirst, tunnelSecond);
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

    private static void AddSpeedDependentStages(SpeedOnlyProfileResult result, string rootStage)
    {
        foreach (var stage in new[] { "tunnel.coreStart", "tunnel.authenticatedEndToEnd", "speed.tunnel" })
            if (stage != rootStage && !result.Stages.Any(item => item.Stage == stage))
                result.Stages.Add(StageResult.DependentSkipped(stage, "The local core prerequisite failed; downstream speed stages were not attempted.", rootStage, "TESTER_OR_CONFIGURATION_FAILURE"));
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
        foreach (var summary in document.Summary)
            builder.AppendLine($"Speed result [{summary.ProfileId} {summary.Name}]: download={summary.DownloadMbps?.ToString("F2", CultureInfo.InvariantCulture) ?? "n/a"} Mbit/s; upload={summary.UploadMbps?.ToString("F2", CultureInfo.InvariantCulture) ?? "n/a"} Mbit/s; confidence={summary.Confidence}");
        foreach (var profile in document.Profiles)
            builder.AppendLine($"Profile timing [{profile.ProfileId}]: started={profile.StartedAt:O}; completed={profile.CompletedAt:O}; duration={TimeSpan.FromMilliseconds(profile.DurationMs ?? 0):c}; correlation={profile.CorrelationId}; server-correlation={profile.ServerCorrelationId} ({profile.ServerCorrelationStatus})");
        builder.AppendLine();
        builder.AppendLine("FILES"); builder.AppendLine("-----");
        builder.AppendLine("speed.json  Raw calibration/measurement samples, 1/4/16-flow download/upload, idle/loaded latency, confidence and matched direct/tunnel comparison.");
        builder.AppendLine("readme.txt  Run metadata, measurement contract and limitations.\n");
        builder.AppendLine("METHOD"); builder.AppendLine("------");
        builder.AppendLine(document.Run.MeasurementContract);
        builder.AppendLine("recommendedMbps is a median of synchronized bounded measurement windows; warm-up and calibration samples are excluded.");
        builder.AppendLine("Direct drift above 15%, stragglers, concurrency collapse, endpoint variation, failed flows, unacknowledged upload windows or a reached byte budget lower confidence.\n");
        builder.AppendLine("DATA BUDGET"); builder.AppendLine("-----------");
        builder.AppendLine("Traffic use is bounded per batch. ABBA repeats the tunnel matrix and uses a full matched direct-after matrix, so accurate SPEED mode can consume substantially more traffic than normal mode.\n");
        builder.AppendLine("PRIVACY"); builder.AppendLine("-------");
        builder.AppendLine("The archive never stores raw VLESS URIs, UUIDs, REALITY keys or short IDs. Endpoint hostnames, IP addresses, timings and throughput remain potentially sensitive.");
        return builder.ToString();
    }

    private static OutcomeDecision SpeedDecision(string outcome, string reasonCode, string reason, params string[] evidence)
        => new() { Outcome = outcome, ReasonCode = reasonCode, Reason = reason, Evidence = evidence };
}

internal sealed class SpeedOnlyRunDocument
{
    public string SchemaVersion { get; init; } = "1.1";
    public string OutputType { get; init; } = "speed-test-results";
    public required SpeedOnlyRunMetadata Run { get; init; }
    public required OutcomeDecision Outcome { get; init; }
    public IReadOnlyList<SpeedOnlyProfileResult> Profiles { get; init; } = [];
    public IReadOnlyList<SpeedOnlyProfileSummary> Summary { get; init; } = [];
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
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public long? DurationMs { get; set; }
    public string? CorrelationId { get; set; }
    public string? ServerCorrelationId { get; set; }
    public string ServerCorrelationStatus { get; set; } = "client-generated-unconfirmed";
    public IReadOnlyList<string> EndpointAddresses { get; set; } = [];
    public List<StageResult> Stages { get; init; } = [];
    public SpeedMeasurementReport? DirectBefore { get; set; }
    public SpeedMeasurementReport? Tunnel { get; set; }
    public IReadOnlyList<SpeedMeasurementReport> TunnelPasses { get; set; } = [];
    public SpeedMeasurementReport? DirectAfter { get; set; }
    public SpeedPathComparison? Comparison { get; set; }
    public OutcomeDecision Outcome { get; set; } = new()
    {
        Outcome = OutcomeClassifier.Unknown,
        ReasonCode = "NOT_CLASSIFIED",
        Reason = "Speed profile has not been classified."
    };
}

internal sealed record SpeedOnlyProfileSummary(
    string ProfileId,
    string Name,
    double? DownloadMbps,
    double? UploadMbps,
    int? DownloadFlows,
    int? UploadFlows,
    string Confidence);
