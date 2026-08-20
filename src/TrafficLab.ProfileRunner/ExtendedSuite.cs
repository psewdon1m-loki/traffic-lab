using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

internal static partial class Program
{
    private const string ExtendedTarget = "https://www.google.com/generate_204";
    private const string TemporaryFirewallRule = "LokiTrafficLab-Temporary-ProcessBlock";

    private static async Task<IReadOnlyList<StageResult>> RunExtendedSuiteAsync(
        ConnectionProfile profile,
        RunnerOptions options,
        int httpPort,
        int socksPort,
        int xrayProcessId,
        HttpClient warmClient,
        Action<int, string>? progress,
        CancellationToken cancellationToken)
    {
        var stages = new List<StageResult>();
        progress?.Invoke(91, "extended: cold/warm connection comparison");
        stages.Add(await ProbeColdWarmAsync(httpPort, warmClient, options.Timeout, cancellationToken));

        progress?.Invoke(92, $"extended: {options.ParallelFlows} parallel TCP flows");
        stages.Add(await ProbeParallelTcpAsync(httpPort, options.Timeout, options.ParallelFlows, cancellationToken));

        progress?.Invoke(93, $"extended: {options.ParallelFlows} parallel UDP flows");
        stages.Add(await ProbeParallelUdpAsync(socksPort, options.Timeout, options.ParallelFlows, cancellationToken));

        progress?.Invoke(94, "extended: DNS failure and recovery");
        stages.Add(await ProbeDnsFailureRecoveryAsync(httpPort, options.Timeout, cancellationToken));

        progress?.Invoke(95, $"extended: {options.SoakDurationSeconds / 60} minute latency/jitter/loss soak");
        stages.Add(await ProbeLongSoakAsync(
            warmClient,
            TimeSpan.FromSeconds(options.SoakDurationSeconds),
            options.Timeout,
            percent => progress?.Invoke(95 + (int)Math.Floor(percent * 2d / 100d), $"extended soak: {percent}%"),
            cancellationToken));

        progress?.Invoke(98, "extended: forced Xray restart and reconnect");
        stages.Add(await ProbeCoreReconnectAsync(profile, options, cancellationToken));

        progress?.Invoke(99, "extended: process-scoped network interruption");
        stages.Add(await ProbeControlledNetworkInterruptionAsync(httpPort, xrayProcessId, options, cancellationToken));
        return stages;
    }

    private static Task<StageResult> ProbeControlledNetworkInterruptionAsync(
        int httpPort,
        int xrayProcessId,
        RunnerOptions options,
        CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
            return ProbeWindowsFirewallInterruptionAsync(httpPort, options, cancellationToken);
        if (OperatingSystem.IsLinux())
            return ProbeLinuxProcessPauseAsync(httpPort, xrayProcessId, options, cancellationToken);
        return Task.FromResult(StageResult.Skipped("tunnel.extended.networkInterruption", "A safe process-scoped interruption is not implemented for this operating system."));
    }

    private static async Task<StageResult> ProbeColdWarmAsync(
        int httpPort,
        HttpClient warmClient,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        int samples = 8)
    {
        var watch = Stopwatch.StartNew();
        samples = Math.Clamp(samples, 3, 20);
        var warm = new List<HttpProbeObservation>();
        var cold = new List<HttpProbeObservation>();

        _ = await ProbeHttpAsync(warmClient, ExtendedTarget, timeout, cancellationToken);
        for (var index = 0; index < samples; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            warm.Add(await ProbeHttpAsync(warmClient, ExtendedTarget, timeout, cancellationToken));
        }
        for (var index = 0; index < samples; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var coldClient = CreateProxyHttpClient(httpPort, timeout);
            cold.Add(await ProbeHttpAsync(coldClient, ExtendedTarget, timeout, cancellationToken));
        }

        watch.Stop();
        var warmLatency = warm.Where(item => item.Success).Select(item => item.ElapsedMs).ToArray();
        var coldLatency = cold.Where(item => item.Success).Select(item => item.ElapsedMs).ToArray();
        var successes = warmLatency.Length + coldLatency.Length;
        return StageResult.FromStatus(
            "tunnel.extended.coldWarm",
            successes == samples * 2 ? "passed" : successes > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                target = ExtendedTarget,
                samplesPerMode = samples,
                cold = SummarizeLatency(coldLatency, cold.Count - coldLatency.Length),
                warm = SummarizeLatency(warmLatency, warm.Count - warmLatency.Length),
                coldRequests = cold,
                warmRequests = warm,
                interpretation = "Cold samples use a newly allocated HTTP proxy connection pool for every request. Warm samples reuse one client pool. Without a controlled server connection ID, reuse is strongly requested but not independently proven by the destination."
            },
            successes == samples * 2 ? null : $"Only {successes} of {samples * 2} cold/warm requests succeeded.");
    }

    private static async Task<StageResult> ProbeParallelTcpAsync(
        int httpPort,
        TimeSpan timeout,
        int flows,
        CancellationToken cancellationToken)
    {
        flows = Math.Clamp(flows, 10, 100);
        var watch = Stopwatch.StartNew();
        var tasks = Enumerable.Range(0, flows).Select(async index =>
        {
            using var client = CreateProxyHttpClient(httpPort, timeout);
            var observation = await ProbeHttpAsync(client, ExtendedTarget + $"?tlab={index}-{Guid.NewGuid():N}", timeout, cancellationToken);
            return new ParallelTcpObservation(index + 1, observation.Success, observation.StatusCode, observation.ElapsedMs, observation.Error);
        }).ToArray();
        var observations = await Task.WhenAll(tasks);
        watch.Stop();
        var successful = observations.Where(item => item.Success).ToArray();
        return StageResult.FromStatus(
            "tunnel.extended.parallelTcp",
            successful.Length == flows ? "passed" : successful.Length > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                requestedFlows = flows,
                successfulFlows = successful.Length,
                failedFlows = flows - successful.Length,
                wallClockMs = watch.ElapsedMilliseconds,
                latency = SummarizeLatency(successful.Select(item => item.ElapsedMs).ToArray(), flows - successful.Length),
                observations,
                interpretation = "Every logical TCP flow owns a separate HttpClient connection pool, forcing independent connections to the local Xray HTTP inbound. Server-side multiplexing beyond the client remains opaque without a controlled canary."
            },
            successful.Length == flows ? null : $"Only {successful.Length} of {flows} parallel TCP flows succeeded.");
    }

    private static async Task<StageResult> ProbeParallelUdpAsync(
        int socksPort,
        TimeSpan timeout,
        int flows,
        CancellationToken cancellationToken)
    {
        flows = Math.Clamp(flows, 10, 100);
        var watch = Stopwatch.StartNew();
        var servers = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8") };
        var tasks = Enumerable.Range(0, flows).Select(async index =>
        {
            var server = servers[index % servers.Length];
            try
            {
                var observation = await SocksUdpDnsProbe.RunAsync(
                    "127.0.0.1", socksPort, server, index % 2 == 0 ? "one.one.one.one" : "dns.google", timeout, cancellationToken);
                return new ParallelUdpObservation(index + 1, server.ToString(), observation.Success, observation.ResponseCode, observation.AnswerCount, observation.Error);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new ParallelUdpObservation(index + 1, server.ToString(), false, null, null, Redact(ex.Message));
            }
        }).ToArray();
        var observations = await Task.WhenAll(tasks);
        watch.Stop();
        var successes = observations.Count(item => item.Success);
        return StageResult.FromStatus(
            "tunnel.extended.parallelUdp",
            successes == flows ? "passed" : successes > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                requestedFlows = flows,
                successfulFlows = successes,
                failedFlows = flows - successes,
                wallClockMs = watch.ElapsedMilliseconds,
                observations,
                interpretation = "Each UDP flow creates an independent SOCKS5 UDP ASSOCIATE control connection and UDP socket. Public resolver rate limiting remains an alternative explanation for isolated failures."
            },
            successes == flows ? null : $"Only {successes} of {flows} parallel UDP flows succeeded.");
    }

    private static async Task<StageResult> ProbeDnsFailureRecoveryAsync(
        int httpPort,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var invalidHost = $"{Guid.NewGuid():N}.traffic-lab.invalid";
        var shortTimeout = TimeSpan.FromSeconds(Math.Clamp(timeout.TotalSeconds, 3, 6));
        HttpProbeObservation expectedFailure;
        using (var failureClient = CreateProxyHttpClient(httpPort, shortTimeout))
            expectedFailure = await ProbeHttpAsync(failureClient, $"https://{invalidHost}/", shortTimeout, cancellationToken);
        HttpProbeObservation recovery;
        using (var recoveryClient = CreateProxyHttpClient(httpPort, timeout))
            recovery = await ProbeHttpAsync(recoveryClient, ExtendedTarget, timeout, cancellationToken);
        watch.Stop();
        var failureObserved = !expectedFailure.Success;
        var passed = failureObserved && recovery.Success;
        return StageResult.FromStatus(
            "tunnel.extended.dnsFailureRecovery",
            passed ? "passed" : recovery.Success || failureObserved ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                failureName = invalidHost,
                expectedFailure,
                recovery,
                failureObserved,
                recovered = recovery.Success,
                interpretation = "A unique reserved .invalid name exercises tunneled domain-resolution failure, followed immediately by a known valid domain. This proves client-path recovery after a DNS failure; it does not inject an outage into the operator's recursive resolver."
            },
            passed ? null : !failureObserved ? "The reserved invalid control unexpectedly succeeded." : "A valid tunneled request did not recover after the expected DNS failure.");
    }

    internal static async Task<StageResult> ProbeLongSoakAsync(
        HttpClient client,
        TimeSpan duration,
        TimeSpan requestTimeout,
        Action<int>? progress,
        CancellationToken cancellationToken,
        TimeSpan? sampleInterval = null)
    {
        if (duration <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(duration));
        var interval = sampleInterval ?? TimeSpan.FromSeconds(1);
        var watch = Stopwatch.StartNew();
        var samples = new List<SoakObservation>((int)Math.Min(1000, Math.Ceiling(duration.TotalMilliseconds / Math.Max(1, interval.TotalMilliseconds)) + 1));
        var index = 0;
        while (watch.Elapsed < duration)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var startedAt = DateTimeOffset.UtcNow;
            var observation = await ProbeHttpAsync(client, ExtendedTarget, requestTimeout, cancellationToken);
            samples.Add(new SoakObservation(++index, startedAt, observation.Success, observation.ElapsedMs, observation.StatusCode, observation.Error));
            progress?.Invoke(Math.Clamp((int)Math.Floor(watch.Elapsed.TotalMilliseconds / duration.TotalMilliseconds * 100), 0, 99));
            var remaining = duration - watch.Elapsed;
            if (remaining <= TimeSpan.Zero) break;
            await Task.Delay(remaining < interval ? remaining : interval, cancellationToken);
        }
        watch.Stop();
        progress?.Invoke(100);
        return BuildSoakStage(samples, watch.ElapsedMilliseconds, duration);
    }

    internal static StageResult BuildSoakStage(IReadOnlyList<SoakObservation> samples, long elapsedMs, TimeSpan requestedDuration)
    {
        var latencies = samples.Where(item => item.Success).Select(item => item.LatencyMs).ToArray();
        var jitters = new List<long>();
        SoakObservation? previous = null;
        foreach (var sample in samples)
        {
            if (sample.Success && previous is { Success: true }) jitters.Add(Math.Abs(sample.LatencyMs - previous.LatencyMs));
            previous = sample;
        }
        var maximumConsecutiveLoss = 0;
        var currentLoss = 0;
        foreach (var sample in samples)
        {
            currentLoss = sample.Success ? 0 : currentLoss + 1;
            maximumConsecutiveLoss = Math.Max(maximumConsecutiveLoss, currentLoss);
        }
        var successes = latencies.Length;
        var failures = samples.Count - successes;
        var lossPercent = samples.Count == 0 ? 100 : Math.Round(failures * 100d / samples.Count, 2);
        return StageResult.FromStatus(
            "tunnel.extended.soak",
            failures == 0 && successes > 0 ? "passed" : successes > 0 ? "partial" : "failed",
            elapsedMs,
            new
            {
                requestedDurationSeconds = Math.Round(requestedDuration.TotalSeconds, 3),
                actualDurationSeconds = Math.Round(elapsedMs / 1000d, 3),
                attempts = samples.Count,
                successes,
                failures,
                lossPercent,
                maximumConsecutiveLoss,
                latency = SummarizeLatency(latencies, failures),
                jitter = new
                {
                    definition = "absolute difference between consecutive successful application RTT samples",
                    samples = jitters.Count,
                    meanMs = Mean(jitters),
                    p50Ms = Percentile(jitters, 0.50),
                    p95Ms = Percentile(jitters, 0.95),
                    maxMs = jitters.Count == 0 ? (long?)null : jitters.Max()
                },
                samples,
                interpretation = "Loss means a timed HTTPS application probe failed; it is not ICMP packet loss. Jitter is application RTT variation and includes proxy, server and scheduler effects."
            },
            failures == 0 && successes > 0 ? null : $"{failures} of {samples.Count} soak probes failed ({lossPercent.ToString(CultureInfo.InvariantCulture)}%).");
    }

    private static async Task<StageResult> ProbeCoreReconnectAsync(
        ConnectionProfile profile,
        RunnerOptions options,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var runtimeDirectory = Path.Combine(Path.GetTempPath(), "loki-traffic-lab", "reconnect-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeDirectory);
        var configPath = Path.Combine(runtimeDirectory, "config.json");
        var httpPort = GetFreeTcpPort();
        var socksPort = GetFreeDualPort();
        await File.WriteAllTextAsync(configPath, BuildXrayConfig(profile, httpPort, socksPort, GetFreeUdpPort(), Path.Combine(runtimeDirectory, "access.log"), Path.Combine(runtimeDirectory, "error.log")), new UTF8Encoding(false), cancellationToken);
        Process? process = null;
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        var processIds = new List<int>();

        async Task<bool> StartAsync()
        {
            process = Process.Start(new ProcessStartInfo
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
            if (process is null) return false;
            processIds.Add(process.Id);
            stdout = process.StandardOutput.ReadToEndAsync();
            stderr = process.StandardError.ReadToEndAsync();
            return await WaitForTcpPortAsync(httpPort, TimeSpan.FromSeconds(10), cancellationToken);
        }

        async Task StopAsync()
        {
            if (process is null) return;
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            try { await process.WaitForExitAsync(); } catch { }
            if (stdout is not null) _ = await SafeTaskResultAsync(stdout);
            if (stderr is not null) _ = await SafeTaskResultAsync(stderr);
            process.Dispose();
            process = null;
            stdout = null;
            stderr = null;
        }

        using var cancellationRegistration = cancellationToken.Register(() =>
        {
            try { if (process is { HasExited: false }) process.Kill(entireProcessTree: true); } catch { }
        });
        try
        {
            var validation = await RunProcessAsync(options.XrayPath, $"run -test -c \"{configPath}\"", runtimeDirectory, options.Timeout, cancellationToken);
            if (validation.ExitCode != 0)
                return StageResult.Failed("tunnel.extended.reconnect", validation.ElapsedMs, "Reconnect Xray configuration validation failed.", new { validation.ExitCode });

            var firstReady = await StartAsync();
            HttpProbeObservation before;
            using (var client = CreateProxyHttpClient(httpPort, options.Timeout))
                before = firstReady
                    ? await ProbeHttpAsync(client, ExtendedTarget, options.Timeout, cancellationToken)
                    : new HttpProbeObservation(ExtendedTarget, null, false, 0, null, "Initial reconnect core did not become ready.");

            await StopAsync();
            using var failedClient = CreateProxyHttpClient(httpPort, TimeSpan.FromSeconds(3));
            var duringBreak = await ProbeHttpAsync(failedClient, ExtendedTarget, TimeSpan.FromSeconds(3), cancellationToken);

            var secondReady = await StartAsync();
            HttpProbeObservation after;
            using (var recoveredClient = CreateProxyHttpClient(httpPort, options.Timeout))
                after = secondReady
                    ? await ProbeHttpAsync(recoveredClient, ExtendedTarget, options.Timeout, cancellationToken)
                    : new HttpProbeObservation(ExtendedTarget, null, false, 0, null, "Restarted reconnect core did not become ready.");
            watch.Stop();
            var passed = before.Success && !duringBreak.Success && after.Success;
            return StageResult.FromStatus(
                "tunnel.extended.reconnect",
                passed ? "passed" : after.Success || before.Success ? "partial" : "failed",
                watch.ElapsedMilliseconds,
                new
                {
                    validationExitCode = validation.ExitCode,
                    firstReady,
                    secondReady,
                    processIds,
                    beforeBreak = before,
                    breakObserved = !duringBreak.Success,
                    duringBreak,
                    afterRestart = after,
                    recovered = after.Success,
                    interpretation = "Traffic Lab force-terminated only its isolated Xray process tree, verified an application failure, restarted the same configuration on the same local ports, and retried from a new client connection."
                },
                passed ? null : "The forced local-core interruption or subsequent recovery was not fully demonstrated.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("tunnel.extended.reconnect", watch.ElapsedMilliseconds, Redact(ex.Message));
        }
        finally
        {
            await StopAsync();
            try { Directory.Delete(runtimeDirectory, recursive: true); } catch { }
        }
    }

    private static async Task<StageResult> ProbeWindowsFirewallInterruptionAsync(
        int httpPort,
        RunnerOptions options,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return StageResult.Skipped("tunnel.extended.networkInterruption", "Process-scoped Windows Firewall interruption is available on Windows only.");
        if (!IsCurrentProcessElevated())
            return StageResult.Skipped("tunnel.extended.networkInterruption", "Administrator elevation was not granted; no firewall state was changed.");

        var netsh = Path.Combine(Environment.SystemDirectory, "netsh.exe");
        if (!File.Exists(netsh))
            return StageResult.Skipped("tunnel.extended.networkInterruption", "The Windows netsh firewall tool is unavailable.");

        var watch = Stopwatch.StartNew();
        var ruleName = TemporaryFirewallRule;
        var xrayPath = Path.GetFullPath(options.XrayPath);
        ProcessResult? add = null;
        ProcessResult? remove = null;
        HttpProbeObservation? duringInterruption = null;
        var ruleMayExist = false;
        DateTimeOffset? failureWindowStartedAt = null;
        DateTimeOffset? failureWindowEndedAt = null;
        try
        {
            _ = await RunProcessAsync(netsh, $"advfirewall firewall delete rule name=\"{ruleName}\"", Environment.SystemDirectory, TimeSpan.FromSeconds(10), CancellationToken.None);
            ruleMayExist = true;
            add = await RunProcessAsync(
                netsh,
                $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block program=\"{xrayPath}\" enable=yes profile=any",
                Environment.SystemDirectory,
                TimeSpan.FromSeconds(10),
                cancellationToken);
            if (add.ExitCode != 0)
                return StageResult.Failed("tunnel.extended.networkInterruption", add.ElapsedMs, "Windows Firewall rejected the temporary process-scoped block rule.", new { add.ExitCode, stderr = Truncate(Redact(add.Stderr), 500) });

            failureWindowStartedAt = DateTimeOffset.UtcNow;
            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
            using var blockedClient = CreateProxyHttpClient(httpPort, TimeSpan.FromSeconds(3));
            duringInterruption = await ProbeHttpAsync(blockedClient, ExtendedTarget, TimeSpan.FromSeconds(3), cancellationToken);
            var remaining = TimeSpan.FromSeconds(options.NetworkLossSeconds) - watch.Elapsed;
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining, cancellationToken);
        }
        finally
        {
            if (ruleMayExist)
            {
                remove = await RunProcessAsync(
                    netsh,
                    $"advfirewall firewall delete rule name=\"{ruleName}\"",
                    Environment.SystemDirectory,
                    TimeSpan.FromSeconds(10),
                    CancellationToken.None);
                failureWindowEndedAt = DateTimeOffset.UtcNow;
            }
        }

        var recoveryAttempts = new List<HttpProbeObservation>();
        var recoveryDeadline = Stopwatch.StartNew();
        while (recoveryDeadline.Elapsed < TimeSpan.FromSeconds(20))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var recoveryClient = CreateProxyHttpClient(httpPort, TimeSpan.FromSeconds(5));
            var attempt = await ProbeHttpAsync(recoveryClient, ExtendedTarget, TimeSpan.FromSeconds(5), cancellationToken);
            recoveryAttempts.Add(attempt);
            if (attempt.Success) break;
            await Task.Delay(500, cancellationToken);
        }
        watch.Stop();
        var interruptionObserved = duringInterruption is { Success: false };
        var recovered = recoveryAttempts.Any(item => item.Success);
        var removed = remove?.ExitCode == 0;
        return StageResult.FromStatus(
            "tunnel.extended.networkInterruption",
            interruptionObserved && recovered && removed ? "passed" : recovered && removed ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new NetworkInterruptionEvidence
            {
                Scope = "outbound Windows Firewall block for the bundled Traffic Lab xray.exe path only",
                RequestedInterruptionSeconds = options.NetworkLossSeconds,
                RuleName = ruleName,
                XrayExecutable = Path.GetFileName(xrayPath),
                AddExitCode = add?.ExitCode,
                RemoveExitCode = remove?.ExitCode,
                InterruptionObserved = interruptionObserved,
                DuringInterruption = duringInterruption,
                Recovered = recovered,
                RecoveryAttempts = recoveryAttempts,
                OtherApplicationsAffected = false,
                ExpectedFailureWindow = failureWindowStartedAt.HasValue && failureWindowEndedAt.HasValue
                    ? new ExpectedFailureWindow(failureWindowStartedAt.Value, failureWindowEndedAt.Value, "controlled_network_interruption")
                    : null,
                Interpretation = "The rule targets only Traffic Lab's bundled Xray executable. It does not disable the network adapter or block unrelated applications. The rule is deleted in a non-cancelable finally block."
            },
            interruptionObserved && recovered && removed ? null : "The process-scoped interruption, cleanup, or recovery was not fully demonstrated.");
    }

    private static async Task<StageResult> ProbeLinuxProcessPauseAsync(
        int httpPort,
        int xrayProcessId,
        RunnerOptions options,
        CancellationToken cancellationToken)
    {
        const int SigStop = 19;
        const int SigCont = 18;
        if (xrayProcessId <= 0)
            return StageResult.Skipped("tunnel.extended.networkInterruption", "The Traffic Lab Xray process ID was unavailable.");

        try
        {
            using var xray = Process.GetProcessById(xrayProcessId);
            if (xray.HasExited)
                return StageResult.Skipped("tunnel.extended.networkInterruption", "The Traffic Lab Xray process had already exited.");
        }
        catch (Exception ex)
        {
            return StageResult.Skipped("tunnel.extended.networkInterruption", "The Traffic Lab Xray process could not be inspected: " + Redact(ex.Message));
        }

        var watch = Stopwatch.StartNew();
        var stopResult = -1;
        var continueResult = -1;
        var stopped = false;
        HttpProbeObservation? duringInterruption = null;
        DateTimeOffset? failureWindowStartedAt = null;
        DateTimeOffset? failureWindowEndedAt = null;
        try
        {
            failureWindowStartedAt = DateTimeOffset.UtcNow;
            stopResult = SendUnixSignal(xrayProcessId, SigStop);
            if (stopResult != 0)
            {
                var errno = Marshal.GetLastPInvokeError();
                return StageResult.Failed(
                    "tunnel.extended.networkInterruption",
                    watch.ElapsedMilliseconds,
                    $"Linux rejected SIGSTOP for the isolated Traffic Lab Xray process (errno {errno}).",
                    new { xrayProcessId, stopResult, errno });
            }
            stopped = true;
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
            using var blockedClient = CreateProxyHttpClient(httpPort, TimeSpan.FromSeconds(3));
            duringInterruption = await ProbeHttpAsync(blockedClient, ExtendedTarget, TimeSpan.FromSeconds(3), cancellationToken);
            var remaining = TimeSpan.FromSeconds(options.NetworkLossSeconds) - watch.Elapsed;
            if (remaining > TimeSpan.Zero) await Task.Delay(remaining, cancellationToken);
        }
        finally
        {
            if (stopped)
            {
                continueResult = SendUnixSignal(xrayProcessId, SigCont);
                failureWindowEndedAt = DateTimeOffset.UtcNow;
            }
        }

        var recoveryAttempts = new List<HttpProbeObservation>();
        var recoveryDeadline = Stopwatch.StartNew();
        while (recoveryDeadline.Elapsed < TimeSpan.FromSeconds(20))
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var recoveryClient = CreateProxyHttpClient(httpPort, TimeSpan.FromSeconds(5));
            var attempt = await ProbeHttpAsync(recoveryClient, ExtendedTarget, TimeSpan.FromSeconds(5), cancellationToken);
            recoveryAttempts.Add(attempt);
            if (attempt.Success) break;
            await Task.Delay(500, cancellationToken);
        }
        watch.Stop();
        var interruptionObserved = duringInterruption is { Success: false };
        var recovered = recoveryAttempts.Any(item => item.Success);
        var resumed = continueResult == 0;
        return StageResult.FromStatus(
            "tunnel.extended.networkInterruption",
            interruptionObserved && recovered && resumed ? "passed" : recovered && resumed ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new NetworkInterruptionEvidence
            {
                Scope = "SIGSTOP/SIGCONT applied only to the Xray process started by this Traffic Lab profile",
                RequestedInterruptionSeconds = options.NetworkLossSeconds,
                RuleName = "linux-process-signals",
                XrayExecutable = Path.GetFileName(options.XrayPath),
                ProcessId = xrayProcessId,
                AddExitCode = stopResult,
                RemoveExitCode = continueResult,
                InterruptionObserved = interruptionObserved,
                DuringInterruption = duringInterruption,
                Recovered = recovered,
                RecoveryAttempts = recoveryAttempts,
                OtherApplicationsAffected = false,
                ExpectedFailureWindow = failureWindowStartedAt.HasValue && failureWindowEndedAt.HasValue
                    ? new ExpectedFailureWindow(failureWindowStartedAt.Value, failureWindowEndedAt.Value, "controlled_xray_process_pause")
                    : null,
                Interpretation = "Linux Traffic Lab pauses only its own Xray process for the requested interval and always sends SIGCONT in a finally block. It does not change UFW, routes, interfaces or unrelated applications."
            },
            interruptionObserved && recovered && resumed ? null : "The Linux process-scoped interruption or recovery was not fully demonstrated.");
    }

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int SendUnixSignal(int processId, int signal);

    internal static bool IsCurrentProcessElevated()
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var uid = File.ReadLines("/proc/self/status")
                    .FirstOrDefault(line => line.StartsWith("Uid:", StringComparison.Ordinal));
                return uid is not null
                    && uid.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Skip(1).FirstOrDefault() == "0";
            }
            catch
            {
                return false;
            }
        }
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static object SummarizeLatency(IReadOnlyList<long> values, int failures) => new
    {
        successes = values.Count,
        failures,
        meanMs = Mean(values),
        minMs = values.Count == 0 ? (long?)null : values.Min(),
        p50Ms = Percentile(values, 0.50),
        p95Ms = Percentile(values, 0.95),
        p99Ms = Percentile(values, 0.99),
        maxMs = values.Count == 0 ? (long?)null : values.Max()
    };

    private static double? Mean(IReadOnlyList<long> values)
        => values.Count == 0 ? null : Math.Round(values.Average(), 2);

    private static long? Percentile(IReadOnlyList<long> values, double percentile)
    {
        if (values.Count == 0) return null;
        var ordered = values.OrderBy(value => value).ToArray();
        var index = (int)Math.Ceiling(Math.Clamp(percentile, 0, 1) * ordered.Length) - 1;
        return ordered[Math.Clamp(index, 0, ordered.Length - 1)];
    }
}

internal sealed record ParallelTcpObservation(int Flow, bool Success, int? StatusCode, long ElapsedMs, string? Error);
internal sealed record ParallelUdpObservation(int Flow, string Resolver, bool Success, int? ResponseCode, int? AnswerCount, string? Error);
internal sealed record SoakObservation(int Sequence, DateTimeOffset StartedAt, bool Success, long LatencyMs, int? StatusCode, string? Error);
internal sealed record ExpectedFailureWindow(DateTimeOffset StartedAt, DateTimeOffset EndedAt, string Reason);

internal sealed class NetworkInterruptionEvidence
{
    public string Scope { get; init; } = "unknown";
    public int RequestedInterruptionSeconds { get; init; }
    public string RuleName { get; init; } = "";
    public string XrayExecutable { get; init; } = "xray.exe";
    public int? ProcessId { get; init; }
    public int? AddExitCode { get; init; }
    public int? RemoveExitCode { get; init; }
    public bool InterruptionObserved { get; init; }
    public HttpProbeObservation? DuringInterruption { get; init; }
    public bool Recovered { get; init; }
    public IReadOnlyList<HttpProbeObservation> RecoveryAttempts { get; init; } = [];
    public bool OtherApplicationsAffected { get; init; }
    public ExpectedFailureWindow? ExpectedFailureWindow { get; init; }
    public string Interpretation { get; init; } = "";
}

internal sealed class SelfTestHttpHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await Task.Delay(5, cancellationToken);
        return new HttpResponseMessage(HttpStatusCode.NoContent) { RequestMessage = request };
    }
}

internal sealed class SpeedSelfTestHttpHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await Task.Delay(5, cancellationToken);
        if (request.RequestUri?.AbsolutePath.Contains("__down", StringComparison.Ordinal) == true)
        {
            var requested = request.RequestUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(item => item.Split('=', 2)).FirstOrDefault(item => item.Length == 2 && item[0] == "bytes")?[1];
            var length = int.TryParse(requested, out var bytes) ? Math.Clamp(bytes, 0, 1024 * 1024) : 0;
            return new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request, Content = new ByteArrayContent(new byte[length]) };
        }
        if (request.Headers.Range is not null)
            return new HttpResponseMessage(HttpStatusCode.PartialContent) { RequestMessage = request, Content = new ByteArrayContent(new byte[1024 * 1024]) };
        if (request.Content is not null) await request.Content.CopyToAsync(Stream.Null, cancellationToken);
        return new HttpResponseMessage(HttpStatusCode.NoContent) { RequestMessage = request };
    }
}
