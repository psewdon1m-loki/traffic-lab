using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using Microsoft.Win32;

internal static partial class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly HttpClient DirectHttp = CreateDirectHttpClient(TimeSpan.FromSeconds(15));
    private static readonly ConcurrentDictionary<string, Task<IpAttribution>> AttributionCache = new(StringComparer.OrdinalIgnoreCase);

    [STAThread]
    public static Task<int> Main(string[] args)
    {
#if WINDOWS
        if ((args.Length == 0 || args.SequenceEqual(["--extended-gui"], StringComparer.OrdinalIgnoreCase))
            && OperatingSystem.IsWindows() && Environment.UserInteractive)
            return Task.FromResult(PortableGui.Run(args.Length == 1));
#endif
        return RunCliAsync(args);
    }

    internal static async Task<int> RunCliAsync(string[] args, Action<string>? progress = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await RunCliCoreAsync(args, progress, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            progress?.Invoke("Testing stopped by user. No partial result archive was retained.");
            return 130;
        }
    }

    private static async Task<int> RunCliCoreAsync(string[] args, Action<string>? progress, CancellationToken cancellationToken)
    {
        Console.OutputEncoding = Encoding.UTF8;
        cancellationToken.ThrowIfCancellationRequested();
        var commandResult = await LabCommands.TryHandleAsync(args);
        if (commandResult.HasValue)
        {
            return commandResult.Value;
        }
        if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
        {
            return RunSelfTests();
        }

        // Every START is a new measurement run; do not reuse attribution tasks
        // collected by an earlier completed or canceled GUI run.
        AttributionCache.Clear();

        RunnerOptions options;
        try
        {
            options = RunnerOptions.Parse(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Invalid runner options: {Redact(ex.Message)}");
            return 2;
        }
        RunnerInput input;
        try
        {
            if (options.ReadStdin)
            {
                input = JsonSerializer.Deserialize<RunnerInput>(await Console.In.ReadToEndAsync(), JsonOptions)
                    ?? throw new InvalidOperationException("Input JSON is empty.");
                input.InputSource = "stdin";
            }
            else
            {
                var fileInput = ConnectionFileLoader.Load(options.ConnectionFilePath);
                input = new RunnerInput
                {
                    Uris = fileInput.Entries.Select(item => item.Uri).ToList(),
                    SourceLineNumbers = fileInput.Entries.Select(item => item.LineNumber).ToList(),
                    InputSource = "connections-file",
                    NetworkLabel = "local-current-network"
                };
                Console.WriteLine($"Loaded {fileInput.Entries.Count} connection(s) from {Path.GetFileName(options.ConnectionFilePath)} in file order.");
                progress?.Invoke($"Loaded {fileInput.Entries.Count} connection(s) from connections.txt in file order.");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Invalid connection input: {Redact(ex.Message)}");
            return 2;
        }

        PortableTestPlan? plan;
        try
        {
            plan = LabCommands.LoadPlan(options.PlanPath);
            input.ApplyPlan(plan);
            options.ApplyPlan(plan);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Invalid test plan: {Redact(ex.Message)}");
            return 2;
        }

        if (input.Uris is not { Count: > 0 })
        {
            Console.Error.WriteLine("Input must contain at least one VLESS URI.");
            return 2;
        }

        var scheduledConnections = Math.Min(input.Uris.Count, options.MaxProfiles);
        var progressFile = new ProgressFileReporter(options.ProgressFilePath);
        var highestReportedPercent = 0;
        void ReportRunProgress(int percent, int completed, string message, string state = "running", string? zipPath = null)
        {
            percent = KeepProgressMonotonic(ref highestReportedPercent, percent);
            progress?.Invoke(message);
            progressFile.Report(state, percent, completed, scheduledConnections, message, zipPath);
        }
        ReportRunProgress(2, 0, $"Loaded {scheduledConnections} connection(s)");
        cancellationToken.ThrowIfCancellationRequested();

        if (!File.Exists(options.XrayPath))
        {
            Console.Error.WriteLine($"Xray executable not found: {options.XrayPath}");
            return 2;
        }

        Directory.CreateDirectory(options.OutputDirectory);
        var startedAt = DateTimeOffset.UtcNow;
        var runId = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
            + "-" + Guid.NewGuid().ToString("N")[..8];
        var report = new RunReport
        {
            RunId = runId,
            GeneratedAt = startedAt,
            StartedAt = startedAt,
            TestType = options.TestType,
            ExtendedTest = new ExtendedTestMetadata
            {
                Enabled = options.IsExtendedTest,
                Elevated = IsCurrentProcessElevated(),
                SoakDurationSeconds = options.IsExtendedTest ? options.SoakDurationSeconds : null,
                ParallelFlows = options.IsExtendedTest ? options.ParallelFlows : null,
                NetworkLossSeconds = options.IsExtendedTest ? options.NetworkLossSeconds : null
            },
            NetworkLabel = string.IsNullOrWhiteSpace(input.NetworkLabel) ? "local-current-network" : input.NetworkLabel.Trim(),
            TestContext = input.ToContext(),
            Tool = new ToolInfo
            {
                Name = "Loki Traffic Lab Profile Runner",
                Version = "3.3.0",
                XrayPath = Path.GetFileName(options.XrayPath),
                XrayVersion = await ReadXrayVersionAsync(options.XrayPath, cancellationToken),
                TimeoutSeconds = options.TimeoutSeconds,
                LocalTestPort = options.LocalPort
            },
            Input = new InputSummary
            {
                Source = input.InputSource,
                FileName = input.InputSource == "connections-file" ? Path.GetFileName(options.ConnectionFilePath) : null,
                LoadedConnections = input.Uris.Count,
                ScheduledConnections = scheduledConnections,
                Sequential = true
            },
            Environment = CaptureNetworkEnvironment(),
            Limitations =
            [
                "Client-side observations cannot prove the configured second hop, server outbound chain, HWID policy, or exact REALITY target.",
                "A successful ordinary TLS fallback is evidence of fallback-like behavior, not proof of VLESS or REALITY authentication.",
                "UDP success proves end-to-end UDP through the SOCKS inbound; it does not by itself prove XUDP packet encoding.",
                "IP geolocation and ASN organization names are attribution hints, not proof of physical server location."
            ]
        };
        if (options.IsExtendedTest)
        {
            report.Limitations.Add("Without a controlled canary, cold/warm reuse and parallel-flow counts are enforced at the client/Xray inbound but cannot independently prove the server's internal connection multiplexing.");
            report.Limitations.Add("The DNS failure/recovery control uses a reserved .invalid name followed by a valid name; it does not inject an outage into the operator's recursive DNS service.");
            report.Limitations.Add(OperatingSystem.IsWindows()
                ? "The Windows Firewall interruption targets only Traffic Lab's bundled Xray executable and does not represent loss of the entire device network interface."
                : OperatingSystem.IsLinux()
                    ? "The Linux interruption pauses only Traffic Lab's own Xray process with SIGSTOP/SIGCONT; it does not represent loss of the physical interface or change UFW."
                    : "A safe process-scoped network interruption is not implemented for this operating system.");
        }
        report.Environment.RouteSnapshot = await ExtendedDiagnostics.CaptureRouteSnapshotAsync(options.Timeout).WaitAsync(cancellationToken);

        Console.WriteLine("Capturing direct-network baseline...");
        ReportRunProgress(5, 0, "Capturing direct-network baseline");
        report.DirectBaseline = await ProbeExitIpsAsync(proxy: null, options.Timeout, cancellationToken);
        foreach (var directIp in report.DirectBaseline.Where(item => item.Valid).Select(item => item.Ip!).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            report.DirectAttribution.Add(await GetIpAttributionAsync(directIp, options.Timeout, cancellationToken));
        }
        report.Node = await NodeDiagnostics.CaptureAsync(report.Environment, report.DirectBaseline, report.DirectAttribution, report.TestContext, options.Timeout).WaitAsync(cancellationToken);
        if (!report.TestContext.Latitude.HasValue && report.Node.DeviceLocation.Status == "observed")
        {
            report.TestContext.Latitude = report.Node.DeviceLocation.Latitude;
            report.TestContext.Longitude = report.Node.DeviceLocation.Longitude;
            report.TestContext.LocationSource = report.Node.DeviceLocation.Source;
        }
        ReportRunProgress(15, 0, "Direct-network baseline captured");

        for (var index = 0; index < input.Uris.Count && index < options.MaxProfiles; index++)
        {
            var profileStartPercent = 15 + (int)Math.Floor(index * 78d / Math.Max(1, scheduledConnections));
            var profileEndPercent = 15 + (int)Math.Floor((index + 1) * 78d / Math.Max(1, scheduledConnections));
            void ReportProfileProgress(int profilePercent, string message)
            {
                var mapped = profileStartPercent + (int)Math.Round((profileEndPercent - profileStartPercent) * Math.Clamp(profilePercent, 0, 100) / 100d);
                ReportRunProgress(mapped, index, $"profile-{index + 1:00}: {message}");
            }
            ConnectionProfile profile;
            try
            {
                profile = ConnectionProfile.Parse(input.Uris[index]);
            }
            catch (Exception ex)
            {
                report.Profiles.Add(new ProfileReport
                {
                    ProfileId = $"profile-{index + 1:00}",
                    SourceOrdinal = index + 1,
                    SourceLine = input.SourceLineNumbers.Count > index ? input.SourceLineNumbers[index] : null,
                    Name = $"Invalid profile {index + 1}",
                    Declared = new DeclaredProfile(),
                    Stages = [StageResult.Failed("profile.parse", 0, Redact(ex.Message))],
                    Inferences = [new Inference("profileUsable", "unknown", "low", "The URI could not be parsed.")]
                });
                ReportRunProgress(profileEndPercent, index + 1, $"profile-{index + 1:00}: invalid profile recorded");
                continue;
            }

            if (options.AllowedHosts.Count > 0 && !options.AllowedHosts.Contains(profile.Host, StringComparer.OrdinalIgnoreCase))
            {
                report.Profiles.Add(new ProfileReport
                {
                    ProfileId = $"profile-{index + 1:00}",
                    SourceOrdinal = index + 1,
                    SourceLine = input.SourceLineNumbers.Count > index ? input.SourceLineNumbers[index] : null,
                    Name = profile.Name,
                    Declared = profile.ToDeclaredProfile(),
                    ProfileFingerprint = ExtendedDiagnostics.ComputeProfileFingerprint(profile.ToDeclaredProfile()),
                    Stages = [StageResult.Failed("profile.policy", 0, "The endpoint host is not present in the test plan allowlist.")],
                    Inferences = [new Inference("profileUsable", "not-tested", "high", "The portable agent refused an endpoint outside its allowlist.")]
                });
                ReportRunProgress(profileEndPercent, index + 1, $"profile-{index + 1:00}: policy refusal recorded");
                continue;
            }

            Console.WriteLine($"Testing profile-{index + 1:00}: {profile.Name} ({profile.Host}:{profile.Port})");
            ReportProfileProgress(1, $"starting {profile.Name}");
            var profileReport = await RunProfileAsync(
                profile,
                $"profile-{index + 1:00}",
                report.Environment.DnsServers,
                report.DirectBaseline,
                options,
                ReportProfileProgress,
                cancellationToken);
            profileReport.SourceOrdinal = index + 1;
            profileReport.SourceLine = input.SourceLineNumbers.Count > index ? input.SourceLineNumbers[index] : null;
            report.Profiles.Add(profileReport);
            ReportRunProgress(profileEndPercent, index + 1, $"profile-{index + 1:00}: completed");
        }

        cancellationToken.ThrowIfCancellationRequested();
        ReportRunProgress(95, scheduledConnections, "Building structured reports");
        report.HostnameGroups = BuildHostnameGroups(report.Profiles);
        OutcomeClassifier.Apply(report);
        report.OsiMap = NodeDiagnostics.BuildOsiMap(report);
        report.CompletedAt = DateTimeOffset.UtcNow;
        report.DurationMs = (long)(report.CompletedAt.Value - report.StartedAt).TotalMilliseconds;
        var stamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var jsonPath = Path.Combine(options.OutputDirectory, $"profile-lab-{stamp}.json");
        var csvPath = Path.Combine(options.OutputDirectory, $"profile-lab-{stamp}.csv");
        var osiPath = Path.Combine(options.OutputDirectory, $"profile-lab-{stamp}-osi.md");
        try
        {
            await WriteCsvAsync(csvPath, report).WaitAsync(cancellationToken);
            await NodeDiagnostics.WriteOsiMarkdownAsync(osiPath, report).WaitAsync(cancellationToken);
            ReportRunProgress(97, scheduledConnections, "Creating result ZIP");
            report.ResultPackage = await ResultPackageBuilder.CreateAsync(report, options.OutputDirectory, stamp, cancellationToken);
            await using (var stream = new FileStream(jsonPath, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                await JsonSerializer.SerializeAsync(stream, report, JsonOptions, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            foreach (var path in new[] { jsonPath, csvPath, osiPath, report.ResultPackage?.ZipPath })
            {
                try { if (!string.IsNullOrWhiteSpace(path) && File.Exists(path)) File.Delete(path); } catch { }
            }
            throw;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(options.HistoryPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(options.HistoryPath) ?? Environment.CurrentDirectory);
                await using var history = new HistoryStore(options.HistoryPath);
                await history.InitializeAsync(cancellationToken);
                await history.ImportAsync(jsonPath, cancellationToken);
            }
            else
            {
                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            foreach (var path in new[] { jsonPath, csvPath, osiPath, report.ResultPackage?.ZipPath })
            {
                try { if (!string.IsNullOrWhiteSpace(path) && File.Exists(path)) File.Delete(path); } catch { }
            }
            throw;
        }

        PrintSummary(report, jsonPath, csvPath, osiPath, report.ResultPackage.ZipPath);
        progress?.Invoke("ZIP : " + Path.GetFullPath(report.ResultPackage.ZipPath));
        var passedProfiles = report.Profiles.Count(profile => profile.Outcome?.Outcome == OutcomeClassifier.Pass);
        var failedProfiles = report.Profiles.Count - passedProfiles;
        var exitCode = passedProfiles > 0 ? 0 : 1;
        var finalMessage = $"Testing completed: {passedProfiles} usable, {failedProfiles} degraded/failed; outcome={report.Outcome?.Outcome ?? OutcomeClassifier.Unknown}";
        ReportRunProgress(100, scheduledConnections, finalMessage, exitCode == 0 ? "completed" : "completed-with-errors", Path.GetFullPath(report.ResultPackage.ZipPath));
        return exitCode;
    }

    private static async Task<ProfileReport> RunProfileAsync(
        ConnectionProfile profile,
        string profileId,
        IReadOnlyList<string> systemDnsServers,
        IReadOnlyList<ExitIpObservation> directBaseline,
        RunnerOptions options,
        Action<int, string>? profileProgress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var report = new ProfileReport
        {
            ProfileId = profileId,
            Name = profile.Name,
            Declared = profile.ToDeclaredProfile(),
            ProfileFingerprint = ExtendedDiagnostics.ComputeProfileFingerprint(profile.ToDeclaredProfile())
        };
        report.Stages.Add(StageResult.Passed("profile.parse", 0, new
        {
            profile.Protocol,
            profile.Host,
            profile.Port,
            profile.Security,
            profile.Network,
            profile.Sni,
            profile.Fingerprint,
            packetEncoding = profile.PacketEncoding ?? "not-declared"
        }));
        profileProgress?.Invoke(5, "profile parsed");

        var endpointDns = await ProbeDnsAsync(profile.Host, systemDnsServers, options.Timeout).WaitAsync(cancellationToken);
        var endpointDnsRounds = new List<DnsProbeResult> { endpointDns };
        if (options.EnableExtendedTests)
        {
            for (var round = 1; round < options.DnsAttempts; round++) endpointDnsRounds.Add(await ProbeDnsAsync(profile.Host, systemDnsServers, options.Timeout).WaitAsync(cancellationToken));
        }
        report.Stages.Add(endpointDns.Stage("endpoint.dns"));
        report.Stages.Add(ExtendedDiagnostics.BuildDnsConsistencyStage("endpoint.dnsConsistency", endpointDnsRounds));
        report.ObservedEndpointIps.AddRange(endpointDns.Addresses);

        DnsProbeResult? sniDns = null;
        if (!string.IsNullOrWhiteSpace(profile.Sni))
        {
            sniDns = await ProbeDnsAsync(profile.Sni, systemDnsServers, options.Timeout).WaitAsync(cancellationToken);
            var sniDnsRounds = new List<DnsProbeResult> { sniDns };
            if (options.EnableExtendedTests)
            {
                for (var round = 1; round < options.DnsAttempts; round++) sniDnsRounds.Add(await ProbeDnsAsync(profile.Sni, systemDnsServers, options.Timeout).WaitAsync(cancellationToken));
            }
            report.Stages.Add(sniDns.Stage("camouflage.dns"));
            report.Stages.Add(ExtendedDiagnostics.BuildDnsConsistencyStage("camouflage.dnsConsistency", sniDnsRounds));
            report.ObservedCamouflageIps.AddRange(sniDns.Addresses);
        }
        profileProgress?.Invoke(18, "DNS checks completed");
        cancellationToken.ThrowIfCancellationRequested();

        var endpointAddresses = endpointDns.Addresses
            .Select(value => IPAddress.TryParse(value, out var ip) ? ip : null)
            .Where(ip => ip is not null)
            .Cast<IPAddress>()
            .Distinct()
            .Take(12)
            .ToArray();

        var tcpResults = new List<TcpProbeObservation>();
        foreach (var address in endpointAddresses)
        {
            tcpResults.Add(await ProbeTcpAsync(address, profile.Port, options.Timeout).WaitAsync(cancellationToken));
        }
        report.Stages.Add(StageResult.FromStatus(
            "endpoint.tcp",
            tcpResults.Any(item => item.Connected) ? "passed" : "failed",
            tcpResults.Sum(item => item.ElapsedMs),
            tcpResults,
            tcpResults.Any(item => item.Connected) ? null : tcpResults.Count == 0 ? "No endpoint IP addresses were available." : "No endpoint TCP connection succeeded."));
        var endpointTcpAvailable = tcpResults.Any(item => item.Connected);
        if (options.EnableExtendedTests && endpointAddresses.Length > 0)
        {
            report.Stages.Add(await ExtendedDiagnostics.ProbeTcpSeriesAsync(endpointAddresses[0], profile.Port, options.TcpAttempts, options.Timeout).WaitAsync(cancellationToken));
            report.Stages.Add(await ExtendedDiagnostics.ProbePathMtuAsync(endpointAddresses[0], options.Timeout).WaitAsync(cancellationToken));
        }
        profileProgress?.Invoke(28, "endpoint transport checked");
        cancellationToken.ThrowIfCancellationRequested();

        var attributionWatch = Stopwatch.StartNew();
        var attributionIps = endpointDns.Addresses
            .Concat(sniDns?.Addresses ?? [])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(16)
            .ToArray();
        var attributions = new List<IpAttribution>();
        foreach (var ip in attributionIps)
        {
            attributions.Add(await GetIpAttributionAsync(ip, options.Timeout, cancellationToken));
        }
        attributionWatch.Stop();
        report.Stages.Add(StageResult.FromStatus(
            "network.attribution",
            attributions.Count > 0 ? "passed" : "skipped",
            attributionWatch.ElapsedMilliseconds,
            attributions,
            attributions.Count == 0 ? "No IP addresses to attribute." : null));
        report.Stages.Add(ExtendedDiagnostics.BuildGeoConsensusStage(
            "network.geoConsensus",
            "endpoint",
            attributions.Where(item => report.ObservedEndpointIps.Contains(item.Ip, StringComparer.OrdinalIgnoreCase))));
        report.Stages.Add(ExtendedDiagnostics.BuildGeoConsensusStage(
            "camouflage.geoConsensus",
            "camouflage-host",
            attributions.Where(item => report.ObservedCamouflageIps.Contains(item.Ip, StringComparer.OrdinalIgnoreCase))));

        if (!options.SkipTraceroute && endpointAddresses.Length > 0)
        {
            var traceroute = await ProbeTracerouteAsync(endpointAddresses[0], options.Timeout, cancellationToken);
            report.Stages.Add(traceroute);
            report.Stages.Add(options.EnableExtendedTests
                ? await EnrichTracerouteAsync(traceroute, options.Timeout, cancellationToken)
                : StageResult.Skipped("endpoint.tracerouteAttribution", "Extended tests are disabled."));
        }
        else
        {
            report.Stages.Add(StageResult.Skipped("endpoint.traceroute", options.SkipTraceroute ? "Disabled by option." : "No endpoint IP."));
            report.Stages.Add(StageResult.Skipped("endpoint.tracerouteAttribution", "Traceroute was not captured."));
        }
        profileProgress?.Invoke(40, "attribution and path checks completed");
        cancellationToken.ThrowIfCancellationRequested();

        if (endpointTcpAvailable && endpointAddresses.Length > 0 && !string.IsNullOrWhiteSpace(profile.Sni)
            && profile.Security is "reality" or "tls")
        {
            report.Stages.Add(await ProbeTlsAsync(endpointAddresses[0], profile.Port, profile.Sni, options.Timeout).WaitAsync(cancellationToken));
            if (options.EnableExtendedTests)
            {
                report.Stages.Add(await ExtendedDiagnostics.ProbeTlsMatrixAsync(endpointAddresses[0], profile.Port, profile.Sni, profile.Host, options.Timeout).WaitAsync(cancellationToken));
            }
        }
        else
        {
            var reason = !endpointTcpAvailable ? "Endpoint TCP prerequisite failed."
                : "Profile does not declare TLS/REALITY with SNI, or endpoint IP is unavailable.";
            report.Stages.Add(StageResult.Skipped("endpoint.tlsFallback", reason));
            report.Stages.Add(StageResult.Skipped("endpoint.tlsMatrix", reason));
        }

        report.Stages.Add(StageResult.Passed("profile.packetEncoding", 0, new
        {
            declared = profile.PacketEncoding ?? "not-declared",
            xudpDeclared = string.Equals(profile.PacketEncoding, "xudp", StringComparison.OrdinalIgnoreCase),
            compatibilityProbeRequested = options.EnableXudpCompatibility,
            interpretation = "A declared packetEncoding proves client configuration. Runtime UDP and an explicit A/B XUDP probe are needed to demonstrate server compatibility."
        }));

        if (endpointTcpAvailable && profile.Network == "ws" && endpointAddresses.Length > 0)
        {
            report.Stages.Add(await ProbeWebSocketUpgradeAsync(profile, endpointAddresses[0], options.Timeout).WaitAsync(cancellationToken));
        }
        else
        {
            report.Stages.Add(StageResult.Skipped("endpoint.websocketUpgrade", profile.Network != "ws" ? "Profile transport is not WebSocket." : "Endpoint TCP prerequisite failed."));
        }
        profileProgress?.Invoke(48, "TLS and transport presentation checked");
        cancellationToken.ThrowIfCancellationRequested();

        var runtimeResult = endpointTcpAvailable
            ? await ProbeTunnelAsync(profile, report, directBaseline, options, profileProgress, cancellationToken)
            : BuildSkippedTunnelResult("Endpoint TCP was unreachable; downstream authentication, performance, stability and UDP probes were not attempted.", options);
        report.Stages.AddRange(runtimeResult.Stages);
        report.ObservedSocketIps.AddRange(runtimeResult.ObservedRemoteIps);
        profileProgress?.Invoke(92, "tunnel tests completed");

        var authenticated = runtimeResult.Stages.Any(item => item.Stage == "tunnel.authenticatedEndToEnd" && item.Status == "passed");
        if (options.EnableNegativeControls && authenticated)
        {
            report.Stages.Add(await ProbeNegativeControlsAsync(profile, options, cancellationToken));
        }
        else
        {
            report.Stages.Add(StageResult.Skipped("tunnel.negativeControls", authenticated
                ? "Disabled by test plan; enable explicitly because controls create several intentionally rejected authentication attempts."
                : "Authenticated baseline did not succeed; negative authentication controls would not be interpretable."));
        }
        profileProgress?.Invoke(96, "negative controls completed");
        if (options.EnableXudpCompatibility && authenticated)
        {
            report.Stages.Add(await ProbeXudpCompatibilityAsync(profile, options, cancellationToken));
        }
        else
        {
            report.Stages.Add(StageResult.Skipped("tunnel.xudpCompatibility", authenticated
                ? "Disabled by test plan; use --xudp or enableXudpCompatibility to run an explicit A/B client configuration."
                : "Authenticated baseline did not succeed; an XUDP compatibility result would not be attributable."));
        }
        profileProgress?.Invoke(98, "XUDP compatibility completed");
        report.Stages.Add(ExtendedDiagnostics.BuildInfrastructureSignals(report));

        foreach (var exit in runtimeResult.ExitIps.Where(item => item.Valid).Select(item => item.Ip!).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            report.ExitAttribution.Add(await GetIpAttributionAsync(exit, options.Timeout, cancellationToken));
        }

        report.Inferences.AddRange(BuildInferences(profile, report, runtimeResult, directBaseline));
        profileProgress?.Invoke(100, "profile analysis completed");
        return report;
    }

    private static async Task<TunnelProbeResult> ProbeTunnelAsync(
        ConnectionProfile profile,
        ProfileReport profileReport,
        IReadOnlyList<ExitIpObservation> directBaseline,
        RunnerOptions options,
        Action<int, string>? profileProgress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new TunnelProbeResult();
        profileProgress?.Invoke(50, "preparing isolated Xray core");
        var routeBefore = await ExtendedDiagnostics.CaptureRouteSnapshotAsync(options.Timeout).WaitAsync(cancellationToken);
        var runtimeDirectory = Path.Combine(Path.GetTempPath(), "loki-traffic-lab", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeDirectory);
        var configPath = Path.Combine(runtimeDirectory, "config.json");
        var accessLog = Path.Combine(runtimeDirectory, "access.log");
        var errorLog = Path.Combine(runtimeDirectory, "error.log");
        var httpPort = options.LocalPort ?? GetFreeTcpPort();
        if (options.LocalPort.HasValue && !CanBindLoopbackTcpPort(httpPort))
        {
            result.Stages.Add(StageResult.Failed(
                "tunnel.localPort",
                0,
                $"Selected local test port {httpPort} is already in use or cannot be bound on 127.0.0.1."));
            return result;
        }
        var socksPort = GetFreeDualPort();
        var quicPort = GetFreeUdpPort();
        await File.WriteAllTextAsync(configPath, BuildXrayConfig(profile, httpPort, socksPort, quicPort, accessLog, errorLog), new UTF8Encoding(false), cancellationToken);

        Process? xray = null;
        Task<string>? stdoutTask = null;
        Task<string>? stderrTask = null;
        using var pollCancellation = new CancellationTokenSource();
        Task<HashSet<string>>? socketPollTask = null;
        using var stopRegistration = cancellationToken.Register(() =>
        {
            try { if (xray is { HasExited: false }) xray.Kill(entireProcessTree: true); } catch { }
        });
        try
        {
            var validation = await RunProcessAsync(
                options.XrayPath,
                $"run -test -c \"{configPath}\"",
                runtimeDirectory,
                options.Timeout,
                cancellationToken);
            result.Stages.Add(StageResult.FromProcess("tunnel.coreValidation", validation));
            profileProgress?.Invoke(55, "Xray configuration validated");
            if (validation.ExitCode != 0)
            {
                return result;
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = options.XrayPath,
                Arguments = $"run -c \"{configPath}\"",
                WorkingDirectory = runtimeDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            xray = Process.Start(startInfo);
            if (xray is null)
            {
                result.Stages.Add(StageResult.Failed("tunnel.coreStart", 0, "Failed to start Xray process."));
                return result;
            }
            stdoutTask = xray.StandardOutput.ReadToEndAsync();
            stderrTask = xray.StandardError.ReadToEndAsync();
            socketPollTask = PollProcessRemoteIpsAsync(xray.Id, pollCancellation.Token);

            var readyWatch = Stopwatch.StartNew();
            var ready = await WaitForTcpPortAsync(httpPort, TimeSpan.FromSeconds(10), cancellationToken);
            readyWatch.Stop();
            result.Stages.Add(StageResult.FromStatus(
                "tunnel.coreStart",
                ready ? "passed" : "failed",
                readyWatch.ElapsedMilliseconds,
                new { processId = xray.Id, httpPort, socksPort, quicPort },
                ready ? null : "Xray did not open the local HTTP inbound."));
            if (!ready)
            {
                return result;
            }
            profileProgress?.Invoke(62, "Xray local inbound ready");
            var routeAfter = await ExtendedDiagnostics.CaptureRouteSnapshotAsync(options.Timeout).WaitAsync(cancellationToken);
            result.Stages.Add(ExtendedDiagnostics.BuildCaptureScopeStage(routeBefore, routeAfter, CaptureNetworkEnvironment()));

            using var proxyHttp = CreateProxyHttpClient(httpPort, options.Timeout);
            result.ExitIps.AddRange(await ProbeExitIpsAsync(new WebProxy($"http://127.0.0.1:{httpPort}"), options.Timeout, cancellationToken));
            result.Stages.Add(StageResult.FromStatus(
                "tunnel.exitIp",
                result.ExitIps.Any(item => item.Valid) ? "passed" : "failed",
                result.ExitIps.Sum(item => item.ElapsedMs),
                new
                {
                    direct = directBaseline,
                    throughTunnel = result.ExitIps,
                    differsFromDirect = ExitDiffers(directBaseline, result.ExitIps)
                },
                result.ExitIps.Any(item => item.Valid) ? null : "No exit-IP service returned a valid IP through the tunnel."));
            result.Stages.Add(ExtendedDiagnostics.BuildAddressFamilyStage(directBaseline, result.ExitIps));

            var httpTargets = new[]
            {
                "https://www.google.com/generate_204",
                "https://www.gstatic.com/generate_204",
                "https://www.cloudflare.com/cdn-cgi/trace"
            };
            var httpObservations = new List<HttpProbeObservation>();
            foreach (var target in httpTargets)
            {
                httpObservations.Add(await ProbeHttpAsync(proxyHttp, target, options.Timeout, cancellationToken));
            }
            var successfulHttp = httpObservations.FirstOrDefault(item => item.Success);
            result.Stages.Add(StageResult.FromStatus(
                "tunnel.http",
                successfulHttp is not null ? "passed" : "failed",
                httpObservations.Sum(item => item.ElapsedMs),
                httpObservations,
                successfulHttp is not null ? null : "No functional HTTP target succeeded through the tunnel."));
            var authenticated = successfulHttp is not null || result.ExitIps.Any(item => item.Valid);
            result.Stages.Add(StageResult.FromStatus(
                "tunnel.authenticatedEndToEnd",
                authenticated ? "passed" : "failed",
                successfulHttp?.ElapsedMs ?? result.ExitIps.Sum(item => item.ElapsedMs),
                new
                {
                    protocol = profile.Protocol,
                    transport = profile.Network,
                    security = profile.Security,
                    firstSuccessfulTarget = successfulHttp?.Target,
                    firstSuccessfulStatus = successfulHttp?.StatusCode,
                    interpretation = "A successful destination request proves that the supplied profile completed the client core, transport security, VLESS authentication, and server outbound path as a whole."
                },
                authenticated ? null : "The authenticated profile did not complete a functional destination request."));
            profileProgress?.Invoke(72, "authenticated HTTP and exit IP checked");

            if (!authenticated)
            {
                AddSkippedTunnelStages(result, "Authenticated end-to-end traffic failed; downstream performance, stability and UDP checks were skipped to avoid repeated timeouts.", options);
                return result;
            }

            result.Stages.Add(await ProbeSocksDomainAsync(socksPort, options.Timeout).WaitAsync(cancellationToken));
            result.Stages.Add(await ProbeDownloadAsync(proxyHttp, options.Timeout, cancellationToken));
            if (options.EnableExtendedTests)
            {
                result.Stages.Add(await ExtendedDiagnostics.ProbeHttpProtocolMatrixAsync(proxyHttp, options.Timeout).WaitAsync(cancellationToken));
                result.Stages.Add(await ExtendedDiagnostics.ProbeTunnelPayloadMatrixAsync(proxyHttp, options.Timeout).WaitAsync(cancellationToken));
                result.Stages.Add(await ExtendedDiagnostics.ProbeUploadAsync(proxyHttp, options.Timeout).WaitAsync(cancellationToken));
            }
            if (!string.IsNullOrWhiteSpace(options.CanaryUrlTemplate))
            {
                result.Stages.Add(await ExtendedDiagnostics.ProbeControlledCanaryAsync(proxyHttp, options.CanaryUrlTemplate, profileReport.ProfileFingerprint ?? profileReport.ProfileId, options.Timeout).WaitAsync(cancellationToken));
            }
            else
            {
                result.Stages.Add(StageResult.Skipped("tunnel.controlledCanary", "No canaryUrlTemplate was configured. A controlled public DNS/HTTP collector is optional."));
            }
            result.Stages.Add(await ProbeStabilityAsync(proxyHttp, options.Timeout, options.StabilityAttempts).WaitAsync(cancellationToken));
            profileProgress?.Invoke(84, "performance and stability checked");
            result.Stages.Add(await ProbeSocksUdpAsync(socksPort, options.Timeout).WaitAsync(cancellationToken));
            if (options.EnableExtendedTests)
            {
                result.Stages.Add(await ExtendedDiagnostics.ProbeStunViaSocksAsync(socksPort, options.Timeout).WaitAsync(cancellationToken));
                result.Stages.Add(await ExtendedDiagnostics.ProbeQuicHandshakeAsync(quicPort, options.Timeout).WaitAsync(cancellationToken));
            }
            profileProgress?.Invoke(90, "UDP, STUN and QUIC checked");
            if (options.IsExtendedTest)
            {
                result.Stages.AddRange(await RunExtendedSuiteAsync(
                    profile, options, httpPort, socksPort, xray?.Id ?? 0, proxyHttp, profileProgress, cancellationToken));
            }
            else
            {
                result.Stages.Add(StageResult.Skipped("tunnel.extendedSuite", "Normal test selected. Long-running, elevated and connection-disrupting checks were not requested."));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.Stages.Add(StageResult.Failed("tunnel.unhandled", 0, Redact(ex.Message)));
        }
        finally
        {
            pollCancellation.Cancel();
            if (socketPollTask is not null)
            {
                try
                {
                    result.ObservedRemoteIps.UnionWith(await socketPollTask);
                }
                catch (OperationCanceledException)
                {
                }
            }

            if (xray is not null)
            {
                try
                {
                    if (!xray.HasExited)
                    {
                        xray.Kill(entireProcessTree: true);
                        await xray.WaitForExitAsync();
                    }
                }
                catch
                {
                }
            }

            var stdout = stdoutTask is null ? "" : await SafeTaskResultAsync(stdoutTask);
            var stderr = stderrTask is null ? "" : await SafeTaskResultAsync(stderrTask);
            var expectedFailureWindows = result.Stages
                .Select(stage => stage.Data)
                .OfType<NetworkInterruptionEvidence>()
                .Select(evidence => evidence.ExpectedFailureWindow)
                .Where(window => window is not null)
                .Cast<ExpectedFailureWindow>()
                .ToArray();
            result.Stages.Add(BuildCoreLogStage(accessLog, errorLog, stdout, stderr, expectedFailureWindows));
            try
            {
                Directory.Delete(runtimeDirectory, recursive: true);
            }
            catch
            {
            }
        }

        return result;
    }

    private static TunnelProbeResult BuildSkippedTunnelResult(string reason, RunnerOptions options)
    {
        var result = new TunnelProbeResult();
        result.Stages.Add(StageResult.Skipped("tunnel.coreValidation", reason));
        result.Stages.Add(StageResult.Skipped("tunnel.coreStart", reason));
        result.Stages.Add(StageResult.Skipped("client.captureScope", reason));
        result.Stages.Add(StageResult.Skipped("tunnel.exitIp", reason));
        result.Stages.Add(StageResult.Skipped("tunnel.addressFamilies", reason));
        result.Stages.Add(StageResult.Skipped("tunnel.http", reason));
        result.Stages.Add(StageResult.Skipped("tunnel.authenticatedEndToEnd", reason));
        AddSkippedTunnelStages(result, reason, options);
        result.Stages.Add(StageResult.Skipped("tunnel.logs", "The isolated core was not started because a prerequisite failed."));
        return result;
    }

    private static void AddSkippedTunnelStages(TunnelProbeResult result, string reason, RunnerOptions options)
    {
        var names = new List<string>
        {
            "tunnel.dnsViaSocks", "tunnel.download", "tunnel.controlledCanary", "tunnel.stability", "tunnel.udp"
        };
        if (options.EnableExtendedTests)
            names.AddRange(["tunnel.httpProtocols", "tunnel.payloadMatrix", "tunnel.upload", "tunnel.stun", "tunnel.quicHandshake"]);
        if (options.IsExtendedTest)
            names.AddRange(["tunnel.extended.coldWarm", "tunnel.extended.parallelTcp", "tunnel.extended.parallelUdp", "tunnel.extended.dnsFailureRecovery", "tunnel.extended.soak", "tunnel.extended.reconnect", "tunnel.extended.networkInterruption"]);
        else
            names.Add("tunnel.extendedSuite");
        foreach (var name in names.Distinct(StringComparer.OrdinalIgnoreCase))
            if (!result.Stages.Any(item => item.Stage.Equals(name, StringComparison.OrdinalIgnoreCase)))
                result.Stages.Add(StageResult.Skipped(name, reason));
    }

    private static async Task<StageResult> ProbeNegativeControlsAsync(ConnectionProfile profile, RunnerOptions options, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var variants = new[]
        {
            (name: "invalid-uuid", profile: profile.Copy(userId: Guid.NewGuid().ToString())),
            (name: "invalid-short-id", profile: profile.Copy(shortId: RandomHex(Math.Max(2, profile.ShortId?.Length ?? 16)))),
            (name: "wrong-sni", profile: profile.Copy(sni: $"invalid-{Guid.NewGuid():N}.invalid"))
        };
        var observations = new List<VariantControlObservation>();
        foreach (var variant in variants)
        {
            cancellationToken.ThrowIfCancellationRequested();
            observations.Add(await ProbeVariantHttpAsync(variant.name, variant.profile, options, cancellationToken));
        }
        watch.Stop();
        var unexpected = observations.Where(item => item.FunctionalRequestSucceeded).ToArray();
        return StageResult.FromStatus(
            "tunnel.negativeControls",
            unexpected.Length == 0 ? "passed" : "partial",
            watch.ElapsedMilliseconds,
            new
            {
                observations,
                expectedRejected = observations.Count(item => !item.FunctionalRequestSucceeded),
                unexpectedSuccesses = unexpected.Select(item => item.Variant).ToArray(),
                interpretation = "These are one-shot negative controls for the supplied authorized profile, not credential discovery. Failure helps separate endpoint reachability from authenticated end-to-end success."
            },
            unexpected.Length == 0 ? null : "At least one intentionally invalid control completed a functional request; inspect server policy and the control outcome.");
    }

    private static async Task<StageResult> ProbeXudpCompatibilityAsync(ConnectionProfile profile, RunnerOptions options, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var variant = profile.Copy(packetEncoding: "xudp");
        var runtimeDirectory = Path.Combine(Path.GetTempPath(), "loki-traffic-lab", "xudp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeDirectory);
        var configPath = Path.Combine(runtimeDirectory, "config.json");
        var httpPort = GetFreeTcpPort();
        var socksPort = GetFreeDualPort();
        await File.WriteAllTextAsync(configPath, BuildXrayConfig(variant, httpPort, socksPort, GetFreeUdpPort(), Path.Combine(runtimeDirectory, "access.log"), Path.Combine(runtimeDirectory, "error.log")), new UTF8Encoding(false), cancellationToken);
        Process? process = null;
        using var stopRegistration = cancellationToken.Register(() =>
        {
            try { if (process is { HasExited: false }) process.Kill(entireProcessTree: true); } catch { }
        });
        try
        {
            var validation = await RunProcessAsync(options.XrayPath, $"run -test -c \"{configPath}\"", runtimeDirectory, options.Timeout, cancellationToken);
            if (validation.ExitCode != 0)
            {
                watch.Stop();
                return StageResult.FromStatus("tunnel.xudpCompatibility", "partial", watch.ElapsedMilliseconds, new
                {
                    clientPacketEncoding = "xudp",
                    coreValidationExitCode = validation.ExitCode,
                    stderr = Truncate(Redact(validation.Stderr), 500)
                }, "The installed Xray core rejected the explicit XUDP client configuration.");
            }
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
            if (process is null || !await WaitForTcpPortAsync(httpPort, TimeSpan.FromSeconds(10), cancellationToken)) throw new InvalidOperationException("XUDP control core did not become ready.");
            var observation = await SocksUdpDnsProbe.RunAsync("127.0.0.1", socksPort, IPAddress.Parse("1.1.1.1"), "one.one.one.one", options.Timeout).WaitAsync(cancellationToken);
            watch.Stop();
            return StageResult.FromStatus(
                "tunnel.xudpCompatibility",
                observation.Success ? "passed" : "partial",
                watch.ElapsedMilliseconds,
                new
                {
                    clientPacketEncoding = "xudp",
                    serverCompatible = observation.Success,
                    udpProbe = observation,
                    interpretation = "Successful UDP with an explicitly generated packetEncoding=xudp client configuration is strong evidence that the server path accepts XUDP."
                },
                observation.Success ? null : observation.Error ?? "The explicit XUDP UDP probe did not complete.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.FromStatus("tunnel.xudpCompatibility", "partial", watch.ElapsedMilliseconds, null, Redact(ex.Message));
        }
        finally
        {
            if (process is not null)
            {
                try { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } } catch { }
                process.Dispose();
            }
            try { Directory.Delete(runtimeDirectory, true); } catch { }
        }
    }

    private static async Task<VariantControlObservation> ProbeVariantHttpAsync(string name, ConnectionProfile profile, RunnerOptions options, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var runtimeDirectory = Path.Combine(Path.GetTempPath(), "loki-traffic-lab", "control-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeDirectory);
        var configPath = Path.Combine(runtimeDirectory, "config.json");
        var accessLog = Path.Combine(runtimeDirectory, "access.log");
        var errorLog = Path.Combine(runtimeDirectory, "error.log");
        var httpPort = GetFreeTcpPort();
        var socksPort = GetFreeDualPort();
        await File.WriteAllTextAsync(configPath, BuildXrayConfig(profile, httpPort, socksPort, GetFreeUdpPort(), accessLog, errorLog), new UTF8Encoding(false), cancellationToken);
        Process? process = null;
        using var stopRegistration = cancellationToken.Register(() =>
        {
            try { if (process is { HasExited: false }) process.Kill(entireProcessTree: true); } catch { }
        });
        try
        {
            var shortTimeout = TimeSpan.FromSeconds(Math.Clamp(options.TimeoutSeconds, 3, 8));
            var validation = await RunProcessAsync(options.XrayPath, $"run -test -c \"{configPath}\"", runtimeDirectory, shortTimeout, cancellationToken);
            if (validation.ExitCode != 0)
            {
                watch.Stop();
                return new VariantControlObservation(name, false, false, "client-config-rejected", watch.ElapsedMilliseconds, Truncate(Redact(validation.Stderr), 400));
            }
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
            var ready = process is not null && await WaitForTcpPortAsync(httpPort, TimeSpan.FromSeconds(5), cancellationToken);
            if (!ready)
            {
                watch.Stop();
                return new VariantControlObservation(name, true, false, "core-not-ready", watch.ElapsedMilliseconds, "Control Xray core did not open its HTTP inbound.");
            }
            using var client = CreateProxyHttpClient(httpPort, shortTimeout);
            var probe = await ProbeHttpAsync(client, "https://www.google.com/generate_204", shortTimeout, cancellationToken);
            watch.Stop();
            var errorTail = string.Join(" | ", ReadTail(errorLog, 8).Where(IsSeriousCoreLogLine).Select(Redact));
            return new VariantControlObservation(name, true, probe.Success, probe.Success ? "unexpected-functional-success" : "rejected-or-failed", watch.ElapsedMilliseconds, probe.Error ?? Truncate(errorTail, 500));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            watch.Stop();
            return new VariantControlObservation(name, process is not null, false, "exception", watch.ElapsedMilliseconds, Redact(ex.Message));
        }
        finally
        {
            if (process is not null)
            {
                try { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } } catch { }
                process.Dispose();
            }
            try { Directory.Delete(runtimeDirectory, true); } catch { }
        }
    }

    private static string RandomHex(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes((length + 1) / 2);
        return Convert.ToHexString(bytes).ToLowerInvariant()[..length];
    }

    private static string BuildXrayConfig(
        ConnectionProfile profile,
        int httpPort,
        int socksPort,
        int quicPort,
        string accessLog,
        string errorLog)
    {
        var user = new Dictionary<string, object?>
        {
            ["id"] = profile.UserId,
            ["encryption"] = profile.Encryption
        };
        AddIfPresent(user, "flow", profile.Flow);
        AddIfPresent(user, "packetEncoding", profile.PacketEncoding);

        var stream = new Dictionary<string, object?>
        {
            ["network"] = profile.Network,
            ["security"] = profile.Security
        };
        if (profile.Security == "reality")
        {
            stream["realitySettings"] = Compact(new Dictionary<string, object?>
            {
                ["serverName"] = profile.Sni,
                ["fingerprint"] = profile.Fingerprint ?? "chrome",
                ["publicKey"] = profile.PublicKey,
                ["shortId"] = profile.ShortId,
                ["spiderX"] = profile.SpiderX ?? "/"
            });
        }
        else if (profile.Security == "tls")
        {
            stream["tlsSettings"] = Compact(new Dictionary<string, object?>
            {
                ["serverName"] = profile.Sni,
                ["fingerprint"] = profile.Fingerprint,
                ["allowInsecure"] = false
            });
        }

        if (profile.Network == "grpc")
        {
            stream["grpcSettings"] = Compact(new Dictionary<string, object?>
            {
                ["serviceName"] = profile.ServiceName,
                ["multiMode"] = false
            });
        }
        else if (profile.Network == "ws")
        {
            stream["wsSettings"] = Compact(new Dictionary<string, object?>
            {
                ["path"] = profile.Path ?? "/",
                ["headers"] = string.IsNullOrWhiteSpace(profile.HostHeader)
                    ? null
                    : new Dictionary<string, object?> { ["Host"] = profile.HostHeader }
            });
        }
        else if (profile.Network == "tcp" && !string.IsNullOrWhiteSpace(profile.HeaderType))
        {
            stream["tcpSettings"] = new Dictionary<string, object?>
            {
                ["header"] = new Dictionary<string, object?> { ["type"] = profile.HeaderType }
            };
        }

        var document = new Dictionary<string, object?>
        {
            ["log"] = new Dictionary<string, object?>
            {
                ["loglevel"] = "info",
                ["access"] = accessLog,
                ["error"] = errorLog
            },
            ["inbounds"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["tag"] = "socks-in",
                    ["listen"] = "127.0.0.1",
                    ["port"] = socksPort,
                    ["protocol"] = "socks",
                    ["settings"] = new Dictionary<string, object?> { ["udp"] = true },
                    ["sniffing"] = new Dictionary<string, object?>
                    {
                        ["enabled"] = true,
                        ["destOverride"] = new[] { "http", "tls", "quic" },
                        ["routeOnly"] = false
                    }
                },
                new Dictionary<string, object?>
                {
                    ["tag"] = "http-in",
                    ["listen"] = "127.0.0.1",
                    ["port"] = httpPort,
                    ["protocol"] = "http",
                    ["settings"] = new Dictionary<string, object?>(),
                    ["sniffing"] = new Dictionary<string, object?>
                    {
                        ["enabled"] = true,
                        ["destOverride"] = new[] { "http", "tls", "quic" },
                        ["routeOnly"] = false
                    }
                },
                new Dictionary<string, object?>
                {
                    ["tag"] = "quic-in",
                    ["listen"] = "127.0.0.1",
                    ["port"] = quicPort,
                    ["protocol"] = "dokodemo-door",
                    ["settings"] = new Dictionary<string, object?>
                    {
                        ["address"] = "cloudflare-dns.com",
                        ["port"] = 443,
                        ["network"] = "udp"
                    }
                }
            },
            ["outbounds"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["tag"] = "proxy",
                    ["protocol"] = "vless",
                    ["settings"] = new Dictionary<string, object?>
                    {
                        ["vnext"] = new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["address"] = profile.Host,
                                ["port"] = profile.Port,
                                ["users"] = new object[] { user }
                            }
                        }
                    },
                    ["streamSettings"] = stream
                },
                new Dictionary<string, object?> { ["tag"] = "direct", ["protocol"] = "freedom" },
                new Dictionary<string, object?> { ["tag"] = "block", ["protocol"] = "blackhole" }
            },
            ["routing"] = new Dictionary<string, object?>
            {
                ["domainStrategy"] = "AsIs",
                ["rules"] = Array.Empty<object>()
            }
        };

        return JsonSerializer.Serialize(document, JsonOptions);
    }

    private static async Task<DnsProbeResult> ProbeDnsAsync(
        string host,
        IReadOnlyList<string> systemDnsServers,
        TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        var result = new DnsProbeResult { Host = host };
        if (IPAddress.TryParse(host, out var literal))
        {
            result.Observations.Add(new DnsObservation("literal", literal.AddressFamily == AddressFamily.InterNetwork ? "A" : "AAAA", literal.ToString(), null, 0, "success", null));
            watch.Stop();
            result.ElapsedMs = watch.ElapsedMilliseconds;
            return result;
        }

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var addresses = await Dns.GetHostAddressesAsync(host, cancellation.Token);
            foreach (var address in addresses)
            {
                result.Observations.Add(new DnsObservation(
                    "system-api",
                    address.AddressFamily == AddressFamily.InterNetwork ? "A" : "AAAA",
                    address.ToString(),
                    null,
                    watch.ElapsedMilliseconds,
                    "success",
                    null));
            }
        }
        catch (Exception ex)
        {
            result.Observations.Add(new DnsObservation("system-api", "A/AAAA", null, null, watch.ElapsedMilliseconds, "failed", Redact(ex.Message)));
        }

        var resolverIps = systemDnsServers
            .Concat(["1.1.1.1", "8.8.8.8"])
            .Where(IsUsableDnsResolver)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToArray();
        foreach (var resolver in resolverIps)
        {
            foreach (var type in new ushort[] { 1, 28 })
            {
                result.Observations.AddRange(await QueryDnsUdpAsync(host, resolver, type, timeout));
            }
        }

        result.Observations.AddRange(await QueryDohAsync(host, "google-doh", $"https://dns.google/resolve?name={Uri.EscapeDataString(host)}&type=A", timeout));
        result.Observations.AddRange(await QueryDohAsync(host, "google-doh", $"https://dns.google/resolve?name={Uri.EscapeDataString(host)}&type=AAAA", timeout));
        result.Observations.AddRange(await QueryDohAsync(host, "cloudflare-doh", $"https://cloudflare-dns.com/dns-query?name={Uri.EscapeDataString(host)}&type=A", timeout));
        result.Observations.AddRange(await QueryDohAsync(host, "cloudflare-doh", $"https://cloudflare-dns.com/dns-query?name={Uri.EscapeDataString(host)}&type=AAAA", timeout));
        watch.Stop();
        result.ElapsedMs = watch.ElapsedMilliseconds;
        return result;
    }

    private static async Task<IReadOnlyList<DnsObservation>> QueryDnsUdpAsync(
        string host,
        string resolver,
        ushort type,
        TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            var resolverIp = IPAddress.Parse(resolver);
            using var udp = new UdpClient(resolverIp.AddressFamily);
            udp.Connect(new IPEndPoint(resolverIp, 53));
            var query = DnsWire.BuildQuery(host, type, out var id);
            await udp.SendAsync(query, query.Length);
            using var cancellation = new CancellationTokenSource(timeout);
            var response = await udp.ReceiveAsync(cancellation.Token);
            watch.Stop();
            return DnsWire.ParseResponse(response.Buffer, id)
                .Select(record => new DnsObservation(resolver, record.Type, record.Value, record.Ttl, watch.ElapsedMilliseconds, "success", null))
                .DefaultIfEmpty(new DnsObservation(resolver, type == 1 ? "A" : "AAAA", null, null, watch.ElapsedMilliseconds, "empty", null))
                .ToArray();
        }
        catch (Exception ex)
        {
            watch.Stop();
            return [new DnsObservation(resolver, type == 1 ? "A" : "AAAA", null, null, watch.ElapsedMilliseconds, "failed", Redact(ex.Message))];
        }
    }

    private static async Task<IReadOnlyList<DnsObservation>> QueryDohAsync(
        string host,
        string resolver,
        string url,
        TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));
            using var cancellation = new CancellationTokenSource(timeout);
            using var response = await DirectHttp.SendAsync(request, cancellation.Token);
            var text = await response.Content.ReadAsStringAsync(cancellation.Token);
            response.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(text);
            var observations = new List<DnsObservation>();
            if (json.RootElement.TryGetProperty("Answer", out var answers) && answers.ValueKind == JsonValueKind.Array)
            {
                foreach (var answer in answers.EnumerateArray())
                {
                    var type = answer.TryGetProperty("type", out var typeElement) ? typeElement.GetInt32() : 0;
                    var value = answer.TryGetProperty("data", out var dataElement) ? dataElement.GetString() : null;
                    var ttl = answer.TryGetProperty("TTL", out var ttlElement) ? ttlElement.GetInt32() : (int?)null;
                    if (type is 1 or 5 or 28)
                    {
                        observations.Add(new DnsObservation(resolver, type switch { 1 => "A", 5 => "CNAME", 28 => "AAAA", _ => type.ToString() }, value?.TrimEnd('.'), ttl, watch.ElapsedMilliseconds, "success", null));
                    }
                }
            }
            watch.Stop();
            return observations.Count > 0
                ? observations
                : [new DnsObservation(resolver, "A", null, null, watch.ElapsedMilliseconds, "empty", null)];
        }
        catch (Exception ex)
        {
            watch.Stop();
            return [new DnsObservation(resolver, "A", null, null, watch.ElapsedMilliseconds, "failed", Redact(ex.Message))];
        }
    }

    private static async Task<TcpProbeObservation> ProbeTcpAsync(IPAddress address, int port, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var cancellation = new CancellationTokenSource(timeout);
            await client.ConnectAsync(address, port, cancellation.Token);
            watch.Stop();
            return new TcpProbeObservation(address.ToString(), port, true, "connected", watch.ElapsedMilliseconds, null);
        }
        catch (SocketException ex)
        {
            watch.Stop();
            return new TcpProbeObservation(address.ToString(), port, false, ex.SocketErrorCode.ToString(), watch.ElapsedMilliseconds, Redact(ex.Message));
        }
        catch (OperationCanceledException)
        {
            watch.Stop();
            return new TcpProbeObservation(address.ToString(), port, false, "timeout", watch.ElapsedMilliseconds, "TCP connect timed out.");
        }
        catch (Exception ex)
        {
            watch.Stop();
            return new TcpProbeObservation(address.ToString(), port, false, "error", watch.ElapsedMilliseconds, Redact(ex.Message));
        }
    }

    private static async Task<StageResult> ProbeTlsAsync(IPAddress address, int port, string sni, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        X509Certificate2? remoteCertificate = null;
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var cancellation = new CancellationTokenSource(timeout);
            await client.ConnectAsync(address, port, cancellation.Token);
            using var ssl = new SslStream(client.GetStream(), false, (_, certificate, _, _) =>
            {
                if (certificate is not null)
                {
                    remoteCertificate = new X509Certificate2(certificate);
                }
                return true;
            });
            var authentication = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
            };
            await ssl.AuthenticateAsClientAsync(authentication, cancellation.Token);
            watch.Stop();
            var certificateInfo = remoteCertificate is null ? null : CertificateInfo.From(remoteCertificate);
            return StageResult.Passed("endpoint.tlsFallback", watch.ElapsedMilliseconds, new
            {
                endpointIp = address.ToString(),
                port,
                sni,
                protocol = ssl.SslProtocol.ToString(),
                cipherSuite = ssl.NegotiatedCipherSuite.ToString(),
                alpn = Encoding.ASCII.GetString(ssl.NegotiatedApplicationProtocol.Protocol.Span),
                certificate = certificateInfo,
                sniCoveredByCertificate = certificateInfo?.CoversHost(sni),
                interpretation = "Ordinary TLS reached a certificate-serving fallback. This does not prove REALITY/VLESS authentication or the exact server target."
            });
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("endpoint.tlsFallback", watch.ElapsedMilliseconds, Redact(ex.Message), new
            {
                endpointIp = address.ToString(),
                port,
                sni,
                certificate = remoteCertificate is null ? null : CertificateInfo.From(remoteCertificate)
            });
        }
        finally
        {
            remoteCertificate?.Dispose();
        }
    }

    private static async Task<StageResult> ProbeWebSocketUpgradeAsync(ConnectionProfile profile, IPAddress address, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var cancellation = new CancellationTokenSource(timeout);
            await client.ConnectAsync(address, profile.Port, cancellation.Token);
            Stream stream = client.GetStream();
            SslStream? ssl = null;
            if (profile.Security == "tls")
            {
                ssl = new SslStream(stream, false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = profile.Sni ?? profile.HostHeader ?? profile.Host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = [SslApplicationProtocol.Http11]
                }, cancellation.Token);
                stream = ssl;
            }

            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var path = string.IsNullOrWhiteSpace(profile.Path) ? "/" : profile.Path;
            var host = profile.HostHeader ?? profile.Host;
            var request = $"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cancellation.Token);
            await stream.FlushAsync(cancellation.Token);
            var buffer = new byte[4096];
            var read = await stream.ReadAsync(buffer, cancellation.Token);
            var response = Encoding.ASCII.GetString(buffer, 0, read);
            var firstLine = response.Split("\r\n", StringSplitOptions.None).FirstOrDefault() ?? "";
            var upgraded = firstLine.Contains(" 101 ", StringComparison.Ordinal);
            watch.Stop();
            ssl?.Dispose();
            return StageResult.FromStatus(
                "endpoint.websocketUpgrade",
                upgraded ? "passed" : "failed",
                watch.ElapsedMilliseconds,
                new { endpointIp = address.ToString(), profile.Port, path, host, responseStatus = firstLine },
                upgraded ? null : "The endpoint did not return HTTP 101 for the profile path and Host header.");
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("endpoint.websocketUpgrade", watch.ElapsedMilliseconds, Redact(ex.Message));
        }
    }

    private static async Task<StageResult> ProbeTracerouteAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var effectiveTimeout = TimeSpan.FromSeconds(Math.Max(20, timeout.TotalSeconds * 2));
        ProcessResult process;
        if (OperatingSystem.IsWindows())
        {
            process = await RunProcessAsync("tracert.exe", $"-d -h 20 -w 500 {address}", Environment.CurrentDirectory, effectiveTimeout, cancellationToken);
        }
        else if (OperatingSystem.IsLinux())
        {
            process = await RunProcessAsync("traceroute", $"-n -m 20 -w 1 -q 1 {address}", Environment.CurrentDirectory, effectiveTimeout, cancellationToken);
        }
        else
        {
            return StageResult.Skipped("endpoint.traceroute", "Traceroute is implemented for Windows and Linux only.");
        }
        var hops = new List<object>();
        foreach (var line in process.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var match = Regex.Match(line, @"^\s*(?<hop>\d+)\s+(?<rest>.+)$");
            if (!match.Success)
            {
                continue;
            }
            var ips = Regex.Matches(match.Groups["rest"].Value, @"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
                .Select(item => item.Value)
                .Distinct()
                .ToArray();
            hops.Add(new { hop = int.Parse(match.Groups["hop"].Value, CultureInfo.InvariantCulture), addresses = ips, timedOut = match.Groups["rest"].Value.Contains('*') });
        }
        return StageResult.FromStatus(
            "endpoint.traceroute",
            process.ExitCode == 0 || hops.Count > 0 ? "passed" : "failed",
            process.ElapsedMs,
            new { target = address.ToString(), hops },
            process.ExitCode == 0 || hops.Count > 0 ? null : Redact(process.Stderr));
    }

    private static async Task<IpAttribution> GetIpAttributionAsync(string ip, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(ip, out _))
        {
            return new IpAttribution { Ip = ip, Status = "invalid" };
        }
        return await AttributionCache.GetOrAdd(ip, _ => QueryIpAttributionAsync(ip, timeout)).WaitAsync(cancellationToken);
    }

    private static async Task<StageResult> EnrichTracerouteAsync(StageResult traceroute, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        if (traceroute.Data is null || traceroute.Status == "skipped") return StageResult.Skipped("endpoint.tracerouteAttribution", "No traceroute data was available.");
        try
        {
            var element = JsonSerializer.SerializeToElement(traceroute.Data, JsonOptions);
            var addresses = element.GetProperty("hops").EnumerateArray()
                .SelectMany(hop => hop.GetProperty("addresses").EnumerateArray().Select(value => value.GetString()))
                .Where(value => !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(value, out var address) && IsPublicAddress(address))
                .Select(value => value!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToArray();
            var attributions = await Task.WhenAll(addresses.Select(address => GetIpAttributionAsync(address, timeout, cancellationToken))).WaitAsync(cancellationToken);
            var asPath = attributions.SelectMany(item => item.OriginAsns).Distinct().ToArray();
            return StageResult.FromStatus(
                "endpoint.tracerouteAttribution",
                attributions.Length > 0 ? "passed" : "partial",
                0,
                new
                {
                    attributedHops = attributions,
                    observedAsPath = asPath,
                    interpretation = "Traceroute is incomplete under ICMP filtering and ECMP. The observed AS sequence is a path hint, not a guaranteed packet-by-packet route."
                },
                attributions.Length > 0 ? null : "No public traceroute hop could be attributed.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return StageResult.FromStatus("endpoint.tracerouteAttribution", "partial", 0, null, Redact(ex.Message));
        }
    }

    private static bool IsPublicAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !(bytes[0] == 10 || bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168)
                || bytes[0] >= 224);
        }
        return !address.IsIPv6LinkLocal && !address.IsIPv6Multicast && !(bytes[0] == 0xfc || bytes[0] == 0xfd);
    }

    private static async Task<IpAttribution> QueryIpAttributionAsync(string ip, TimeSpan timeout)
    {
        var result = new IpAttribution { Ip = ip, Status = "partial" };
        try
        {
            var reverse = await Dns.GetHostEntryAsync(ip);
            result.ReverseDns = reverse.HostName;
        }
        catch
        {
        }

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var url = $"https://stat.ripe.net/data/prefix-overview/data.json?resource={Uri.EscapeDataString(ip)}";
            var json = await DirectHttp.GetStringAsync(url, cancellation.Token);
            using var doc = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data");
            result.Prefix = ReadString(data, "prefix") ?? ReadString(data, "resource");
            result.AsnHolder = ReadString(data, "holder");
            if (data.TryGetProperty("asns", out var asns) && asns.ValueKind == JsonValueKind.Array)
            {
                var originAsns = new List<long>();
                foreach (var item in asns.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Number && item.TryGetInt64(out var numericAsn))
                    {
                        originAsns.Add(numericAsn);
                    }
                    else if (item.ValueKind == JsonValueKind.Object)
                    {
                        if (item.TryGetProperty("asn", out var asnElement) && asnElement.TryGetInt64(out var objectAsn))
                        {
                            originAsns.Add(objectAsn);
                        }
                        result.AsnHolder ??= ReadString(item, "holder");
                    }
                }
                result.OriginAsns = originAsns.Distinct().ToArray();
            }
            result.BgpSource = "RIPEstat prefix-overview";
        }
        catch (Exception ex)
        {
            result.Errors.Add("BGP: " + Redact(ex.Message));
        }

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var url = $"https://stat.ripe.net/data/geoloc/data.json?resource={Uri.EscapeDataString(ip)}";
            var json = await DirectHttp.GetStringAsync(url, cancellation.Token);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.GetProperty("data").TryGetProperty("located_resources", out var resources)
                && resources.ValueKind == JsonValueKind.Array)
            {
                foreach (var resource in resources.EnumerateArray())
                {
                    if (!resource.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array) continue;
                    foreach (var location in locations.EnumerateArray())
                    {
                        result.GeolocationHints.Add(new GeoHint
                        {
                            Country = ReadString(location, "country"),
                            City = ReadString(location, "city"),
                            Latitude = location.TryGetProperty("latitude", out var latitude) && latitude.TryGetDouble(out var lat) ? lat : null,
                            Longitude = location.TryGetProperty("longitude", out var longitude) && longitude.TryGetDouble(out var lon) ? lon : null,
                            Source = "RIPEstat geoloc",
                            Confidence = "hint-only"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add("Geolocation: " + Redact(ex.Message));
        }

        var rdapEndpoints = new[]
        {
            "https://rdap.arin.net/registry/ip/",
            "https://rdap.db.ripe.net/ip/",
            "https://rdap.apnic.net/ip/",
            "https://rdap.lacnic.net/rdap/ip/",
            "https://rdap.afrinic.net/rdap/ip/"
        };
        foreach (var endpoint in rdapEndpoints)
        {
            try
            {
                using var cancellation = new CancellationTokenSource(timeout);
                using var response = await DirectHttp.GetAsync(endpoint + Uri.EscapeDataString(ip), cancellation.Token);
                if (!response.IsSuccessStatusCode)
                {
                    continue;
                }
                using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellation.Token));
                var root = doc.RootElement;
                result.RdapName = ReadString(root, "name");
                result.RdapCountry = ReadString(root, "country");
                result.RdapStartAddress = ReadString(root, "startAddress");
                result.RdapEndAddress = ReadString(root, "endAddress");
                result.RdapSource = response.RequestMessage?.RequestUri?.GetLeftPart(UriPartial.Path) ?? endpoint;
                break;
            }
            catch
            {
            }
        }

        result.Status = result.OriginAsns.Count > 0 || result.RdapSource is not null ? "success" : "partial";
        return result;
    }

    private static async Task<IReadOnlyList<ExitIpObservation>> ProbeExitIpsAsync(IWebProxy? proxy, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        using var client = proxy is null ? CreateDirectHttpClient(timeout) : CreateProxyHttpClient(((WebProxy)proxy).Address!.Port, timeout);
        var services = new Dictionary<string, string>
        {
            ["api.ipify.org"] = "https://api.ipify.org?format=json",
            ["checkip.amazonaws.com"] = "https://checkip.amazonaws.com",
            ["ifconfig.me"] = "https://ifconfig.me/ip"
        };
        var results = new List<ExitIpObservation>();
        foreach (var pair in services)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var watch = Stopwatch.StartNew();
            try
            {
                using var timeoutCancellation = new CancellationTokenSource(timeout);
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellation.Token);
                var body = (await client.GetStringAsync(pair.Value, cancellation.Token)).Trim();
                var match = Regex.Match(body, @"(?<![0-9A-Fa-f:.])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{3,})(?![0-9A-Fa-f:.])");
                var value = match.Success ? match.Groups[1].Value : body.Trim('"', '{', '}', ' ', '\r', '\n').Split(':', ',', '"').LastOrDefault(part => IPAddress.TryParse(part.Trim(), out _))?.Trim();
                var valid = IPAddress.TryParse(value, out _);
                watch.Stop();
                results.Add(new ExitIpObservation(pair.Key, valid ? value : null, valid, watch.ElapsedMilliseconds, valid ? null : "Response did not contain a valid IP."));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                watch.Stop();
                results.Add(new ExitIpObservation(pair.Key, null, false, watch.ElapsedMilliseconds, Redact(ex.Message)));
            }
        }
        return results;
    }

    private static async Task<HttpProbeObservation> ProbeHttpAsync(HttpClient client, string target, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var timeoutCancellation = new CancellationTokenSource(timeout);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellation.Token);
            using var response = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
            watch.Stop();
            return new HttpProbeObservation(target, (int)response.StatusCode, (int)response.StatusCode is >= 200 and < 400, watch.ElapsedMilliseconds, response.Content.Headers.ContentLength, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            watch.Stop();
            return new HttpProbeObservation(target, null, false, watch.ElapsedMilliseconds, null, Redact(ex.Message));
        }
    }

    private static async Task<StageResult> ProbeSocksDomainAsync(int socksPort, TimeSpan timeout)
    {
        const string destination = "www.google.com";
        var watch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            using var control = new TcpClient(AddressFamily.InterNetwork);
            await control.ConnectAsync(IPAddress.Loopback, socksPort, cancellation.Token);
            var stream = control.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellation.Token);
            var greeting = await ReadExactStreamAsync(stream, 2, cancellation.Token);
            if (greeting[0] != 0x05 || greeting[1] != 0x00) throw new IOException("SOCKS5 server rejected no-auth negotiation.");
            var hostBytes = Encoding.ASCII.GetBytes(destination);
            using var request = new MemoryStream();
            request.Write(new byte[] { 0x05, 0x01, 0x00, 0x03, (byte)hostBytes.Length });
            request.Write(hostBytes);
            request.WriteByte(0x01);
            request.WriteByte(0xBB);
            await stream.WriteAsync(request.ToArray(), cancellation.Token);
            var reply = await ReadExactStreamAsync(stream, 4, cancellation.Token);
            if (reply[0] != 0x05 || reply[1] != 0x00) throw new IOException($"SOCKS5 CONNECT returned code {reply[1]}.");
            var boundLength = reply[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => (await ReadExactStreamAsync(stream, 1, cancellation.Token))[0],
                _ => throw new IOException("SOCKS5 CONNECT returned an unsupported address type.")
            };
            await ReadExactStreamAsync(stream, boundLength + 2, cancellation.Token);
            using var ssl = new SslStream(stream, false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = destination,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http11]
            }, cancellation.Token);
            var httpRequest = Encoding.ASCII.GetBytes($"GET /generate_204 HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n");
            await ssl.WriteAsync(httpRequest, cancellation.Token);
            await ssl.FlushAsync(cancellation.Token);
            using var reader = new StreamReader(ssl, Encoding.ASCII, false, 4096, true);
            var statusLine = await reader.ReadLineAsync(cancellation.Token) ?? "";
            watch.Stop();
            var passed = Regex.IsMatch(statusLine, @"^HTTP/\d(?:\.\d)?\s+(?:2\d\d|3\d\d)\b");
            return StageResult.FromStatus(
                "tunnel.dnsViaSocks",
                passed ? "passed" : "failed",
                watch.ElapsedMilliseconds,
                new { socksPort, mode = "native SOCKS5 domain CONNECT (no local destination lookup)", destination, statusLine, tls = ssl.SslProtocol.ToString() },
                passed ? null : "The native SOCKS5 hostname request did not return an HTTP 2xx/3xx status.");
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("tunnel.dnsViaSocks", watch.ElapsedMilliseconds, Redact(ex.Message), new { socksPort, destination });
        }
    }

    private static async Task<byte[]> ReadExactStreamAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        return buffer;
    }

    private static async Task<StageResult> ProbeDownloadAsync(HttpClient client, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        const int requestedBytes = 2 * 1024 * 1024;
        var attempts = new List<TunnelDownloadObservation>();
        var stageWatch = Stopwatch.StartNew();
        for (var ordinal = 1; ordinal <= 3; ordinal++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = $"https://speed.cloudflare.com/__down?bytes={requestedBytes}&nonce={Guid.NewGuid():N}";
            var watch = Stopwatch.StartNew();
            try
            {
                using var timeoutCancellation = new CancellationTokenSource(timeout + TimeSpan.FromSeconds(15));
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellation.Token);
                using var response = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
                response.EnsureSuccessStatusCode();
                await using var stream = await response.Content.ReadAsStreamAsync(cancellation.Token);
                var buffer = new byte[64 * 1024];
                long bytes = 0;
                long? firstByteMs = null;
                while (bytes < requestedBytes)
                {
                    var read = await stream.ReadAsync(buffer, cancellation.Token);
                    if (read == 0) break;
                    firstByteMs ??= watch.ElapsedMilliseconds;
                    bytes += read;
                }
                watch.Stop();
                var payloadTransferMs = firstByteMs.HasValue ? Math.Max(1, watch.ElapsedMilliseconds - firstByteMs.Value) : (long?)null;
                var effectiveKbps = watch.Elapsed.TotalSeconds > 0 ? Math.Round(bytes * 8d / 1000d / watch.Elapsed.TotalSeconds, 1) : (double?)null;
                var payloadKbps = payloadTransferMs.HasValue ? Math.Round(bytes * 8d / payloadTransferMs.Value, 1) : (double?)null;
                attempts.Add(new TunnelDownloadObservation(
                    ordinal,
                    ordinal == 1 ? "cold-origin-request" : "warm/reused-pool-request",
                    target,
                    bytes >= requestedBytes,
                    bytes,
                    firstByteMs,
                    payloadTransferMs,
                    watch.ElapsedMilliseconds,
                    effectiveKbps,
                    payloadKbps,
                    bytes >= requestedBytes ? null : "Response ended before the requested payload size."));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                watch.Stop();
                attempts.Add(new TunnelDownloadObservation(ordinal, ordinal == 1 ? "cold-origin-request" : "warm/reused-pool-request", target, false, 0, null, null, watch.ElapsedMilliseconds, null, null, Redact(ex.Message)));
            }
        }
        stageWatch.Stop();
        var successful = attempts.Where(item => item.Success).ToArray();
        var warmSuccessful = attempts.Where(item => item.Success && item.Ordinal > 1).ToArray();
        static double? Median(IEnumerable<double?> source)
        {
            var values = source.Where(value => value.HasValue).Select(value => value!.Value).OrderBy(value => value).ToArray();
            return values.Length == 0 ? null : values[values.Length / 2];
        }
        var effectiveRates = successful.Select(item => item.EffectiveKilobitsPerSecond).Where(value => value.HasValue && value.Value > 0).Select(value => value!.Value).ToArray();
        return StageResult.FromStatus(
            "tunnel.download",
            successful.Length == attempts.Count ? "passed" : successful.Length > 0 ? "partial" : "failed",
            stageWatch.ElapsedMilliseconds,
            new
            {
                requestedBytesPerAttempt = requestedBytes,
                attempts,
                coldAttempt = attempts.FirstOrDefault(),
                warmAttempts = attempts.Skip(1).ToArray(),
                representativeWarmEffectiveKilobitsPerSecond = Median(warmSuccessful.Select(item => item.EffectiveKilobitsPerSecond)),
                representativeWarmPayloadTransferKilobitsPerSecond = Median(warmSuccessful.Select(item => item.PayloadTransferKilobitsPerSecond)),
                effectiveVariabilityRatio = effectiveRates.Length < 2 ? (double?)null : Math.Round(effectiveRates.Max() / effectiveRates.Min(), 2),
                metricSemantics = new
                {
                    effective = "bytes divided by total request time, including connection establishment and time to first byte",
                    payloadTransfer = "bytes divided by approximate time from first byte to completion",
                    limitation = "Payload-transfer rate is still a bounded single-stream estimate, not calibrated sustained line rate. Interpret it together with tunnel.extended.coldWarm."
                }
            },
            successful.Length == attempts.Count ? null : $"Only {successful.Length} of {attempts.Count} repeated tunnel download attempts completed.");
    }

    private static async Task<StageResult> ProbeStabilityAsync(HttpClient client, TimeSpan timeout, int attempts)
    {
        attempts = Math.Clamp(attempts, 1, 100);
        var observations = new List<HttpProbeObservation>();
        var watch = Stopwatch.StartNew();
        for (var index = 0; index < attempts; index++)
        {
            observations.Add(await ProbeHttpAsync(client, "https://www.google.com/generate_204", timeout));
            if (index + 1 < attempts)
            {
                await Task.Delay(250);
            }
        }
        watch.Stop();
        var successes = observations.Count(item => item.Success);
        return StageResult.FromStatus(
            "tunnel.stability",
            successes == attempts ? "passed" : successes > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                attempts,
                successes,
                failures = attempts - successes,
                connectionLifetimeMs = watch.ElapsedMilliseconds,
                requests = observations
            },
            successes == attempts ? null : $"Only {successes} of {attempts} repeated requests succeeded.");
    }

    private static async Task<StageResult> ProbeSocksUdpAsync(int socksPort, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            var observation = await SocksUdpDnsProbe.RunAsync("127.0.0.1", socksPort, IPAddress.Parse("1.1.1.1"), "one.one.one.one", timeout);
            watch.Stop();
            return StageResult.FromStatus(
                "tunnel.udp",
                observation.Success ? "passed" : "failed",
                watch.ElapsedMilliseconds,
                observation,
                observation.Success ? null : observation.Error);
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("tunnel.udp", watch.ElapsedMilliseconds, Redact(ex.Message));
        }
    }

    private static StageResult BuildCoreLogStage(
        string accessLog,
        string errorLog,
        string stdout,
        string stderr,
        IReadOnlyList<ExpectedFailureWindow>? expectedFailureWindows = null)
    {
        var accessLines = ReadTail(accessLog, 80);
        var errorLines = ReadTail(errorLog, 300);
        expectedFailureWindows ??= [];
        var tags = accessLines
            .Select(line => Regex.Match(line, @"\[(?<in>[^\]\s]+)\s*(?:-\>|\>\>)\s*(?<out>[^\]\s]+)\]"))
            .Where(match => match.Success)
            .Select(match => new { inbound = match.Groups["in"].Value, outbound = match.Groups["out"].Value })
            .Distinct()
            .ToArray();
        var benignLifecycleMarkers = errorLines.Where(IsBenignCoreLifecycleLine).Select(Redact).ToArray();
        var seriousMarkers = errorLines.Where(IsSeriousCoreLogLine).ToArray();
        var expectedInducedMarkers = new List<object>();
        var unexpectedFailureMarkers = new List<string>();
        foreach (var line in seriousMarkers)
        {
            var window = expectedFailureWindows.FirstOrDefault(candidate => CoreLogLineFallsInside(line, candidate));
            if (window is not null)
            {
                expectedInducedMarkers.Add(new
                {
                    line = Redact(line),
                    classification = "expected/induced",
                    window.Reason,
                    window.StartedAt,
                    window.EndedAt
                });
            }
            else
            {
                unexpectedFailureMarkers.Add(Redact(line));
            }
        }
        var fatal = unexpectedFailureMarkers.Count > 0;
        return StageResult.FromStatus(
            "tunnel.logs",
            fatal ? "partial" : "passed",
            0,
            new
            {
                outboundTagsObserved = tags,
                accessTail = accessLines.Select(Redact).ToArray(),
                errorTail = errorLines.Select(Redact).ToArray(),
                expectedFailureWindows,
                expectedInducedMarkers,
                benignLifecycleMarkers,
                unexpectedFailureMarkers,
                classificationSummary = new
                {
                    expectedOrInduced = expectedInducedMarkers.Count,
                    benignLifecycle = benignLifecycleMarkers.Length,
                    unexpected = unexpectedFailureMarkers.Count
                },
                processStdout = Truncate(Redact(stdout), 1000),
                processStderr = Truncate(Redact(stderr), 1000)
            },
            fatal ? "Core logs contain unexpected failure markers; inspect unexpectedFailureMarkers." : null);
    }

    private static IReadOnlyList<Inference> BuildInferences(
        ConnectionProfile profile,
        ProfileReport report,
        TunnelProbeResult runtime,
        IReadOnlyList<ExitIpObservation> directBaseline)
    {
        var inferences = new List<Inference>();
        var endpointIps = report.ObservedEndpointIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var exitIps = runtime.ExitIps.Where(item => item.Valid).Select(item => item.Ip!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var directIps = directBaseline.Where(item => item.Valid).Select(item => item.Ip!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var tunnelPassed = runtime.Stages.Any(stage => stage.Stage == "tunnel.http" && stage.Status == "passed");
        var udp = runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.udp");
        var tls = report.Stages.FirstOrDefault(stage => stage.Stage == "endpoint.tlsFallback");
        var xudp = report.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.xudpCompatibility");
        var negativeControls = report.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.negativeControls");

        inferences.Add(new Inference(
            "profileUsable",
            tunnelPassed ? "yes" : "no",
            tunnelPassed ? "high" : "medium",
            tunnelPassed ? "At least one functional HTTP request succeeded through the authenticated profile." : "No functional HTTP request succeeded; use the failed stage and Xray logs for localization."));
        inferences.Add(new Inference(
            "exitDiffersFromDirect",
            exitIps.Count > 0 && directIps.Count > 0 && !exitIps.Overlaps(directIps) ? "yes" : "unknown",
            exitIps.Count > 0 && directIps.Count > 0 ? "high" : "low",
            "A different exit IP proves egress changed, but does not alone prove the number of server hops."));
        inferences.Add(new Inference(
            "ingressAndEgressDiffer",
            DescribeIngressEgress(endpointIps, exitIps),
            exitIps.Count > 0 && endpointIps.Count > 0 ? "medium" : "low",
            "Different ingress and exit IPs are compatible with relay, NAT, load balancing, or a multi-hop route; server configuration is required to distinguish them."));
        inferences.Add(new Inference(
            "ordinaryTlsFallbackObserved",
            tls?.Status == "passed" ? "yes" : tls?.Status == "failed" ? "no" : "not-tested",
            tls?.Status == "passed" ? "medium" : "low",
            "This is an unauthenticated ordinary TLS observation and is not proof of the exact REALITY target."));
        inferences.Add(new Inference(
            "udpEndToEnd",
            udp?.Status == "passed" ? "yes" : udp?.Status == "failed" ? "no" : "not-tested",
            udp is null ? "low" : "high",
            "The UDP probe uses SOCKS5 UDP ASSOCIATE and a DNS request to a fixed public resolver."));
        inferences.Add(new Inference(
            "xudpEncoding",
            xudp?.Status == "passed" ? "server-compatible-with-xudp" : string.IsNullOrWhiteSpace(profile.PacketEncoding) ? "unknown" : profile.PacketEncoding,
            xudp?.Status == "passed" ? "high" : string.IsNullOrWhiteSpace(profile.PacketEncoding) ? "low" : "medium",
            xudp?.Status == "passed" ? "An explicit packetEncoding=xudp client configuration completed a real UDP response." : "Packet encoding can be declared by the profile or tested with an explicit A/B configuration; ordinary UDP success alone is insufficient."));
        inferences.Add(new Inference(
            "authenticationNegativeControls",
            negativeControls?.Status == "passed" ? "invalid-controls-rejected" : negativeControls?.Status == "partial" ? "unexpected-or-inconclusive" : "not-tested",
            negativeControls?.Status == "passed" ? "high" : "low",
            "One-shot invalid UUID/short-ID/SNI controls help distinguish raw reachability from authenticated end-to-end success without attempting credential discovery."));
        inferences.Add(new Inference(
            "captureMode",
            "explicit-local-proxy",
            "high",
            "The runner does not modify Windows system proxy or install TUN routes; all tunnel probes use explicit HTTP/SOCKS inbounds."));
        inferences.Add(new Inference(
            "dnsInsideTunnel",
            runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.dnsViaSocks")?.Status == "passed" ? "functional" : "not-confirmed",
            "high",
            "SOCKS5 hostname mode proves that a domain destination works without local pre-resolution; identifying the exact resolver requires a controlled authoritative domain."));
        inferences.Add(new Inference(
            "osTunnelScope",
            "not-full-tunnel",
            "high",
            "This diagnostic runtime uses explicit loopback proxies and does not change the OS default route."));
        inferences.Add(new Inference(
            "loadBalancerOrReverseProxy",
            endpointIps.Count > 1 ? "possible-multiple-frontends" : tls?.Status == "passed" && profile.Security == "reality" ? "fallback-or-l4-front-observed" : "unknown",
            "low",
            "DNS multiplicity and certificate forwarding are only external signs; infrastructure configuration is authoritative."));
        var attribution = report.Stages.FirstOrDefault(stage => stage.Stage == "network.attribution")?.Data as List<IpAttribution>;
        var endpointAsns = attribution?.Where(item => endpointIps.Contains(item.Ip)).SelectMany(item => item.OriginAsns).ToHashSet() ?? [];
        var camouflageAsns = attribution?.Where(item => report.ObservedCamouflageIps.Contains(item.Ip, StringComparer.OrdinalIgnoreCase)).SelectMany(item => item.OriginAsns).ToHashSet() ?? [];
        inferences.Add(new Inference(
            "endpointAndCamouflageAsn",
            endpointAsns.Count == 0 || camouflageAsns.Count == 0 ? "unknown" : endpointAsns.Overlaps(camouflageAsns) ? "same-origin-asn-observed" : "different-origin-asn-observed",
            endpointAsns.Count > 0 && camouflageAsns.Count > 0 ? "high" : "low",
            $"Endpoint ASNs: [{string.Join(',', endpointAsns)}]; camouflage-host ASNs: [{string.Join(',', camouflageAsns)}]. Same ASN is a camouflage-quality signal, not proof of why a network permits the connection."));
        inferences.Add(new Inference(
            "outboundTopology",
            DescribeIngressEgress(endpointIps, exitIps) switch
            {
                "yes" => "separate-ingress-egress-observed",
                "no-observed-separation" => "endpoint-egress-observed",
                "mixed-by-address-family-or-route" => "mixed-egress-observed",
                _ => "unknown"
            },
            "medium",
            "NAT and dual-stack addressing can mimic relay topology; the server outbound configuration remains authoritative."));
        inferences.Add(ClassifyFailure(runtime, report));
        inferences.Add(new Inference("secondHop", "unknown", "low", "Requires an authoritative server routing configuration or correlated server logs."));
        inferences.Add(new Inference("realityTarget", profile.Sni ?? "unknown", "low", "The URI SNI and fallback certificate are hints; only server realitySettings.target is authoritative."));
        inferences.Add(new Inference("hwidPolicy", "unknown", "low", "Requires panel state."));
        return inferences;
    }

    private static List<HostnameGroup> BuildHostnameGroups(IReadOnlyList<ProfileReport> profiles)
    {
        var hosts = profiles
            .SelectMany(profile => new[]
            {
                new { Host = profile.Declared.Host, Ips = profile.ObservedEndpointIps },
                new { Host = profile.Declared.Sni, Ips = profile.ObservedCamouflageIps }
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.Host))
            .GroupBy(item => item.Host!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.SelectMany(item => item.Ips).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), StringComparer.OrdinalIgnoreCase);
        var result = new List<HostnameGroup>();
        var keys = hosts.Keys.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
        for (var left = 0; left < keys.Length; left++)
        {
            for (var right = left + 1; right < keys.Length; right++)
            {
                var shared = hosts[keys[left]].Intersect(hosts[keys[right]], StringComparer.OrdinalIgnoreCase).ToArray();
                if (shared.Length > 0)
                {
                    result.Add(new HostnameGroup(keys[left], keys[right], shared));
                }
            }
        }
        return result;
    }

    internal static NetworkEnvironment CaptureNetworkEnvironmentForCommands() => CaptureNetworkEnvironment();

    internal static async Task<NodeDiagnosticsReport> CaptureNodeDiagnosticsForCommandsAsync(NetworkEnvironment environment, TestContext context, TimeSpan timeout)
    {
        var baseline = await ProbeExitIpsAsync(proxy: null, timeout);
        var attribution = new List<IpAttribution>();
        foreach (var ip in baseline.Where(item => item.Valid && item.Ip is not null).Select(item => item.Ip!).Distinct(StringComparer.OrdinalIgnoreCase))
            attribution.Add(await GetIpAttributionAsync(ip, timeout));
        return await NodeDiagnostics.CaptureAsync(environment, baseline, attribution, context, timeout);
    }

    private static NetworkEnvironment CaptureNetworkEnvironment()
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(item => item.OperationalStatus == OperationalStatus.Up)
            .Select(item =>
            {
                var properties = item.GetIPProperties();
                var macBytes = item.GetPhysicalAddress().GetAddressBytes();
                return new NetworkInterfaceInfo
                {
                    Name = item.Name,
                    Description = item.Description,
                    InterfaceType = item.NetworkInterfaceType.ToString(),
                    SpeedMbps = NormalizeInterfaceSpeedMbps(item.Speed),
                    Ipv4Mtu = TryGetIpv4Mtu(properties),
                    Addresses = properties.UnicastAddresses.Select(address => address.Address.ToString()).ToArray(),
                    Gateways = properties.GatewayAddresses.Select(gateway => gateway.Address.ToString()).ToArray(),
                    DnsServers = properties.DnsAddresses.Select(address => address.ToString()).ToArray(),
                    DnsSuffix = string.IsNullOrWhiteSpace(properties.DnsSuffix) ? null : properties.DnsSuffix,
                    DhcpEnabled = TryGetDhcpEnabled(properties),
                    DynamicDnsEnabled = TryGetDynamicDnsEnabled(properties),
                    SupportsMulticast = item.SupportsMulticast,
                    MacOui = macBytes.Length >= 3 ? string.Join(':', macBytes.Take(3).Select(value => value.ToString("X2", CultureInfo.InvariantCulture))) : null,
                    MacAddressHash = macBytes.Length > 0 ? Convert.ToHexString(SHA256.HashData(macBytes)).ToLowerInvariant()[..16] : null,
                    HasDefaultGateway = properties.GatewayAddresses.Any(gateway => !gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.IPv6Any)),
                    LooksLikeTunnel = item.NetworkInterfaceType == NetworkInterfaceType.Tunnel
                        || Regex.IsMatch(item.Name + " " + item.Description, "tun|tap|wintun|wireguard|vpn", RegexOptions.IgnoreCase)
                };
            })
            .ToArray();

        var proxyEnabled = false;
        string? proxyServer = null;
        var autoDetect = false;
        var autoConfigUrlPresent = false;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                proxyEnabled = Convert.ToInt32(key?.GetValue("ProxyEnable") ?? 0, CultureInfo.InvariantCulture) == 1;
                proxyServer = key?.GetValue("ProxyServer") as string;
                autoDetect = Convert.ToInt32(key?.GetValue("AutoDetect") ?? 0, CultureInfo.InvariantCulture) == 1;
                autoConfigUrlPresent = !string.IsNullOrWhiteSpace(key?.GetValue("AutoConfigURL") as string);
            }
            catch
            {
            }
        }

        return new NetworkEnvironment
        {
            CapturedAt = DateTimeOffset.UtcNow,
            Platform = CurrentPlatformName(),
            OperatingSystem = CurrentOperatingSystemName(),
            KernelVersion = Environment.OSVersion.VersionString,
            Architecture = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
            Interfaces = interfaces,
            DnsServers = interfaces.SelectMany(item => item.DnsServers).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            PotentialTunnelInterfaces = interfaces.Where(item => item.LooksLikeTunnel).Select(item => item.Name).ToArray(),
            WindowsSystemProxyEnabled = proxyEnabled,
            WindowsSystemProxyServer = SanitizeProxyServer(proxyServer),
            WindowsAutoDetectEnabled = autoDetect,
            WindowsAutoConfigUrlPresent = autoConfigUrlPresent,
            ProxyEnvironmentVariablesPresent = new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY" }
                .Where(name => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name)))
                .ToArray()
        };
    }

    internal static double? NormalizeInterfaceSpeedMbps(long speedBitsPerSecond)
    {
        if (speedBitsPerSecond <= 0) return null;
        var speedMbps = speedBitsPerSecond / 1_000_000d;
        // Linux reports UINT_MAX Mbps when the driver cannot determine link speed.
        if (speedMbps >= uint.MaxValue) return null;
        return Math.Round(speedMbps, 1);
    }

    private static string CurrentPlatformName()
        => OperatingSystem.IsWindows() ? "windows"
            : OperatingSystem.IsLinux() ? "linux"
            : OperatingSystem.IsMacOS() ? "macos"
            : OperatingSystem.IsAndroid() ? "android"
            : "unknown";

    private static string CurrentOperatingSystemName()
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                const string osRelease = "/etc/os-release";
                if (File.Exists(osRelease))
                {
                    var prettyName = File.ReadLines(osRelease)
                        .FirstOrDefault(line => line.StartsWith("PRETTY_NAME=", StringComparison.Ordinal));
                    if (!string.IsNullOrWhiteSpace(prettyName))
                    {
                        var value = prettyName["PRETTY_NAME=".Length..].Trim();
                        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"') value = value[1..^1];
                        value = value.Replace("\\\"", "\"", StringComparison.Ordinal)
                            .Replace("\\n", " ", StringComparison.Ordinal)
                            .Replace("\\\\", "\\", StringComparison.Ordinal);
                        if (!string.IsNullOrWhiteSpace(value)) return value;
                    }
                }
            }
            catch
            {
            }
        }
        return RuntimeInformation.OSDescription.Trim();
    }

    private static int? TryGetIpv4Mtu(IPInterfaceProperties properties)
    {
        try { return properties.GetIPv4Properties()?.Mtu; } catch { return null; }
    }

    internal static int KeepProgressMonotonic(ref int highestReportedPercent, int requestedPercent)
    {
        requestedPercent = Math.Clamp(requestedPercent, 0, 100);
        highestReportedPercent = Math.Max(Math.Clamp(highestReportedPercent, 0, 100), requestedPercent);
        return highestReportedPercent;
    }

    private static bool? TryGetDhcpEnabled(IPInterfaceProperties properties)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try { return properties.GetIPv4Properties()?.IsDhcpEnabled; } catch { return null; }
    }

    private static bool TryGetDynamicDnsEnabled(IPInterfaceProperties properties)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try { return properties.IsDynamicDnsEnabled; } catch { return false; }
    }

    private static async Task<HashSet<string>> PollProcessRemoteIpsAsync(int processId, CancellationToken cancellationToken)
    {
        var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            return addresses;
        }
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var snapshot = OperatingSystem.IsWindows()
                    ? await RunProcessAsync("netstat.exe", "-ano -p tcp", Environment.CurrentDirectory, TimeSpan.FromSeconds(3))
                    : await RunProcessAsync("ss", "-Hntp", Environment.CurrentDirectory, TimeSpan.FromSeconds(3));
                foreach (var line in snapshot.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = Regex.Split(line.Trim(), @"\s+");
                    string remote;
                    if (OperatingSystem.IsWindows())
                    {
                        if (parts.Length < 5 || !string.Equals(parts[0], "TCP", StringComparison.OrdinalIgnoreCase)
                            || !int.TryParse(parts[^1], out var pid) || pid != processId)
                        {
                            continue;
                        }
                        remote = parts[2];
                    }
                    else
                    {
                        if (parts.Length < 5 || !Regex.IsMatch(line, $@"\bpid={processId}\b")) continue;
                        remote = parts[4];
                    }
                    var addressText = ExtractEndpointAddress(remote);
                    if (IPAddress.TryParse(addressText, out var address) && !IPAddress.IsLoopback(address)
                        && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
                    {
                        addresses.Add(address.ToString());
                    }
                }
            }
            catch
            {
            }
            try
            {
                await Task.Delay(200, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
        return addresses;
    }

    private static bool IsUsableDnsResolver(string value)
    {
        if (!IPAddress.TryParse(value, out var address)) return false;
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;
        return !address.ToString().StartsWith("fec0:0:0:ffff::", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSeriousCoreLogLine(string line)
    {
        if (IsBenignCoreLifecycleLine(line)) return false;
        return line.Contains("[Error]", StringComparison.OrdinalIgnoreCase)
            || Regex.IsMatch(line, "failed to (dial|start|process|find)|authentication failed|invalid user|rejected|connection refused|i/o timeout", RegexOptions.IgnoreCase);
    }

    private static bool IsBenignCoreLifecycleLine(string line)
        => line.Contains("use of closed network connection", StringComparison.OrdinalIgnoreCase)
            || line.Contains("read/write on closed pipe", StringComparison.OrdinalIgnoreCase)
            || line.Contains("failed to read http request > EOF", StringComparison.OrdinalIgnoreCase)
            || line.Contains("connection ends > EOF", StringComparison.OrdinalIgnoreCase)
            || line.Contains("websocket: close 1000", StringComparison.OrdinalIgnoreCase)
            || Regex.IsMatch(line, @"(?:wsasend|send|write) tcp 127\.0\.0\.1:\d+->127\.0\.0\.1:\d+:.*(?:aborted by the software|operation.*aborted|broken pipe|connection reset)", RegexOptions.IgnoreCase)
            || Regex.IsMatch(line, @"(?:websocket|grpc).*(?:deprecated|legacy transport)", RegexOptions.IgnoreCase)
            || Regex.IsMatch(line, @"XTLS.*rejected UDP/443 traffic", RegexOptions.IgnoreCase);

    private static bool CoreLogLineFallsInside(string line, ExpectedFailureWindow window)
    {
        var match = Regex.Match(line, @"^(?<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,7})?)");
        if (!match.Success || !DateTime.TryParseExact(
                match.Groups["timestamp"].Value,
                ["yyyy/MM/dd HH:mm:ss", "yyyy/MM/dd HH:mm:ss.FFFFFFF"],
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var localTime)) return false;
        localTime = DateTime.SpecifyKind(localTime, DateTimeKind.Unspecified);
        var observedAt = new DateTimeOffset(localTime, TimeZoneInfo.Local.GetUtcOffset(localTime)).ToUniversalTime();
        return observedAt >= window.StartedAt.ToUniversalTime() - TimeSpan.FromSeconds(1)
            && observedAt <= window.EndedAt.ToUniversalTime() + TimeSpan.FromSeconds(2);
    }

    private static string DescribeIngressEgress(IReadOnlySet<string> endpointIps, IReadOnlySet<string> exitIps)
    {
        if (endpointIps.Count == 0 || exitIps.Count == 0) return "unknown";
        var matching = exitIps.Count(endpointIps.Contains);
        if (matching == exitIps.Count) return "no-observed-separation";
        if (matching == 0) return "yes";
        return "mixed-by-address-family-or-route";
    }

    private static Inference ClassifyFailure(TunnelProbeResult runtime, ProfileReport report)
    {
        var endpointDns = report.Stages.FirstOrDefault(stage => stage.Stage == "endpoint.dns");
        var endpointTcp = report.Stages.FirstOrDefault(stage => stage.Stage == "endpoint.tcp");
        var validation = runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.coreValidation");
        var start = runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.coreStart");
        var http = runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.http");
        var dns = runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.dnsViaSocks");
        var udp = runtime.Stages.FirstOrDefault(stage => stage.Stage == "tunnel.udp");
        if (endpointDns?.Status == "failed") return new Inference("failureLocalization", "dns-resolution", "medium", "The endpoint could not be resolved.");
        if (endpointTcp?.Status == "failed") return new Inference("failureLocalization", "endpoint-tcp", "medium", "DNS/literal IP was available but no endpoint TCP connection succeeded.");
        if (validation?.Status == "failed") return new Inference("failureLocalization", "local-config-validation", "high", "Xray rejected the generated profile configuration before network use.");
        if (start?.Status == "failed") return new Inference("failureLocalization", "local-core-start", "high", "Xray did not expose the local inbound.");
        if (http?.Status == "failed") return new Inference("failureLocalization", "reality-vless-or-server-path", "medium", "Endpoint TCP worked, but no authenticated functional HTTP request completed. Client and server logs are needed to split REALITY from VLESS authentication.");
        if (dns?.Status == "failed") return new Inference("failureLocalization", "tunnel-domain-resolution", "medium", "The tunnel passed HTTP tests but a SOCKS hostname request failed.");
        if (udp?.Status == "failed") return new Inference("failureLocalization", "udp-path-only", "high", "TCP/HTTPS worked but the SOCKS5 UDP DNS probe failed.");
        return new Inference("failureLocalization", "none-observed", "high", "All required local end-to-end stages succeeded.");
    }

    private static string ExtractEndpointAddress(string endpoint)
    {
        if (endpoint.StartsWith('['))
        {
            var end = endpoint.IndexOf(']');
            return end > 0 ? endpoint[1..end] : endpoint;
        }
        var colon = endpoint.LastIndexOf(':');
        return colon > 0 ? endpoint[..colon] : endpoint;
    }

    private static async Task<bool> WaitForTcpPortAsync(int port, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var client = new TcpClient();
                using var attemptTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, attemptTimeout.Token);
                await client.ConnectAsync(IPAddress.Loopback, port, cancellation.Token);
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                await Task.Delay(100, cancellationToken);
            }
        }
        return false;
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static bool CanBindLoopbackTcpPort(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int GetFreeDualPort()
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            try
            {
                using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
                return port;
            }
            catch
            {
            }
            finally
            {
                listener.Stop();
            }
        }
        throw new InvalidOperationException("Could not allocate a free TCP/UDP port pair.");
    }

    private static int GetFreeUdpPort()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
    }

    private static HttpClient CreateDirectHttpClient(TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = timeout,
            AutomaticDecompression = DecompressionMethods.All
        };
        var client = new HttpClient(handler) { Timeout = timeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("LokiTrafficLab/1.0");
        return client;
    }

    private static HttpClient CreateProxyHttpClient(int port, TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = true,
            Proxy = new WebProxy($"http://127.0.0.1:{port}"),
            ConnectTimeout = timeout,
            AutomaticDecompression = DecompressionMethods.All
        };
        var client = new HttpClient(handler) { Timeout = timeout + TimeSpan.FromSeconds(5) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("LokiTrafficLab/1.0");
        return client;
    }

    private static async Task<ProcessResult> RunProcessAsync(string fileName, string arguments, string workingDirectory, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var watch = Stopwatch.StartNew();
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            }
        };
        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var processTimeout = new CancellationTokenSource(timeout);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, processTimeout.Token);
        try
        {
            await process.WaitForExitAsync(cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            await SafeTaskResultAsync(stdoutTask);
            await SafeTaskResultAsync(stderrTask);
            throw;
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            watch.Stop();
            return new ProcessResult(-1, await SafeTaskResultAsync(stdoutTask), await SafeTaskResultAsync(stderrTask) + " process timeout", watch.ElapsedMilliseconds);
        }
        watch.Stop();
        return new ProcessResult(process.ExitCode, await stdoutTask, await stderrTask, watch.ElapsedMilliseconds);
    }

    private static async Task<string> ReadXrayVersionAsync(string xrayPath, CancellationToken cancellationToken = default)
    {
        var result = await RunProcessAsync(xrayPath, "version", Path.GetDirectoryName(xrayPath) ?? Environment.CurrentDirectory, TimeSpan.FromSeconds(5), cancellationToken);
        return result.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "unknown";
    }

    private static async Task<string> SafeTaskResultAsync(Task<string> task)
    {
        try { return await task; } catch { return ""; }
    }

    private static string[] ReadTail(string path, int maxLines)
    {
        try
        {
            return File.Exists(path) ? File.ReadLines(path).TakeLast(maxLines).ToArray() : [];
        }
        catch
        {
            return [];
        }
    }

    private static StageResult StageFromObservations<T>(string stage, IReadOnlyList<T> data, bool passed, string? failure)
    {
        return StageResult.FromStatus(stage, passed ? "passed" : "failed", 0, data, passed ? null : failure);
    }

    private static bool ExitDiffers(IReadOnlyList<ExitIpObservation> direct, IReadOnlyList<ExitIpObservation> proxy)
    {
        var directIps = direct.Where(item => item.Valid).Select(item => item.Ip!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var proxyIps = proxy.Where(item => item.Valid).Select(item => item.Ip!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return directIps.Count > 0 && proxyIps.Count > 0 && !directIps.Overlaps(proxyIps);
    }

    private static string? ReadString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static Dictionary<string, object?> Compact(Dictionary<string, object?> values)
    {
        return values.Where(pair => pair.Value is not null && (pair.Value is not string || !string.IsNullOrWhiteSpace((string)pair.Value)))
            .ToDictionary(pair => pair.Key, pair => pair.Value);
    }

    private static void AddIfPresent(IDictionary<string, object?> target, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) target[key] = value;
    }

    private static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value ?? "";
        var redacted = Regex.Replace(value, @"(?i)(vless|vmess|trojan|ss)://\S+", "<redacted-uri>");
        redacted = Regex.Replace(redacted, @"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<redacted-uuid>");
        return redacted;
    }

    private static string Truncate(string? value, int limit)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= limit) return value ?? "";
        return value[..limit] + "…";
    }

    private static string? SanitizeProxyServer(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        return Regex.Replace(value, @"(?i)(https?://)?([^:@;\s]+):([^@;\s]+)@", "$1<credentials>@");
    }

    private static async Task WriteCsvAsync(string path, RunReport report)
    {
        static string Csv(string? value) => "\"" + (value ?? "").Replace("\"", "\"\"") + "\"";
        await using var writer = new StreamWriter(path, false, new UTF8Encoding(false), 64 * 1024);
        await writer.WriteLineAsync("profileId,profileName,stage,status,outcome,reasonCode,elapsedMs,error,reason,data");
        async Task AppendRowAsync(string profileId, string name, string stage, string status, object data)
        {
            await writer.WriteLineAsync(string.Join(',', Csv(profileId), Csv(name), Csv(stage), Csv(status), Csv(OutcomeClassifier.Unknown), Csv("NODE_OBSERVATION"), "0", "", "", Csv(JsonSerializer.Serialize(data, new JsonSerializerOptions(JsonSerializerDefaults.Web)))));
        }
        await AppendRowAsync("run", report.TestContext.NodeId, "run.metadata", "observed", new { report.RunId, report.TestType, report.ExtendedTest, report.StartedAt, report.CompletedAt, report.DurationMs });
        if (report.Node is not null)
        {
            await AppendRowAsync("node", Environment.MachineName, "node.identity", "observed", new { report.Node.DetectedAccessType, report.Node.LocalAddresses, report.Node.PublicAddresses, report.Node.Provider, report.Node.Geolocation });
            await AppendRowAsync("node", Environment.MachineName, "node.directPerformance", report.Node.DirectPerformance.Status, report.Node.DirectPerformance);
            await AppendRowAsync("node", Environment.MachineName, "node.nat", report.Node.Nat.Presence, report.Node.Nat);
            await AppendRowAsync("node", Environment.MachineName, "node.gateway", report.Node.Gateway.Status, report.Node.Gateway);
            await AppendRowAsync("node", Environment.MachineName, "node.settings", "observed", report.Node.Settings);
        }
        if (report.OsiMap is not null) await AppendRowAsync("node", Environment.MachineName, "node.osiMap", "observed", report.OsiMap);
        foreach (var profile in report.Profiles)
        {
            foreach (var stage in profile.Stages)
            {
                var compactData = stage.Data is null ? "" : JsonSerializer.Serialize(stage.Data, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                await writer.WriteLineAsync(string.Join(',', Csv(profile.ProfileId), Csv(profile.Name), Csv(stage.Stage), Csv(stage.Status), Csv(stage.Outcome), Csv(stage.ReasonCode), stage.ElapsedMs.ToString(CultureInfo.InvariantCulture), Csv(stage.Error), Csv(stage.Reason), Csv(compactData)));
            }
        }
    }

    private static void PrintSummary(RunReport report, string jsonPath, string csvPath, string osiPath, string zipPath)
    {
        Console.WriteLine();
        Console.WriteLine($"Test type: {report.TestType.ToUpperInvariant()}" + (report.ExtendedTest.Enabled
            ? $" (soak {report.ExtendedTest.SoakDurationSeconds}s, {report.ExtendedTest.ParallelFlows} parallel flows, interruption {report.ExtendedTest.NetworkLossSeconds}s, elevated={report.ExtendedTest.Elevated})"
            : ""));
        Console.WriteLine();
        if (report.Node is not null)
        {
            Console.WriteLine("Test node summary");
            Console.WriteLine($"  Network : {report.Node.DetectedAccessType} ({report.Node.AccessTypeConfidence}) via {string.Join(", ", report.Node.ActiveInterfaceNames)}");
            Console.WriteLine($"  Public IP: {string.Join(", ", report.Node.PublicAddresses)}");
            Console.WriteLine($"  Provider : {report.Node.Provider.DisplayName ?? "unknown"} {string.Join(", ", report.Node.Provider.Asns.Select(value => "AS" + value))}");
            Console.WriteLine($"  Geo hint : {report.Node.Geolocation.Country ?? "unknown"} ({report.Node.Geolocation.Confidence}, radius {report.Node.Geolocation.EstimatedRadiusKm?.ToString(CultureInfo.InvariantCulture) ?? "?"} km)");
            Console.WriteLine($"  Device geo: {report.Node.DeviceLocation.Status} {report.Node.DeviceLocation.Latitude?.ToString(CultureInfo.InvariantCulture) ?? "?"},{report.Node.DeviceLocation.Longitude?.ToString(CultureInfo.InvariantCulture) ?? "?"} accuracy={report.Node.DeviceLocation.AccuracyMeters?.ToString(CultureInfo.InvariantCulture) ?? "?"}m; IP distance={report.Node.GeolocationComparison.DistanceKm?.ToString(CultureInfo.InvariantCulture) ?? "?"}km");
            Console.WriteLine($"  Direct   : latency p50={report.Node.DirectPerformance.LatencyP50Ms?.ToString(CultureInfo.InvariantCulture) ?? "?"} ms, down effective/payload={report.Node.DirectPerformance.Download.EffectiveMegabitsPerSecond?.ToString(CultureInfo.InvariantCulture) ?? "?"}/{report.Node.DirectPerformance.Download.PayloadTransferMegabitsPerSecond?.ToString(CultureInfo.InvariantCulture) ?? "?"} Mbps, up effective={report.Node.DirectPerformance.Upload.EffectiveMegabitsPerSecond?.ToString(CultureInfo.InvariantCulture) ?? "?"} Mbps");
            Console.WriteLine($"  NAT      : {report.Node.Nat.Presence} ({report.Node.Nat.Confidence}), CGNAT hint={report.Node.Nat.CgnatHint}");
            Console.WriteLine($"  Gateway  : {report.Node.Gateway.Address ?? "unknown"} {report.Node.Gateway.ModelLabel ?? "model not advertised"}");
            Console.WriteLine();
        }
        Console.WriteLine("Loki Traffic Lab profile summary");
        Console.WriteLine(new string('-', 104));
        Console.WriteLine($"{"PROFILE",-12} {"STAGE",-30} {"STATUS",-8} {"OUTCOME",-14} {"MS",8}  DETAILS");
        Console.WriteLine(new string('-', 104));
        foreach (var profile in report.Profiles)
        {
            foreach (var stage in profile.Stages)
            {
                var detail = stage.Error ?? SummarizeStage(stage);
                Console.WriteLine($"{profile.ProfileId,-12} {stage.Stage,-30} {stage.Status,-8} {stage.Outcome,-14} {stage.ElapsedMs,8}  {Truncate(stage.ReasonCode + ": " + detail, 54)}");
            }
            foreach (var inference in profile.Inferences.Where(item => item.Key is "profileUsable" or "ingressAndEgressDiffer" or "udpEndToEnd" or "secondHop"))
            {
                Console.WriteLine($"{profile.ProfileId,-12} {"inference." + inference.Key,-30} {inference.Value,-8} {"",-14} {"",8}  confidence={inference.Confidence}");
            }
            Console.WriteLine($"{profile.ProfileId,-12} {"profile.outcome",-30} {profile.Outcome?.Outcome ?? OutcomeClassifier.Unknown,-8} {profile.Outcome?.ReasonCode ?? "RUN_INCONCLUSIVE",-14} {"",8}  {Truncate(profile.Outcome?.Reason ?? "No causal classification.", 54)}");
        }
        Console.WriteLine(new string('-', 104));
        Console.WriteLine($"Run outcome: {report.Outcome?.Outcome ?? OutcomeClassifier.Unknown} / {report.Outcome?.ReasonCode ?? "RUN_INCONCLUSIVE"} - {report.Outcome?.Reason}");
        Console.WriteLine("JSON: " + Path.GetFullPath(jsonPath));
        Console.WriteLine("CSV : " + Path.GetFullPath(csvPath));
        Console.WriteLine("OSI : " + Path.GetFullPath(osiPath));
        Console.WriteLine("ZIP : " + Path.GetFullPath(zipPath));
    }

    private static string SummarizeStage(StageResult stage)
    {
        if (stage.Data is IReadOnlyList<ExitIpObservation> exits)
        {
            return string.Join(", ", exits.Where(item => item.Valid).Select(item => item.Ip));
        }
        if (stage.Data is null) return stage.Status;
        try
        {
            var data = JsonSerializer.SerializeToElement(stage.Data, JsonOptions);
            return stage.Stage switch
            {
                "profile.parse" => $"{ReadJson(data, "security")}/{ReadJson(data, "network")} {ReadJson(data, "host")}:{ReadJson(data, "port")}",
                "endpoint.dns" or "camouflage.dns" => string.Join(',', data.GetProperty("uniqueAddresses").EnumerateArray().Select(item => item.GetString())),
                "endpoint.dnsConsistency" or "camouflage.dnsConsistency" => $"rounds={ReadJson(data, "roundCount")} divergence={ReadJson(data, "resolverAnswerDivergenceObserved")} rotation={ReadJson(data, "rotationObserved")}",
                "endpoint.tcp" => $"{data.EnumerateArray().Count(item => item.GetProperty("connected").GetBoolean())}/{data.GetArrayLength()} connected",
                "endpoint.tcpSeries" => $"{ReadJson(data, "successes")}/{ReadJson(data, "attempts")} min/p50/p95={ReadJson(data, "minMs")}/{ReadJson(data, "p50Ms")}/{ReadJson(data, "p95Ms")}ms",
                "endpoint.pathMtu" => $"largest ICMP payload={ReadJson(data, "largestSuccessfulIcmpPayloadBytes")} estimated MTU={ReadJson(data, "estimatedIpMtu")}",
                "network.attribution" => string.Join("; ", data.EnumerateArray().Take(3).Select(item => $"{ReadJson(item, "ip")}=AS{ReadFirstAsn(item)} {ReadJson(item, "asnHolder")}")),
                "network.geoConsensus" or "camouflage.geoConsensus" => $"{ReadJson(data, "subject")}={ReadJson(data, "country")} confidence={ReadJson(data, "confidence")} radius={ReadJson(data, "estimatedRadiusKm")}km",
                "endpoint.traceroute" => $"{data.GetProperty("hops").GetArrayLength()} hops captured",
                "endpoint.tracerouteAttribution" => $"AS path={string.Join(',', data.GetProperty("observedAsPath").EnumerateArray().Select(item => item.ToString()))}",
                "endpoint.tlsFallback" => $"{ReadJson(data, "protocol")} ALPN={ReadJson(data, "alpn")} cert-covers-SNI={ReadJson(data, "sniCoveredByCertificate")}",
                "endpoint.tlsMatrix" => $"cert-match={ReadJson(data, "endpointAndDirectTargetCertificateMatch")} spki-match={ReadJson(data, "endpointAndDirectTargetSpkiMatch")}",
                "profile.packetEncoding" => $"declared={ReadJson(data, "declared")}",
                "tunnel.coreValidation" => $"xray exit={ReadJson(data, "exitCode")}",
                "tunnel.coreStart" => $"HTTP={ReadJson(data, "httpPort")} SOCKS={ReadJson(data, "socksPort")}",
                "client.captureScope" => $"mode={ReadJson(data, "mode")} route-changed={ReadJson(data, "routeChangedWhileCoreRunning")}",
                "tunnel.exitIp" => $"proxy={string.Join(',', data.GetProperty("throughTunnel").EnumerateArray().Where(item => item.GetProperty("valid").GetBoolean()).Select(item => ReadJson(item, "ip")).Distinct())}",
                "tunnel.addressFamilies" => $"overlap={data.GetProperty("directTunnelOverlap").GetArrayLength()} possible-leak={ReadJson(data, "possibleLeak")}",
                "tunnel.http" => $"{data.EnumerateArray().Count(item => item.GetProperty("success").GetBoolean())}/{data.GetArrayLength()} targets",
                "tunnel.authenticatedEndToEnd" => $"{ReadJson(data, "security")}/{ReadJson(data, "protocol")} -> HTTP {ReadJson(data, "firstSuccessfulStatus")}",
                "tunnel.dnsViaSocks" => ReadJson(data, "statusLine"),
                "tunnel.download" => SummarizeDownload(data),
                "tunnel.httpProtocols" => $"{data.GetProperty("observations").EnumerateArray().Count(item => item.GetProperty("success").GetBoolean())}/{data.GetProperty("observations").GetArrayLength()} variants",
                "tunnel.payloadMatrix" => $"largest={ReadJson(data, "largestSuccessfulBytes")} bytes",
                "tunnel.upload" => $"{ReadJson(data, "bytes")} bytes @ {ReadJson(data, "kilobitsPerSecond")} kbps",
                "tunnel.controlledCanary" => $"source={ReadJson(data, "observedSourceIp")} correlation={ReadJson(data, "correlationId")}",
                "tunnel.stability" => $"{ReadJson(data, "successes")}/{ReadJson(data, "attempts")} requests",
                "tunnel.extended.coldWarm" => $"cold/warm samples={ReadJson(data, "samplesPerMode")}",
                "tunnel.extended.parallelTcp" or "tunnel.extended.parallelUdp" => $"{ReadJson(data, "successfulFlows")}/{ReadJson(data, "requestedFlows")} flows",
                "tunnel.extended.dnsFailureRecovery" => $"failure={ReadJson(data, "failureObserved")} recovered={ReadJson(data, "recovered")}",
                "tunnel.extended.soak" => $"loss={ReadJson(data, "lossPercent")}% attempts={ReadJson(data, "attempts")}",
                "tunnel.extended.reconnect" or "tunnel.extended.networkInterruption" => $"recovered={ReadJson(data, "recovered")}",
                "tunnel.udp" => $"DNS rcode={ReadJson(data, "responseCode")} answers={ReadJson(data, "answerCount")}",
                "tunnel.stun" => $"UDP mapped={ReadJson(data, "mappedAddress")}:{ReadJson(data, "mappedPort")}",
                "tunnel.quicHandshake" => $"QUIC ALPN={ReadJson(data, "negotiatedAlpn")} destination={ReadJson(data, "fixedDestination")}",
                "tunnel.negativeControls" => $"expected-rejected={ReadJson(data, "expectedRejected")} unexpected={data.GetProperty("unexpectedSuccesses").GetArrayLength()}",
                "tunnel.xudpCompatibility" => $"server-compatible={ReadJson(data, "serverCompatible")}",
                "analysis.infrastructureSignals" => $"LB={ReadJson(data, "loadBalancerLikelihood")} fronting={ReadJson(data, "tlsFrontingOrFallbackLikelihood")}",
                "tunnel.logs" => $"{data.GetProperty("outboundTagsObserved").GetArrayLength()} inbound/outbound paths",
                _ => stage.Status == "passed" ? "completed" : stage.Status
            };
        }
        catch
        {
            return stage.Status == "passed" ? "completed" : stage.Status;
        }
    }

    private static string ReadJson(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value)) return "";
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
    }

    private static string ReadFirstAsn(JsonElement item)
    {
        return item.TryGetProperty("originAsns", out var asns) && asns.ValueKind == JsonValueKind.Array && asns.GetArrayLength() > 0
            ? asns[0].ToString()
            : "?";
    }

    private static string SummarizeDownload(JsonElement data)
    {
        if (!data.TryGetProperty("attempts", out var attempts) || attempts.GetArrayLength() == 0) return "no download result";
        var successful = attempts.EnumerateArray().FirstOrDefault(item => item.TryGetProperty("success", out var success) && success.GetBoolean());
        return successful.ValueKind == JsonValueKind.Undefined
            ? "all download targets failed"
            : $"warm effective={ReadJson(data, "representativeWarmEffectiveKilobitsPerSecond")} kbps payload={ReadJson(data, "representativeWarmPayloadTransferKilobitsPerSecond")} kbps";
    }

    private static int RunSelfTests()
    {
        var failures = new List<string>();
        var checks = 0;
        void Assert(bool condition, string message)
        {
            checks++;
            if (!condition) failures.Add(message);
        }

        var sample = "vless://11111111-1111-1111-1111-111111111111@example.com:443?encryption=none&security=reality&type=tcp&sni=www.example.com&fp=chrome&pbk=test-key&sid=abcd#Sample";
        var parsed = ConnectionProfile.Parse(sample);
        Assert(parsed.Host == "example.com", "VLESS host parsing failed.");
        Assert(parsed.Port == 443, "VLESS port parsing failed.");
        Assert(parsed.Security == "reality", "VLESS security parsing failed.");
        Assert(parsed.Sni == "www.example.com", "VLESS SNI parsing failed.");
        var declaredJson = JsonSerializer.Serialize(parsed.ToDeclaredProfile(), JsonOptions);
        Assert(!declaredJson.Contains("11111111", StringComparison.Ordinal), "Declared profile leaks UUID.");
        Assert(!declaredJson.Contains("test-key", StringComparison.Ordinal), "Declared profile leaks REALITY public key/password.");
        var query = DnsWire.BuildQuery("example.com", 1, out _);
        Assert(query.Length > 20, "DNS query construction failed.");
        Assert(Redact(sample) == "<redacted-uri>", "URI redaction failed.");
        var fingerprint = ExtendedDiagnostics.ComputeProfileFingerprint(parsed.ToDeclaredProfile());
        Assert(fingerprint.Length == 16, "Sanitized profile fingerprint has the wrong length.");
        Assert(fingerprint == "dc782c09bba97c90", "Canonical cross-platform profile fingerprint v2 changed unexpectedly.");
        var sharedFingerprintVector = ConnectionProfile.Parse("vless://11111111-2222-4333-8444-555555555555@192.0.2.10:8021?encryption=none&security=reality&type=tcp&sni=example.com&fp=chrome&pbk=test&sid=abcd#secure%20sh");
        Assert(ExtendedDiagnostics.ComputeProfileFingerprint(sharedFingerprintVector.ToDeclaredProfile()) == "f1568b5341baaddf", "Desktop fingerprint does not match the shared Android v2 test vector.");
        var anotherCredential = ConnectionProfile.Parse(sample.Replace("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", StringComparison.Ordinal));
        Assert(fingerprint == ExtendedDiagnostics.ComputeProfileFingerprint(anotherCredential.ToDeclaredProfile()), "Profile fingerprint must not depend on UUID.");
        var pathFailureProfile = new ProfileReport { ProfileId = "profile-path", Name = "path", Declared = parsed.ToDeclaredProfile(), Stages = [StageResult.Passed("profile.parse", 0), StageResult.Passed("endpoint.dns", 1), StageResult.Failed("endpoint.tcp", 1, "timeout")] };
        Assert(OutcomeClassifier.ClassifyProfile(pathFailureProfile, true).ReasonCode == "PROXY_PATH_FAIL", "Endpoint TCP failure outcome classification is incorrect.");
        var authFailureProfile = new ProfileReport { ProfileId = "profile-auth", Name = "auth", Declared = parsed.ToDeclaredProfile(), Stages = [StageResult.Passed("profile.parse", 0), StageResult.Passed("endpoint.dns", 1), StageResult.Passed("endpoint.tcp", 1), StageResult.Failed("tunnel.authenticatedEndToEnd", 1, "auth failed")] };
        Assert(OutcomeClassifier.ClassifyProfile(authFailureProfile, true).ReasonCode == "PROTOCOL_AUTH_FAIL", "Authenticated protocol failure outcome classification is incorrect.");
        Assert(OutcomeClassifier.ClassifyProfile(authFailureProfile, false).Outcome == OutcomeClassifier.UnderlayFail, "Direct-control failure must take precedence over proxy classification.");
        var xudp = ConnectionProfile.Parse(sample.Replace("#Sample", "&packetEncoding=xudp#Sample", StringComparison.Ordinal));
        Assert(xudp.PacketEncoding == "xudp", "packetEncoding parsing failed.");
        var dnsRound = new DnsProbeResult { Host = "example.com", Observations = { new DnsObservation("test", "A", "192.0.2.1", 60, 1, "success", null) } };
        Assert(ExtendedDiagnostics.BuildDnsConsistencyStage("test.dns", [dnsRound]).Status == "passed", "DNS consistency stage construction failed.");
        Assert(ExtendedDiagnostics.BuildGeoConsensusStage("test.geo", "endpoint", []).Status == "skipped", "Geo-consensus empty-evidence handling failed.");
        var linuxRoutes = ExtendedDiagnostics.ParseDefaultRoutes(
            "unicast default via 216.73.158.126 dev enp3s0 proto static metric 100\n" +
            "unicast 216.73.158.0/24 dev enp3s0 proto kernel scope link\n" +
            "unicast default via fe80::1 dev enp3s0 proto ra metric 100",
            windows: false);
        Assert(linuxRoutes.Count == 2 && linuxRoutes.All(route => route.Contains("default", StringComparison.OrdinalIgnoreCase)),
            "Linux detailed default-route parsing failed.");
        Assert(NormalizeInterfaceSpeedMbps((long)uint.MaxValue * 1_000_000L) is null,
            "Unknown Linux interface-speed sentinel was not normalized to null.");
        Assert(NormalizeInterfaceSpeedMbps(10_000_000_000L) == 10_000,
            "Known interface speed normalization failed.");
        Assert(ExtendedDiagnostics.IsRawSocketPermissionError("Run program under privileged user account or grant cap_net_raw capability using setcap(8)."),
            "Linux raw-socket privilege failure was not recognized.");
        Assert(!ExtendedDiagnostics.IsRawSocketPermissionError("Request timed out."),
            "An ICMP timeout was incorrectly classified as a privilege failure.");
        var sanCertificate = new CertificateInfo
        {
            Subject = "CN=example",
            Issuer = "CN=example",
            ThumbprintSha256 = "self-test",
            SubjectAlternativeNames = ["DNS:*.yandex.com", "DNS Name=example.org"]
        };
        Assert(sanCertificate.CoversHost("market.yandex.com"), "Linux DNS: wildcard SAN matching failed.");
        Assert(sanCertificate.CoversHost("example.org"), "Windows DNS Name= SAN matching failed.");
        Assert(!sanCertificate.CoversHost("deep.market.yandex.com"), "Wildcard SAN incorrectly matched multiple labels.");
        var context = new PortableTestPlan { NodeId = "node-a", NetworkLabel = "ru-ethernet", Country = "RU" }.ToContext();
        Assert(context.NodeId == "node-a" && context.Country == "RU", "Portable test-plan context mapping failed.");
        var fileInput = ConnectionFileLoader.ParseLines(["# comment", "", sample, "; disabled", anotherCredential.Name.Replace("Sample", sample, StringComparison.Ordinal)]);
        Assert(fileInput.Entries.Count == 2, "Connection-file comments or ordering parsing failed.");
        Assert(fileInput.Entries[0].LineNumber == 3 && fileInput.Entries[1].LineNumber == 5, "Connection-file source line tracking failed.");
        var exportTestRoot = Path.Combine(Path.GetTempPath(), "traffic-lab-export-selftest-" + Guid.NewGuid().ToString("N"));
        try
        {
            var sourceDirectory = Path.Combine(exportTestRoot, "source");
            var destinationDirectory = Path.Combine(exportTestRoot, "downloads");
            Directory.CreateDirectory(sourceDirectory);
            var sourceArchive = Path.Combine(sourceDirectory, "traffic-lab-results-test.zip");
            var payload = Enumerable.Range(0, 256 * 1024).Select(index => (byte)(index % 251)).ToArray();
            File.WriteAllBytes(sourceArchive, payload);
            var firstExport = ArchiveExporter.CopyToDirectoryAsync(sourceArchive, destinationDirectory).GetAwaiter().GetResult();
            var secondExport = ArchiveExporter.CopyToDirectoryAsync(sourceArchive, destinationDirectory).GetAwaiter().GetResult();
            Assert(Path.GetFileName(firstExport) == "traffic-lab-results-test.zip", "First archive export name is incorrect.");
            Assert(Path.GetFileName(secondExport) == "traffic-lab-results-test (1).zip", "Archive export did not preserve an existing file.");
            Assert(File.ReadAllBytes(firstExport).SequenceEqual(payload) && File.ReadAllBytes(secondExport).SequenceEqual(payload), "Archive export changed file content.");
            Assert(!Directory.EnumerateFiles(destinationDirectory, ".traffic-lab-export-*.tmp").Any(), "Archive export left a temporary file behind.");
        }
        catch (Exception ex)
        {
            Assert(false, "Archive export self-test failed: " + ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(exportTestRoot)) Directory.Delete(exportTestRoot, recursive: true); } catch { }
        }

        var readmeReport = new RunReport
        {
            RunId = "self-test-run",
            GeneratedAt = DateTimeOffset.UtcNow,
            StartedAt = DateTimeOffset.UtcNow,
            CompletedAt = DateTimeOffset.UtcNow,
            DurationMs = 1,
            TestType = "extended",
            ExtendedTest = new ExtendedTestMetadata { Enabled = true, Elevated = false, SoakDurationSeconds = 300, ParallelFlows = 20, NetworkLossSeconds = 5 },
            NetworkLabel = "self-test",
            TestContext = new TestContext { NodeId = "self-test-pc" },
            Tool = new ToolInfo { Name = "Loki Traffic Lab Profile Runner", Version = "3.3.0", XrayPath = "xray.exe", XrayVersion = "self-test" },
            Input = new InputSummary { LoadedConnections = 1, ScheduledConnections = 1 },
            Environment = new NetworkEnvironment()
        };
        var readmeProfile = new ProfileReport { ProfileId = "profile-01", SourceOrdinal = 1, Name = "self-test", Declared = new DeclaredProfile() };
        var resultReadme = ResultPackageBuilder.BuildReadme(readmeReport, readmeProfile);
        var expectedPlatform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : "unknown";
        Assert(resultReadme.Contains($"Platform: {expectedPlatform}", StringComparison.Ordinal), "Result README platform metadata is missing.");
        Assert(resultReadme.Contains($"Operating system: {readmeReport.Environment.OperatingSystem}", StringComparison.Ordinal), "Result README OS metadata is missing.");
        Assert(resultReadme.Contains("Test execution node: Windows PC, Loki Traffic Lab Portable tester", StringComparison.Ordinal) == OperatingSystem.IsWindows(),
            "Result README portable-PC execution marker is incorrect.");
        Assert(resultReadme.Contains("Test execution node: Linux PC, Loki Traffic Lab command-line tester", StringComparison.Ordinal) == OperatingSystem.IsLinux(),
            "Result README Linux execution marker is incorrect.");
        var progressHighWatermark = 92;
        Assert(KeepProgressMonotonic(ref progressHighWatermark, 87) == 92 && progressHighWatermark == 92,
            "Progress percentage regressed after an extended stage.");
        Assert(resultReadme.Contains("Test type: EXTENDED", StringComparison.Ordinal), "Result README test-type metadata is missing.");
        Assert(resultReadme.Contains("soak=300s, parallel flows=20", StringComparison.Ordinal), "Result README extended settings are missing.");

        var extendedOptions = RunnerOptions.Parse(["--test-type", "extended", "--soak-seconds", "300", "--parallel-flows", "100", "--network-loss-seconds", "5"]);
        Assert(extendedOptions.IsExtendedTest && extendedOptions.ParallelFlows == 100 && extendedOptions.SoakDurationSeconds == 300,
            "Extended runner options were not parsed correctly.");
        var soakStage = BuildSoakStage([
            new SoakObservation(1, DateTimeOffset.UtcNow, true, 10, 204, null),
            new SoakObservation(2, DateTimeOffset.UtcNow, true, 20, 204, null),
            new SoakObservation(3, DateTimeOffset.UtcNow, false, 100, null, "timeout"),
            new SoakObservation(4, DateTimeOffset.UtcNow, true, 30, 204, null)
        ], 4000, TimeSpan.FromSeconds(4));
        var soakData = JsonSerializer.SerializeToElement(soakStage.Data, JsonOptions);
        Assert(soakStage.Status == "partial" && soakData.GetProperty("lossPercent").GetDouble() == 25,
            "Soak loss aggregation is incorrect.");
        var soakCancellationObserved = false;
        var soakCancellationWatch = Stopwatch.StartNew();
        try
        {
            using var selfTestHttp = new HttpClient(new SelfTestHttpHandler());
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            ProbeLongSoakAsync(selfTestHttp, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(1), null, cancellation.Token, TimeSpan.FromMilliseconds(20)).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            soakCancellationObserved = true;
        }
        soakCancellationWatch.Stop();
        Assert(soakCancellationObserved, "STOP cancellation was not observed during the extended soak.");
        Assert(soakCancellationWatch.Elapsed < TimeSpan.FromSeconds(2), "Extended soak did not stop promptly.");

        var logClassifierRoot = Path.Combine(Path.GetTempPath(), "traffic-lab-log-selftest-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(logClassifierRoot);
            var expectedAt = DateTimeOffset.Now;
            var expectedWindow = new ExpectedFailureWindow(expectedAt.ToUniversalTime() - TimeSpan.FromSeconds(1), expectedAt.ToUniversalTime() + TimeSpan.FromSeconds(1), "controlled_network_interruption");
            var inducedLine = expectedAt.ToString("yyyy/MM/dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " [Info] app/proxyman/outbound: failed to process outbound traffic > failed to find an available destination > connectex: forbidden by its access permissions";
            var benignLine = expectedAt.ToString("yyyy/MM/dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " [Info] transport/internet/udp: failed to handle UDP input > io: read/write on closed pipe";
            var errorPath = Path.Combine(logClassifierRoot, "error.log");
            var normalWebSocketClose = expectedAt.ToString("yyyy/MM/dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " [Error] websocket: close 1000 (normal)";
            var deprecatedTransport = expectedAt.ToString("yyyy/MM/dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " [Warning] WebSocket transport is deprecated";
            var quicPolicy = expectedAt.ToString("yyyy/MM/dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " [Error] XTLS rejected UDP/443 traffic";
            File.WriteAllLines(errorPath, [inducedLine, benignLine, normalWebSocketClose, deprecatedTransport, quicPolicy]);
            var classifiedLogs = BuildCoreLogStage(Path.Combine(logClassifierRoot, "access.log"), errorPath, "", "", [expectedWindow]);
            var classifiedData = JsonSerializer.SerializeToElement(classifiedLogs.Data, JsonOptions);
            Assert(classifiedLogs.Status == "passed", "An induced firewall failure incorrectly downgraded tunnel.logs.");
            Assert(classifiedData.GetProperty("classificationSummary").GetProperty("expectedOrInduced").GetInt32() == 1
                && classifiedData.GetProperty("classificationSummary").GetProperty("benignLifecycle").GetInt32() == 4
                && classifiedData.GetProperty("classificationSummary").GetProperty("unexpected").GetInt32() == 0,
                "Core-log expected/benign/unexpected classification is incorrect.");
            var unexpectedLine = expectedAt.AddMinutes(1).ToString("yyyy/MM/dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture) + " [Error] failed to dial: connection refused";
            File.AppendAllLines(errorPath, [unexpectedLine]);
            Assert(BuildCoreLogStage(Path.Combine(logClassifierRoot, "access.log"), errorPath, "", "", [expectedWindow]).Status == "partial",
                "An unexpected core failure did not downgrade tunnel.logs.");
        }
        catch (Exception ex)
        {
            Assert(false, "Core-log classifier self-test failed: " + ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(logClassifierRoot)) Directory.Delete(logClassifierRoot, recursive: true); } catch { }
        }

        var throughput = ThroughputSample.From("download", 2 * 1024 * 1024, 2 * 1024 * 1024, TimeSpan.FromMilliseconds(1200), 1000, true, null);
        Assert(throughput.PayloadTransferMs == 200 && throughput.PayloadTransferMegabitsPerSecond > throughput.EffectiveMegabitsPerSecond,
            "Throughput effective/payload-transfer separation is incorrect.");

        var packageSelfTestRoot = Path.Combine(Path.GetTempPath(), "traffic-lab-package-selftest-" + Guid.NewGuid().ToString("N"));
        try
        {
            readmeProfile.Stages.Add(StageResult.Passed("tunnel.extended.soak", 1, new { attempts = 1 }));
            readmeProfile.Stages.Add(StageResult.Passed("tunnel.logs", 0, new { classificationSummary = new { expectedOrInduced = 1, benignLifecycle = 1, unexpected = 0 } }));
            readmeReport.Profiles.Add(readmeProfile);
            var package = ResultPackageBuilder.CreateAsync(readmeReport, packageSelfTestRoot, "selftest").GetAwaiter().GetResult();
            using var archive = ZipFile.OpenRead(package.ZipPath);
            Assert(package.FilesPerProfile == 5 && archive.GetEntry("extended-test.json") is not null,
                "Extended result package did not contain the fifth extended-test.json file.");
            using var connectionReader = new StreamReader(archive.GetEntry("connection.json")!.Open(), Encoding.UTF8);
            using var extendedReader = new StreamReader(archive.GetEntry("extended-test.json")!.Open(), Encoding.UTF8);
            var connectionText = connectionReader.ReadToEnd();
            var extendedText = extendedReader.ReadToEnd();
            Assert(!connectionText.Contains("tunnel.extended.soak", StringComparison.Ordinal) && extendedText.Contains("tunnel.extended.soak", StringComparison.Ordinal),
                "Extended stages were not separated from connection.json.");
        }
        catch (Exception ex)
        {
            Assert(false, "Extended package self-test failed: " + ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(packageSelfTestRoot)) Directory.Delete(packageSelfTestRoot, recursive: true); } catch { }
        }

        var cancellationObserved = false;
        var cancellationWatch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(350));
            var sleeper = OperatingSystem.IsWindows()
                ? RunProcessAsync("cmd.exe", "/d /c \"ping -n 30 127.0.0.1 >nul\"", Environment.CurrentDirectory, TimeSpan.FromSeconds(30), cancellation.Token)
                : RunProcessAsync("/bin/sh", "-c \"sleep 30\"", Environment.CurrentDirectory, TimeSpan.FromSeconds(30), cancellation.Token);
            sleeper.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            cancellationObserved = true;
        }
        cancellationWatch.Stop();
        Assert(cancellationObserved, "Forced process cancellation was not observed.");
        Assert(cancellationWatch.Elapsed < TimeSpan.FromSeconds(5), "Forced process cancellation took too long.");

        var stoppedRunRoot = Path.Combine(Path.GetTempPath(), "traffic-lab-stop-selftest-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(stoppedRunRoot);
            var stoppedConnections = Path.Combine(stoppedRunRoot, "connections.txt");
            var stoppedArtifacts = Path.Combine(stoppedRunRoot, "artifacts");
            File.WriteAllText(stoppedConnections, sample);
            var harmlessExecutable = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe")
                : "/bin/true";
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            var stoppedRunWatch = Stopwatch.StartNew();
            var stoppedExit = RunCliAsync([
                "run", "--connections", stoppedConnections, "--outdir", stoppedArtifacts,
                "--xray", harmlessExecutable, "--timeout", "5"
            ], cancellationToken: cancellation.Token).GetAwaiter().GetResult();
            stoppedRunWatch.Stop();
            Assert(stoppedExit == 130, "Canceled complete run did not return the stop exit code 130.");
            Assert(stoppedRunWatch.Elapsed < TimeSpan.FromSeconds(5), "Canceled complete run did not stop promptly.");
            Assert(!Directory.Exists(stoppedArtifacts) || !Directory.EnumerateFiles(stoppedArtifacts, "*", SearchOption.AllDirectories).Any(),
                "Canceled complete run retained partial result files.");
        }
        catch (Exception ex)
        {
            Assert(false, "Complete-run stop self-test failed: " + ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(stoppedRunRoot)) Directory.Delete(stoppedRunRoot, recursive: true); } catch { }
        }
#if WINDOWS
        Assert(ProxyConflictDetector.Scan() is not null, "Proxy/VPN preflight scan failed.");
#else
        Assert(RunnerOptions.Parse(["--local-port", "18080"]).LocalPort == 18080, "Linux local test-port parsing failed.");
#endif

        if (failures.Count == 0)
        {
            Console.WriteLine($"TrafficLab.ProfileRunner self-tests: PASS ({checks} checks)");
            return 0;
        }
        Console.Error.WriteLine("TrafficLab.ProfileRunner self-tests: FAIL");
        foreach (var failure in failures) Console.Error.WriteLine("- " + failure);
        return 1;
    }
}

internal sealed class RunnerOptions
{
    public bool ReadStdin { get; init; }
    public required string ConnectionFilePath { get; init; }
    public required string XrayPath { get; set; }
    public required string OutputDirectory { get; set; }
    public string? PlanPath { get; init; }
    public string? HistoryPath { get; init; }
    public int TimeoutSeconds { get; set; } = 15;
    public bool SkipTraceroute { get; init; }
    public int DnsAttempts { get; set; } = 1;
    public int TcpAttempts { get; set; } = 3;
    public int StabilityAttempts { get; set; } = 5;
    public bool EnableExtendedTests { get; set; } = true;
    public bool EnableNegativeControls { get; set; }
    public bool EnableXudpCompatibility { get; set; }
    public string? CanaryUrlTemplate { get; set; }
    public string TestType { get; set; } = "normal";
    public int SoakDurationSeconds { get; set; } = 300;
    public int ParallelFlows { get; set; } = 20;
    public int NetworkLossSeconds { get; set; } = 5;
    public IReadOnlyList<string> AllowedHosts { get; set; } = [];
    public int MaxProfiles { get; set; } = 25;
    public int? LocalPort { get; init; }
    public string? ProgressFilePath { get; init; }
    [JsonIgnore] public TimeSpan Timeout => TimeSpan.FromSeconds(Math.Clamp(TimeoutSeconds, 3, 120));
    [JsonIgnore] public bool IsExtendedTest => TestType.Equals("extended", StringComparison.OrdinalIgnoreCase);

    public static RunnerOptions Parse(string[] args)
    {
        string? Read(string name)
        {
            var index = Array.FindIndex(args, value => value.Equals(name, StringComparison.OrdinalIgnoreCase));
            return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
        }
        var timeout = int.TryParse(Read("--timeout"), out var parsedTimeout) ? parsedTimeout : 15;
        var localPortText = Read("--local-port");
        int? localPort = null;
        if (!string.IsNullOrWhiteSpace(localPortText))
        {
            if (!int.TryParse(localPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedPort)
                || parsedPort is < 1024 or > 65535)
                throw new ArgumentException("--local-port must be an integer from 1024 through 65535.");
            localPort = parsedPort;
        }
        var executableDirectory = AppContext.BaseDirectory;
        var xrayFileName = OperatingSystem.IsWindows() ? "xray.exe" : "xray";
        var adjacentXray = Path.Combine(executableDirectory, xrayFileName);
        var xray = Read("--xray") ?? (File.Exists(adjacentXray) ? adjacentXray : xrayFileName);
        var connectionFile = Read("--connections") ?? Path.Combine(executableDirectory, "connections.txt");
        var requestedTestType = Read("--test-type")?.Trim().ToLowerInvariant();
        if (requestedTestType is not null && requestedTestType is not ("normal" or "extended"))
            throw new ArgumentException("--test-type must be normal or extended.");
        return new RunnerOptions
        {
            ReadStdin = args.Contains("--stdin", StringComparer.OrdinalIgnoreCase),
            ConnectionFilePath = Path.GetFullPath(connectionFile),
            XrayPath = Path.GetFullPath(xray),
            OutputDirectory = Path.GetFullPath(Read("--outdir") ?? Path.Combine(executableDirectory, "artifacts")),
            TimeoutSeconds = Math.Clamp(timeout, 3, 120),
            SkipTraceroute = args.Contains("--skip-traceroute", StringComparer.OrdinalIgnoreCase),
            PlanPath = Read("--plan"),
            HistoryPath = string.IsNullOrWhiteSpace(Read("--history")) ? null : Path.GetFullPath(Read("--history")!),
            DnsAttempts = int.TryParse(Read("--dns-attempts"), out var dns) ? Math.Clamp(dns, 1, 10) : 1,
            TcpAttempts = int.TryParse(Read("--tcp-attempts"), out var tcp) ? Math.Clamp(tcp, 1, 20) : 3,
            StabilityAttempts = int.TryParse(Read("--stability-attempts"), out var stability) ? Math.Clamp(stability, 1, 100) : 5,
            EnableExtendedTests = !args.Contains("--basic", StringComparer.OrdinalIgnoreCase),
            EnableNegativeControls = args.Contains("--negative-controls", StringComparer.OrdinalIgnoreCase),
            EnableXudpCompatibility = args.Contains("--xudp", StringComparer.OrdinalIgnoreCase),
            CanaryUrlTemplate = Read("--canary-url"),
            TestType = requestedTestType ?? "normal",
            SoakDurationSeconds = int.TryParse(Read("--soak-seconds"), out var soakSeconds) ? Math.Clamp(soakSeconds, 300, 900) : 300,
            ParallelFlows = int.TryParse(Read("--parallel-flows"), out var parallelFlows) ? Math.Clamp(parallelFlows, 10, 100) : 20,
            NetworkLossSeconds = int.TryParse(Read("--network-loss-seconds"), out var lossSeconds) ? Math.Clamp(lossSeconds, 3, 15) : 5,
            LocalPort = localPort,
            ProgressFilePath = string.IsNullOrWhiteSpace(Read("--progress-file")) ? null : Path.GetFullPath(Read("--progress-file")!)
        };
    }

    public void ApplyPlan(PortableTestPlan? plan)
    {
        if (plan is null) return;
        DnsAttempts = Math.Clamp(plan.DnsAttempts, 1, 10);
        TcpAttempts = Math.Clamp(plan.TcpAttempts, 1, 20);
        StabilityAttempts = Math.Clamp(plan.StabilityAttempts, 1, 100);
        EnableExtendedTests = plan.EnableExtendedTests;
        EnableNegativeControls = plan.EnableNegativeControls;
        EnableXudpCompatibility = plan.EnableXudpCompatibility;
        CanaryUrlTemplate = plan.CanaryUrlTemplate;
        AllowedHosts = plan.AllowedHosts;
        MaxProfiles = Math.Clamp(plan.MaxProfiles, 1, 100);
    }
}

internal sealed class ProgressFileReporter
{
    private readonly string? path;
    private readonly DateTimeOffset startedAt = DateTimeOffset.UtcNow;

    public ProgressFileReporter(string? path) => this.path = string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path);

    public void Report(string state, int percent, int completed, int total, string message, string? zipPath)
    {
        if (path is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? Environment.CurrentDirectory);
            static string Clean(string? value) => (value ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
            var elapsed = Math.Max(0, (long)(DateTimeOffset.UtcNow - startedAt).TotalSeconds);
            var line = string.Join('\t', Clean(state), Math.Clamp(percent, 0, 100), Math.Max(0, completed), Math.Max(0, total), elapsed, Clean(message), Clean(zipPath));
            var temporary = path + $".{Environment.ProcessId}.tmp";
            File.WriteAllText(temporary, line + Environment.NewLine, new UTF8Encoding(false));
            File.Move(temporary, path, overwrite: true);
        }
        catch
        {
            // Progress reporting is best effort and must never invalidate a network measurement.
        }
    }
}

internal sealed class RunnerInput
{
    public List<string> Uris { get; init; } = [];
    [JsonIgnore] public List<int> SourceLineNumbers { get; init; } = [];
    [JsonIgnore] public string InputSource { get; set; } = "stdin";
    public string? RunGroupId { get; set; }
    public string? NodeId { get; set; }
    public string? NetworkLabel { get; set; }
    public string? Scenario { get; set; }
    public string? Country { get; set; }
    public string? Region { get; set; }
    public string? AccessType { get; set; }
    public string? Provider { get; set; }
    public string? RestrictionState { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }

    public void ApplyPlan(PortableTestPlan? plan)
    {
        if (plan is null) return;
        RunGroupId ??= plan.RunGroupId;
        NodeId ??= plan.NodeId;
        NetworkLabel ??= plan.NetworkLabel;
        Scenario ??= plan.Scenario;
        Country ??= plan.Country;
        Region ??= plan.Region;
        AccessType ??= plan.AccessType;
        Provider ??= plan.Provider;
        RestrictionState ??= plan.RestrictionState;
        Latitude ??= plan.Latitude;
        Longitude ??= plan.Longitude;
    }

    public TestContext ToContext() => new()
    {
        RunGroupId = RunGroupId ?? "",
        NodeId = string.IsNullOrWhiteSpace(NodeId) ? Environment.MachineName : NodeId,
        NetworkLabel = string.IsNullOrWhiteSpace(NetworkLabel) ? "local-current-network" : NetworkLabel,
        Scenario = string.IsNullOrWhiteSpace(Scenario) ? "standalone" : Scenario,
        Country = Country,
        Region = Region,
        AccessType = AccessType,
        Provider = Provider,
        RestrictionState = string.IsNullOrWhiteSpace(RestrictionState) ? "unknown" : RestrictionState,
        Latitude = Latitude,
        Longitude = Longitude,
        LocationSource = Latitude.HasValue && Longitude.HasValue ? "test-context/user-supplied" : null
    };
}

internal static class ConnectionFileLoader
{
    public static ConnectionFileInput Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Connection file not found. Put one VLESS URI per line in connections.txt or use --stdin.", path);
        }
        return ParseLines(File.ReadLines(path));
    }

    internal static ConnectionFileInput ParseLines(IEnumerable<string> lines)
    {
        var entries = new List<ConnectionFileEntry>();
        var lineNumber = 0;
        foreach (var raw in lines)
        {
            lineNumber++;
            var value = raw.Trim().TrimStart('\uFEFF');
            if (string.IsNullOrWhiteSpace(value) || value.StartsWith('#') || value.StartsWith(';') || value.StartsWith("//", StringComparison.Ordinal)) continue;
            if (value.Length > 16 * 1024) throw new FormatException($"Connection line {lineNumber} exceeds the 16 KiB safety limit.");
            entries.Add(new ConnectionFileEntry(lineNumber, value));
            if (entries.Count > 1000) throw new FormatException("Connection file exceeds the 1000-entry safety limit.");
        }
        if (entries.Count == 0) throw new FormatException("Connection file contains no active connection lines.");
        return new ConnectionFileInput(entries);
    }
}

internal sealed record ConnectionFileEntry(int LineNumber, string Uri);
internal sealed record ConnectionFileInput(IReadOnlyList<ConnectionFileEntry> Entries);

internal sealed class ConnectionProfile
{
    public required string Name { get; init; }
    public string Protocol { get; init; } = "vless";
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string UserId { get; init; }
    public string Encryption { get; init; } = "none";
    public string Security { get; init; } = "none";
    public string Network { get; init; } = "tcp";
    public string? Flow { get; init; }
    public string? Sni { get; init; }
    public string? Fingerprint { get; init; }
    public string? PublicKey { get; init; }
    public string? ShortId { get; init; }
    public string? SpiderX { get; init; }
    public string? Path { get; init; }
    public string? ServiceName { get; init; }
    public string? HeaderType { get; init; }
    public string? HostHeader { get; init; }
    public string? PacketEncoding { get; init; }

    public static ConnectionProfile Parse(string raw)
    {
        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri) || !uri.Scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("Only absolute vless:// URIs are supported.");
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port is <= 0 or > 65535)
            throw new FormatException("The VLESS URI must contain a valid host and port.");
        var userId = Uri.UnescapeDataString(uri.UserInfo);
        if (string.IsNullOrWhiteSpace(userId)) throw new FormatException("The VLESS URI does not contain a user identifier.");
        var query = ParseQuery(uri.Query);
        string? Get(string key) => query.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
        return new ConnectionProfile
        {
            Name = string.IsNullOrWhiteSpace(uri.Fragment) ? $"{uri.Host}:{uri.Port}" : Uri.UnescapeDataString(uri.Fragment.TrimStart('#')),
            Host = uri.Host,
            Port = uri.Port,
            UserId = userId,
            Encryption = (Get("encryption") ?? "none").ToLowerInvariant(),
            Security = (Get("security") ?? "none").ToLowerInvariant(),
            Network = (Get("type") ?? "tcp").ToLowerInvariant(),
            Flow = Get("flow"),
            Sni = Get("sni"),
            Fingerprint = Get("fp"),
            PublicKey = Get("pbk") ?? Get("password"),
            ShortId = Get("sid"),
            SpiderX = Get("spx"),
            Path = Get("path"),
            ServiceName = Get("serviceName"),
            HeaderType = Get("headerType"),
            HostHeader = Get("host"),
            PacketEncoding = Get("packetEncoding")
        };
    }

    public DeclaredProfile ToDeclaredProfile() => new()
    {
        Protocol = Protocol,
        Name = Name,
        Host = Host,
        Port = Port,
        Encryption = Encryption,
        Security = Security,
        Network = Network,
        Flow = Flow,
        Sni = Sni,
        Fingerprint = Fingerprint,
        HasRealityCredential = !string.IsNullOrWhiteSpace(PublicKey),
        HasShortId = !string.IsNullOrWhiteSpace(ShortId),
        Path = Path,
        ServiceName = ServiceName,
        HeaderType = HeaderType,
        HostHeader = HostHeader,
        PacketEncoding = PacketEncoding
    };

    public ConnectionProfile Copy(
        string? userId = null,
        string? shortId = null,
        string? sni = null,
        string? packetEncoding = null) => new()
    {
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        UserId = userId ?? UserId,
        Encryption = Encryption,
        Security = Security,
        Network = Network,
        Flow = Flow,
        Sni = sni ?? Sni,
        Fingerprint = Fingerprint,
        PublicKey = PublicKey,
        ShortId = shortId ?? ShortId,
        SpiderX = SpiderX,
        Path = Path,
        ServiceName = ServiceName,
        HeaderType = HeaderType,
        HostHeader = HostHeader,
        PacketEncoding = packetEncoding ?? PacketEncoding
    };

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0]);
            var value = parts.Length == 2 ? Uri.UnescapeDataString(parts[1].Replace("+", " ")) : "";
            if (!string.IsNullOrWhiteSpace(key)) result[key] = value;
        }
        return result;
    }
}

internal sealed class RunReport
{
    public string SchemaVersion { get; init; } = "3.0";
    public required string RunId { get; init; }
    public DateTimeOffset GeneratedAt { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; set; }
    public long? DurationMs { get; set; }
    public string TestType { get; init; } = "normal";
    public ExtendedTestMetadata ExtendedTest { get; init; } = new();
    public required string NetworkLabel { get; init; }
    public required TestContext TestContext { get; init; }
    public required ToolInfo Tool { get; init; }
    public required InputSummary Input { get; init; }
    public required NetworkEnvironment Environment { get; init; }
    public NodeDiagnosticsReport? Node { get; set; }
    public IReadOnlyList<ExitIpObservation> DirectBaseline { get; set; } = [];
    public List<IpAttribution> DirectAttribution { get; init; } = [];
    public List<ProfileReport> Profiles { get; init; } = [];
    public List<HostnameGroup> HostnameGroups { get; set; } = [];
    public OsiTrafficMap? OsiMap { get; set; }
    public ResultPackageInfo? ResultPackage { get; set; }
    public OutcomeDecision? Outcome { get; set; }
    public List<string> Limitations { get; init; } = [];
}

internal sealed class ExtendedTestMetadata
{
    public bool Enabled { get; init; }
    public bool Elevated { get; init; }
    public int? SoakDurationSeconds { get; init; }
    public int? ParallelFlows { get; init; }
    public int? NetworkLossSeconds { get; init; }
}

internal sealed class ProfileReport
{
    public required string ProfileId { get; init; }
    public int SourceOrdinal { get; set; }
    public int? SourceLine { get; set; }
    public string? ProfileFingerprint { get; init; }
    public required string Name { get; init; }
    public required DeclaredProfile Declared { get; init; }
    public List<string> ObservedEndpointIps { get; init; } = [];
    public List<string> ObservedCamouflageIps { get; init; } = [];
    public List<string> ObservedSocketIps { get; init; } = [];
    public List<IpAttribution> ExitAttribution { get; init; } = [];
    public List<StageResult> Stages { get; init; } = [];
    public List<Inference> Inferences { get; init; } = [];
    public OutcomeDecision? Outcome { get; set; }
}

internal sealed class DeclaredProfile
{
    public string? Protocol { get; init; }
    public string? Name { get; init; }
    public string? Host { get; init; }
    public int Port { get; init; }
    public string? Encryption { get; init; }
    public string? Security { get; init; }
    public string? Network { get; init; }
    public string? Flow { get; init; }
    public string? Sni { get; init; }
    public string? Fingerprint { get; init; }
    public bool HasRealityCredential { get; init; }
    public bool HasShortId { get; init; }
    public string? Path { get; init; }
    public string? ServiceName { get; init; }
    public string? HeaderType { get; init; }
    public string? HostHeader { get; init; }
    public string? PacketEncoding { get; init; }
}

internal sealed class StageResult
{
    public required string Stage { get; init; }
    public required string Status { get; init; }
    public long ElapsedMs { get; init; }
    public object? Data { get; init; }
    public string? Error { get; init; }
    public string Outcome { get; set; } = OutcomeClassifier.Unknown;
    public string ReasonCode { get; set; } = "NOT_CLASSIFIED";
    public string? Reason { get; set; }

    public static StageResult Passed(string stage, long elapsedMs, object? data = null) => new() { Stage = stage, Status = "passed", ElapsedMs = elapsedMs, Data = data };
    public static StageResult Failed(string stage, long elapsedMs, string? error, object? data = null) => new() { Stage = stage, Status = "failed", ElapsedMs = elapsedMs, Error = error, Data = data };
    public static StageResult Skipped(string stage, string reason) => new() { Stage = stage, Status = "skipped", ElapsedMs = 0, Error = reason };
    public static StageResult FromStatus(string stage, string status, long elapsedMs, object? data, string? error) => new() { Stage = stage, Status = status, ElapsedMs = elapsedMs, Data = data, Error = error };
    public static StageResult FromProcess(string stage, ProcessResult result) => FromStatus(stage, result.ExitCode == 0 ? "passed" : "failed", result.ElapsedMs, new { exitCode = result.ExitCode, stdout = ProgramAccess.Truncate(ProgramAccess.Redact(result.Stdout), 1000), stderr = ProgramAccess.Truncate(ProgramAccess.Redact(result.Stderr), 1000) }, result.ExitCode == 0 ? null : ProgramAccess.Truncate(ProgramAccess.Redact(result.Stderr), 500));
}

// Small bridge keeps StageResult concise without exposing runner secrets.
internal static class ProgramAccess
{
    public static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value ?? "";
        var redacted = Regex.Replace(value, @"(?i)(vless|vmess|trojan|ss)://\S+", "<redacted-uri>");
        return Regex.Replace(redacted, @"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<redacted-uuid>");
    }
    public static string Truncate(string? value, int limit) => string.IsNullOrEmpty(value) || value.Length <= limit ? value ?? "" : value[..limit] + "…";
}

internal sealed class ToolInfo
{
    public required string Name { get; init; }
    public required string Version { get; init; }
    public required string XrayPath { get; init; }
    public required string XrayVersion { get; init; }
    public int TimeoutSeconds { get; init; }
    public int? LocalTestPort { get; init; }
}

internal sealed class InputSummary
{
    public string Source { get; init; } = "stdin";
    public string? FileName { get; init; }
    public int LoadedConnections { get; init; }
    public int ScheduledConnections { get; init; }
    public bool Sequential { get; init; } = true;
}

internal sealed class NetworkEnvironment
{
    public DateTimeOffset CapturedAt { get; init; }
    public string Platform { get; init; } = System.OperatingSystem.IsWindows() ? "windows" : System.OperatingSystem.IsLinux() ? "linux" : System.OperatingSystem.IsAndroid() ? "android" : "unknown";
    public string OperatingSystem { get; init; } = RuntimeInformation.OSDescription.Trim();
    public string KernelVersion { get; init; } = Environment.OSVersion.VersionString;
    public string Architecture { get; init; } = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
    public string Runtime { get; init; } = RuntimeInformation.FrameworkDescription;
    public string TimeZone { get; init; } = TimeZoneInfo.Local.Id;
    public IReadOnlyList<NetworkInterfaceInfo> Interfaces { get; init; } = [];
    public IReadOnlyList<string> DnsServers { get; init; } = [];
    public IReadOnlyList<string> PotentialTunnelInterfaces { get; init; } = [];
    public bool WindowsSystemProxyEnabled { get; init; }
    public string? WindowsSystemProxyServer { get; init; }
    public bool WindowsAutoDetectEnabled { get; init; }
    public bool WindowsAutoConfigUrlPresent { get; init; }
    public IReadOnlyList<string> ProxyEnvironmentVariablesPresent { get; init; } = [];
    public RouteSnapshot? RouteSnapshot { get; set; }
}

internal sealed class NetworkInterfaceInfo
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string InterfaceType { get; init; }
    public double? SpeedMbps { get; init; }
    public int? Ipv4Mtu { get; init; }
    public IReadOnlyList<string> Addresses { get; init; } = [];
    public IReadOnlyList<string> Gateways { get; init; } = [];
    public IReadOnlyList<string> DnsServers { get; init; } = [];
    public string? DnsSuffix { get; init; }
    public bool? DhcpEnabled { get; init; }
    public bool DynamicDnsEnabled { get; init; }
    public bool SupportsMulticast { get; init; }
    public string? MacOui { get; init; }
    public string? MacAddressHash { get; init; }
    public bool HasDefaultGateway { get; init; }
    public bool LooksLikeTunnel { get; init; }
}

internal sealed class DnsProbeResult
{
    public required string Host { get; init; }
    public long ElapsedMs { get; set; }
    public List<DnsObservation> Observations { get; init; } = [];
    [JsonIgnore]
    public IReadOnlyList<string> Addresses => Observations
        .Where(item => item.Status == "success" && item.Type is "A" or "AAAA" && IPAddress.TryParse(item.Value, out _))
        .Select(item => item.Value!)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
    public StageResult Stage(string name) => StageResult.FromStatus(name, Addresses.Count > 0 ? "passed" : "failed", ElapsedMs, new { host = Host, observations = Observations, uniqueAddresses = Addresses }, Addresses.Count > 0 ? null : "No A/AAAA address was observed.");
}

internal sealed record DnsObservation(string Resolver, string Type, string? Value, int? TtlSeconds, long ElapsedMs, string Status, string? Error);
internal sealed record TcpProbeObservation(string Ip, int Port, bool Connected, string Outcome, long ElapsedMs, string? Error);
internal sealed record HttpProbeObservation(string Target, int? StatusCode, bool Success, long ElapsedMs, long? ContentLength, string? Error);
internal sealed record TunnelDownloadObservation(
    int Ordinal,
    string ConnectionMode,
    string Target,
    bool Success,
    long Bytes,
    long? FirstByteMs,
    long? PayloadTransferMs,
    long TotalMs,
    double? EffectiveKilobitsPerSecond,
    double? PayloadTransferKilobitsPerSecond,
    string? Error);
internal sealed record ExitIpObservation(string Service, string? Ip, bool Valid, long ElapsedMs, string? Error);
internal sealed record ProcessResult(int ExitCode, string Stdout, string Stderr, long ElapsedMs);
internal sealed record VariantControlObservation(string Variant, bool CoreStarted, bool FunctionalRequestSucceeded, string Outcome, long ElapsedMs, string? Error);
internal sealed record Inference(string Key, string Value, string Confidence, string Reason);
internal sealed record HostnameGroup(string HostA, string HostB, IReadOnlyList<string> SharedIps);

internal sealed class TunnelProbeResult
{
    public List<StageResult> Stages { get; } = [];
    public List<ExitIpObservation> ExitIps { get; } = [];
    public HashSet<string> ObservedRemoteIps { get; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed class IpAttribution
{
    public required string Ip { get; init; }
    public string Status { get; set; } = "unknown";
    public string? ReverseDns { get; set; }
    public string? Prefix { get; set; }
    public IReadOnlyList<long> OriginAsns { get; set; } = [];
    public string? AsnHolder { get; set; }
    public string? BgpSource { get; set; }
    public string? RdapName { get; set; }
    public string? RdapCountry { get; set; }
    public string? RdapStartAddress { get; set; }
    public string? RdapEndAddress { get; set; }
    public string? RdapSource { get; set; }
    public List<GeoHint> GeolocationHints { get; init; } = [];
    public List<string> Errors { get; init; } = [];
}

internal sealed class GeoHint
{
    public string? Country { get; init; }
    public string? City { get; init; }
    public double? Latitude { get; init; }
    public double? Longitude { get; init; }
    public required string Source { get; init; }
    public required string Confidence { get; init; }
}

internal sealed class CertificateInfo
{
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required string ThumbprintSha256 { get; init; }
    public DateTimeOffset NotBefore { get; init; }
    public DateTimeOffset NotAfter { get; init; }
    public IReadOnlyList<string> SubjectAlternativeNames { get; init; } = [];

    public bool CoversHost(string host)
    {
        foreach (var raw in SubjectAlternativeNames)
        {
            var value = Regex.Replace(
                raw,
                @"^DNS(?:\s+Name)?\s*[:=]\s*",
                "",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).Trim();
            var ascii = value.Contains('(') && value.EndsWith(')')
                ? value[(value.LastIndexOf('(') + 1)..^1]
                : value;
            if (ascii.Equals(host, StringComparison.OrdinalIgnoreCase)) return true;
            if (ascii.StartsWith("*.", StringComparison.Ordinal) && host.EndsWith(ascii[1..], StringComparison.OrdinalIgnoreCase)
                && host.Count(character => character == '.') == ascii.Count(character => character == '.')) return true;
        }
        return false;
    }

    public static CertificateInfo From(X509Certificate2 certificate)
    {
        var sans = certificate.Extensions
            .Where(extension => extension.Oid?.Value == "2.5.29.17")
            .SelectMany(extension => extension.Format(false).Split([", ", "\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
            .Select(value => value.Trim())
            .ToArray();
        return new CertificateInfo
        {
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            ThumbprintSha256 = Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant(),
            NotBefore = certificate.NotBefore.ToUniversalTime(),
            NotAfter = certificate.NotAfter.ToUniversalTime(),
            SubjectAlternativeNames = sans
        };
    }
}

internal static class DnsWire
{
    internal sealed record Record(string Type, string Value, int Ttl);

    public static byte[] BuildQuery(string host, ushort type, out ushort id)
    {
        id = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        using var stream = new MemoryStream();
        WriteU16(stream, id);
        WriteU16(stream, 0x0100);
        WriteU16(stream, 1);
        WriteU16(stream, 0);
        WriteU16(stream, 0);
        WriteU16(stream, 0);
        foreach (var label in host.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new FormatException("Invalid DNS label.");
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }
        stream.WriteByte(0);
        WriteU16(stream, type);
        WriteU16(stream, 1);
        return stream.ToArray();
    }

    public static IReadOnlyList<Record> ParseResponse(byte[] message, ushort expectedId)
    {
        if (message.Length < 12 || ReadU16(message, 0) != expectedId) return [];
        var questionCount = ReadU16(message, 4);
        var answerCount = ReadU16(message, 6);
        var offset = 12;
        for (var index = 0; index < questionCount; index++)
        {
            SkipName(message, ref offset);
            offset += 4;
        }
        var records = new List<Record>();
        for (var index = 0; index < answerCount && offset + 12 <= message.Length; index++)
        {
            SkipName(message, ref offset);
            var type = ReadU16(message, offset); offset += 2;
            offset += 2;
            var ttl = (int)ReadU32(message, offset); offset += 4;
            var length = ReadU16(message, offset); offset += 2;
            if (offset + length > message.Length) break;
            if (type == 1 && length == 4)
                records.Add(new Record("A", new IPAddress(message.AsSpan(offset, length)).ToString(), ttl));
            else if (type == 28 && length == 16)
                records.Add(new Record("AAAA", new IPAddress(message.AsSpan(offset, length)).ToString(), ttl));
            else if (type == 5)
            {
                var nameOffset = offset;
                records.Add(new Record("CNAME", ReadName(message, ref nameOffset), ttl));
            }
            offset += length;
        }
        return records;
    }

    private static void SkipName(byte[] message, ref int offset)
    {
        while (offset < message.Length)
        {
            var length = message[offset++];
            if (length == 0) return;
            if ((length & 0xC0) == 0xC0) { offset++; return; }
            offset += length;
        }
    }

    private static string ReadName(byte[] message, ref int offset)
    {
        var labels = new List<string>();
        var current = offset;
        var jumped = false;
        var guard = 0;
        while (current < message.Length && guard++ < 128)
        {
            var length = message[current++];
            if (length == 0)
            {
                if (!jumped) offset = current;
                break;
            }
            if ((length & 0xC0) == 0xC0)
            {
                if (current >= message.Length) break;
                var pointer = ((length & 0x3F) << 8) | message[current++];
                if (!jumped) offset = current;
                current = pointer;
                jumped = true;
                continue;
            }
            if (current + length > message.Length) break;
            labels.Add(Encoding.ASCII.GetString(message, current, length));
            current += length;
        }
        return string.Join('.', labels);
    }

    private static ushort ReadU16(byte[] value, int offset) => (ushort)((value[offset] << 8) | value[offset + 1]);
    private static uint ReadU32(byte[] value, int offset) => ((uint)value[offset] << 24) | ((uint)value[offset + 1] << 16) | ((uint)value[offset + 2] << 8) | value[offset + 3];
    private static void WriteU16(Stream stream, ushort value) { stream.WriteByte((byte)(value >> 8)); stream.WriteByte((byte)value); }
}

internal sealed class SocksUdpObservation
{
    public bool Success { get; init; }
    public string? RelayEndpoint { get; init; }
    public string Destination { get; init; } = "1.1.1.1:53";
    public string QueryName { get; init; } = "one.one.one.one";
    public int? ResponseCode { get; init; }
    public int? AnswerCount { get; init; }
    public string? Error { get; init; }
    public string Interpretation { get; init; } = "SOCKS5 UDP success proves an end-to-end UDP response, not the internal XUDP encoding.";
}

internal static class SocksUdpDnsProbe
{
    public static async Task<SocksUdpObservation> RunAsync(string socksHost, int socksPort, IPAddress dnsServer, string queryName, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        using var timeoutCancellation = new CancellationTokenSource(timeout);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellation.Token);
        using var control = new TcpClient(AddressFamily.InterNetwork);
        await control.ConnectAsync(IPAddress.Parse(socksHost), socksPort, cancellation.Token);
        var stream = control.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, cancellation.Token);
        var greeting = await ReadExactAsync(stream, 2, cancellation.Token);
        if (greeting[0] != 5 || greeting[1] != 0) return new SocksUdpObservation { Success = false, Error = "SOCKS5 server rejected no-auth negotiation." };

        await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, cancellation.Token);
        var header = await ReadExactAsync(stream, 4, cancellation.Token);
        if (header[0] != 5 || header[1] != 0) return new SocksUdpObservation { Success = false, Error = $"SOCKS5 UDP ASSOCIATE failed with code {header[1]}." };
        var relayAddress = await ReadSocksAddressAsync(stream, header[3], cancellation.Token);
        var portBytes = await ReadExactAsync(stream, 2, cancellation.Token);
        var relayPort = (portBytes[0] << 8) | portBytes[1];
        if (relayAddress.Equals(IPAddress.Any)) relayAddress = IPAddress.Loopback;
        if (relayAddress.Equals(IPAddress.IPv6Any)) relayAddress = IPAddress.IPv6Loopback;

        var dnsQuery = DnsWire.BuildQuery(queryName, 1, out var id);
        using var packet = new MemoryStream();
        packet.Write(new byte[] { 0, 0, 0, 1 });
        packet.Write(dnsServer.GetAddressBytes());
        packet.WriteByte(0);
        packet.WriteByte(53);
        packet.Write(dnsQuery);
        using var udp = new UdpClient(relayAddress.AddressFamily);
        var relay = new IPEndPoint(relayAddress, relayPort);
        var payload = packet.ToArray();
        await udp.SendAsync(payload, payload.Length, relay);
        var response = await udp.ReceiveAsync(cancellation.Token);
        var dataOffset = SocksPayloadOffset(response.Buffer);
        if (dataOffset < 0 || response.Buffer.Length < dataOffset + 12) return new SocksUdpObservation { Success = false, RelayEndpoint = relay.ToString(), Error = "Invalid SOCKS5 UDP response framing." };
        var dns = response.Buffer[dataOffset..];
        var responseId = (ushort)((dns[0] << 8) | dns[1]);
        var responseCode = dns[3] & 0x0F;
        var answerCount = (dns[6] << 8) | dns[7];
        return new SocksUdpObservation
        {
            Success = responseId == id && responseCode == 0,
            RelayEndpoint = relay.ToString(),
            Destination = dnsServer + ":53",
            QueryName = queryName,
            ResponseCode = responseCode,
            AnswerCount = answerCount,
            Error = responseId == id && responseCode == 0 ? null : "DNS response ID or response code did not match."
        };
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken);
            if (read == 0) throw new EndOfStreamException("SOCKS5 control connection closed unexpectedly.");
            offset += read;
        }
        return buffer;
    }

    private static async Task<IPAddress> ReadSocksAddressAsync(Stream stream, byte atyp, CancellationToken cancellationToken)
    {
        return atyp switch
        {
            1 => new IPAddress(await ReadExactAsync(stream, 4, cancellationToken)),
            4 => new IPAddress(await ReadExactAsync(stream, 16, cancellationToken)),
            3 => await ReadDomainAddressAsync(stream, cancellationToken),
            _ => throw new InvalidDataException("Unsupported SOCKS5 address type.")
        };
    }

    private static async Task<IPAddress> ReadDomainAddressAsync(Stream stream, CancellationToken cancellationToken)
    {
        var length = (await ReadExactAsync(stream, 1, cancellationToken))[0];
        var domain = Encoding.ASCII.GetString(await ReadExactAsync(stream, length, cancellationToken));
        return (await Dns.GetHostAddressesAsync(domain, cancellationToken)).First();
    }

    private static int SocksPayloadOffset(byte[] packet)
    {
        if (packet.Length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0) return -1;
        return packet[3] switch
        {
            1 when packet.Length >= 10 => 10,
            4 when packet.Length >= 22 => 22,
            3 when packet.Length >= 7 + packet[4] => 7 + packet[4],
            _ => -1
        };
    }
}
