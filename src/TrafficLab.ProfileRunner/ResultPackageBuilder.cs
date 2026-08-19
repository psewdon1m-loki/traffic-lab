using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

internal static class ResultPackageBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task<ResultPackageInfo> CreateAsync(RunReport report, string outputDirectory, string stamp, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var zipPath = Path.Combine(outputDirectory, $"traffic-lab-results-{stamp}-{report.RunId[^8..]}.zip");
        var usedFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            await using (var file = new FileStream(zipPath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create, leaveOpen: false, Encoding.UTF8))
            {
                foreach (var profile in report.Profiles.OrderBy(item => item.SourceOrdinal))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var prefix = report.Profiles.Count == 1 ? "" : UniqueFolder(profile, usedFolders) + "/";
                    await WriteJsonEntryAsync(archive, prefix + "connection.json", BuildConnectionOutput(report, profile), cancellationToken);
                    await WriteJsonEntryAsync(archive, prefix + "local-machine.json", BuildLocalMachineOutput(report, profile), cancellationToken);
                    if (report.ExtendedTest.Enabled)
                        await WriteJsonEntryAsync(archive, prefix + "extended-test.json", BuildExtendedOutput(report, profile), cancellationToken);
                    await WriteTextEntryAsync(archive, prefix + "osi-map.md", NodeDiagnostics.BuildOsiMarkdown(report, profile.ProfileId), includeBom: false, cancellationToken);
                    await WriteTextEntryAsync(archive, prefix + "README.txt", BuildReadme(report, profile), includeBom: true, cancellationToken);
                }
            }
        }
        catch
        {
            try { if (File.Exists(zipPath)) File.Delete(zipPath); } catch { }
            throw;
        }

        using var verification = ZipFile.OpenRead(zipPath);
        var entries = verification.Entries.Select(item => new ResultArchiveEntry(item.FullName, item.Length, item.CompressedLength)).ToArray();
        var archiveBytes = new FileInfo(zipPath).Length;
        var uncompressedBytes = entries.Sum(item => item.UncompressedBytes);
        return new ResultPackageInfo
        {
            ZipPath = Path.GetFullPath(zipPath),
            ProfileCount = report.Profiles.Count,
            FilesPerProfile = report.ExtendedTest.Enabled ? 5 : 4,
            EntryCount = entries.Length,
            ArchiveBytes = archiveBytes,
            UncompressedBytes = uncompressedBytes,
            CompressionRatio = uncompressedBytes > 0 ? Math.Round(archiveBytes / (double)uncompressedBytes, 3) : null,
            Entries = entries,
            Layout = report.Profiles.Count == 1
                ? report.ExtendedTest.Enabled ? "five-files-at-archive-root" : "four-files-at-archive-root"
                : report.ExtendedTest.Enabled ? "one-named-folder-per-connection-with-five-files" : "one-named-folder-per-connection-with-four-files",
            MemoryDesign = "JSON is streamed directly into ZipArchive entries; no packet capture, executable, SQLite database or test payload is included."
        };
    }

    private static object BuildConnectionOutput(RunReport report, ProfileReport profile)
    {
        var connectionStages = report.ExtendedTest.Enabled
            ? profile.Stages.Where(item => !item.Stage.StartsWith("tunnel.extended.", StringComparison.OrdinalIgnoreCase)).ToArray()
            : profile.Stages.ToArray();
        var statusCounts = connectionStages.GroupBy(item => item.Status).ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        var outcomeCounts = connectionStages.GroupBy(item => item.Outcome).ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        return new
        {
            schemaVersion = "1.0",
            outputType = "connection-characteristics",
            generatedAt = DateTimeOffset.UtcNow,
            run = new
            {
                report.RunId,
                report.StartedAt,
                report.CompletedAt,
                report.DurationMs,
                report.TestType,
                report.ExtendedTest,
                report.NetworkLabel,
                report.TestContext.NodeId,
                report.TestContext.Scenario,
                report.Environment.Platform,
                report.Environment.OperatingSystem,
                outcome = report.Outcome,
                inputSource = report.Input.Source
            },
            connection = new
            {
                profile.ProfileId,
                profile.SourceOrdinal,
                profile.SourceLine,
                profile.Name,
                profile.ProfileFingerprint,
                profileFingerprintAlgorithm = "sha256-canonical-v2-truncated-16",
                profile.Declared,
                profile.ObservedEndpointIps,
                profile.ObservedCamouflageIps,
                profile.ObservedSocketIps,
                profile.ExitAttribution,
                statusCounts,
                outcomeCounts,
                outcome = profile.Outcome,
                stages = connectionStages,
                extendedResultsFile = report.ExtendedTest.Enabled ? "extended-test.json" : null,
                inferences = profile.Inferences,
                sharedHostnameBackends = report.HostnameGroups
            },
            directVersusTunnel = new
            {
                directPublicIps = report.DirectBaseline.Where(item => item.Valid).Select(item => item.Ip).Where(item => item is not null).Distinct().ToArray(),
                tunnelExitIps = profile.ExitAttribution.Select(item => item.Ip).Distinct().ToArray(),
                ingressIps = profile.ObservedEndpointIps
            },
            likelihoodAssessments = BuildConnectionLikelihoods(profile),
            probabilityNotice = "Percentages are conservative heuristic evidence weights for competing explanations. They are not calibrated statistical probabilities and do not replace server/panel configuration.",
            limitations = report.Limitations
        };
    }

    private static object BuildExtendedOutput(RunReport report, ProfileReport profile)
    {
        var stages = profile.Stages.Where(item => item.Stage.StartsWith("tunnel.extended.", StringComparison.OrdinalIgnoreCase)).ToArray();
        var logClassification = profile.Stages.FirstOrDefault(item => item.Stage == "tunnel.logs");
        var tunnelDownload = profile.Stages.FirstOrDefault(item => item.Stage == "tunnel.download");
        var counts = stages.GroupBy(item => item.Status).ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        var outcomeCounts = stages.GroupBy(item => item.Outcome).ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        return new
        {
            schemaVersion = "1.0",
            outputType = "extended-test-results",
            generatedAt = DateTimeOffset.UtcNow,
            run = new
            {
                report.RunId,
                report.StartedAt,
                report.CompletedAt,
                report.DurationMs,
                report.TestType,
                report.ExtendedTest,
                report.NetworkLabel,
                report.TestContext.NodeId,
                report.Environment.Platform,
                report.Environment.OperatingSystem,
                report.Environment.KernelVersion,
                report.Environment.Architecture
            },
            connection = new { profile.ProfileId, profile.SourceOrdinal, profile.Name, profile.ProfileFingerprint },
            outcome = profile.Outcome,
            statusCounts = counts,
            outcomeCounts,
            stages,
            coreLogClassification = logClassification,
            throughputAnalysis = new
            {
                direct = report.Node?.DirectPerformance,
                tunnelDownload,
                coldWarm = stages.FirstOrDefault(item => item.Stage == "tunnel.extended.coldWarm"),
                soak = stages.FirstOrDefault(item => item.Stage == "tunnel.extended.soak"),
                interpretation = "Effective throughput includes establishment and TTFB. Payload-transfer throughput excludes the pre-first-byte interval approximately. Compare repeated warm attempts and variability; neither number is calibrated line rate."
            },
            limitations = report.Limitations
        };
    }

    private static object BuildLocalMachineOutput(RunReport report, ProfileReport profile)
    {
        return new
        {
            schemaVersion = "1.0",
            outputType = "local-machine-and-network-characteristics",
            generatedAt = DateTimeOffset.UtcNow,
            appliesTo = new { profile.ProfileId, profile.SourceOrdinal, profile.Name, profile.ProfileFingerprint },
            run = new { report.RunId, report.StartedAt, report.CompletedAt, report.DurationMs, report.TestType, report.ExtendedTest, report.NetworkLabel, report.TestContext, outcome = report.Outcome },
            environment = report.Environment,
            node = report.Node,
            publicIpObservations = report.DirectBaseline,
            publicIpAttribution = report.DirectAttribution,
            likelihoodAssessments = BuildLocalLikelihoods(report.Node),
            probabilityNotice = "Percentages are heuristic evidence weights. IP geolocation, access-medium detection and NAT topology are explicitly bounded by their listed evidence and limitations."
        };
    }

    private static IReadOnlyList<LikelihoodAssessment> BuildConnectionLikelihoods(ProfileReport profile)
    {
        bool Passed(string stage) => profile.Stages.Any(item => item.Stage == stage && item.Status == "passed");
        var endpoints = profile.ObservedEndpointIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var exits = profile.ExitAttribution.Select(item => item.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var same = endpoints.Overlaps(exits);
        var different = exits.Except(endpoints, StringComparer.OrdinalIgnoreCase).Any();
        var results = new List<LikelihoodAssessment>
        {
            Pair("Profile usability", Passed("tunnel.authenticatedEndToEnd") && Passed("tunnel.http") ? "usable with authenticated application traffic" : "not proven usable", Passed("tunnel.authenticatedEndToEnd") && Passed("tunnel.http") ? 99 : 20, "high", "Authenticated VLESS/REALITY plus successful HTTP is direct client-side evidence."),
            Pair("UDP reachability", Passed("tunnel.udp") ? "end-to-end UDP works" : "UDP not proven", Passed("tunnel.udp") ? 97 : 25, Passed("tunnel.udp") ? "high" : "low", "A real DNS response was requested through SOCKS5 UDP ASSOCIATE."),
            Pair("XUDP server compatibility", Passed("tunnel.xudpCompatibility") ? "compatible with explicit packetEncoding=xudp" : "not tested or not proven", Passed("tunnel.xudpCompatibility") ? 98 : 20, Passed("tunnel.xudpCompatibility") ? "high" : "low", "Only the explicit A/B client variant can demonstrate XUDP compatibility."),
            Pair("QUIC path", Passed("tunnel.quicHandshake") ? "QUIC/TLS h3 handshake reachable" : "QUIC not proven", Passed("tunnel.quicHandshake") ? 97 : 25, Passed("tunnel.quicHandshake") ? "high" : "low", "Native QUIC handshake evidence is stronger than generic UDP but is not a complete HTTP/3 transaction.")
        };

        if (same && different)
            results.Add(Alternatives("Outbound topology", "medium", "Ingress equals at least one exit address, while another address family differs. NAT, dual-stack routing and a relay remain competing explanations.", ("same-node/direct-or-NAT outbound", 60), ("relay/second-hop outbound", 40)));
        else if (same)
            results.Add(Alternatives("Outbound topology", "medium", "Observed ingress and exit addresses overlap, which favors direct/same-node egress but cannot exclude transparent routing.", ("same-node/direct outbound", 75), ("hidden relay/translated outbound", 25)));
        else if (exits.Count > 0)
            results.Add(Alternatives("Outbound topology", "medium", "No observed exit equals an ingress address. A relay is plausible, but NAT/load balancing can produce the same signature.", ("relay/second-hop outbound", 70), ("same-node NAT/load-balanced outbound", 30)));
        else
            results.Add(Alternatives("Outbound topology", "low", "No valid exit address was observed.", ("unknown/insufficient evidence", 100)));

        if (!string.IsNullOrWhiteSpace(profile.Declared.Sni))
            results.Add(Alternatives("Exact REALITY target", "low", "SNI and ordinary TLS fallback are external hints; realitySettings.target is server-private.", ($"declared SNI or closely related backend: {profile.Declared.Sni}", Passed("endpoint.tlsFallback") ? 60 : 35), ("different hidden target/backend", Passed("endpoint.tlsFallback") ? 40 : 65)));
        results.Add(Alternatives("HWID or panel binding", "unknown", "A single client without panel state supplies no discriminating evidence. The 50/50 split is explicitly an uninformative prior.", ("binding/restriction present", 50), ("no binding/restriction", 50)));
        results.Add(Alternatives("Reverse proxy or load balancer", "low", "DNS rotation, connected socket IPs, certificate routing and traceroute are external indicators only.", ("not externally observed", 70), ("present but hidden/undetected", 30)));
        return results;
    }

    private static IReadOnlyList<LikelihoodAssessment> BuildLocalLikelihoods(NodeDiagnosticsReport? node)
    {
        if (node is null) return [Alternatives("Local node", "unknown", "Node diagnostics were unavailable.", ("unknown", 100))];
        var accessProbability = node.AccessTypeConfidence.StartsWith("high", StringComparison.OrdinalIgnoreCase) ? 97 : node.AccessTypeConfidence.StartsWith("medium", StringComparison.OrdinalIgnoreCase) ? 78 : 55;
        var natProbability = node.Nat.Confidence == "high" ? node.Nat.Presence == "observed" ? 98 : 5 : node.Nat.Presence == "observed" ? 75 : 50;
        var providerProbability = node.Provider.Confidence.StartsWith("high", StringComparison.OrdinalIgnoreCase) ? 90 : 65;
        var geoProbability = node.Geolocation.Confidence.StartsWith("low", StringComparison.OrdinalIgnoreCase) ? 60 : 80;
        var results = new List<LikelihoodAssessment>
        {
            Pair("Access medium", node.DetectedAccessType, accessProbability, node.AccessTypeConfidence, node.AccessTypeReason ?? "Adapter/default-route classification."),
            Pair("NAT presence", node.Nat.Presence, natProbability, node.Nat.Confidence, node.Nat.Reason ?? "Local/public/STUN comparison."),
            Alternatives("CGNAT", node.Nat.CgnatHint ? "medium" : "low", "Carrier-grade address space in visible early hops is a positive hint; its absence does not exclude provider-side translation.", (node.Nat.CgnatHint ? "CGNAT likely" : "CGNAT not observed", node.Nat.CgnatHint ? 80 : 75), (node.Nat.CgnatHint ? "other private routing" : "CGNAT present but hidden", node.Nat.CgnatHint ? 20 : 25)),
            Alternatives("Multiple NAT layers", node.Nat.MultipleNatLayersHint ? "medium" : "low", "Multiple distinct private hops can indicate double NAT, but routed private ISP infrastructure is an alternative.", (node.Nat.MultipleNatLayersHint ? "multiple translation/private routing layers likely" : "not observed", node.Nat.MultipleNatLayersHint ? 75 : 70), (node.Nat.MultipleNatLayersHint ? "single NAT plus routed private hops" : "hidden multiple NAT", node.Nat.MultipleNatLayersHint ? 25 : 30)),
            Pair("Observed provider/prefix holder", node.Provider.DisplayName ?? "unknown", providerProbability, node.Provider.Confidence, node.Provider.Limitation ?? "BGP/RDAP attribution."),
            Pair("Public-IP country", node.Geolocation.Country ?? "unknown", node.Geolocation.Country is null ? 25 : geoProbability, node.Geolocation.Confidence, node.Geolocation.Limitation ?? "IP geolocation only."),
            Pair("Device location", node.DeviceLocation.Status == "observed" ? $"{node.DeviceLocation.Latitude},{node.DeviceLocation.Longitude}" : "unavailable", node.DeviceLocation.Status == "observed" ? 95 : 10, node.DeviceLocation.Confidence, node.DeviceLocation.Limitation ?? "Operating-system or user-supplied device location."),
            Pair("Device/IP geo agreement", node.GeolocationComparison.Status, node.GeolocationComparison.Status == "consistent" ? 85 : node.GeolocationComparison.Status == "coarsely-consistent" ? 65 : node.GeolocationComparison.Status == "divergent" ? 90 : 20, node.DeviceLocation.Status == "observed" ? "medium" : "unknown", node.GeolocationComparison.Interpretation ?? "Both sources are required.")
        };
        if (node.Gateway.ModelLabel is not null)
            results.Add(Alternatives("Gateway model", "medium", "UPnP/SSDP metadata is self-advertised and not cryptographically verified.", ($"advertised model: {node.Gateway.ModelLabel}", 90), ("misidentified/spoofed metadata", 10)));
        else
            results.Add(Alternatives("Gateway model", "unknown", "The gateway did not advertise usable UPnP/SSDP manufacturer/model metadata.", ("model cannot be determined from current evidence", 100)));
        return results;
    }

    private static LikelihoodAssessment Pair(string subject, string favored, int probability, string confidence, string basis)
        => Alternatives(subject, confidence, basis, (favored, probability), ($"alternative to '{favored}'", 100 - probability));

    private static LikelihoodAssessment Alternatives(string subject, string confidence, string basis, params (string Value, int Probability)[] values)
        => new(subject, confidence, values.Select(item => new LikelihoodCandidate(item.Value, item.Probability)).ToArray(), basis, values.Sum(item => item.Probability) == 100 ? "heuristic-weights-sum-to-100" : "non-normalized-evidence");

    internal static string BuildReadme(RunReport report, ProfileReport profile)
    {
        var passed = profile.Stages.Count(item => item.Status == "passed");
        var partial = profile.Stages.Count(item => item.Status == "partial");
        var failed = profile.Stages.Count(item => item.Status == "failed");
        var skipped = profile.Stages.Count(item => item.Status == "skipped");
        var builder = new StringBuilder();
        builder.AppendLine("LOKI TRAFFIC LAB - TEST RESULT PACKAGE");
        builder.AppendLine("=====================================").AppendLine();
        builder.AppendLine($"Run ID: {report.RunId}");
        builder.AppendLine($"Test started (UTC): {report.StartedAt:O}");
        builder.AppendLine($"Test started (node local time): {report.StartedAt.ToLocalTime():O}");
        builder.AppendLine($"Test completed (UTC): {report.CompletedAt:O}");
        builder.AppendLine($"Total run duration: {TimeSpan.FromMilliseconds(report.DurationMs ?? 0):c}");
        builder.AppendLine($"Test type: {report.TestType.ToUpperInvariant()} ({(report.ExtendedTest.Enabled ? "long-running/disruptive extended suite" : "standard suite")})");
        if (report.ExtendedTest.Enabled)
            builder.AppendLine($"Extended settings: soak={report.ExtendedTest.SoakDurationSeconds}s, parallel flows={report.ExtendedTest.ParallelFlows}, network interruption={report.ExtendedTest.NetworkLossSeconds}s, elevated={report.ExtendedTest.Elevated}");
        builder.AppendLine($"Platform: {report.Environment.Platform}");
        builder.AppendLine($"Operating system: {report.Environment.OperatingSystem}");
        builder.AppendLine($"Kernel/OS version: {report.Environment.KernelVersion}");
        builder.AppendLine($"Architecture: {report.Environment.Architecture}");
        builder.AppendLine($"Node time zone: {report.Environment.TimeZone}");
        builder.AppendLine($"Node ID: {report.TestContext.NodeId}");
        builder.AppendLine($"Network label: {report.NetworkLabel}");
        builder.AppendLine($"Scenario: {report.TestContext.Scenario}");
        builder.AppendLine($"Test execution node: {DescribeExecutionNode(report.Environment.Platform)}");
        builder.AppendLine($"Input source: {report.Input.Source}");
        builder.AppendLine($"Connections loaded/scheduled: {report.Input.LoadedConnections}/{report.Input.ScheduledConnections}");
        builder.AppendLine($"Execution order: sequential");
        builder.AppendLine($"Tool: {report.Tool.Name} {report.Tool.Version}");
        builder.AppendLine($"Core: {report.Tool.XrayVersion}");
        builder.AppendLine($"Local test port: {(report.Tool.LocalTestPort?.ToString() ?? "automatic")}").AppendLine();
        builder.AppendLine("CONNECTION");
        builder.AppendLine("----------");
        builder.AppendLine($"Profile ID/order: {profile.ProfileId} / {profile.SourceOrdinal}");
        builder.AppendLine($"Source line: {(profile.SourceLine?.ToString() ?? "stdin/not applicable")}");
        builder.AppendLine($"Name: {profile.Name}");
        builder.AppendLine($"Sanitized fingerprint: {profile.ProfileFingerprint}");
        builder.AppendLine("Fingerprint algorithm: sha256-canonical-v2-truncated-16");
        builder.AppendLine($"Declared transport: {profile.Declared.Protocol}/{profile.Declared.Security}/{profile.Declared.Network}");
        builder.AppendLine($"Endpoint: {profile.Declared.Host}:{profile.Declared.Port}");
        builder.AppendLine($"Observed endpoint IPs: {string.Join(", ", profile.ObservedEndpointIps)}");
        builder.AppendLine($"Stage results: passed={passed}, partial={partial}, failed={failed}, skipped={skipped}").AppendLine();
        builder.AppendLine($"Profile outcome: {profile.Outcome?.Outcome ?? OutcomeClassifier.Unknown}");
        builder.AppendLine($"Outcome reason: {profile.Outcome?.ReasonCode ?? "INSUFFICIENT_EVIDENCE"} - {profile.Outcome?.Reason ?? "No causal classification was available."}");
        builder.AppendLine($"Run outcome: {report.Outcome?.Outcome ?? OutcomeClassifier.Unknown} ({report.Outcome?.ReasonCode ?? "RUN_INCONCLUSIVE"})").AppendLine();
        builder.AppendLine("FILES");
        builder.AppendLine("-----");
        builder.AppendLine("connection.json    Connection characteristics, standard stages, endpoint/exit attribution and probability assessments.");
        builder.AppendLine("local-machine.json Full test-PC, interface, speed, provider, geolocation, NAT, gateway and OS settings.");
        if (report.ExtendedTest.Enabled)
            builder.AppendLine("extended-test.json Long-running/disruptive stages, induced-failure log classification and throughput correlation.");
        builder.AppendLine("osi-map.md         Human-readable seven-layer OSI evidence table and Mermaid traffic-path graph.");
        builder.AppendLine("README.txt         This metadata and interpretation guide.").AppendLine();
        builder.AppendLine("CONFIDENCE AND PROBABILITY");
        builder.AppendLine("--------------------------");
        builder.AppendLine("Measured/high: directly observed protocol response or stable OS/API state.");
        builder.AppendLine("Medium: multiple compatible external signals with plausible alternatives.");
        builder.AppendLine("Low: weak external hint such as IP geolocation, TLS fallback or hidden topology.");
        builder.AppendLine("Unknown: no discriminating client-side evidence.");
        builder.AppendLine("Probability percentages are heuristic evidence weights, not calibrated statistical probabilities.").AppendLine();
        builder.AppendLine("PRIVACY AND LIMITS");
        builder.AppendLine("------------------");
        builder.AppendLine("Raw connection URI, UUID, REALITY public key/password and short ID are not included.");
        builder.AppendLine("Local/public addresses and network metadata requested by the test are included and may be sensitive.");
        builder.AppendLine("When available or explicitly supplied, device coordinates, accuracy and capture time are included and are sensitive location data.");
        builder.AppendLine("The archive excludes executables, packet captures, SQLite history and downloaded/uploaded test payloads.");
        foreach (var limitation in report.Limitations) builder.AppendLine("- " + limitation);
        return builder.ToString();
    }

    private static string DescribeExecutionNode(string platform)
        => platform.ToLowerInvariant() switch
        {
            "windows" => "Windows PC, Loki Traffic Lab Portable tester",
            "linux" => "Linux PC, Loki Traffic Lab command-line tester",
            "android" => "Android device, Loki Traffic Lab application",
            _ => $"{platform} device, Loki Traffic Lab tester"
        };

    private static string UniqueFolder(ProfileReport profile, ISet<string> used)
    {
        var safeName = Regex.Replace(profile.Name.Normalize(NormalizationForm.FormKC), @"[<>:""/\\|?*\x00-\x1F]", "-");
        safeName = Regex.Replace(safeName, @"\s+", " ").Trim(' ', '.');
        if (string.IsNullOrWhiteSpace(safeName)) safeName = profile.ProfileId;
        if (safeName.Length > 60) safeName = safeName[..60].TrimEnd(' ', '.');
        var root = $"{profile.SourceOrdinal:00}-{safeName}";
        var candidate = root;
        var suffix = 2;
        while (!used.Add(candidate)) candidate = $"{root}-{suffix++}";
        return candidate;
    }

    private static async Task WriteJsonEntryAsync(ZipArchive archive, string name, object value, CancellationToken cancellationToken)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.SmallestSize);
        entry.LastWriteTime = DateTimeOffset.Now;
        await using var stream = entry.Open();
        await JsonSerializer.SerializeAsync(stream, value, value.GetType(), JsonOptions, cancellationToken);
    }

    private static async Task WriteTextEntryAsync(ZipArchive archive, string name, string value, bool includeBom, CancellationToken cancellationToken)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.SmallestSize);
        entry.LastWriteTime = DateTimeOffset.Now;
        await using var stream = entry.Open();
        await using var writer = new StreamWriter(stream, new UTF8Encoding(includeBom), 16 * 1024, leaveOpen: false);
        await writer.WriteAsync(value.AsMemory(), cancellationToken);
    }
}

internal sealed record LikelihoodAssessment(string Subject, string Confidence, IReadOnlyList<LikelihoodCandidate> Candidates, string Basis, string Calibration);
internal sealed record LikelihoodCandidate(string Value, int ProbabilityPercent);
internal sealed class ResultPackageInfo
{
    public string ZipPath { get; init; } = "";
    public int ProfileCount { get; init; }
    public int FilesPerProfile { get; init; }
    public int EntryCount { get; init; }
    public long ArchiveBytes { get; init; }
    public long UncompressedBytes { get; init; }
    public double? CompressionRatio { get; init; }
    public string Layout { get; init; } = "";
    public string MemoryDesign { get; init; } = "";
    public IReadOnlyList<ResultArchiveEntry> Entries { get; init; } = [];
}
internal sealed record ResultArchiveEntry(string Path, long UncompressedBytes, long CompressedBytes);
