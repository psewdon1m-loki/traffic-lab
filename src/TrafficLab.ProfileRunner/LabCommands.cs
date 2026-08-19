using System.Globalization;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;

internal static class LabCommands
{
    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task<int?> TryHandleAsync(string[] args)
    {
        var command = args.FirstOrDefault()?.ToLowerInvariant();
        if (command is null or "run" or "--self-test" || args.Contains("--stdin", StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        switch (command)
        {
            case "help":
            case "--help":
            case "-h":
                PrintHelp();
                return 0;
            case "plan":
                return await CreatePlanAsync(args[1..]);
            case "snapshot":
                return await CaptureSnapshotAsync(args[1..]);
            case "compare":
                return await CompareAsync(args[1..]);
            case "observe":
                return await PortableAppObserver.RunAsync(args[1..]);
            case "collector":
                return await PortableCollector.RunAsync(args[1..]);
            case "matrix":
                return await NetworkMatrixBuilder.RunAsync(args[1..]);
            case "capture":
                return await PacketCaptureCommand.RunAsync(args[1..]);
            case "history":
                return await HistoryAsync(args[1..]);
            default:
                Console.Error.WriteLine($"Unknown command: {command}");
                PrintHelp();
                return 2;
        }
    }

    public static PortableTestPlan? LoadPlan(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("Test plan not found.", fullPath);
        return JsonSerializer.Deserialize<PortableTestPlan>(File.ReadAllText(fullPath), JsonOptions)
            ?? throw new InvalidOperationException("Test plan JSON is empty.");
    }

    private static async Task<int> CreatePlanAsync(string[] args)
    {
        var output = Read(args, "--out") ?? "traffic-lab-plan.json";
        var plan = new PortableTestPlan
        {
            SchemaVersion = "1.0",
            RunGroupId = Read(args, "--run-group") ?? $"group-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}",
            NodeId = Read(args, "--node-id") ?? Environment.MachineName,
            NetworkLabel = Read(args, "--network-label") ?? "unlabelled-network",
            Scenario = Read(args, "--scenario") ?? "standalone",
            Country = Read(args, "--country"),
            Region = Read(args, "--region"),
            AccessType = Read(args, "--access") ?? "auto",
            Provider = Read(args, "--provider"),
            RestrictionState = Read(args, "--restriction") ?? "unknown",
            Latitude = ReadDouble(args, "--latitude", -90, 90),
            Longitude = ReadDouble(args, "--longitude", -180, 180),
            DnsAttempts = ReadInt(args, "--dns-attempts", 3, 1, 10),
            TcpAttempts = ReadInt(args, "--tcp-attempts", 5, 1, 20),
            StabilityAttempts = ReadInt(args, "--stability-attempts", 10, 1, 100),
            EnableExtendedTests = !args.Contains("--basic", StringComparer.OrdinalIgnoreCase),
            EnableNegativeControls = args.Contains("--negative-controls", StringComparer.OrdinalIgnoreCase),
            EnableXudpCompatibility = args.Contains("--xudp", StringComparer.OrdinalIgnoreCase),
            CanaryUrlTemplate = Read(args, "--canary-url"),
            AllowedHosts = ReadMany(args, "--allow-host")
        };
        var fullPath = Path.GetFullPath(output);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory);
        await File.WriteAllTextAsync(fullPath, JsonSerializer.Serialize(plan, JsonOptions), new UTF8Encoding(false));
        Console.WriteLine("Portable test plan written: " + fullPath);
        Console.WriteLine("The plan contains no connection URI or authentication secret.");
        return 0;
    }

    private static async Task<int> CaptureSnapshotAsync(string[] args)
    {
        var outputDirectory = Path.GetFullPath(Read(args, "--outdir") ?? "artifacts");
        Directory.CreateDirectory(outputDirectory);
        var plan = LoadPlan(Read(args, "--plan"));
        var route = await ExtendedDiagnostics.CaptureRouteSnapshotAsync(TimeSpan.FromSeconds(10));
        var environment = Program.CaptureNetworkEnvironmentForCommands();
        environment.RouteSnapshot = route;
        var nodeContext = plan is null ? new TestContext { NodeId = Environment.MachineName, NetworkLabel = "unlabelled-network" } : plan.ToContext();
        var nodeDiagnostics = await Program.CaptureNodeDiagnosticsForCommandsAsync(environment, nodeContext, TimeSpan.FromSeconds(10));
        var snapshot = new
        {
            schemaVersion = "1.0",
            snapshotId = $"snapshot-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..34],
            capturedAt = DateTimeOffset.UtcNow,
            node = nodeContext,
            nodeDiagnostics,
            environment,
            route,
            privileges = new
            {
                isElevated = IsElevated(),
                packetCaptureAvailable = OperatingSystem.IsWindows() && File.Exists(Path.Combine(Environment.SystemDirectory, "pktmon.exe"))
                    || OperatingSystem.IsLinux() && (File.Exists("/usr/bin/tcpdump") || File.Exists("/usr/sbin/tcpdump")),
                packetCaptureEnabled = false,
                reason = "Packet capture is opt-in and is never started by snapshot or run commands."
            }
        };
        var path = Path.Combine(outputDirectory, $"network-snapshot-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(snapshot, JsonOptions), new UTF8Encoding(false));
        Console.WriteLine("Network snapshot: " + path);
        return 0;
    }

    private static async Task<int> CompareAsync(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: LokiTrafficLab compare <baseline.json> <candidate.json> [--out comparison.json]");
            return 2;
        }
        var baselinePath = Path.GetFullPath(args[0]);
        var candidatePath = Path.GetFullPath(args[1]);
        if (!File.Exists(baselinePath) || !File.Exists(candidatePath))
        {
            Console.Error.WriteLine("Both report paths must exist.");
            return 2;
        }
        var comparison = ReportComparer.Compare(baselinePath, candidatePath);
        var output = Path.GetFullPath(Read(args, "--out") ?? Path.Combine(Path.GetDirectoryName(candidatePath)!, $"comparison-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json"));
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(comparison, JsonOptions), new UTF8Encoding(false));
        var markdown = Path.ChangeExtension(output, ".md");
        await File.WriteAllTextAsync(markdown, ReportComparer.ToMarkdown(comparison), new UTF8Encoding(false));
        Console.WriteLine($"Comparison: {output}");
        Console.WriteLine($"Markdown  : {markdown}");
        Console.WriteLine($"Stage changes: {comparison.Profiles.Sum(item => item.StageChanges.Count)}; DNS changes: {comparison.Profiles.Count(item => item.EndpointDnsChanged || item.CamouflageDnsChanged)}; exit changes: {comparison.Profiles.Count(item => item.ExitIpsChanged)}");
        return 0;
    }

    private static async Task<int> HistoryAsync(string[] args)
    {
        var action = args.FirstOrDefault()?.ToLowerInvariant() ?? "list";
        var dbPath = Path.GetFullPath(Read(args, "--db") ?? Path.Combine("artifacts", "traffic-lab-history.sqlite"));
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath) ?? Environment.CurrentDirectory);
        await using var store = new HistoryStore(dbPath);
        await store.InitializeAsync();
        if (action == "import")
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: LokiTrafficLab history import <report-or-directory> [--db history.sqlite]");
                return 2;
            }
            var target = Path.GetFullPath(args[1]);
            var files = Directory.Exists(target)
                ? Directory.EnumerateFiles(target, "profile-lab-*.json", SearchOption.TopDirectoryOnly).ToArray()
                : File.Exists(target) ? new[] { target } : [];
            var imported = 0;
            foreach (var file in files)
            {
                imported += await store.ImportAsync(file) ? 1 : 0;
            }
            Console.WriteLine($"History database: {dbPath}");
            Console.WriteLine($"Imported/updated runs: {imported}");
            return files.Length > 0 ? 0 : 2;
        }
        if (action == "list")
        {
            var rows = await store.ListAsync(ReadInt(args, "--limit", 20, 1, 1000));
            Console.WriteLine($"History database: {dbPath}");
            Console.WriteLine($"{"generatedAt",-26} {"runId",-30} {"network",-24} {"profiles",8} {"passed",7} {"failed",7}");
            foreach (var row in rows)
            {
                Console.WriteLine($"{row.GeneratedAt,-26} {row.RunId,-30} {Trim(row.NetworkLabel, 24),-24} {row.ProfileCount,8} {row.PassedStages,7} {row.FailedStages,7}");
            }
            return 0;
        }
        Console.Error.WriteLine("History actions: import, list");
        return 2;
    }

    private static string? Read(string[] args, string name)
    {
        var index = Array.FindIndex(args, value => value.Equals(name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static string[] ReadMany(string[] args, string name)
    {
        var values = new List<string>();
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(args[index + 1])) values.Add(args[index + 1]);
        }
        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static int ReadInt(string[] args, string name, int fallback, int minimum, int maximum)
        => int.TryParse(Read(args, name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? Math.Clamp(value, minimum, maximum) : fallback;
    private static double? ReadDouble(string[] args, string name, double minimum, double maximum)
        => double.TryParse(Read(args, name), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) ? Math.Clamp(value, minimum, maximum) : null;

    private static string Trim(string value, int length) => value.Length <= length ? value : value[..Math.Max(1, length - 1)] + "…";

    private static bool IsElevated()
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var uid = File.ReadLines("/proc/self/status").FirstOrDefault(line => line.StartsWith("Uid:", StringComparison.Ordinal));
                return uid is not null && uid.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Skip(1).FirstOrDefault() == "0";
            }
            catch { return false; }
        }
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Loki Traffic Lab 3.4 - portable distributed black-box network laboratory");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  run [--connections connections.txt] [--plan plan.json] [--xray xray.exe] [--outdir artifacts]");
        Console.WriteLine("      [--test-type normal|extended|speed] [--soak-seconds 300..900] [--parallel-flows 10..100] [--network-loss-seconds 3..15]");
        Console.WriteLine("  run --stdin [--plan plan.json]  (safer ephemeral secret input)");
        Console.WriteLine("  plan --out plan.json --node-id ru-pc --network-label ru-ethernet --country RU --access ethernet");
        Console.WriteLine("  snapshot [--plan plan.json] [--outdir artifacts]");
        Console.WriteLine("  compare baseline.json candidate.json [--out comparison.json]");
        Console.WriteLine("  observe --process app --proxy-port 18091 --duration 30 [--outdir artifacts]");
        Console.WriteLine("  collector --http-port 18080 --udp-port 18081 --dns-port 15353 --dns-answer <public-ip>");
        Console.WriteLine("  matrix <report-or-directory> [--out network-matrix.json]");
        Console.WriteLine("  capture --duration 30 --i-understand [--outdir artifacts]  (Administrator/root, opt-in)");
        Console.WriteLine("  history import <report-or-directory> [--db history.sqlite]");
        Console.WriteLine("  history list [--db history.sqlite] [--limit 20]");
        Console.WriteLine("  --self-test");
        Console.WriteLine();
        Console.WriteLine("Without --stdin, run reads one connection per active line from adjacent connections.txt in file order.");
        Console.WriteLine("Connection secrets are never persisted in reports; connections.txt itself is sensitive plaintext.");
    }
}

internal sealed class PortableTestPlan
{
    public string SchemaVersion { get; init; } = "1.0";
    public string RunGroupId { get; init; } = "";
    public string NodeId { get; init; } = "";
    public string NetworkLabel { get; init; } = "unlabelled-network";
    public string Scenario { get; init; } = "standalone";
    public string? Country { get; init; }
    public string? Region { get; init; }
    public string AccessType { get; init; } = "auto";
    public string? Provider { get; init; }
    public string RestrictionState { get; init; } = "unknown";
    public double? Latitude { get; init; }
    public double? Longitude { get; init; }
    public int DnsAttempts { get; init; } = 3;
    public int TcpAttempts { get; init; } = 5;
    public int StabilityAttempts { get; init; } = 10;
    public bool EnableExtendedTests { get; init; } = true;
    public bool EnableNegativeControls { get; init; }
    public bool EnableXudpCompatibility { get; init; }
    public string? CanaryUrlTemplate { get; init; }
    public IReadOnlyList<string> AllowedHosts { get; init; } = [];
    public int MaxProfiles { get; init; } = 25;

    public TestContext ToContext() => new()
    {
        RunGroupId = RunGroupId,
        NodeId = string.IsNullOrWhiteSpace(NodeId) ? Environment.MachineName : NodeId,
        NetworkLabel = NetworkLabel,
        Scenario = Scenario,
        Country = Country,
        Region = Region,
        AccessType = AccessType,
        Provider = Provider,
        RestrictionState = RestrictionState,
        Latitude = Latitude,
        Longitude = Longitude,
        LocationSource = Latitude.HasValue && Longitude.HasValue ? "test-context/user-supplied" : null
    };
}

internal sealed class TestContext
{
    public string RunGroupId { get; init; } = "";
    public string NodeId { get; init; } = Environment.MachineName;
    public string NetworkLabel { get; init; } = "local-current-network";
    public string Scenario { get; init; } = "standalone";
    public string? Country { get; init; }
    public string? Region { get; init; }
    public string? AccessType { get; init; }
    public string? Provider { get; init; }
    public string RestrictionState { get; init; } = "unknown";
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string? LocationSource { get; set; }
}

internal sealed class ComparisonReport
{
    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;
    public required ComparedRun Baseline { get; init; }
    public required ComparedRun Candidate { get; init; }
    public List<ProfileComparison> Profiles { get; init; } = [];
    public List<string> Conclusions { get; init; } = [];
}

internal sealed record ComparedRun(string Path, string RunId, string NetworkLabel, string? NodeId, DateTimeOffset? GeneratedAt);
internal sealed class ProfileComparison
{
    public required string Key { get; init; }
    public string? BaselineName { get; init; }
    public string? CandidateName { get; init; }
    public bool EndpointDnsChanged { get; init; }
    public bool CamouflageDnsChanged { get; init; }
    public bool ExitIpsChanged { get; init; }
    public IReadOnlyList<string> BaselineEndpointIps { get; init; } = [];
    public IReadOnlyList<string> CandidateEndpointIps { get; init; } = [];
    public IReadOnlyList<string> BaselineExitIps { get; init; } = [];
    public IReadOnlyList<string> CandidateExitIps { get; init; } = [];
    public List<StageChange> StageChanges { get; init; } = [];
}
internal sealed record StageChange(string Stage, string? BaselineStatus, string? CandidateStatus);

internal static class ReportComparer
{
    public static ComparisonReport Compare(string baselinePath, string candidatePath)
    {
        using var baseline = JsonDocument.Parse(File.ReadAllText(baselinePath));
        using var candidate = JsonDocument.Parse(File.ReadAllText(candidatePath));
        var result = new ComparisonReport
        {
            Baseline = ReadRun(baseline.RootElement, baselinePath),
            Candidate = ReadRun(candidate.RootElement, candidatePath)
        };
        var baselineProfiles = ReadProfiles(baseline.RootElement);
        var candidateProfiles = ReadProfiles(candidate.RootElement);
        foreach (var key in baselineProfiles.Keys.Union(candidateProfiles.Keys, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
        {
            baselineProfiles.TryGetValue(key, out var left);
            candidateProfiles.TryGetValue(key, out var right);
            var leftStages = left.ValueKind == JsonValueKind.Undefined ? new Dictionary<string, string>() : ReadStages(left);
            var rightStages = right.ValueKind == JsonValueKind.Undefined ? new Dictionary<string, string>() : ReadStages(right);
            var changes = leftStages.Keys.Union(rightStages.Keys, StringComparer.OrdinalIgnoreCase)
                .Where(stage => !string.Equals(leftStages.GetValueOrDefault(stage), rightStages.GetValueOrDefault(stage), StringComparison.OrdinalIgnoreCase))
                .Select(stage => new StageChange(stage, leftStages.GetValueOrDefault(stage), rightStages.GetValueOrDefault(stage)))
                .ToList();
            var leftEndpoint = ReadStrings(left, "observedEndpointIps");
            var rightEndpoint = ReadStrings(right, "observedEndpointIps");
            var leftCamouflage = ReadStrings(left, "observedCamouflageIps");
            var rightCamouflage = ReadStrings(right, "observedCamouflageIps");
            var leftExit = ReadExitIps(left);
            var rightExit = ReadExitIps(right);
            result.Profiles.Add(new ProfileComparison
            {
                Key = key,
                BaselineName = ReadString(left, "name"),
                CandidateName = ReadString(right, "name"),
                EndpointDnsChanged = !SameSet(leftEndpoint, rightEndpoint),
                CamouflageDnsChanged = !SameSet(leftCamouflage, rightCamouflage),
                ExitIpsChanged = !SameSet(leftExit, rightExit),
                BaselineEndpointIps = leftEndpoint,
                CandidateEndpointIps = rightEndpoint,
                BaselineExitIps = leftExit,
                CandidateExitIps = rightExit,
                StageChanges = changes
            });
        }
        if (result.Profiles.Any(item => item.EndpointDnsChanged)) result.Conclusions.Add("Endpoint DNS differs between runs; GeoDNS, rotation, resolver policy, or DNS interference is possible.");
        if (result.Profiles.Any(item => item.ExitIpsChanged)) result.Conclusions.Add("Tunnel exit addresses differ between runs; address-family selection, load balancing, or client-dependent outbound routing is possible.");
        if (result.Profiles.Any(item => item.StageChanges.Count > 0)) result.Conclusions.Add("At least one diagnostic stage changed status; inspect per-stage evidence before attributing the cause.");
        if (result.Conclusions.Count == 0) result.Conclusions.Add("No material DNS, exit-IP, or stage-status difference was observed.");
        return result;
    }

    public static string ToMarkdown(ComparisonReport report)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Traffic Lab comparison").AppendLine();
        builder.AppendLine($"- Baseline: `{report.Baseline.NetworkLabel}` / `{report.Baseline.RunId}`");
        builder.AppendLine($"- Candidate: `{report.Candidate.NetworkLabel}` / `{report.Candidate.RunId}`").AppendLine();
        builder.AppendLine("| Profile | Endpoint DNS | Exit IP | Stage changes |");
        builder.AppendLine("|---|---:|---:|---:|");
        foreach (var profile in report.Profiles)
        {
            builder.AppendLine($"| {Escape(profile.CandidateName ?? profile.BaselineName ?? profile.Key)} | {(profile.EndpointDnsChanged ? "changed" : "same")} | {(profile.ExitIpsChanged ? "changed" : "same")} | {profile.StageChanges.Count} |");
        }
        builder.AppendLine().AppendLine("## Conclusions").AppendLine();
        foreach (var conclusion in report.Conclusions) builder.AppendLine("- " + conclusion);
        return builder.ToString();
    }

    private static ComparedRun ReadRun(JsonElement root, string path)
    {
        var context = root.TryGetProperty("testContext", out var testContext) ? testContext : default;
        DateTimeOffset? generated = root.TryGetProperty("generatedAt", out var time) && time.TryGetDateTimeOffset(out var parsed) ? parsed : null;
        return new ComparedRun(path, String(root, "runId") ?? "unknown", String(root, "networkLabel") ?? "unknown", context.ValueKind == JsonValueKind.Object ? String(context, "nodeId") : null, generated);
    }

    private static Dictionary<string, JsonElement> ReadProfiles(JsonElement root)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("profiles", out var profiles) || profiles.ValueKind != JsonValueKind.Array) return result;
        foreach (var profile in profiles.EnumerateArray())
        {
            var fingerprint = String(profile, "profileFingerprint") ?? "no-fingerprint";
            var instance = String(profile, "profileId") ?? Guid.NewGuid().ToString("N");
            var key = $"{fingerprint}:{instance}";
            result[key] = profile.Clone();
        }
        return result;
    }

    private static Dictionary<string, string> ReadStages(JsonElement profile)
    {
        if (!profile.TryGetProperty("stages", out var stages) || stages.ValueKind != JsonValueKind.Array) return [];
        return stages.EnumerateArray().Where(stage => stage.ValueKind == JsonValueKind.Object)
            .ToDictionary(stage => String(stage, "stage") ?? "unknown", stage => String(stage, "status") ?? "unknown", StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> ReadExitIps(JsonElement? profile)
    {
        if (profile is null || !profile.Value.TryGetProperty("stages", out var stages)) return [];
        foreach (var stage in stages.EnumerateArray())
        {
            if (!string.Equals(String(stage, "stage"), "tunnel.exitIp", StringComparison.OrdinalIgnoreCase)
                || !stage.TryGetProperty("data", out var data)
                || !data.TryGetProperty("throughTunnel", out var exits)) continue;
            return exits.EnumerateArray()
                .Where(item => item.TryGetProperty("valid", out var valid) && valid.ValueKind == JsonValueKind.True)
                .Select(item => String(item, "ip"))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        return [];
    }

    private static IReadOnlyList<string> ReadStrings(JsonElement? element, string property)
        => element is not null && element.Value.TryGetProperty(property, out var values) && values.ValueKind == JsonValueKind.Array
            ? values.EnumerateArray().Select(item => item.GetString()).Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray()
            : [];
    private static string? ReadString(JsonElement? element, string property) => element is null ? null : String(element.Value, property);
    private static string? String(JsonElement element, string property) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static bool SameSet(IReadOnlyList<string> left, IReadOnlyList<string> right) => left.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(right);
    private static string Escape(string value) => value.Replace("|", "\\|", StringComparison.Ordinal);
}

internal sealed class HistoryStore : IAsyncDisposable
{
    private readonly SqliteConnection connection;

    public HistoryStore(string path)
    {
        connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate }.ToString());
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await connection.OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                network_label TEXT NOT NULL,
                node_id TEXT,
                source_path TEXT NOT NULL,
                profile_count INTEGER NOT NULL,
                passed_stages INTEGER NOT NULL,
                failed_stages INTEGER NOT NULL,
                report_json TEXT NOT NULL,
                imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stages (
                run_id TEXT NOT NULL,
                profile_key TEXT NOT NULL,
                profile_name TEXT,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                elapsed_ms INTEGER NOT NULL,
                error TEXT,
                data_json TEXT,
                PRIMARY KEY (run_id, profile_key, stage),
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_runs_generated_at ON runs(generated_at);
            CREATE INDEX IF NOT EXISTS ix_stages_stage_status ON stages(stage, status);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> ImportAsync(string path, CancellationToken cancellationToken = default)
    {
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path, cancellationToken));
        var root = document.RootElement;
        var runId = GetString(root, "runId") ?? throw new InvalidDataException($"Report has no runId: {path}");
        var generatedAt = GetString(root, "generatedAt") ?? DateTimeOffset.UtcNow.ToString("O");
        var network = GetString(root, "networkLabel") ?? "unknown";
        var node = root.TryGetProperty("testContext", out var context) ? GetString(context, "nodeId") : null;
        var profiles = root.TryGetProperty("profiles", out var profileArray) && profileArray.ValueKind == JsonValueKind.Array ? profileArray.EnumerateArray().ToArray() : [];
        var stages = profiles.SelectMany(profile => profile.TryGetProperty("stages", out var list) ? list.EnumerateArray().Select(stage => (profile, stage)) : []).ToArray();
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var run = connection.CreateCommand();
        run.Transaction = (SqliteTransaction)transaction;
        run.CommandText = """
            INSERT INTO runs(run_id,generated_at,network_label,node_id,source_path,profile_count,passed_stages,failed_stages,report_json,imported_at)
            VALUES($id,$at,$network,$node,$path,$profiles,$passed,$failed,$json,$imported)
            ON CONFLICT(run_id) DO UPDATE SET generated_at=excluded.generated_at,network_label=excluded.network_label,node_id=excluded.node_id,source_path=excluded.source_path,profile_count=excluded.profile_count,passed_stages=excluded.passed_stages,failed_stages=excluded.failed_stages,report_json=excluded.report_json,imported_at=excluded.imported_at;
            """;
        run.Parameters.AddWithValue("$id", runId);
        run.Parameters.AddWithValue("$at", generatedAt);
        run.Parameters.AddWithValue("$network", network);
        run.Parameters.AddWithValue("$node", (object?)node ?? DBNull.Value);
        run.Parameters.AddWithValue("$path", Path.GetFullPath(path));
        run.Parameters.AddWithValue("$profiles", profiles.Length);
        run.Parameters.AddWithValue("$passed", stages.Count(item => GetString(item.stage, "status") == "passed"));
        run.Parameters.AddWithValue("$failed", stages.Count(item => GetString(item.stage, "status") is "failed" or "partial"));
        run.Parameters.AddWithValue("$json", root.GetRawText());
        run.Parameters.AddWithValue("$imported", DateTimeOffset.UtcNow.ToString("O"));
        await run.ExecuteNonQueryAsync(cancellationToken);

        var delete = connection.CreateCommand();
        delete.Transaction = (SqliteTransaction)transaction;
        delete.CommandText = "DELETE FROM stages WHERE run_id=$id";
        delete.Parameters.AddWithValue("$id", runId);
        await delete.ExecuteNonQueryAsync(cancellationToken);
        foreach (var (profile, stage) in stages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var insert = connection.CreateCommand();
            insert.Transaction = (SqliteTransaction)transaction;
            insert.CommandText = "INSERT INTO stages(run_id,profile_key,profile_name,stage,status,elapsed_ms,error,data_json) VALUES($run,$profile,$name,$stage,$status,$elapsed,$error,$data)";
            insert.Parameters.AddWithValue("$run", runId);
            var fingerprint = GetString(profile, "profileFingerprint") ?? "no-fingerprint";
            var instance = GetString(profile, "profileId") ?? "unknown";
            insert.Parameters.AddWithValue("$profile", $"{fingerprint}:{instance}");
            insert.Parameters.AddWithValue("$name", (object?)GetString(profile, "name") ?? DBNull.Value);
            insert.Parameters.AddWithValue("$stage", GetString(stage, "stage") ?? "unknown");
            insert.Parameters.AddWithValue("$status", GetString(stage, "status") ?? "unknown");
            insert.Parameters.AddWithValue("$elapsed", stage.TryGetProperty("elapsedMs", out var elapsed) && elapsed.TryGetInt64(out var ms) ? ms : 0);
            insert.Parameters.AddWithValue("$error", stage.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String ? error.GetString()! : DBNull.Value);
            insert.Parameters.AddWithValue("$data", stage.TryGetProperty("data", out var data) ? data.GetRawText() : DBNull.Value);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async Task<IReadOnlyList<HistoryRow>> ListAsync(int limit)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT run_id,generated_at,network_label,profile_count,passed_stages,failed_stages FROM runs ORDER BY generated_at DESC LIMIT $limit";
        command.Parameters.AddWithValue("$limit", limit);
        var rows = new List<HistoryRow>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync()) rows.Add(new HistoryRow(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5)));
        return rows;
    }

    public async ValueTask DisposeAsync() => await connection.DisposeAsync();
    private static string? GetString(JsonElement element, string property) => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

internal sealed record HistoryRow(string RunId, string GeneratedAt, string NetworkLabel, int ProfileCount, int PassedStages, int FailedStages);
