using System.Text;
using System.Text.Json;

internal static class NetworkMatrixBuilder
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: LokiTrafficLab matrix <report-or-directory> [--out network-matrix.json]");
            return 2;
        }
        var source = Path.GetFullPath(args[0]);
        var files = Directory.Exists(source)
            ? Directory.EnumerateFiles(source, "profile-lab-*.json", SearchOption.TopDirectoryOnly).Order().ToArray()
            : File.Exists(source) ? new[] { source } : [];
        if (files.Length == 0)
        {
            Console.Error.WriteLine("No profile-lab JSON reports found.");
            return 2;
        }
        var rows = new List<NetworkMatrixRow>();
        foreach (var file in files)
        {
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(file));
            var root = document.RootElement;
            var context = root.TryGetProperty("testContext", out var testContext) ? testContext : default;
            if (!root.TryGetProperty("profiles", out var profiles) || profiles.ValueKind != JsonValueKind.Array) continue;
            foreach (var profile in profiles.EnumerateArray())
            {
                var stages = profile.TryGetProperty("stages", out var stageArray)
                    ? stageArray.EnumerateArray().ToDictionary(item => String(item, "stage") ?? "unknown", item => String(item, "status") ?? "unknown", StringComparer.OrdinalIgnoreCase)
                    : [];
                var tcpData = ReadStageData(profile, "endpoint.tcpSeries");
                var endpointIps = ReadStrings(profile, "observedEndpointIps");
                var failure = stages.FirstOrDefault(item => item.Value is "failed" or "partial");
                rows.Add(new NetworkMatrixRow(
                    String(root, "runId") ?? "unknown",
                    String(root, "generatedAt") ?? "unknown",
                    String(root, "networkLabel") ?? "unknown",
                    context.ValueKind == JsonValueKind.Object ? String(context, "runGroupId") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "nodeId") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "scenario") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "country") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "region") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "accessType") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "provider") : null,
                    context.ValueKind == JsonValueKind.Object ? String(context, "restrictionState") : null,
                    context.ValueKind == JsonValueKind.Object ? Number(context, "latitude") : null,
                    context.ValueKind == JsonValueKind.Object ? Number(context, "longitude") : null,
                    String(profile, "profileId") ?? "unknown",
                    Integer(profile, "sourceOrdinal"),
                    String(profile, "profileFingerprint") ?? String(profile, "profileId") ?? "unknown",
                    String(profile, "name") ?? "unknown",
                    endpointIps.FirstOrDefault(),
                    Number(tcpData, "p50Ms"),
                    stages.GetValueOrDefault("endpoint.dns"),
                    stages.GetValueOrDefault("endpoint.tcp"),
                    stages.GetValueOrDefault("endpoint.tlsFallback"),
                    stages.GetValueOrDefault("tunnel.authenticatedEndToEnd"),
                    stages.GetValueOrDefault("tunnel.udp"),
                    stages.GetValueOrDefault("tunnel.xudpCompatibility"),
                    string.IsNullOrWhiteSpace(failure.Key) ? null : failure.Key,
                    stages.GetValueOrDefault("tunnel.authenticatedEndToEnd") == "passed"));
            }
        }
        var inferences = new List<MatrixInference>();
        var locationEstimates = new List<LatencyLocationEstimate>();
        foreach (var group in rows.GroupBy(item => item.ProfileFingerprint, StringComparer.OrdinalIgnoreCase))
        {
            var standalone = group.Where(item => !string.Equals(item.Scenario, "concurrent", StringComparison.OrdinalIgnoreCase)).ToArray();
            var concurrent = group.Where(item => string.Equals(item.Scenario, "concurrent", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (standalone.Any(item => item.Usable) && concurrent.Any(item => !item.Usable))
            {
                inferences.Add(new MatrixInference(group.Key, "concurrency-or-device-policy-suspected", "medium", "The profile worked in a standalone scenario but at least one concurrent scenario failed. Session count, source IP, rate limit, and HWID remain competing explanations."));
            }
            var nodes = group.Where(item => !string.IsNullOrWhiteSpace(item.NodeId)).GroupBy(item => item.NodeId!, StringComparer.OrdinalIgnoreCase).ToArray();
            if (nodes.Length >= 2 && nodes.Any(node => node.Any(item => item.Usable)) && nodes.Any(node => node.All(item => !item.Usable)))
            {
                inferences.Add(new MatrixInference(group.Key, "node-or-network-binding-suspected", "low", "The outcome differs consistently by node. Swap networks or use a common egress before attributing the result to HWID."));
            }
            var estimate = EstimateLocation(group.Key, group);
            if (estimate is not null) locationEstimates.Add(estimate);
        }
        var report = new { schemaVersion = "1.0", generatedAt = DateTimeOffset.UtcNow, sourceFiles = files, rows, inferences, locationEstimates };
        var output = Path.GetFullPath(Read(args, "--out") ?? Path.Combine(Directory.Exists(source) ? source : Path.GetDirectoryName(source)!, $"network-matrix-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json"));
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, LabCommands.JsonOptions), new UTF8Encoding(false));
        var csv = Path.ChangeExtension(output, ".csv");
        await WriteCsvAsync(csv, rows);
        Console.WriteLine($"Network matrix: {output}");
        Console.WriteLine($"CSV           : {csv}");
        Console.WriteLine($"Runs/profiles : {rows.Select(item => item.RunId).Distinct().Count()}/{rows.Select(item => item.ProfileFingerprint).Distinct().Count()}");
        Console.WriteLine($"Policy hints  : {inferences.Count}");
        Console.WriteLine($"Geo estimates : {locationEstimates.Count}");
        return 0;
    }

    private static async Task WriteCsvAsync(string path, IReadOnlyList<NetworkMatrixRow> rows)
    {
        static string Csv(object? value) => "\"" + (value?.ToString() ?? "").Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        var properties = typeof(NetworkMatrixRow).GetProperties();
        var builder = new StringBuilder(string.Join(',', properties.Select(property => property.Name)) + "\r\n");
        foreach (var row in rows) builder.AppendLine(string.Join(',', properties.Select(property => Csv(property.GetValue(row)))));
        await File.WriteAllTextAsync(path, builder.ToString(), new UTF8Encoding(false));
    }

    private static string? Read(string[] args, string name) { var index = Array.FindIndex(args, value => value.Equals(name, StringComparison.OrdinalIgnoreCase)); return index >= 0 && index + 1 < args.Length ? args[index + 1] : null; }
    private static string? String(JsonElement element, string property) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static double? Number(JsonElement element, string property) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.TryGetDouble(out var number) ? number : null;
    private static int? Integer(JsonElement element, string property) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.TryGetInt32(out var number) ? number : null;
    private static IReadOnlyList<string> ReadStrings(JsonElement element, string property) => element.TryGetProperty(property, out var values) && values.ValueKind == JsonValueKind.Array ? values.EnumerateArray().Select(item => item.GetString()).Where(value => !string.IsNullOrWhiteSpace(value)).Select(value => value!).ToArray() : [];
    private static JsonElement ReadStageData(JsonElement profile, string stageName)
    {
        if (!profile.TryGetProperty("stages", out var stages)) return default;
        foreach (var stage in stages.EnumerateArray()) if (String(stage, "stage") == stageName && stage.TryGetProperty("data", out var data)) return data;
        return default;
    }

    private static LatencyLocationEstimate? EstimateLocation(string profileFingerprint, IEnumerable<NetworkMatrixRow> source)
    {
        var observations = source
            .Where(item => item.Latitude.HasValue && item.Longitude.HasValue && item.TcpP50Ms is > 0 && !string.IsNullOrWhiteSpace(item.NodeId))
            .GroupBy(item => item.NodeId!, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderBy(item => item.TcpP50Ms).First())
            .ToArray();
        if (observations.Length < 3) return null;
        var feasible = new List<(double lat, double lon)>();
        for (var latitude = -84d; latitude <= 84; latitude += 2)
        {
            for (var longitude = -180d; longitude < 180; longitude += 2)
            {
                var fits = observations.All(item => HaversineKm(latitude, longitude, item.Latitude!.Value, item.Longitude!.Value) <= Math.Max(200, item.TcpP50Ms!.Value * 100));
                if (fits) feasible.Add((latitude, longitude));
            }
        }
        if (feasible.Count == 0) return new LatencyLocationEstimate(profileFingerprint, observations.Length, null, null, null, "inconclusive", 0, observations.Select(ToVantage).ToArray(), "No coarse grid point satisfied every speed-of-light upper bound; node coordinates, clocks, or RTT samples may be inconsistent.");
        var latitudeEstimate = feasible.Average(item => item.lat);
        var longitudeEstimate = CircularMeanLongitude(feasible.Select(item => item.lon));
        var radius = feasible.Max(item => HaversineKm(latitudeEstimate, longitudeEstimate, item.lat, item.lon));
        var confidence = radius <= 250 ? "medium" : "low";
        return new LatencyLocationEstimate(profileFingerprint, observations.Length, Math.Round(latitudeEstimate, 2), Math.Round(longitudeEstimate, 2), Math.Round(radius, 0), confidence, feasible.Count, observations.Select(ToVantage).ToArray(), "RTT supplies only an upper-distance bound. Routing inflation, anycast, relays, and queueing make this a coarse region estimate, never a physical server address.");
    }

    private static LatencyVantage ToVantage(NetworkMatrixRow row) => new(row.NodeId!, row.NetworkLabel, row.Latitude!.Value, row.Longitude!.Value, row.TcpP50Ms!.Value, Math.Max(200, row.TcpP50Ms.Value * 100));
    private static double CircularMeanLongitude(IEnumerable<double> longitudes)
    {
        var radians = longitudes.Select(value => value * Math.PI / 180).ToArray();
        return Math.Atan2(radians.Average(Math.Sin), radians.Average(Math.Cos)) * 180 / Math.PI;
    }
    private static double HaversineKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double radius = 6371;
        static double Rad(double value) => value * Math.PI / 180;
        var dLat = Rad(lat2 - lat1); var dLon = Rad(lon2 - lon1);
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) + Math.Cos(Rad(lat1)) * Math.Cos(Rad(lat2)) * Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return radius * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
    }
}

internal sealed record NetworkMatrixRow(string RunId, string GeneratedAt, string NetworkLabel, string? RunGroupId, string? NodeId, string? Scenario, string? Country, string? Region, string? AccessType, string? Provider, string? RestrictionState, double? Latitude, double? Longitude, string ProfileId, int? SourceOrdinal, string ProfileFingerprint, string ProfileName, string? EndpointIp, double? TcpP50Ms, string? DnsStatus, string? TcpStatus, string? TlsStatus, string? AuthenticatedStatus, string? UdpStatus, string? XudpStatus, string? FirstFailureStage, bool Usable);
internal sealed record MatrixInference(string ProfileFingerprint, string Value, string Confidence, string Reason);
internal sealed record LatencyVantage(string NodeId, string NetworkLabel, double Latitude, double Longitude, double MinRttMs, double MaximumPhysicalDistanceKm);
internal sealed record LatencyLocationEstimate(string ProfileFingerprint, int VantageCount, double? Latitude, double? Longitude, double? EstimatedRadiusKm, string Confidence, int FeasibleGridPoints, IReadOnlyList<LatencyVantage> Vantages, string Limitation);
