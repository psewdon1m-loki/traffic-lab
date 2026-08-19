using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

internal static class NodeDiagnostics
{
    public static async Task<NodeDiagnosticsReport> CaptureAsync(
        NetworkEnvironment environment,
        IReadOnlyList<ExitIpObservation> directBaseline,
        IReadOnlyList<IpAttribution> directAttribution,
        TestContext context,
        TimeSpan timeout)
    {
        var active = environment.Interfaces.Where(item => item.HasDefaultGateway && !item.LooksLikeTunnel).ToArray();
        var detected = DetectAccessType(active, context.AccessType);
        var gateway = await CaptureGatewayAsync(active, timeout);
        var route = await TraceDirectPathAsync(timeout);
        var directStun = await ProbeDirectStunAsync(timeout);
        var publicIps = directBaseline.Where(item => item.Valid && item.Ip is not null).Select(item => item.Ip!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var localIps = active.SelectMany(item => item.Addresses).Where(value => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork).Distinct().ToArray();
        var ipGeolocation = BuildNodeGeo(directAttribution);
        var deviceLocation = await CaptureDeviceLocationAsync(context, timeout);

        return new NodeDiagnosticsReport
        {
            CapturedAt = DateTimeOffset.UtcNow,
            DeclaredAccessType = context.AccessType,
            DetectedAccessType = detected.Type,
            AccessTypeConfidence = detected.Confidence,
            AccessTypeReason = detected.Reason,
            ActiveInterfaceNames = active.Select(item => item.Name).ToArray(),
            LocalAddresses = active.SelectMany(item => item.Addresses).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            PublicAddresses = publicIps,
            Provider = BuildProvider(directAttribution),
            Geolocation = ipGeolocation,
            DeviceLocation = deviceLocation,
            GeolocationComparison = CompareLocations(deviceLocation, ipGeolocation),
            DirectPerformance = await ProbeDirectPerformanceAsync(timeout),
            Nat = BuildNatReport(localIps, publicIps, directStun, route),
            Gateway = gateway,
            Wifi = await CaptureWifiAsync(timeout),
            Cellular = await CaptureCellularAsync(timeout),
            DirectPath = route,
            Settings = await CaptureAdditionalSettingsAsync(environment, timeout),
            Limitations =
            [
                "The detected access type is an adapter/route observation. USB or Wi-Fi phone tethering can hide an LTE/5G underlay unless the test plan labels it.",
                "NAT presence can be inferred by comparing local, STUN and public addresses; cone/symmetric NAT classification requires a purpose-built multi-address STUN server.",
                "Router manufacturer/model is reported only when the gateway advertises safe UPnP/SSDP metadata. Absence is not evidence that no router exists.",
                "IP geolocation describes a public egress prefix. Device location is reported separately only when explicitly supplied or the operating-system location service grants it; neither source identifies an LTE tower."
            ]
        };
    }

    public static OsiTrafficMap BuildOsiMap(RunReport report)
    {
        var node = report.Node;
        var layers = new List<OsiLayerEvidence>
        {
            new(1, "Physical", node?.DetectedAccessType ?? "unknown", node?.AccessTypeConfidence ?? "low", node?.AccessTypeConfidence.StartsWith("high", StringComparison.OrdinalIgnoreCase) == true ? 97 : 75, "Adapter medium, negotiated link rate and Wi-Fi/cellular radio hints; physical cabling and tower identity are not remotely observable."),
            new(2, "Data link", string.Join(", ", report.Environment.Interfaces.Where(item => item.HasDefaultGateway).Select(item => $"{item.InterfaceType}/OUI {item.MacOui ?? "unknown"}")), "medium", 75, "Local adapter and gateway-neighbor evidence. VLAN tags and upstream carrier L2 are normally hidden from an application."),
            new(3, "Network", $"local={string.Join(',', node?.LocalAddresses ?? [])}; public={string.Join(',', node?.PublicAddresses ?? [])}; NAT={node?.Nat.Presence ?? "unknown"}", "high", 95, "IP addressing, routes, gateways, traceroute, NAT/CGNAT hints, ASN and geolocation."),
            new(4, "Transport", "TCP connect, UDP DNS/STUN and QUIC reachability", "high", 97, "Measured ports, RTT, loss-like failures and QUIC handshake. Remote firewalls remain inferential."),
            new(5, "Session", "VLESS authentication, repeated-request lifetime and negative controls", "high", 97, "Client-visible session establishment; server session policy and HWID panel state remain private."),
            new(6, "Presentation", "TLS 1.2/1.3, REALITY/SNI, ALPN and certificate/SPKI fingerprints", "high", 90, "Observed cryptographic presentation. The exact configured REALITY target remains server-side."),
            new(7, "Application", "DNS, HTTP/1.1, HTTP/2, HTTP/3-path QUIC, WebSocket when applicable, upload/download", "high", 97, "Application responses, tunneled DNS behavior, exit IP and bounded throughput."
            )
        };

        var paths = new List<OsiProfilePath>();
        foreach (var profile in report.Profiles)
        {
            var entry = profile.ObservedEndpointIps.FirstOrDefault() ?? profile.Declared.Host ?? "unknown";
            var exits = profile.ExitAttribution.Select(item => item.Ip).Where(item => !string.IsNullOrWhiteSpace(item)).Cast<string>().Distinct().ToArray();
            var stages = profile.Stages.ToDictionary(item => item.Stage, item => item.Status, StringComparer.OrdinalIgnoreCase);
            paths.Add(new OsiProfilePath
            {
                ProfileId = profile.ProfileId,
                ProfileName = profile.Name,
                Nodes =
                [
                    new("device", "test-device", Environment.MachineName, node?.LocalAddresses ?? [], "high"),
                    new("gateway", "local-gateway", node?.Gateway.ModelLabel ?? node?.Gateway.Address ?? "not-observed", node?.Gateway.Address is null ? [] : [node.Gateway.Address], node?.Gateway.Address is null ? "low" : "high"),
                    new("isp", "provider/nat", node?.Provider.DisplayName ?? "unknown provider", node?.PublicAddresses ?? [], node?.Provider.Confidence ?? "low"),
                    new("entry", "proxy-entry", entry, profile.ObservedEndpointIps, stages.GetValueOrDefault("endpoint.tcp") == "passed" ? "high" : "low"),
                    new("tunnel", "authenticated-tunnel", $"{profile.Declared.Security}/{profile.Declared.Protocol} over {profile.Declared.Network}", [], stages.GetValueOrDefault("tunnel.authenticatedEndToEnd") == "passed" ? "high" : "low"),
                    new("exit", "proxy-exit", exits.Length == 0 ? "unknown" : string.Join(',', exits), exits, exits.Length == 0 ? "low" : "high"),
                    new("application", "internet-service", "HTTPS/DNS/STUN test services", [], stages.GetValueOrDefault("tunnel.http") == "passed" ? "high" : "low")
                ],
                Edges =
                [
                    new("device", "gateway", [1,2,3], node?.DetectedAccessType ?? "unknown", "local interface/default-gateway evidence", "observed local edge 97%; hidden bridge/VLAN details 3%/unknown"),
                    new("gateway", "isp", [2,3], node?.Nat.Presence ?? "NAT unknown", "public-IP, STUN and direct traceroute evidence", node?.Nat.Presence == "observed" ? "translated/NAT edge 98%; no NAT 2%" : "NAT topology unknown; alternatives are not distinguishable"),
                    new("isp", "entry", [3,4], $"TCP/{profile.Declared.Port}", stages.GetValueOrDefault("endpoint.tcp") ?? "not-tested", stages.GetValueOrDefault("endpoint.tcp") == "passed" ? "reachable transport edge 99%; transient false positive 1%" : "reachability unknown"),
                    new("entry", "tunnel", [5,6], $"VLESS/{profile.Declared.Security}", stages.GetValueOrDefault("tunnel.authenticatedEndToEnd") ?? "not-tested", stages.GetValueOrDefault("tunnel.authenticatedEndToEnd") == "passed" ? "authenticated session edge 99%; alternative explanation 1%" : "authenticated edge not proven"),
                    new("tunnel", "exit", [3,4,5], "server outbound (black box)", exits.Length > 0 ? "exit observed; hop count unknown" : "not observed", exits.Length > 0 ? "exit identity observed 95%; exact direct/relay topology remains split across connection.json alternatives" : "no probability assigned without an exit observation"),
                    new("exit", "application", [4,6,7], "TCP/UDP/QUIC + TLS/HTTP/DNS", stages.GetValueOrDefault("tunnel.http") ?? "not-tested", stages.GetValueOrDefault("tunnel.http") == "passed" ? "application edge 99%; transient/cached alternative 1%" : "application edge not proven")
                ]
            });
        }
        return new OsiTrafficMap
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            Layers = layers,
            Profiles = paths,
            Interpretation = "This is an evidence graph, not a packet capture. Each edge states what the portable client actually observed and where server/provider internals remain opaque."
        };
    }

    public static async Task WriteOsiMarkdownAsync(string path, RunReport report)
    {
        await File.WriteAllTextAsync(path, BuildOsiMarkdown(report), new UTF8Encoding(false));
    }

    public static string BuildOsiMarkdown(RunReport report, string? profileId = null)
    {
        static string Text(string? value) => (value ?? "unknown").Replace("\"", "'", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
        var map = report.OsiMap ?? BuildOsiMap(report);
        var builder = new StringBuilder();
        builder.AppendLine("# Traffic Lab OSI evidence map").AppendLine();
        builder.AppendLine($"Generated: `{map.GeneratedAt:O}`  ");
        builder.AppendLine($"Test node: `{Text(report.TestContext.NodeId)}` / `{Text(report.NetworkLabel)}`  ");
        builder.AppendLine($"Test type: `{Text(report.TestType.ToUpperInvariant())}`; extended settings: soak `{report.ExtendedTest.SoakDurationSeconds?.ToString() ?? "not applicable"}` seconds, parallel flows `{report.ExtendedTest.ParallelFlows?.ToString() ?? "not applicable"}`, interruption `{report.ExtendedTest.NetworkLossSeconds?.ToString() ?? "not applicable"}` seconds  ");
        builder.AppendLine("Heuristic percentages express relative evidence confidence and are not calibrated statistical probabilities.  ");
        if (report.Node is not null)
        {
            builder.AppendLine($"Access: `{Text(report.Node.DetectedAccessType)}`; public IP: `{Text(string.Join(", ", report.Node.PublicAddresses))}`; NAT: `{Text(report.Node.Nat.Presence)}`  ");
            builder.AppendLine($"Provider: `{Text(report.Node.Provider.DisplayName)}`; gateway: `{Text(report.Node.Gateway.ModelLabel ?? report.Node.Gateway.Address)}`").AppendLine();
        }
        builder.AppendLine("## Seven-layer evidence").AppendLine();
        builder.AppendLine("| OSI | Layer | Observation | Confidence | Heuristic weight | Limitation |");
        builder.AppendLine("|---:|---|---|---|---:|---|");
        foreach (var layer in map.Layers)
            builder.AppendLine($"| {layer.Layer} | {Text(layer.Name)} | {Text(layer.Observation).Replace("|", "\\|", StringComparison.Ordinal)} | {Text(layer.Confidence)} | {layer.ConfidenceWeightPercent}% | {Text(layer.Limitation).Replace("|", "\\|", StringComparison.Ordinal)} |");

        foreach (var profile in map.Profiles.Where(item => profileId is null || item.ProfileId.Equals(profileId, StringComparison.OrdinalIgnoreCase)))
        {
            builder.AppendLine().AppendLine($"## {Text(profile.ProfileId)} - {Text(profile.ProfileName)}").AppendLine();
            builder.AppendLine("```mermaid").AppendLine("flowchart LR");
            foreach (var node in profile.Nodes)
            {
                var nodeId = Regex.Replace(profile.ProfileId + "_" + node.Id, "[^A-Za-z0-9_]", "_");
                var addresses = node.Addresses.Count == 0 ? "" : "<br/>" + Text(string.Join(", ", node.Addresses));
                builder.AppendLine($"  {nodeId}[\"{Text(node.Role)}<br/>{Text(node.Label)}{addresses}<br/>confidence: {Text(node.Confidence)}\"]");
            }
            foreach (var edge in profile.Edges)
            {
                var from = Regex.Replace(profile.ProfileId + "_" + edge.From, "[^A-Za-z0-9_]", "_");
                var to = Regex.Replace(profile.ProfileId + "_" + edge.To, "[^A-Za-z0-9_]", "_");
                builder.AppendLine($"  {from} -->|\"L{string.Join("/L", edge.OsiLayers)} {Text(edge.Transport)}; {Text(edge.Evidence)}; {Text(edge.Likelihood)}\"| {to}");
            }
            builder.AppendLine("```");
        }
        builder.AppendLine().AppendLine($"> {Text(map.Interpretation)}");
        return builder.ToString();
    }

    private static (string Type, string Confidence, string Reason) DetectAccessType(IReadOnlyList<NetworkInterfaceInfo> active, string? declared)
    {
        if (!string.IsNullOrWhiteSpace(declared) && !declared.Equals("unknown", StringComparison.OrdinalIgnoreCase) && !declared.Equals("auto", StringComparison.OrdinalIgnoreCase))
            return (NormalizeAccess(declared), "high-declared", "The non-secret test plan explicitly labels the access network; adapter evidence is retained separately.");
        var text = string.Join(' ', active.Select(item => item.InterfaceType + " " + item.Description + " " + item.Name));
        if (Regex.IsMatch(text, @"\b(?:wwan|cellular|mobile|lte|5g|4g)\b|мобиль|сотов", RegexOptions.IgnoreCase)) return ("cellular", "medium", "The active default-route adapter identifies itself as WWAN/cellular.");
        if (active.Any(item => item.InterfaceType.Equals("Wireless80211", StringComparison.OrdinalIgnoreCase)) || Regex.IsMatch(text, "wi-?fi|wireless|wlan|беспровод", RegexOptions.IgnoreCase)) return ("wifi", "high", "The active default-route adapter is IEEE 802.11/wireless.");
        if (Regex.IsMatch(text, "rndis|tether|usb.*ethernet|remote ndis", RegexOptions.IgnoreCase)) return ("phone-tethering-or-usb-ethernet", "medium", "The adapter resembles USB/RNDIS tethering, but the phone underlay is hidden.");
        if (active.Any(item => item.InterfaceType.Equals("Ppp", StringComparison.OrdinalIgnoreCase))) return ("ppp-or-cellular", "medium", "The active default-route adapter uses PPP.");
        if (active.Any(item => item.InterfaceType.Contains("Ethernet", StringComparison.OrdinalIgnoreCase))) return ("ethernet", "high", "The active default-route adapter is Ethernet.");
        return ("unknown", "low", "No unambiguous active default-route adapter type was observed.");
    }

    private static string NormalizeAccess(string value)
    {
        var lower = value.Trim().ToLowerInvariant();
        if (Regex.IsMatch(lower, "lte|5g|4g|wwan|cell")) return "cellular";
        if (Regex.IsMatch(lower, "wifi|wi-fi|wlan")) return "wifi";
        if (Regex.IsMatch(lower, "ethernet|lan")) return "ethernet";
        return lower;
    }

    private static NodeProvider BuildProvider(IReadOnlyList<IpAttribution> attributions)
    {
        var valid = attributions.Where(item => item.Status is "success" or "partial").ToArray();
        var asns = valid.SelectMany(item => item.OriginAsns).Distinct().ToArray();
        var names = valid.Select(item => item.AsnHolder ?? item.RdapName).Where(item => !string.IsNullOrWhiteSpace(item)).Cast<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return new NodeProvider
        {
            DisplayName = names.FirstOrDefault(),
            Names = names,
            Asns = asns,
            ReverseDnsNames = valid.Select(item => item.ReverseDns).Where(item => !string.IsNullOrWhiteSpace(item)).Cast<string>().Distinct().ToArray(),
            Confidence = asns.Length > 0 ? "high-prefix-owner" : names.Length > 0 ? "medium" : "low",
            Limitation = "The BGP/RDAP holder may be a transit or hosting organization rather than the retail ISP shown on a bill."
        };
    }

    private static NodeGeolocation BuildNodeGeo(IReadOnlyList<IpAttribution> attributions)
    {
        var hints = attributions.SelectMany(item => item.GeolocationHints).Where(item => item.Latitude.HasValue && item.Longitude.HasValue).ToArray();
        var countries = attributions.Select(item => item.RdapCountry).Concat(hints.Select(item => item.Country)).Where(item => !string.IsNullOrWhiteSpace(item)).Cast<string>().GroupBy(item => item, StringComparer.OrdinalIgnoreCase).OrderByDescending(group => group.Count()).ToArray();
        return new NodeGeolocation
        {
            Country = countries.FirstOrDefault()?.Key,
            Latitude = hints.Length == 0 ? null : Math.Round(hints.Average(item => item.Latitude!.Value), 4),
            Longitude = hints.Length == 0 ? null : Math.Round(hints.Average(item => item.Longitude!.Value), 4),
            EstimatedRadiusKm = hints.Length == 0 ? null : 500,
            Confidence = hints.Length == 0 ? "unavailable" : "low-ip-geolocation",
            Sources = hints.Select(item => item.Source).Distinct().ToArray(),
            Limitation = "This locates the public IP prefix only. It must not be treated as the physical location of the PC, router or LTE cell."
        };
    }

    private static async Task<DeviceLocationObservation> CaptureDeviceLocationAsync(TestContext context, TimeSpan timeout)
    {
        if (context.Latitude.HasValue && context.Longitude.HasValue)
            return new DeviceLocationObservation
            {
                Status = "observed",
                Latitude = Math.Round(context.Latitude.Value, 6),
                Longitude = Math.Round(context.Longitude.Value, 6),
                Source = "test-context/user-supplied",
                Confidence = "high-user-declared",
                CapturedAt = DateTimeOffset.UtcNow,
                Limitation = "Coordinates were supplied by the test plan/operator and were not independently verified by Traffic Lab."
            };

        if (OperatingSystem.IsWindows())
        {
            const string script = """
                $ErrorActionPreference='Stop'
                Add-Type -AssemblyName System.Runtime.WindowsRuntime
                $locator=[Windows.Devices.Geolocation.Geolocator,Windows.Devices.Geolocation,ContentType=WindowsRuntime]::new()
                $locator.DesiredAccuracy=[Windows.Devices.Geolocation.PositionAccuracy]::High
                $operation=$locator.GetGeopositionAsync([TimeSpan]::FromMinutes(10),[TimeSpan]::FromSeconds(8))
                $method=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 } | Select-Object -First 1
                $task=$method.MakeGenericMethod([Windows.Devices.Geolocation.Geoposition]).Invoke($null,@($operation))
                if(-not $task.Wait(10000)){throw 'Windows location request timed out'}
                $coordinate=$task.Result.Coordinate
                [pscustomobject]@{latitude=$coordinate.Point.Position.Latitude;longitude=$coordinate.Point.Position.Longitude;accuracyMeters=$coordinate.Accuracy;altitudeMeters=$coordinate.Point.Position.Altitude;capturedAt=$coordinate.Timestamp.ToString('O');source='windows-location-api'} | ConvertTo-Json -Compress
                """;
            var result = await RunProcessAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], TimeSpan.FromSeconds(Math.Min(14, Math.Max(10, timeout.TotalSeconds))));
            var parsed = ParseDeviceLocationJson(result.Stdout, "windows-location-api", result.Stderr);
            if (parsed.Status == "observed") return parsed;
            return parsed with { Limitation = "Windows Location Service did not return a position. Location may be disabled, denied, stale, or unavailable on this hardware." };
        }

        if (OperatingSystem.IsLinux())
        {
            foreach (var command in new[] { "where-am-i", "geoclue-where-am-i" })
            {
                var result = await RunProcessAsync(command, [], TimeSpan.FromSeconds(Math.Min(8, Math.Max(3, timeout.TotalSeconds))));
                if (result.ExitCode != 0) continue;
                var latitude = ParseFirstDouble(Regex.Match(result.Stdout, @"(?im)^\s*Latitude\s*:\s*(?<value>-?[\d.]+)").Groups["value"].Value);
                var longitude = ParseFirstDouble(Regex.Match(result.Stdout, @"(?im)^\s*Longitude\s*:\s*(?<value>-?[\d.]+)").Groups["value"].Value);
                var accuracy = ParseFirstDouble(Regex.Match(result.Stdout, @"(?im)^\s*Accuracy\s*:\s*(?<value>[\d.]+)").Groups["value"].Value);
                if (latitude.HasValue && longitude.HasValue)
                    return new DeviceLocationObservation
                    {
                        Status = "observed",
                        Latitude = Math.Round(latitude.Value, 6),
                        Longitude = Math.Round(longitude.Value, 6),
                        AccuracyMeters = accuracy,
                        CapturedAt = DateTimeOffset.UtcNow,
                        Source = "geoclue/system-location",
                        Confidence = accuracy is <= 100 ? "high-os-location" : "medium-os-location",
                        Limitation = "GeoClue position is supplied by the operating system and may combine Wi-Fi, GNSS and network hints."
                    };
            }
            return new DeviceLocationObservation
            {
                Status = "unavailable",
                Source = "geoclue/system-location",
                Confidence = "unavailable",
                Limitation = "No automatic GeoClue client was available or authorized. Use --latitude/--longitude or test-plan coordinates without installing a Traffic Lab dependency."
            };
        }

        return new DeviceLocationObservation { Status = "unsupported", Confidence = "unavailable", Limitation = "Automatic device location is not implemented for this platform." };
    }

    private static DeviceLocationObservation ParseDeviceLocationJson(string json, string source, string error)
    {
        try
        {
            using var document = JsonDocument.Parse(json.Trim());
            var root = document.RootElement;
            var latitude = root.GetProperty("latitude").GetDouble();
            var longitude = root.GetProperty("longitude").GetDouble();
            var accuracy = root.TryGetProperty("accuracyMeters", out var accuracyValue) && accuracyValue.TryGetDouble(out var meters) ? meters : (double?)null;
            return new DeviceLocationObservation
            {
                Status = "observed",
                Latitude = Math.Round(latitude, 6),
                Longitude = Math.Round(longitude, 6),
                AccuracyMeters = accuracy,
                AltitudeMeters = root.TryGetProperty("altitudeMeters", out var altitude) && altitude.TryGetDouble(out var altitudeMeters) ? altitudeMeters : null,
                CapturedAt = root.TryGetProperty("capturedAt", out var captured) && DateTimeOffset.TryParse(captured.GetString(), out var capturedAt) ? capturedAt : DateTimeOffset.UtcNow,
                Source = source,
                Confidence = accuracy is <= 100 ? "high-os-location" : accuracy is <= 1000 ? "medium-os-location" : "low-os-location",
                Limitation = "Operating-system location can be stale or inferred and is not proof of the access point, router, or LTE-cell position."
            };
        }
        catch
        {
            return new DeviceLocationObservation { Status = "unavailable", Source = source, Confidence = "unavailable", Error = ProgramAccess.Truncate(ProgramAccess.Redact(error), 300) };
        }
    }

    private static DeviceIpGeolocationComparison CompareLocations(DeviceLocationObservation device, NodeGeolocation ip)
    {
        if (!device.Latitude.HasValue || !device.Longitude.HasValue || !ip.Latitude.HasValue || !ip.Longitude.HasValue)
            return new DeviceIpGeolocationComparison
            {
                Status = "inconclusive",
                Interpretation = "Both an OS/device position and an IP-prefix position are required for a distance comparison."
            };
        var distance = HaversineKm(device.Latitude.Value, device.Longitude.Value, ip.Latitude.Value, ip.Longitude.Value);
        return new DeviceIpGeolocationComparison
        {
            Status = distance <= 100 ? "consistent" : distance <= 500 ? "coarsely-consistent" : "divergent",
            DistanceKm = Math.Round(distance, 1),
            DeviceAccuracyMeters = device.AccuracyMeters,
            IpEstimatedRadiusKm = ip.EstimatedRadiusKm,
            Interpretation = distance <= 100
                ? "The device and public-prefix hints are geographically compatible at city/region scale."
                : distance <= 500
                    ? "The hints agree only at broad regional scale; IP geolocation is coarse."
                    : "The public-IP location is far from the device position, which can indicate remote egress, VPN/proxy routing, mobile-core breakout, or inaccurate IP geolocation."
        };
    }

    private static double HaversineKm(double latitude1, double longitude1, double latitude2, double longitude2)
    {
        const double radius = 6371.0088;
        var dLat = (latitude2 - latitude1) * Math.PI / 180;
        var dLon = (longitude2 - longitude1) * Math.PI / 180;
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2)
            + Math.Cos(latitude1 * Math.PI / 180) * Math.Cos(latitude2 * Math.PI / 180) * Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return radius * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
    }

    private static async Task<DirectPerformanceReport> ProbeDirectPerformanceAsync(TimeSpan timeout)
    {
        using var client = SpeedTestEngine.CreateDirectClient(timeout);
        var detailed = await SpeedTestEngine.MeasureAsync(client, SpeedTestSettings.Normal, "direct");
        var downloadSeries = detailed.Series.FirstOrDefault(item => item.Direction == "download" && item.Flows == 1);
        var uploadSeries = detailed.Series.FirstOrDefault(item => item.Direction == "upload" && item.Flows == 1);
        var downloadAttempts = ToLegacySamples(downloadSeries).ToArray();
        var uploadAttempts = ToLegacySamples(uploadSeries).ToArray();
        var download = Representative(downloadAttempts, "download");
        var upload = Representative(uploadAttempts, "upload");
        var effectiveRates = downloadAttempts.Select(item => item.EffectiveMegabitsPerSecond).Where(item => item.HasValue && item.Value > 0).Select(item => item!.Value).ToArray();
        return new DirectPerformanceReport
        {
            Status = download.Success || upload.Success || detailed.IdleLatency.Successful > 0 ? "observed" : "unavailable",
            LatencyAttemptsMs = detailed.IdleLatency.SamplesMs,
            LatencyP50Ms = detailed.IdleLatency.P50Ms,
            Download = download,
            DownloadAttempts = downloadAttempts,
            ColdDownload = downloadAttempts.FirstOrDefault(),
            WarmDownloads = downloadAttempts.Skip(1).ToArray(),
            DownloadEffectiveVariabilityRatio = effectiveRates.Length < 2 ? null : Math.Round(effectiveRates.Max() / effectiveRates.Min(), 2),
            Upload = upload,
            Errors = detailed.Series.SelectMany(item => item.ConfidenceReasons).Distinct().ToArray(),
            DetailedSpeed = detailed,
            Interpretation = "Adaptive calibration selects a payload for three steady-state attempts. The median payload rate is primary; effective rate, duration, byte-cap flags, loaded latency and variation bound confidence."
        };

        static IReadOnlyList<ThroughputSample> ToLegacySamples(SpeedFlowSeries? series)
            => series?.Attempts.Where(item => item.Role == "measurement").Select(item => new ThroughputSample
            {
                Direction = series.Direction,
                Success = item.Success,
                RequestedBytes = checked(item.RequestedBytesPerFlow * item.Flows),
                TransferredBytes = item.TransferredBytes,
                ElapsedMs = item.ElapsedMs,
                FirstByteMs = item.PayloadElapsedMs.HasValue ? Math.Max(0, item.ElapsedMs - item.PayloadElapsedMs.Value) : null,
                PayloadTransferMs = item.PayloadElapsedMs,
                MegabitsPerSecond = item.EffectiveMbps,
                EffectiveMegabitsPerSecond = item.EffectiveMbps,
                PayloadTransferMegabitsPerSecond = item.PayloadMbps,
                MetricKind = "adaptive-time-window-throughput",
                Interpretation = "Compatibility projection of the adaptive speed measurement.",
                Error = item.Error
            }).ToArray() ?? [];

        static ThroughputSample Representative(IReadOnlyList<ThroughputSample> samples, string direction)
        {
            var successful = samples.Where(item => item.Success).OrderBy(item => item.PayloadTransferMegabitsPerSecond ?? item.EffectiveMegabitsPerSecond ?? 0).ToArray();
            return successful.Length > 0 ? successful[successful.Length / 2] : samples.FirstOrDefault() ?? new ThroughputSample { Direction = direction };
        }
    }

    private static async Task<ThroughputSample> MeasureDownloadAsync(HttpClient client, TimeSpan timeout)
    {
        const int requested = 2 * 1024 * 1024;
        var watch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout + TimeSpan.FromSeconds(15));
            using var response = await client.GetAsync($"https://speed.cloudflare.com/__down?bytes={requested}&nonce={Guid.NewGuid():N}", HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellation.Token);
            var buffer = new byte[64 * 1024];
            var bytes = 0L;
            long? firstByte = null;
            while (bytes < requested)
            {
                var read = await stream.ReadAsync(buffer, cancellation.Token);
                if (read == 0) break;
                firstByte ??= watch.ElapsedMilliseconds;
                bytes += read;
            }
            watch.Stop();
            return ThroughputSample.From("download", requested, bytes, watch.Elapsed, firstByte, bytes >= requested, null);
        }
        catch (Exception ex) { watch.Stop(); return ThroughputSample.From("download", requested, 0, watch.Elapsed, null, false, ProgramAccess.Redact(ex.Message)); }
    }

    private static async Task<ThroughputSample> MeasureUploadAsync(HttpClient client, TimeSpan timeout)
    {
        const int requested = 512 * 1024;
        var bytes = RandomNumberGenerator.GetBytes(requested);
        var watch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout + TimeSpan.FromSeconds(15));
            using var content = new ByteArrayContent(bytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            using var response = await client.PostAsync("https://speed.cloudflare.com/__up", content, cancellation.Token);
            watch.Stop();
            return ThroughputSample.From("upload", requested, response.IsSuccessStatusCode ? requested : 0, watch.Elapsed, null, response.IsSuccessStatusCode, response.IsSuccessStatusCode ? null : $"HTTP {(int)response.StatusCode}");
        }
        catch (Exception ex) { watch.Stop(); return ThroughputSample.From("upload", requested, 0, watch.Elapsed, null, false, ProgramAccess.Redact(ex.Message)); }
    }

    private static NatDiagnostics BuildNatReport(IReadOnlyList<string> localIps, IReadOnlyList<string> publicIps, StunObservation stun, DirectPathObservation route)
    {
        var parsedLocal = localIps.Select(value => IPAddress.TryParse(value, out var ip) ? ip : null).Where(item => item is not null).Cast<IPAddress>().ToArray();
        var privateLocal = parsedLocal.Where(IsPrivateOrCgnat).Select(item => item.ToString()).ToArray();
        var globalLocal = parsedLocal.Where(item => !IsPrivateOrCgnat(item)).Select(item => item.ToString()).ToArray();
        var publicV4 = publicIps.FirstOrDefault(value => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork);
        var mapped = stun.Success ? stun.MappedAddress : null;
        var presence = "unknown";
        var confidence = "low";
        var reason = "Insufficient local/public/STUN address evidence.";
        if (publicV4 is not null && globalLocal.Contains(publicV4, StringComparer.OrdinalIgnoreCase))
        {
            presence = "not-observed"; confidence = "high"; reason = "A local globally routable IPv4 address equals the observed public IPv4 address.";
        }
        else if (privateLocal.Length > 0 && (publicV4 is not null || mapped is not null))
        {
            presence = "observed"; confidence = "high"; reason = "The active interface has private/CGNAT space while STUN or HTTPS observes a different public address.";
        }
        var cgnatHops = route.Hops.Where(IsCgnatText).ToArray();
        var privateHops = route.Hops.Where(IsPrivateText).Distinct().ToArray();
        return new NatDiagnostics
        {
            Presence = presence,
            Confidence = confidence,
            Reason = reason,
            LocalIpv4 = localIps,
            PublicIpv4 = publicV4,
            StunMappedAddress = mapped,
            StunMappedPort = stun.MappedPort,
            StunServer = stun.Server,
            PrivateRouteHops = privateHops,
            CgnatRouteHops = cgnatHops,
            CgnatHint = cgnatHops.Length > 0,
            MultipleNatLayersHint = privateHops.Length > 1,
            NatBehavior = "not-classified",
            Limitation = "One-client observations identify address translation but cannot reliably distinguish full-cone, restricted, port-restricted and symmetric NAT."
        };
    }

    private static async Task<GatewayDiagnostics> CaptureGatewayAsync(IReadOnlyList<NetworkInterfaceInfo> active, TimeSpan timeout)
    {
        var gateway = active.SelectMany(item => item.Gateways).FirstOrDefault(value => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork);
        if (gateway is null) return new GatewayDiagnostics { Status = "not-observed" };
        var pings = new List<long>();
        for (var i = 0; i < 3; i++)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(gateway, 1000);
                if (reply.Status == IPStatus.Success) pings.Add(reply.RoundtripTime);
            }
            catch { }
        }
        var arp = OperatingSystem.IsWindows()
            ? await RunProcessAsync("arp.exe", ["-a", gateway], TimeSpan.FromSeconds(3))
            : OperatingSystem.IsLinux()
                ? await RunProcessAsync("ip", ["neigh", "show", gateway], TimeSpan.FromSeconds(3))
                : new CommandOutput(-1, "", "unsupported");
        var macMatch = Regex.Match(arp.Stdout, @"(?i)\b(?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2}\b");
        var mac = macMatch.Success ? macMatch.Value.Replace('-', ':').ToUpperInvariant() : null;
        var devices = await DiscoverUpnpDevicesAsync(gateway, timeout);
        var best = devices.FirstOrDefault(item => string.Equals(item.Address, gateway, StringComparison.OrdinalIgnoreCase)) ?? devices.FirstOrDefault();
        return new GatewayDiagnostics
        {
            Status = "observed",
            Address = gateway,
            PingAttempts = 3,
            PingSuccesses = pings.Count,
            PingP50Ms = Percentile(pings, 0.5),
            MacOui = mac is null ? null : string.Join(':', mac.Split(':').Take(3)),
            MacAddressHash = mac is null ? null : HashPrefix(mac),
            UpnpDevices = devices,
            Manufacturer = best?.Manufacturer,
            ModelName = best?.ModelName,
            ModelNumber = best?.ModelNumber,
            ModelLabel = string.Join(' ', new[] { best?.Manufacturer, best?.ModelName, best?.ModelNumber }.Where(value => !string.IsNullOrWhiteSpace(value))).Trim() is { Length: > 0 } label ? label : null,
            Limitation = "A gateway can suppress ICMP, ARP visibility or UPnP. Model fields are self-advertised and are not cryptographically verified."
        };
    }

    private static async Task<IReadOnlyList<UpnpDeviceInfo>> DiscoverUpnpDevicesAsync(string gateway, TimeSpan timeout)
    {
        var results = new List<UpnpDeviceInfo>();
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            var request = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n");
            await udp.SendAsync(request, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(Math.Min(3000, Math.Max(1200, timeout.TotalMilliseconds))));
            var locations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (!cancellation.IsCancellationRequested && locations.Count < 8)
            {
                try
                {
                    var response = await udp.ReceiveAsync(cancellation.Token);
                    var text = Encoding.ASCII.GetString(response.Buffer);
                    var match = Regex.Match(text, @"(?im)^LOCATION\s*:\s*(?<url>\S+)\s*$");
                    if (match.Success) locations.Add(match.Groups["url"].Value.Trim());
                }
                catch (OperationCanceledException) { break; }
            }
            using var client = CreateDirectClient();
            foreach (var location in locations)
            {
                if (!Uri.TryCreate(location, UriKind.Absolute, out var uri) || uri.Scheme != "http" || !IPAddress.TryParse(uri.Host, out var hostIp) || !IsPrivateOrCgnat(hostIp)) continue;
                try
                {
                    using var itemCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var xml = await client.GetStringAsync(uri, itemCancellation.Token);
                    if (xml.Length > 512 * 1024) continue;
                    var document = XDocument.Parse(xml, LoadOptions.None);
                    string? Value(string name) => document.Descendants().FirstOrDefault(item => item.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value.Trim();
                    results.Add(new UpnpDeviceInfo(uri.Host, Value("deviceType"), Value("manufacturer"), Value("modelName"), Value("modelNumber")));
                }
                catch { }
            }
        }
        catch { }
        return results.DistinctBy(item => string.Join('|', item.Address, item.Manufacturer, item.ModelName, item.ModelNumber), StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static async Task<IReadOnlyList<WifiObservation>> CaptureWifiAsync(TimeSpan timeout)
    {
        if (OperatingSystem.IsLinux())
        {
            var devices = await RunProcessAsync("iw", ["dev"], timeout);
            if (devices.ExitCode != 0) return [];
            var linuxObservations = new List<WifiObservation>();
            foreach (Match match in Regex.Matches(devices.Stdout, @"(?m)^\s*Interface\s+(?<name>\S+)"))
            {
                var name = match.Groups["name"].Value;
                var link = await RunProcessAsync("iw", ["dev", name, "link"], timeout);
                var bssid = Regex.Match(link.Stdout, @"(?im)^Connected to\s+(?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})").Groups["mac"].Value;
                var ssid = Regex.Match(link.Stdout, @"(?im)^\s*SSID:\s*(?<value>.+)$").Groups["value"].Value.Trim();
                var signalDbm = ParseFirstInt(Regex.Match(link.Stdout, @"(?im)^\s*signal:\s*(?<value>-?\d+)\s*dBm").Groups["value"].Value);
                var frequency = ParseFirstInt(Regex.Match(link.Stdout, @"(?im)^\s*freq:\s*(?<value>\d+)").Groups["value"].Value);
                linuxObservations.Add(new WifiObservation
                {
                    InterfaceName = name,
                    State = link.Stdout.Contains("Not connected", StringComparison.OrdinalIgnoreCase) ? "disconnected" : link.ExitCode == 0 ? "connected" : "unknown",
                    SsidHash = string.IsNullOrWhiteSpace(ssid) ? null : HashPrefix(ssid),
                    BssidOui = string.IsNullOrWhiteSpace(bssid) ? null : string.Join(':', bssid.Split(':').Take(3)).ToUpperInvariant(),
                    BssidHash = string.IsNullOrWhiteSpace(bssid) ? null : HashPrefix(bssid),
                    RadioType = "linux-iw",
                    Channel = WifiChannel(frequency),
                    SignalPercent = signalDbm.HasValue ? Math.Clamp(2 * (signalDbm.Value + 100), 0, 100) : null,
                    ReceiveRateMbps = ParseFirstDouble(Regex.Match(link.Stdout, @"(?im)^\s*rx bitrate:\s*(?<value>[\d.]+)").Groups["value"].Value),
                    TransmitRateMbps = ParseFirstDouble(Regex.Match(link.Stdout, @"(?im)^\s*tx bitrate:\s*(?<value>[\d.]+)").Groups["value"].Value)
                });
            }
            return linuxObservations;
        }
        if (!OperatingSystem.IsWindows()) return [];
        var result = await RunProcessAsync("netsh.exe", ["wlan", "show", "interfaces"], timeout);
        if (result.ExitCode != 0) return [];
        var blocks = SplitNetshBlocks(result.Stdout, ["Name", "Имя"]);
        var observations = new List<WifiObservation>();
        foreach (var block in blocks)
        {
            var ssid = FindValue(block, "SSID");
            var bssid = FindValue(block, "BSSID");
            var signal = ParseFirstInt(FindValue(block, "Signal", "Сигнал"));
            observations.Add(new WifiObservation
            {
                InterfaceName = FindValue(block, "Name", "Имя"),
                State = FindValue(block, "State", "Состояние"),
                SsidHash = string.IsNullOrWhiteSpace(ssid) ? null : HashPrefix(ssid),
                BssidOui = string.IsNullOrWhiteSpace(bssid) ? null : string.Join(':', bssid.Replace('-', ':').Split(':').Take(3)).ToUpperInvariant(),
                BssidHash = string.IsNullOrWhiteSpace(bssid) ? null : HashPrefix(bssid),
                RadioType = FindValue(block, "Radio type", "Тип радио"),
                Authentication = FindValue(block, "Authentication", "Проверка подлинности"),
                Cipher = FindValue(block, "Cipher", "Шифр"),
                Channel = ParseFirstInt(FindValue(block, "Channel", "Канал")),
                SignalPercent = signal,
                ReceiveRateMbps = ParseFirstDouble(FindValue(block, "Receive rate", "Скорость приема")),
                TransmitRateMbps = ParseFirstDouble(FindValue(block, "Transmit rate", "Скорость передачи"))
            });
        }
        return observations.Where(item => item.InterfaceName is not null || item.SsidHash is not null).ToArray();
    }

    private static async Task<IReadOnlyList<CellularObservation>> CaptureCellularAsync(TimeSpan timeout)
    {
        if (OperatingSystem.IsLinux())
        {
            var list = await RunProcessAsync("mmcli", ["-L"], timeout);
            if (list.ExitCode != 0) return [];
            var observations = new List<CellularObservation>();
            foreach (Match match in Regex.Matches(list.Stdout, @"/Modem/(?<id>\d+)", RegexOptions.IgnoreCase))
            {
                var modem = await RunProcessAsync("mmcli", ["-m", match.Groups["id"].Value, "--output-keyvalue"], timeout);
                if (modem.ExitCode != 0) continue;
                var values = ParseEqualsValues(modem.Stdout);
                observations.Add(new CellularObservation
                {
                    InterfaceName = FindValue(values, "modem.generic.primary-port", "modem.generic.ports"),
                    Manufacturer = FindValue(values, "modem.generic.manufacturer"),
                    Model = FindValue(values, "modem.generic.model"),
                    ProviderName = FindValue(values, "modem.3gpp.operator-name"),
                    SignalPercent = ParseFirstInt(FindValue(values, "modem.generic.signal-quality.value")),
                    Rssi = FindValue(values, "modem.signal.cdma.rssi.value", "modem.signal.lte.rssi.value"),
                    DataClass = FindValue(values, "modem.generic.access-technologies")
                });
            }
            return observations;
        }
        if (!OperatingSystem.IsWindows()) return [];
        var interfaces = await RunProcessAsync("netsh.exe", ["mbn", "show", "interfaces"], timeout);
        if (interfaces.ExitCode != 0 || Regex.IsMatch(interfaces.Stdout, "no mobile broadband|нет интерфейс", RegexOptions.IgnoreCase)) return [];
        var signal = await RunProcessAsync("netsh.exe", ["mbn", "show", "signal", "interface=*"], timeout);
        var provider = await RunProcessAsync("netsh.exe", ["mbn", "show", "homeprovider", "interface=*"], timeout);
        var combined = ParseKeyValues(interfaces.Stdout + Environment.NewLine + signal.Stdout + Environment.NewLine + provider.Stdout);
        var model = FindValue(combined, "Model", "Модель");
        var manufacturer = FindValue(combined, "Manufacturer", "Изготовитель", "Производитель");
        var providerName = FindValue(combined, "Provider Name", "Имя поставщика", "Оператор");
        if (model is null && manufacturer is null && providerName is null) return [];
        return
        [
            new CellularObservation
            {
                InterfaceName = FindValue(combined, "Name", "Имя"),
                Manufacturer = manufacturer,
                Model = model,
                ProviderName = providerName,
                SignalPercent = ParseFirstInt(FindValue(combined, "Signal", "Сигнал")),
                Rssi = FindValue(combined, "RSSI"),
                DataClass = FindValue(combined, "Data class", "Класс данных")
            }
        ];
    }

    private static async Task<AdditionalNetworkSettings> CaptureAdditionalSettingsAsync(NetworkEnvironment environment, TimeSpan timeout)
    {
        var hostsCount = 0;
        string? hostsHash = null;
        var hostsPath = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts")
            : "/etc/hosts";
        try
        {
            var activeLines = File.ReadLines(hostsPath).Select(line => line.Split('#', 2)[0].Trim()).Where(line => !string.IsNullOrWhiteSpace(line)).OrderBy(line => line, StringComparer.OrdinalIgnoreCase).ToArray();
            hostsCount = activeLines.Length;
            hostsHash = activeLines.Length == 0 ? null : HashPrefix(string.Join('\n', activeLines));
        }
        catch { }
        var winHttp = OperatingSystem.IsWindows() ? await RunProcessAsync("netsh.exe", ["winhttp", "show", "proxy"], timeout) : new CommandOutput(-1, "", "unsupported");
        var firewall = OperatingSystem.IsWindows()
            ? await RunProcessAsync("netsh.exe", ["advfirewall", "show", "allprofiles", "state"], timeout)
            : OperatingSystem.IsLinux()
                ? await RunProcessAsync("ufw", ["status", "verbose"], timeout)
                : new CommandOutput(-1, "", "unsupported");
        var nat64 = new List<string>();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            nat64.AddRange((await Dns.GetHostAddressesAsync("ipv4only.arpa", cancellation.Token)).Where(item => item.AddressFamily == AddressFamily.InterNetworkV6).Select(item => item.ToString()));
        }
        catch { }
        var captive = await ProbeCaptivePortalAsync(timeout);
        return new AdditionalNetworkSettings
        {
            DnsServers = environment.DnsServers,
            DnsSuffixes = environment.Interfaces.Select(item => item.DnsSuffix).Where(value => !string.IsNullOrWhiteSpace(value)).Cast<string>().Distinct().ToArray(),
            DhcpInterfaces = environment.Interfaces.Where(item => item.DhcpEnabled == true).Select(item => item.Name).ToArray(),
            PotentialTunnelInterfaces = environment.PotentialTunnelInterfaces,
            WindowsSystemProxyEnabled = environment.WindowsSystemProxyEnabled,
            WindowsAutoDetectEnabled = environment.WindowsAutoDetectEnabled,
            WindowsAutoConfigUrlPresent = environment.WindowsAutoConfigUrlPresent,
            ProxyEnvironmentVariablesPresent = environment.ProxyEnvironmentVariablesPresent,
            WinHttpProxyMode = Regex.IsMatch(winHttp.Stdout, "Direct access|прямой доступ", RegexOptions.IgnoreCase) ? "direct" : winHttp.ExitCode == 0 ? "proxy-or-custom" : "unknown",
            FirewallProvider = OperatingSystem.IsWindows() ? "Windows Defender Firewall" : OperatingSystem.IsLinux() ? "ufw" : "unknown",
            FirewallStateSummary = firewall.ExitCode == 0 ? ExtractFirewallSummary(firewall.Stdout) : "unavailable: " + ProgramAccess.Truncate(firewall.Stderr, 240),
            HostsFileCustomEntryCount = hostsCount,
            HostsFileContentHash = hostsHash,
            HostsFilePath = hostsPath,
            Nat64Ipv4OnlyArpaAnswers = nat64,
            Nat64Or464XlatHint = nat64.Count > 0,
            CaptivePortal = captive,
            RouteTableHash = environment.RouteSnapshot?.RouteTableSha256,
            DefaultRoutes = environment.RouteSnapshot?.DefaultRoutes ?? []
        };
    }

    private static async Task<CaptivePortalObservation> ProbeCaptivePortalAsync(TimeSpan timeout)
    {
        try
        {
            using var handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = timeout };
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var cancellation = new CancellationTokenSource(timeout);
            using var response = await client.GetAsync("http://www.msftconnecttest.com/connecttest.txt", cancellation.Token);
            var body = await response.Content.ReadAsStringAsync(cancellation.Token);
            var expected = (int)response.StatusCode == 200 && body.Trim().Equals("Microsoft Connect Test", StringComparison.Ordinal);
            return new CaptivePortalObservation(expected ? "not-observed" : "possible", (int)response.StatusCode, response.Headers.Location?.Host, expected ? "Expected connectivity-check body returned." : "Redirect or unexpected body returned by the no-proxy HTTP connectivity check.");
        }
        catch (Exception ex) { return new CaptivePortalObservation("unknown", null, null, ProgramAccess.Redact(ex.Message)); }
    }

    private static async Task<DirectPathObservation> TraceDirectPathAsync(TimeSpan timeout)
    {
        var effective = TimeSpan.FromSeconds(Math.Min(20, Math.Max(8, timeout.TotalSeconds + 5)));
        CommandOutput result;
        if (OperatingSystem.IsWindows())
            result = await RunProcessAsync("tracert.exe", ["-d", "-h", "8", "-w", "350", "1.1.1.1"], effective);
        else if (OperatingSystem.IsLinux())
            result = await RunProcessAsync("traceroute", ["-n", "-m", "8", "-w", "1", "-q", "1", "1.1.1.1"], effective);
        else
            return new DirectPathObservation { Status = "unsupported", Target = "1.1.1.1" };
        var hops = new List<string>();
        foreach (var line in result.Stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Where(line => Regex.IsMatch(line, @"^\s*\d+\s+")))
        {
            var addresses = Regex.Matches(line, @"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])").Select(match => match.Value).Where(value => IPAddress.TryParse(value, out _)).ToArray();
            if (addresses.Length > 0) hops.Add(addresses[^1]);
        }
        return new DirectPathObservation { Status = hops.Count > 0 ? "observed" : result.ExitCode == 0 ? "filtered" : "failed", Target = "1.1.1.1", Hops = hops.Distinct().Take(8).ToArray(), Error = result.ExitCode == 0 ? null : ProgramAccess.Truncate(ProgramAccess.Redact(result.Stderr), 300) };
    }

    private static async Task<StunObservation> ProbeDirectStunAsync(TimeSpan timeout)
    {
        var server = new StunServer("stun.cloudflare.com", 3478);
        var watch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var addresses = await Dns.GetHostAddressesAsync(server.Host, cancellation.Token);
            var address = addresses.First(item => item.AddressFamily == AddressFamily.InterNetwork);
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(address, server.Port);
            var transaction = RandomNumberGenerator.GetBytes(12);
            var request = new byte[20] { 0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            transaction.CopyTo(request, 8);
            await udp.SendAsync(request, cancellation.Token);
            var response = await udp.ReceiveAsync(cancellation.Token);
            var mapped = SocksStunProbe.ParseMappedAddress(response.Buffer, transaction);
            watch.Stop();
            return new StunObservation($"{server.Host}:{server.Port}", mapped.address is not null, mapped.address, mapped.port, watch.ElapsedMilliseconds, mapped.address is null ? "No mapped address in STUN response." : null);
        }
        catch (Exception ex) { watch.Stop(); return new StunObservation($"{server.Host}:{server.Port}", false, null, null, watch.ElapsedMilliseconds, ProgramAccess.Redact(ex.Message)); }
    }

    private static HttpClient CreateDirectClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2)
        };
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static async Task<CommandOutput> RunProcessAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };
            foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
            process.Start();
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var cancellation = new CancellationTokenSource(timeout);
            try { await process.WaitForExitAsync(cancellation.Token); }
            catch (OperationCanceledException) { try { process.Kill(true); } catch { } return new CommandOutput(-1, await stdout, "timeout"); }
            return new CommandOutput(process.ExitCode, await stdout, await stderr);
        }
        catch (Exception ex) { return new CommandOutput(-1, "", ProgramAccess.Redact(ex.Message)); }
    }

    private static IReadOnlyList<Dictionary<string, string>> SplitNetshBlocks(string text, IReadOnlyList<string> startKeys)
    {
        var blocks = new List<Dictionary<string, string>>();
        Dictionary<string, string>? current = null;
        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split(':', 2);
            if (parts.Length != 2) continue;
            var key = parts[0].Trim();
            var value = parts[1].Trim();
            if (startKeys.Any(item => key.Equals(item, StringComparison.OrdinalIgnoreCase)))
            {
                if (current is { Count: > 0 }) blocks.Add(current);
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
            current ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            current[key] = value;
        }
        if (current is { Count: > 0 }) blocks.Add(current);
        return blocks;
    }

    private static Dictionary<string, string> ParseKeyValues(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split(':', 2);
            if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[0]) && !string.IsNullOrWhiteSpace(parts[1])) result[parts[0].Trim()] = parts[1].Trim();
        }
        return result;
    }

    private static Dictionary<string, string> ParseEqualsValues(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split('=', 2);
            if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[0]) && !string.IsNullOrWhiteSpace(parts[1]))
                result[parts[0].Trim()] = parts[1].Trim();
        }
        return result;
    }

    private static string? FindValue(IReadOnlyDictionary<string, string> values, params string[] keys)
    {
        foreach (var key in keys)
            if (values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)) return value;
        return null;
    }

    private static int? ParseFirstInt(string? value) => int.TryParse(Regex.Match(value ?? "", @"-?\d+").Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    private static double? ParseFirstDouble(string? value) => double.TryParse(Regex.Match(value ?? "", @"\d+(?:[.,]\d+)?").Value.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    private static int? WifiChannel(int? frequency) => frequency switch
    {
        2484 => 14,
        >= 2412 and <= 2472 => (frequency.Value - 2407) / 5,
        >= 5000 and <= 5900 => (frequency.Value - 5000) / 5,
        >= 5955 and <= 7115 => (frequency.Value - 5950) / 5,
        _ => null
    };
    private static double? Percentile(IReadOnlyList<long> values, double percentile) => values.Count == 0 ? null : values.Order().ElementAt((int)Math.Round((values.Count - 1) * percentile));
    private static string HashPrefix(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..16];
    private static string ExtractFirewallSummary(string text)
    {
        var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()).Where(line => Regex.IsMatch(line, "profile|state|status|default|профил|состоя", RegexOptions.IgnoreCase)).Take(12);
        return ProgramAccess.Truncate(string.Join(" | ", lines), 1000);
    }
    private static bool IsPrivateText(string value) => IPAddress.TryParse(value, out var ip) && IsPrivateOrCgnat(ip);
    private static bool IsCgnatText(string value) => IPAddress.TryParse(value, out var ip) && IsCgnat(ip);
    private static bool IsCgnat(IPAddress ip) { var b = ip.GetAddressBytes(); return ip.AddressFamily == AddressFamily.InterNetwork && b[0] == 100 && b[1] is >= 64 and <= 127; }
    private static bool IsPrivateOrCgnat(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10 || b[0] == 127 || b[0] == 169 && b[1] == 254 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168 || IsCgnat(ip);
        }
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.GetAddressBytes()[0] is 0xfc or 0xfd;
    }
}

internal sealed class NodeDiagnosticsReport
{
    public DateTimeOffset CapturedAt { get; init; }
    public string? DeclaredAccessType { get; init; }
    public string DetectedAccessType { get; init; } = "unknown";
    public string AccessTypeConfidence { get; init; } = "low";
    public string? AccessTypeReason { get; init; }
    public IReadOnlyList<string> ActiveInterfaceNames { get; init; } = [];
    public IReadOnlyList<string> LocalAddresses { get; init; } = [];
    public IReadOnlyList<string> PublicAddresses { get; init; } = [];
    public NodeProvider Provider { get; init; } = new();
    public NodeGeolocation Geolocation { get; init; } = new();
    public DeviceLocationObservation DeviceLocation { get; init; } = new();
    public DeviceIpGeolocationComparison GeolocationComparison { get; init; } = new();
    public DirectPerformanceReport DirectPerformance { get; init; } = new();
    public NatDiagnostics Nat { get; init; } = new();
    public GatewayDiagnostics Gateway { get; init; } = new();
    public IReadOnlyList<WifiObservation> Wifi { get; init; } = [];
    public IReadOnlyList<CellularObservation> Cellular { get; init; } = [];
    public DirectPathObservation DirectPath { get; init; } = new();
    public AdditionalNetworkSettings Settings { get; init; } = new();
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

internal sealed class NodeProvider
{
    public string? DisplayName { get; init; }
    public IReadOnlyList<string> Names { get; init; } = [];
    public IReadOnlyList<long> Asns { get; init; } = [];
    public IReadOnlyList<string> ReverseDnsNames { get; init; } = [];
    public string Confidence { get; init; } = "low";
    public string? Limitation { get; init; }
}

internal sealed class NodeGeolocation
{
    public string? Country { get; init; }
    public double? Latitude { get; init; }
    public double? Longitude { get; init; }
    public double? EstimatedRadiusKm { get; init; }
    public string Confidence { get; init; } = "unavailable";
    public IReadOnlyList<string> Sources { get; init; } = [];
    public string? Limitation { get; init; }
}

internal sealed record DeviceLocationObservation
{
    public string Status { get; init; } = "unavailable";
    public double? Latitude { get; init; }
    public double? Longitude { get; init; }
    public double? AccuracyMeters { get; init; }
    public double? AltitudeMeters { get; init; }
    public DateTimeOffset? CapturedAt { get; init; }
    public string? Source { get; init; }
    public string Confidence { get; init; } = "unavailable";
    public string? Error { get; init; }
    public string? Limitation { get; init; }
}

internal sealed class DeviceIpGeolocationComparison
{
    public string Status { get; init; } = "inconclusive";
    public double? DistanceKm { get; init; }
    public double? DeviceAccuracyMeters { get; init; }
    public double? IpEstimatedRadiusKm { get; init; }
    public string? Interpretation { get; init; }
}

internal sealed class DirectPerformanceReport
{
    public string Status { get; init; } = "unavailable";
    public IReadOnlyList<long> LatencyAttemptsMs { get; init; } = [];
    public double? LatencyP50Ms { get; init; }
    public ThroughputSample Download { get; init; } = new();
    public IReadOnlyList<ThroughputSample> DownloadAttempts { get; init; } = [];
    public ThroughputSample? ColdDownload { get; init; }
    public IReadOnlyList<ThroughputSample> WarmDownloads { get; init; } = [];
    public double? DownloadEffectiveVariabilityRatio { get; init; }
    public ThroughputSample Upload { get; init; } = new();
    public SpeedMeasurementReport? DetailedSpeed { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = [];
    public string? Interpretation { get; init; }
}

internal sealed class ThroughputSample
{
    public string Direction { get; init; } = "unknown";
    public bool Success { get; init; }
    public int RequestedBytes { get; init; }
    public long TransferredBytes { get; init; }
    public long ElapsedMs { get; init; }
    public long? FirstByteMs { get; init; }
    public long? PayloadTransferMs { get; init; }
    public double? MegabitsPerSecond { get; init; }
    public double? EffectiveMegabitsPerSecond { get; init; }
    public double? PayloadTransferMegabitsPerSecond { get; init; }
    public string MetricKind { get; init; } = "bounded-request-effective-throughput";
    public string Interpretation { get; init; } = "Effective throughput includes request establishment and TTFB; payload-transfer throughput is an approximation after first byte.";
    public string? Error { get; init; }
    public static ThroughputSample From(string direction, int requested, long transferred, TimeSpan elapsed, long? firstByte, bool success, string? error)
    {
        var elapsedMs = (long)elapsed.TotalMilliseconds;
        var transferMs = firstByte.HasValue ? Math.Max(1, elapsedMs - firstByte.Value) : (long?)null;
        var effective = elapsed.TotalSeconds > 0 && transferred > 0 ? Math.Round(transferred * 8d / 1_000_000d / elapsed.TotalSeconds, 2) : (double?)null;
        var payload = transferMs.HasValue && transferred > 0 ? Math.Round(transferred * 8d / 1000d / transferMs.Value, 2) : (double?)null;
        return new ThroughputSample
        {
            Direction = direction,
            RequestedBytes = requested,
            TransferredBytes = transferred,
            ElapsedMs = elapsedMs,
            FirstByteMs = firstByte,
            PayloadTransferMs = transferMs,
            Success = success,
            Error = error,
            MegabitsPerSecond = effective,
            EffectiveMegabitsPerSecond = effective,
            PayloadTransferMegabitsPerSecond = payload,
            MetricKind = direction == "download" ? "bounded-download-request" : "bounded-upload-request"
        };
    }
}

internal sealed class NatDiagnostics
{
    public string Presence { get; init; } = "unknown";
    public string Confidence { get; init; } = "low";
    public string? Reason { get; init; }
    public IReadOnlyList<string> LocalIpv4 { get; init; } = [];
    public string? PublicIpv4 { get; init; }
    public string? StunMappedAddress { get; init; }
    public int? StunMappedPort { get; init; }
    public string? StunServer { get; init; }
    public IReadOnlyList<string> PrivateRouteHops { get; init; } = [];
    public IReadOnlyList<string> CgnatRouteHops { get; init; } = [];
    public bool CgnatHint { get; init; }
    public bool MultipleNatLayersHint { get; init; }
    public string NatBehavior { get; init; } = "not-classified";
    public string? Limitation { get; init; }
}

internal sealed class GatewayDiagnostics
{
    public string Status { get; init; } = "not-observed";
    public string? Address { get; init; }
    public int PingAttempts { get; init; }
    public int PingSuccesses { get; init; }
    public double? PingP50Ms { get; init; }
    public string? MacOui { get; init; }
    public string? MacAddressHash { get; init; }
    public string? Manufacturer { get; init; }
    public string? ModelName { get; init; }
    public string? ModelNumber { get; init; }
    public string? ModelLabel { get; init; }
    public IReadOnlyList<UpnpDeviceInfo> UpnpDevices { get; init; } = [];
    public string? Limitation { get; init; }
}

internal sealed record UpnpDeviceInfo(string Address, string? DeviceType, string? Manufacturer, string? ModelName, string? ModelNumber);

internal sealed class WifiObservation
{
    public string? InterfaceName { get; init; }
    public string? State { get; init; }
    public string? SsidHash { get; init; }
    public string? BssidOui { get; init; }
    public string? BssidHash { get; init; }
    public string? RadioType { get; init; }
    public string? Authentication { get; init; }
    public string? Cipher { get; init; }
    public int? Channel { get; init; }
    public int? SignalPercent { get; init; }
    public double? ReceiveRateMbps { get; init; }
    public double? TransmitRateMbps { get; init; }
}

internal sealed class CellularObservation
{
    public string? InterfaceName { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? ProviderName { get; init; }
    public int? SignalPercent { get; init; }
    public string? Rssi { get; init; }
    public string? DataClass { get; init; }
}

internal sealed class AdditionalNetworkSettings
{
    public IReadOnlyList<string> DnsServers { get; init; } = [];
    public IReadOnlyList<string> DnsSuffixes { get; init; } = [];
    public IReadOnlyList<string> DhcpInterfaces { get; init; } = [];
    public IReadOnlyList<string> PotentialTunnelInterfaces { get; init; } = [];
    public bool WindowsSystemProxyEnabled { get; init; }
    public bool WindowsAutoDetectEnabled { get; init; }
    public bool WindowsAutoConfigUrlPresent { get; init; }
    public IReadOnlyList<string> ProxyEnvironmentVariablesPresent { get; init; } = [];
    public string WinHttpProxyMode { get; init; } = "unknown";
    public string FirewallProvider { get; init; } = "unknown";
    public string? FirewallStateSummary { get; init; }
    public int HostsFileCustomEntryCount { get; init; }
    public string? HostsFileContentHash { get; init; }
    public string? HostsFilePath { get; init; }
    public IReadOnlyList<string> Nat64Ipv4OnlyArpaAnswers { get; init; } = [];
    public bool Nat64Or464XlatHint { get; init; }
    public CaptivePortalObservation CaptivePortal { get; init; } = new("unknown", null, null, "not tested");
    public string? RouteTableHash { get; init; }
    public IReadOnlyList<string> DefaultRoutes { get; init; } = [];
}

internal sealed record CaptivePortalObservation(string Status, int? StatusCode, string? RedirectHost, string Reason);
internal sealed class DirectPathObservation { public string Status { get; init; } = "unknown"; public string Target { get; init; } = "1.1.1.1"; public IReadOnlyList<string> Hops { get; init; } = []; public string? Error { get; init; } }
internal sealed record CommandOutput(int ExitCode, string Stdout, string Stderr);

internal sealed class OsiTrafficMap
{
    public DateTimeOffset GeneratedAt { get; init; }
    public IReadOnlyList<OsiLayerEvidence> Layers { get; init; } = [];
    public IReadOnlyList<OsiProfilePath> Profiles { get; init; } = [];
    public string? Interpretation { get; init; }
}
internal sealed record OsiLayerEvidence(int Layer, string Name, string Observation, string Confidence, int ConfidenceWeightPercent, string Limitation);
internal sealed class OsiProfilePath { public string ProfileId { get; init; } = ""; public string ProfileName { get; init; } = ""; public IReadOnlyList<OsiPathNode> Nodes { get; init; } = []; public IReadOnlyList<OsiPathEdge> Edges { get; init; } = []; }
internal sealed record OsiPathNode(string Id, string Role, string Label, IReadOnlyList<string> Addresses, string Confidence);
internal sealed record OsiPathEdge(string From, string To, IReadOnlyList<int> OsiLayers, string Transport, string Evidence, string Likelihood);
