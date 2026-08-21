using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

internal static class ExtendedDiagnostics
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<RouteSnapshot> CaptureRouteSnapshotAsync(TimeSpan timeout)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            return new RouteSnapshot
            {
                CapturedAt = DateTimeOffset.UtcNow,
                Supported = false,
                Error = "Portable route capture is implemented for Windows and Linux."
            };
        }

        try
        {
            SimpleProcessResult output;
            string normalized;
            IReadOnlyList<string> defaults;
            if (OperatingSystem.IsWindows())
            {
                output = await RunProcessAsync("route.exe", "print", timeout);
                normalized = output.Stdout.Replace("\r", "", StringComparison.Ordinal);
                defaults = ParseDefaultRoutes(normalized, windows: true);
            }
            else
            {
                var ipv4 = await RunProcessAsync("ip", "-details route show table all", timeout);
                var ipv6 = await RunProcessAsync("ip", "-6 -details route show table all", timeout);
                output = new SimpleProcessResult(ipv4.ExitCode, ipv4.Stdout + "\n" + ipv6.Stdout, ipv4.Stderr + "\n" + ipv6.Stderr);
                normalized = output.Stdout.Replace("\r", "", StringComparison.Ordinal);
                defaults = ParseDefaultRoutes(normalized, windows: false);
            }
            return new RouteSnapshot
            {
                CapturedAt = DateTimeOffset.UtcNow,
                Supported = output.ExitCode == 0,
                DefaultRoutes = defaults,
                RouteTableSha256 = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))),
                Error = output.ExitCode == 0 ? null : ProgramAccess.Truncate(ProgramAccess.Redact(output.Stderr), 500)
            };
        }
        catch (Exception ex)
        {
            return new RouteSnapshot
            {
                CapturedAt = DateTimeOffset.UtcNow,
                Supported = false,
                Error = ProgramAccess.Redact(ex.Message)
            };
        }
    }

    internal static IReadOnlyList<string> ParseDefaultRoutes(string output, bool windows)
    {
        return output.Replace("\r", "", StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => Regex.Replace(line.Trim(), @"\s+", " "))
            .Where(line => windows
                ? line.StartsWith("0.0.0.0 0.0.0.0 ", StringComparison.Ordinal)
                    || line.StartsWith("::/0 ", StringComparison.OrdinalIgnoreCase)
                : Regex.IsMatch(
                    line,
                    @"^(?:(?:unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole|nat)\s+)?default(?:\s|$)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static StageResult BuildCaptureScopeStage(RouteSnapshot before, RouteSnapshot after, NetworkEnvironment environment)
    {
        var routeChanged = before.Supported && after.Supported
            && !string.Equals(before.RouteTableSha256, after.RouteTableSha256, StringComparison.OrdinalIgnoreCase);
        var mode = routeChanged || environment.PotentialTunnelInterfaces.Count > 0
            ? "system-route-or-tun-observed"
            : environment.WindowsSystemProxyEnabled
                ? "system-proxy-observed"
                : "explicit-local-proxy";
        return StageResult.Passed("client.captureScope", 0, new
        {
            mode,
            routeChangedWhileCoreRunning = routeChanged,
            before,
            after,
            potentialTunnelInterfaces = environment.PotentialTunnelInterfaces,
            windowsSystemProxyEnabled = environment.WindowsSystemProxyEnabled,
            interpretation = "The isolated runner only sends its own probes to loopback HTTP/SOCKS inbounds. Route or TUN changes would be external state and are reported separately."
        });
    }

    public static StageResult BuildAddressFamilyStage(IReadOnlyList<ExitIpObservation> direct, IReadOnlyList<ExitIpObservation> tunnel)
    {
        static object Families(IReadOnlyList<ExitIpObservation> observations)
        {
            var ipv4 = observations.Where(item => item.Valid && IPAddress.TryParse(item.Ip, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork).Select(item => item.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var ipv6 = observations.Where(item => item.Valid && IPAddress.TryParse(item.Ip, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6).Select(item => item.Ip).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            return new { ipv4, ipv6 };
        }
        var directIps = direct.Where(item => item.Valid).Select(item => item.Ip!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var tunnelIps = tunnel.Where(item => item.Valid).Select(item => item.Ip!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var overlap = directIps.Intersect(tunnelIps, StringComparer.OrdinalIgnoreCase).ToArray();
        return StageResult.FromStatus(
            "tunnel.addressFamilies",
            tunnelIps.Count > 0 ? "passed" : "failed",
            0,
            new
            {
                direct = Families(direct),
                tunnel = Families(tunnel),
                directTunnelOverlap = overlap,
                possibleLeak = overlap.Length > 0,
                interpretation = "An overlapping direct/tunnel public address is a leak signal only for the tested address family and destination; explicit-proxy mode intentionally leaves unrelated OS traffic direct."
            },
            tunnelIps.Count > 0 ? null : "No tunnel exit address was observed.");
    }

    public static async Task<StageResult> ProbeTcpSeriesAsync(IPAddress address, int port, int attempts, TimeSpan timeout)
    {
        attempts = Math.Clamp(attempts, 1, 20);
        var observations = new List<TcpAttempt>();
        var watch = Stopwatch.StartNew();
        for (var index = 0; index < attempts; index++)
        {
            var attemptWatch = Stopwatch.StartNew();
            try
            {
                using var client = new TcpClient(address.AddressFamily);
                using var cancellation = new CancellationTokenSource(timeout);
                await client.ConnectAsync(address, port, cancellation.Token);
                attemptWatch.Stop();
                observations.Add(new TcpAttempt(index + 1, true, attemptWatch.ElapsedMilliseconds, "connected", null));
            }
            catch (OperationCanceledException)
            {
                attemptWatch.Stop();
                observations.Add(new TcpAttempt(index + 1, false, attemptWatch.ElapsedMilliseconds, "timeout", "TCP connect timed out."));
            }
            catch (SocketException ex)
            {
                attemptWatch.Stop();
                observations.Add(new TcpAttempt(index + 1, false, attemptWatch.ElapsedMilliseconds, ex.SocketErrorCode.ToString(), ProgramAccess.Redact(ex.Message)));
            }
            catch (Exception ex)
            {
                attemptWatch.Stop();
                observations.Add(new TcpAttempt(index + 1, false, attemptWatch.ElapsedMilliseconds, "error", ProgramAccess.Redact(ex.Message)));
            }
        }
        watch.Stop();
        var successful = observations.Where(item => item.Success).Select(item => item.ElapsedMs).Order().ToArray();
        return StageResult.FromStatus(
            "endpoint.tcpSeries",
            successful.Length == attempts ? "passed" : successful.Length > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                ip = address.ToString(),
                port,
                attempts,
                successes = successful.Length,
                failures = attempts - successful.Length,
                minMs = Percentile(successful, 0),
                p50Ms = Percentile(successful, 0.50),
                p95Ms = Percentile(successful, 0.95),
                observations
            },
            successful.Length == attempts ? null : $"Only {successful.Length} of {attempts} TCP attempts succeeded.");
    }

    public static StageResult BuildDnsConsistencyStage(string stage, IReadOnlyList<DnsProbeResult> rounds)
    {
        if (rounds.Count == 0)
        {
            return StageResult.Skipped(stage, "No DNS rounds were captured.");
        }

        var resolverRounds = rounds.Select((round, index) => new
        {
            round = index + 1,
            elapsedMs = round.ElapsedMs,
            answers = round.Observations
                .Where(item => item.Status == "success" && item.Type is "A" or "AAAA" or "CNAME")
                .GroupBy(item => item.Resolver, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.Select(item => $"{item.Type}:{item.Value}").Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
                    StringComparer.OrdinalIgnoreCase)
        }).ToArray();

        var resolverNames = resolverRounds.SelectMany(item => item.answers.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var resolvers = resolverNames.Select(resolver =>
        {
            var sets = resolverRounds.Select(round => round.answers.TryGetValue(resolver, out var answers) ? string.Join('|', answers) : "<no-answer>").ToArray();
            return new
            {
                resolver,
                distinctAnswerSets = sets.Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                rotated = sets.Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1,
                rounds = sets
            };
        }).ToArray();

        var allAddresses = rounds.SelectMany(round => round.Addresses).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
        var divergenceByType = new[] { "A", "AAAA", "CNAME" }.Select(type =>
        {
            var divergent = resolverRounds.Any(round =>
            {
                var nonEmptySets = round.answers.Values
                    .Select(answers => answers.Where(answer => answer.StartsWith(type + ":", StringComparison.OrdinalIgnoreCase)).ToArray())
                    .Where(answers => answers.Length > 0)
                    .Select(answers => string.Join('|', answers))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                return nonEmptySets.Length > 1;
            });
            return new { type, divergent };
        }).ToArray();
        var splitResolverEvidence = divergenceByType.Any(item => item.divergent);
        return StageResult.Passed(stage, rounds.Sum(round => round.ElapsedMs), new
        {
            host = rounds[0].Host,
            roundCount = rounds.Count,
            uniqueAddresses = allAddresses,
            resolverAnswerDivergenceObserved = splitResolverEvidence,
            divergenceByType,
            rotationObserved = resolvers.Any(item => item.rotated),
            resolvers,
            rounds = resolverRounds,
            interpretation = "Different answers are evidence of resolver-dependent DNS or rotation; they are not by themselves proof of operator manipulation."
        });
    }

    public static async Task<StageResult> ProbePathMtuAsync(IPAddress address, TimeSpan timeout)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return StageResult.Skipped("endpoint.pathMtu", "The portable DF probe currently targets IPv4; IPv6 MTU is represented by functional payload tests.");
        }

        var sizes = new[] { 1472, 1440, 1400, 1360, 1300, 1200, 1000, 512 };
        var observations = new List<object>();
        var watch = Stopwatch.StartNew();
        int? largestSuccessfulPayload = null;
        var consecutiveTimeouts = 0;
        var rawSocketPermissionUnavailable = false;
        using var ping = new Ping();
        foreach (var size in sizes)
        {
            try
            {
                var buffer = new byte[size];
                RandomNumberGenerator.Fill(buffer);
                var reply = await ping.SendPingAsync(address, 1200, buffer, new PingOptions(64, true));
                var success = reply.Status == IPStatus.Success;
                if (success && (!largestSuccessfulPayload.HasValue || size > largestSuccessfulPayload.Value)) largestSuccessfulPayload = size;
                consecutiveTimeouts = reply.Status == IPStatus.TimedOut ? consecutiveTimeouts + 1 : 0;
                observations.Add(new { payloadBytes = size, success, status = reply.Status.ToString(), roundtripMs = reply.RoundtripTime });
                if (consecutiveTimeouts >= 3) break;
            }
            catch (Exception ex)
            {
                var error = ProgramAccess.Redact(ex.Message);
                rawSocketPermissionUnavailable = IsRawSocketPermissionError(error);
                observations.Add(new
                {
                    payloadBytes = size,
                    success = false,
                    status = rawSocketPermissionUnavailable ? "unavailable-insufficient-privileges" : "error",
                    error
                });
                if (rawSocketPermissionUnavailable) break;
            }
        }
        watch.Stop();
        var status = largestSuccessfulPayload.HasValue
            ? "passed"
            : rawSocketPermissionUnavailable
                ? "skipped"
                : "partial";
        var errorSummary = largestSuccessfulPayload.HasValue
            ? null
            : rawSocketPermissionUnavailable
                ? OperatingSystem.IsLinux()
                    ? "Path MTU probe was not executed because raw-socket permission is unavailable. Run as root or grant cap_net_raw to the Traffic Lab executable."
                    : "Path MTU probe was not executed because raw-socket permission is unavailable. Run Traffic Lab elevated."
                : "No ICMP DF size succeeded; ICMP may be filtered or the path may reject these payload sizes.";
        return StageResult.FromStatus(
            "endpoint.pathMtu",
            status,
            watch.ElapsedMilliseconds,
            new
            {
                ip = address.ToString(),
                dontFragment = true,
                probeAvailability = rawSocketPermissionUnavailable ? "insufficient-raw-socket-permission" : "available",
                requiresRawSocketPrivilege = rawSocketPermissionUnavailable,
                largestSuccessfulIcmpPayloadBytes = largestSuccessfulPayload,
                estimatedIpMtu = largestSuccessfulPayload.HasValue ? (int?)(largestSuccessfulPayload.Value + 28) : null,
                observations,
                interpretation = rawSocketPermissionUnavailable
                    ? "No ICMP DF packet was sent. This is a local privilege limitation, not evidence of ICMP filtering or an MTU failure."
                    : "ICMP can be filtered. A missing reply is not proof of an MTU failure, so tunnel payload tests remain authoritative for application traffic."
            },
            errorSummary);
    }

    internal static bool IsRawSocketPermissionError(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return false;
        return Regex.IsMatch(
            message,
            @"privileged user account|cap_net_raw|operation not permitted|permission denied|access (?:is )?denied",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static StageResult BuildGeoConsensusStage(string stage, string subject, IEnumerable<IpAttribution> attributions)
    {
        var items = attributions.ToArray();
        var hints = items.SelectMany(item => item.GeolocationHints.Select(hint => new
        {
            item.Ip,
            hint.Country,
            hint.City,
            hint.Latitude,
            hint.Longitude,
            hint.Source,
            hint.Confidence
        })).ToArray();
        if (items.Length == 0)
        {
            return StageResult.Skipped(stage, $"No attributed {subject} IP addresses were available.");
        }

        var countries = items.Select(item => item.RdapCountry)
            .Concat(hints.Select(item => item.Country))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .GroupBy(value => value!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .Select(group => new { value = group.Key, votes = group.Count() })
            .ToArray();
        var coordinateHints = hints.Where(item => item.Latitude.HasValue && item.Longitude.HasValue).ToArray();
        double? latitude = coordinateHints.Length == 0 ? null : Median(coordinateHints.Select(item => item.Latitude!.Value));
        double? longitude = coordinateHints.Length == 0 ? null : Median(coordinateHints.Select(item => item.Longitude!.Value));
        var radius = latitude.HasValue && longitude.HasValue
            ? coordinateHints.Select(item => HaversineKm(latitude.Value, longitude.Value, item.Latitude!.Value, item.Longitude!.Value)).DefaultIfEmpty(0).Max()
            : (double?)null;
        var independentSources = hints.Select(item => item.Source).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var confidence = independentSources >= 3 && radius is <= 100 ? "high"
            : independentSources >= 2 && radius is <= 300 ? "medium"
            : "low";
        var minimumRadius = confidence == "high" ? 25 : confidence == "medium" ? 100 : 500;
        return StageResult.Passed(stage, 0, new
        {
            subject,
            country = countries.FirstOrDefault()?.value,
            countryVotes = countries,
            latitude,
            longitude,
            estimatedRadiusKm = radius.HasValue ? (double?)Math.Round(Math.Max(radius.Value, minimumRadius), 1) : null,
            confidence,
            independentSources,
            hints,
            interpretation = $"This is an IP/route attribution estimate for {subject}, not proof of a physical rack, datacenter, cellular base station, or legal entity."
        });
    }

    public static async Task<StageResult> ProbeTlsMatrixAsync(IPAddress endpoint, int endpointPort, string sni, string endpointHost, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        var variants = new List<TlsFingerprint>();
        variants.Add(await CaptureTlsFingerprintAsync("endpoint-profile-sni", endpoint, endpointPort, sni, timeout));
        if (!string.Equals(endpointHost, sni, StringComparison.OrdinalIgnoreCase))
        {
            variants.Add(await CaptureTlsFingerprintAsync("endpoint-endpoint-host", endpoint, endpointPort, endpointHost, timeout));
        }
        variants.Add(await CaptureTlsFingerprintAsync("endpoint-control-sni", endpoint, endpointPort, $"invalid-{Guid.NewGuid():N}.invalid", timeout));

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var targetAddresses = await Dns.GetHostAddressesAsync(sni, cancellation.Token);
            var targetAddress = targetAddresses.FirstOrDefault(address => address.AddressFamily == endpoint.AddressFamily) ?? targetAddresses.FirstOrDefault();
            if (targetAddress is not null)
            {
                variants.Add(await CaptureTlsFingerprintAsync("camouflage-direct-443", targetAddress, 443, sni, timeout));
            }
        }
        catch (Exception ex)
        {
            variants.Add(new TlsFingerprint("camouflage-direct-443", null, 443, sni, false, null, null, null, null, null, ProgramAccess.Redact(ex.Message)));
        }

        watch.Stop();
        var profile = variants.First();
        var direct = variants.FirstOrDefault(item => item.Variant == "camouflage-direct-443");
        var spkiMatch = profile.Success && direct is { Success: true }
            && !string.IsNullOrWhiteSpace(profile.SpkiSha256)
            && string.Equals(profile.SpkiSha256, direct.SpkiSha256, StringComparison.OrdinalIgnoreCase);
        var certMatch = profile.Success && direct is { Success: true }
            && string.Equals(profile.CertificateSha256, direct.CertificateSha256, StringComparison.OrdinalIgnoreCase);
        return StageResult.FromStatus(
            "endpoint.tlsMatrix",
            profile.Success ? "passed" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                variants,
                endpointAndDirectTargetCertificateMatch = certMatch,
                endpointAndDirectTargetSpkiMatch = spkiMatch,
                interpretation = "Certificate/SPKI and TLS behavior can strongly support a fallback-target hypothesis, but only server configuration can prove the exact REALITY target."
            },
            profile.Success ? null : "The profile-SNI ordinary TLS variant did not complete.");
    }

    public static async Task<StageResult> ProbeHttpProtocolMatrixAsync(HttpClient client, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        var observations = new List<HttpProtocolObservation>();
        foreach (var requested in new[] { HttpVersion.Version11, HttpVersion.Version20 })
        {
            var itemWatch = Stopwatch.StartNew();
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "https://www.google.com/generate_204")
                {
                    Version = requested,
                    VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                };
                using var cancellation = new CancellationTokenSource(timeout);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
                itemWatch.Stop();
                observations.Add(new HttpProtocolObservation(requested.ToString(), response.Version.ToString(), (int)response.StatusCode, response.IsSuccessStatusCode, itemWatch.ElapsedMilliseconds, null));
            }
            catch (Exception ex)
            {
                itemWatch.Stop();
                observations.Add(new HttpProtocolObservation(requested.ToString(), null, null, false, itemWatch.ElapsedMilliseconds, ProgramAccess.Redact(ex.Message)));
            }
        }
        watch.Stop();
        var success = observations.Count(item => item.Success);
        return StageResult.FromStatus(
            "tunnel.httpProtocols",
            success == observations.Count ? "passed" : success > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                observations,
                http3 = new { status = "not-applicable-via-http-connect", reason = "HTTP/3 uses QUIC/UDP and cannot be proven by the runner's HTTP CONNECT inbound; UDP is tested separately." }
            },
            success == observations.Count ? null : $"Only {success} HTTP protocol variants succeeded.");
    }

    public static async Task<StageResult> ProbeTunnelPayloadMatrixAsync(HttpClient client, TimeSpan timeout)
    {
        var sizes = new[] { 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024 };
        var results = new List<PayloadObservation>();
        var watch = Stopwatch.StartNew();
        foreach (var size in sizes)
        {
            var itemWatch = Stopwatch.StartNew();
            try
            {
                using var cancellation = new CancellationTokenSource(timeout + TimeSpan.FromSeconds(10));
                using var response = await client.GetAsync($"https://speed.cloudflare.com/__down?bytes={size}", HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
                response.EnsureSuccessStatusCode();
                await using var stream = await response.Content.ReadAsStreamAsync(cancellation.Token);
                var buffer = new byte[32 * 1024];
                var bytes = 0;
                long? firstByteMs = null;
                while (bytes < size)
                {
                    var read = await stream.ReadAsync(buffer, cancellation.Token);
                    if (read == 0) break;
                    firstByteMs ??= itemWatch.ElapsedMilliseconds;
                    bytes += read;
                }
                itemWatch.Stop();
                results.Add(new PayloadObservation(size, bytes, bytes >= size, firstByteMs, itemWatch.ElapsedMilliseconds, null));
            }
            catch (Exception ex)
            {
                itemWatch.Stop();
                results.Add(new PayloadObservation(size, 0, false, null, itemWatch.ElapsedMilliseconds, ProgramAccess.Redact(ex.Message)));
            }
        }
        watch.Stop();
        var successes = results.Count(item => item.Success);
        return StageResult.FromStatus(
            "tunnel.payloadMatrix",
            successes == results.Count ? "passed" : successes > 0 ? "partial" : "failed",
            watch.ElapsedMilliseconds,
            new
            {
                results,
                largestSuccessfulBytes = results.Where(item => item.Success).Select(item => item.ReceivedBytes).DefaultIfEmpty(0).Max(),
                interpretation = "Successful progressively larger HTTPS bodies are application-level evidence against a path-MTU black hole; they do not reveal the exact tunnel MTU."
            },
            successes == results.Count ? null : $"Only {successes} of {results.Count} payload sizes completed.");
    }

    public static async Task<StageResult> ProbeUploadAsync(HttpClient client, TimeSpan timeout, int bytes = 256 * 1024)
    {
        var buffer = new byte[bytes];
        RandomNumberGenerator.Fill(buffer);
        var watch = Stopwatch.StartNew();
        try
        {
            using var content = new ByteArrayContent(buffer);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            using var cancellation = new CancellationTokenSource(timeout + TimeSpan.FromSeconds(15));
            using var response = await client.PostAsync("https://speed.cloudflare.com/__up", content, cancellation.Token);
            watch.Stop();
            var kbps = watch.Elapsed.TotalSeconds > 0 ? Math.Round(bytes * 8d / 1000d / watch.Elapsed.TotalSeconds, 1) : 0;
            return StageResult.FromStatus(
                "tunnel.upload",
                response.IsSuccessStatusCode ? "passed" : "failed",
                watch.ElapsedMilliseconds,
                new { target = "https://speed.cloudflare.com/__up", bytes, statusCode = (int)response.StatusCode, kilobitsPerSecond = kbps },
                response.IsSuccessStatusCode ? null : $"Upload endpoint returned HTTP {(int)response.StatusCode}.");
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("tunnel.upload", watch.ElapsedMilliseconds, ProgramAccess.Redact(ex.Message), new { bytes });
        }
    }

    public static async Task<StageResult> ProbeControlledCanaryAsync(HttpClient client, string urlTemplate, string profileFingerprint, string correlationId, TimeSpan timeout)
    {
        var url = urlTemplate.Replace("{id}", correlationId, StringComparison.OrdinalIgnoreCase)
            .Replace("{profile}", profileFingerprint, StringComparison.OrdinalIgnoreCase);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            return StageResult.Failed("tunnel.controlledCanary", 0, "Canary URL template must produce an absolute HTTP or HTTPS URL.");
        }
        var watch = Stopwatch.StartNew();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.TryAddWithoutValidation("X-Traffic-Lab-Correlation-Id", correlationId);
            using var cancellation = new CancellationTokenSource(timeout);
            using var response = await client.SendAsync(request, cancellation.Token);
            var body = await response.Content.ReadAsStringAsync(cancellation.Token);
            watch.Stop();
            string? observedSourceIp = null;
            try
            {
                using var document = JsonDocument.Parse(body);
                if (document.RootElement.TryGetProperty("observedSourceIp", out var source) && source.ValueKind == JsonValueKind.String) observedSourceIp = source.GetString();
            }
            catch { }
            return StageResult.FromStatus(
                "tunnel.controlledCanary",
                response.IsSuccessStatusCode ? "passed" : "failed",
                watch.ElapsedMilliseconds,
                new
                {
                    correlationId,
                    requestHost = uri.Host,
                    statusCode = (int)response.StatusCode,
                    observedSourceIp,
                    responseSample = ProgramAccess.Truncate(ProgramAccess.Redact(body), 1000),
                    interpretation = "Correlate this ID with the collector DNS/HTTP event log to identify recursive resolver source and tunnel egress without relying on a public IP service."
                },
                response.IsSuccessStatusCode ? null : $"Controlled canary returned HTTP {(int)response.StatusCode}.");
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.Failed("tunnel.controlledCanary", watch.ElapsedMilliseconds, ProgramAccess.Redact(ex.Message), new { correlationId, requestHost = uri.Host });
        }
    }

    public static async Task<StageResult> ProbeStunViaSocksAsync(int socksPort, TimeSpan timeout)
    {
        var servers = new[]
        {
            new StunServer("stun.cloudflare.com", 3478),
            new StunServer("stun.l.google.com", 19302)
        };
        var observations = new List<StunObservation>();
        var watch = Stopwatch.StartNew();
        foreach (var server in servers)
        {
            observations.Add(await SocksStunProbe.RunAsync("127.0.0.1", socksPort, server, timeout));
            if (observations[^1].Success) break;
        }
        watch.Stop();
        var success = observations.FirstOrDefault(item => item.Success);
        return StageResult.FromStatus(
            "tunnel.stun",
            success is not null ? "passed" : "partial",
            watch.ElapsedMilliseconds,
            new
            {
                observations,
                mappedAddress = success?.MappedAddress,
                mappedPort = success?.MappedPort,
                interpretation = "A STUN mapping supplies independent UDP-egress evidence. Failure may mean the public STUN service is unavailable rather than that all UDP is blocked."
            },
            success is not null ? null : "No configured public STUN server returned a valid binding response.");
    }

    public static async Task<StageResult> ProbeQuicHandshakeAsync(int localUdpPort, TimeSpan timeout)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return StageResult.Skipped("tunnel.quicHandshake", "QUIC probing is supported on Windows, Linux and macOS only.");
        if (!QuicConnection.IsSupported)
        {
            return StageResult.Skipped("tunnel.quicHandshake", "The bundled .NET runtime or current operating system does not provide MsQuic support.");
        }
        var watch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var options = new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, localUdpPort),
                DefaultStreamErrorCode = 0x100,
                DefaultCloseErrorCode = 0x100,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "cloudflare-dns.com",
                    ApplicationProtocols = [new SslApplicationProtocol("h3")],
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }
            };
            await using var connection = await QuicConnection.ConnectAsync(options, cancellation.Token);
            watch.Stop();
            return StageResult.Passed("tunnel.quicHandshake", watch.ElapsedMilliseconds, new
            {
                localUdpInbound = $"127.0.0.1:{localUdpPort}",
                fixedDestination = "cloudflare-dns.com:443/udp",
                negotiatedAlpn = Encoding.ASCII.GetString(connection.NegotiatedApplicationProtocol.Protocol.Span),
                targetHost = connection.TargetHostName,
                remoteEndPoint = connection.RemoteEndPoint?.ToString(),
                interpretation = "A native QUIC TLS handshake with ALPN h3 completed through Xray's fixed UDP dokodemo inbound and the tested VLESS outbound. This proves QUIC transport reachability, not a complete HTTP/3 request."
            });
        }
        catch (Exception ex)
        {
            watch.Stop();
            return StageResult.FromStatus(
                "tunnel.quicHandshake",
                "partial",
                watch.ElapsedMilliseconds,
                new { localUdpInbound = $"127.0.0.1:{localUdpPort}", fixedDestination = "cloudflare-dns.com:443/udp" },
                ProgramAccess.Redact(ex.Message));
        }
    }

    public static string ComputeProfileFingerprint(DeclaredProfile profile)
    {
        static string Lower(string? value, bool trimDot = false)
        {
            var normalized = (value ?? "").Trim();
            if (trimDot) normalized = normalized.TrimEnd('.');
            return normalized.ToLowerInvariant();
        }
        var material = string.Join('|',
            "v2",
            Lower(profile.Protocol),
            Lower(profile.Host, trimDot: true),
            profile.Port.ToString(CultureInfo.InvariantCulture),
            Lower(profile.Security),
            Lower(profile.Network),
            Lower(profile.Sni, trimDot: true),
            profile.Path ?? "",
            profile.ServiceName ?? "",
            Lower(profile.HostHeader, trimDot: true),
            Lower(profile.PacketEncoding));
        return Hex(SHA256.HashData(Encoding.UTF8.GetBytes(material)))[..16];
    }

    public static StageResult BuildInfrastructureSignals(ProfileReport report)
    {
        var dnsConsistency = ReadStageData(report, "endpoint.dnsConsistency");
        var tlsMatrix = ReadStageData(report, "endpoint.tlsMatrix");
        var traceroute = ReadStageData(report, "endpoint.tracerouteAttribution");
        var dnsRotation = ReadBoolean(dnsConsistency, "rotationObserved");
        var dnsDivergence = ReadBoolean(dnsConsistency, "resolverAnswerDivergenceObserved");
        var certMatch = ReadBoolean(tlsMatrix, "endpointAndDirectTargetCertificateMatch");
        var spkiMatch = ReadBoolean(tlsMatrix, "endpointAndDirectTargetSpkiMatch");
        var sniCertificateRouting = false;
        if (tlsMatrix.ValueKind == JsonValueKind.Object && tlsMatrix.TryGetProperty("variants", out var variants))
        {
            var profile = variants.EnumerateArray().FirstOrDefault(item => ReadString(item, "variant") == "endpoint-profile-sni");
            var control = variants.EnumerateArray().FirstOrDefault(item => ReadString(item, "variant") == "endpoint-control-sni");
            sniCertificateRouting = profile.ValueKind == JsonValueKind.Object && control.ValueKind == JsonValueKind.Object
                && !string.IsNullOrWhiteSpace(ReadString(profile, "certificateSha256"))
                && !string.Equals(ReadString(profile, "certificateSha256"), ReadString(control, "certificateSha256"), StringComparison.OrdinalIgnoreCase);
        }
        var observedAsPath = traceroute.ValueKind == JsonValueKind.Object && traceroute.TryGetProperty("observedAsPath", out var path)
            ? path.EnumerateArray().Select(item => item.ToString()).ToArray()
            : [];
        var loadBalancerScore = (report.ObservedEndpointIps.Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1 ? 2 : 0)
            + (dnsRotation ? 2 : 0)
            + (dnsDivergence ? 1 : 0)
            + (report.ObservedSocketIps.Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1 ? 2 : 0);
        var frontingScore = (sniCertificateRouting ? 3 : 0) + (certMatch || spkiMatch ? 2 : 0) + (report.Declared.Security == "reality" ? 1 : 0);
        return StageResult.Passed("analysis.infrastructureSignals", 0, new
        {
            endpointAddressCount = report.ObservedEndpointIps.Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            observedSocketAddressCount = report.ObservedSocketIps.Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            dnsRotation,
            dnsResolverDivergence = dnsDivergence,
            sniCertificateRouting,
            endpointAndDirectTargetCertificateMatch = certMatch,
            endpointAndDirectTargetSpkiMatch = spkiMatch,
            observedAsPath,
            loadBalancerLikelihood = loadBalancerScore >= 4 ? "high-inferred" : loadBalancerScore >= 2 ? "medium-inferred" : "low-or-not-observed",
            tlsFrontingOrFallbackLikelihood = frontingScore >= 4 ? "high-inferred" : frontingScore >= 2 ? "medium-inferred" : "low-or-not-observed",
            limitation = "These are externally observable signals. NAT, anycast, CDN, SNI routing, and a load balancer can produce overlapping signatures."
        });
    }

    private static JsonElement ReadStageData(ProfileReport report, string stageName)
    {
        var data = report.Stages.FirstOrDefault(stage => stage.Stage == stageName)?.Data;
        return data is null ? default : JsonSerializer.SerializeToElement(data, JsonOptions);
    }

    private static bool ReadBoolean(JsonElement element, string property)
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.True;

    private static string? ReadString(JsonElement element, string property)
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static async Task<TlsFingerprint> CaptureTlsFingerprintAsync(string variant, IPAddress address, int port, string targetHost, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        X509Certificate2? certificate = null;
        try
        {
            using var tcp = new TcpClient(address.AddressFamily);
            using var cancellation = new CancellationTokenSource(timeout);
            await tcp.ConnectAsync(address, port, cancellation.Token);
            using var ssl = new SslStream(tcp.GetStream(), false, (_, remote, _, _) =>
            {
                if (remote is not null) certificate = new X509Certificate2(remote);
                return true;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
            }, cancellation.Token);
            watch.Stop();
            var certHash = certificate is null ? null : Hex(SHA256.HashData(certificate.RawData));
            string? spki = null;
            if (certificate is not null)
            {
                try { spki = Hex(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo())); } catch { }
            }
            return new TlsFingerprint(variant, address.ToString(), port, targetHost, true, ssl.SslProtocol.ToString(), ssl.NegotiatedCipherSuite.ToString(), Encoding.ASCII.GetString(ssl.NegotiatedApplicationProtocol.Protocol.Span), certHash, spki, null);
        }
        catch (Exception ex)
        {
            watch.Stop();
            return new TlsFingerprint(variant, address.ToString(), port, targetHost, false, null, null, null, certificate is null ? null : Hex(SHA256.HashData(certificate.RawData)), null, ProgramAccess.Redact(ex.Message));
        }
        finally
        {
            certificate?.Dispose();
        }
    }

    private static long? Percentile(long[] sorted, double percentile)
    {
        if (sorted.Length == 0) return null;
        var index = (int)Math.Ceiling(percentile * sorted.Length) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Length - 1)];
    }

    private static double Median(IEnumerable<double> values)
    {
        var sorted = values.Order().ToArray();
        if (sorted.Length == 0) return 0;
        return sorted.Length % 2 == 1 ? sorted[sorted.Length / 2] : (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2;
    }

    private static double HaversineKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double radius = 6371.0;
        static double Radians(double degrees) => degrees * Math.PI / 180;
        var dLat = Radians(lat2 - lat1);
        var dLon = Radians(lon2 - lon1);
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2)
            + Math.Cos(Radians(lat1)) * Math.Cos(Radians(lat2)) * Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return radius * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
    }

    private static string Hex(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();

    private static async Task<SimpleProcessResult> RunProcessAsync(string fileName, string arguments, TimeSpan timeout)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            }
        };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch { }
            return new SimpleProcessResult(-1, await stdout, (await stderr) + " process timeout");
        }
        return new SimpleProcessResult(process.ExitCode, await stdout, await stderr);
    }
}

internal sealed class RouteSnapshot
{
    public DateTimeOffset CapturedAt { get; init; }
    public bool Supported { get; init; }
    public IReadOnlyList<string> DefaultRoutes { get; init; } = [];
    public string? RouteTableSha256 { get; init; }
    public string? Error { get; init; }
}

internal sealed record SimpleProcessResult(int ExitCode, string Stdout, string Stderr);
internal sealed record TcpAttempt(int Attempt, bool Success, long ElapsedMs, string Outcome, string? Error);
internal sealed record TlsFingerprint(string Variant, string? Ip, int Port, string Sni, bool Success, string? Protocol, string? CipherSuite, string? Alpn, string? CertificateSha256, string? SpkiSha256, string? Error);
internal sealed record HttpProtocolObservation(string RequestedVersion, string? NegotiatedVersion, int? StatusCode, bool Success, long ElapsedMs, string? Error);
internal sealed record PayloadObservation(int RequestedBytes, int ReceivedBytes, bool Success, long? FirstByteMs, long ElapsedMs, string? Error);
internal sealed record StunServer(string Host, int Port);
internal sealed record StunObservation(string Server, bool Success, string? MappedAddress, int? MappedPort, long ElapsedMs, string? Error);

internal static class SocksStunProbe
{
    private const uint MagicCookie = 0x2112A442;

    public static async Task<StunObservation> RunAsync(string socksHost, int socksPort, StunServer server, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var addresses = await Dns.GetHostAddressesAsync(server.Host, cancellation.Token);
            var target = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork) ?? addresses.First();
            using var control = new TcpClient(AddressFamily.InterNetwork);
            await control.ConnectAsync(IPAddress.Parse(socksHost), socksPort, cancellation.Token);
            var stream = control.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellation.Token);
            var greeting = await ReadExactAsync(stream, 2, cancellation.Token);
            if (greeting[0] != 0x05 || greeting[1] != 0x00) throw new IOException("SOCKS5 authentication negotiation failed.");
            await stream.WriteAsync(new byte[] { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, cancellation.Token);
            var header = await ReadExactAsync(stream, 4, cancellation.Token);
            if (header[1] != 0x00) throw new IOException($"SOCKS5 UDP ASSOCIATE failed with reply {header[1]}.");
            var relayAddress = await ReadAddressAsync(stream, header[3], cancellation.Token);
            var relayPortBytes = await ReadExactAsync(stream, 2, cancellation.Token);
            var relayPort = (relayPortBytes[0] << 8) | relayPortBytes[1];
            if (relayAddress.Equals(IPAddress.Any)) relayAddress = IPAddress.Loopback;

            var transaction = RandomNumberGenerator.GetBytes(12);
            var stun = new byte[20];
            stun[0] = 0x00;
            stun[1] = 0x01;
            stun[4] = 0x21;
            stun[5] = 0x12;
            stun[6] = 0xA4;
            stun[7] = 0x42;
            transaction.CopyTo(stun, 8);
            var targetBytes = target.GetAddressBytes();
            var packet = new byte[10 + targetBytes.Length + stun.Length];
            packet[0] = 0;
            packet[1] = 0;
            packet[2] = 0;
            packet[3] = target.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            targetBytes.CopyTo(packet, 4);
            packet[4 + targetBytes.Length] = (byte)(server.Port >> 8);
            packet[5 + targetBytes.Length] = (byte)server.Port;
            stun.CopyTo(packet, 6 + targetBytes.Length);

            using var udp = new UdpClient(relayAddress.AddressFamily);
            await udp.SendAsync(packet, new IPEndPoint(relayAddress, relayPort), cancellation.Token);
            var response = await udp.ReceiveAsync(cancellation.Token);
            var payloadOffset = SocksPayloadOffset(response.Buffer);
            var mapped = ParseMappedAddress(response.Buffer[payloadOffset..], transaction);
            watch.Stop();
            return new StunObservation($"{server.Host}:{server.Port}", mapped.address is not null, mapped.address, mapped.port, watch.ElapsedMilliseconds, mapped.address is null ? "STUN response did not contain a mapped address." : null);
        }
        catch (Exception ex)
        {
            watch.Stop();
            return new StunObservation($"{server.Host}:{server.Port}", false, null, null, watch.ElapsedMilliseconds, ProgramAccess.Redact(ex.Message));
        }
    }

    internal static (string? address, int? port) ParseMappedAddress(ReadOnlySpan<byte> message, byte[] transaction)
    {
        if (message.Length < 20 || message[0] != 0x01 || message[1] != 0x01) return (null, null);
        var length = (message[2] << 8) | message[3];
        var offset = 20;
        var end = Math.Min(message.Length, 20 + length);
        while (offset + 4 <= end)
        {
            var type = (message[offset] << 8) | message[offset + 1];
            var attributeLength = (message[offset + 2] << 8) | message[offset + 3];
            var value = offset + 4;
            if (value + attributeLength > message.Length) break;
            if ((type == 0x0020 || type == 0x0001) && attributeLength >= 8)
            {
                var family = message[value + 1];
                var encodedPort = (message[value + 2] << 8) | message[value + 3];
                var port = type == 0x0020 ? encodedPort ^ (int)(MagicCookie >> 16) : encodedPort;
                if (family == 0x01 && attributeLength >= 8)
                {
                    var bytes = message.Slice(value + 4, 4).ToArray();
                    if (type == 0x0020)
                    {
                        var cookie = BitConverter.GetBytes(MagicCookie);
                        if (BitConverter.IsLittleEndian) Array.Reverse(cookie);
                        for (var index = 0; index < 4; index++) bytes[index] ^= cookie[index];
                    }
                    return (new IPAddress(bytes).ToString(), port);
                }
                if (family == 0x02 && attributeLength >= 20)
                {
                    var bytes = message.Slice(value + 4, 16).ToArray();
                    if (type == 0x0020)
                    {
                        var mask = new byte[16] { 0x21, 0x12, 0xA4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                        transaction.CopyTo(mask, 4);
                        for (var index = 0; index < 16; index++) bytes[index] ^= mask[index];
                    }
                    return (new IPAddress(bytes).ToString(), port);
                }
            }
            offset = value + ((attributeLength + 3) & ~3);
        }
        return (null, null);
    }

    private static int SocksPayloadOffset(byte[] packet)
    {
        if (packet.Length < 10 || packet[0] != 0 || packet[1] != 0) throw new IOException("Invalid SOCKS5 UDP response.");
        return packet[3] switch
        {
            0x01 => 10,
            0x04 => 22,
            0x03 when packet.Length >= 7 => 7 + packet[4],
            _ => throw new IOException("Unsupported SOCKS5 UDP address type.")
        };
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken)
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

    private static async Task<IPAddress> ReadAddressAsync(Stream stream, byte atyp, CancellationToken cancellationToken)
    {
        return atyp switch
        {
            0x01 => new IPAddress(await ReadExactAsync(stream, 4, cancellationToken)),
            0x04 => new IPAddress(await ReadExactAsync(stream, 16, cancellationToken)),
            0x03 => await ReadDomainAddressAsync(stream, cancellationToken),
            _ => throw new IOException("Unsupported SOCKS5 relay address type.")
        };
    }

    private static async Task<IPAddress> ReadDomainAddressAsync(Stream stream, CancellationToken cancellationToken)
    {
        var length = (await ReadExactAsync(stream, 1, cancellationToken))[0];
        var host = Encoding.ASCII.GetString(await ReadExactAsync(stream, length, cancellationToken));
        return (await Dns.GetHostAddressesAsync(host, cancellationToken)).First();
    }
}
