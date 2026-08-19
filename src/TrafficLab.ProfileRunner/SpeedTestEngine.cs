using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;

internal sealed record SpeedTestSettings(
    string Mode,
    int TargetWindowMs,
    int MeasurementAttempts,
    IReadOnlyList<int> FlowCounts,
    int DownloadMaximumBytes,
    int UploadMaximumBytes,
    int LatencyIntervalMs)
{
    public static SpeedTestSettings Normal { get; } = new(
        "normal", 2_000, 3, [1], 16 * 1024 * 1024, 8 * 1024 * 1024, 400);

    public static SpeedTestSettings Extended { get; } = new(
        "extended", 3_000, 2, [1, 4, 16], 16 * 1024 * 1024, 8 * 1024 * 1024, 350);

    public static SpeedTestSettings SpeedOnly { get; } = new(
        "speed", 3_000, 3, [1, 4, 16], 24 * 1024 * 1024, 12 * 1024 * 1024, 300);

    public static SpeedTestSettings DirectAfterControl { get; } = new(
        "direct-after-control", 1_500, 2, [1], 8 * 1024 * 1024, 4 * 1024 * 1024, 400);
}

internal static class SpeedTestEngine
{
    private const int DownloadCalibrationBytesPerFlow = 256 * 1024;
    private const int UploadCalibrationBytesPerFlow = 128 * 1024;
    private const string DownloadEndpoint = "https://speed.cloudflare.com/__down";
    private const string UploadEndpoint = "https://speed.cloudflare.com/__up";
    private const string LatencyEndpoint = "https://www.gstatic.com/generate_204";

    public static HttpClient CreateDirectClient(TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = timeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = 64,
            UseProxy = false
        };
        return CreateClient(handler, timeout);
    }

    public static HttpClient CreateProxyClient(int httpPort, TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = timeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = 64,
            Proxy = new WebProxy($"http://127.0.0.1:{httpPort}"),
            UseProxy = true
        };
        return CreateClient(handler, timeout);
    }

    private static HttpClient CreateClient(HttpMessageHandler handler, TimeSpan timeout)
    {
        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = timeout + TimeSpan.FromSeconds(45)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("LokiTrafficLab-Speed/3.4");
        client.DefaultRequestHeaders.AcceptEncoding.Clear();
        client.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
        return client;
    }

    public static async Task<SpeedMeasurementReport> MeasureAsync(
        HttpClient client,
        SpeedTestSettings settings,
        string path,
        CancellationToken cancellationToken = default)
    {
        var watch = Stopwatch.StartNew();
        using var process = Process.GetCurrentProcess();
        var processCpuBefore = process.TotalProcessorTime;
        var managedMemoryBefore = GC.GetTotalMemory(forceFullCollection: false);
        var idleLatency = await MeasureIdleLatencyAsync(client, 5, cancellationToken);
        var series = new List<SpeedFlowSeries>();
        foreach (var flows in settings.FlowCounts.Distinct().Order())
        {
            cancellationToken.ThrowIfCancellationRequested();
            series.Add(await MeasureDirectionAsync(client, settings, "download", flows, cancellationToken));
            cancellationToken.ThrowIfCancellationRequested();
            series.Add(await MeasureDirectionAsync(client, settings, "upload", flows, cancellationToken));
        }
        watch.Stop();
        process.Refresh();
        var cpuDeltaMs = Math.Max(0, (process.TotalProcessorTime - processCpuBefore).TotalMilliseconds);
        var successful = series.Count(item => item.SuccessfulAttempts > 0);
        var confidence = successful == series.Count && series.All(item => item.Confidence == "high") ? "high"
            : successful == series.Count && series.All(item => item.Confidence is "high" or "medium") ? "medium"
            : successful > 0 ? "low" : "unavailable";
        return new SpeedMeasurementReport
        {
            MeasurementVersion = 3,
            Path = path,
            Mode = settings.Mode,
            StartedAt = DateTimeOffset.UtcNow - watch.Elapsed,
            DurationMs = watch.ElapsedMilliseconds,
            TargetWindowMs = settings.TargetWindowMs,
            MeasurementAttempts = settings.MeasurementAttempts,
            FlowCounts = settings.FlowCounts.ToArray(),
            Endpoint = new SpeedEndpointContract
            {
                Download = DownloadEndpoint,
                Upload = UploadEndpoint,
                Latency = LatencyEndpoint,
                ContentEncoding = "identity",
                CacheBust = "unique query parameter per request",
                Limitation = "A public endpoint is route-dependent. Configure a controlled primary and neutral twin for server-timestamped acceptance measurements."
            },
            IdleLatency = idleLatency,
            Series = series,
            ClientLoad = new SpeedClientLoad
            {
                ProcessCpuTimeMs = Math.Round(cpuDeltaMs, 2),
                NormalizedProcessCpuPercent = watch.ElapsedMilliseconds <= 0 ? null
                    : Math.Round(cpuDeltaMs * 100d / watch.ElapsedMilliseconds / Math.Max(1, Environment.ProcessorCount), 2),
                ManagedMemoryBeforeBytes = managedMemoryBefore,
                ManagedMemoryAfterBytes = GC.GetTotalMemory(forceFullCollection: false),
                PeakWorkingSetBytes = process.PeakWorkingSet64,
                Interpretation = "High client CPU or memory pressure can cap application-layer throughput; compare this field across paths."
            },
            Confidence = confidence,
            Interpretation = "recommendedMbps is the median aggregate payload rate across non-calibration attempts. effectiveMbps includes connection/TLS/TTFB or response acknowledgement. Duration, coefficient of variation, loaded latency and byte-cap flags bound confidence."
        };
    }

    private static async Task<SpeedFlowSeries> MeasureDirectionAsync(
        HttpClient client,
        SpeedTestSettings settings,
        string direction,
        int flows,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        var calibrationBytes = direction == "download" ? DownloadCalibrationBytesPerFlow : UploadCalibrationBytesPerFlow;
        var maximumTotalBytes = direction == "download" ? settings.DownloadMaximumBytes : settings.UploadMaximumBytes;
        var calibration = await MeasureBatchAsync(client, direction, flows, calibrationBytes, settings, "calibration", 0, cancellationToken);
        var calibratedMbps = calibration.PayloadMbps ?? calibration.EffectiveMbps ?? 0;
        var targetTotalBytes = calibratedMbps > 0
            ? (long)Math.Ceiling(calibratedMbps * 125d * settings.TargetWindowMs)
            : (long)calibrationBytes * flows;
        var minimumTotalBytes = (long)calibrationBytes * flows;
        targetTotalBytes = Math.Clamp(targetTotalBytes, minimumTotalBytes, maximumTotalBytes);
        var requestedPerFlow = (int)Math.Clamp(
            (long)Math.Ceiling(targetTotalBytes / (double)flows),
            Math.Max(64 * 1024, calibrationBytes),
            Math.Max(calibrationBytes, maximumTotalBytes / Math.Max(1, flows)));

        var attempts = new List<SpeedBatchObservation> { calibration };
        for (var attempt = 1; attempt <= settings.MeasurementAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            attempts.Add(await MeasureBatchAsync(client, direction, flows, requestedPerFlow, settings, "measurement", attempt, cancellationToken));
        }
        watch.Stop();
        var selected = attempts.Where(item => item.Role == "measurement" && item.Success).ToArray();
        var payload = selected.Select(item => item.PayloadMbps).Where(item => item.HasValue).Select(item => item!.Value).Order().ToArray();
        var effective = selected.Select(item => item.EffectiveMbps).Where(item => item.HasValue).Select(item => item!.Value).Order().ToArray();
        var durations = selected.Select(item => item.PayloadElapsedMs ?? item.ElapsedMs).ToArray();
        var variation = CoefficientOfVariation(payload);
        var durationSufficient = durations.Length > 0 && durations.Count(value => value >= settings.TargetWindowMs * 0.8) >= Math.Max(1, durations.Length - 1);
        var hitCap = requestedPerFlow * (long)flows >= maximumTotalBytes;
        var confidence = selected.Length == settings.MeasurementAttempts && variation <= 0.25 && durationSufficient ? "high"
            : selected.Length >= 2 && variation <= 0.50 ? "medium"
            : selected.Length > 0 ? "low" : "unavailable";
        var reasons = new List<string>();
        if (selected.Length < settings.MeasurementAttempts) reasons.Add($"Only {selected.Length}/{settings.MeasurementAttempts} measurement attempts succeeded.");
        if (!durationSufficient) reasons.Add("The byte cap or path behavior prevented most attempts from spanning at least 80% of the target window.");
        if (variation > 0.25) reasons.Add($"Payload coefficient of variation was {variation:F2}.");
        if (hitCap) reasons.Add("Adaptive sizing reached the configured byte budget; high-speed paths may be underestimated.");
        return new SpeedFlowSeries
        {
            Direction = direction,
            Flows = flows,
            TargetWindowMs = settings.TargetWindowMs,
            RequestedBytesPerFlow = requestedPerFlow,
            MaximumTotalBytesPerAttempt = maximumTotalBytes,
            ByteCapReached = hitCap,
            RequestedMeasurementAttempts = settings.MeasurementAttempts,
            SuccessfulAttempts = selected.Length,
            Calibration = calibration,
            Attempts = attempts,
            RecommendedMbps = Median(payload),
            MedianEffectiveMbps = Median(effective),
            P10Mbps = Percentile(payload, 0.10),
            P90Mbps = Percentile(payload, 0.90),
            CoefficientOfVariation = Math.Round(variation, 3),
            Confidence = confidence,
            ConfidenceReasons = reasons,
            ElapsedMs = watch.ElapsedMilliseconds
        };
    }

    private static async Task<SpeedBatchObservation> MeasureBatchAsync(
        HttpClient client,
        string direction,
        int flows,
        int bytesPerFlow,
        SpeedTestSettings settings,
        string role,
        int attempt,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        using var latencyCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var latencyTask = MeasureLoadedLatencyAsync(client, settings.LatencyIntervalMs, latencyCancellation.Token);
        var tasks = Enumerable.Range(1, flows)
            .Select(flow => direction == "download"
                ? DownloadFlowAsync(client, flow, bytesPerFlow, role == "calibration", cancellationToken)
                : UploadFlowAsync(client, flow, bytesPerFlow, role == "calibration", cancellationToken))
            .ToArray();
        SpeedFlowObservation[] observations;
        try
        {
            observations = await Task.WhenAll(tasks);
        }
        finally
        {
            latencyCancellation.Cancel();
        }
        var loadedLatency = await latencyTask;
        watch.Stop();
        var successful = observations.Where(item => item.Success).ToArray();
        var bytes = successful.Sum(item => item.TransferredBytes);
        var payloadStart = successful.Select(item => item.PayloadStartMs).Where(item => item.HasValue).Select(item => item!.Value).DefaultIfEmpty(0).Min();
        // Download separates TTFB from transfer time. Upload deliberately uses the full
        // batch wall clock because per-request socket writes may complete into local OS
        // buffers before the server has acknowledged the final concurrent flow.
        var payloadElapsed = successful.Length == 0 ? (long?)null
            : direction == "upload" ? Math.Max(1, watch.ElapsedMilliseconds)
            : Math.Max(1, watch.ElapsedMilliseconds - payloadStart);
        var effectiveMbps = bytes > 0 ? Math.Round(bytes * 8d / Math.Max(1, watch.ElapsedMilliseconds) / 1000d, 2) : (double?)null;
        var payloadMbps = payloadElapsed.HasValue && bytes > 0 ? Math.Round(bytes * 8d / payloadElapsed.Value / 1000d, 2) : (double?)null;
        return new SpeedBatchObservation
        {
            Role = role,
            Attempt = attempt,
            Flows = flows,
            RequestedBytesPerFlow = bytesPerFlow,
            SuccessfulFlows = successful.Length,
            TransferredBytes = bytes,
            ElapsedMs = watch.ElapsedMilliseconds,
            PayloadElapsedMs = payloadElapsed,
            EffectiveMbps = effectiveMbps,
            PayloadMbps = payloadMbps,
            Success = successful.Length == flows,
            FlowObservations = observations,
            LoadedLatency = loadedLatency,
            Error = successful.Length == flows ? null : $"Only {successful.Length}/{flows} flows completed."
        };
    }

    private static async Task<SpeedFlowObservation> DownloadFlowAsync(
        HttpClient client,
        int flow,
        int requestedBytes,
        bool forceClose,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            var url = $"{DownloadEndpoint}?bytes={requestedBytes}&tlab={Guid.NewGuid():N}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.ConnectionClose = forceClose;
            request.Headers.AcceptEncoding.Clear();
            request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var buffer = new byte[64 * 1024];
            long bytes = 0;
            long? firstByteMs = null;
            while (bytes < requestedBytes)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, requestedBytes - bytes)), cancellationToken);
                if (read == 0) break;
                firstByteMs ??= watch.ElapsedMilliseconds;
                bytes += read;
            }
            watch.Stop();
            return new SpeedFlowObservation
            {
                Flow = flow,
                Success = response.IsSuccessStatusCode && bytes >= requestedBytes,
                StatusCode = (int)response.StatusCode,
                RequestedBytes = requestedBytes,
                TransferredBytes = bytes,
                ElapsedMs = watch.ElapsedMilliseconds,
                PayloadStartMs = firstByteMs,
                PayloadElapsedMs = firstByteMs.HasValue ? Math.Max(1, watch.ElapsedMilliseconds - firstByteMs.Value) : null
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            watch.Stop();
            return new SpeedFlowObservation { Flow = flow, RequestedBytes = requestedBytes, ElapsedMs = watch.ElapsedMilliseconds, Error = ProgramAccess.Redact(ex.Message) };
        }
    }

    private static async Task<SpeedFlowObservation> UploadFlowAsync(
        HttpClient client,
        int flow,
        int requestedBytes,
        bool forceClose,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var content = new GeneratedPayloadContent(requestedBytes);
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{UploadEndpoint}?tlab={Guid.NewGuid():N}") { Content = content };
            request.Headers.ConnectionClose = forceClose;
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            watch.Stop();
            return new SpeedFlowObservation
            {
                Flow = flow,
                Success = response.IsSuccessStatusCode && content.BytesWritten == requestedBytes,
                StatusCode = (int)response.StatusCode,
                RequestedBytes = requestedBytes,
                TransferredBytes = content.BytesWritten,
                ElapsedMs = watch.ElapsedMilliseconds,
                PayloadStartMs = content.WriteStartedMs,
                PayloadElapsedMs = content.WriteElapsedMs,
                ServerAcknowledgementMs = watch.ElapsedMilliseconds
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            watch.Stop();
            return new SpeedFlowObservation { Flow = flow, RequestedBytes = requestedBytes, ElapsedMs = watch.ElapsedMilliseconds, Error = ProgramAccess.Redact(ex.Message) };
        }
    }

    private static async Task<SpeedLatencySummary> MeasureIdleLatencyAsync(HttpClient client, int attempts, CancellationToken cancellationToken)
    {
        var values = new List<long>();
        var failures = 0;
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var value = await ProbeLatencyAsync(client, cancellationToken);
            if (value.HasValue) values.Add(value.Value); else failures++;
        }
        return SummarizeLatency(values, failures);
    }

    private static async Task<SpeedLatencySummary> MeasureLoadedLatencyAsync(HttpClient client, int intervalMs, CancellationToken cancellationToken)
    {
        var values = new List<long>();
        var failures = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var value = await ProbeLatencyAsync(client, cancellationToken);
                if (value.HasValue) values.Add(value.Value); else failures++;
                await Task.Delay(intervalMs, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
        }
        return SummarizeLatency(values, failures);
    }

    private static async Task<long?> ProbeLatencyAsync(HttpClient client, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{LatencyEndpoint}?tlab={Guid.NewGuid():N}");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            watch.Stop();
            return (int)response.StatusCode is >= 200 and < 400 ? watch.ElapsedMilliseconds : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    private static SpeedLatencySummary SummarizeLatency(IReadOnlyList<long> values, int failures)
    {
        var ordered = values.Select(value => (double)value).Order().ToArray();
        var jitter = values.Count < 2 ? (double?)null : Math.Round(values.Zip(values.Skip(1), (a, b) => Math.Abs(a - b)).Average(), 2);
        return new SpeedLatencySummary
        {
            Attempts = values.Count + failures,
            Successful = values.Count,
            Failed = failures,
            LossPercent = values.Count + failures == 0 ? null : Math.Round(failures * 100d / (values.Count + failures), 2),
            P50Ms = Percentile(ordered, 0.50),
            P95Ms = Percentile(ordered, 0.95),
            JitterMs = jitter,
            SamplesMs = values.ToArray()
        };
    }

    public static SpeedPathComparison Compare(SpeedMeasurementReport before, SpeedMeasurementReport tunnel, SpeedMeasurementReport after)
    {
        var rows = new List<SpeedComparisonRow>();
        foreach (var tunnelSeries in tunnel.Series)
        {
            var pre = before.Series.FirstOrDefault(item => item.Direction == tunnelSeries.Direction && item.Flows == tunnelSeries.Flows)?.RecommendedMbps;
            var post = after.Series.FirstOrDefault(item => item.Direction == tunnelSeries.Direction && item.Flows == tunnelSeries.Flows)?.RecommendedMbps;
            var control = Median(new[] { pre, post }.Where(item => item.HasValue).Select(item => item!.Value).Order().ToArray());
            var tunnelMbps = tunnelSeries.RecommendedMbps;
            var drift = pre.HasValue && post.HasValue && Math.Min(pre.Value, post.Value) > 0
                ? Math.Abs(post.Value - pre.Value) / Math.Min(pre.Value, post.Value)
                : (double?)null;
            rows.Add(new SpeedComparisonRow
            {
                Direction = tunnelSeries.Direction,
                Flows = tunnelSeries.Flows,
                DirectBeforeMbps = pre,
                TunnelMbps = tunnelMbps,
                DirectAfterMbps = post,
                InterpolatedDirectMbps = control,
                TunnelEfficiencyPercent = control > 0 && tunnelMbps.HasValue ? Math.Round(tunnelMbps.Value * 100d / control.Value, 2) : null,
                DirectDriftPercent = drift.HasValue ? Math.Round(drift.Value * 100, 2) : null,
                Confidence = !control.HasValue || !tunnelMbps.HasValue ? "unavailable" : drift <= 0.25 ? tunnelSeries.Confidence : "low",
                Interpretation = drift > 0.25
                    ? "Direct controls changed by more than 25%; underlay drift makes proxy attribution low-confidence."
                    : "Direct controls were sufficiently stable for a matched tunnel-efficiency estimate."
            });
        }
        var comparable = rows.Where(item => item.DirectDriftPercent.HasValue).ToArray();
        return new SpeedPathComparison { Rows = rows, DirectControlStable = comparable.Length > 0 && comparable.All(item => item.DirectDriftPercent <= 25) };
    }

    public static StageResult ToStage(string name, SpeedMeasurementReport report)
    {
        var successful = report.Series.Count(item => item.SuccessfulAttempts > 0);
        return StageResult.FromStatus(name,
            successful == report.Series.Count ? "passed" : successful > 0 ? "partial" : "failed",
            report.DurationMs,
            report,
            successful == report.Series.Count ? null : $"Only {successful}/{report.Series.Count} direction/flow series produced a measurement.");
    }

    public static StageResult ToDirectionStage(string name, SpeedMeasurementReport report, string direction)
    {
        var series = report.Series.Where(item => item.Direction == direction).ToArray();
        var successful = series.Count(item => item.SuccessfulAttempts > 0);
        return StageResult.FromStatus(name,
            successful == series.Length && series.Length > 0 ? "passed" : successful > 0 ? "partial" : "failed",
            series.Sum(item => item.ElapsedMs),
            new
            {
                report.MeasurementVersion,
                report.Path,
                report.Mode,
                report.TargetWindowMs,
                report.MeasurementAttempts,
                report.Endpoint,
                report.IdleLatency,
                direction,
                series,
                recommendedMbps = series.FirstOrDefault(item => item.Flows == 1)?.RecommendedMbps,
                aggregateRecommendedMbps = series.OrderByDescending(item => item.Flows).FirstOrDefault()?.RecommendedMbps,
                report.Confidence,
                report.Interpretation
            },
            successful == series.Length && series.Length > 0 ? null : $"Only {successful}/{series.Length} {direction} flow series produced a measurement.");
    }

    private static double CoefficientOfVariation(IReadOnlyList<double> values)
    {
        if (values.Count < 2) return 0;
        var mean = values.Average();
        if (mean <= 0) return 0;
        return Math.Sqrt(values.Sum(value => Math.Pow(value - mean, 2)) / values.Count) / mean;
    }

    private static double? Median(IReadOnlyList<double> values) => Percentile(values, 0.50);

    private static double? Percentile(IReadOnlyList<double> values, double percentile)
    {
        if (values.Count == 0) return null;
        var ordered = values.Order().ToArray();
        if (ordered.Length == 1) return Math.Round(ordered[0], 2);
        var position = Math.Clamp(percentile, 0, 1) * (ordered.Length - 1);
        var lower = (int)Math.Floor(position);
        var upper = (int)Math.Ceiling(position);
        var value = lower == upper ? ordered[lower] : ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower);
        return Math.Round(value, 2);
    }

    private sealed class GeneratedPayloadContent : HttpContent
    {
        private readonly int length;
        public long BytesWritten { get; private set; }
        public long? WriteStartedMs { get; private set; }
        public long? WriteElapsedMs { get; private set; }

        public GeneratedPayloadContent(int length)
        {
            this.length = length;
            Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            Headers.ContentLength = length;
        }

        protected override bool TryComputeLength(out long computedLength) { computedLength = length; return true; }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => await SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            var buffer = new byte[64 * 1024];
            RandomNumberGenerator.Fill(buffer);
            var watch = Stopwatch.StartNew();
            WriteStartedMs = 0;
            var remaining = length;
            while (remaining > 0)
            {
                var count = Math.Min(buffer.Length, remaining);
                await stream.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
                BytesWritten += count;
                remaining -= count;
            }
            await stream.FlushAsync(cancellationToken);
            watch.Stop();
            WriteElapsedMs = Math.Max(1, watch.ElapsedMilliseconds);
        }
    }
}

internal sealed class SpeedMeasurementReport
{
    public int MeasurementVersion { get; init; }
    public string Path { get; init; } = "unknown";
    public string Mode { get; init; } = "normal";
    public DateTimeOffset StartedAt { get; init; }
    public long DurationMs { get; init; }
    public int TargetWindowMs { get; init; }
    public int MeasurementAttempts { get; init; }
    public IReadOnlyList<int> FlowCounts { get; init; } = [];
    public SpeedEndpointContract Endpoint { get; init; } = new();
    public SpeedLatencySummary IdleLatency { get; init; } = new();
    public IReadOnlyList<SpeedFlowSeries> Series { get; init; } = [];
    public SpeedClientLoad ClientLoad { get; init; } = new();
    public string Confidence { get; init; } = "unavailable";
    public string? Interpretation { get; init; }
}

internal sealed class SpeedClientLoad
{
    public double? ProcessCpuTimeMs { get; init; }
    public double? NormalizedProcessCpuPercent { get; init; }
    public long? ManagedMemoryBeforeBytes { get; init; }
    public long? ManagedMemoryAfterBytes { get; init; }
    public long? PeakWorkingSetBytes { get; init; }
    public string? Interpretation { get; init; }
}

internal sealed class SpeedEndpointContract
{
    public string? Download { get; init; }
    public string? Upload { get; init; }
    public string? Latency { get; init; }
    public string? ContentEncoding { get; init; }
    public string? CacheBust { get; init; }
    public string? Limitation { get; init; }
}

internal sealed class SpeedFlowSeries
{
    public string Direction { get; init; } = "unknown";
    public int Flows { get; init; }
    public int TargetWindowMs { get; init; }
    public int RequestedBytesPerFlow { get; init; }
    public int MaximumTotalBytesPerAttempt { get; init; }
    public bool ByteCapReached { get; init; }
    public int RequestedMeasurementAttempts { get; init; }
    public int SuccessfulAttempts { get; init; }
    public SpeedBatchObservation Calibration { get; init; } = new();
    public IReadOnlyList<SpeedBatchObservation> Attempts { get; init; } = [];
    public double? RecommendedMbps { get; init; }
    public double? MedianEffectiveMbps { get; init; }
    public double? P10Mbps { get; init; }
    public double? P90Mbps { get; init; }
    public double CoefficientOfVariation { get; init; }
    public string Confidence { get; init; } = "unavailable";
    public IReadOnlyList<string> ConfidenceReasons { get; init; } = [];
    public long ElapsedMs { get; init; }
}

internal sealed class SpeedBatchObservation
{
    public string Role { get; init; } = "measurement";
    public int Attempt { get; init; }
    public int Flows { get; init; }
    public int RequestedBytesPerFlow { get; init; }
    public int SuccessfulFlows { get; init; }
    public long TransferredBytes { get; init; }
    public long ElapsedMs { get; init; }
    public long? PayloadElapsedMs { get; init; }
    public double? EffectiveMbps { get; init; }
    public double? PayloadMbps { get; init; }
    public bool Success { get; init; }
    public IReadOnlyList<SpeedFlowObservation> FlowObservations { get; init; } = [];
    public SpeedLatencySummary LoadedLatency { get; init; } = new();
    public string? Error { get; init; }
}

internal sealed class SpeedFlowObservation
{
    public int Flow { get; init; }
    public bool Success { get; init; }
    public int? StatusCode { get; init; }
    public int RequestedBytes { get; init; }
    public long TransferredBytes { get; init; }
    public long ElapsedMs { get; init; }
    public long? PayloadStartMs { get; init; }
    public long? PayloadElapsedMs { get; init; }
    public long? ServerAcknowledgementMs { get; init; }
    public string? Error { get; init; }
}

internal sealed class SpeedLatencySummary
{
    public int Attempts { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
    public double? LossPercent { get; init; }
    public double? P50Ms { get; init; }
    public double? P95Ms { get; init; }
    public double? JitterMs { get; init; }
    public IReadOnlyList<long> SamplesMs { get; init; } = [];
}

internal sealed class SpeedPathComparison
{
    public bool DirectControlStable { get; init; }
    public IReadOnlyList<SpeedComparisonRow> Rows { get; init; } = [];
}

internal sealed class SpeedComparisonRow
{
    public string Direction { get; init; } = "unknown";
    public int Flows { get; init; }
    public double? DirectBeforeMbps { get; init; }
    public double? TunnelMbps { get; init; }
    public double? DirectAfterMbps { get; init; }
    public double? InterpolatedDirectMbps { get; init; }
    public double? TunnelEfficiencyPercent { get; init; }
    public double? DirectDriftPercent { get; init; }
    public string Confidence { get; init; } = "unavailable";
    public string? Interpretation { get; init; }
}
