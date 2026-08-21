using System.Text.Json;

namespace LokiTrafficLab;

public sealed record EmbeddedAnalyticsResult(
    int ExitCode,
    string RunId,
    string Outcome,
    DateTimeOffset StartedAt,
    JsonElement Report);

public static class EmbeddedAnalyticsRunner
{
    public const string EngineVersion = "3.6.0";

    public static async Task<EmbeddedAnalyticsResult> RunNormalJsonAsync(
        IReadOnlyList<string> vlessUris,
        string xrayPath,
        string networkLabel,
        Action<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vlessUris);
        if (vlessUris.Count == 0)
        {
            throw new ArgumentException("At least one VLESS profile is required.", nameof(vlessUris));
        }

        var outputDirectory = Path.Combine(Path.GetTempPath(), $"cake-full-analytics-{Guid.NewGuid():N}");
        var jsonPath = Path.Combine(outputDirectory, "full-analytics.json");
        Directory.CreateDirectory(outputDirectory);
        try
        {
            var input = new global::RunnerInput
            {
                Uris = vlessUris.ToList(),
                SourceLineNumbers = Enumerable.Range(1, vlessUris.Count).ToList(),
                InputSource = "embedded-client",
                NetworkLabel = string.IsNullOrWhiteSpace(networkLabel) ? "local-current-network" : networkLabel
            };
            var args = new[]
            {
                "run",
                "--test-type", "normal",
                "--json-only", jsonPath,
                "--outdir", outputDirectory,
                "--xray", Path.GetFullPath(xrayPath),
                "--max-profiles", Math.Min(100, vlessUris.Count).ToString(System.Globalization.CultureInfo.InvariantCulture)
            };
            var exitCode = await global::Program
                .RunEmbeddedAsync(args, input, progress, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await using var stream = new FileStream(jsonPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var root = document.RootElement;
            var runId = root.TryGetProperty("runId", out var runIdValue) ? runIdValue.GetString() ?? string.Empty : string.Empty;
            var outcome = root.TryGetProperty("outcome", out var outcomeValue)
                && outcomeValue.ValueKind == JsonValueKind.Object
                && outcomeValue.TryGetProperty("outcome", out var outcomeName)
                    ? outcomeName.GetString() ?? "unknown"
                    : "unknown";
            var startedAt = root.TryGetProperty("startedAt", out var startedAtValue)
                && startedAtValue.TryGetDateTimeOffset(out var parsedStartedAt)
                    ? parsedStartedAt
                    : DateTimeOffset.UtcNow;
            return new EmbeddedAnalyticsResult(exitCode, runId, outcome, startedAt, root.Clone());
        }
        finally
        {
            try
            {
                if (Directory.Exists(outputDirectory))
                {
                    Directory.Delete(outputDirectory, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
