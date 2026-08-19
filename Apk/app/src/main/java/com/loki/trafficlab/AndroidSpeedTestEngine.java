package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

final class AndroidSpeedTestEngine {
    enum Mode { EXTENDED, SPEED, CONTROL }
    interface CancelCheck { void check() throws InterruptedException; }

    private static final String DOWNLOAD = "https://speed.cloudflare.com/__down?bytes=%d&tlab=%s";
    private static final String UPLOAD = "https://speed.cloudflare.com/__up?tlab=%s";
    private static final String LATENCY = "https://www.google.com/generate_204?tlab=%s";

    private AndroidSpeedTestEngine() {}

    static JSONObject measure(Proxy proxy, Mode mode, CancelCheck cancel) throws InterruptedException {
        Settings settings = mode == Mode.SPEED
                ? new Settings("speed", 3_000, 3, 16 * 1024 * 1024, 8 * 1024 * 1024, new int[]{1, 4, 16})
                : mode == Mode.EXTENDED
                ? new Settings("extended", 2_500, 2, 12 * 1024 * 1024, 6 * 1024 * 1024, new int[]{1, 4, 16})
                : new Settings("direct-after-control", 1_500, 2, 8 * 1024 * 1024, 4 * 1024 * 1024, new int[]{1});
        long started = System.nanoTime();
        long cpuStartedMs = android.os.Process.getElapsedCpuTime();
        long heapBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        JSONObject root = JsonUtil.object(
                "measurementVersion", 3,
                "mode", settings.name,
                "method", "adaptive incompressible transfers; calibration excluded; 1/4/16 simultaneous flows; idle and loaded HTTPS latency; bounded streaming upload",
                "targetMeasurementWindowMs", settings.targetMs,
                "measurementAttemptsPerSeries", settings.attempts,
                "flowCounts", intArray(settings.flowCounts),
                "resourceBounds", JsonUtil.object(
                        "maximumAggregateDownloadBytesPerBatch", settings.maxDownloadBytes,
                        "maximumAggregateUploadBytesPerBatch", settings.maxUploadBytes,
                        "uploadBufferBytesPerFlow", 64 * 1024,
                        "payloadRetainedInMemory", false));
        JsonUtil.put(root, "idleLatency", latency(proxy, 6, cancel));
        JSONArray series = new JSONArray();
        for (String direction : new String[]{"download", "upload"}) {
            for (int flows : settings.flowCounts) {
                cancel.check();
                series.put(measureSeries(proxy, direction, flows, settings, cancel));
            }
        }
        JsonUtil.put(root, "series", series);
        JsonUtil.put(root, "status", overallStatus(series));
        long elapsedMs = ProbeSuite.elapsed(started);
        long cpuElapsedMs = Math.max(0, android.os.Process.getElapsedCpuTime() - cpuStartedMs);
        long heapAfter = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        JsonUtil.put(root, "elapsedMs", elapsedMs);
        JsonUtil.put(root, "clientLoad", JsonUtil.object("processCpuTimeMs", cpuElapsedMs,
                "normalizedProcessCpuPercent", elapsedMs <= 0 ? null : round2(cpuElapsedMs * 100.0 / elapsedMs / Math.max(1, Runtime.getRuntime().availableProcessors())),
                "heapUsedBeforeBytes", heapBefore, "heapUsedAfterBytes", heapAfter,
                "availableProcessors", Runtime.getRuntime().availableProcessors(),
                "interpretation", "High app CPU or heap pressure can cap measured HTTPS throughput; Android thermal/power state is recorded in the node metadata."));
        JsonUtil.put(root, "interpretation", "Use the median aggregate Mbps together with p10/p90, coefficient of variation, byte-cap flags, loaded latency and direct-control drift. It is not an ISP line-rate claim when the endpoint, radio or byte cap is limiting.");
        return root;
    }

    static JSONObject compare(JSONObject directBefore, JSONObject tunnel, JSONObject directAfter) {
        JSONArray rows = new JSONArray();
        JSONArray beforeSeries = directBefore.optJSONArray("series");
        JSONArray tunnelSeries = tunnel.optJSONArray("series");
        JSONArray afterSeries = directAfter.optJSONArray("series");
        boolean stable = true;
        int compared = 0;
        if (beforeSeries != null && tunnelSeries != null && afterSeries != null) {
            for (int index = 0; index < beforeSeries.length(); index++) {
                JSONObject before = beforeSeries.optJSONObject(index);
                if (before == null) continue;
                String direction = before.optString("direction"); int flows = before.optInt("flows");
                JSONObject through = find(tunnelSeries, direction, flows);
                JSONObject after = find(afterSeries, direction, flows);
                Double beforeMbps = number(before, "medianAggregateMbps");
                Double tunnelMbps = number(through, "medianAggregateMbps");
                Double afterMbps = number(after, "medianAggregateMbps");
                Double drift = percentDifference(beforeMbps, afterMbps);
                if (drift != null) { compared++; if (drift > 25.0) stable = false; }
                Double baseline = beforeMbps == null ? afterMbps : afterMbps == null ? beforeMbps : (beforeMbps + afterMbps) / 2.0;
                JSONObject row = JsonUtil.object("direction", direction, "flows", flows,
                        "directBeforeMbps", round2(beforeMbps), "tunnelMbps", round2(tunnelMbps),
                        "directAfterMbps", round2(afterMbps), "directDriftPercent", round2(drift),
                        "tunnelToDirectRatio", baseline == null || tunnelMbps == null || baseline <= 0 ? null : round2(tunnelMbps / baseline));
                rows.put(row);
            }
        }
        boolean controlsStable = compared > 0 && stable;
        String confidence = controlsStable ? "high" : "low";
        return JsonUtil.object("rows", rows, "directControlStable", controlsStable,
                "directSeriesCompared", compared, "confidence", confidence,
                "interpretation", controlsStable
                        ? "Direct before/after controls stayed within 25%; tunnel ratios are comparable within the observed window."
                        : "Direct capacity changed by more than 25% or was unavailable; do not attribute the full difference to the proxy.");
    }

    private static JSONObject measureSeries(Proxy proxy, String direction, int flows, Settings settings, CancelCheck cancel) throws InterruptedException {
        int calibrationPerFlow = "download".equals(direction) ? 256 * 1024 : 128 * 1024;
        int maximumTotal = "download".equals(direction) ? settings.maxDownloadBytes : settings.maxUploadBytes;
        JSONArray batches = new JSONArray();
        JSONObject calibration = batch(proxy, direction, flows, calibrationPerFlow, true, cancel);
        JsonUtil.put(calibration, "sampleRole", "calibration"); batches.put(calibration);
        double calibrationMbps = calibration.optDouble("aggregateEffectiveMbps", 0);
        int totalBytes = ProbeSuite.adaptiveBytes(calibrationMbps, settings.targetMs,
                calibrationPerFlow * flows, maximumTotal);
        int perFlowBytes = Math.max(64 * 1024, totalBytes / flows);
        perFlowBytes = Math.min(perFlowBytes, Math.max(64 * 1024, maximumTotal / flows));
        for (int attempt = 1; attempt <= settings.attempts; attempt++) {
            cancel.check();
            JSONObject value = batch(proxy, direction, flows, perFlowBytes, false, cancel);
            JsonUtil.put(value, "sampleRole", "measurement"); JsonUtil.put(value, "attempt", attempt);
            batches.put(value);
        }
        List<Double> values = new ArrayList<>(); int successes = 0;
        boolean capReached = perFlowBytes * flows >= maximumTotal;
        for (int index = 1; index < batches.length(); index++) {
            JSONObject value = batches.optJSONObject(index);
            if (value != null && "passed".equals(value.optString("status"))) {
                successes++; values.add(value.optDouble("aggregateEffectiveMbps"));
            }
        }
        Collections.sort(values);
        String status = successes == settings.attempts ? "passed" : successes > 0 ? "partial" : "failed";
        JSONObject result = JsonUtil.object("direction", direction, "flows", flows, "status", status,
                "calibrationBytesPerFlow", calibrationPerFlow, "measurementBytesPerFlow", perFlowBytes,
                "measurementAggregateBytesPerBatch", (long) perFlowBytes * flows,
                "byteCapReached", capReached, "successfulMeasurementAttempts", successes,
                "requestedMeasurementAttempts", settings.attempts, "batches", batches);
        if (!values.isEmpty()) {
            JsonUtil.put(result, "p10AggregateMbps", round2(percentile(values, 0.10)));
            JsonUtil.put(result, "medianAggregateMbps", round2(percentile(values, 0.50)));
            JsonUtil.put(result, "p90AggregateMbps", round2(percentile(values, 0.90)));
            JsonUtil.put(result, "coefficientOfVariation", round2(cv(values)));
            JsonUtil.put(result, "confidence", successes >= 3 && cv(values) <= 0.25 && !capReached ? "high"
                    : successes >= 2 && cv(values) <= 0.50 ? "medium" : "low");
        } else JsonUtil.put(result, "error", "No measurement batch completed successfully.");
        return result;
    }

    private static JSONObject batch(Proxy proxy, String direction, int flows, int bytesPerFlow, boolean forceClose, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime();
        ExecutorService workers = Executors.newFixedThreadPool(flows);
        AtomicBoolean transferActive = new AtomicBoolean(true);
        List<Long> loadedLatencies = Collections.synchronizedList(new ArrayList<>());
        Thread latencyThread = new Thread(() -> {
            while (transferActive.get()) {
                try {
                    long probeStarted = System.nanoTime();
                    ProbeSuite.http(String.format(Locale.ROOT, LATENCY, UUID.randomUUID()), proxy, "GET", null, 4 * 1024, 5_000, false, 0);
                    loadedLatencies.add(ProbeSuite.elapsed(probeStarted));
                    Thread.sleep(120);
                } catch (InterruptedException error) { Thread.currentThread().interrupt(); break; }
                catch (Exception ignored) { loadedLatencies.add(-1L); }
            }
        }, "tlab-loaded-latency");
        latencyThread.start();
        JSONArray observations = new JSONArray(); int successful = 0; long successfulBytes = 0;
        try {
            List<Future<JSONObject>> futures = new ArrayList<>();
            for (int index = 0; index < flows; index++) {
                final int flow = index + 1;
                futures.add(workers.submit(() -> flow(proxy, direction, flow, bytesPerFlow, forceClose)));
            }
            for (Future<JSONObject> future : futures) {
                while (!future.isDone()) { cancel.check(); Thread.sleep(100); }
                cancel.check();
                try {
                    JSONObject item = future.get(); observations.put(item);
                    if (item.optBoolean("success")) { successful++; successfulBytes += item.optLong("bytes"); }
                } catch (Exception error) {
                    observations.put(JsonUtil.object("success", false, "error", JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage())));
                }
            }
        } finally {
            transferActive.set(false); latencyThread.interrupt(); latencyThread.join(1_000); workers.shutdownNow();
        }
        long elapsedMs = Math.max(1, ProbeSuite.elapsed(started));
        List<Long> validLatency = new ArrayList<>(); for (Long value : loadedLatencies) if (value != null && value >= 0) validLatency.add(value);
        Collections.sort(validLatency);
        String status = successful == flows ? "passed" : successful > 0 ? "partial" : "failed";
        return JsonUtil.object("status", status, "flowsRequested", flows, "flowsSucceeded", successful,
                "bytesPerFlow", bytesPerFlow, "successfulBytes", successfulBytes, "wallElapsedMs", elapsedMs,
                "aggregateEffectiveMbps", round2(successfulBytes * 8.0 / elapsedMs / 1000.0),
                "loadedLatency", latencySummary(validLatency, loadedLatencies.size() - validLatency.size()),
                "flowObservations", observations);
    }

    private static JSONObject flow(Proxy proxy, String direction, int flow, int bytes, boolean forceClose) {
        try {
            ProbeSuite.HttpResult response = "download".equals(direction)
                    ? ProbeSuite.http(String.format(Locale.ROOT, DOWNLOAD, bytes, UUID.randomUUID()), proxy, "GET", null, bytes, 30_000, forceClose, 0)
                    : ProbeSuite.httpGeneratedUpload(String.format(Locale.ROOT, UPLOAD, UUID.randomUUID()), proxy, bytes, 30_000, forceClose);
            boolean success = response.statusCode >= 200 && response.statusCode < 300
                    && (!"download".equals(direction) || response.bytesRead >= bytes);
            return JsonUtil.object("flow", flow, "success", success, "statusCode", response.statusCode,
                    "bytes", "download".equals(direction) ? response.bytesRead : bytes,
                    "totalMs", response.totalElapsedMs, "ttfbMs", response.firstByteElapsedMs,
                    "payloadTransferMs", "download".equals(direction) ? response.responseTransferElapsedMs : response.requestAcknowledgedElapsedMs,
                    "effectiveMbps", round2(("download".equals(direction) ? response.bytesRead : bytes) * 8.0 / Math.max(1, response.totalElapsedMs) / 1000.0));
        } catch (Exception error) {
            return JsonUtil.object("flow", flow, "success", false,
                    "error", JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()));
        }
    }

    private static JSONObject latency(Proxy proxy, int attempts, CancelCheck cancel) throws InterruptedException {
        List<Long> values = new ArrayList<>(); int failures = 0;
        for (int index = 0; index < attempts; index++) {
            cancel.check(); long started = System.nanoTime();
            try { ProbeSuite.http(String.format(Locale.ROOT, LATENCY, UUID.randomUUID()), proxy, "GET", null, 4096, 5_000, false, 0); values.add(ProbeSuite.elapsed(started)); }
            catch (Exception error) { failures++; }
        }
        Collections.sort(values); return latencySummary(values, failures);
    }

    private static JSONObject latencySummary(List<Long> sorted, int failures) {
        JSONArray samples = new JSONArray(); for (long value : sorted) samples.put(value);
        JSONObject result = JsonUtil.object("successful", sorted.size(), "failed", failures, "samplesMs", samples);
        if (!sorted.isEmpty()) {
            List<Double> values = new ArrayList<>(); for (long value : sorted) values.add((double) value);
            JsonUtil.put(result, "medianMs", Math.round(percentile(values, 0.5)));
            JsonUtil.put(result, "p90Ms", Math.round(percentile(values, 0.9)));
            JsonUtil.put(result, "jitterMs", round2(stddev(values)));
        }
        return result;
    }

    private static String overallStatus(JSONArray series) {
        int passed = 0, partial = 0;
        for (int index = 0; index < series.length(); index++) {
            String status = series.optJSONObject(index) == null ? "failed" : series.optJSONObject(index).optString("status");
            if ("passed".equals(status)) passed++; else if ("partial".equals(status)) partial++;
        }
        return passed == series.length() ? "passed" : passed + partial > 0 ? "partial" : "failed";
    }

    private static JSONObject find(JSONArray series, String direction, int flows) {
        for (int index = 0; index < series.length(); index++) {
            JSONObject item = series.optJSONObject(index);
            if (item != null && direction.equals(item.optString("direction")) && flows == item.optInt("flows")) return item;
        }
        return null;
    }

    private static Double number(JSONObject object, String key) {
        return object == null || !object.has(key) ? null : object.optDouble(key);
    }
    private static Double percentDifference(Double first, Double second) {
        if (first == null || second == null || first <= 0 || second <= 0) return null;
        return Math.abs(first - second) / ((first + second) / 2.0) * 100.0;
    }
    private static Object round2(Double value) { return value == null || !Double.isFinite(value) ? null : Math.round(value * 100.0) / 100.0; }
    private static JSONArray intArray(int[] values) { JSONArray result = new JSONArray(); for (int value : values) result.put(value); return result; }
    private static double percentile(List<Double> sorted, double value) {
        if (sorted.size() == 1) return sorted.get(0);
        double position = value * (sorted.size() - 1); int lower = (int) Math.floor(position), upper = (int) Math.ceil(position);
        if (lower == upper) return sorted.get(lower);
        return sorted.get(lower) + (sorted.get(upper) - sorted.get(lower)) * (position - lower);
    }
    private static double cv(List<Double> values) {
        if (values.size() < 2) return 0; double mean = 0; for (double value : values) mean += value; mean /= values.size();
        return mean == 0 ? 0 : stddev(values) / mean;
    }
    private static double stddev(List<Double> values) {
        if (values.size() < 2) return 0; double mean = 0; for (double value : values) mean += value; mean /= values.size();
        double variance = 0; for (double value : values) variance += (value - mean) * (value - mean);
        return Math.sqrt(variance / values.size());
    }

    private static final class Settings {
        final String name; final int targetMs; final int attempts; final int maxDownloadBytes; final int maxUploadBytes; final int[] flowCounts;
        Settings(String name, int targetMs, int attempts, int maxDownloadBytes, int maxUploadBytes, int[] flowCounts) {
            this.name = name; this.targetMs = targetMs; this.attempts = attempts;
            this.maxDownloadBytes = maxDownloadBytes; this.maxUploadBytes = maxUploadBytes; this.flowCounts = flowCounts;
        }
    }
}
