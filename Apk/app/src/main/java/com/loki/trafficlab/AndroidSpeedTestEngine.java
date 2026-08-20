package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONException;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

final class AndroidSpeedTestEngine {
    enum Mode { NORMAL, EXTENDED, SPEED, CONTROL }
    interface CancelCheck { void check() throws InterruptedException; }

    private static final String DOWNLOAD = "https://speed.cloudflare.com/__down?bytes=%d&tlab=%s";
    private static final String UPLOAD = "https://speed.cloudflare.com/__up?tlab=%s";
    private static final String LATENCY = "https://www.google.com/generate_204?tlab=%s";
    private static final String[][] VALIDATION_DOWNLOAD_ENDPOINTS = new String[][]{
            {"cloudflare-anycast", "https://speed.cloudflare.com/__down?bytes=1048576"},
            {"ovh-sbg", "https://sbg.proof.ovh.net/files/10Mb.dat"},
            {"ovh-rbx", "https://rbx.proof.ovh.net/files/10Mb.dat"},
            {"ovh-bhs", "https://bhs.proof.ovh.ca/files/10Mb.dat"}
    };

    private AndroidSpeedTestEngine() {}

    static JSONObject measure(Proxy proxy, Mode mode, CancelCheck cancel) throws InterruptedException {
        return measure(proxy, mode, null, cancel);
    }

    static JSONObject measure(Proxy proxy, Mode mode, JSONObject matchedPlan, CancelCheck cancel) throws InterruptedException {
        Settings settings = mode == Mode.SPEED
                ? new Settings("speed", 4_000, 3, 3, 32 * 1024 * 1024, 16 * 1024 * 1024, new int[]{1, 4, 16})
                : mode == Mode.EXTENDED
                ? new Settings("extended", 3_500, 2, 3, 24 * 1024 * 1024, 12 * 1024 * 1024, new int[]{1, 4, 16})
                : mode == Mode.NORMAL
                ? new Settings("normal", 2_500, 3, 2, 16 * 1024 * 1024, 8 * 1024 * 1024, new int[]{1})
                : new Settings("direct-after-control", 2_500, 2, 2, 16 * 1024 * 1024, 8 * 1024 * 1024, new int[]{1, 4, 16});
        long started = System.nanoTime();
        long cpuStartedMs = android.os.Process.getElapsedCpuTime();
        long heapBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        JSONObject root = JsonUtil.object(
                "measurementVersion", 4,
                "mode", settings.name,
                "method", "adaptive incompressible transfers; calibration excluded; 1/4/16 simultaneous flows; idle and loaded HTTPS latency; bounded streaming upload",
                "targetMeasurementWindowMs", settings.targetMs,
                "planSource", matchedPlan == null ? "locally-calibrated" : "matched-direct-plan",
                "calibrationAttempts", matchedPlan == null ? settings.calibrationAttempts : 0,
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
                series.put(measureSeries(proxy, direction, flows, settings, matchedPlan, cancel));
            }
        }
        applyCrossSeriesClassifications(series);
        JsonUtil.put(root, "series", series);
        JsonUtil.put(root, "endpointValidation", endpointValidation(proxy, cancel));
        JsonUtil.put(root, "measurementPlan", createPlan(series));
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
        JsonUtil.put(root, "interpretation", "Use median window Mbps together with p10/p90, variation, straggler/concurrency classifications, loaded latency and direct-control drift. Android upload remains client/ack bounded without a controlled server timestamp.");
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
                if (drift != null) { compared++; if (drift > 15.0) stable = false; }
                Double baseline = beforeMbps == null ? afterMbps : afterMbps == null ? beforeMbps : (beforeMbps + afterMbps) / 2.0;
                JSONObject row = JsonUtil.object("direction", direction, "flows", flows,
                        "directBeforeMbps", round2(beforeMbps), "tunnelMbps", round2(tunnelMbps),
                        "directAfterMbps", round2(afterMbps), "directDriftPercent", round2(drift),
                        "tunnelToDirectRatio", baseline == null || tunnelMbps == null || baseline <= 0 ? null : round2(tunnelMbps / baseline));
                rows.put(row);
            }
        }
        boolean controlsStable = compared > 0 && compared == rows.length() && stable;
        String confidence = controlsStable ? "high" : "low";
        return JsonUtil.object("rows", rows, "directControlStable", controlsStable,
                "directSeriesCompared", compared, "confidence", confidence,
                "interpretation", controlsStable
                        ? "Same-flow direct controls stayed within 15%; tunnel ratios are comparable within the observed window."
                        : "Direct capacity changed by more than 15% or was unavailable; do not attribute the full difference to the proxy.");
    }

    private static JSONObject measureSeries(Proxy proxy, String direction, int flows, Settings settings, JSONObject matchedPlan, CancelCheck cancel) throws InterruptedException {
        int calibrationPerFlow = "download".equals(direction) ? 256 * 1024 : 128 * 1024;
        int maximumTotal = "download".equals(direction) ? settings.maxDownloadBytes : settings.maxUploadBytes;
        JSONArray batches = new JSONArray();
        JSONObject warmup = batch(proxy, direction, flows, calibrationPerFlow, false, settings.targetMs, cancel);
        JsonUtil.put(warmup, "sampleRole", "warmup"); batches.put(warmup);
        List<Double> calibrationRates = new ArrayList<>();
        if (matchedPlan == null) for (int index = 1; index <= settings.calibrationAttempts; index++) {
            cancel.check();
            JSONObject calibration = batch(proxy, direction, flows, calibrationPerFlow, false, settings.targetMs, cancel);
            JsonUtil.put(calibration, "sampleRole", "calibration"); JsonUtil.put(calibration, "attempt", index); batches.put(calibration);
            if (!"failed".equals(calibration.optString("status"))) calibrationRates.add(calibration.optDouble("aggregateWindowMbps", 0));
        }
        Collections.sort(calibrationRates);
        double calibrationMbps = calibrationRates.isEmpty() ? warmup.optDouble("aggregateWindowMbps", 0) : percentile(calibrationRates, 0.5);
        int totalBytes = ProbeSuite.adaptiveBytes(calibrationMbps, (int) Math.round(settings.targetMs * 1.35),
                calibrationPerFlow * flows, maximumTotal);
        int perFlowBytes = Math.max(64 * 1024, totalBytes / flows);
        perFlowBytes = Math.min(perFlowBytes, Math.max(64 * 1024, maximumTotal / flows));
        if (matchedPlan != null) perFlowBytes = Math.max(calibrationPerFlow,
                Math.min(maximumTotal / Math.max(1, flows), matchedPlan.optInt(direction + ":" + flows, perFlowBytes)));
        for (int attempt = 1; attempt <= settings.attempts; attempt++) {
            cancel.check();
            JSONObject value = batch(proxy, direction, flows, perFlowBytes, false, settings.targetMs, cancel);
            JsonUtil.put(value, "sampleRole", "measurement"); JsonUtil.put(value, "attempt", attempt);
            batches.put(value);
        }
        List<Double> values = new ArrayList<>(); List<Long> measurementDurations = new ArrayList<>(); int successes = 0;
        boolean configuredBudgetReached = perFlowBytes * flows >= maximumTotal;
        for (int index = 0; index < batches.length(); index++) {
            JSONObject value = batches.optJSONObject(index);
            if (value != null && "measurement".equals(value.optString("sampleRole")) && !"failed".equals(value.optString("status"))) {
                successes++; values.add(value.optDouble("aggregateWindowMbps")); measurementDurations.add(value.optLong("wallElapsedMs"));
            }
        }
        Collections.sort(values);
        int sufficientlyLong = 0; for (long duration : measurementDurations) if (duration >= settings.targetMs * 0.8) sufficientlyLong++;
        boolean durationSufficient = !measurementDurations.isEmpty() && sufficientlyLong >= Math.max(1, measurementDurations.size() - 1);
        boolean capReached = configuredBudgetReached && !durationSufficient;
        String status = successes == settings.attempts ? "passed" : successes > 0 ? "partial" : "failed";
        JSONArray classifications = new JSONArray();
        boolean straggler = false; for (int index = 0; index < batches.length(); index++) {
            JSONObject batch = batches.optJSONObject(index);
            if (batch != null && "measurement".equals(batch.optString("sampleRole")) && batch.optBoolean("stragglerDetected")) straggler = true;
        }
        boolean rateLimited = false, requestRejected = false, uploadAckBounded = false;
        for (int index = 0; index < batches.length(); index++) {
            JSONObject value = batches.optJSONObject(index);
            if (value == null || !"measurement".equals(value.optString("sampleRole"))) continue;
            rateLimited |= value.optBoolean("endpointRateLimited");
            requestRejected |= value.optBoolean("endpointRequestRejected");
            uploadAckBounded |= value.optBoolean("uploadAckBoundedEstimate");
        }
        if (straggler) classifications.put("STRAGGLER_DETECTED");
        if (rateLimited) classifications.put("ENDPOINT_RATE_LIMITED");
        if (requestRejected) classifications.put("ENDPOINT_REQUEST_REJECTED");
        if (uploadAckBounded) classifications.put("UPLOAD_ACK_BOUNDED_ESTIMATE");
        if (capReached) classifications.put("BYTE_CAP_LIMITED");
        if (cv(values) > 0.35) classifications.put("ENDPOINT_UNSTABLE");
        if (classifications.length() == 0) classifications.put("VALID");
        JSONObject result = JsonUtil.object("direction", direction, "flows", flows, "status", status,
                "calibrationBytesPerFlow", calibrationPerFlow, "measurementBytesPerFlow", perFlowBytes,
                "measurementAggregateBytesPerBatch", (long) perFlowBytes * flows,
                "byteCapReached", capReached, "successfulMeasurementAttempts", successes,
                "requestedMeasurementAttempts", settings.attempts, "batches", batches, "classifications", classifications);
        if (!values.isEmpty()) {
            JsonUtil.put(result, "p10AggregateMbps", round2(percentile(values, 0.10)));
            JsonUtil.put(result, "medianAggregateMbps", round2(percentile(values, 0.50)));
            JsonUtil.put(result, "p90AggregateMbps", round2(percentile(values, 0.90)));
            JsonUtil.put(result, "coefficientOfVariation", round2(cv(values)));
            JsonUtil.put(result, "confidence", successes >= 3 && cv(values) <= 0.25 && !capReached && !straggler && !uploadAckBounded ? "high"
                    : successes >= 2 && cv(values) <= 0.50 ? "medium" : "low");
        } else JsonUtil.put(result, "error", "No measurement batch completed successfully.");
        return result;
    }

    private static JSONObject batch(Proxy proxy, String direction, int flows, int bytesPerFlow, boolean forceClose, int targetMs, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime();
        ExecutorService workers = Executors.newFixedThreadPool(flows);
        CountDownLatch startGate = new CountDownLatch(1);
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
            int endpointBytesPerFlow = "download".equals(direction) ? normalizeCloudflareMeasurementSize(bytesPerFlow) : bytesPerFlow;
            for (int index = 0; index < flows; index++) {
                final int flow = index + 1;
                futures.add(workers.submit(() -> flow(proxy, direction, flow, endpointBytesPerFlow, forceClose, targetMs, startGate)));
            }
            startGate.countDown();
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
        List<Double> flowRates = new ArrayList<>(); List<Long> flowDurations = new ArrayList<>();
        boolean rateLimited = false, requestRejected = false;
        for (int index = 0; index < observations.length(); index++) {
            JSONObject item = observations.optJSONObject(index); if (item == null) continue;
            rateLimited |= item.optInt("statusCode") == 429;
            requestRejected |= item.optInt("statusCode") == 403;
            if (!item.optBoolean("success")) continue;
            flowRates.add(item.optDouble("effectiveMbps")); flowDurations.add(item.optLong("totalMs"));
        }
        Collections.sort(flowRates); Collections.sort(flowDurations);
        double robustAggregate = flowRates.isEmpty() ? 0 : percentile(flowRates, 0.5) * flows;
        boolean straggler = flowDurations.size() > 1 && flowDurations.get(0) > 0
                && flowDurations.get(flowDurations.size() - 1) > percentileLong(flowDurations, 0.5) * 3;
        boolean uploadAckBounded = "upload".equals(direction) && successful == flows;
        return JsonUtil.object("status", status, "flowsRequested", flows, "flowsSucceeded", successful,
                "plannedBytesPerFlow", bytesPerFlow,
                "endpointBytesPerFlow", "download".equals(direction) ? normalizeCloudflareMeasurementSize(bytesPerFlow) : bytesPerFlow,
                "successfulBytes", successfulBytes, "wallElapsedMs", elapsedMs,
                "aggregateEffectiveMbps", round2(successfulBytes * 8.0 / elapsedMs / 1000.0),
                "aggregateWindowMbps", round2(robustAggregate),
                "estimator", "median per-flow effective Mbps multiplied by requested concurrency; batchCompletionMbps remains available as aggregateEffectiveMbps",
                "stragglerDetected", straggler,
                "endpointRateLimited", rateLimited,
                "endpointRequestRejected", requestRejected,
                "uploadAckBoundedEstimate", uploadAckBounded,
                "loadedLatency", latencySummary(validLatency, loadedLatencies.size() - validLatency.size()),
                "flowObservations", observations);
    }

    private static JSONObject flow(Proxy proxy, String direction, int flow, int bytes, boolean forceClose, int targetMs, CountDownLatch startGate) {
        try {
            startGate.await();
            int timeoutMs = Math.max(4_000, targetMs + 2_500);
            ProbeSuite.HttpResult response = "download".equals(direction)
                    ? ProbeSuite.http(String.format(Locale.ROOT, DOWNLOAD, bytes, UUID.randomUUID()), proxy, "GET", null, bytes, timeoutMs, forceClose, 0)
                    : ProbeSuite.httpGeneratedUpload(String.format(Locale.ROOT, UPLOAD, UUID.randomUUID()), proxy, bytes, timeoutMs, forceClose);
            boolean success = response.statusCode >= 200 && response.statusCode < 300
                    && (!"download".equals(direction) || response.bytesRead >= bytes);
            long payloadMs = "download".equals(direction) ? response.responseTransferElapsedMs : response.requestAcknowledgedElapsedMs;
            return JsonUtil.object("flow", flow, "success", success, "statusCode", response.statusCode,
                    "requestedBytes", bytes,
                    "bytes", "download".equals(direction) ? response.bytesRead : bytes,
                    "totalMs", response.totalElapsedMs, "ttfbMs", response.firstByteElapsedMs,
                    "payloadTransferMs", payloadMs,
                    "serverAcknowledgementMs", response.requestAcknowledgedElapsedMs,
                    "coldEffectiveMbps", round2(("download".equals(direction) ? response.bytesRead : bytes) * 8.0 / Math.max(1, response.totalElapsedMs) / 1000.0),
                    "effectiveMbps", round2(("download".equals(direction) ? response.bytesRead : bytes) * 8.0 / Math.max(1, payloadMs) / 1000.0));
        } catch (Exception error) {
            if (error instanceof InterruptedException) Thread.currentThread().interrupt();
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

    private static JSONArray endpointValidation(Proxy proxy, CancelCheck cancel) throws InterruptedException {
        final int bytes = 1024 * 1024;
        ExecutorService workers = Executors.newFixedThreadPool(VALIDATION_DOWNLOAD_ENDPOINTS.length);
        List<Future<JSONObject>> futures = new ArrayList<>();
        try {
            for (String[] endpoint : VALIDATION_DOWNLOAD_ENDPOINTS) futures.add(workers.submit(() -> {
                long started = System.nanoTime();
                try {
                    String separator = endpoint[1].contains("?") ? "&" : "?";
                    ProbeSuite.HttpResult response = ProbeSuite.http(endpoint[1] + separator + "tlab=" + UUID.randomUUID(),
                            proxy, "GET", null, bytes, 7_000, false, 0);
                    long payloadMs = response.firstByteElapsedMs > 0
                            ? Math.max(1, response.totalElapsedMs - response.firstByteElapsedMs)
                            : response.responseTransferElapsedMs;
                    return JsonUtil.object("name", endpoint[0], "url", endpoint[1],
                            "success", response.statusCode >= 200 && response.statusCode < 400 && response.bytesRead >= bytes,
                            "statusCode", response.statusCode, "bytes", response.bytesRead,
                            "totalMs", response.totalElapsedMs, "ttfbMs", response.firstByteElapsedMs,
                            "payloadMs", payloadMs,
                            "payloadMbps", round2(response.bytesRead * 8.0 / Math.max(1, payloadMs) / 1000.0),
                            "interpretation", "A 1 MiB cross-provider control detects endpoint/CDN/peering bias; it is not merged into the matched primary speed result.");
                } catch (Exception error) {
                    return JsonUtil.object("name", endpoint[0], "url", endpoint[1], "success", false,
                            "totalMs", ProbeSuite.elapsed(started), "error", JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()));
                }
            }));
            JSONArray result = new JSONArray();
            for (Future<JSONObject> future : futures) {
                while (!future.isDone()) { cancel.check(); Thread.sleep(50); }
                try { result.put(future.get()); }
                catch (Exception error) { result.put(JsonUtil.object("success", false, "error", JsonUtil.redact(error.getMessage()))); }
            }
            return result;
        } finally {
            workers.shutdownNow();
        }
    }

    static int normalizeCloudflareMeasurementSize(int requestedBytes) {
        return requestedBytes > 10_000_000 && requestedBytes < 25_000_000 ? 25_000_000 : requestedBytes;
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

    static JSONObject createPlan(JSONObject report) {
        return createPlan(report == null ? null : report.optJSONArray("series"));
    }

    private static JSONObject createPlan(JSONArray series) {
        JSONObject plan = new JSONObject();
        if (series == null) return plan;
        for (int index = 0; index < series.length(); index++) {
            JSONObject item = series.optJSONObject(index); if (item == null) continue;
            JsonUtil.put(plan, item.optString("direction") + ":" + item.optInt("flows"), item.optInt("measurementBytesPerFlow"));
        }
        return plan;
    }

    static JSONObject combine(JSONObject first, JSONObject second) throws JSONException {
        if (first == null) return second == null ? new JSONObject() : new JSONObject(second.toString());
        if (second == null) return new JSONObject(first.toString());
        JSONObject root = new JSONObject(first.toString());
        JSONArray combined = new JSONArray(); JSONArray firstSeries = first.optJSONArray("series"), secondSeries = second.optJSONArray("series");
        if (firstSeries != null) for (int index = 0; index < firstSeries.length(); index++) {
            JSONObject left = firstSeries.optJSONObject(index); if (left == null) continue;
            JSONObject right = find(secondSeries, left.optString("direction"), left.optInt("flows"));
            JSONObject row = new JSONObject(left.toString()); JSONArray allBatches = new JSONArray(); List<Double> values = new ArrayList<>();
            for (JSONObject source : new JSONObject[]{left, right}) {
                if (source == null) continue; JSONArray batches = source.optJSONArray("batches"); if (batches == null) continue;
                for (int batchIndex = 0; batchIndex < batches.length(); batchIndex++) {
                    JSONObject batch = batches.optJSONObject(batchIndex); if (batch == null) continue;
                    allBatches.put(batch);
                    if ("measurement".equals(batch.optString("sampleRole")) && !"failed".equals(batch.optString("status")))
                        values.add(batch.optDouble("aggregateWindowMbps"));
                }
            }
            Collections.sort(values); JsonUtil.put(row, "batches", allBatches);
            JsonUtil.put(row, "successfulMeasurementAttempts", values.size());
            JsonUtil.put(row, "requestedMeasurementAttempts", left.optInt("requestedMeasurementAttempts") + (right == null ? 0 : right.optInt("requestedMeasurementAttempts")));
            if (!values.isEmpty()) {
                JsonUtil.put(row, "p10AggregateMbps", round2(percentile(values, 0.10)));
                JsonUtil.put(row, "medianAggregateMbps", round2(percentile(values, 0.50)));
                JsonUtil.put(row, "p90AggregateMbps", round2(percentile(values, 0.90)));
                JsonUtil.put(row, "coefficientOfVariation", round2(cv(values)));
            }
            JSONArray classifications = mergeClassifications(left.optJSONArray("classifications"), right == null ? null : right.optJSONArray("classifications"));
            if (cv(values) > 0.35) addClassification(classifications, "ENDPOINT_UNSTABLE");
            JsonUtil.put(row, "classifications", classifications); combined.put(row);
        }
        applyCrossSeriesClassifications(combined);
        JsonUtil.put(root, "series", combined); JsonUtil.put(root, "status", overallStatus(combined));
        JsonUtil.put(root, "planSource", "ABBA-combined-matched-plan");
        JsonUtil.put(root, "measurementPlan", createPlan(combined));
        return root;
    }

    static JSONObject summary(JSONObject report) {
        JSONArray series = report == null ? null : report.optJSONArray("series");
        JSONObject download = pickSummarySeries(series, "download"), upload = pickSummarySeries(series, "upload");
        String confidence = minConfidence(download == null ? null : download.optString("confidence"), upload == null ? null : upload.optString("confidence"));
        return JsonUtil.object("downloadMbps", download == null ? null : round2(download.optDouble("medianAggregateMbps")),
                "uploadMbps", upload == null ? null : round2(upload.optDouble("medianAggregateMbps")),
                "downloadFlows", download == null ? null : download.optInt("flows"),
                "uploadFlows", upload == null ? null : upload.optInt("flows"), "confidence", confidence);
    }

    private static JSONObject pickSummarySeries(JSONArray series, String direction) {
        if (series == null) return null; JSONObject fallback = null;
        for (int preferred : new int[]{4, 1, 16}) for (int index = 0; index < series.length(); index++) {
            JSONObject item = series.optJSONObject(index); if (item == null || !direction.equals(item.optString("direction")) || preferred != item.optInt("flows") || !item.has("medianAggregateMbps")) continue;
            if (!hasClassification(item.optJSONArray("classifications"), "CONCURRENCY_COLLAPSE")) return item;
            if (fallback == null) fallback = item;
        }
        return fallback;
    }

    private static void applyCrossSeriesClassifications(JSONArray series) {
        if (series == null) return;
        for (String direction : new String[]{"download", "upload"}) {
            JSONObject baseline = find(series, direction, 1); double one = baseline == null ? 0 : baseline.optDouble("medianAggregateMbps", 0);
            if (one <= 0) continue;
            for (int index = 0; index < series.length(); index++) {
                JSONObject item = series.optJSONObject(index); if (item == null || !direction.equals(item.optString("direction")) || item.optInt("flows") <= 1) continue;
                if (item.optDouble("medianAggregateMbps", 0) >= one * 0.55) continue;
                JSONArray values = item.optJSONArray("classifications"); if (values == null) values = new JSONArray();
                addClassification(values, "CONCURRENCY_COLLAPSE"); JsonUtil.put(item, "classifications", values); JsonUtil.put(item, "confidence", "low");
            }
        }
    }

    private static JSONArray mergeClassifications(JSONArray first, JSONArray second) {
        JSONArray result = new JSONArray();
        for (JSONArray source : new JSONArray[]{first, second}) if (source != null) for (int index = 0; index < source.length(); index++)
            if (!"VALID".equals(source.optString(index))) addClassification(result, source.optString(index));
        if (result.length() == 0) result.put("VALID"); return result;
    }
    private static void addClassification(JSONArray values, String value) { if (!hasClassification(values, value)) values.put(value); }
    private static boolean hasClassification(JSONArray values, String value) { if (values == null) return false; for (int index = 0; index < values.length(); index++) if (value.equals(values.optString(index))) return true; return false; }
    private static String minConfidence(String first, String second) {
        int rank = Math.min(confidenceRank(first), confidenceRank(second)); return rank >= 3 ? "high" : rank == 2 ? "medium" : rank == 1 ? "low" : "unavailable";
    }
    private static int confidenceRank(String value) { return "high".equals(value) ? 3 : "medium".equals(value) ? 2 : "low".equals(value) ? 1 : 0; }
    private static long percentileLong(List<Long> sorted, double value) {
        if (sorted.isEmpty()) return 0; if (sorted.size() == 1) return sorted.get(0);
        double position = value * (sorted.size() - 1); int lower = (int) Math.floor(position), upper = (int) Math.ceil(position);
        return Math.round(lower == upper ? sorted.get(lower) : sorted.get(lower) + (sorted.get(upper) - sorted.get(lower)) * (position - lower));
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
        if (series == null) return null;
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
        final String name; final int targetMs; final int attempts; final int calibrationAttempts; final int maxDownloadBytes; final int maxUploadBytes; final int[] flowCounts;
        Settings(String name, int targetMs, int attempts, int calibrationAttempts, int maxDownloadBytes, int maxUploadBytes, int[] flowCounts) {
            this.name = name; this.targetMs = targetMs; this.attempts = attempts; this.calibrationAttempts = calibrationAttempts;
            this.maxDownloadBytes = maxDownloadBytes; this.maxUploadBytes = maxUploadBytes; this.flowCounts = flowCounts;
        }
    }
}
