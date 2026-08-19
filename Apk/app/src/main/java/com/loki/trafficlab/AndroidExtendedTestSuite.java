package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

final class AndroidExtendedTestSuite {
    static final int SOAK_SECONDS = 300;
    static final int PARALLEL_FLOWS = 20;
    static final int INTERRUPTION_SECONDS = 5;
    private static final String TARGET = "https://www.google.com/generate_204";

    interface CancelCheck { void check() throws InterruptedException; }
    interface Progress { void update(int percent, String message); }

    private AndroidExtendedTestSuite() {}

    static JSONArray run(XrayManager xray, ConnectionParser.Profile profile, CancelCheck cancel, Progress progress) throws InterruptedException {
        JSONArray stages = new JSONArray();
        JSONObject directSpeedBefore = AndroidSpeedTestEngine.measure(null, AndroidSpeedTestEngine.Mode.EXTENDED, cancel::check);
        JSONObject tunnelSpeed = null;
        XrayManager.RunSession session = null;
        try {
            cancel.check();
            session = xray.start(profile);
            Proxy proxy = httpProxy(session.httpPort);
            tunnelSpeed = AndroidSpeedTestEngine.measure(proxy, AndroidSpeedTestEngine.Mode.EXTENDED, cancel::check);
            progress.update(12, "extended speed matrix completed");
            stages.put(coldWarm(proxy, cancel));
            progress.update(20, "cold/warm connection comparison completed");
            stages.put(parallelTcp(proxy, cancel));
            progress.update(30, "parallel TCP flows completed");
            stages.put(parallelUdp(session.socksPort, cancel));
            progress.update(40, "parallel UDP flows completed");
            stages.put(dnsFailureRecovery(proxy, cancel));
            progress.update(48, "DNS failure/recovery completed");
            stages.put(soak(proxy, cancel, (elapsed, total) ->
                    progress.update(48 + (int) Math.min(34, elapsed * 34L / Math.max(1, total)), "extended stability soak")));
            progress.update(82, "five-minute stability soak completed");
        } catch (InterruptedException error) {
            throw error;
        } catch (Exception error) {
            String reason = JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage());
            if (stages.length() == 0) stages.put(JsonUtil.failed("tunnel.extended.coldWarm", 0, reason, null));
            for (String name : new String[]{"tunnel.extended.parallelTcp", "tunnel.extended.parallelUdp", "tunnel.extended.dnsFailureRecovery", "tunnel.extended.soak"}) {
                if (!containsStage(stages, name)) stages.put(JsonUtil.skipped(name, "Extended Xray session was unavailable: " + reason));
            }
        } finally {
            if (session != null) session.close();
        }

        cancel.check();
        JSONObject directSpeedAfter = AndroidSpeedTestEngine.measure(null, AndroidSpeedTestEngine.Mode.CONTROL, cancel::check);
        if (tunnelSpeed == null) {
            stages.put(JsonUtil.skipped("tunnel.extended.speedMatrix", "The isolated tunnel speed session was unavailable."));
        } else {
            JSONObject data = JsonUtil.object("directBefore", directSpeedBefore, "tunnel", tunnelSpeed,
                    "directAfter", directSpeedAfter,
                    "comparison", AndroidSpeedTestEngine.compare(directSpeedBefore, tunnelSpeed, directSpeedAfter));
            boolean stable = data.optJSONObject("comparison").optBoolean("directControlStable");
            stages.put(stable ? JsonUtil.passed("tunnel.extended.speedMatrix", 0, data)
                    : JsonUtil.partial("tunnel.extended.speedMatrix", 0, "Direct control drift exceeded 25% or lacked comparable samples.", data));
        }

        cancel.check();
        stages.put(restartRecovery(xray, profile, 0, "tunnel.extended.reconnect", "forced_core_restart", cancel));
        progress.update(92, "forced reconnect completed");
        cancel.check();
        stages.put(restartRecovery(xray, profile, INTERRUPTION_SECONDS * 1000L,
                "tunnel.extended.networkInterruption", "controlled_xray_process_stop", cancel));
        progress.update(100, "process-scoped interruption recovery completed");
        return stages;
    }

    private static JSONObject coldWarm(Proxy proxy, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime();
        JSONArray cold = new JSONArray();
        JSONArray warm = new JSONArray();
        for (int index = 0; index < 6; index++) {
            cancel.check();
            cold.put(httpObservation(TARGET + "?tlab=" + UUID.randomUUID(), proxy, true, index + 1));
        }
        for (int index = 0; index < 6; index++) {
            cancel.check();
            warm.put(httpObservation(TARGET, proxy, false, index + 1));
        }
        JSONObject data = new JSONObject();
        JsonUtil.put(data, "target", TARGET); JsonUtil.put(data, "samplesPerMode", 6);
        JsonUtil.put(data, "cold", summarize(cold)); JsonUtil.put(data, "warm", summarize(warm));
        JsonUtil.put(data, "coldRequests", cold); JsonUtil.put(data, "warmRequests", warm);
        JsonUtil.put(data, "interpretation", "Cold requests ask the origin and proxy to close the connection and use unique URLs; warm requests request keep-alive reuse. Android/network pools may still influence reuse, and a controlled canary is required to prove server connection identity.");
        boolean passed = successes(cold) > 0 && successes(warm) > 0;
        return passed ? JsonUtil.passed("tunnel.extended.coldWarm", ProbeSuite.elapsed(started), data)
                : JsonUtil.failed("tunnel.extended.coldWarm", ProbeSuite.elapsed(started), "Cold or warm mode produced no successful request.", data);
    }

    private static JSONObject parallelTcp(Proxy proxy, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(10, PARALLEL_FLOWS));
        JSONArray observations = new JSONArray();
        try {
            List<Callable<JSONObject>> tasks = new ArrayList<>();
            for (int index = 0; index < PARALLEL_FLOWS; index++) {
                final int ordinal = index + 1;
                tasks.add(() -> httpObservation(TARGET + "?parallel=" + ordinal + "-" + UUID.randomUUID(), proxy, true, ordinal));
            }
            List<Future<JSONObject>> futures = pool.invokeAll(tasks);
            for (Future<JSONObject> future : futures) {
                cancel.check();
                try { observations.put(future.get()); }
                catch (Exception error) { observations.put(failedObservation(observations.length() + 1, error)); }
            }
        } finally {
            pool.shutdownNow();
        }
        JSONObject data = new JSONObject(); int passed = successes(observations);
        JsonUtil.put(data, "requestedFlows", PARALLEL_FLOWS); JsonUtil.put(data, "successfulFlows", passed);
        JsonUtil.put(data, "failedFlows", PARALLEL_FLOWS - passed); JsonUtil.put(data, "wallClockMs", ProbeSuite.elapsed(started));
        JsonUtil.put(data, "latency", summarize(observations)); JsonUtil.put(data, "observations", observations);
        JsonUtil.put(data, "interpretation", "Each logical flow creates an independent URLConnection and requests Connection: close. Server-side multiplexing remains opaque without a controlled canary.");
        return passed == PARALLEL_FLOWS ? JsonUtil.passed("tunnel.extended.parallelTcp", ProbeSuite.elapsed(started), data)
                : passed > 0 ? JsonUtil.partial("tunnel.extended.parallelTcp", ProbeSuite.elapsed(started), "Some parallel TCP flows failed.", data)
                : JsonUtil.failed("tunnel.extended.parallelTcp", ProbeSuite.elapsed(started), "All parallel TCP flows failed.", data);
    }

    private static JSONObject parallelUdp(int socksPort, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(10, PARALLEL_FLOWS));
        JSONArray observations = new JSONArray();
        try {
            List<Callable<JSONObject>> tasks = new ArrayList<>();
            for (int index = 0; index < PARALLEL_FLOWS; index++) {
                final int ordinal = index + 1;
                tasks.add(() -> {
                    JSONObject stage = ProbeSuite.socksUdpDns(socksPort);
                    return JsonUtil.object("ordinal", ordinal, "success", "passed".equals(stage.optString("status")),
                            "elapsedMs", stage.optLong("elapsedMs"), "error", stage.optString("error", null));
                });
            }
            List<Future<JSONObject>> futures = pool.invokeAll(tasks);
            for (Future<JSONObject> future : futures) {
                cancel.check();
                try { observations.put(future.get()); }
                catch (Exception error) { observations.put(failedObservation(observations.length() + 1, error)); }
            }
        } finally {
            pool.shutdownNow();
        }
        JSONObject data = new JSONObject(); int passed = successes(observations);
        JsonUtil.put(data, "requestedFlows", PARALLEL_FLOWS); JsonUtil.put(data, "successfulFlows", passed);
        JsonUtil.put(data, "failedFlows", PARALLEL_FLOWS - passed); JsonUtil.put(data, "wallClockMs", ProbeSuite.elapsed(started));
        JsonUtil.put(data, "observations", observations);
        JsonUtil.put(data, "interpretation", "Every flow creates its own SOCKS5 UDP ASSOCIATE control connection and UDP socket; resolver rate limiting can cause isolated failures.");
        return passed == PARALLEL_FLOWS ? JsonUtil.passed("tunnel.extended.parallelUdp", ProbeSuite.elapsed(started), data)
                : passed > 0 ? JsonUtil.partial("tunnel.extended.parallelUdp", ProbeSuite.elapsed(started), "Some parallel UDP flows failed.", data)
                : JsonUtil.failed("tunnel.extended.parallelUdp", ProbeSuite.elapsed(started), "All parallel UDP flows failed.", data);
    }

    private static JSONObject dnsFailureRecovery(Proxy proxy, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime(); String invalid = UUID.randomUUID().toString().replace("-", "") + ".traffic-lab.invalid";
        JSONObject failure; boolean failureObserved;
        try {
            JSONObject observation = httpObservation("https://" + invalid + "/", proxy, true, 1);
            failureObserved = !observation.optBoolean("success"); failure = observation;
        } catch (Exception error) {
            failureObserved = true; failure = failedObservation(1, error);
        }
        cancel.check();
        JSONObject recovery = httpObservation(TARGET, proxy, true, 1);
        boolean recovered = recovery.optBoolean("success");
        JSONObject data = JsonUtil.object("failureName", invalid, "expectedFailure", failure, "recovery", recovery,
                "failureObserved", failureObserved, "recovered", recovered,
                "interpretation", "A unique reserved .invalid name exercises tunneled DNS failure, followed by a valid destination. It does not inject an outage into the operator recursive resolver.");
        return failureObserved && recovered ? JsonUtil.passed("tunnel.extended.dnsFailureRecovery", ProbeSuite.elapsed(started), data)
                : JsonUtil.partial("tunnel.extended.dnsFailureRecovery", ProbeSuite.elapsed(started), "Expected DNS failure or subsequent recovery was not observed.", data);
    }

    private interface SoakProgress { void update(long elapsedSeconds, long totalSeconds); }

    private static JSONObject soak(Proxy proxy, CancelCheck cancel, SoakProgress progress) throws InterruptedException {
        long started = System.nanoTime(); long deadline = System.currentTimeMillis() + SOAK_SECONDS * 1000L;
        JSONArray samples = new JSONArray(); int ordinal = 0;
        while (System.currentTimeMillis() < deadline) {
            cancel.check(); long cycle = System.currentTimeMillis();
            samples.put(httpObservation(TARGET, proxy, false, ++ordinal));
            long elapsedSeconds = Math.min(SOAK_SECONDS, ProbeSuite.elapsed(started) / 1000L);
            progress.update(elapsedSeconds, SOAK_SECONDS);
            sleepCancelable(Math.max(0, 1000L - (System.currentTimeMillis() - cycle)), cancel);
        }
        int passed = successes(samples); int failed = samples.length() - passed;
        JSONObject data = new JSONObject();
        JsonUtil.put(data, "requestedDurationSeconds", SOAK_SECONDS); JsonUtil.put(data, "actualDurationSeconds", ProbeSuite.elapsed(started) / 1000.0);
        JsonUtil.put(data, "attempts", samples.length()); JsonUtil.put(data, "successes", passed); JsonUtil.put(data, "failures", failed);
        JsonUtil.put(data, "lossPercent", samples.length() == 0 ? 100 : Math.round(failed * 10000.0 / samples.length()) / 100.0);
        JsonUtil.put(data, "maximumConsecutiveLoss", maximumConsecutiveLoss(samples)); JsonUtil.put(data, "latency", summarize(samples));
        JsonUtil.put(data, "jitter", jitter(samples)); JsonUtil.put(data, "samples", samples);
        JsonUtil.put(data, "interpretation", "Loss is a failed timed HTTPS application probe, not ICMP packet loss. Jitter is the absolute difference between consecutive successful application RTT samples.");
        return failed == 0 && passed > 0 ? JsonUtil.passed("tunnel.extended.soak", ProbeSuite.elapsed(started), data)
                : passed > 0 ? JsonUtil.partial("tunnel.extended.soak", ProbeSuite.elapsed(started), "Application-probe loss occurred during the soak.", data)
                : JsonUtil.failed("tunnel.extended.soak", ProbeSuite.elapsed(started), "No soak probe succeeded.", data);
    }

    private static JSONObject restartRecovery(XrayManager xray, ConnectionParser.Profile profile, long interruptionMs,
                                              String stageName, String reason, CancelCheck cancel) throws InterruptedException {
        long started = System.nanoTime(); XrayManager.RunSession first = null; XrayManager.RunSession second = null;
        JSONObject before = null; JSONObject during = null; JSONObject after = null;
        boolean breakObserved = false; boolean recovered = false;
        String windowStart = null; String windowEnd = null;
        try {
            cancel.check(); first = xray.start(profile); Proxy oldProxy = httpProxy(first.httpPort);
            before = httpObservation(TARGET, oldProxy, true, 1);
            windowStart = JsonUtil.now(); xray.cancel(); first.close(); first = null;
            during = httpObservation(TARGET, oldProxy, true, 1); breakObserved = !during.optBoolean("success");
            sleepCancelable(interruptionMs, cancel); windowEnd = JsonUtil.now();
            second = xray.start(profile); after = httpObservation(TARGET, httpProxy(second.httpPort), true, 1);
            recovered = after.optBoolean("success");
        } catch (InterruptedException error) {
            throw error;
        } catch (Exception error) {
            if (after == null) after = failedObservation(1, error);
        } finally {
            if (first != null) first.close(); if (second != null) second.close();
        }
        JSONObject data = JsonUtil.object("beforeBreak", before, "breakObserved", breakObserved, "duringBreak", during,
                "afterRestart", after, "recovered", recovered, "requestedInterruptionSeconds", interruptionMs / 1000,
                "scope", "Only the Xray process started by this Android Traffic Lab profile",
                "otherApplicationsAffected", false,
                "expectedFailureWindow", JsonUtil.object("startedAt", windowStart, "endedAt", windowEnd, "reason", reason),
                "interpretation", interruptionMs > 0
                        ? "Traffic Lab stops only its isolated Xray process, waits for the requested interval, restarts it and verifies recovery. Android routes, radios and unrelated applications are unchanged."
                        : "Traffic Lab force-stops only its isolated Xray process, verifies failure on the old loopback proxy and starts a fresh process.");
        return before != null && before.optBoolean("success") && breakObserved && recovered
                ? JsonUtil.passed(stageName, ProbeSuite.elapsed(started), data)
                : JsonUtil.partial(stageName, ProbeSuite.elapsed(started), "The controlled break or recovery was not fully observed.", data);
    }

    private static JSONObject httpObservation(String target, Proxy proxy, boolean forceClose, int ordinal) {
        long started = System.nanoTime(); JSONObject value = new JSONObject();
        JsonUtil.put(value, "ordinal", ordinal); JsonUtil.put(value, "target", target);
        try {
            ProbeSuite.HttpResult response = ProbeSuite.http(target, proxy, "GET", null, 1024, 10_000, forceClose);
            boolean success = response.statusCode >= 200 && response.statusCode < 400;
            JsonUtil.put(value, "statusCode", response.statusCode); JsonUtil.put(value, "success", success);
        } catch (Exception error) {
            JsonUtil.put(value, "success", false); JsonUtil.put(value, "error", JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()));
        }
        JsonUtil.put(value, "elapsedMs", ProbeSuite.elapsed(started)); return value;
    }

    private static JSONObject failedObservation(int ordinal, Exception error) {
        return JsonUtil.object("ordinal", ordinal, "success", false, "elapsedMs", 0,
                "error", JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()));
    }

    static JSONObject summarize(JSONArray observations) {
        List<Long> times = successfulLatencies(observations);
        JSONObject data = JsonUtil.object("successes", times.size(), "failures", observations.length() - times.size());
        if (times.isEmpty()) return data;
        Collections.sort(times); double mean = 0; for (long value : times) mean += value; mean /= times.size();
        JsonUtil.put(data, "meanMs", Math.round(mean * 100.0) / 100.0); JsonUtil.put(data, "minMs", times.get(0));
        JsonUtil.put(data, "p50Ms", percentile(times, 0.50)); JsonUtil.put(data, "p95Ms", percentile(times, 0.95));
        JsonUtil.put(data, "p99Ms", percentile(times, 0.99)); JsonUtil.put(data, "maxMs", times.get(times.size() - 1)); return data;
    }

    static long percentile(List<Long> sortedValues, double percentile) {
        if (sortedValues == null || sortedValues.isEmpty()) return 0;
        int index = (int) Math.ceil(Math.max(0, Math.min(1, percentile)) * sortedValues.size()) - 1;
        return sortedValues.get(Math.max(0, Math.min(sortedValues.size() - 1, index)));
    }

    private static JSONObject jitter(JSONArray observations) {
        List<Long> values = successfulLatencies(observations); List<Long> differences = new ArrayList<>();
        for (int index = 1; index < values.size(); index++) differences.add(Math.abs(values.get(index) - values.get(index - 1)));
        Collections.sort(differences); double mean = 0; for (long value : differences) mean += value; if (!differences.isEmpty()) mean /= differences.size();
        return JsonUtil.object("definition", "absolute difference between consecutive successful application RTT samples",
                "samples", differences.size(), "meanMs", Math.round(mean * 100.0) / 100.0,
                "p50Ms", percentile(differences, 0.50), "p95Ms", percentile(differences, 0.95),
                "maxMs", differences.isEmpty() ? 0 : differences.get(differences.size() - 1));
    }

    private static List<Long> successfulLatencies(JSONArray observations) {
        List<Long> values = new ArrayList<>();
        for (int index = 0; index < observations.length(); index++) {
            JSONObject item = observations.optJSONObject(index);
            if (item != null && item.optBoolean("success")) values.add(item.optLong("elapsedMs"));
        }
        return values;
    }

    private static int successes(JSONArray observations) { return successfulLatencies(observations).size(); }

    private static int maximumConsecutiveLoss(JSONArray observations) {
        int maximum = 0, current = 0;
        for (int index = 0; index < observations.length(); index++) {
            JSONObject item = observations.optJSONObject(index);
            if (item != null && item.optBoolean("success")) current = 0; else maximum = Math.max(maximum, ++current);
        }
        return maximum;
    }

    private static boolean containsStage(JSONArray stages, String name) {
        for (int index = 0; index < stages.length(); index++) {
            JSONObject stage = stages.optJSONObject(index);
            if (stage != null && name.equals(stage.optString("stage"))) return true;
        }
        return false;
    }

    private static Proxy httpProxy(int port) { return new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", port)); }

    private static void sleepCancelable(long millis, CancelCheck cancel) throws InterruptedException {
        long deadline = System.currentTimeMillis() + Math.max(0, millis);
        while (System.currentTimeMillis() < deadline) {
            cancel.check(); Thread.sleep(Math.min(250, Math.max(1, deadline - System.currentTimeMillis())));
        }
    }
}
