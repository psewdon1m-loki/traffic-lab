package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.io.File;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipFile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ResultContractTest {
    @Test public void extendedRunMetadataNamesAndroidPlatformOsAndMode() throws Exception {
        ResultPackager.PackageInput input = input(TrafficLabRunner.TestType.EXTENDED, Collections.emptyList());
        JSONObject root = ResultPackager.base(input, "test-output");
        JSONObject run = root.getJSONObject("run");
        assertEquals("android", run.getString("platform"));
        assertEquals("extended", run.getString("testType"));
        assertTrue(run.has("operatingSystem"));
        assertTrue(run.has("operatingSystemVersion"));
        assertTrue(run.has("androidApiLevel"));
        assertTrue(run.getJSONObject("extendedTest").getBoolean("enabled"));
        assertEquals(AndroidExtendedTestSuite.SOAK_SECONDS, run.getJSONObject("extendedTest").getInt("soakDurationSeconds"));
        assertFalse("1.0.0".equals(root.getJSONObject("tool").getString("version")));
    }

    @Test public void extendedResultsAreSeparatedFromStandardStages() throws Exception {
        JSONArray standard = new JSONArray().put(JsonUtil.passed("profile.parse", 0, null));
        JSONArray extended = new JSONArray().put(JsonUtil.passed("tunnel.extended.soak", 300_000, JsonUtil.object("attempts", 250)));
        TrafficLabRunner.ProfileResult profile = new TrafficLabRunner.ProfileResult(
                "profile-01", 1, "sample", "fingerprint", new JSONObject(), Collections.emptyList(), Collections.emptyList(),
                new JSONArray(), new JSONArray(), new JSONArray(), standard, extended, new JSONArray(), true,
                JsonUtil.object("outcome", "PASS", "reasonCode", "AUTHENTICATED_E2E_SUCCEEDED", "reason", "test"));
        ResultPackager.PackageInput input = input(TrafficLabRunner.TestType.EXTENDED, Collections.singletonList(profile));
        JSONObject result = ResultPackager.extendedJson(input, profile);
        assertEquals("extended-test-results", result.getString("outputType"));
        assertEquals(1, result.getJSONArray("stages").length());
        assertEquals("tunnel.extended.soak", result.getJSONArray("stages").getJSONObject(0).getString("stage"));
        assertEquals(1, result.getJSONObject("statusCounts").getInt("passed"));
        assertEquals(1, standard.length());
    }

    @Test public void testTypeParsingIsExplicitAndSafe() {
        assertEquals(TrafficLabRunner.TestType.EXTENDED, TrafficLabRunner.TestType.from("extended"));
        assertEquals(TrafficLabRunner.TestType.SPEED, TrafficLabRunner.TestType.from("speed"));
        assertEquals(TrafficLabRunner.TestType.NORMAL, TrafficLabRunner.TestType.from("unexpected"));
    }

    @Test public void speedDocumentUsesDedicatedTwoFileContract() throws Exception {
        JSONArray stages = new JSONArray().put(JsonUtil.passed("speed.directBefore", 1,
                JsonUtil.object("status", "passed", "series", new JSONArray())));
        TrafficLabRunner.ProfileResult profile = new TrafficLabRunner.ProfileResult(
                "profile-01", 1, "sample", "fingerprint", new JSONObject(), Collections.emptyList(), Collections.emptyList(),
                new JSONArray(), new JSONArray(), new JSONArray(), stages, new JSONArray(), new JSONArray(), true,
                JsonUtil.object("outcome", "PASS", "reasonCode", "SPEED_MEASUREMENT_SUCCEEDED", "reason", "test"));
        ResultPackager.PackageInput input = input(TrafficLabRunner.TestType.SPEED, Collections.singletonList(profile));
        JSONObject result = ResultPackager.speedJson(input);
        assertEquals("speed-test-results", result.getString("outputType"));
        assertEquals("speed", result.getJSONObject("run").getString("testType"));
        assertEquals(1, result.getJSONArray("profiles").length());
        assertEquals(4_000, result.getJSONObject("measurementProtocol").getInt("measurementWindowTargetMs"));
        assertEquals("ABBA Direct-Tunnel-Tunnel-Direct with the same 1/4/16-flow workload plan",
                result.getJSONObject("measurementProtocol").getString("directControls"));
        File root = Files.createTempDirectory("tlab-android-speed-package-").toFile();
        try {
            File zip = ResultPackager.create(root, input);
            try (ZipFile archive = new ZipFile(zip)) {
                Set<String> names = new HashSet<>();
                archive.stream().forEach(entry -> names.add(entry.getName()));
                assertEquals(new HashSet<>(Arrays.asList("speed.json", "readme.txt")), names);
            }
        } finally { deleteTree(root); }
    }

    @Test public void latencyPercentilesUseNearestRank() {
        ArrayList<Long> values = new ArrayList<>(Arrays.asList(10L, 20L, 30L, 40L, 50L));
        assertEquals(30L, AndroidExtendedTestSuite.percentile(values, 0.50));
        assertEquals(50L, AndroidExtendedTestSuite.percentile(values, 0.95));
    }

    @Test public void speedPlanSummaryAndDriftUseMatchedFlowContract() throws Exception {
        JSONArray series = new JSONArray()
                .put(JsonUtil.object("direction", "download", "flows", 1, "measurementBytesPerFlow", 1000,
                        "medianAggregateMbps", 40.0, "confidence", "high", "classifications", new JSONArray().put("VALID")))
                .put(JsonUtil.object("direction", "download", "flows", 4, "measurementBytesPerFlow", 2000,
                        "medianAggregateMbps", 80.0, "confidence", "medium", "classifications", new JSONArray().put("VALID")))
                .put(JsonUtil.object("direction", "upload", "flows", 4, "measurementBytesPerFlow", 1500,
                        "medianAggregateMbps", 60.0, "confidence", "medium", "classifications", new JSONArray().put("VALID")));
        JSONObject report = JsonUtil.object("series", series);
        assertEquals(2000, AndroidSpeedTestEngine.createPlan(report).getInt("download:4"));
        JSONObject summary = AndroidSpeedTestEngine.summary(report);
        assertEquals(80.0, summary.getDouble("downloadMbps"), 0.01);
        assertEquals(60.0, summary.getDouble("uploadMbps"), 0.01);

        JSONObject before = JsonUtil.object("series", new JSONArray().put(JsonUtil.object("direction", "download", "flows", 1, "medianAggregateMbps", 100.0)));
        JSONObject tunnel = JsonUtil.object("series", new JSONArray().put(JsonUtil.object("direction", "download", "flows", 1, "medianAggregateMbps", 80.0)));
        JSONObject stableAfter = JsonUtil.object("series", new JSONArray().put(JsonUtil.object("direction", "download", "flows", 1, "medianAggregateMbps", 110.0)));
        JSONObject driftingAfter = JsonUtil.object("series", new JSONArray().put(JsonUtil.object("direction", "download", "flows", 1, "medianAggregateMbps", 125.0)));
        assertTrue(AndroidSpeedTestEngine.compare(before, tunnel, stableAfter).getBoolean("directControlStable"));
        assertFalse(AndroidSpeedTestEngine.compare(before, tunnel, driftingAfter).getBoolean("directControlStable"));
    }

    @Test public void speedEndpointSizesAvoidRejectedPublicEdgeRange() {
        assertEquals(25_000_000, AndroidSpeedTestEngine.normalizeCloudflareMeasurementSize(16 * 1024 * 1024));
        assertEquals(64 * 1024 * 1024, AndroidSpeedTestEngine.normalizeCloudflareMeasurementSize(64 * 1024 * 1024));
    }

    @Test public void extendedEtaAccountsForTheFixedFiveMinuteSoak() {
        assertEquals(570_000L, ProgressEstimate.remaining(90_000L, 75, 1, true, TrafficLabRunner.TestType.EXTENDED));
        assertEquals(30_000L, ProgressEstimate.remaining(90_000L, 75, 1, true, TrafficLabRunner.TestType.NORMAL));
        assertEquals(-1L, ProgressEstimate.remaining(90_000L, 100, 1, false, TrafficLabRunner.TestType.EXTENDED));
    }

    private static ResultPackager.PackageInput input(TrafficLabRunner.TestType type, java.util.List<TrafficLabRunner.ProfileResult> profiles) {
        return new ResultPackager.PackageInput("run-12345678", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60_000,
                "Xray test", new JSONObject(), new JSONArray(), new JSONArray(), profiles, type,
                JsonUtil.object("outcome", "PASS", "reasonCode", "RUN_COMPLETED_WITH_USABLE_PROFILE", "reason", "test"));
    }

    private static void deleteTree(File file) {
        if (file == null || !file.exists()) return;
        File[] children = file.listFiles(); if (children != null) for (File child : children) deleteTree(child);
        //noinspection ResultOfMethodCallIgnored
        file.delete();
    }
}
