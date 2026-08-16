package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

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
                new JSONArray(), new JSONArray(), new JSONArray(), standard, extended, new JSONArray(), true);
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
        assertEquals(TrafficLabRunner.TestType.NORMAL, TrafficLabRunner.TestType.from("unexpected"));
    }

    @Test public void latencyPercentilesUseNearestRank() {
        ArrayList<Long> values = new ArrayList<>(Arrays.asList(10L, 20L, 30L, 40L, 50L));
        assertEquals(30L, AndroidExtendedTestSuite.percentile(values, 0.50));
        assertEquals(50L, AndroidExtendedTestSuite.percentile(values, 0.95));
    }

    @Test public void extendedEtaAccountsForTheFixedFiveMinuteSoak() {
        assertEquals(330_000L, ProgressEstimate.remaining(90_000L, 75, 1, true, TrafficLabRunner.TestType.EXTENDED));
        assertEquals(30_000L, ProgressEstimate.remaining(90_000L, 75, 1, true, TrafficLabRunner.TestType.NORMAL));
        assertEquals(-1L, ProgressEstimate.remaining(90_000L, 100, 1, false, TrafficLabRunner.TestType.EXTENDED));
    }

    private static ResultPackager.PackageInput input(TrafficLabRunner.TestType type, java.util.List<TrafficLabRunner.ProfileResult> profiles) {
        return new ResultPackager.PackageInput("run-12345678", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60_000,
                "Xray test", new JSONObject(), new JSONArray(), new JSONArray(), profiles, type);
    }
}
