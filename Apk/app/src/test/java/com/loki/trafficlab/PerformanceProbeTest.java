package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class PerformanceProbeTest {
    @Test public void adaptiveSizeTargetsTwoSecondsWithinBounds() {
        assertEquals(250_000, ProbeSuite.adaptiveBytes(1.0, 2_000, 64 * 1024, 2 * 1024 * 1024));
        assertEquals(64 * 1024, ProbeSuite.adaptiveBytes(0.01, 2_000, 64 * 1024, 2 * 1024 * 1024));
        assertEquals(2 * 1024 * 1024, ProbeSuite.adaptiveBytes(100.0, 2_000, 64 * 1024, 2 * 1024 * 1024));
    }

    @Test public void summaryUsesMedianAndReportsVariability() throws Exception {
        JSONArray samples = new JSONArray()
                .put(sample(1, 2, 1, 500, 1000))
                .put(sample(2, 10, 8, 100, 1000))
                .put(sample(3, 20, 16, 80, 1000))
                .put(sample(4, 30, 24, 90, 1000));
        JSONObject summary = ProbeSuite.summarizePerformance("download", samples, 3000);
        assertEquals("passed", summary.getString("status"));
        assertEquals(20.0, summary.getDouble("recommendedMbps"), 0.001);
        assertEquals(16.0, summary.getDouble("medianEffectiveMbps"), 0.001);
        assertEquals(90, summary.getLong("medianTtfbMs"));
        assertEquals(4000, summary.getLong("successfulBytes"));
        assertEquals(3, summary.getInt("measurementSuccessfulAttempts"));
        assertFalse(summary.getBoolean("calibrationIncludedInRecommended"));
    }

    @Test public void failedAttemptMakesMeasurementPartialInsteadOfSilentlyPassing() throws Exception {
        JSONArray samples = new JSONArray()
                .put(sample(1, 10, 8, 100, 1000))
                .put(sample(2, 11, 9, 90, 1000))
                .put(sample(3, 12, 10, 95, 1000))
                .put(JsonUtil.object("attempt", 4, "sampleRole", "measurement", "success", false, "error", "SocketTimeoutException"));
        JSONObject summary = ProbeSuite.summarizePerformance("download", samples, 3000);
        assertEquals("partial", summary.getString("status"));
        assertEquals(3, summary.getInt("successfulAttempts"));
        assertEquals("SocketTimeoutException", summary.getString("summaryError"));
    }

    private static JSONObject sample(int attempt, double payloadMbps, double effectiveMbps, long ttfb, long bytes) {
        return JsonUtil.object("attempt", attempt, "success", true, "payloadMbps", payloadMbps,
                "effectiveMbps", effectiveMbps, "ttfbMs", ttfb, "totalMs", 200, "bytes", bytes);
    }
}
