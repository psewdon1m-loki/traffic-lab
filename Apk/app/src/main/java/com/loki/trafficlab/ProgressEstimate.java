package com.loki.trafficlab;

final class ProgressEstimate {
    private ProgressEstimate() {}

    static long remaining(long elapsedMs, int percent, int profileCount, boolean running, TrafficLabRunner.TestType testType) {
        if (!running) return -1;
        long estimate = percent > 2 ? elapsedMs * (100L - percent) / percent : -1;
        if (testType != null && testType.extended() && profileCount > 0) {
            long planned = profileCount * (AndroidExtendedTestSuite.SOAK_SECONDS + 120L) * 1000L;
            estimate = Math.max(estimate, planned - elapsedMs);
        }
        return Math.max(-1, estimate);
    }
}
