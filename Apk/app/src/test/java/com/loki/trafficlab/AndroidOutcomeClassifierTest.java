package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AndroidOutcomeClassifierTest {
    @Test public void directFailureTakesPrecedence() {
        JSONArray stages = new JSONArray().put(JsonUtil.failed("endpoint.tcp", 10, "timeout", null));
        assertEquals("UNDERLAY_FAIL", AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), false).optString("outcome"));
    }

    @Test public void unreachableEndpointIsProxyPathFailure() {
        JSONArray stages = new JSONArray()
                .put(JsonUtil.passed("profile.parse", 0, null))
                .put(JsonUtil.passed("endpoint.dns", 1, null))
                .put(JsonUtil.failed("endpoint.tcp", 10, "timeout", null));
        JSONObject outcome = AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), true);
        assertEquals("PROXY_FAIL", outcome.optString("outcome"));
        assertEquals("ENDPOINT_TCP_UNREACHABLE", outcome.optString("reasonCode"));
    }

    @Test public void dependentStagesRemainSkippedWithoutBecomingFailures() {
        JSONObject dependent = JsonUtil.dependentSkipped("tunnel.udp", "TCP prerequisite failed.", "endpoint.tcp", "ENDPOINT_TCP_UNREACHABLE");
        JSONArray stages = new JSONArray().put(JsonUtil.failed("endpoint.tcp", 10, "timeout", null)).put(dependent);
        AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), true);
        assertEquals("skipped", dependent.optString("status"));
        assertEquals("DEPENDENCY_NOT_MET", dependent.optString("reasonCode"));
        assertEquals("endpoint.tcp", dependent.optString("dependsOn"));
    }

    @Test public void reachableEndpointWithoutAuthIsProtocolFailure() {
        JSONArray stages = new JSONArray()
                .put(JsonUtil.passed("profile.parse", 0, null))
                .put(JsonUtil.passed("endpoint.dns", 1, null))
                .put(JsonUtil.passed("endpoint.tcp", 10, null))
                .put(JsonUtil.failed("tunnel.authenticatedEndToEnd", 20, "auth failed", null));
        assertEquals("PROTOCOL_AUTH_FAIL", AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), true).optString("reasonCode"));
    }
}
