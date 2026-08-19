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
        assertEquals("PROXY_PATH_FAIL", outcome.optString("reasonCode"));
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
