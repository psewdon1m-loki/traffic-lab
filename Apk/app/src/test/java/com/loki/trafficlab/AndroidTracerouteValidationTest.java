package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class AndroidTracerouteValidationTest {
    @Test public void parserIgnoresDestinationInPingHeaderForExpiredTtl() {
        String output = "PING 199.68.196.107 (199.68.196.107) 56(84) bytes of data.\n"
                + "From 10.0.0.1 icmp_seq=1 Time to live exceeded\n";
        JSONObject hop = ProbeSuite.parseAndroidPingHop(output, 1, 1);
        assertEquals("10.0.0.1", hop.optString("address"));
        assertEquals("ttl-expired", hop.optString("outcome"));
    }

    @Test public void destinationCannotBeTtlExpiredIntermediateHop() {
        JSONArray hops = new JSONArray().put(JsonUtil.object("ttl", 1, "address", "199.68.196.107", "outcome", "ttl-expired"));
        assertNotNull(ProbeSuite.validateAndroidTraceroute(hops, "199.68.196.107"));
    }

    @Test public void repeatedExpiredResponderIsRejected() {
        JSONArray hops = new JSONArray();
        for (int ttl = 1; ttl <= 3; ttl++) hops.put(JsonUtil.object("ttl", ttl, "address", "10.0.0.1", "outcome", "ttl-expired"));
        assertNotNull(ProbeSuite.validateAndroidTraceroute(hops, "199.68.196.107"));
    }

    @Test public void OrdinaryRouteWithDistinctRespondersIsAccepted() {
        JSONArray hops = new JSONArray()
                .put(JsonUtil.object("ttl", 1, "address", "10.0.0.1", "outcome", "ttl-expired"))
                .put(JsonUtil.object("ttl", 2, "address", "100.64.0.1", "outcome", "ttl-expired"))
                .put(JsonUtil.object("ttl", 3, "address", "199.68.196.107", "outcome", "destination-reply"));
        assertNull(ProbeSuite.validateAndroidTraceroute(hops, "199.68.196.107"));
    }

    @Test public void invalidTracerouteIsTesterFailureNotPathEvidence() {
        JSONObject stage = JsonUtil.testFailure("endpoint.traceroute", 10, "INVALID_TRACEROUTE_OUTPUT", "invalid", new JSONObject());
        JSONArray stages = new JSONArray().put(stage);
        AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), true);
        assertEquals("failed", stage.optString("status"));
        assertEquals("TEST_FAILURE", stage.optString("outcome"));
        assertEquals("INVALID_TRACEROUTE_OUTPUT", stage.optString("reasonCode"));
    }
}
