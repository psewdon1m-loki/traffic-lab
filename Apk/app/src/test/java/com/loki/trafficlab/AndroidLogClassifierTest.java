package com.loki.trafficlab;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AndroidLogClassifierTest {
    @Test public void classifiesReadinessEofAsBenign() throws Exception {
        JSONObject stage = AndroidLogClassifier.stage(logs(
                "2026/08/17 13:53:43 [Info] app/proxyman/inbound: connection ends > proxy/http: failed to read http request > EOF"));
        assertEquals("passed", stage.getString("status"));
        JSONObject analysis = stage.getJSONObject("data").getJSONObject("logAnalysis");
        assertEquals(1, analysis.getInt("benignMarkerCount"));
        assertEquals(0, analysis.getInt("unexpectedMarkerCount"));
    }

    @Test public void classifiesLoopbackBrokenPipeAfterClientTimeoutAsBenign() throws Exception {
        JSONObject stage = AndroidLogClassifier.stage(logs(
                "2026/08/17 14:42:27 [Info] failed to transfer response payload > write tcp 127.0.0.1:42827->127.0.0.1:49834: write: broken pipe"));
        assertEquals("passed", stage.getString("status"));
        JSONObject marker = stage.getJSONObject("data").getJSONObject("logAnalysis")
                .getJSONArray("benignMarkers").getJSONObject(0);
        assertEquals("app_closed_loopback_request_after_completion_or_timeout", marker.getString("reason"));
    }

    @Test public void classifiesCompletedUdpAssociationTeardownAsBenign() throws Exception {
        JSONObject stage = AndroidLogClassifier.stage(logs(
                "2026/08/17 14:42:27 [Info] failed to handle UDP input > io: read/write on closed pipe"));
        assertEquals("passed", stage.getString("status"));
        assertTrue(stage.getJSONObject("data").getJSONObject("logAnalysis").getBoolean("allMarkersClassified"));
    }

    @Test public void preservesUnexpectedOutboundFailureAsPartial() throws Exception {
        JSONObject stage = AndroidLogClassifier.stage(logs(
                "2026/08/17 14:42:27 [Error] dial tcp 203.0.113.10:443: connect: connection refused"));
        assertEquals("partial", stage.getString("status"));
        JSONObject analysis = stage.getJSONObject("data").getJSONObject("logAnalysis");
        assertEquals(0, analysis.getInt("benignMarkerCount"));
        assertEquals(1, analysis.getInt("unexpectedMarkerCount"));
    }

    private static JSONObject logs(String errorTail) {
        return JsonUtil.object("accessTail", "", "errorTail", errorTail, "stdoutTail", "", "stderrTail", "", "credentialsRedacted", true);
    }
}
