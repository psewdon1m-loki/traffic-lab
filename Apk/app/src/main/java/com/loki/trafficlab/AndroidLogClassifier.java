package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;

final class AndroidLogClassifier {
    private AndroidLogClassifier() {}

    static JSONObject stage(JSONObject logs) {
        if (logs == null) return JsonUtil.skipped("tunnel.logs", "No running core logs were available.");
        JSONObject analysis = analyze(logs);
        JsonUtil.put(logs, "logAnalysis", analysis);
        int unexpected = analysis.optInt("unexpectedMarkerCount");
        return unexpected == 0
                ? JsonUtil.passed("tunnel.logs", 0, logs)
                : JsonUtil.partial("tunnel.logs", 0,
                "Core logs contain " + unexpected + " unexpected failure marker(s); inspect data.logAnalysis.unexpectedMarkers.", logs);
    }

    static JSONObject analyze(JSONObject logs) {
        JSONArray benign = new JSONArray();
        JSONArray unexpected = new JSONArray();
        int markerCount = 0;
        for (String source : new String[]{"errorTail", "stderrTail", "stdoutTail"}) {
            String value = logs.optString(source, "");
            if (value.isEmpty()) continue;
            for (String rawLine : value.split("\\R")) {
                String line = rawLine == null ? "" : rawLine.trim();
                if (line.isEmpty() || !isMarker(line)) continue;
                markerCount++;
                String reason = benignReason(line);
                JSONObject item = JsonUtil.object("source", source, "line", JsonUtil.redact(line));
                if (reason == null) {
                    JsonUtil.put(item, "classification", "unexpected");
                    unexpected.put(item);
                } else {
                    JsonUtil.put(item, "classification", "expected/benign");
                    JsonUtil.put(item, "reason", reason);
                    benign.put(item);
                }
            }
        }
        String classification = unexpected.length() > 0 ? "unexpected_markers"
                : benign.length() > 0 ? "expected_or_benign_markers_only" : "clean";
        return JsonUtil.object(
                "classification", classification,
                "markerCount", markerCount,
                "benignMarkerCount", benign.length(),
                "unexpectedMarkerCount", unexpected.length(),
                "allMarkersClassified", unexpected.length() == 0,
                "benignMarkers", benign,
                "unexpectedMarkers", unexpected,
                "policy", "Loopback client teardown after a completed/timed-out app probe, readiness-probe EOF and completed UDP-association teardown are expected; other failure markers remain unexpected.");
    }

    private static boolean isMarker(String line) {
        String value = line.toLowerCase(Locale.ROOT);
        return value.contains("[error]") || value.contains("[warning]") || value.contains("failed")
                || value.contains("forbidden") || value.contains("broken pipe") || value.contains("closed pipe")
                || value.contains("connection refused") || value.contains("timed out") || value.contains("timeout")
                || value.contains("panic") || value.contains("fatal");
    }

    private static String benignReason(String line) {
        String value = line.toLowerCase(Locale.ROOT);
        if (value.contains("proxy/http: failed to read http request > eof")) {
            return "local_inbound_readiness_probe_eof";
        }
        boolean loopbackFlow = value.matches(".*(?:write|read) tcp 127\\.0\\.0\\.1:[0-9]+->127\\.0\\.0\\.1:[0-9]+:.*");
        if (loopbackFlow && (value.contains("broken pipe") || value.contains("closed pipe")
                || value.contains("connection reset by peer"))) {
            return "app_closed_loopback_request_after_completion_or_timeout";
        }
        if (value.contains("failed to handle udp input")
                && (value.contains("closed pipe") || value.contains(" > eof") || value.endsWith("eof"))) {
            return "completed_udp_association_teardown";
        }
        if (value.contains("websocket: close 1000")) {
            return "normal_websocket_close";
        }
        if ((value.contains("websocket") || value.contains("grpc"))
                && (value.contains("deprecated") || value.contains("legacy transport"))) {
            return "transport_deprecation_notice";
        }
        if (value.contains("xtls") && value.contains("rejected udp/443 traffic")) {
            return "udp_quic_probe_policy_notice";
        }
        return null;
    }
}
