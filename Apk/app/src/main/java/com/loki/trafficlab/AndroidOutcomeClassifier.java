package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Locale;

final class AndroidOutcomeClassifier {
    static final String PASS = "PASS";
    static final String PROXY_FAIL = "PROXY_FAIL";
    static final String UNDERLAY_FAIL = "UNDERLAY_FAIL";
    static final String TEST_FAILURE = "TEST_FAILURE";
    static final String UNKNOWN = "UNKNOWN";

    private AndroidOutcomeClassifier() {}

    static JSONObject applyProfile(JSONArray stages, JSONArray extendedStages, boolean directControlAvailable) {
        classifyStages(stages, directControlAvailable);
        classifyStages(extendedStages, directControlAvailable);
        if (!directControlAvailable) return decision(UNDERLAY_FAIL, "DIRECT_CONTROL_UNAVAILABLE",
                "The direct no-proxy control produced no usable HTTPS/IP/STUN evidence, so proxy-specific conclusions are unsafe.", "direct baseline unavailable");
        if (failed(stages, "profile.parse") || failed(stages, "profile.policy") || failed(stages, "tunnel.coreValidation")
                || failed(stages, "tunnel.coreStart") || failed(stages, "tunnel.unhandled")) {
            return decision(TEST_FAILURE, "TESTER_OR_CONFIGURATION_FAILURE",
                    "The tester could not parse, validate, or start the isolated client core; the proxy path was not fairly evaluated.", firstFailure(stages));
        }
        if (failed(stages, "endpoint.dns")) return decision(PROXY_FAIL, "ENDPOINT_DNS_UNRESOLVED",
                "The direct control worked, but the profile endpoint did not resolve on this underlay.", "endpoint.dns");
        if (failed(stages, "endpoint.tcp")) return decision(PROXY_FAIL, "ENDPOINT_TCP_UNREACHABLE",
                "The direct control worked, but no TCP connection to the profile endpoint succeeded.", "endpoint.tcp");
        if (passed(stages, "tunnel.authenticatedEndToEnd")) return decision(PASS, "AUTHENTICATED_E2E_SUCCEEDED",
                "At least one authenticated destination request completed through the tested profile.", "tunnel.authenticatedEndToEnd");
        if (passed(stages, "endpoint.tcp")) return decision(PROXY_FAIL, "PROTOCOL_AUTH_FAIL",
                "Endpoint TCP was reachable, but an authenticated end-to-end VLESS request was not completed.", "endpoint.tcp passed; tunnel.authenticatedEndToEnd did not pass");
        return decision(UNKNOWN, "INSUFFICIENT_EVIDENCE",
                "The available stages do not distinguish an underlay, proxy-path, authentication, or tester failure.", firstFailure(stages));
    }

    static JSONObject run(JSONArray profileOutcomes, boolean directControlAvailable) {
        if (!directControlAvailable) return decision(UNDERLAY_FAIL, "DIRECT_CONTROL_UNAVAILABLE",
                "The run has no usable direct-network control; proxy-specific conclusions are unsafe.", "direct baseline unavailable");
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (int i = 0; i < profileOutcomes.length(); i++) {
            JSONObject value = profileOutcomes.optJSONObject(i);
            String outcome = value == null ? UNKNOWN : value.optString("outcome", UNKNOWN);
            counts.put(outcome, counts.containsKey(outcome) ? counts.get(outcome) + 1 : 1);
        }
        String evidence = counts.toString();
        if (counts.containsKey(PASS)) return decision(PASS, "RUN_COMPLETED_WITH_USABLE_PROFILE",
                "The test run completed and at least one profile passed authenticated end-to-end traffic.", evidence);
        if (!counts.isEmpty() && counts.size() == 1 && counts.containsKey(TEST_FAILURE)) return decision(TEST_FAILURE, "ALL_PROFILES_TEST_FAILURE",
                "Every scheduled profile was blocked by a tester, parse, or local-core failure.", evidence);
        if (counts.containsKey(PROXY_FAIL)) return decision(PROXY_FAIL, "NO_USABLE_PROFILE",
                "The direct control worked, but no profile completed authenticated end-to-end traffic.", evidence);
        return decision(UNKNOWN, "RUN_INCONCLUSIVE", "The run completed without enough evidence for a causal result.", evidence);
    }

    private static void classifyStages(JSONArray stages, boolean directControlAvailable) {
        if (stages == null) return;
        for (int i = 0; i < stages.length(); i++) {
            JSONObject stage = stages.optJSONObject(i);
            if (stage == null) continue;
            String name = stage.optString("stage", "unknown");
            String status = stage.optString("status", "unknown");
            String error = stage.optString("error", "");
            if ("passed".equals(status)) { set(stage, PASS, "CHECK_SUCCEEDED", "The stage success criterion was directly observed."); continue; }
            if ("skipped".equals(status)) {
                String normalizedError = error.toLowerCase(Locale.ROOT);
                String declaredCode = stage.optString("reasonCode");
                String code = "UNSUPPORTED_ON_PLATFORM".equals(declaredCode) || "DEPENDENCY_NOT_MET".equals(declaredCode) || "NOT_APPLICABLE".equals(declaredCode) || "CONTROL_NOT_APPLICABLE".equals(declaredCode) ? declaredCode
                        : normalizedError.contains("did not") || normalizedError.contains("unavailable") ? "DEPENDENCY_NOT_MET" : "NOT_REQUESTED_OR_NOT_APPLICABLE";
                set(stage, UNKNOWN, code, error.isEmpty() ? "The stage was not executed." : error); continue;
            }
            if ("INVALID_TRACEROUTE_OUTPUT".equals(stage.optString("reasonCode"))) {
                set(stage, TEST_FAILURE, "INVALID_TRACEROUTE_OUTPUT", error); continue;
            }
            if (!directControlAvailable && remote(name)) { set(stage, UNDERLAY_FAIL, "DIRECT_CONTROL_UNAVAILABLE", "The no-proxy control was unavailable, so this remote result cannot be attributed to the profile."); continue; }
            if (name.equals("profile.parse") || name.equals("profile.policy") || name.equals("tunnel.coreValidation") || name.equals("tunnel.coreStart") || name.equals("tunnel.unhandled")) {
                set(stage, TEST_FAILURE, "TESTER_OR_CONFIGURATION_FAILURE", error); continue;
            }
            if (name.equals("endpoint.tcp")) { set(stage, PROXY_FAIL, "ENDPOINT_TCP_UNREACHABLE", error); continue; }
            if (name.equals("endpoint.dns")) { set(stage, PROXY_FAIL, "ENDPOINT_DNS_UNRESOLVED", error); continue; }
            if (name.equals("tunnel.authenticatedEndToEnd")) { set(stage, PROXY_FAIL, "PROTOCOL_AUTH_FAIL", error); continue; }
            if (remote(name)) { set(stage, "partial".equals(status) ? UNKNOWN : PROXY_FAIL,
                    "partial".equals(status) ? "INCONCLUSIVE_REMOTE_CHECK" : "PROXY_SUBCHECK_FAIL", error); continue; }
            set(stage, UNKNOWN, "partial".equals(status) ? "INCONCLUSIVE_CHECK" : "UNCLASSIFIED_CHECK_FAILURE", error);
        }
    }

    private static void set(JSONObject stage, String outcome, String code, String reason) {
        JsonUtil.put(stage, "outcome", outcome); JsonUtil.put(stage, "reasonCode", code);
        JsonUtil.put(stage, "reason", reason == null || reason.trim().isEmpty() ? "No additional stage reason was recorded." : reason);
    }
    private static boolean remote(String name) { return name.startsWith("endpoint.") || name.startsWith("camouflage.") || name.startsWith("network.") || name.startsWith("tunnel."); }
    private static boolean passed(JSONArray stages, String name) { return status(stages, name, "passed"); }
    private static boolean failed(JSONArray stages, String name) { return status(stages, name, "failed"); }
    private static boolean status(JSONArray stages, String name, String status) {
        for (int i = 0; i < stages.length(); i++) { JSONObject stage = stages.optJSONObject(i); if (stage != null && name.equals(stage.optString("stage")) && status.equals(stage.optString("status"))) return true; }
        return false;
    }
    private static String firstFailure(JSONArray stages) {
        for (int i = 0; i < stages.length(); i++) { JSONObject stage = stages.optJSONObject(i); if (stage != null && ("failed".equals(stage.optString("status")) || "partial".equals(stage.optString("status")))) return stage.optString("stage", "unknown"); }
        return "no failed stage recorded";
    }
    private static JSONObject decision(String outcome, String code, String reason, String evidence) {
        return JsonUtil.object("outcome", outcome, "reasonCode", code, "reason", reason, "evidence", new JSONArray().put(evidence));
    }
}
