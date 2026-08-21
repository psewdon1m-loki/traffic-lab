package com.loki.trafficlab;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;

final class JsonUtil {
    private JsonUtil() {}

    static void put(JSONObject object, String key, Object value) {
        if (value == null) return;
        try { object.put(key, value); } catch (JSONException ignored) {}
    }

    static JSONObject object(Object... keyValues) {
        JSONObject object = new JSONObject();
        if (keyValues == null) return object;
        for (int i = 0; i + 1 < keyValues.length; i += 2) put(object, String.valueOf(keyValues[i]), keyValues[i + 1]);
        return object;
    }

    static JSONArray array(Collection<?> values) {
        JSONArray array = new JSONArray();
        if (values != null) for (Object value : values) array.put(value);
        return array;
    }

    static JSONObject stage(String name, String status, long elapsedMs, Object data, String error) {
        JSONObject stage = new JSONObject();
        Instant completedAt = Instant.now();
        Instant startedAt = completedAt.minusMillis(Math.max(0, elapsedMs));
        put(stage, "stage", name);
        put(stage, "status", status);
        put(stage, "elapsedMs", elapsedMs);
        put(stage, "startedAt", startedAt.toString());
        put(stage, "completedAt", completedAt.toString());
        put(stage, "data", data);
        put(stage, "error", error);
        if ("passed".equals(status)) {
            put(stage, "outcome", "PASS");
            put(stage, "reasonCode", "CHECK_SUCCEEDED");
            put(stage, "reason", "The stage success criterion was directly observed.");
        } else if ("skipped".equals(status)) {
            put(stage, "outcome", "UNKNOWN");
            put(stage, "reasonCode", "NOT_REQUESTED_OR_NOT_APPLICABLE");
            put(stage, "reason", error == null ? "The stage was not executed." : error);
        } else {
            put(stage, "outcome", "UNKNOWN");
            put(stage, "reasonCode", "NOT_CLASSIFIED");
            put(stage, "reason", error == null ? "The stage did not provide a conclusive causal result." : error);
        }
        return stage;
    }

    static JSONObject passed(String name, long elapsedMs, Object data) { return stage(name, "passed", elapsedMs, data, null); }
    static JSONObject failed(String name, long elapsedMs, String error, Object data) { return stage(name, "failed", elapsedMs, data, error); }
    static JSONObject partial(String name, long elapsedMs, String error, Object data) { return stage(name, "partial", elapsedMs, data, error); }
    static JSONObject skipped(String name, String reason) { return stage(name, "skipped", 0, null, reason); }
    static JSONObject notApplicable(String name, String reason) {
        JSONObject value = stage(name, "skipped", 0, null, reason);
        put(value, "reasonCode", "NOT_APPLICABLE");
        return value;
    }
    static JSONObject controlNotApplicable(String name, String reason) {
        JSONObject value = stage(name, "skipped", 0, null, reason);
        put(value, "reasonCode", "CONTROL_NOT_APPLICABLE");
        return value;
    }
    static JSONObject dependentSkipped(String name, String reason, String dependsOn, String rootFailureCode) {
        JSONObject value = stage(name, "skipped", 0, null, reason);
        put(value, "reasonCode", "DEPENDENCY_NOT_MET");
        put(value, "dependsOn", dependsOn);
        put(value, "rootFailureCode", rootFailureCode);
        return value;
    }
    static JSONObject testFailure(String name, long elapsedMs, String reasonCode, String error, Object data) {
        JSONObject value = stage(name, "failed", elapsedMs, data, error);
        put(value, "outcome", "TEST_FAILURE");
        put(value, "reasonCode", reasonCode);
        put(value, "reason", error);
        return value;
    }
    static JSONObject unsupported(String name, String reason, Object data) {
        JSONObject value = stage(name, "skipped", 0, data, reason);
        put(value, "reasonCode", "UNSUPPORTED_ON_PLATFORM");
        return value;
    }

    static String readUtf8(InputStream input, int maxBytes) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer, 0, Math.min(buffer.length, maxBytes - total))) > 0) {
            output.write(buffer, 0, read);
            total += read;
            if (total >= maxBytes) break;
        }
        return output.toString(StandardCharsets.UTF_8.name());
    }

    static String now() { return Instant.now().toString(); }

    static String redact(String value) {
        if (value == null) return null;
        return value
                .replaceAll("(?i)vless://[^\\s]+", "vless://[redacted]")
                .replaceAll("(?i)(publicKey|shortId|id|password)[=:]\\s*[^,\\s}]+", "$1=[redacted]")
                .replaceAll("[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", "[uuid-redacted]");
    }
}
