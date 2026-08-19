package com.loki.trafficlab;

import android.content.Context;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class ResultPackager {
    private ResultPackager() {}

    static File create(Context context, PackageInput input) throws Exception {
        return create(context.getCacheDir(), input);
    }

    static File create(File cacheDirectory, PackageInput input) throws Exception {
        File directory = new File(cacheDirectory, "results");
        deleteTree(directory);
        if (!directory.mkdirs() && !directory.isDirectory()) throw new IllegalStateException("Could not create result cache");
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(new Date());
        File zip = new File(directory, "traffic-lab-android-" + input.testType.value + "-results-" + stamp + "-" + input.runId.substring(input.runId.length() - 8) + ".zip");
        Map<String, List<String>> shared = sharedBackends(input.profiles);
        Set<String> folders = new HashSet<>();
        try (ZipOutputStream output = new ZipOutputStream(new FileOutputStream(zip), StandardCharsets.UTF_8)) {
            output.setLevel(9);
            if (input.testType.speed()) {
                write(output, "speed.json", speedJson(input).toString(2));
                write(output, "readme.txt", speedReadme(input));
                return zip;
            }
            for (TrafficLabRunner.ProfileResult profile : input.profiles) {
                String prefix = input.profiles.size() == 1 ? "" : uniqueFolder(profile, folders) + "/";
                write(output, prefix + "connection.json", connectionJson(input, profile, shared).toString(2));
                write(output, prefix + "local-machine.json", localJson(input, profile).toString(2));
                write(output, prefix + "osi-map.md", osiMap(input, profile));
                write(output, prefix + "README.txt", readme(input, profile));
                if (input.testType.extended()) write(output, prefix + "extended-test.json", extendedJson(input, profile).toString(2));
            }
        }
        return zip;
    }

    static JSONObject speedJson(PackageInput input) {
        JSONObject root = base(input, "speed-test-results");
        JsonUtil.put(root, "measurementProtocol", JsonUtil.object(
                "calibrationExcluded", true, "measurementWindowTargetMs", 3000,
                "parallelFlowCounts", new JSONArray().put(1).put(4).put(16),
                "directControls", "full 1/4/16 matrix before tunnel plus bounded 1-flow control after tunnel",
                "statistics", new JSONArray().put("median").put("p10").put("p90").put("coefficientOfVariation"),
                "latency", "idle and concurrent loaded HTTPS latency",
                "uploadPayload", "incompressible generated stream with a 64 KiB buffer per flow"));
        JSONObject network = input.node.optJSONObject("connectivity");
        JSONObject testNode = JsonUtil.object("platform", "android", "operatingSystem", "Android " + androidRelease(),
                "device", Build.MANUFACTURER + " " + Build.MODEL,
                "accessType", network == null ? "unknown" : network.optString("detectedAccessType", "unknown"),
                "connectivity", input.node.opt("connectivity"), "wifi", input.node.opt("wifi"),
                "cellular", input.node.opt("cellular"), "powerAndPolicy", input.node.opt("powerAndPolicy"),
                "deviceLocation", input.node.opt("deviceLocation"));
        JsonUtil.put(root, "testNode", testNode);
        JSONArray profiles = new JSONArray();
        for (TrafficLabRunner.ProfileResult profile : input.profiles) {
            profiles.put(JsonUtil.object("profileId", profile.profileId, "sourceOrdinal", profile.ordinal,
                    "name", profile.name, "profileFingerprint", profile.fingerprint, "declared", profile.declared,
                    "endpointIps", JsonUtil.array(profile.endpointIps), "outcome", profile.outcome,
                    "speedStages", profile.stages));
        }
        JsonUtil.put(root, "profiles", profiles);
        JsonUtil.put(root, "runOutcome", input.runOutcome);
        JsonUtil.put(root, "limitations", new JSONArray()
                .put("The public Cloudflare measurement endpoint, Android radio state, thermal/power policy and byte caps can limit the result below access-line capacity.")
                .put("A direct-control drift above 25% makes proxy attribution low-confidence.")
                .put("The direct-after control intentionally uses one flow to limit mobile-data use; 4/16-flow ratios use direct-before and inherit the 1-flow drift confidence.")
                .put("The test is application-layer HTTPS capacity, not a modem PHY-rate measurement."));
        return root;
    }

    private static String speedReadme(PackageInput input) {
        return "LOKI TRAFFIC LAB - ANDROID SPEED TEST\n"
                + "=======================================\n\n"
                + "Run ID: " + input.runId + "\n"
                + "Test started (UTC): " + input.startedAt + "\n"
                + "Test completed (UTC): " + input.completedAt + "\n"
                + "Duration: " + formatDuration(input.durationMs) + "\n"
                + "Test type: SPEED (speed-only suite)\n"
                + "Platform: android\n"
                + "Operating system: Android " + androidRelease() + " (API " + Build.VERSION.SDK_INT + ")\n"
                + "Device: " + Build.MANUFACTURER + " " + Build.MODEL + "\n"
                + "Tool: Loki Traffic Lab Android " + BuildConfig.VERSION_NAME + "\n"
                + "Connections tested: " + input.profiles.size() + "\n"
                + "Run outcome: " + input.runOutcome.optString("outcome", "UNKNOWN") + " (" + input.runOutcome.optString("reasonCode", "RUN_INCONCLUSIVE") + ")\n\n"
                + "FILES\n-----\n"
                + "speed.json  Direct-before, tunnel and direct-after 1/4/16-flow measurements, raw attempts, latency-under-load, statistics and causal outcomes.\n"
                + "readme.txt  This run metadata and method guide.\n\n"
                + "METHOD\n------\n"
                + "Each speed series uses a small calibration transfer followed by three adaptive measurement windows. Calibration is excluded from the reported median. Download data is discarded while reading; upload data is generated through bounded 64 KiB buffers. Reports retain median, p10, p90, coefficient of variation, cap flags, idle latency, loaded latency and direct-network drift.\n\n"
                + "DATA BUDGET\n-----------\nThe Android worst-case transfer budget is approximately 500 MiB per profile. Actual use is usually lower because adaptive payloads stop below the cap on slower paths.\n\n"
                + "PRIVACY AND LIMITS\n------------------\n"
                + "Raw VLESS credentials are never stored. Public/local IP metadata and optional Android device location can be sensitive. Speed tests can consume substantial mobile data. The result is application-layer HTTPS capacity to the selected public endpoint, not a guaranteed ISP or modem line rate.\n";
    }

    private static JSONObject connectionJson(PackageInput input, TrafficLabRunner.ProfileResult profile, Map<String, List<String>> shared) {
        JSONObject root = base(input, "connection-characteristics");
        JSONObject connection = new JSONObject();
        JsonUtil.put(connection, "profileId", profile.profileId); JsonUtil.put(connection, "sourceOrdinal", profile.ordinal);
        JsonUtil.put(connection, "name", profile.name); JsonUtil.put(connection, "profileFingerprint", profile.fingerprint);
        JsonUtil.put(connection, "profileFingerprintAlgorithm", "sha256-canonical-v2-truncated-16");
        JsonUtil.put(connection, "declared", profile.declared); JsonUtil.put(connection, "observedEndpointIps", JsonUtil.array(profile.endpointIps));
        JsonUtil.put(connection, "observedCamouflageIps", JsonUtil.array(profile.camouflageIps));
        JsonUtil.put(connection, "exitAttribution", profile.exitAttribution); JsonUtil.put(connection, "stages", profile.stages);
        JsonUtil.put(connection, "statusCounts", statusCounts(profile.stages)); JsonUtil.put(connection, "outcomeCounts", outcomeCounts(profile.stages));
        JsonUtil.put(connection, "outcome", profile.outcome); JsonUtil.put(connection, "inferences", profile.inferences);
        if (input.testType.extended()) JsonUtil.put(connection, "extendedResultsFile", "extended-test.json");
        JSONArray sharedRows = new JSONArray();
        for (Map.Entry<String, List<String>> entry : shared.entrySet()) if (entry.getValue().contains(profile.profileId)) {
            sharedRows.put(JsonUtil.object("ip", entry.getKey(), "profileIds", JsonUtil.array(entry.getValue())));
        }
        JsonUtil.put(connection, "sharedHostnameBackends", sharedRows); JsonUtil.put(root, "connection", connection);
        JSONObject comparison = new JSONObject(); JsonUtil.put(comparison, "directPublicIps", JsonUtil.array(ProbeSuite.validExitAddresses(input.directExit)));
        JsonUtil.put(comparison, "tunnelExitIps", JsonUtil.array(ProbeSuite.validExitAddresses(profile.tunnelExit))); JsonUtil.put(comparison, "ingressIps", JsonUtil.array(profile.endpointIps));
        JsonUtil.put(root, "directVersusTunnel", comparison);
        JsonUtil.put(root, "probabilityNotice", "Percentages and confidence labels are conservative heuristic evidence weights, not calibrated statistical probabilities.");
        JsonUtil.put(root, "limitations", commonLimitations());
        return root;
    }

    static JSONObject extendedJson(PackageInput input, TrafficLabRunner.ProfileResult profile) {
        JSONObject root = base(input, "extended-test-results");
        JsonUtil.put(root, "connection", JsonUtil.object("profileId", profile.profileId, "sourceOrdinal", profile.ordinal,
                "name", profile.name, "profileFingerprint", profile.fingerprint));
        JsonUtil.put(root, "outcome", profile.outcome);
        JsonUtil.put(root, "statusCounts", statusCounts(profile.extendedStages));
        JsonUtil.put(root, "outcomeCounts", outcomeCounts(profile.extendedStages));
        JsonUtil.put(root, "stages", profile.extendedStages);
        JsonUtil.put(root, "limitations", new JSONArray()
                .put("Android extended interruption stops only Traffic Lab's isolated Xray process; it does not disable the radio, modify routes or interrupt unrelated applications.")
                .put("Cold/warm and parallel-flow behavior is requested at the Android client/Xray inbound; a controlled canary is required to prove server-side connection reuse or multiplexing.")
                .put("DNS failure/recovery uses a reserved .invalid name and does not inject an outage into the operator recursive resolver.")
                .put("Soak loss and jitter are HTTPS application observations, not ICMP packet statistics."));
        return root;
    }

    private static JSONObject localJson(PackageInput input, TrafficLabRunner.ProfileResult profile) {
        JSONObject root = base(input, "local-machine-and-network-characteristics");
        JsonUtil.put(root, "appliesTo", JsonUtil.object("profileId", profile.profileId, "sourceOrdinal", profile.ordinal, "name", profile.name, "profileFingerprint", profile.fingerprint));
        JsonUtil.put(root, "node", input.node); JsonUtil.put(root, "publicIpObservations", input.directExit);
        JsonUtil.put(root, "publicIpAttribution", input.directAttribution);
        JsonUtil.put(root, "androidSpecificCoverage", new JSONArray()
                .put("NetworkCapabilities transports/validation/captive/metered/roaming/bandwidth")
                .put("LinkProperties routes, MTU, DNS, Private DNS, NAT64 and HTTP proxy")
                .put("Wi-Fi standard, frequency, RSSI and negotiated link rates")
                .put("Cellular LTE/NR type, carrier/SIM summaries and signal levels without subscriber identifiers")
                .put("Battery saver, idle mode, Data Saver and airplane mode"));
        JsonUtil.put(root, "probabilityNotice", "IP location, NAT layers and provider identity are bounded external inferences. When permission is granted, deviceLocation is a separate sensitive Android OS fix; neither source locates the LTE cell.");
        return root;
    }

    static JSONObject base(PackageInput input, String outputType) {
        JSONObject root = new JSONObject(); JsonUtil.put(root, "schemaVersion", "1.0"); JsonUtil.put(root, "outputType", outputType);
        JsonUtil.put(root, "generatedAt", JsonUtil.now());
        JSONObject run = new JSONObject(); JsonUtil.put(run, "runId", input.runId); JsonUtil.put(run, "startedAt", input.startedAt);
        JsonUtil.put(run, "completedAt", input.completedAt); JsonUtil.put(run, "durationMs", input.durationMs);
        JsonUtil.put(run, "testType", input.testType.value); JsonUtil.put(run, "platform", "android");
        JsonUtil.put(run, "outcome", input.runOutcome);
        JsonUtil.put(run, "operatingSystem", "Android " + androidRelease());
        JsonUtil.put(run, "operatingSystemVersion", androidRelease()); JsonUtil.put(run, "androidApiLevel", Build.VERSION.SDK_INT);
        JsonUtil.put(run, "extendedTest", JsonUtil.object("enabled", input.testType.extended(),
                "soakDurationSeconds", input.testType.extended() ? AndroidExtendedTestSuite.SOAK_SECONDS : null,
                "parallelFlows", input.testType.extended() ? AndroidExtendedTestSuite.PARALLEL_FLOWS : null,
                "processInterruptionSeconds", input.testType.extended() ? AndroidExtendedTestSuite.INTERRUPTION_SECONDS : null));
        JsonUtil.put(run, "executionOrder", "sequential");
        JsonUtil.put(run, "inputSource", "in-app clipboard/import field"); JsonUtil.put(root, "run", run);
        JSONObject location = input.node.optJSONObject("deviceLocation");
        JSONObject testContext = JsonUtil.object("nodeId", android.os.Build.MANUFACTURER + "-" + android.os.Build.MODEL,
                "scenario", "standalone", "accessType", input.node.optJSONObject("connectivity") == null ? "unknown" : input.node.optJSONObject("connectivity").optString("detectedAccessType", "unknown"));
        if (location != null && "observed".equals(location.optString("status"))) {
            JsonUtil.put(testContext, "latitude", location.optDouble("latitude")); JsonUtil.put(testContext, "longitude", location.optDouble("longitude"));
            JsonUtil.put(testContext, "locationSource", "android-location-api"); JsonUtil.put(testContext, "locationAccuracyMeters", location.opt("accuracyMeters"));
        }
        JsonUtil.put(run, "testContext", testContext);
        JSONObject tool = new JSONObject(); JsonUtil.put(tool, "name", "Loki Traffic Lab Android"); JsonUtil.put(tool, "version", BuildConfig.VERSION_NAME);
        JsonUtil.put(tool, "embeddedXrayVersion", input.xrayVersion); JsonUtil.put(tool, "abi", primaryAbi()); JsonUtil.put(root, "tool", tool);
        return root;
    }

    private static String osiMap(PackageInput input, TrafficLabRunner.ProfileResult profile) {
        JSONObject connectivity = input.node.optJSONObject("connectivity");
        String access = connectivity == null ? "unknown" : connectivity.optString("detectedAccessType", "unknown");
        String local = connectivity == null || connectivity.optJSONObject("link") == null ? "unknown" : connectivity.optJSONObject("link").optJSONArray("addresses").toString();
        String publicIps = ProbeSuite.validExitAddresses(input.directExit).toString();
        String exitIps = ProbeSuite.validExitAddresses(profile.tunnelExit).toString();
        return "# Loki Traffic Lab — Android OSI evidence map\n\n"
                + "Profile: " + safeMarkdown(profile.name) + " (`" + profile.profileId + "`)  \n"
                + "Generated: " + input.completedAt + "\n\n"
                + "| OSI | Layer | Observed Android evidence | Confidence / limits |\n"
                + "|---:|---|---|---|\n"
                + "| 1 | Physical | Access=`" + access + "`; Wi-Fi/cellular radio and negotiated rate are in local-machine.json. | Medium; Android cannot identify cable plant or LTE tower from an ordinary app. |\n"
                + "| 2 | Data link | Hashed SSID/BSSID/MAC, Wi-Fi standard/frequency/RSSI and active interface. | Medium; VLAN and upstream carrier L2 remain hidden. |\n"
                + "| 3 | Network | Local=" + safeMarkdown(local) + "; public=" + safeMarkdown(publicIps) + "; endpoint=" + safeMarkdown(profile.endpointIps.toString()) + ". | High for observed IPs/routes; IP geolocation is low confidence. |\n"
                + "| 4 | Transport | Repeated TCP, tunneled UDP DNS, MTU/payload sweep, RTT/timeouts. | High for responses; firewalls and QUIC internals remain inferential. |\n"
                + "| 5 | Session | Isolated VLESS session, stability and negative UUID/shortId/SNI controls. | High for end-to-end success; panel/HWID state is private. |\n"
                + "| 6 | Presentation | TLS/REALITY SNI, TLS version, cipher, ALPN and certificate/SPKI hashes. | Medium/high; exact REALITY target remains server-side. |\n"
                + "| 7 | Application | DNS variants, HTTP, exit IP, SOCKS remote-domain DNS, upload/download and payload sizes. | High for measured requests. |\n\n"
                + "```mermaid\nflowchart LR\n"
                + "  A[\"Android app / explicit loopback proxy\"] --> B[\"" + escapeMermaid(access) + " network / gateway\"]\n"
                + "  B --> C[\"ISP / NAT / public " + escapeMermaid(publicIps) + "\"]\n"
                + "  C --> D[\"VLESS entry " + escapeMermaid(profile.endpointIps.toString()) + "\"]\n"
                + "  D --> E[\"Authenticated server path / hidden routing\"]\n"
                + "  E --> F[\"Exit " + escapeMermaid(exitIps) + "\"]\n"
                + "  F --> G[\"DNS / HTTP / STUN test services\"]\nend\n```\n";
    }

    private static String readme(PackageInput input, TrafficLabRunner.ProfileResult profile) {
        JSONObject counts = statusCounts(combinedStages(profile, input.testType.extended()));
        return "LOKI TRAFFIC LAB - ANDROID TEST RESULT PACKAGE\n"
                + "================================================\n\n"
                + "Run ID: " + input.runId + "\n"
                + "Test started (UTC): " + input.startedAt + "\n"
                + "Test completed (UTC): " + input.completedAt + "\n"
                + "Duration: " + formatDuration(input.durationMs) + "\n"
                + "Test type: " + input.testType.value.toUpperCase(Locale.ROOT) + (input.testType.extended() ? " (long-running/process-disruptive extended suite)" : " (standard suite)") + "\n"
                + (input.testType.extended() ? "Extended settings: soak=" + AndroidExtendedTestSuite.SOAK_SECONDS + "s, parallel flows=" + AndroidExtendedTestSuite.PARALLEL_FLOWS + ", process interruption=" + AndroidExtendedTestSuite.INTERRUPTION_SECONDS + "s\n" : "")
                + "Device local timezone: " + TimeZone.getDefault().getID() + "\n"
                + "Platform: android\n"
                + "Operating system: Android " + androidRelease() + "\n"
                + "Android API level: " + Build.VERSION.SDK_INT + "\n"
                + "Device: " + Build.MANUFACTURER + " " + Build.MODEL + "\n"
                + "ABI: " + primaryAbi() + "\n"
                + "Test execution node: Android device, Loki Traffic Lab APK tester\n"
                + "Tool: Loki Traffic Lab Android " + BuildConfig.VERSION_NAME + "\n"
                + "Core: " + input.xrayVersion + "\n"
                + "Connections loaded/scheduled: " + input.profiles.size() + "/" + input.profiles.size() + "\n"
                + "Execution order: sequential\n"
                + "Input source: in-app text parsed from clipboard\n\n"
                + "CONNECTION\n----------\n"
                + "Profile ID/order: " + profile.profileId + " / " + profile.ordinal + "\n"
                + "Name: " + profile.name + "\n"
                + "Sanitized fingerprint: " + profile.fingerprint + "\n"
                + "Fingerprint algorithm: sha256-canonical-v2-truncated-16\n"
                + "Endpoint: " + profile.declared.optString("host", "unknown") + ":" + profile.declared.optInt("port", 0) + "\n"
                + "Stages: passed=" + counts.optInt("passed") + ", partial=" + counts.optInt("partial") + ", failed=" + counts.optInt("failed") + ", skipped=" + counts.optInt("skipped") + "\n\n"
                + "Profile outcome: " + profile.outcome.optString("outcome", "UNKNOWN") + "\n"
                + "Outcome reason: " + profile.outcome.optString("reasonCode", "INSUFFICIENT_EVIDENCE") + " - " + profile.outcome.optString("reason", "No causal classification was available.") + "\n"
                + "Run outcome: " + input.runOutcome.optString("outcome", "UNKNOWN") + " (" + input.runOutcome.optString("reasonCode", "RUN_INCONCLUSIVE") + ")\n\n"
                + "FILES\n-----\n"
                + "connection.json    Connection, DNS/TCP/TLS/tunnel stages, attribution and bounded inferences.\n"
                + "local-machine.json Android device/network passport and direct-network measurements.\n"
                + "osi-map.md         Seven-layer evidence table and traffic path.\n"
                + "README.txt         Run metadata, file guide, privacy and confidence notes.\n\n"
                + (input.testType.extended() ? "extended-test.json Long-running, parallel, DNS recovery, soak, reconnect and process-interruption stages.\n\n" : "")
                + "PRIVACY AND STORAGE\n-------------------\n"
                + "The raw VLESS URI, UUID, REALITY public key and short ID are not written to this archive.\n"
                + "Subscriber identifiers, phone number, IMSI, ICCID and precise cell identity are not collected. If location permission is granted, device coordinates, accuracy and age are included and are sensitive.\n"
                + "The ZIP exists only in the app cache until Save, Share or Clear; it is not automatically copied to shared storage.\n"
                + "Public/local addresses and requested network metadata remain potentially sensitive.\n\n"
                + "CONFIDENCE AND LIMITS\n---------------------\n"
                + "High means a direct protocol response or Android OS API observation; medium means compatible external signals; low means a weak hint.\n"
                + "Probabilities are heuristic evidence weights, not calibrated statistical probabilities.\n"
                + "Speed uses one bounded calibration plus three adaptive measurement samples. recommendedMbps excludes calibration and is the measurement median payload transfer/acknowledgement rate; medianEffectiveMbps includes connection, TLS, TTFB and response overhead. Sample spread and confidence must be considered with either value.\n"
                + "Core log markers are listed in connection.json data.logAnalysis as expected/benign or unexpected; only unexpected markers downgrade tunnel.logs.\n"
                + "Exact server routing, second hop, REALITY target and panel/HWID policy require server-side state.\n";
    }

    private static JSONObject statusCounts(JSONArray stages) {
        JSONObject counts = JsonUtil.object("passed", 0, "partial", 0, "failed", 0, "skipped", 0);
        for (int i = 0; i < stages.length(); i++) {
            JSONObject stage = stages.optJSONObject(i); if (stage == null) continue; String status = stage.optString("status", "unknown");
            JsonUtil.put(counts, status, counts.optInt(status) + 1);
        }
        return counts;
    }

    private static JSONObject outcomeCounts(JSONArray stages) {
        JSONObject counts = JsonUtil.object("PASS", 0, "PROXY_FAIL", 0, "UNDERLAY_FAIL", 0, "TEST_FAILURE", 0, "UNKNOWN", 0);
        for (int i = 0; i < stages.length(); i++) {
            JSONObject stage = stages.optJSONObject(i); if (stage == null) continue; String outcome = stage.optString("outcome", "UNKNOWN");
            JsonUtil.put(counts, outcome, counts.optInt(outcome) + 1);
        }
        return counts;
    }

    private static JSONArray combinedStages(TrafficLabRunner.ProfileResult profile, boolean includeExtended) {
        JSONArray values = new JSONArray();
        for (int index = 0; index < profile.stages.length(); index++) values.put(profile.stages.opt(index));
        if (includeExtended) for (int index = 0; index < profile.extendedStages.length(); index++) values.put(profile.extendedStages.opt(index));
        return values;
    }

    private static String androidRelease() {
        String value = Build.VERSION.RELEASE;
        return value == null || value.trim().isEmpty() ? "unknown" : value.trim();
    }

    private static String primaryAbi() {
        return Build.SUPPORTED_ABIS == null || Build.SUPPORTED_ABIS.length == 0 ? "unknown" : Build.SUPPORTED_ABIS[0];
    }

    private static Map<String, List<String>> sharedBackends(List<TrafficLabRunner.ProfileResult> profiles) {
        Map<String, List<String>> result = new HashMap<>();
        for (TrafficLabRunner.ProfileResult profile : profiles) for (String ip : profile.endpointIps) result.computeIfAbsent(ip, ignored -> new java.util.ArrayList<>()).add(profile.profileId);
        result.entrySet().removeIf(entry -> entry.getValue().size() < 2); return result;
    }

    private static String uniqueFolder(TrafficLabRunner.ProfileResult profile, Set<String> used) {
        String safe = profile.name.replaceAll("[<>:\"/\\\\|?*\\x00-\\x1F]", "-").replaceAll("\\s+", " ").trim();
        if (safe.trim().isEmpty()) safe = profile.profileId; if (safe.length() > 60) safe = safe.substring(0, 60).trim();
        String root = String.format(Locale.ROOT, "%02d-%s", profile.ordinal, safe); String value = root; int suffix = 2;
        while (!used.add(value)) value = root + "-" + suffix++; return value;
    }

    private static JSONArray commonLimitations() {
        return new JSONArray().put("Client observations cannot prove server routing rules, a hidden second hop, panel HWID policy or the exact REALITY target.")
                .put("IP geolocation and ASN organization names are attribution hints, not proof of physical server or LTE-tower location.")
                .put("Android testing uses explicit app-local HTTP/SOCKS inbounds and does not represent a device-wide full-tunnel configuration.");
    }

    private static void write(ZipOutputStream output, String name, String content) throws Exception {
        ZipEntry entry = new ZipEntry(name); entry.setTime(System.currentTimeMillis()); output.putNextEntry(entry);
        output.write(content.getBytes(StandardCharsets.UTF_8)); output.closeEntry();
    }

    private static String formatDuration(long ms) {
        long seconds = ms / 1000; return String.format(Locale.ROOT, "%02d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60);
    }

    private static String safeMarkdown(String value) { return value == null ? "unknown" : value.replace("|", "\\|").replace("\n", " "); }
    private static String escapeMermaid(String value) { return value == null ? "unknown" : value.replace("\\", "\\\\").replace("\"", "'").replace("\n", " "); }

    private static void deleteTree(File target) {
        if (target == null || !target.exists()) return; File[] children = target.listFiles(); if (children != null) for (File child : children) deleteTree(child);
        //noinspection ResultOfMethodCallIgnored
        target.delete();
    }

    static final class PackageInput {
        final String runId; final String startedAt; final String completedAt; final long durationMs; final String xrayVersion;
        final JSONObject node; final JSONArray directExit; final JSONArray directAttribution; final List<TrafficLabRunner.ProfileResult> profiles;
        final TrafficLabRunner.TestType testType; final JSONObject runOutcome;
        PackageInput(String runId, String startedAt, String completedAt, long durationMs, String xrayVersion, JSONObject node,
                     JSONArray directExit, JSONArray directAttribution, List<TrafficLabRunner.ProfileResult> profiles, TrafficLabRunner.TestType testType, JSONObject runOutcome) {
            this.runId = runId; this.startedAt = startedAt; this.completedAt = completedAt; this.durationMs = durationMs;
            this.xrayVersion = xrayVersion; this.node = node; this.directExit = directExit; this.directAttribution = directAttribution; this.profiles = profiles;
            this.testType = testType == null ? TrafficLabRunner.TestType.NORMAL : testType;
            this.runOutcome = runOutcome == null ? JsonUtil.object("outcome", "UNKNOWN", "reasonCode", "RUN_INCONCLUSIVE", "reason", "No run classification was available.") : runOutcome;
        }
    }
}
