package com.loki.trafficlab;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

final class TrafficLabRunner {
    interface ProgressListener { void onProgress(int percent, int completed, int total, String message); }

    enum TestType {
        NORMAL("normal"), EXTENDED("extended"), SPEED("speed");
        final String value;
        TestType(String value) { this.value = value; }
        boolean extended() { return this == EXTENDED; }
        boolean speed() { return this == SPEED; }
        static TestType from(String value) {
            return "extended".equalsIgnoreCase(value) ? EXTENDED : "speed".equalsIgnoreCase(value) ? SPEED : NORMAL;
        }
    }

    private final Context context;
    private final ProgressListener progress;
    private final AtomicBoolean canceled = new AtomicBoolean();
    private final XrayManager xray;

    TrafficLabRunner(Context context, ProgressListener progress) {
        this.context = context.getApplicationContext();
        this.progress = progress;
        this.xray = new XrayManager(context);
    }

    void cancel() { canceled.set(true); xray.cancel(); }

    RunResult run(List<String> connections) throws Exception { return run(connections, TestType.NORMAL); }

    RunResult run(List<String> connections, TestType testType) throws Exception {
        if (connections == null || connections.isEmpty()) throw new IllegalArgumentException("No VLESS connections were supplied");
        if (testType == null) testType = TestType.NORMAL;
        long startedNanos = System.nanoTime();
        String startedAt = JsonUtil.now();
        String runId = startedAt.replaceAll("[-:.TZ]", "").substring(0, 14) + "-" + UUID.randomUUID().toString().substring(0, 8);
        report(2, 0, connections.size(), "Loaded " + connections.size() + " connection(s) for " + testType.value + " test");
        checkCanceled();

        if (testType.speed()) return runSpeedOnly(connections, testType, startedNanos, startedAt, runId);

        report(5, 0, connections.size(), "Capturing Android network baseline");
        JSONObject node = AndroidNetworkDiagnostics.capture(context);
        JSONArray directExit = ProbeSuite.exitIps(null);
        List<String> directAddresses = ProbeSuite.validExitAddresses(directExit);
        JSONArray directAttribution = ProbeSuite.attribution(directAddresses);
        JSONObject directStun = ProbeSuite.directStun();
        JSONObject directPerformance = AndroidSpeedTestEngine.measure(null, AndroidSpeedTestEngine.Mode.NORMAL, this::checkCanceled);
        enrichNode(node, directExit, directAttribution, directStun, directPerformance);
        boolean directControlAvailable = ProbeSuite.anyValidExit(directExit)
                || !"failed".equals(directPerformance.optString("status"));
        report(15, 0, connections.size(), "Direct network baseline captured");

        List<ProfileResult> profiles = new ArrayList<>();
        for (int index = 0; index < connections.size(); index++) {
            checkCanceled();
            int start = 15 + (int) Math.floor(index * 78.0 / connections.size());
            int end = 15 + (int) Math.floor((index + 1) * 78.0 / connections.size());
            int current = index;
            ProgressListener profileProgress = (percent, ignored, ignoredTotal, message) ->
                    report(start + (int) Math.round((end - start) * Math.max(0, Math.min(100, percent)) / 100.0), current, connections.size(), "profile-" + String.format(Locale.ROOT, "%02d", current + 1) + ": " + message);
            ProfileResult profile = runProfile(connections.get(index), index + 1, directExit, directControlAvailable, findActiveMtu(node), profileProgress, testType);
            profiles.add(profile);
            report(end, index + 1, connections.size(), "profile-" + String.format(Locale.ROOT, "%02d", index + 1) + ": completed");
        }

        checkCanceled();
        report(95, connections.size(), connections.size(), "Building structured Android reports");
        String completedAt = JsonUtil.now();
        long durationMs = ProbeSuite.elapsed(startedNanos);
        JSONArray profileOutcomes = new JSONArray(); for (ProfileResult profile : profiles) profileOutcomes.put(profile.outcome);
        JSONObject runOutcome = AndroidOutcomeClassifier.run(profileOutcomes, directControlAvailable);
        ResultPackager.PackageInput input = new ResultPackager.PackageInput(runId, startedAt, completedAt, durationMs,
                xray.version(), node, directExit, directAttribution, profiles, testType, runOutcome);
        report(97, connections.size(), connections.size(), "Creating temporary result ZIP");
        File zip = ResultPackager.create(context, input);
        boolean usable = false;
        for (ProfileResult profile : profiles) if (profile.usable) { usable = true; break; }
        report(100, connections.size(), connections.size(), usable ? "Testing completed successfully" : "Testing completed with no usable profile");
        return new RunResult(zip, profiles.size(), durationMs, usable, startedAt, completedAt, testType, runOutcome);
    }

    private RunResult runSpeedOnly(List<String> connections, TestType testType, long startedNanos,
                                   String startedAt, String runId) throws Exception {
        report(4, 0, connections.size(), "Capturing Android network context for speed test");
        JSONObject node = AndroidNetworkDiagnostics.capture(context);
        List<ProfileResult> profiles = new ArrayList<>();
        JSONArray speedSummaries = new JSONArray();
        boolean anyDirectControl = false;
        for (int index = 0; index < connections.size(); index++) {
            checkCanceled(); int ordinal = index + 1;
            int startPercent = 5 + (int) Math.floor(index * 90.0 / connections.size());
            int endPercent = 5 + (int) Math.floor((index + 1) * 90.0 / connections.size());
            String profileId = "profile-" + String.format(Locale.ROOT, "%02d", ordinal);
            JSONArray stages = new JSONArray(); ConnectionParser.Profile profile;
            try {
                profile = ConnectionParser.parse(connections.get(index));
                stages.put(JsonUtil.passed("profile.parse", 0, profile.declared()));
            } catch (Exception error) {
                stages.put(JsonUtil.failed("profile.parse", 0, JsonUtil.redact(error.getMessage()), null));
                AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), true);
                profiles.add(new ProfileResult(profileId, ordinal, "Invalid profile " + ordinal, "unavailable", new JSONObject(),
                        Collections.<String>emptyList(), Collections.<String>emptyList(), new JSONArray(), new JSONArray(), new JSONArray(),
                        stages, new JSONArray(), new JSONArray(), false,
                        speedDecision("TEST_FAILURE", "PROFILE_PARSE_FAILURE", "The supplied connection URI could not be parsed.")));
                report(endPercent, ordinal, connections.size(), profileId + ": invalid profile skipped");
                continue;
            }

            report(startPercent + (endPercent - startPercent) * 5 / 100, index, connections.size(), profileId + ": direct speed control before tunnel");
            JSONObject directBefore = AndroidSpeedTestEngine.measure(null, AndroidSpeedTestEngine.Mode.SPEED, this::checkCanceled);
            JSONObject matchedPlan = AndroidSpeedTestEngine.createPlan(directBefore);
            boolean directAvailable = !"failed".equals(directBefore.optString("status")); anyDirectControl |= directAvailable;
            stages.put(speedStage("speed.directBefore", directBefore, false));

            report(startPercent + (endPercent - startPercent) * 30 / 100, index, connections.size(), profileId + ": endpoint DNS and TCP");
            ProbeSuite.DnsResult dns = ProbeSuite.dns(profile.host); stages.put(dns.stage);
            JSONObject tcp = ProbeSuite.tcp(dns.addresses, profile.port, 3); stages.put(tcp);
            JSONObject tunnelSpeed = JsonUtil.object("status", "failed", "error", "Tunnel speed was not attempted.");
            boolean authenticated = false;
            if ("passed".equals(tcp.optString("status"))) {
                try (XrayManager.RunSession session = xray.start(profile)) {
                    stages.put(JsonUtil.passed("tunnel.coreValidation", 0, JsonUtil.object("embeddedCore", true, "abi", android.os.Build.SUPPORTED_ABIS[0])));
                    stages.put(JsonUtil.passed("tunnel.coreStart", 0, JsonUtil.object("httpPort", session.httpPort, "loopbackOnly", true)));
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", session.httpPort));
                    JSONObject http = ProbeSuite.httpStage(proxy); authenticated = "passed".equals(http.optString("status"));
                    stages.put(authenticated
                            ? JsonUtil.passed("tunnel.authenticatedEndToEnd", http.optLong("elapsedMs"), JsonUtil.object("protocol", "vless", "speedPrerequisite", true))
                            : JsonUtil.failed("tunnel.authenticatedEndToEnd", http.optLong("elapsedMs"), "No authenticated control request completed before speed measurement.", http));
                    if (authenticated) {
                        report(startPercent + (endPercent - startPercent) * 45 / 100, index, connections.size(), profileId + ": ABBA tunnel leg 1/2");
                        JSONObject tunnelFirst = AndroidSpeedTestEngine.measure(proxy, AndroidSpeedTestEngine.Mode.SPEED, matchedPlan, this::checkCanceled);
                        report(startPercent + (endPercent - startPercent) * 62 / 100, index, connections.size(), profileId + ": ABBA tunnel leg 2/2");
                        JSONObject tunnelSecond = AndroidSpeedTestEngine.measure(proxy, AndroidSpeedTestEngine.Mode.SPEED, matchedPlan, this::checkCanceled);
                        tunnelSpeed = AndroidSpeedTestEngine.combine(tunnelFirst, tunnelSecond);
                        JsonUtil.put(tunnelSpeed, "abbaPasses", new JSONArray().put(tunnelFirst).put(tunnelSecond));
                        stages.put(speedStage("speed.tunnel", tunnelSpeed, true));
                    } else stages.put(JsonUtil.skipped("speed.tunnel", "Authenticated tunnel prerequisite failed."));
                } catch (Exception error) {
                    stages.put(JsonUtil.failed("tunnel.coreStart", 0, JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()), null));
                    stages.put(JsonUtil.skipped("tunnel.authenticatedEndToEnd", "The isolated Xray core was unavailable."));
                    stages.put(JsonUtil.skipped("speed.tunnel", "The isolated Xray core was unavailable."));
                }
            } else {
                stages.put(JsonUtil.skipped("tunnel.coreValidation", "Endpoint TCP prerequisite failed."));
                stages.put(JsonUtil.skipped("tunnel.coreStart", "Endpoint TCP prerequisite failed."));
                stages.put(JsonUtil.skipped("tunnel.authenticatedEndToEnd", "Endpoint TCP prerequisite failed."));
                stages.put(JsonUtil.skipped("speed.tunnel", "Endpoint TCP prerequisite failed."));
            }

            report(startPercent + (endPercent - startPercent) * 78 / 100, index, connections.size(), profileId + ": direct speed control after tunnel");
            JSONObject directAfter = AndroidSpeedTestEngine.measure(null, AndroidSpeedTestEngine.Mode.SPEED, matchedPlan, this::checkCanceled);
            directAvailable |= !"failed".equals(directAfter.optString("status"));
            anyDirectControl |= directAvailable;
            stages.put(speedStage("speed.directAfter", directAfter, false));
            JSONObject comparison = AndroidSpeedTestEngine.compare(directBefore, tunnelSpeed, directAfter);
            stages.put(authenticated ? (comparison.optBoolean("directControlStable")
                    ? JsonUtil.passed("speed.comparison", 0, comparison)
                    : JsonUtil.partial("speed.comparison", 0, "Direct before/after capacity drifted or was unavailable; tunnel attribution is low-confidence.", comparison))
                    : JsonUtil.skipped("speed.comparison", "No tunnel speed result was available."));
            AndroidOutcomeClassifier.applyProfile(stages, new JSONArray(), directAvailable);
            JSONObject outcome = !directAvailable
                    ? speedDecision("UNDERLAY_FAIL", "DIRECT_CONTROL_UNAVAILABLE", "Matched direct speed controls produced no usable measurement.")
                    : !"passed".equals(tcp.optString("status"))
                    ? speedDecision("PROXY_FAIL", "PROXY_PATH_FAIL", "The profile endpoint was not TCP-reachable.")
                    : !authenticated
                    ? speedDecision("PROXY_FAIL", "PROTOCOL_AUTH_FAIL", "Endpoint TCP worked but authenticated VLESS traffic did not.")
                    : "failed".equals(tunnelSpeed.optString("status"))
                    ? speedDecision("UNKNOWN", "SPEED_MEASUREMENT_INCONCLUSIVE", "Authentication succeeded but no tunnel speed series completed.")
                    : speedDecision("PASS", "SPEED_MEASUREMENT_SUCCEEDED", "Matched direct and authenticated tunnel speed measurements completed.");
            if (authenticated && !"failed".equals(tunnelSpeed.optString("status"))) {
                JSONObject summary = AndroidSpeedTestEngine.summary(tunnelSpeed);
                JsonUtil.put(summary, "profileId", profileId); JsonUtil.put(summary, "name", profile.name); speedSummaries.put(summary);
            }
            profiles.add(new ProfileResult(profileId, ordinal, profile.name, profile.fingerprint(), profile.declared(), dns.addresses,
                    Collections.<String>emptyList(), new JSONArray(), new JSONArray(), new JSONArray(), stages,
                    new JSONArray(), new JSONArray(), authenticated, outcome));
            report(endPercent, ordinal, connections.size(), profileId + ": speed test completed");
        }

        String completedAt = JsonUtil.now(); long durationMs = ProbeSuite.elapsed(startedNanos);
        JSONArray outcomes = new JSONArray(); boolean usable = false;
        for (ProfileResult profile : profiles) { outcomes.put(profile.outcome); usable |= profile.usable; }
        boolean allTestFailure = profiles.size() > 0;
        for (ProfileResult profile : profiles) allTestFailure &= "TEST_FAILURE".equals(profile.outcome.optString("outcome"));
        JSONObject runOutcome = allTestFailure
                ? speedDecision("TEST_FAILURE", "ALL_PROFILES_TEST_FAILURE", "Every connection was rejected before a fair speed-path measurement could start.")
                : AndroidOutcomeClassifier.run(outcomes, anyDirectControl);
        JsonUtil.put(runOutcome, "speedSummary", speedSummaries);
        ResultPackager.PackageInput input = new ResultPackager.PackageInput(runId, startedAt, completedAt, durationMs,
                xray.version(), node, new JSONArray(), new JSONArray(), profiles, testType, runOutcome);
        report(97, profiles.size(), profiles.size(), "Creating speed.json and readme.txt");
        File zip = ResultPackager.create(context, input);
        report(100, profiles.size(), profiles.size(), "Speed testing completed: " + runOutcome.optString("outcome", "UNKNOWN"));
        return new RunResult(zip, profiles.size(), durationMs, usable, startedAt, completedAt, testType, runOutcome,
                formatSpeedSummaries(speedSummaries));
    }

    private static JSONObject speedStage(String name, JSONObject report, boolean proxyPath) {
        String status = report.optString("status", "failed"); long elapsedMs = report.optLong("elapsedMs");
        if ("passed".equals(status)) return JsonUtil.passed(name, elapsedMs, report);
        String reason = proxyPath ? "One or more tunneled speed series did not complete." : "One or more direct speed series did not complete.";
        return "partial".equals(status) ? JsonUtil.partial(name, elapsedMs, reason, report)
                : JsonUtil.failed(name, elapsedMs, reason, report);
    }

    private static JSONObject speedDirectionStage(String name, JSONObject report, String direction) {
        JSONArray selected = new JSONArray(); JSONArray series = report.optJSONArray("series");
        if (series != null) for (int index = 0; index < series.length(); index++) {
            JSONObject item = series.optJSONObject(index);
            if (item != null && direction.equals(item.optString("direction"))) selected.put(item);
        }
        JSONObject summary = AndroidSpeedTestEngine.summary(report);
        Object recommended = "download".equals(direction) ? summary.opt("downloadMbps") : summary.opt("uploadMbps");
        JSONObject data = JsonUtil.object("direction", direction, "recommendedMbps", recommended,
                "series", selected, "measurementVersion", report.optInt("measurementVersion"), "method", report.optString("method"));
        return selected.length() > 0 ? JsonUtil.passed(name, report.optLong("elapsedMs"), data)
                : JsonUtil.failed(name, report.optLong("elapsedMs"), "No usable " + direction + " speed series completed.", data);
    }

    private static JSONObject speedDecision(String outcome, String reasonCode, String reason) {
        return JsonUtil.object("outcome", outcome, "reasonCode", reasonCode, "reason", reason,
                "evidence", new JSONArray().put("speed.directBefore").put("speed.tunnel").put("speed.directAfter"));
    }

    private static String formatSpeedSummaries(JSONArray summaries) {
        if (summaries == null || summaries.length() == 0) return null;
        List<String> rows = new ArrayList<>();
        for (int index = 0; index < summaries.length(); index++) {
            JSONObject value = summaries.optJSONObject(index); if (value == null) continue;
            rows.add(value.optString("name", value.optString("profileId", "profile")) + ": Download "
                    + String.format(Locale.ROOT, "%.2f", value.optDouble("downloadMbps")) + " Mbit/s · Upload "
                    + String.format(Locale.ROOT, "%.2f", value.optDouble("uploadMbps")) + " Mbit/s · confidence="
                    + value.optString("confidence", "unknown"));
        }
        return rows.isEmpty() ? null : String.join(" | ", rows);
    }

    private ProfileResult runProfile(String raw, int ordinal, JSONArray directExit, boolean directControlAvailable, Integer activeMtu, ProgressListener listener, TestType testType) throws Exception {
        String profileId = "profile-" + String.format(Locale.ROOT, "%02d", ordinal);
        JSONArray stages = new JSONArray();
        JSONArray extendedStages = new JSONArray();
        ProgressListener standardProgress = testType.extended()
                ? (percent, completed, total, message) -> listener.onProgress((int) Math.round(percent * 0.58), completed, total, message)
                : listener;
        ConnectionParser.Profile profile;
        try {
            profile = ConnectionParser.parse(raw);
        } catch (Exception error) {
            stages.put(JsonUtil.failed("profile.parse", 0, JsonUtil.redact(error.getMessage()), null));
            return ProfileResult.invalid(profileId, ordinal, stages, testType, directControlAvailable);
        }
        stages.put(JsonUtil.passed("profile.parse", 0, profile.declared()));
        standardProgress.onProgress(5, 0, 0, "profile parsed");

        ProbeSuite.DnsResult endpointDns = ProbeSuite.dns(profile.host);
        stages.put(endpointDns.stage);
        stages.put(ProbeSuite.dnsConsistency("endpoint.dnsConsistency", endpointDns));
        ProbeSuite.DnsResult camouflageDns = null;
        if (profile.sni != null && !profile.sni.trim().isEmpty()) {
            camouflageDns = ProbeSuite.dns(profile.sni);
            JsonUtil.put(camouflageDns.stage, "stage", "camouflage.dns");
            stages.put(camouflageDns.stage);
            stages.put(ProbeSuite.dnsConsistency("camouflage.dnsConsistency", camouflageDns));
        } else {
            stages.put(JsonUtil.skipped("camouflage.dns", "Profile does not declare SNI."));
            stages.put(JsonUtil.skipped("camouflage.dnsConsistency", "No camouflage hostname."));
        }
        standardProgress.onProgress(18, 0, 0, "DNS checks completed");
        checkCanceled();

        JSONObject tcpStage = ProbeSuite.tcp(endpointDns.addresses, profile.port, 3);
        stages.put(tcpStage);
        boolean endpointTcpAvailable = "passed".equals(tcpStage.optString("status"));
        JSONObject mtu = new JSONObject();
        JsonUtil.put(mtu, "interfaceMtu", activeMtu);
        JsonUtil.put(mtu, "method", "Android interface MTU plus tunneled payload sweep");
        stages.put(JsonUtil.unsupported("endpoint.pathMtu", "Android apps cannot reliably set IPv4 DF or observe ICMP fragmentation-needed on every device.", mtu));
        standardProgress.onProgress(28, 0, 0, "endpoint transport checked");

        List<String> attributionAddresses = new ArrayList<>(endpointDns.addresses);
        if (camouflageDns != null) attributionAddresses.addAll(camouflageDns.addresses);
        long attributionStarted = System.nanoTime();
        JSONArray attribution = ProbeSuite.attribution(attributionAddresses);
        stages.put(attribution.length() > 0 ? JsonUtil.passed("network.attribution", ProbeSuite.elapsed(attributionStarted), attribution)
                : JsonUtil.skipped("network.attribution", "No IP addresses to attribute."));
        stages.put(geoConsensus("network.geoConsensus", endpointDns.addresses, attribution, "endpoint"));
        stages.put(geoConsensus("camouflage.geoConsensus", camouflageDns == null ? Collections.<String>emptyList() : camouflageDns.addresses, attribution, "camouflage-host"));
        stages.put(ProbeSuite.androidTraceroute(endpointDns.addresses.isEmpty() ? profile.host : endpointDns.addresses.get(0)));
        stages.put(JsonUtil.unsupported("endpoint.tracerouteAttribution", "Android TTL sweep is retained in endpoint.traceroute; per-hop BGP calls are omitted to cap mobile data and runtime.", null));
        standardProgress.onProgress(40, 0, 0, "attribution and path checks completed");
        checkCanceled();

        if (endpointTcpAvailable && !endpointDns.addresses.isEmpty() && profile.sni != null && ("reality".equals(profile.security) || "tls".equals(profile.security))) {
            stages.put(ProbeSuite.tlsFallback(endpointDns.addresses.get(0), profile.port, profile.sni));
            stages.put(ProbeSuite.tlsMatrix(endpointDns.addresses.get(0), profile.port, profile.sni, profile.host));
        } else {
            stages.put(JsonUtil.skipped("endpoint.tlsFallback", "TLS/REALITY SNI or endpoint IP is unavailable."));
            stages.put(JsonUtil.skipped("endpoint.tlsMatrix", "TLS matrix is not applicable."));
        }
        JSONObject encoding = new JSONObject(); JsonUtil.put(encoding, "declared", profile.packetEncoding == null ? "not-declared" : profile.packetEncoding);
        JsonUtil.put(encoding, "xudpDeclared", "xudp".equalsIgnoreCase(profile.packetEncoding));
        JsonUtil.put(encoding, "explicitCompatibilityProbe", true);
        stages.put(JsonUtil.passed("profile.packetEncoding", 0, encoding));
        stages.put(endpointTcpAvailable
                ? ProbeSuite.websocket(profile, endpointDns.addresses.isEmpty() ? profile.host : endpointDns.addresses.get(0))
                : JsonUtil.skipped("endpoint.websocketUpgrade", "Endpoint TCP prerequisite failed."));
        standardProgress.onProgress(48, 0, 0, "TLS and presentation checked");

        JSONArray tunnelExit = new JSONArray();
        JSONArray exitAttribution = new JSONArray();
        JSONObject logs = null;
        boolean usable = false;
        if (!endpointTcpAvailable) {
            addSkippedTunnelPrerequisite(stages, "Endpoint TCP was unreachable; downstream authentication, performance, stability and UDP probes were not attempted.", testType);
        } else try (XrayManager.RunSession session = xray.start(profile)) {
            stages.put(JsonUtil.passed("tunnel.coreValidation", 0, JsonUtil.object("embeddedCore", true, "abi", android.os.Build.SUPPORTED_ABIS[0])));
            stages.put(JsonUtil.passed("tunnel.coreStart", 0, JsonUtil.object("httpPort", session.httpPort, "socksPort", session.socksPort, "loopbackOnly", true)));
            stages.put(JsonUtil.passed("client.captureScope", 0, JsonUtil.object(
                    "mode", "explicit-app-local-proxy", "systemVpnCreated", false,
                    "interpretation", "Only Traffic Lab requests use loopback inbounds; Android default routes and other apps are unchanged.")));
            standardProgress.onProgress(62, 0, 0, "embedded Xray core ready");

            Proxy httpProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", session.httpPort));
            tunnelExit = ProbeSuite.exitIps(httpProxy);
            JSONObject exitData = new JSONObject(); JsonUtil.put(exitData, "direct", directExit); JsonUtil.put(exitData, "throughTunnel", tunnelExit);
            JsonUtil.put(exitData, "differsFromDirect", exitsDiffer(directExit, tunnelExit));
            long exitElapsed = sumElapsed(tunnelExit);
            stages.put(ProbeSuite.anyValidExit(tunnelExit) ? JsonUtil.passed("tunnel.exitIp", exitElapsed, exitData)
                    : JsonUtil.failed("tunnel.exitIp", exitElapsed, "No exit-IP service returned a valid address through the tunnel.", exitData));
            stages.put(addressFamilies(directExit, tunnelExit));
            JSONObject httpStage = ProbeSuite.httpStage(httpProxy); stages.put(httpStage);
            usable = "passed".equals(httpStage.optString("status")) || ProbeSuite.anyValidExit(tunnelExit);
            JSONObject authData = new JSONObject(); JsonUtil.put(authData, "protocol", "vless"); JsonUtil.put(authData, "transport", profile.network);
            JsonUtil.put(authData, "security", profile.security); JsonUtil.put(authData, "interpretation", "A destination response through this isolated core proves the supplied profile completed transport security, VLESS authentication and server outbound as a whole.");
            stages.put(usable ? JsonUtil.passed("tunnel.authenticatedEndToEnd", httpStage.optLong("elapsedMs") + exitElapsed, authData)
                    : JsonUtil.failed("tunnel.authenticatedEndToEnd", httpStage.optLong("elapsedMs") + exitElapsed, "No authenticated destination request completed.", authData));
            standardProgress.onProgress(72, 0, 0, "authenticated HTTP and exit IP checked");
            checkCanceled();

            if (usable) {
                stages.put(ProbeSuite.socksDomain(session.socksPort));
                JSONObject performance = AndroidSpeedTestEngine.measure(httpProxy, AndroidSpeedTestEngine.Mode.NORMAL, this::checkCanceled);
                stages.put(speedStage("tunnel.speed", performance, true));
                stages.put(speedDirectionStage("tunnel.download", performance, "download"));
                stages.put(speedDirectionStage("tunnel.upload", performance, "upload"));
                stages.put(JsonUtil.unsupported("tunnel.httpProtocols", "Android HttpURLConnection does not expose the negotiated HTTP version consistently; TLS ALPN is recorded separately.", null));
                stages.put(payloadMatrix(httpProxy));
                stages.put(JsonUtil.skipped("tunnel.controlledCanary", "No authorized controlled collector URL is configured in the Android UI."));
                stages.put(ProbeSuite.stability(httpProxy, 3));
                standardProgress.onProgress(84, 0, 0, "performance and stability checked");
                stages.put(ProbeSuite.socksUdpDns(session.socksPort));
                stages.put(ProbeSuite.socksStun(session.socksPort));
                stages.put(JsonUtil.unsupported("tunnel.quicHandshake", "The APK does not bundle a separate QUIC engine; real UDP and XUDP are tested independently.", null));
            } else {
                addSkippedTunnelDownstream(stages, "Authenticated end-to-end traffic failed; downstream performance, stability and UDP checks were skipped to avoid repeated timeouts.");
            }
            logs = session.logs();
            standardProgress.onProgress(90, 0, 0, "UDP and Android tunnel checks completed");
        } catch (Exception error) {
            String message = JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage());
            putIfAbsent(stages, JsonUtil.failed("tunnel.coreValidation", 0, message, JsonUtil.object("embeddedBinaryAvailable", xray.binaryAvailable(), "binary", "libxray.so")));
            putIfAbsent(stages, JsonUtil.skipped("tunnel.coreStart", "Embedded Xray did not start."));
            addSkippedTunnelPrerequisite(stages, "Tunnel core unavailable.", testType);
        }
        stages.put(AndroidLogClassifier.stage(logs));
        exitAttribution = ProbeSuite.attribution(ProbeSuite.validExitAddresses(tunnelExit));
        standardProgress.onProgress(92, 0, 0, "tunnel tests completed");
        checkCanceled();

        stages.put(usable ? negativeControls(profile) : JsonUtil.skipped("tunnel.negativeControls", "Authenticated baseline did not succeed; negative authentication controls would not be interpretable."));
        standardProgress.onProgress(96, 0, 0, "negative authentication controls completed");
        stages.put(usable ? xudpControl(profile) : JsonUtil.skipped("tunnel.xudpCompatibility", "Authenticated baseline did not succeed; an XUDP compatibility result would not be attributable."));
        standardProgress.onProgress(98, 0, 0, "XUDP compatibility checked");
        stages.put(infrastructureSignals(endpointDns, camouflageDns, tunnelExit, stages));

        if (testType.extended()) {
            if (usable) {
                extendedStages = AndroidExtendedTestSuite.run(xray, profile, this::checkCanceled,
                        (percent, message) -> listener.onProgress(60 + (int) Math.round(percent * 0.40), 0, 0, message));
            } else {
                extendedStages = skippedExtendedStages("The authenticated standard tunnel stage did not succeed.");
                listener.onProgress(100, 0, 0, "extended suite skipped because the profile was not usable");
            }
        } else {
            stages.put(JsonUtil.skipped("tunnel.extendedSuite", "Normal test selected. Long-running and disruptive checks require Extended test."));
        }

        JSONArray inferences = buildInferences(profile, endpointDns.addresses, tunnelExit, stages);
        JSONObject outcome = AndroidOutcomeClassifier.applyProfile(stages, extendedStages, directControlAvailable);
        return new ProfileResult(profileId, ordinal, profile.name, profile.fingerprint(), profile.declared(),
                endpointDns.addresses, camouflageDns == null ? Collections.<String>emptyList() : camouflageDns.addresses,
                attribution, tunnelExit, exitAttribution, stages, extendedStages, inferences, usable, outcome);
    }

    private static JSONArray skippedExtendedStages(String reason) {
        JSONArray stages = new JSONArray();
        for (String name : new String[]{"tunnel.extended.speedMatrix", "tunnel.extended.coldWarm", "tunnel.extended.parallelTcp", "tunnel.extended.parallelUdp",
                "tunnel.extended.dnsFailureRecovery", "tunnel.extended.soak", "tunnel.extended.reconnect", "tunnel.extended.networkInterruption"}) {
            stages.put(JsonUtil.skipped(name, reason));
        }
        return stages;
    }

    private static void addSkippedTunnelPrerequisite(JSONArray stages, String reason, TestType testType) {
        for (String name : new String[]{"tunnel.coreValidation", "tunnel.coreStart", "client.captureScope", "tunnel.exitIp",
                "tunnel.addressFamilies", "tunnel.http", "tunnel.authenticatedEndToEnd"}) putIfAbsent(stages, JsonUtil.skipped(name, reason));
        addSkippedTunnelDownstream(stages, reason);
    }

    private static void addSkippedTunnelDownstream(JSONArray stages, String reason) {
        for (String name : new String[]{"tunnel.dnsViaSocks", "tunnel.download", "tunnel.upload", "tunnel.httpProtocols",
                "tunnel.payloadMatrix", "tunnel.controlledCanary", "tunnel.stability", "tunnel.udp", "tunnel.stun", "tunnel.quicHandshake"}) {
            putIfAbsent(stages, JsonUtil.skipped(name, reason));
        }
    }

    private static void putIfAbsent(JSONArray stages, JSONObject value) {
        String name = value.optString("stage");
        for (int i = 0; i < stages.length(); i++) { JSONObject stage = stages.optJSONObject(i); if (stage != null && name.equals(stage.optString("stage"))) return; }
        stages.put(value);
    }

    private static long sumElapsed(JSONArray observations) {
        long total = 0; if (observations == null) return total;
        for (int i = 0; i < observations.length(); i++) { JSONObject item = observations.optJSONObject(i); if (item != null) total += Math.max(0, item.optLong("elapsedMs")); }
        return total;
    }

    private JSONObject negativeControls(ConnectionParser.Profile profile) {
        long started = System.nanoTime(); JSONArray observations = new JSONArray(); int rejected = 0;
        List<String> names = applicableNegativeControlNames(profile);
        List<ConnectionParser.Profile> variants = new ArrayList<>();
        for (String name : names) {
            ConnectionParser.Profile variant = profile.copy();
            if ("invalid-uuid".equals(name)) variant.id = UUID.randomUUID().toString();
            else if ("invalid-short-id".equals(name)) variant.shortId = randomHex(Math.max(2, profile.shortId.length()));
            else if ("wrong-sni".equals(name)) variant.sni = "invalid-" + UUID.randomUUID().toString().replace("-", "") + ".invalid";
            else throw new IllegalStateException("Unknown negative-control variant: " + name);
            variants.add(variant);
        }
        for (int i = 0; i < variants.size(); i++) {
            JSONObject item = new JSONObject(); JsonUtil.put(item, "variant", names.get(i)); boolean success = false;
            try (XrayManager.RunSession session = xray.start(variants.get(i))) {
                Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", session.httpPort));
                ProbeSuite.HttpResult response = ProbeSuite.http("https://www.google.com/generate_204", proxy, "GET", null, 1024, 5_000);
                success = response.statusCode == 204;
                JsonUtil.put(item, "statusCode", response.statusCode);
            } catch (Exception error) { JsonUtil.put(item, "errorClass", error.getClass().getSimpleName()); }
            JsonUtil.put(item, "functionalRequestSucceeded", success); if (!success) rejected++; observations.put(item);
            if (canceled.get()) break;
        }
        JSONObject data = new JSONObject(); JsonUtil.put(data, "applicability", negativeControlApplicability(profile));
        JsonUtil.put(data, "observations", observations); JsonUtil.put(data, "expectedRejected", rejected);
        JsonUtil.put(data, "interpretation", "One-shot invalid variants distinguish raw reachability from authenticated success. UUID applies to every VLESS profile; short ID and SNI controls apply only to declared REALITY parameters.");
        return rejected == observations.length() ? JsonUtil.passed("tunnel.negativeControls", ProbeSuite.elapsed(started), data)
                : JsonUtil.partial("tunnel.negativeControls", ProbeSuite.elapsed(started), "At least one invalid control unexpectedly completed.", data);
    }

    static List<String> applicableNegativeControlNames(ConnectionParser.Profile profile) {
        List<String> names = new ArrayList<>();
        names.add("invalid-uuid");
        boolean reality = "reality".equalsIgnoreCase(profile.security);
        if (reality && present(profile.shortId)) names.add("invalid-short-id");
        if (reality && present(profile.sni)) names.add("wrong-sni");
        return names;
    }

    private static JSONArray negativeControlApplicability(ConnectionParser.Profile profile) {
        boolean reality = "reality".equalsIgnoreCase(profile.security);
        JSONArray rows = new JSONArray();
        rows.put(JsonUtil.object("variant", "invalid-uuid", "applicable", true,
                "reason", "The VLESS user identifier is always an authentication input."));
        rows.put(JsonUtil.object("variant", "invalid-short-id", "applicable", reality && present(profile.shortId),
                "reason", !reality ? "Short ID is not used when security is not REALITY."
                        : present(profile.shortId) ? "The declared REALITY short ID is an applicable handshake control."
                        : "The REALITY profile does not declare a short ID, so mutating one would not invalidate a supplied parameter."));
        rows.put(JsonUtil.object("variant", "wrong-sni", "applicable", reality && present(profile.sni),
                "reason", !reality ? "SNI is not a REALITY authentication input when security is not REALITY."
                        : present(profile.sni) ? "The declared REALITY SNI is an applicable handshake control."
                        : "The REALITY profile does not declare SNI, so no SNI control is attributable."));
        return rows;
    }

    private static boolean present(String value) { return value != null && !value.trim().isEmpty(); }

    private JSONObject xudpControl(ConnectionParser.Profile profile) {
        long started = System.nanoTime(); JSONObject data = new JSONObject();
        try (XrayManager.RunSession session = xray.start(profile.withPacketEncoding("xudp"))) {
            JSONObject udp = ProbeSuite.socksUdpDns(session.socksPort);
            boolean passed = "passed".equals(udp.optString("status"));
            JsonUtil.put(data, "clientPacketEncoding", "xudp"); JsonUtil.put(data, "serverCompatible", passed); JsonUtil.put(data, "udpProbe", udp);
            return passed ? JsonUtil.passed("tunnel.xudpCompatibility", ProbeSuite.elapsed(started), data)
                    : JsonUtil.partial("tunnel.xudpCompatibility", ProbeSuite.elapsed(started), "Explicit XUDP client did not complete the UDP probe.", data);
        } catch (Exception error) {
            JsonUtil.put(data, "clientPacketEncoding", "xudp"); JsonUtil.put(data, "serverCompatible", false);
            return JsonUtil.partial("tunnel.xudpCompatibility", ProbeSuite.elapsed(started), JsonUtil.redact(error.getMessage()), data);
        }
    }

    private static JSONObject payloadMatrix(Proxy proxy) {
        long started = System.nanoTime(); JSONArray rows = new JSONArray(); int passed = 0;
        for (int size : new int[]{1024, 16 * 1024, 256 * 1024, 1024 * 1024}) {
            JSONObject row = new JSONObject(); JsonUtil.put(row, "requestedBytes", size);
            try {
                ProbeSuite.HttpResult response = ProbeSuite.http("https://speed.cloudflare.com/__down?bytes=" + size, proxy, "GET", null, size, 15_000);
                boolean ok = response.statusCode == 200 && response.bytesRead == size; if (ok) passed++;
                JsonUtil.put(row, "statusCode", response.statusCode); JsonUtil.put(row, "receivedBytes", response.bytesRead); JsonUtil.put(row, "success", ok);
            } catch (Exception error) { JsonUtil.put(row, "success", false); JsonUtil.put(row, "error", error.getClass().getSimpleName()); }
            rows.put(row);
        }
        return passed > 0 ? JsonUtil.passed("tunnel.payloadMatrix", ProbeSuite.elapsed(started), rows)
                : JsonUtil.failed("tunnel.payloadMatrix", ProbeSuite.elapsed(started), "All payload sizes failed.", rows);
    }

    private static JSONObject addressFamilies(JSONArray direct, JSONArray tunnel) {
        JSONObject data = new JSONObject(); JsonUtil.put(data, "direct", direct); JsonUtil.put(data, "tunnel", tunnel);
        Set<String> directValues = new LinkedHashSet<>(ProbeSuite.validExitAddresses(direct)); Set<String> tunnelValues = new LinkedHashSet<>(ProbeSuite.validExitAddresses(tunnel));
        Set<String> overlap = new LinkedHashSet<>(directValues); overlap.retainAll(tunnelValues); JsonUtil.put(data, "directTunnelOverlap", JsonUtil.array(overlap));
        JsonUtil.put(data, "possibleLeak", !overlap.isEmpty());
        return ProbeSuite.anyValidExit(tunnel) ? JsonUtil.passed("tunnel.addressFamilies", 0, data)
                : JsonUtil.failed("tunnel.addressFamilies", 0, "No tunnel address family produced an exit address.", data);
    }

    private static JSONObject geoConsensus(String stage, List<String> addresses, JSONArray attribution, String subject) {
        JSONArray hints = new JSONArray();
        for (int i = 0; i < attribution.length(); i++) {
            JSONObject item = attribution.optJSONObject(i); if (item == null || !addresses.contains(item.optString("ip"))) continue;
            if (item.has("geolocation")) hints.put(item.optJSONObject("geolocation"));
        }
        JSONObject data = new JSONObject(); JsonUtil.put(data, "subject", subject); JsonUtil.put(data, "hints", hints);
        JsonUtil.put(data, "estimatedRadiusKm", hints.length() > 0 ? 500 : null); JsonUtil.put(data, "confidence", hints.length() > 0 ? "low" : "unknown");
        JsonUtil.put(data, "interpretation", "IP-prefix geolocation is not proof of a rack, datacenter, device position or LTE tower.");
        return hints.length() > 0 ? JsonUtil.passed(stage, 0, data) : JsonUtil.skipped(stage, "No geolocation hints.");
    }

    private static JSONObject infrastructureSignals(ProbeSuite.DnsResult endpoint, ProbeSuite.DnsResult camouflage, JSONArray exits, JSONArray stages) {
        JSONObject data = new JSONObject(); JsonUtil.put(data, "endpointAddressCount", endpoint.addresses.size());
        JsonUtil.put(data, "camouflageAddressCount", camouflage == null ? 0 : camouflage.addresses.size()); JsonUtil.put(data, "exitAddressCount", ProbeSuite.validExitAddresses(exits).size());
        JsonUtil.put(data, "dnsResolverDivergence", resolverDivergence(endpoint) || camouflage != null && resolverDivergence(camouflage));
        JsonUtil.put(data, "loadBalancerLikelihood", endpoint.addresses.size() > 1 ? "medium" : "low-or-not-observed");
        JsonUtil.put(data, "limitation", "Anycast, CDN, SNI routing, NAT and load balancers can produce overlapping external signatures.");
        return JsonUtil.passed("analysis.infrastructureSignals", 0, data);
    }

    private static boolean resolverDivergence(ProbeSuite.DnsResult result) {
        Set<String> values = new LinkedHashSet<>();
        for (int i = 0; i < result.observations.length(); i++) { JSONObject item = result.observations.optJSONObject(i); if (item != null && item.has("answer")) values.add(item.optString("answer")); }
        return values.size() > 1;
    }

    private static JSONArray buildInferences(ConnectionParser.Profile profile, List<String> ingress, JSONArray exits, JSONArray stages) {
        JSONArray values = new JSONArray(); boolean usable = stagePassed(stages, "tunnel.authenticatedEndToEnd");
        values.put(inference("profileUsable", usable ? "yes" : "not-proven", usable ? "high" : "low", usable ? "Authenticated application traffic completed." : "No authenticated application response completed."));
        boolean differ = true; Set<String> exitValues = new LinkedHashSet<>(ProbeSuite.validExitAddresses(exits)); for (String value : ingress) if (exitValues.contains(value)) differ = false;
        values.put(inference("ingressAndEgressDiffer", exitValues.isEmpty() ? "unknown" : differ ? "yes" : "no-or-overlap", "medium", "Different IPs support relay/NAT/load-balancing alternatives but do not prove hop count."));
        values.put(inference("dnsInsideTunnel", stagePassed(stages, "tunnel.dnsViaSocks") ? "functional" : "not-confirmed", stagePassed(stages, "tunnel.dnsViaSocks") ? "high" : "low", "SOCKS unresolved-domain mode avoids local destination lookup; an authoritative controlled domain is needed to identify the exact resolver."));
        values.put(inference("udpEndToEnd", stagePassed(stages, "tunnel.udp") ? "yes" : "not-proven", stagePassed(stages, "tunnel.udp") ? "high" : "low", "A real DNS datagram is used."));
        values.put(inference("xudpEncoding", stagePassed(stages, "tunnel.xudpCompatibility") ? "server-compatible" : "not-proven", stagePassed(stages, "tunnel.xudpCompatibility") ? "high" : "low", "An explicit packetEncoding=xudp variant is tested."));
        values.put(inference("osTunnelScope", "app-explicit-proxy-only", "high", "The Android tester does not create VpnService/TUN routes or change system proxy state."));
        values.put(inference("secondHop", "unknown", "low", "Server routing configuration or correlated server logs are authoritative."));
        values.put(inference("realityTarget", profile.sni == null ? "unknown" : profile.sni, "low", "SNI and fallback certificates are hints; realitySettings.target remains server-private."));
        values.put(inference("hwidPolicy", "unknown", "low", "Panel state is unavailable."));
        values.put(inference("reverseProxyOrLoadBalancer", "external-signals-only", "low", "DNS multiplicity, TLS variation and route evidence cannot uniquely identify private infrastructure."));
        return values;
    }

    private static JSONObject inference(String key, String value, String confidence, String reason) {
        return JsonUtil.object("key", key, "value", value, "confidence", confidence, "reason", reason);
    }

    private static boolean stagePassed(JSONArray stages, String name) {
        for (int i = 0; i < stages.length(); i++) { JSONObject stage = stages.optJSONObject(i); if (stage != null && name.equals(stage.optString("stage")) && "passed".equals(stage.optString("status"))) return true; }
        return false;
    }

    private static boolean exitsDiffer(JSONArray direct, JSONArray tunnel) {
        Set<String> a = new LinkedHashSet<>(ProbeSuite.validExitAddresses(direct)); Set<String> b = new LinkedHashSet<>(ProbeSuite.validExitAddresses(tunnel));
        if (a.isEmpty() || b.isEmpty()) return false; Set<String> overlap = new LinkedHashSet<>(a); overlap.retainAll(b); return overlap.isEmpty();
    }

    private static void enrichNode(JSONObject node, JSONArray directExit, JSONArray attribution, JSONObject stun, JSONObject performance) {
        JsonUtil.put(node, "directPublicIpObservations", directExit); JsonUtil.put(node, "publicIpAttribution", attribution);
        JsonUtil.put(node, "directStun", stun); JsonUtil.put(node, "directPerformance", performance);
        Set<String> local = new LinkedHashSet<>(); JSONObject connectivity = node.optJSONObject("connectivity");
        if (connectivity != null && connectivity.optJSONObject("link") != null) {
            JSONArray addresses = connectivity.optJSONObject("link").optJSONArray("addresses");
            if (addresses != null) for (int i = 0; i < addresses.length(); i++) local.add(addresses.optString(i).split("/")[0]);
        }
        List<String> publicAddresses = ProbeSuite.validExitAddresses(directExit);
        JSONObject nat = new JSONObject(); boolean privateLocal = false;
        for (String address : local) try { InetAddress ip = InetAddress.getByName(address); if (ip.isSiteLocalAddress() || address.startsWith("100.")) privateLocal = true; } catch (Exception ignored) {}
        JsonUtil.put(nat, "presence", privateLocal && !publicAddresses.isEmpty() ? "observed" : "unknown");
        JsonUtil.put(nat, "confidence", privateLocal && !publicAddresses.isEmpty() ? "high" : "low");
        JsonUtil.put(nat, "localAddresses", JsonUtil.array(local)); JsonUtil.put(nat, "publicAddresses", JsonUtil.array(publicAddresses));
        JsonUtil.put(nat, "reason", "Android link addresses are compared with independent exit-IP and STUN observations."); JsonUtil.put(node, "nat", nat);
        JsonUtil.put(node, "deviceVsIpGeolocation", compareDeviceAndIpLocation(node.optJSONObject("deviceLocation"), attribution));
    }

    private static JSONObject compareDeviceAndIpLocation(JSONObject device, JSONArray attribution) {
        if (device == null || !device.has("latitude") || !device.has("longitude"))
            return JsonUtil.object("status", "inconclusive", "reason", "No Android device location fix was available.");
        JSONObject ipGeo = null;
        for (int i = 0; i < attribution.length(); i++) {
            JSONObject item = attribution.optJSONObject(i); if (item != null && item.optJSONObject("geolocation") != null) { ipGeo = item.optJSONObject("geolocation"); break; }
        }
        if (ipGeo == null || !ipGeo.has("latitude") || !ipGeo.has("longitude"))
            return JsonUtil.object("status", "inconclusive", "reason", "No IP-prefix geolocation was available for comparison.");
        double distance = haversineKm(device.optDouble("latitude"), device.optDouble("longitude"), ipGeo.optDouble("latitude"), ipGeo.optDouble("longitude"));
        String status = distance <= 100 ? "consistent" : distance <= 500 ? "coarsely-consistent" : "divergent";
        String interpretation = distance <= 100 ? "Device and public-prefix hints are compatible at city/region scale."
                : distance <= 500 ? "The hints agree only at broad regional scale; IP geolocation is coarse."
                : "The public-IP hint is far from the device. Remote egress, mobile-core breakout, another proxy/VPN, or inaccurate IP geolocation are plausible.";
        return JsonUtil.object("status", status, "distanceKm", Math.round(distance * 10.0) / 10.0,
                "deviceAccuracyMeters", device.opt("accuracyMeters"), "ipEstimatedRadiusKm", 500,
                "ipGeolocationSource", ipGeo.optString("source", "unknown"), "interpretation", interpretation);
    }

    private static double haversineKm(double lat1, double lon1, double lat2, double lon2) {
        double dLat = Math.toRadians(lat2 - lat1), dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return 6371.0088 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    }

    private static Integer findActiveMtu(JSONObject node) {
        JSONObject connectivity = node.optJSONObject("connectivity"); if (connectivity == null) return null;
        JSONObject link = connectivity.optJSONObject("link"); return link == null || !link.has("mtu") ? null : link.optInt("mtu");
    }

    private static String randomHex(int length) {
        byte[] bytes = new byte[(length + 1) / 2]; new SecureRandom().nextBytes(bytes); StringBuilder value = new StringBuilder();
        for (byte b : bytes) value.append(String.format(Locale.ROOT, "%02x", b)); return value.substring(0, length);
    }

    private void checkCanceled() throws InterruptedException { if (canceled.get()) throw new InterruptedException("Testing canceled by user"); }
    private void report(int percent, int completed, int total, String message) { if (progress != null) progress.onProgress(percent, completed, total, message); }

    static final class ProfileResult {
        final String profileId; final int ordinal; final String name; final String fingerprint; final JSONObject declared;
        final List<String> endpointIps; final List<String> camouflageIps; final JSONArray attribution; final JSONArray tunnelExit;
        final JSONArray exitAttribution; final JSONArray stages; final JSONArray extendedStages; final JSONArray inferences; final boolean usable; final JSONObject outcome;

        ProfileResult(String profileId, int ordinal, String name, String fingerprint, JSONObject declared, List<String> endpointIps,
                      List<String> camouflageIps, JSONArray attribution, JSONArray tunnelExit, JSONArray exitAttribution,
                      JSONArray stages, JSONArray extendedStages, JSONArray inferences, boolean usable, JSONObject outcome) {
            this.profileId = profileId; this.ordinal = ordinal; this.name = name; this.fingerprint = fingerprint; this.declared = declared;
            this.endpointIps = endpointIps; this.camouflageIps = camouflageIps; this.attribution = attribution; this.tunnelExit = tunnelExit;
            this.exitAttribution = exitAttribution; this.stages = stages; this.extendedStages = extendedStages; this.inferences = inferences; this.usable = usable; this.outcome = outcome;
        }

        static ProfileResult invalid(String id, int ordinal, JSONArray stages, TestType testType, boolean directControlAvailable) {
            JSONArray extended = testType != null && testType.extended()
                    ? skippedExtendedStages("The connection URI could not be parsed.") : new JSONArray();
            JSONObject outcome = AndroidOutcomeClassifier.applyProfile(stages, extended, directControlAvailable);
            return new ProfileResult(id, ordinal, "Invalid profile " + ordinal, "unavailable", new JSONObject(), Collections.<String>emptyList(), Collections.<String>emptyList(), new JSONArray(), new JSONArray(), new JSONArray(), stages, extended, new JSONArray().put(inference("profileUsable", "unknown", "low", "URI parsing failed.")), false, outcome);
        }
    }

    static final class RunResult {
        final File zip; final int profileCount; final long durationMs; final boolean usable; final String startedAt; final String completedAt; final TestType testType; final JSONObject outcome; final String speedResult;
        RunResult(File zip, int profileCount, long durationMs, boolean usable, String startedAt, String completedAt, TestType testType, JSONObject outcome) {
            this(zip, profileCount, durationMs, usable, startedAt, completedAt, testType, outcome, null);
        }
        RunResult(File zip, int profileCount, long durationMs, boolean usable, String startedAt, String completedAt, TestType testType, JSONObject outcome, String speedResult) {
            this.zip = zip; this.profileCount = profileCount; this.durationMs = durationMs; this.usable = usable; this.startedAt = startedAt; this.completedAt = completedAt; this.testType = testType; this.outcome = outcome;
            this.speedResult = speedResult;
        }
    }
}
