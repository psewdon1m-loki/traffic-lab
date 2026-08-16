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
import java.util.Arrays;
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

    RunResult run(List<String> connections) throws Exception {
        if (connections == null || connections.isEmpty()) throw new IllegalArgumentException("No VLESS connections were supplied");
        long startedNanos = System.nanoTime();
        String startedAt = JsonUtil.now();
        String runId = startedAt.replaceAll("[-:.TZ]", "").substring(0, 14) + "-" + UUID.randomUUID().toString().substring(0, 8);
        report(2, 0, connections.size(), "Loaded " + connections.size() + " connection(s)");
        checkCanceled();

        report(5, 0, connections.size(), "Capturing Android network baseline");
        JSONObject node = AndroidNetworkDiagnostics.capture(context);
        JSONArray directExit = ProbeSuite.exitIps(null);
        List<String> directAddresses = ProbeSuite.validExitAddresses(directExit);
        JSONArray directAttribution = ProbeSuite.attribution(directAddresses);
        JSONObject directStun = ProbeSuite.directStun();
        JSONObject directPerformance = ProbeSuite.directPerformance(null);
        enrichNode(node, directExit, directAttribution, directStun, directPerformance);
        report(15, 0, connections.size(), "Direct network baseline captured");

        List<ProfileResult> profiles = new ArrayList<>();
        for (int index = 0; index < connections.size(); index++) {
            checkCanceled();
            int start = 15 + (int) Math.floor(index * 78.0 / connections.size());
            int end = 15 + (int) Math.floor((index + 1) * 78.0 / connections.size());
            int current = index;
            ProgressListener profileProgress = (percent, ignored, ignoredTotal, message) ->
                    report(start + (int) Math.round((end - start) * Math.max(0, Math.min(100, percent)) / 100.0), current, connections.size(), "profile-" + String.format(Locale.ROOT, "%02d", current + 1) + ": " + message);
            ProfileResult profile = runProfile(connections.get(index), index + 1, directExit, profileProgress);
            profiles.add(profile);
            report(end, index + 1, connections.size(), "profile-" + String.format(Locale.ROOT, "%02d", index + 1) + ": completed");
        }

        checkCanceled();
        report(95, connections.size(), connections.size(), "Building structured Android reports");
        String completedAt = JsonUtil.now();
        long durationMs = ProbeSuite.elapsed(startedNanos);
        ResultPackager.PackageInput input = new ResultPackager.PackageInput(runId, startedAt, completedAt, durationMs,
                xray.version(), node, directExit, directAttribution, profiles);
        report(97, connections.size(), connections.size(), "Creating temporary result ZIP");
        File zip = ResultPackager.create(context, input);
        boolean usable = false;
        for (ProfileResult profile : profiles) if (profile.usable) { usable = true; break; }
        report(100, connections.size(), connections.size(), usable ? "Testing completed successfully" : "Testing completed with no usable profile");
        return new RunResult(zip, profiles.size(), durationMs, usable, startedAt, completedAt);
    }

    private ProfileResult runProfile(String raw, int ordinal, JSONArray directExit, ProgressListener listener) throws Exception {
        String profileId = "profile-" + String.format(Locale.ROOT, "%02d", ordinal);
        JSONArray stages = new JSONArray();
        ConnectionParser.Profile profile;
        try {
            profile = ConnectionParser.parse(raw);
        } catch (Exception error) {
            stages.put(JsonUtil.failed("profile.parse", 0, JsonUtil.redact(error.getMessage()), null));
            return ProfileResult.invalid(profileId, ordinal, stages);
        }
        stages.put(JsonUtil.passed("profile.parse", 0, profile.declared()));
        listener.onProgress(5, 0, 0, "profile parsed");

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
        listener.onProgress(18, 0, 0, "DNS checks completed");
        checkCanceled();

        stages.put(ProbeSuite.tcp(endpointDns.addresses, profile.port, 3));
        JSONObject mtu = new JSONObject();
        JsonUtil.put(mtu, "interfaceMtu", findActiveMtu(AndroidNetworkDiagnostics.capture(context)));
        JsonUtil.put(mtu, "method", "Android interface MTU plus tunneled payload sweep");
        stages.put(JsonUtil.partial("endpoint.pathMtu", 0, "Android apps cannot reliably set IPv4 DF or observe ICMP fragmentation-needed on every device.", mtu));
        listener.onProgress(28, 0, 0, "endpoint transport checked");

        List<String> attributionAddresses = new ArrayList<>(endpointDns.addresses);
        if (camouflageDns != null) attributionAddresses.addAll(camouflageDns.addresses);
        JSONArray attribution = ProbeSuite.attribution(attributionAddresses);
        stages.put(attribution.length() > 0 ? JsonUtil.passed("network.attribution", 0, attribution)
                : JsonUtil.skipped("network.attribution", "No IP addresses to attribute."));
        stages.put(geoConsensus("network.geoConsensus", endpointDns.addresses, attribution, "endpoint"));
        stages.put(geoConsensus("camouflage.geoConsensus", camouflageDns == null ? Collections.<String>emptyList() : camouflageDns.addresses, attribution, "camouflage-host"));
        stages.put(ProbeSuite.androidTraceroute(endpointDns.addresses.isEmpty() ? profile.host : endpointDns.addresses.get(0)));
        stages.put(JsonUtil.partial("endpoint.tracerouteAttribution", 0, "Android TTL sweep is retained in endpoint.traceroute; per-hop BGP calls are omitted to cap mobile data and runtime.", null));
        listener.onProgress(40, 0, 0, "attribution and path checks completed");
        checkCanceled();

        if (!endpointDns.addresses.isEmpty() && profile.sni != null && ("reality".equals(profile.security) || "tls".equals(profile.security))) {
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
        stages.put(ProbeSuite.websocket(profile, endpointDns.addresses.isEmpty() ? profile.host : endpointDns.addresses.get(0)));
        listener.onProgress(48, 0, 0, "TLS and presentation checked");

        JSONArray tunnelExit = new JSONArray();
        JSONArray exitAttribution = new JSONArray();
        JSONObject logs = null;
        boolean usable = false;
        try (XrayManager.RunSession session = xray.start(profile)) {
            stages.put(JsonUtil.passed("tunnel.coreValidation", 0, JsonUtil.object("embeddedCore", true, "abi", android.os.Build.SUPPORTED_ABIS[0])));
            stages.put(JsonUtil.passed("tunnel.coreStart", 0, JsonUtil.object("httpPort", session.httpPort, "socksPort", session.socksPort, "loopbackOnly", true)));
            stages.put(JsonUtil.passed("client.captureScope", 0, JsonUtil.object(
                    "mode", "explicit-app-local-proxy", "systemVpnCreated", false,
                    "interpretation", "Only Traffic Lab requests use loopback inbounds; Android default routes and other apps are unchanged.")));
            listener.onProgress(62, 0, 0, "embedded Xray core ready");

            Proxy httpProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", session.httpPort));
            tunnelExit = ProbeSuite.exitIps(httpProxy);
            JSONObject exitData = new JSONObject(); JsonUtil.put(exitData, "direct", directExit); JsonUtil.put(exitData, "throughTunnel", tunnelExit);
            JsonUtil.put(exitData, "differsFromDirect", exitsDiffer(directExit, tunnelExit));
            stages.put(ProbeSuite.anyValidExit(tunnelExit) ? JsonUtil.passed("tunnel.exitIp", 0, exitData)
                    : JsonUtil.failed("tunnel.exitIp", 0, "No exit-IP service returned a valid address through the tunnel.", exitData));
            stages.put(addressFamilies(directExit, tunnelExit));
            JSONObject httpStage = ProbeSuite.httpStage(httpProxy); stages.put(httpStage);
            usable = "passed".equals(httpStage.optString("status"));
            JSONObject authData = new JSONObject(); JsonUtil.put(authData, "protocol", "vless"); JsonUtil.put(authData, "transport", profile.network);
            JsonUtil.put(authData, "security", profile.security); JsonUtil.put(authData, "interpretation", "A destination response through this isolated core proves the supplied profile completed transport security, VLESS authentication and server outbound as a whole.");
            stages.put(usable ? JsonUtil.passed("tunnel.authenticatedEndToEnd", 0, authData)
                    : JsonUtil.failed("tunnel.authenticatedEndToEnd", 0, "No authenticated destination request completed.", authData));
            listener.onProgress(72, 0, 0, "authenticated HTTP and exit IP checked");
            checkCanceled();

            stages.put(ProbeSuite.socksDomain(session.socksPort));
            JSONObject performance = ProbeSuite.directPerformance(httpProxy);
            stages.put(performance.has("downloadBytes") ? JsonUtil.passed("tunnel.download", performance.optLong("downloadElapsedMs"), performance)
                    : JsonUtil.failed("tunnel.download", 0, "Bounded tunneled download failed.", performance));
            stages.put(performance.has("uploadBytes") ? JsonUtil.passed("tunnel.upload", performance.optLong("uploadElapsedMs"), performance)
                    : JsonUtil.failed("tunnel.upload", 0, "Bounded tunneled upload failed.", performance));
            stages.put(JsonUtil.partial("tunnel.httpProtocols", 0, "Android HttpURLConnection does not expose the negotiated HTTP version consistently; TLS ALPN is recorded separately.", null));
            stages.put(payloadMatrix(httpProxy));
            stages.put(JsonUtil.skipped("tunnel.controlledCanary", "No authorized controlled collector URL is configured in the Android UI."));
            stages.put(ProbeSuite.stability(httpProxy, 3));
            listener.onProgress(84, 0, 0, "performance and stability checked");
            stages.put(ProbeSuite.socksUdpDns(session.socksPort));
            stages.put(ProbeSuite.socksStun(session.socksPort));
            stages.put(JsonUtil.skipped("tunnel.quicHandshake", "The APK does not bundle a separate QUIC engine; real UDP and XUDP are tested independently."));
            logs = session.logs();
            listener.onProgress(90, 0, 0, "UDP and Android tunnel checks completed");
        } catch (Exception error) {
            String message = JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage());
            stages.put(JsonUtil.failed("tunnel.coreValidation", 0, message, JsonUtil.object("embeddedBinaryAvailable", xray.binaryAvailable(), "binary", "libxray.so")));
            stages.put(JsonUtil.skipped("tunnel.coreStart", "Embedded Xray did not start."));
            stages.put(JsonUtil.skipped("tunnel.http", "Tunnel core unavailable."));
            stages.put(JsonUtil.skipped("tunnel.authenticatedEndToEnd", "Tunnel core unavailable."));
        }
        stages.put(logs == null ? JsonUtil.skipped("tunnel.logs", "No running core logs were available.") : JsonUtil.passed("tunnel.logs", 0, logs));
        exitAttribution = ProbeSuite.attribution(ProbeSuite.validExitAddresses(tunnelExit));
        listener.onProgress(92, 0, 0, "tunnel tests completed");
        checkCanceled();

        stages.put(negativeControls(profile));
        listener.onProgress(96, 0, 0, "negative authentication controls completed");
        stages.put(xudpControl(profile));
        listener.onProgress(98, 0, 0, "XUDP compatibility checked");
        stages.put(infrastructureSignals(endpointDns, camouflageDns, tunnelExit, stages));

        JSONArray inferences = buildInferences(profile, endpointDns.addresses, tunnelExit, stages);
        return new ProfileResult(profileId, ordinal, profile.name, profile.fingerprint(), profile.declared(),
                endpointDns.addresses, camouflageDns == null ? Collections.<String>emptyList() : camouflageDns.addresses,
                attribution, tunnelExit, exitAttribution, stages, inferences, usable);
    }

    private JSONObject negativeControls(ConnectionParser.Profile profile) {
        long started = System.nanoTime(); JSONArray observations = new JSONArray(); int rejected = 0;
        List<ConnectionParser.Profile> variants = new ArrayList<>(); List<String> names = Arrays.asList("invalid-uuid", "invalid-short-id", "wrong-sni");
        ConnectionParser.Profile invalidUuid = profile.copy(); invalidUuid.id = UUID.randomUUID().toString(); variants.add(invalidUuid);
        ConnectionParser.Profile invalidSid = profile.copy(); invalidSid.shortId = randomHex(Math.max(2, profile.shortId == null ? 16 : profile.shortId.length())); variants.add(invalidSid);
        ConnectionParser.Profile invalidSni = profile.copy(); invalidSni.sni = "invalid-" + UUID.randomUUID().toString().replace("-", "") + ".invalid"; variants.add(invalidSni);
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
        JSONObject data = new JSONObject(); JsonUtil.put(data, "observations", observations); JsonUtil.put(data, "expectedRejected", rejected);
        JsonUtil.put(data, "interpretation", "One-shot invalid variants distinguish raw reachability from authenticated success; this is not credential discovery.");
        return rejected == observations.length() ? JsonUtil.passed("tunnel.negativeControls", ProbeSuite.elapsed(started), data)
                : JsonUtil.partial("tunnel.negativeControls", ProbeSuite.elapsed(started), "At least one invalid control unexpectedly completed.", data);
    }

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
        final JSONArray exitAttribution; final JSONArray stages; final JSONArray inferences; final boolean usable;

        ProfileResult(String profileId, int ordinal, String name, String fingerprint, JSONObject declared, List<String> endpointIps,
                      List<String> camouflageIps, JSONArray attribution, JSONArray tunnelExit, JSONArray exitAttribution,
                      JSONArray stages, JSONArray inferences, boolean usable) {
            this.profileId = profileId; this.ordinal = ordinal; this.name = name; this.fingerprint = fingerprint; this.declared = declared;
            this.endpointIps = endpointIps; this.camouflageIps = camouflageIps; this.attribution = attribution; this.tunnelExit = tunnelExit;
            this.exitAttribution = exitAttribution; this.stages = stages; this.inferences = inferences; this.usable = usable;
        }

        static ProfileResult invalid(String id, int ordinal, JSONArray stages) {
            return new ProfileResult(id, ordinal, "Invalid profile " + ordinal, "unavailable", new JSONObject(), Collections.<String>emptyList(), Collections.<String>emptyList(), new JSONArray(), new JSONArray(), new JSONArray(), stages, new JSONArray().put(inference("profileUsable", "unknown", "low", "URI parsing failed.")), false);
        }
    }

    static final class RunResult {
        final File zip; final int profileCount; final long durationMs; final boolean usable; final String startedAt; final String completedAt;
        RunResult(File zip, int profileCount, long durationMs, boolean usable, String startedAt, String completedAt) {
            this.zip = zip; this.profileCount = profileCount; this.durationMs = durationMs; this.usable = usable; this.startedAt = startedAt; this.completedAt = completedAt;
        }
    }
}
