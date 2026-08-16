package com.loki.trafficlab;

import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

final class ProbeSuite {
    static final int TIMEOUT_MS = 6_000;
    private static final Pattern IP_PATTERN = Pattern.compile("(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![0-9])|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])");
    private static final SecureRandom RANDOM = new SecureRandom();

    private ProbeSuite() {}

    static DnsResult dns(String host) {
        long started = System.nanoTime();
        JSONArray observations = new JSONArray();
        Set<String> addresses = new LinkedHashSet<>();
        try {
            for (InetAddress address : InetAddress.getAllByName(host)) {
                addresses.add(address.getHostAddress());
                observations.put(dnsObservation("android-system", address instanceof Inet4Address ? "A" : "AAAA", address.getHostAddress(), "success", null));
            }
        } catch (Exception error) {
            observations.put(dnsObservation("android-system", "A/AAAA", null, "failed", error.getClass().getSimpleName()));
        }
        if (!isIpLiteral(host)) {
            doh(host, "A", "https://dns.google/resolve?name=%s&type=A", "google-doh", observations, addresses);
            doh(host, "AAAA", "https://cloudflare-dns.com/dns-query?name=%s&type=AAAA", "cloudflare-doh", observations, addresses);
            udpDns(host, InetAddressLoop.PUBLIC_DNS_1, observations, addresses);
            udpDns(host, InetAddressLoop.PUBLIC_DNS_2, observations, addresses);
        }
        JSONObject data = new JSONObject();
        JsonUtil.put(data, "host", host);
        JsonUtil.put(data, "observations", observations);
        JsonUtil.put(data, "uniqueAddresses", JsonUtil.array(addresses));
        boolean passed = !addresses.isEmpty();
        JSONObject stage = passed ? JsonUtil.passed("endpoint.dns", elapsed(started), data)
                : JsonUtil.failed("endpoint.dns", elapsed(started), "No A/AAAA answer was observed.", data);
        return new DnsResult(stage, new ArrayList<>(addresses), observations);
    }

    static JSONObject dnsConsistency(String name, DnsResult result) {
        Set<String> sets = new LinkedHashSet<>();
        for (int i = 0; i < result.observations.length(); i++) {
            JSONObject item = result.observations.optJSONObject(i);
            if (item != null && "success".equals(item.optString("status"))) sets.add(item.optString("answer"));
        }
        JSONObject data = new JSONObject();
        JsonUtil.put(data, "resolverAnswerDivergenceObserved", sets.size() > 1);
        JsonUtil.put(data, "answerSet", JsonUtil.array(sets));
        JsonUtil.put(data, "interpretation", "Different resolver answers can indicate GeoDNS, split DNS, rotation or filtering; they do not alone prove operator manipulation.");
        return JsonUtil.passed(name, 0, data);
    }

    private static void doh(String host, String type, String template, String source, JSONArray observations, Set<String> addresses) {
        try {
            String url = String.format(Locale.ROOT, template, URLEncoder.encode(host, StandardCharsets.UTF_8.name()));
            HttpResult response = http(url, null, "GET", null, 256 * 1024, TIMEOUT_MS);
            JSONObject root = new JSONObject(response.body);
            JSONArray answers = root.optJSONArray("Answer");
            if (answers == null) throw new IllegalStateException("No Answer array, status=" + root.optInt("Status", -1));
            boolean found = false;
            for (int i = 0; i < answers.length(); i++) {
                JSONObject answer = answers.optJSONObject(i);
                if (answer == null) continue;
                String value = answer.optString("data", "");
                if (isIpLiteral(value)) {
                    found = true;
                    addresses.add(value);
                    observations.put(dnsObservation(source, type, value, "success", null));
                }
            }
            if (!found) observations.put(dnsObservation(source, type, null, "empty", null));
        } catch (Exception error) {
            observations.put(dnsObservation(source, type, null, "failed", error.getClass().getSimpleName()));
        }
    }

    private static void udpDns(String host, String resolver, JSONArray observations, Set<String> addresses) {
        long started = System.nanoTime();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(TIMEOUT_MS);
            int id = RANDOM.nextInt(65536);
            byte[] request = buildDnsQuery(host, id, 1);
            DatagramPacket packet = new DatagramPacket(request, request.length, InetAddress.getByName(resolver), 53);
            socket.send(packet);
            byte[] response = new byte[2048];
            DatagramPacket incoming = new DatagramPacket(response, response.length);
            socket.receive(incoming);
            for (String address : parseDnsAddresses(Arrays.copyOf(response, incoming.getLength()), id)) {
                addresses.add(address);
                observations.put(dnsObservation("udp-" + resolver, address.contains(":") ? "AAAA" : "A", address, "success", null));
            }
        } catch (Exception error) {
            observations.put(dnsObservation("udp-" + resolver, "A", null, "failed", error.getClass().getSimpleName() + " after " + elapsed(started) + "ms"));
        }
    }

    static JSONObject tcp(List<String> addresses, int port, int attempts) {
        long started = System.nanoTime();
        JSONArray observations = new JSONArray();
        boolean connected = false;
        for (String address : addresses) {
            for (int attempt = 1; attempt <= attempts; attempt++) {
                long itemStarted = System.nanoTime();
                JSONObject item = new JSONObject();
                JsonUtil.put(item, "ip", address); JsonUtil.put(item, "port", port); JsonUtil.put(item, "attempt", attempt);
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(address, port), TIMEOUT_MS);
                    connected = true;
                    JsonUtil.put(item, "connected", true); JsonUtil.put(item, "outcome", "connected");
                } catch (Exception error) {
                    JsonUtil.put(item, "connected", false); JsonUtil.put(item, "outcome", error.getClass().getSimpleName());
                }
                JsonUtil.put(item, "elapsedMs", elapsed(itemStarted));
                observations.put(item);
            }
        }
        return connected ? JsonUtil.passed("endpoint.tcp", elapsed(started), observations)
                : JsonUtil.failed("endpoint.tcp", elapsed(started), addresses.isEmpty() ? "No endpoint address." : "No TCP connection succeeded.", observations);
    }

    static JSONObject tlsFallback(String address, int port, String sni) {
        long started = System.nanoTime();
        try {
            JSONObject value = tlsObservation(address, port, sni);
            return JsonUtil.passed("endpoint.tlsFallback", elapsed(started), value);
        } catch (Exception error) {
            return JsonUtil.failed("endpoint.tlsFallback", elapsed(started), JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()), null);
        }
    }

    static JSONObject tlsMatrix(String address, int port, String sni, String endpointHost) {
        long started = System.nanoTime();
        JSONArray observations = new JSONArray();
        for (String candidate : new String[]{sni, endpointHost, "invalid-control.example.invalid"}) {
            if (candidate == null || candidate.trim().isEmpty() || observations.toString().contains("\"sni\":\"" + candidate + "\"")) continue;
            try { observations.put(tlsObservation(address, port, candidate)); }
            catch (Exception error) {
                JSONObject item = new JSONObject(); JsonUtil.put(item, "sni", candidate); JsonUtil.put(item, "status", "failed");
                JsonUtil.put(item, "error", JsonUtil.redact(error.getClass().getSimpleName())); observations.put(item);
            }
        }
        JSONObject data = new JSONObject();
        JsonUtil.put(data, "observations", observations);
        JsonUtil.put(data, "interpretation", "Certificate/SPKI changes across SNI values are external routing signals, not proof of the hidden REALITY target or load-balancer configuration.");
        return observations.length() > 0 ? JsonUtil.passed("endpoint.tlsMatrix", elapsed(started), data)
                : JsonUtil.failed("endpoint.tlsMatrix", elapsed(started), "No TLS matrix observation.", data);
    }

    private static JSONObject tlsObservation(String address, int port, String sni) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());
        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(address, port), TIMEOUT_MS);
            raw.setSoTimeout(TIMEOUT_MS);
            try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(raw, sni, port, true)) {
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setServerNames(Collections.singletonList(new SNIHostName(sni)));
                parameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                if (Build.VERSION.SDK_INT >= 29) parameters.setApplicationProtocols(new String[]{"h2", "http/1.1"});
                socket.setSSLParameters(parameters);
                socket.startHandshake();
                SSLSession session = socket.getSession();
                X509Certificate certificate = (X509Certificate) session.getPeerCertificates()[0];
                JSONObject cert = new JSONObject();
                JsonUtil.put(cert, "subject", certificate.getSubjectX500Principal().getName());
                JsonUtil.put(cert, "issuer", certificate.getIssuerX500Principal().getName());
                JsonUtil.put(cert, "serialSha256", sha256(certificate.getSerialNumber().toString(16).getBytes(StandardCharsets.UTF_8)));
                JsonUtil.put(cert, "spkiSha256", sha256(certificate.getPublicKey().getEncoded()));
                JsonUtil.put(cert, "notBefore", certificate.getNotBefore().toInstant().toString());
                JsonUtil.put(cert, "notAfter", certificate.getNotAfter().toInstant().toString());
                JSONObject value = new JSONObject();
                JsonUtil.put(value, "endpointIp", address); JsonUtil.put(value, "port", port); JsonUtil.put(value, "sni", sni);
                JsonUtil.put(value, "protocol", session.getProtocol()); JsonUtil.put(value, "cipherSuite", session.getCipherSuite());
                if (Build.VERSION.SDK_INT >= 29) JsonUtil.put(value, "alpn", socket.getApplicationProtocol());
                JsonUtil.put(value, "certificate", cert);
                JsonUtil.put(value, "interpretation", "Ordinary TLS certificate behavior is a fallback/fronting hint; it does not prove VLESS authentication.");
                return value;
            }
        }
    }

    static JSONObject websocket(ConnectionParser.Profile profile, String address) {
        if (!"ws".equals(profile.network)) return JsonUtil.skipped("endpoint.websocketUpgrade", "Profile transport is not WebSocket.");
        long started = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, profile.port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            String path = profile.path == null || profile.path.trim().isEmpty() ? "/" : profile.path;
            String host = profile.hostHeader == null || profile.hostHeader.trim().isEmpty() ? profile.host : profile.hostHeader;
            String request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: SGVsbG9Xb3JsZDEyMzQ1Ng==\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            byte[] buffer = new byte[1024];
            int count = socket.getInputStream().read(buffer);
            String response = count <= 0 ? "" : new String(buffer, 0, count, StandardCharsets.ISO_8859_1);
            String[] responseLines = response.split("\\r?\\n", 2);
            String status = responseLines.length == 0 ? "" : responseLines[0];
            JSONObject data = new JSONObject(); JsonUtil.put(data, "statusLine", status); JsonUtil.put(data, "path", path); JsonUtil.put(data, "hostHeader", host);
            return status.contains(" 101 ") ? JsonUtil.passed("endpoint.websocketUpgrade", elapsed(started), data)
                    : JsonUtil.partial("endpoint.websocketUpgrade", elapsed(started), "The server did not return HTTP 101 without a VLESS payload.", data);
        } catch (Exception error) {
            return JsonUtil.failed("endpoint.websocketUpgrade", elapsed(started), JsonUtil.redact(error.getMessage()), null);
        }
    }

    static JSONArray exitIps(Proxy proxy) {
        JSONArray result = new JSONArray();
        String[] services = {"https://api.ipify.org", "https://checkip.amazonaws.com", "https://ifconfig.me/ip"};
        for (String service : services) {
            long started = System.nanoTime();
            JSONObject item = new JSONObject(); JsonUtil.put(item, "service", service);
            try {
                HttpResult response = http(service, proxy, "GET", null, 1024, TIMEOUT_MS + 4_000);
                String candidate = firstIp(response.body);
                JsonUtil.put(item, "statusCode", response.statusCode); JsonUtil.put(item, "elapsedMs", elapsed(started));
                JsonUtil.put(item, "ip", candidate); JsonUtil.put(item, "valid", candidate != null);
            } catch (Exception error) {
                JsonUtil.put(item, "elapsedMs", elapsed(started)); JsonUtil.put(item, "valid", false);
                JsonUtil.put(item, "error", JsonUtil.redact(error.getClass().getSimpleName()));
            }
            result.put(item);
        }
        return result;
    }

    static JSONArray attribution(List<String> addresses) {
        JSONArray result = new JSONArray();
        for (String ip : new LinkedHashSet<>(addresses)) {
            JSONObject item = new JSONObject(); JsonUtil.put(item, "ip", ip);
            try {
                HttpResult ripe = http("https://stat.ripe.net/data/prefix-overview/data.json?resource=" + URLEncoder.encode(ip, StandardCharsets.UTF_8.name()), null, "GET", null, 512 * 1024, TIMEOUT_MS);
                JSONObject data = new JSONObject(ripe.body).optJSONObject("data");
                if (data != null) {
                    JsonUtil.put(item, "prefix", data.optString("prefix", null));
                    JsonUtil.put(item, "originAsns", data.optJSONArray("asns"));
                    JsonUtil.put(item, "asnHolder", data.optString("holder", null));
                    JsonUtil.put(item, "bgpSource", "RIPEstat prefix-overview");
                }
            } catch (Exception error) { JsonUtil.put(item, "bgpError", error.getClass().getSimpleName()); }
            try {
                HttpResult geo = http("https://ipwho.is/" + URLEncoder.encode(ip, StandardCharsets.UTF_8.name()), null, "GET", null, 256 * 1024, TIMEOUT_MS);
                JSONObject data = new JSONObject(geo.body);
                JSONObject location = new JSONObject();
                JsonUtil.put(location, "country", data.optString("country", null));
                JsonUtil.put(location, "countryCode", data.optString("country_code", null));
                JsonUtil.put(location, "region", data.optString("region", null));
                JsonUtil.put(location, "city", data.optString("city", null));
                JsonUtil.put(location, "latitude", data.has("latitude") ? data.optDouble("latitude") : null);
                JsonUtil.put(location, "longitude", data.has("longitude") ? data.optDouble("longitude") : null);
                JsonUtil.put(location, "source", "ipwho.is");
                JsonUtil.put(location, "confidence", "low/IP-prefix hint");
                JsonUtil.put(item, "geolocation", location);
            } catch (Exception error) { JsonUtil.put(item, "geoError", error.getClass().getSimpleName()); }
            try {
                String reverse = InetAddress.getByName(ip).getCanonicalHostName();
                if (!reverse.equals(ip)) JsonUtil.put(item, "reverseDns", reverse);
            } catch (Exception ignored) {}
            JsonUtil.put(item, "status", item.has("prefix") || item.has("geolocation") ? "success" : "partial");
            result.put(item);
        }
        return result;
    }

    static JSONObject directPerformance(Proxy proxy) {
        JSONObject data = new JSONObject();
        try {
            long started = System.nanoTime();
            HttpResult download = http("https://speed.cloudflare.com/__down?bytes=2097152", proxy, "GET", null, 2 * 1024 * 1024, 20_000);
            long elapsed = Math.max(1, elapsed(started));
            JsonUtil.put(data, "downloadBytes", download.bytesRead);
            JsonUtil.put(data, "downloadElapsedMs", elapsed);
            JsonUtil.put(data, "downloadMbps", Math.round(download.bytesRead * 8.0 / elapsed / 1000.0 * 100.0) / 100.0);
        } catch (Exception error) { JsonUtil.put(data, "downloadError", error.getClass().getSimpleName()); }
        try {
            byte[] upload = new byte[512 * 1024];
            long started = System.nanoTime();
            HttpResult response = http("https://speed.cloudflare.com/__up", proxy, "POST", upload, 64 * 1024, 20_000);
            long elapsed = Math.max(1, elapsed(started));
            JsonUtil.put(data, "uploadBytes", upload.length); JsonUtil.put(data, "uploadStatus", response.statusCode);
            JsonUtil.put(data, "uploadElapsedMs", elapsed);
            JsonUtil.put(data, "uploadMbps", Math.round(upload.length * 8.0 / elapsed / 1000.0 * 100.0) / 100.0);
        } catch (Exception error) { JsonUtil.put(data, "uploadError", error.getClass().getSimpleName()); }
        return data;
    }

    static JSONObject httpStage(Proxy proxy) {
        long started = System.nanoTime();
        JSONArray observations = new JSONArray();
        boolean success = false;
        for (String target : new String[]{"https://www.google.com/generate_204", "https://www.gstatic.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace"}) {
            JSONObject item = new JSONObject(); JsonUtil.put(item, "target", target);
            long itemStarted = System.nanoTime();
            try {
                HttpResult response = http(target, proxy, "GET", null, 64 * 1024, TIMEOUT_MS + 5_000);
                boolean itemSuccess = response.statusCode >= 200 && response.statusCode < 400;
                success |= itemSuccess;
                JsonUtil.put(item, "statusCode", response.statusCode); JsonUtil.put(item, "success", itemSuccess);
                JsonUtil.put(item, "bytes", response.bytesRead);
            } catch (Exception error) { JsonUtil.put(item, "success", false); JsonUtil.put(item, "error", error.getClass().getSimpleName()); }
            JsonUtil.put(item, "elapsedMs", elapsed(itemStarted)); observations.put(item);
        }
        return success ? JsonUtil.passed("tunnel.http", elapsed(started), observations)
                : JsonUtil.failed("tunnel.http", elapsed(started), "No functional HTTP target succeeded through the tunnel.", observations);
    }

    static JSONObject stability(Proxy proxy, int attempts) {
        long started = System.nanoTime();
        JSONArray values = new JSONArray(); int successes = 0;
        for (int i = 1; i <= attempts; i++) {
            JSONObject item = new JSONObject(); JsonUtil.put(item, "attempt", i); long itemStarted = System.nanoTime();
            try {
                HttpResult response = http("https://www.google.com/generate_204", proxy, "GET", null, 1024, TIMEOUT_MS + 4_000);
                boolean ok = response.statusCode == 204; if (ok) successes++;
                JsonUtil.put(item, "success", ok); JsonUtil.put(item, "statusCode", response.statusCode);
            } catch (Exception error) { JsonUtil.put(item, "success", false); JsonUtil.put(item, "error", error.getClass().getSimpleName()); }
            JsonUtil.put(item, "elapsedMs", elapsed(itemStarted)); values.put(item);
        }
        JSONObject data = new JSONObject(); JsonUtil.put(data, "attempts", attempts); JsonUtil.put(data, "successes", successes);
        JsonUtil.put(data, "failures", attempts - successes); JsonUtil.put(data, "connectionLifetimeMs", elapsed(started)); JsonUtil.put(data, "requests", values);
        return successes > 0 ? JsonUtil.passed("tunnel.stability", elapsed(started), data)
                : JsonUtil.failed("tunnel.stability", elapsed(started), "All repeated requests failed.", data);
    }

    static JSONObject socksDomain(int socksPort) {
        long started = System.nanoTime();
        try {
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", socksPort));
            try (Socket socket = new Socket(proxy)) {
                socket.connect(InetSocketAddress.createUnresolved("www.google.com", 443), TIMEOUT_MS);
                JSONObject data = new JSONObject(); JsonUtil.put(data, "mode", "SOCKS5 unresolved-domain CONNECT");
                JsonUtil.put(data, "destination", "www.google.com:443");
                return JsonUtil.passed("tunnel.dnsViaSocks", elapsed(started), data);
            }
        } catch (Exception error) {
            return JsonUtil.failed("tunnel.dnsViaSocks", elapsed(started), JsonUtil.redact(error.getMessage()), null);
        }
    }

    static JSONObject socksUdpDns(int socksPort) {
        long started = System.nanoTime();
        JSONObject data = new JSONObject();
        try (Socket control = new Socket()) {
            control.connect(new InetSocketAddress("127.0.0.1", socksPort), TIMEOUT_MS);
            control.setSoTimeout(TIMEOUT_MS);
            DataInputStream input = new DataInputStream(new BufferedInputStream(control.getInputStream()));
            DataOutputStream output = new DataOutputStream(new BufferedOutputStream(control.getOutputStream()));
            output.write(new byte[]{5, 1, 0}); output.flush();
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0) throw new IllegalStateException("SOCKS authentication negotiation failed");
            output.write(new byte[]{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); output.flush();
            if (input.readUnsignedByte() != 5) throw new IllegalStateException("Invalid SOCKS UDP reply");
            int reply = input.readUnsignedByte(); input.readUnsignedByte(); int atyp = input.readUnsignedByte();
            if (reply != 0) throw new IllegalStateException("SOCKS UDP associate reply=" + reply);
            String relayHost;
            if (atyp == 1) { byte[] ip = new byte[4]; input.readFully(ip); relayHost = InetAddress.getByAddress(ip).getHostAddress(); }
            else if (atyp == 4) { byte[] ip = new byte[16]; input.readFully(ip); relayHost = InetAddress.getByAddress(ip).getHostAddress(); }
            else if (atyp == 3) { int len = input.readUnsignedByte(); byte[] name = new byte[len]; input.readFully(name); relayHost = new String(name, StandardCharsets.US_ASCII); }
            else throw new IllegalStateException("Unsupported relay address type");
            int relayPort = input.readUnsignedShort();
            if ("0.0.0.0".equals(relayHost) || "::".equals(relayHost)) relayHost = "127.0.0.1";
            byte[] query = buildDnsQuery("one.one.one.one", RANDOM.nextInt(65536), 1);
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(new byte[]{0, 0, 0, 1, 1, 1, 1, 1, 0, 53}); frame.write(query);
            try (DatagramSocket udp = new DatagramSocket()) {
                udp.setSoTimeout(TIMEOUT_MS);
                byte[] bytes = frame.toByteArray();
                udp.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName(relayHost), relayPort));
                byte[] response = new byte[4096]; DatagramPacket packet = new DatagramPacket(response, response.length); udp.receive(packet);
                int offset = socksUdpPayloadOffset(response, packet.getLength());
                byte[] dns = Arrays.copyOfRange(response, offset, packet.getLength());
                int answers = dns.length >= 8 ? ((dns[6] & 255) << 8) | (dns[7] & 255) : 0;
                JsonUtil.put(data, "relayEndpoint", relayHost + ":" + relayPort); JsonUtil.put(data, "destination", "1.1.1.1:53");
                JsonUtil.put(data, "queryName", "one.one.one.one"); JsonUtil.put(data, "answerCount", answers);
                JsonUtil.put(data, "interpretation", "A real DNS response through SOCKS5 UDP ASSOCIATE proves end-to-end UDP, not packet encoding by itself.");
                return answers > 0 ? JsonUtil.passed("tunnel.udp", elapsed(started), data)
                        : JsonUtil.partial("tunnel.udp", elapsed(started), "UDP response contained no DNS answers.", data);
            }
        } catch (Exception error) {
            return JsonUtil.failed("tunnel.udp", elapsed(started), JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()), data);
        }
    }

    static JSONObject directStun() {
        long started = System.nanoTime();
        JSONObject data = new JSONObject();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(TIMEOUT_MS);
            byte[] transaction = new byte[12]; RANDOM.nextBytes(transaction);
            ByteBuffer request = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
            request.putShort((short) 0x0001).putShort((short) 0).putInt(0x2112A442).put(transaction);
            InetAddress server = InetAddress.getByName("stun.cloudflare.com");
            socket.send(new DatagramPacket(request.array(), 20, server, 3478));
            byte[] response = new byte[1024]; DatagramPacket packet = new DatagramPacket(response, response.length); socket.receive(packet);
            String mapped = parseStunMapped(response, packet.getLength());
            JsonUtil.put(data, "server", "stun.cloudflare.com:3478"); JsonUtil.put(data, "mappedAddress", mapped);
            return mapped == null ? JsonUtil.partial("node.directStun", elapsed(started), "No XOR-MAPPED-ADDRESS attribute.", data)
                    : JsonUtil.passed("node.directStun", elapsed(started), data);
        } catch (Exception error) {
            return JsonUtil.failed("node.directStun", elapsed(started), error.getClass().getSimpleName(), data);
        }
    }

    static JSONObject socksStun(int socksPort) {
        long started = System.nanoTime();
        JSONObject data = new JSONObject();
        final String destinationHost = "stun.cloudflare.com";
        final int destinationPort = 3478;
        try (Socket control = new Socket()) {
            control.connect(new InetSocketAddress("127.0.0.1", socksPort), TIMEOUT_MS);
            control.setSoTimeout(TIMEOUT_MS);
            DataInputStream input = new DataInputStream(new BufferedInputStream(control.getInputStream()));
            DataOutputStream output = new DataOutputStream(new BufferedOutputStream(control.getOutputStream()));
            output.write(new byte[]{5, 1, 0}); output.flush();
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0) throw new IllegalStateException("SOCKS authentication negotiation failed");
            output.write(new byte[]{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); output.flush();
            if (input.readUnsignedByte() != 5) throw new IllegalStateException("Invalid SOCKS UDP reply");
            int reply = input.readUnsignedByte(); input.readUnsignedByte(); int atyp = input.readUnsignedByte();
            if (reply != 0) throw new IllegalStateException("SOCKS UDP associate reply=" + reply);
            String relayHost;
            if (atyp == 1) { byte[] ip = new byte[4]; input.readFully(ip); relayHost = InetAddress.getByAddress(ip).getHostAddress(); }
            else if (atyp == 4) { byte[] ip = new byte[16]; input.readFully(ip); relayHost = InetAddress.getByAddress(ip).getHostAddress(); }
            else if (atyp == 3) { int len = input.readUnsignedByte(); byte[] name = new byte[len]; input.readFully(name); relayHost = new String(name, StandardCharsets.US_ASCII); }
            else throw new IllegalStateException("Unsupported relay address type");
            int relayPort = input.readUnsignedShort();
            if ("0.0.0.0".equals(relayHost) || "::".equals(relayHost)) relayHost = "127.0.0.1";

            byte[] transaction = new byte[12]; RANDOM.nextBytes(transaction);
            ByteBuffer request = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
            request.putShort((short) 0x0001).putShort((short) 0).putInt(0x2112A442).put(transaction);
            byte[] hostBytes = destinationHost.getBytes(StandardCharsets.US_ASCII);
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(new byte[]{0, 0, 0, 3}); frame.write(hostBytes.length); frame.write(hostBytes);
            frame.write((destinationPort >>> 8) & 255); frame.write(destinationPort & 255); frame.write(request.array());
            try (DatagramSocket udp = new DatagramSocket()) {
                udp.setSoTimeout(TIMEOUT_MS);
                byte[] bytes = frame.toByteArray();
                udp.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName(relayHost), relayPort));
                byte[] response = new byte[2048]; DatagramPacket packet = new DatagramPacket(response, response.length); udp.receive(packet);
                int offset = socksUdpPayloadOffset(response, packet.getLength());
                byte[] stun = Arrays.copyOfRange(response, offset, packet.getLength());
                String mapped = parseStunMapped(stun, stun.length);
                JsonUtil.put(data, "relayEndpoint", relayHost + ":" + relayPort);
                JsonUtil.put(data, "server", destinationHost + ":" + destinationPort);
                JsonUtil.put(data, "mappedAddress", mapped);
                JsonUtil.put(data, "interpretation", "The STUN binding response traversed SOCKS5 UDP ASSOCIATE; the mapped address is server-outbound evidence, not a hidden-hop proof.");
                return mapped == null ? JsonUtil.partial("tunnel.stun", elapsed(started), "No STUN mapped-address attribute was returned.", data)
                        : JsonUtil.passed("tunnel.stun", elapsed(started), data);
            }
        } catch (Exception error) {
            return JsonUtil.failed("tunnel.stun", elapsed(started), JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()), data);
        }
    }

    static JSONObject androidTraceroute(String host) {
        long started = System.nanoTime(); JSONArray hops = new JSONArray();
        if (!new java.io.File("/system/bin/ping").canExecute()) return JsonUtil.skipped("endpoint.traceroute", "Android ping binary is unavailable.");
        for (int ttl = 1; ttl <= 12; ttl++) {
            Process process = null;
            try {
                process = new ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "2", "-t", Integer.toString(ttl), host).redirectErrorStream(true).start();
                String output = JsonUtil.readUtf8(process.getInputStream(), 8192);
                process.waitFor();
                String ip = firstIp(output);
                JSONObject hop = new JSONObject(); JsonUtil.put(hop, "ttl", ttl); JsonUtil.put(hop, "address", ip);
                JsonUtil.put(hop, "outcome", process.exitValue() == 0 ? "destination-or-reply" : ip == null ? "timeout" : "ttl-expired");
                hops.put(hop);
                if (process.exitValue() == 0) break;
            } catch (Exception error) {
                if (process != null) process.destroyForcibly();
                JSONObject hop = new JSONObject(); JsonUtil.put(hop, "ttl", ttl); JsonUtil.put(hop, "outcome", "unsupported");
                JsonUtil.put(hop, "error", error.getClass().getSimpleName()); hops.put(hop); break;
            }
        }
        JSONObject data = new JSONObject(); JsonUtil.put(data, "method", "Android ping TTL sweep"); JsonUtil.put(data, "hops", hops);
        JsonUtil.put(data, "limitation", "ICMP filtering and Android ping variations can hide hops; this is not an authoritative server route.");
        return hops.length() > 0 ? JsonUtil.passed("endpoint.traceroute", elapsed(started), data)
                : JsonUtil.skipped("endpoint.traceroute", "No hop evidence was available.");
    }

    static HttpResult http(String url, Proxy proxy, String method, byte[] body, int maxResponse, int timeout) throws Exception {
        return http(url, proxy, method, body, maxResponse, timeout, false);
    }

    static HttpResult http(String url, Proxy proxy, String method, byte[] body, int maxResponse, int timeout, boolean forceClose) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) (proxy == null ? new URL(url).openConnection() : new URL(url).openConnection(proxy));
        connection.setConnectTimeout(timeout); connection.setReadTimeout(timeout); connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("User-Agent", "LokiTrafficLabAndroid/1.0");
        connection.setRequestProperty("Accept", "application/json,text/plain,*/*");
        connection.setRequestProperty("Connection", forceClose ? "close" : "keep-alive");
        connection.setRequestMethod(method);
        if (body != null) {
            connection.setDoOutput(true); connection.setFixedLengthStreamingMode(body.length);
            connection.setRequestProperty("Content-Type", "application/octet-stream");
            try (OutputStream output = connection.getOutputStream()) { output.write(body); }
        }
        int status = connection.getResponseCode();
        InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        int total = 0; ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(maxResponse, 64 * 1024));
        if (stream != null) try (InputStream input = new BufferedInputStream(stream)) {
            byte[] buffer = new byte[16 * 1024]; int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read == 0) continue;
                total += read;
                if (bytes.size() < maxResponse) bytes.write(buffer, 0, Math.min(read, maxResponse - bytes.size()));
                if (total >= maxResponse) break;
            }
        }
        String response = bytes.toString(StandardCharsets.UTF_8.name());
        String contentType = connection.getContentType();
        connection.disconnect();
        return new HttpResult(status, response, total, contentType);
    }

    static boolean anyValidExit(JSONArray observations) {
        for (int i = 0; i < observations.length(); i++) if (observations.optJSONObject(i) != null && observations.optJSONObject(i).optBoolean("valid")) return true;
        return false;
    }

    static List<String> validExitAddresses(JSONArray observations) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < observations.length(); i++) {
            JSONObject item = observations.optJSONObject(i); if (item != null && item.optBoolean("valid")) result.add(item.optString("ip"));
        }
        return result;
    }

    static long elapsed(long startedNanos) { return Math.max(0, (System.nanoTime() - startedNanos) / 1_000_000L); }

    private static JSONObject dnsObservation(String source, String type, String answer, String status, String error) {
        JSONObject item = new JSONObject(); JsonUtil.put(item, "resolver", source); JsonUtil.put(item, "type", type);
        JsonUtil.put(item, "answer", answer); JsonUtil.put(item, "status", status); JsonUtil.put(item, "error", JsonUtil.redact(error)); return item;
    }

    private static boolean isIpLiteral(String value) {
        if (value == null || value.trim().isEmpty()) return false;
        try { return InetAddress.getByName(value).getHostAddress() != null && (value.contains(":") || value.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")); }
        catch (Exception ignored) { return false; }
    }

    private static String firstIp(String text) {
        if (text == null) return null;
        Matcher matcher = IP_PATTERN.matcher(text.trim());
        while (matcher.find()) {
            String candidate = matcher.group();
            try { return InetAddress.getByName(candidate).getHostAddress(); } catch (Exception ignored) {}
        }
        return null;
    }

    private static byte[] buildDnsQuery(String host, int id, int type) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream out = new DataOutputStream(bytes);
        out.writeShort(id); out.writeShort(0x0100); out.writeShort(1); out.writeShort(0); out.writeShort(0); out.writeShort(0);
        for (String label : host.split("\\.")) { byte[] encoded = label.getBytes(StandardCharsets.US_ASCII); out.writeByte(encoded.length); out.write(encoded); }
        out.writeByte(0); out.writeShort(type); out.writeShort(1); out.flush(); return bytes.toByteArray();
    }

    private static List<String> parseDnsAddresses(byte[] data, int id) throws Exception {
        List<String> values = new ArrayList<>();
        if (data.length < 12 || ((data[0] & 255) << 8 | data[1] & 255) != id) return values;
        int questions = ((data[4] & 255) << 8) | data[5] & 255; int answers = ((data[6] & 255) << 8) | data[7] & 255; int offset = 12;
        for (int i = 0; i < questions; i++) { offset = skipDnsName(data, offset); offset += 4; }
        for (int i = 0; i < answers && offset + 12 <= data.length; i++) {
            offset = skipDnsName(data, offset); if (offset + 10 > data.length) break;
            int type = ((data[offset] & 255) << 8) | data[offset + 1] & 255; int length = ((data[offset + 8] & 255) << 8) | data[offset + 9] & 255; offset += 10;
            if (offset + length > data.length) break;
            if (type == 1 && length == 4 || type == 28 && length == 16) values.add(InetAddress.getByAddress(Arrays.copyOfRange(data, offset, offset + length)).getHostAddress());
            offset += length;
        }
        return values;
    }

    private static int skipDnsName(byte[] data, int offset) {
        while (offset < data.length) {
            int len = data[offset] & 255;
            if (len == 0) return offset + 1;
            if ((len & 0xC0) == 0xC0) return offset + 2;
            offset += 1 + len;
        }
        return offset;
    }

    private static int socksUdpPayloadOffset(byte[] bytes, int length) throws Exception {
        if (length < 4 || bytes[2] != 0) throw new IllegalStateException("Fragmented or short SOCKS UDP reply");
        int atyp = bytes[3] & 255;
        if (atyp == 1) return 10;
        if (atyp == 4) return 22;
        if (atyp == 3) return 7 + (bytes[4] & 255);
        throw new IllegalStateException("Unsupported SOCKS UDP address type");
    }

    private static String parseStunMapped(byte[] bytes, int length) throws Exception {
        if (length < 20) return null; int offset = 20;
        while (offset + 4 <= length) {
            int type = ((bytes[offset] & 255) << 8) | bytes[offset + 1] & 255;
            int size = ((bytes[offset + 2] & 255) << 8) | bytes[offset + 3] & 255; int value = offset + 4;
            if ((type == 0x0020 || type == 0x0001) && size >= 8 && value + size <= length) {
                int family = bytes[value + 1] & 255;
                int port = ((bytes[value + 2] & 255) << 8) | bytes[value + 3] & 255;
                if (type == 0x0020) port ^= 0x2112;
                int addressLength = family == 1 ? 4 : 16; byte[] address = Arrays.copyOfRange(bytes, value + 4, value + 4 + addressLength);
                if (type == 0x0020) {
                    byte[] cookie = {0x21, 0x12, (byte) 0xA4, 0x42};
                    for (int i = 0; i < address.length; i++) address[i] ^= i < 4 ? cookie[i] : bytes[4 + i];
                }
                return InetAddress.getByAddress(address).getHostAddress() + ":" + port;
            }
            offset = value + ((size + 3) & ~3);
        }
        return null;
    }

    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes); StringBuilder result = new StringBuilder();
        for (byte b : digest) result.append(String.format(Locale.ROOT, "%02x", b)); return result.toString();
    }

    static final class DnsResult {
        final JSONObject stage; final List<String> addresses; final JSONArray observations;
        DnsResult(JSONObject stage, List<String> addresses, JSONArray observations) { this.stage = stage; this.addresses = addresses; this.observations = observations; }
    }

    static final class HttpResult {
        final int statusCode; final String body; final int bytesRead; final String contentType;
        HttpResult(int statusCode, String body, int bytesRead, String contentType) { this.statusCode = statusCode; this.body = body; this.bytesRead = bytesRead; this.contentType = contentType; }
    }

    private static final class InetAddressLoop {
        static final String PUBLIC_DNS_1 = "1.1.1.1";
        static final String PUBLIC_DNS_2 = "8.8.8.8";
    }
}
