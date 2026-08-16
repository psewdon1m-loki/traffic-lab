package com.loki.trafficlab;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

final class XrayManager {
    private final Context context;
    private volatile Process activeProcess;

    XrayManager(Context context) { this.context = context.getApplicationContext(); }

    String binaryPath() {
        return new File(context.getApplicationInfo().nativeLibraryDir, "libxray.so").getAbsolutePath();
    }

    boolean binaryAvailable() {
        File binary = new File(binaryPath());
        return binary.isFile() && binary.canExecute();
    }

    String version() {
        File directory = new File(context.getCacheDir(), "xray-version");
        directory.mkdirs();
        try {
            Process process = new ProcessBuilder(binaryPath(), "version").directory(directory).redirectErrorStream(true).start();
            String output = JsonUtil.readUtf8(process.getInputStream(), 32 * 1024);
            if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly();
            String[] lines = output.split("\\r?\\n", 2);
            return lines.length == 0 || lines[0].trim().isEmpty() ? "unknown" : lines[0];
        } catch (Exception error) {
            return "unavailable: " + error.getClass().getSimpleName();
        }
    }

    RunSession start(ConnectionParser.Profile profile) throws Exception {
        if (!binaryAvailable()) throw new IllegalStateException("Embedded Android Xray binary is missing or not executable for this ABI");
        int httpPort = freeTcpPort();
        int socksPort = freeTcpUdpPort();
        File directory = new File(context.getCacheDir(), "xray/" + UUID.randomUUID().toString().replace("-", ""));
        if (!directory.mkdirs()) throw new IllegalStateException("Could not create isolated Xray directory");
        File config = new File(directory, "config.json");
        File access = new File(directory, "access.log");
        File error = new File(directory, "error.log");
        write(config, buildConfig(profile, httpPort, socksPort, access, error).toString(2));

        ProcessResult validation = runBounded(directory, 8_000, "run", "-test", "-c", config.getAbsolutePath());
        if (validation.exitCode != 0) {
            deleteTree(directory);
            throw new IllegalStateException("Xray config validation failed: " + JsonUtil.redact(validation.output));
        }

        File stdout = new File(directory, "stdout.log");
        File stderr = new File(directory, "stderr.log");
        Process process = new ProcessBuilder(binaryPath(), "run", "-c", config.getAbsolutePath())
                .directory(directory)
                .redirectOutput(stdout)
                .redirectError(stderr)
                .start();
        activeProcess = process;
        if (!waitForPort(httpPort, 10_000)) {
            process.destroy();
            if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly();
            activeProcess = null;
            String output = read(stdout, 64 * 1024) + "\n" + read(stderr, 64 * 1024) + "\n" + read(error, 64 * 1024);
            deleteTree(directory);
            throw new IllegalStateException("Xray local inbound did not start: " + JsonUtil.redact(output));
        }
        return new RunSession(directory, process, httpPort, socksPort, access, error, stdout, stderr, this);
    }

    void cancel() {
        Process process = activeProcess;
        if (process != null) {
            process.destroy();
            try { if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly(); } catch (Exception ignored) { process.destroyForcibly(); }
        }
        activeProcess = null;
    }

    private ProcessResult runBounded(File directory, long timeoutMs, String... args) throws Exception {
        String[] command = new String[args.length + 1]; command[0] = binaryPath(); System.arraycopy(args, 0, command, 1, args.length);
        Process process = new ProcessBuilder(command).directory(directory).redirectErrorStream(true).start();
        String output = JsonUtil.readUtf8(process.getInputStream(), 128 * 1024);
        if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) { process.destroyForcibly(); return new ProcessResult(-1, output + " timeout"); }
        return new ProcessResult(process.exitValue(), output);
    }

    private static JSONObject buildConfig(ConnectionParser.Profile profile, int httpPort, int socksPort, File access, File error) {
        JSONObject user = new JSONObject();
        JsonUtil.put(user, "id", profile.id); JsonUtil.put(user, "encryption", profile.encryption);
        JsonUtil.put(user, "flow", profile.flow); JsonUtil.put(user, "packetEncoding", profile.packetEncoding);

        JSONObject stream = new JSONObject();
        JsonUtil.put(stream, "network", profile.network); JsonUtil.put(stream, "security", profile.security);
        if ("reality".equals(profile.security)) {
            JSONObject reality = new JSONObject(); JsonUtil.put(reality, "serverName", profile.sni);
            JsonUtil.put(reality, "fingerprint", profile.fingerprint == null ? "chrome" : profile.fingerprint);
            JsonUtil.put(reality, "publicKey", profile.publicKey); JsonUtil.put(reality, "shortId", profile.shortId);
            JsonUtil.put(reality, "spiderX", profile.spiderX == null ? "/" : profile.spiderX); JsonUtil.put(stream, "realitySettings", reality);
        } else if ("tls".equals(profile.security)) {
            JSONObject tls = new JSONObject(); JsonUtil.put(tls, "serverName", profile.sni); JsonUtil.put(tls, "fingerprint", profile.fingerprint);
            JsonUtil.put(tls, "allowInsecure", false); JsonUtil.put(stream, "tlsSettings", tls);
        }
        if ("grpc".equals(profile.network)) {
            JSONObject grpc = new JSONObject(); JsonUtil.put(grpc, "serviceName", profile.serviceName); JsonUtil.put(grpc, "multiMode", false);
            JsonUtil.put(stream, "grpcSettings", grpc);
        } else if ("ws".equals(profile.network)) {
            JSONObject ws = new JSONObject(); JsonUtil.put(ws, "path", profile.path == null ? "/" : profile.path);
            if (profile.hostHeader != null && !profile.hostHeader.trim().isEmpty()) JsonUtil.put(ws, "headers", JsonUtil.object("Host", profile.hostHeader));
            JsonUtil.put(stream, "wsSettings", ws);
        } else if ("tcp".equals(profile.network) && profile.headerType != null && !profile.headerType.trim().isEmpty()) {
            JsonUtil.put(stream, "tcpSettings", JsonUtil.object("header", JsonUtil.object("type", profile.headerType)));
        }

        JSONObject socks = JsonUtil.object("tag", "socks-in", "listen", "127.0.0.1", "port", socksPort,
                "protocol", "socks", "settings", JsonUtil.object("udp", true), "sniffing", sniffing());
        JSONObject http = JsonUtil.object("tag", "http-in", "listen", "127.0.0.1", "port", httpPort,
                "protocol", "http", "settings", new JSONObject(), "sniffing", sniffing());
        JSONObject endpoint = JsonUtil.object("address", profile.host, "port", profile.port, "users", new JSONArray().put(user));
        JSONObject proxy = JsonUtil.object("tag", "proxy", "protocol", "vless",
                "settings", JsonUtil.object("vnext", new JSONArray().put(endpoint)), "streamSettings", stream);
        JSONObject document = new JSONObject();
        JsonUtil.put(document, "log", JsonUtil.object("loglevel", "info", "access", access.getAbsolutePath(), "error", error.getAbsolutePath()));
        JsonUtil.put(document, "inbounds", new JSONArray().put(socks).put(http));
        JsonUtil.put(document, "outbounds", new JSONArray().put(proxy)
                .put(JsonUtil.object("tag", "direct", "protocol", "freedom"))
                .put(JsonUtil.object("tag", "block", "protocol", "blackhole")));
        JsonUtil.put(document, "routing", JsonUtil.object("domainStrategy", "AsIs", "rules", new JSONArray()));
        return document;
    }

    private static JSONObject sniffing() {
        return JsonUtil.object("enabled", true, "destOverride", new JSONArray().put("http").put("tls").put("quic"), "routeOnly", false);
    }

    private static int freeTcpPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) { return socket.getLocalPort(); }
    }

    private static int freeTcpUdpPort() throws Exception {
        for (int i = 0; i < 20; i++) {
            int port = freeTcpPort();
            try (DatagramSocket ignored = new DatagramSocket(new InetSocketAddress("127.0.0.1", port))) { return port; }
            catch (Exception ignored) {}
        }
        throw new IllegalStateException("Could not allocate a loopback TCP/UDP port pair");
    }

    private static boolean waitForPort(int port, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 250); return true;
            } catch (Exception ignored) { Thread.sleep(100); }
        }
        return false;
    }

    private static void write(File file, String content) throws Exception {
        try (FileOutputStream output = new FileOutputStream(file)) { output.write(content.getBytes(StandardCharsets.UTF_8)); }
    }

    private static String read(File file, int maxBytes) {
        if (!file.isFile()) return "";
        try (FileInputStream input = new FileInputStream(file)) { return JsonUtil.readUtf8(input, maxBytes); }
        catch (Exception ignored) { return ""; }
    }

    private static void deleteTree(File target) {
        if (target == null || !target.exists()) return;
        File[] children = target.listFiles(); if (children != null) for (File child : children) deleteTree(child);
        //noinspection ResultOfMethodCallIgnored
        target.delete();
    }

    static final class RunSession implements AutoCloseable {
        final File directory; final Process process; final int httpPort; final int socksPort;
        private final File access; private final File error; private final File stdout; private final File stderr; private final XrayManager owner;

        RunSession(File directory, Process process, int httpPort, int socksPort, File access, File error, File stdout, File stderr, XrayManager owner) {
            this.directory = directory; this.process = process; this.httpPort = httpPort; this.socksPort = socksPort;
            this.access = access; this.error = error; this.stdout = stdout; this.stderr = stderr; this.owner = owner;
        }

        JSONObject logs() {
            JSONObject value = new JSONObject();
            JsonUtil.put(value, "accessTail", tail(read(access, 96 * 1024), 30));
            JsonUtil.put(value, "errorTail", tail(read(error, 96 * 1024), 50));
            JsonUtil.put(value, "stdoutTail", tail(read(stdout, 32 * 1024), 20));
            JsonUtil.put(value, "stderrTail", tail(read(stderr, 32 * 1024), 20));
            JsonUtil.put(value, "credentialsRedacted", true);
            return value;
        }

        @Override public void close() {
            process.destroy();
            try { if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly(); } catch (Exception ignored) { process.destroyForcibly(); }
            owner.activeProcess = null;
            deleteTree(directory);
        }

        private static String tail(String value, int maxLines) {
            String redacted = JsonUtil.redact(value); String[] lines = redacted.split("\\R");
            int start = Math.max(0, lines.length - maxLines); StringBuilder result = new StringBuilder();
            for (int i = start; i < lines.length; i++) result.append(lines[i]).append('\n'); return result.toString().trim();
        }
    }

    private static final class ProcessResult {
        final int exitCode; final String output;
        ProcessResult(int exitCode, String output) { this.exitCode = exitCode; this.output = output; }
    }
}
