package com.loki.trafficlab;

import org.json.JSONObject;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ConnectionParser {
    private static final Pattern VLESS_START = Pattern.compile("(?i)vless://");

    private ConnectionParser() {}

    static List<String> extractLinks(String clipboardText) {
        List<String> result = new ArrayList<>();
        if (blank(clipboardText)) return result;
        String text = clipboardText.replace('\u0000', ' ').replace("\r\n", "\n").replace('\r', '\n');
        Matcher matcher = VLESS_START.matcher(text);
        List<Integer> starts = new ArrayList<>();
        while (matcher.find()) starts.add(matcher.start());
        for (int i = 0; i < starts.size(); i++) {
            int start = starts.get(i);
            int next = i + 1 < starts.size() ? starts.get(i + 1) : text.length();
            int lineEnd = text.indexOf('\n', start);
            int end = lineEnd >= 0 && lineEnd < next ? lineEnd : next;
            String candidate = text.substring(start, end).trim();
            candidate = candidate.replaceAll("^[\\s\\u2022*-]+", "");
            candidate = candidate.replaceAll("[\\s,;\\]\\)}>]+$", "");
            int fragment = candidate.indexOf('#');
            if (fragment < 0) {
                int whitespace = firstWhitespace(candidate);
                if (whitespace > 0) candidate = candidate.substring(0, whitespace);
            } else {
                String before = candidate.substring(0, fragment);
                String name = candidate.substring(fragment + 1).trim().replace(" ", "%20");
                candidate = before + "#" + name;
            }
            if (candidate.regionMatches(true, 0, "vless://", 0, 8) && candidate.length() > 8) result.add(candidate);
        }
        return result;
    }

    private static int firstWhitespace(String value) {
        for (int i = 0; i < value.length(); i++) if (Character.isWhitespace(value.charAt(i))) return i;
        return -1;
    }

    static Profile parse(String raw) throws Exception {
        if (raw == null) throw new IllegalArgumentException("Empty connection URI");
        String normalized = raw.trim().replace(" ", "%20");
        URI uri = new URI(normalized);
        if (!"vless".equalsIgnoreCase(uri.getScheme())) throw new IllegalArgumentException("Only vless:// profiles are supported");
        String id = decode(uri.getRawUserInfo());
        UUID.fromString(id);
        String host = uri.getHost();
        int port = uri.getPort();
        if (blank(host)) throw new IllegalArgumentException("Endpoint host is missing");
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Endpoint port is invalid");
        Map<String, String> query = parseQuery(uri.getRawQuery());
        Profile profile = new Profile();
        profile.raw = raw.trim();
        profile.id = id;
        profile.host = host;
        profile.port = port;
        profile.encryption = value(query, "encryption", "none");
        profile.security = value(query, "security", "none").toLowerCase(Locale.ROOT);
        profile.network = value(query, "type", "tcp").toLowerCase(Locale.ROOT);
        profile.sni = query.get("sni");
        profile.fingerprint = value(query, "fp", "chrome");
        profile.publicKey = query.get("pbk");
        profile.shortId = query.get("sid");
        profile.flow = query.get("flow");
        profile.packetEncoding = query.get("packetEncoding");
        profile.path = query.get("path");
        profile.hostHeader = query.get("host");
        profile.serviceName = query.get("serviceName");
        profile.headerType = query.get("headerType");
        profile.spiderX = query.get("spx");
        profile.name = blank(uri.getRawFragment())
                ? host + ":" + port : decode(uri.getRawFragment());
        if ("reality".equals(profile.security)) {
            if (blank(profile.sni)) throw new IllegalArgumentException("REALITY profile has no SNI");
            if (blank(profile.publicKey)) throw new IllegalArgumentException("REALITY profile has no public key");
        }
        return profile;
    }

    private static String value(Map<String, String> map, String key, String fallback) {
        String value = map.get(key);
        return blank(value) ? fallback : value;
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> values = new LinkedHashMap<>();
        if (blank(raw)) return values;
        for (String pair : raw.split("&")) {
            int equals = pair.indexOf('=');
            String key = decode(equals < 0 ? pair : pair.substring(0, equals));
            String value = decode(equals < 0 ? "" : pair.substring(equals + 1));
            values.put(key, value);
        }
        return values;
    }

    private static String decode(String value) {
        try { return value == null ? null : URLDecoder.decode(value, StandardCharsets.UTF_8.name()); }
        catch (Exception error) { return value; }
    }

    private static boolean blank(String value) {
        return value == null || value.trim().isEmpty();
    }

    static final class Profile {
        String raw;
        String id;
        String host;
        int port;
        String encryption;
        String security;
        String network;
        String sni;
        String fingerprint;
        String publicKey;
        String shortId;
        String flow;
        String packetEncoding;
        String path;
        String hostHeader;
        String serviceName;
        String headerType;
        String spiderX;
        String name;

        JSONObject declared() {
            JSONObject value = new JSONObject();
            JsonUtil.put(value, "protocol", "vless");
            JsonUtil.put(value, "name", name);
            JsonUtil.put(value, "host", host);
            JsonUtil.put(value, "port", port);
            JsonUtil.put(value, "encryption", encryption);
            JsonUtil.put(value, "security", security);
            JsonUtil.put(value, "network", network);
            JsonUtil.put(value, "sni", sni);
            JsonUtil.put(value, "fingerprint", fingerprint);
            JsonUtil.put(value, "hasRealityCredential", !blank(publicKey));
            JsonUtil.put(value, "hasShortId", !blank(shortId));
            JsonUtil.put(value, "flow", flow);
            JsonUtil.put(value, "packetEncoding", packetEncoding);
            JsonUtil.put(value, "path", path);
            JsonUtil.put(value, "hostHeader", hostHeader);
            JsonUtil.put(value, "serviceName", serviceName);
            JsonUtil.put(value, "headerType", headerType);
            return value;
        }

        String fingerprint() {
            try {
                String input = String.join("|", "vless", host, Integer.toString(port), nullToEmpty(security),
                        nullToEmpty(network), nullToEmpty(sni), nullToEmpty(path), nullToEmpty(serviceName));
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : digest) hex.append(String.format(Locale.ROOT, "%02x", b));
                return hex.substring(0, 16);
            } catch (Exception ignored) {
                return "unavailable";
            }
        }

        Profile withPacketEncoding(String encoding) {
            Profile copy = copy();
            copy.packetEncoding = encoding;
            return copy;
        }

        Profile copy() {
            Profile p = new Profile();
            p.raw = raw; p.id = id; p.host = host; p.port = port; p.encryption = encryption;
            p.security = security; p.network = network; p.sni = sni; p.fingerprint = fingerprint;
            p.publicKey = publicKey; p.shortId = shortId; p.flow = flow; p.packetEncoding = packetEncoding;
            p.path = path; p.hostHeader = hostHeader; p.serviceName = serviceName; p.headerType = headerType;
            p.spiderX = spiderX; p.name = name;
            return p;
        }

        private static String nullToEmpty(String value) { return value == null ? "" : value; }
    }
}
