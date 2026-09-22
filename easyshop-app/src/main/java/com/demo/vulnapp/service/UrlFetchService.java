package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * fetch() is the vulnerable path (#11 in GROUND_TRUTH.md): it opens a
 * connection to whatever URL the caller supplies, with no allowlist — an
 * attacker can reach internal-only services (e.g. 127.0.0.1, link-local
 * metadata endpoints) through this server. fetchSafe() (#12) is the same
 * feature gated by a host allowlist.
 */
@Component
public class UrlFetchService {

    private static final Set<String> ALLOWED_HOSTS = Set.of("example.com", "api.example.com");

    public record FetchResult(int statusCode, String body) {}

    /** No allowlist, no scheme restriction — deliberately vulnerable to SSRF. */
    public FetchResult fetch(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        return read(conn);
    }

    public FetchResult fetchSafe(String url) throws Exception {
        URL parsed = URI.create(url).toURL();
        if (!"http".equalsIgnoreCase(parsed.getProtocol()) && !"https".equalsIgnoreCase(parsed.getProtocol())) {
            throw new IllegalArgumentException("scheme not allowed: " + parsed.getProtocol());
        }
        if (!ALLOWED_HOSTS.contains(parsed.getHost())) {
            throw new IllegalArgumentException("host not in allowlist: " + parsed.getHost());
        }
        HttpURLConnection conn = (HttpURLConnection) parsed.openConnection();
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        return read(conn);
    }

    private FetchResult read(HttpURLConnection conn) throws Exception {
        int code = conn.getResponseCode();
        StringBuilder body = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                code < 400 ? conn.getInputStream() : conn.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) body.append(line).append('\n');
        }
        return new FetchResult(code, body.toString());
    }
}
