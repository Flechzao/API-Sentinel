package com.flechazo.apisentinel.benchmark;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Drives a fixed sequence of HTTP requests against the demo-vuln-app,
 * returning one {@link CapturedExchange} per call. The captured pairs
 * are what the Agent (or Pipeline) consumes as its input — mirroring
 * how Burp's Proxy History feeds the plugin in production.
 *
 * <p>The sequence covers every row of {@code GROUND_TRUTH.md} exactly
 * once so a benchmark run has full visibility into recall (27 vulnerable
 * rows) and false-positive rate (17 safe controls). Authentication is
 * handled by pre-logging in as {@code alice} and {@code bob} and reusing
 * their cookies for the endpoints that need them.
 *
 * <p>This class is <b>not</b> JUnit-driven — it's a plain helper that
 * can be invoked from an integration test, a main-method runner, or a
 * CI script. JUnit-level orchestration lives in
 * {@link BenchmarkIntegrationTest}.
 */
public final class BenchmarkTrafficDriver {

    /** One captured request+response pair, shaped to match the inputs
     *  the plugin sees from Burp's proxy history. */
    public record CapturedExchange(
            int groundTruthId,
            String httpMethod,
            String url,
            String apiPath,
            int statusCode,
            Map<String, List<String>> responseHeaders,
            String requestBody,
            String responseBody
    ) {}

    private final String baseUrl;
    private final HttpClient client;
    private final Duration timeout;

    public BenchmarkTrafficDriver(String baseUrl) {
        this(baseUrl, Duration.ofSeconds(15));
    }

    public BenchmarkTrafficDriver(String baseUrl, Duration timeout) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.timeout = timeout;
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Returns true when the demo-vuln-app is reachable at the configured
     *  base URL. Use this from a {@code org.junit.jupiter.api.Assumptions}
     *  guard to skip integration tests when the app isn't running. */
    public boolean isReachable() {
        try {
            HttpResponse<String> r = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/web/dashboard"))
                            .timeout(timeout)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            return r.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /** Pre-log in as {@code alice} and {@code bob}, returning the two
     *  cookie jars (keyed by username). IDOR / vertical-privesc rows
     *  in GROUND_TRUTH need both identities so the Agent can probe
     *  "bob reads alice's order" style attacks. */
    public Map<String, String> loginBothUsers() throws IOException, InterruptedException {
        Map<String, String> cookies = new LinkedHashMap<>();
        for (String user : List.of("alice", "bob")) {
            HttpResponse<String> r = client.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + "/api/login?username=" + user))
                            .timeout(timeout)
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            String cookie = r.headers().firstValue("set-cookie").orElse("");
            // Pull just the name=value part; drop Path=/HttpOnly/etc.
            int semi = cookie.indexOf(';');
            cookies.put(user, semi > 0 ? cookie.substring(0, semi) : cookie);
        }
        return cookies;
    }

    /** Walk the full GROUND_TRUTH universe and emit one captured
     *  exchange per row. Vulnerable rows that need a malicious payload
     *  get the canonical payload from the markdown; safe rows get the
     *  same call with a benign input so the Agent has a baseline to
     *  compare against. */
    public List<CapturedExchange> captureAll(Map<String, String> cookies) {
        List<CapturedExchange> out = new ArrayList<>();
        for (GroundTruthEntry row : GroundTruthEntry.loadAll()) {
            try {
                out.add(captureOne(row, cookies));
            } catch (Exception e) {
                // A single unreachable row shouldn't abort the whole
                // benchmark — record it as a 500 so the Agent sees the
                // failure and the report still accounts for the row.
                out.add(new CapturedExchange(row.id(), row.httpMethod(),
                        baseUrl + row.apiPath(), row.apiPath(),
                        500, Map.of(), "",
                        "benchmark driver failed: " + e.getMessage()));
            }
        }
        return out;
    }

    private CapturedExchange captureOne(GroundTruthEntry row, Map<String, String> cookies)
            throws IOException, InterruptedException {
        String url = baseUrl + row.apiPath();
        String requestBody = "";
        String method = row.httpMethod();

        HttpRequest.Builder b = HttpRequest.newBuilder().timeout(timeout);

        // Per-row identity: IDOR / vertical-privesc rows need bob (to
        // attempt to read alice's resources); everything else uses alice.
        String identity = needsBobIdentity(row) ? "bob" : "alice";
        String cookie = cookies.get(identity);
        if (cookie != null && !cookie.isEmpty()) {
            b.header("Cookie", cookie);
        }

        // Malicious payloads for vulnerable rows, benign for safe rows.
        // Kept intentionally minimal — the goal is to exercise the code
        // path the Agent would, not to actually exploit the app.
        switch (row.id()) {
            case 1, 2 -> url += "?name='";
            case 3, 4 -> url = baseUrl + row.apiPath().replace("{id}", "9999");
            case 5 -> url = baseUrl + row.apiPath().replace("{id}", "2001");
            case 7 -> {
                requestBody = "{\"token\":\"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoxfQ.\"}";
                b.header("Content-Type", "application/json");
            }
            case 8 -> {
                requestBody = "{\"token\":\"aaa.bbb.ccc\"}";
                b.header("Content-Type", "application/json");
            }
            case 10 -> b.header("Origin", "https://evil.example.com");
            case 11, 12 -> {
                requestBody = "{\"url\":\"" + baseUrl + "/api/debug/config\"}";
                b.header("Content-Type", "application/json");
            }
            case 21, 22 -> url += "?name=<script>alert(1)</script>";
            case 23, 24 -> url += "?template=${7*7}";
            case 25, 26 -> url += "?path=../../../etc/passwd";
            case 29, 30 -> url += "?id=1 OR 1=1";
            case 39, 40 -> url += "?url=http://evil.example.com";
            // New endpoints #45-#53
            case 45 -> url += "?file=app.log%3B%20cat%20/etc/passwd";  // command injection payload (URL-encoded)
            case 46 -> url += "?file=app.log";
            case 47 -> {
                requestBody = "{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}";
                b.header("Content-Type", "application/json");
            }
            case 48 -> {
                requestBody = "{\"username\":\"alice\",\"password\":\"alice123\"}";
                b.header("Content-Type", "application/json");
            }
            case 49 -> url += "?filename=report.pdf%0d%0aX-Injected:%20evil";  // CRLF payload (URL-encoded)
            case 50 -> url += "?filename=report.pdf";
            case 51 -> {
                requestBody = "{\"code\":\"SAVE10\",\"orderTotal\":\"100\"}";
                b.header("Content-Type", "application/json");
            }
            case 52 -> {
                requestBody = "{\"code\":\"VIP20\",\"orderTotal\":\"100\"}";
                b.header("Content-Type", "application/json");
            }
            case 53 -> {} // /api/v0/users — no auth needed, default GET is fine
            default -> {
                // Most remaining rows are simple GETs / POSTs with default
                // bodies; the switch is additive — add a case when a row
                // genuinely needs a non-default payload.
            }
        }

        // Attach method + body. POST/PUT rows that didn't get a specific
        // payload above fall through to an empty body.
        if ("POST".equalsIgnoreCase(method)) {
            b.uri(URI.create(url));
            b.POST(HttpRequest.BodyPublishers.ofString(requestBody));
        } else if ("PUT".equalsIgnoreCase(method)) {
            b.uri(URI.create(url));
            b.PUT(HttpRequest.BodyPublishers.ofString(requestBody));
        } else {
            b.uri(URI.create(url));
            b.GET();
        }

        HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        Map<String, List<String>> headers = new LinkedHashMap<>();
        r.headers().map().forEach((k, v) -> headers.put(k.toLowerCase(Locale.ROOT), v));
        return new CapturedExchange(row.id(), method,
                url, row.apiPath(),
                r.statusCode(), headers, requestBody, r.body());
    }

    private static boolean needsBobIdentity(GroundTruthEntry row) {
        // IDOR rows where bob reads alice's resource, and the vertical-
        // privesc row where bob (a non-admin) attempts an admin endpoint.
        return row.id() == 4 || row.id() == 5 || row.id() == 6;
    }
}
