package com.flechazo.apisentinel.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Searches Burp's proxy history for traffic matching a domain, path pattern,
 * or parameter name. Used by the Agent to construct requests for APIs that
 * have no captured traffic — it finds similar-domain traffic to reuse auth
 * tokens, content-type headers, and parameter values.
 */
public class TrafficSearcher {

    private final MontoyaApi api;

    // P3-10: unified to single source of truth
    private static final Set<String> AUTH_HEADER_NAMES = com.flechazo.apisentinel.util.AuthHeaders.AUTH_HEADERS;

    public TrafficSearcher(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Represents an extracted traffic template — auth tokens and common headers
     * from a similar-domain request that can be reused to construct a new request.
     */
    public record TrafficTemplate(
            String domain,
            String method,
            String path,
            Map<String, String> authHeaders,
            Map<String, String> commonHeaders,
            String body,
            String contentType,
            int statusCode,
            String responseSnippet
    ) {}

    /**
     * Find traffic templates from the same domain. The Agent uses these to
     * construct requests for APIs that have no captured traffic.
     *
     * @param domain the target domain (e.g. "api.example.com")
     * @param pathPattern optional path pattern to narrow search (e.g. "/api/users")
     * @param paramName optional parameter name to find values for
     * @param limit max results
     */
    public List<TrafficTemplate> findSimilarTraffic(String domain, String pathPattern,
                                                     String paramName, int limit) {
        List<TrafficTemplate> results = new ArrayList<>();
        List<ProxyHttpRequestResponse> history = api.proxy().history();

        for (ProxyHttpRequestResponse entry : history) {
            if (results.size() >= limit) break;

            HttpRequest req = entry.finalRequest();
            String reqHost = extractHost(req);
            // P2-10: exact host or registered-domain suffix match, NOT
            // substring. Pre-P2-10 `reqHost.contains(domain)` let
            // domain="." match everything (harvesting the entire proxy
            // history's credentials) and let "api.corp.com" match
            // "api.corp.com.evil.tld".
            if (reqHost == null || !hostMatches(reqHost, domain)) continue;

            // Extract auth headers
            Map<String, String> authHeaders = new LinkedHashMap<>();
            Map<String, String> commonHeaders = new LinkedHashMap<>();
            for (var header : req.headers()) {
                String name = header.name().toLowerCase();
                if (AUTH_HEADER_NAMES.contains(name)) {
                    authHeaders.put(header.name(), header.value());
                } else if (isCommonHeader(name)) {
                    commonHeaders.put(header.name(), header.value());
                }
            }

            String contentType = req.headerValue("Content-Type");
            String body = req.bodyToString();

            // Capture the response so the agent can compare responses across
            // sessions (e.g. two different auth headers returning the SAME
            // resource body = IDOR) without having to replay. Truncated to
            // keep context bounded — the head of a JSON body usually carries
            // the owner/uid/data fields that prove cross-account access.
            int statusCode = 0;
            String responseSnippet = "";
            if (entry.response() != null) {
                statusCode = entry.response().statusCode();
                String respBody = entry.response().bodyToString();
                if (respBody != null && !respBody.isEmpty()) {
                    responseSnippet = respBody.length() > 1000
                            ? respBody.substring(0, 1000) + "..." : respBody;
                }
            }

            String reqPath = req.path();
            // Optional path pattern filter
            if (pathPattern != null && !pathPattern.isBlank()) {
                String[] patternParts = pathPattern.split("/");
                String[] reqParts = reqPath.split("/");
                boolean match = false;
                for (String pp : patternParts) {
                    if (pp.isEmpty() || pp.equals(":param")) continue;
                    for (String rp : reqParts) {
                        if (rp.equalsIgnoreCase(pp)) { match = true; break; }
                    }
                }
                if (!match && !reqPath.contains(pathPattern.replace("{", "").replace("}", ""))) continue;
            }

            // Optional param name filter
            if (paramName != null && !paramName.isBlank()) {
                if (!reqPath.contains(paramName) && !body.contains(paramName)) continue;
            }

            results.add(new TrafficTemplate(
                    reqHost, req.method(), reqPath,
                    authHeaders, commonHeaders, body, contentType,
                    statusCode, responseSnippet));
        }

        return results;
    }

    /**
     * Quick check: does the proxy history contain ANY traffic for this domain?
     */
    public boolean hasTrafficForDomain(String domain) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        for (ProxyHttpRequestResponse entry : history) {
            String host = extractHost(entry.finalRequest());
            if (host != null && hostMatches(host, domain)) return true;
        }
        return false;
    }

    /**
     * Distinct "host:port" targets seen in proxy history, ordered by frequency
     * (most common first). Used to bootstrap a routable host for an entry that
     * has no captured traffic of its own — only safe to auto-use when exactly
     * one host is present (unambiguous); with several hosts the caller must let
     * the Agent pick rather than guess.
     */
    public List<String> recentHostPorts(int limit) {
        Map<String, Integer> freq = new LinkedHashMap<>();
        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
            try {
                var svc = entry.finalRequest().httpService();
                if (svc.host() == null || svc.host().isBlank()) continue;
                freq.merge(svc.host() + ":" + svc.port(), 1, Integer::sum);
            } catch (Exception ignored) {}
        }
        return freq.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .map(Map.Entry::getKey)
                .limit(limit)
                .collect(Collectors.toList());
    }

    /**
     * Extract auth tokens from ANY traffic on the domain. Returns the first
     * set of auth headers found — useful as a fallback when no similar path exists.
     */
    public Map<String, String> extractAuthHeaders(String domain) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        for (ProxyHttpRequestResponse entry : history) {
            String host = extractHost(entry.finalRequest());
            if (host == null || !hostMatches(host, domain)) continue;

            Map<String, String> headers = new LinkedHashMap<>();
            for (var header : entry.finalRequest().headers()) {
                if (AUTH_HEADER_NAMES.contains(header.name().toLowerCase())) {
                    headers.put(header.name(), header.value());
                }
            }
            if (!headers.isEmpty()) return headers;
        }
        return Map.of();
    }

    /**
     * Find parameter values used in traffic for a given domain. E.g., if the
     * Agent needs to know what value "userId" usually takes on this domain.
     */
    public List<String> findParamValues(String domain, String paramName) {
        Set<String> values = new LinkedHashSet<>();
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        for (ProxyHttpRequestResponse entry : history) {
            if (values.size() >= 5) break;
            String host = extractHost(entry.finalRequest());
            if (host == null || !hostMatches(host, domain)) continue;

            String path = entry.finalRequest().path();
            String body = entry.finalRequest().bodyToString();

            // Check query params
            if (path.contains(paramName + "=")) {
                String[] parts = path.split("[?&]");
                for (String p : parts) {
                    if (p.startsWith(paramName + "=")) {
                        values.add(p.substring(paramName.length() + 1));
                    }
                }
            }
            // Check JSON body
            if (body.contains("\"" + paramName + "\"")) {
                // Simple extract — just grab the value
                int idx = body.indexOf("\"" + paramName + "\"");
                int colon = body.indexOf(":", idx);
                if (colon > 0) {
                    int valStart = colon + 1;
                    while (valStart < body.length() && Character.isWhitespace(body.charAt(valStart))) valStart++;
                    int valEnd = valStart;
                    if (valEnd < body.length() && body.charAt(valEnd) == '"') {
                        valEnd++;
                        while (valEnd < body.length() && body.charAt(valEnd) != '"') valEnd++;
                        if (valEnd < body.length()) valEnd++;
                    } else {
                        while (valEnd < body.length() && !Character.isWhitespace(body.charAt(valEnd))
                                && body.charAt(valEnd) != ',' && body.charAt(valEnd) != '}') valEnd++;
                    }
                    values.add(body.substring(valStart, valEnd).replace("\"", "").trim());
                }
            }
        }
        return new ArrayList<>(values);
    }

    private static String extractHost(HttpRequest req) {
        try {
            return req.httpService().host();
        } catch (Exception e) {
            return null;
        }
    }

    /** P2-10: exact host or registered-domain suffix match.
     *  <ul>
     *    <li>{@code host.equals(domain)} — same host</li>
     *    <li>{@code host.endsWith("." + domain)} — subdomain of the
     *        searched domain (e.g. searching "example.com" matches
     *        "api.example.com" but NOT "api.example.com.evil.tld")</li>
     *  </ul>
     *  Also rejects domains shorter than 4 chars (e.g. "." or "a")
     *  that would match an unreasonably broad set of hosts. */
    static boolean hostMatches(String host, String domain) {
        if (host == null || domain == null) return false;
        String h = host.toLowerCase(java.util.Locale.ROOT).trim();
        String d = domain.toLowerCase(java.util.Locale.ROOT).trim();
        if (d.length() < 4) return false;  // too short → ambiguous
        return h.equals(d) || h.endsWith("." + d);
    }

    private static boolean isCommonHeader(String name) {
        return name.equals("content-type") || name.equals("accept")
                || name.equals("user-agent") || name.equals("accept-language")
                || name.equals("accept-encoding") || name.equals("origin")
                || name.equals("referer");
    }
}