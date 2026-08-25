package com.flechazo.apisentinel.auth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.util.UrlUtils;

import java.security.MessageDigest;
import java.util.*;
import java.util.function.Predicate;

/**
 * Discovers distinct sessions from Burp Proxy History for a given API.
 * Groups matching requests by their authentication fingerprint (Cookie + Auth headers).
 */
/** 会话发现——从代理历史自动发现不同用户的 session（Cookie/Authorization 头）。 */
public class SessionDiscovery {

    private final MontoyaApi api;

    /** Cap iteration so a huge proxy history doesn't make every run scan tens of
     *  thousands of entries. 3000 is plenty to find the distinct sessions. */
    private static final int MAX_ITEMS = 3000;

    public SessionDiscovery(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Scan proxy history and return distinct sessions that accessed the given API path.
     * Now domain-aware: when the entry has a domain, only requests to that same
     * domain are considered, so sessions from unrelated hosts never mix in.
     *
     * @param entry the API entry to match against
     * @return list of SessionInfo, one per unique auth fingerprint (may be 0, 1, or more)
     */
    public List<SessionInfo> discoverSessions(ApiEntry entry) {
        String entryDomain = normalizeDomain(entry.getDomain());
        return scanSessions(item -> {
            String url = item.finalRequest().url();
            String urlPath = UrlUtils.extractPath(url);
            if (UrlUtils.isStaticResource(urlPath)) return false;
            if (!UrlUtils.pathsLikelyMatch(entry.getApiPath(), urlPath)) return false;
            if (!entryDomain.isEmpty()) {
                String host = normalizeDomain(UrlUtils.extractHost(url));
                if (!host.equalsIgnoreCase(entryDomain)) return false;
            }
            return true;
        });
    }

    /**
     * Scan proxy history and return distinct sessions seen on ANY endpoint of the
     * given domain (not just one path). This is the broader fallback used when a
     * specific endpoint was only visited by one account — other accounts' sessions
     * are still recoverable from their login / other-endpoint traffic on the host.
     *
     * @param domain target host, with or without port
     * @return list of SessionInfo for the domain (may be 0, 1, or more)
     */
    public List<SessionInfo> discoverDomainSessions(String domain) {
        String target = normalizeDomain(domain);
        if (target.isEmpty()) return new ArrayList<>();
        return scanSessions(item -> {
            String url = item.finalRequest().url();
            String urlPath = UrlUtils.extractPath(url);
            if (UrlUtils.isStaticResource(urlPath)) return false;
            String host = normalizeDomain(UrlUtils.extractHost(url));
            return host.equalsIgnoreCase(target);
        });
    }

    /**
     * Discover distinct authenticated sessions across ALL recent proxy traffic
     * (path-agnostic) — used by the auth-config panel's "auto-detect" button so
     * users can populate Session A/B without tying discovery to one endpoint.
     * Results are ordered by request count (most active session first).
     */
    public List<SessionInfo> discoverRecentSessions() {
        List<SessionInfo> sessions = scanSessions(item -> {
            String urlPath = UrlUtils.extractPath(item.finalRequest().url());
            return !UrlUtils.isStaticResource(urlPath);
        });
        sessions.sort((a, b) -> Integer.compare(b.getRequests().size(), a.getRequests().size()));
        return sessions;
    }

    /** Shared scan loop: group history requests matching {@code include} by auth fingerprint. */
    private List<SessionInfo> scanSessions(Predicate<ProxyHttpRequestResponse> include) {
        Map<String, SessionInfo> sessionMap = new LinkedHashMap<>();
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int processed = 0;
        for (ProxyHttpRequestResponse item : history) {
            if (processed++ >= MAX_ITEMS) break;
            try {
                if (!include.test(item)) continue;
                HttpRequest req = item.finalRequest();
                Map<String, String> cookieMap = parseCookies(getHeaderValue(req, "Cookie"));
                Map<String, String> authHeaders = extractAuthHeaders(req);

                String fingerprint = computeFingerprint(cookieMap, authHeaders);
                if (fingerprint.isEmpty()) continue; // no auth info at all

                SessionInfo session = sessionMap.computeIfAbsent(fingerprint,
                        fp -> new SessionInfo(fp, cookieMap, authHeaders));
                session.addRequest(item);
                // Keep the freshest cookies for this fingerprint (rotating CSRF etc.)
                session.updateLatest(cookieMap, authHeaders);
            } catch (Exception ignored) {}
        }
        return new ArrayList<>(sessionMap.values());
    }

    /** Strip port and trim a host/domain for comparison; empty-safe. */
    private static String normalizeDomain(String domain) {
        if (domain == null || domain.isBlank()) return "";
        return UrlUtils.stripPort(domain.trim());
    }

    /** Parse "k1=v1; k2=v2" into a map. */
    public static Map<String, String> parseCookies(String cookieHeader) {
        Map<String, String> map = new LinkedHashMap<>();
        if (cookieHeader == null || cookieHeader.isBlank()) return map;
        for (String pair : cookieHeader.split(";")) {
            String trimmed = pair.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                map.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
            }
        }
        return map;
    }

    /** Extract auth-related headers (Authorization, X-Token, etc.) */
    private Map<String, String> extractAuthHeaders(HttpRequest req) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (var header : req.headers()) {
            String name = header.name().toLowerCase();
            if (name.equals("authorization") || name.startsWith("x-token")
                    || name.startsWith("x-auth") || name.startsWith("x-access-token")
                    || name.equals("token") || name.equals("api-key") || name.equals("x-api-key")) {
                headers.put(header.name(), header.value());
            }
        }
        return headers;
    }

    /** Get a specific header value from a request. */
    private String getHeaderValue(HttpRequest req, String headerName) {
        for (var header : req.headers()) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }
        return "";
    }

    /** Compute a fingerprint from auth-related values to group sessions. */
    private String computeFingerprint(Map<String, String> cookieMap, Map<String, String> authHeaders) {
        StringBuilder sb = new StringBuilder();
        // Use only auth-relevant cookie keys for fingerprint (not _ga, theme, etc.)
        cookieMap.forEach((k, v) -> {
            if (isLikelyAuthCookieKey(k)) {
                sb.append(k).append("=").append(v).append(";");
            }
        });
        authHeaders.forEach((k, v) -> sb.append(k).append("=").append(v).append(";"));
        if (sb.isEmpty()) {
            // Fallback: use all cookie values
            cookieMap.forEach((k, v) -> sb.append(k).append("=").append(v).append(";"));
        }
        if (sb.isEmpty()) return "";
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes());
            return HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (Exception e) {
            return sb.toString().hashCode() + "";
        }
    }

    /** Heuristic: is this cookie key likely an auth parameter? */
    static boolean isLikelyAuthCookieKey(String key) {
        String lower = key.toLowerCase();
        // Positive patterns
        if (lower.contains("session") || lower.contains("token") || lower.contains("auth")
                || lower.contains("jwt") || lower.contains("sid") || lower.contains("sso")
                || lower.contains("credential") || lower.contains("login")
                || lower.equals("phpsessid") || lower.equals("jsessionid")
                || lower.equals("asp.net_sessionid") || lower.equals("connect.sid")) {
            return true;
        }
        return false;
    }
}
