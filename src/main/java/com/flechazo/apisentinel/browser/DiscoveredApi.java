package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.model.ApiEntry;

/**
 * Represents an API endpoint discovered through browser-based analysis.
 *
 * @param method HTTP method (GET, POST, etc.)
 * @param path API path (e.g., /api/v1/users)
 * @param source Discovery source: "network" (XHR/Fetch capture), "js_bundle"
 *               (JS code analysis), or "router" (frontend router extraction)
 * @param requestBody Sample request body if observed (may be empty)
 * @param responseSnippet Response body snippet (may be empty)
 * @param discoveredIn The page URL where this API was discovered
 */
public record DiscoveredApi(
    String method,
    String path,
    String source,
    String requestBody,
    String responseSnippet,
    String discoveredIn
) {
    /** Convert to an ApiEntry for the repository. */
    public ApiEntry toApiEntry(String domain) {
        ApiEntry entry = new ApiEntry(method != null ? method : "GET", path);
        if (domain != null && !domain.isEmpty()) {
            entry.setDomain(domain);
        }
        // P1-3 hardening: the pre-P1-3 label ("(页面: <url>)") was
        // rendered downstream as "### User Notes (hand-written)" /
        // "## 人工备注" — framing a PAGE-CONTROLLED URL as a hand-
        // written human note. An attacker who can influence the page
        // URL (e.g. via a reflected parameter) could smuggle content
        // into what the model treats as a trusted analyst annotation.
        // The new label explicitly tags the note as browser-discovered
        // and page-controlled so downstream prompts can route it into
        // the untrusted zone instead of the trusted "hand-written"
        // zone. The {@code discoveredIn} URL itself may still carry
        // attacker content; that's defanged by UntrustedContent in
        // the prompt layer (see VulnAnalysisPrompt).
        String sourceLabel = switch (source != null ? source : "") {
            case "network" -> "[Browser-discovered: network capture, untrusted]";
            case "js_bundle" -> "[Browser-discovered: JS bundle, untrusted]";
            case "router" -> "[Browser-discovered: frontend router, untrusted]";
            default -> "[Browser-discovered, untrusted]";
        };
        String safePage = sanitisePageUrl(discoveredIn);
        entry.setNote(sourceLabel + " (page: " + safePage + ")");
        return entry;
    }

    /** Strip anything from the page URL that could confuse a downstream
     *  prompt parser: control chars, line breaks (would split the note
     *  into multiple logical lines), and markdown-header prefixes
     *  (would hijack the "### User Notes" header downstream). The URL
     *  is kept recognisable for forensic purposes but can no longer
     *  impersonate syntax. */
    private static String sanitisePageUrl(String url) {
        if (url == null || url.isEmpty()) return "<unknown page>";
        StringBuilder sb = new StringBuilder(url.length());
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '\n' || c == '\r' || c == '\0') {
                sb.append('␤');
            } else {
                sb.append(c);
            }
        }
        String out = sb.toString();
        // A leading "# " would merge with the downstream "### User
        // Notes" header; defang it.
        while (out.startsWith("#")) out = "\\" + out;
        return out;
    }

    /** Create from network request capture. */
    public static DiscoveredApi fromNetwork(String method, String path, String body, String response, String pageUrl) {
        return new DiscoveredApi(method, path, "network", body, response, pageUrl);
    }

    /** Create from JS bundle analysis. */
    public static DiscoveredApi fromJsBundle(String method, String path, String pageUrl) {
        return new DiscoveredApi(method, path, "js_bundle", "", "", pageUrl);
    }

    /** Create from frontend router extraction. */
    public static DiscoveredApi fromRouter(String path, String pageUrl) {
        return new DiscoveredApi("GET", path, "router", "", "", pageUrl);
    }
}
