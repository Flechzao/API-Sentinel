package com.flechazo.apisentinel.browser;

import java.util.List;
import java.util.Map;

/**
 * Authentication context extracted from browser session.
 * Contains cookies, localStorage, and bearer token.
 */
public class AuthContext {
    
    /** List of cookies from browser session */
    public final List<CookieInfo> cookies;
    
    /** localStorage entries (may contain JWT tokens) */
    public final Map<String, String> localStorage;
    
    /** Bearer token extracted from localStorage or headers */
    public final String bearerToken;
    
    public AuthContext(List<CookieInfo> cookies, Map<String, String> localStorage, String bearerToken) {
        this.cookies = cookies;
        this.localStorage = localStorage;
        this.bearerToken = bearerToken;
    }
    
    /**
     * Build Cookie header value from all cookies.
     * 
     * @return Cookie header value (e.g., "JSESSIONID=abc123; userId=456")
     */
    public String getCookieString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cookies.size(); i++) {
            if (i > 0) {
                sb.append("; ");
            }
            CookieInfo cookie = cookies.get(i);
            sb.append(cookie.name).append("=").append(cookie.value);
        }
        return sb.toString();
    }
    
    /**
     * Build Authorization header value.
     * 
     * @return Authorization header value (e.g., "Bearer eyJhbG...") or null
     */
    public String getAuthorizationHeader() {
        if (bearerToken == null) {
            return null;
        }
        return "Bearer " + bearerToken;
    }
    
    /**
     * Check if this context has any authentication credentials.
     * 
     * @return true if cookies or bearer token present
     */
    public boolean hasAuth() {
        return !cookies.isEmpty() || bearerToken != null;
    }
    
    @Override
    public String toString() {
        return "AuthContext{" +
            "cookies=" + cookies.size() +
            ", localStorage=" + localStorage.size() + " entries" +
            ", bearerToken=" + (bearerToken != null ? "present" : "null") +
            '}';
    }
}
