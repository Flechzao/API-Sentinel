package com.flechazo.apisentinel.browser;

import java.util.Map;

/**
 * Captured HTTP request from browser network traffic.
 * 
 * @param method HTTP method (GET, POST, PUT, DELETE, etc.)
 * @param url Full URL
 * @param headers Request headers
 * @param body Request body (for POST/PUT/PATCH)
 * @param responseStatus Response status code
 * @param responseBodySnippet First 500 chars of response body
 */
public record CapturedRequest(
        String method,
        String url,
        Map<String, String> headers,
        String body,
        int responseStatus,
        String responseBodySnippet
) {
    
    /**
     * Convenience constructor for simple cases without response info.
     */
    public CapturedRequest(String method, String url, int status, Map<String, String> headers, String body) {
        this(method, url, headers, body, status, "");
    }
    
    /**
     * Alias for responseStatus (backward compatibility).
     */
    public int status() {
        return responseStatus;
    }
    
    /**
     * Check if this request is an API call (XHR/Fetch).
     * 
     * @return true if request appears to be an API call
     */
    public boolean isApiCall() {
        if (headers == null) return false;
        String contentType = headers.getOrDefault("Content-Type", "");
        String accept = headers.getOrDefault("Accept", "");
        
        return contentType.contains("application/json") ||
               accept.contains("application/json") ||
               url.contains("/api/") ||
               url.contains("/graphql");
    }
    
    /**
     * Check if this request was successful (2xx status).
     * 
     * @return true if status is 2xx
     */
    public boolean isSuccessful() {
        return responseStatus >= 200 && responseStatus < 300;
    }
    
    @Override
    public String toString() {
        return method + " " + url + " [" + responseStatus + "]";
    }
}
