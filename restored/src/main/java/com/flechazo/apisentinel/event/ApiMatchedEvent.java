package com.flechazo.apisentinel.event;

import com.flechazo.apisentinel.model.ApiEntry;

/**
 * Published when an HTTP request/response matches a known API entry.
 *
 * @param rawRequest  Full raw HTTP request including headers (from HttpMessageUtils.buildRawRequest),
 *                    may be null if unavailable
 * @param rawResponse Full raw HTTP response including headers (from HttpMessageUtils.buildRawResponse),
 *                    may be null if unavailable
 */
public record ApiMatchedEvent(
    ApiEntry entry,
    String url,
    String method,
    String requestBody,
    String responseBody,
    int statusCode,
    String rawRequest,
    String rawResponse
) {
    /**
     * Backward-compatible constructor without raw request/response.
     */
    public ApiMatchedEvent(ApiEntry entry, String url, String method,
                           String requestBody, String responseBody, int statusCode) {
        this(entry, url, method, requestBody, responseBody, statusCode, null, null);
    }
}
