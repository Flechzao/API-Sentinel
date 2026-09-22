package com.flechazo.apisentinel.ai.provider;

import java.net.http.HttpResponse;

/**
 * Shared HTTP-level retry utilities for LLM providers. Extracted from the
 * copy-pasted {@code computeBackoffMs}/{@code isRetryable}/{@code truncateBody}
 * methods that were duplicated across ClaudeProvider, OpenAiProvider, and
 * OllamaProvider (~90 lines ×3).
 *
 * <p>All methods are static and stateless — providers call them directly
 * without needing an instance.
 */
public final class HttpRetryHelper {

    private HttpRetryHelper() {}

    /**
     * Compute the backoff delay in milliseconds for a rate-limited or
     * server-error HTTP response. Honors the {@code Retry-After} header
     * (seconds form); falls back to exponential backoff capped at 30 s.
     *
     * @param resp    the HTTP response (may carry a {@code retry-after} header)
     * @param attempt zero-based attempt index (0 = first retry)
     * @return delay in milliseconds, capped at 30 000
     */
    public static long computeBackoffMs(HttpResponse<String> resp, int attempt) {
        String ra = resp.headers().firstValue("retry-after").orElse(null);
        if (ra != null) {
            try {
                long ms = Long.parseLong(ra.trim()) * 1000L;
                if (ms > 0) return Math.min(ms, 30_000L);
            } catch (NumberFormatException ignored) {
                // HTTP-date form (e.g. "Wed, 21 Oct 2025 07:28:00 GMT") —
                // not parsed; fall back to exponential.
            }
        }
        // Exponential: attempt 0 → 2 s, 1 → 4 s, capped at 30 s.
        return Math.min(2000L * (1L << attempt), 30_000L);
    }

    /**
     * Truncate a response body for error messages. Keeps the first 500
     * characters so the error is diagnostic without flooding logs.
     */
    public static String truncateBody(String body) {
        if (body == null) return "";
        return body.length() <= 500 ? body : body.substring(0, 500) + "...";
    }

    /**
     * Determine whether an exception from an HTTP call is worth retrying.
     * Matches transient network errors (EOF, connection reset, broken pipe,
     * premature stream closure) — these are the typical failure modes of
     * long-running LLM streaming connections.
     */
    public static boolean isRetryable(Exception e) {
        String msg = (e.getMessage() != null ? e.getMessage() : "").toLowerCase();
        Throwable cause = e.getCause();
        String causeMsg = cause != null && cause.getMessage() != null
                ? cause.getMessage().toLowerCase() : "";

        return msg.contains("eof") || msg.contains("end of file")
                || msg.contains("connection reset") || msg.contains("broken pipe")
                || msg.contains("stream is closed") || msg.contains("premature")
                || causeMsg.contains("eof") || causeMsg.contains("end of file")
                || causeMsg.contains("connection reset") || causeMsg.contains("broken pipe")
                || causeMsg.contains("stream is closed") || causeMsg.contains("premature")
                || e instanceof java.io.EOFException
                || cause instanceof java.io.EOFException;
    }

    /**
     * Close a {@link java.net.http.HttpClient} via reflection. Java 21+ added
     * {@code AutoCloseable} to HttpClient, releasing the internal SelectorManager
     * thread pool and connection pool. On Java 17/20 this is a no-op (the method
     * doesn't exist yet). Callers should use this on extension unload to avoid
     * leaking native threads across reload cycles.
     */
    public static void closeHttpClient(java.net.http.HttpClient client) {
        if (client == null) return;
        try {
            java.lang.reflect.Method close = client.getClass().getMethod("close");
            close.invoke(client);
        } catch (NoSuchMethodException ignored) {
            // Java < 21 — HttpClient has no close() method. The SelectorManager
            // thread will eventually terminate when its keep-alive expires.
        } catch (Exception ignored) {
            // Invocation failed — best-effort, don't propagate.
        }
    }
}
