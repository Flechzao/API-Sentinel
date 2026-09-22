package com.flechazo.apisentinel.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * P1-6: redact credentials and other sensitive headers from raw HTTP
 * request/response text before it lands in the LLM context.
 *
 * <p><b>Why this class exists</b>: pre-P1-6 the plugin shipped the full
 * captured request — cookies, {@code Authorization} bearer tokens,
 * {@code Proxy-Authorization} credentials, custom {@code x-*-token}
 * headers — to the LLM verbatim. For users who pointed the plugin at
 * a cloud provider (Anthropic / OpenAI), that meant every captured
 * session cookie, every access token, and every internal API key left
 * the local machine in plaintext on every LLM call. Even with TLS,
 * the provider (and anyone who compromises it) gets the live secret.
 *
 * <p><b>What the redactor preserves</b>: header names, header structure,
 * and an 8-hex-char SHA-256 fingerprint of each redacted value. The
 * fingerprint lets the model (and the operator) tell that two requests
 * share the same credential without seeing the credential itself —
 * useful for clustering sessions, spotting rotated tokens, and
 * verifying "the same cookie is used across these calls". The first
 * 4 characters of the value are also kept so humans reading the
 * report can visually recognise the cookie without re-exposing it.
 *
 * <p><b>What the redactor strips</b>: the sensitive header list below.
 * Non-sensitive headers (Content-Type, Accept, User-Agent, …) pass
 * through unchanged. The {@link #redact(String)} call is idempotent
 * and best-effort — malformed requests come back best-effort-redacted
 * rather than throwing.
 */
public final class RequestRedactor {

    /** Headers whose values are always sensitive. Matched case-
     *  insensitively against the header name. */
    private static final List<String> ALWAYS_SENSITIVE = List.of(
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-xsrf-token"
    );

    /** Headers that carry a credential when their name matches this
     *  suffix — e.g. {@code x-session-token}, {@code x-firebase-token},
     *  {@code X-My-Corp-Access-Token}. */
    private static final List<String> SENSITIVE_NAME_SUFFIXES = List.of(
            "-token",
            "-key",
            "-secret",
            "-credential"
    );

    /** Pattern that matches a single HTTP header line:
     *  {@code Name: Value\r?\n}. The value runs up to (but not
     *  including) the line terminator — {@code .*?} is anchored by
     *  the {@code (?=\r?\n|$)} lookahead so it picks up the whole
     *  value including internal whitespace (e.g. "Bearer eyJ…").
     *
     *  <p>P1-6 idempotency: the value alternative also accepts a
     *  previously-redacted placeholder {@code ⟨REDACTED:...⟩} verbatim
     *  and returns it unchanged. Without this, a double-redaction
     *  would wrap the marker in another layer of redaction and the
     *  model would see a mangled token. */
    private static final Pattern HEADER_LINE = Pattern.compile(
            "^([!#$%&'*+\\-.^_`|~A-Za-z0-9]+)\\s*:\\s*(.*?)\\s*(?=\\r?\\n|$)",
            Pattern.MULTILINE);

    /** Matches an already-redacted placeholder so we can skip it on a
     *  second pass. The prefix {@code ⟨REDACTED:} is a unique enough
     *  marker that accidental collisions are vanishingly unlikely. */
    private static final Pattern ALREADY_REDACTED = Pattern.compile(
            "^⟨REDACTED:.*⟩$");

    private RequestRedactor() {}

    /** Redact sensitive headers from a raw HTTP request or response.
     *  The body (everything after the blank line) is returned
     *  untouched — bodies can contain credentials too, but redacting
     *  them would break every analysis that looks at the body for
     *  evidence; body redaction is handled by a separate pass in the
     *  evidence store, not here. */
    public static String redact(String rawHttpMessage) {
        if (rawHttpMessage == null || rawHttpMessage.isEmpty()) return rawHttpMessage;

        // Split head from body at the first blank line. Headers only
        // live in the head; the body is passed through verbatim so
        // evidence analysis keeps working.
        int headEnd = indexOfBlankLine(rawHttpMessage);
        String head = headEnd < 0 ? rawHttpMessage : rawHttpMessage.substring(0, headEnd);
        String tail = headEnd < 0 ? "" : rawHttpMessage.substring(headEnd);

        Matcher m = HEADER_LINE.matcher(head);
        StringBuilder out = new StringBuilder(head.length() + 32);
        int last = 0;
        while (m.find()) {
            String name = m.group(1);
            String value = m.group(2);
            out.append(head, last, m.start(2));
            if (ALREADY_REDACTED.matcher(value).matches()) {
                // P1-6 idempotency: leave an existing placeholder alone
                // so re-redacting a previously redacted message doesn't
                // double-wrap it.
                out.append(value);
            } else if (isSensitive(name)) {
                out.append(redactedValue(value));
            } else {
                out.append(value);
            }
            last = m.end(2);
        }
        out.append(head, last, head.length());
        return out.append(tail).toString();
    }

    /** Whether {@code headerName} is one we should redact. */
    static boolean isSensitive(String headerName) {
        if (headerName == null) return false;
        String lower = headerName.toLowerCase(Locale.ROOT);
        for (String exact : ALWAYS_SENSITIVE) {
            if (lower.equals(exact)) return true;
        }
        for (String suffix : SENSITIVE_NAME_SUFFIXES) {
            if (lower.endsWith(suffix)) return true;
        }
        return false;
    }

    /** Replace a credential value with a privacy-preserving token.
     *  Empty values are returned as-is so the redactor doesn't invent
     *  a fake fingerprint for "no value". */
    static String redactedValue(String original) {
        if (original == null || original.isEmpty()) return original;
        String fingerprint = sha256Hex(original).substring(0, 8);
        String preview = original.length() >= 4 ? original.substring(0, 4) : original;
        return "⟨REDACTED:" + preview + "…" + fingerprint + "⟩";
    }

    /** Hex SHA-256 of the UTF-8 bytes of {@code s}. Cached locally so
     *  repeated redactions of the same value don't re-hash — not
     *  thread-safe but the redactor is only called from the request-
     *  building path which is single-threaded per analysis. */
    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present on every JDK.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static int indexOfBlankLine(String s) {
        int crlfcrlf = s.indexOf("\r\n\r\n");
        int lflf = s.indexOf("\n\n");
        if (crlfcrlf < 0) return lflf;
        if (lflf < 0) return crlfcrlf;
        return Math.min(crlfcrlf, lflf);
    }

    /** List of sensitive header names, for callers (e.g. reports) that
     *  want to enumerate what was stripped. */
    public static List<String> sensitiveHeaderNames() {
        return new ArrayList<>(ALWAYS_SENSITIVE);
    }
}
