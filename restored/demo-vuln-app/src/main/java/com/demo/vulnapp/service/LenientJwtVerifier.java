package com.demo.vulnapp.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

/**
 * Vulnerable JWT verifier (#7 in GROUND_TRUTH.md): if the token's header
 * claims "alg":"none", the signature is never checked at all — an attacker
 * can forge any claims by hand-crafting header/payload and leaving the
 * signature segment empty.
 */
@Component
public class LenientJwtVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public record VerifyResult(boolean valid, String reason, JsonNode claims) {}

    public VerifyResult verify(String token) {
        if (token == null || token.isBlank()) return new VerifyResult(false, "missing token", null);
        String[] parts = token.split("\\.");
        if (parts.length < 2) return new VerifyResult(false, "malformed token", null);

        JsonNode header;
        JsonNode payload;
        try {
            header = MAPPER.readTree(JwtUtil.decode(parts[0]));
            payload = MAPPER.readTree(JwtUtil.decode(parts[1]));
        } catch (Exception e) {
            return new VerifyResult(false, "malformed header/payload", null);
        }

        String alg = header.has("alg") ? header.get("alg").asText() : "";
        if ("none".equalsIgnoreCase(alg)) {
            // BUG: accepted with no signature verification whatsoever.
            return new VerifyResult(true, "accepted (alg=none, unsigned)", payload);
        }

        // Any other alg falls through to a token-length "check" that isn't a
        // real signature verification either — this verifier should not be
        // trusted for anything; use StrictJwtVerifier instead.
        boolean looksSigned = parts.length == 3 && !parts[2].isBlank();
        return new VerifyResult(looksSigned, looksSigned ? "accepted (unverified signature)" : "no signature present", payload);
    }
}
