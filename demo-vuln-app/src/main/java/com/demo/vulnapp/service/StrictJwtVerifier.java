package com.demo.vulnapp.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

/**
 * Safe counterpart to LenientJwtVerifier (#8 in GROUND_TRUTH.md): rejects
 * alg=none and anything other than HS256, verifies the HMAC signature over
 * header+payload with a server-side secret, and rejects expired tokens.
 */
@Component
public class StrictJwtVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Demo-only secret — in a real app this comes from a secrets manager, not source.
    private static final byte[] SECRET = "demo-strict-hs256-secret-key-32bytes!".getBytes(StandardCharsets.UTF_8);

    public record VerifyResult(boolean valid, String reason, JsonNode claims) {}

    public VerifyResult verify(String token) {
        if (token == null || token.isBlank()) return new VerifyResult(false, "missing token", null);
        String[] parts = token.split("\\.");
        if (parts.length != 3) return new VerifyResult(false, "malformed token", null);

        JsonNode header;
        JsonNode payload;
        try {
            header = MAPPER.readTree(JwtUtil.decode(parts[0]));
            payload = MAPPER.readTree(JwtUtil.decode(parts[1]));
        } catch (Exception e) {
            return new VerifyResult(false, "malformed header/payload", null);
        }

        String alg = header.has("alg") ? header.get("alg").asText() : "";
        if (!"HS256".equalsIgnoreCase(alg)) {
            return new VerifyResult(false, "unsupported alg: " + alg, null);
        }

        String signingInput = parts[0] + "." + parts[1];
        String expectedSig = hmacSha256(signingInput);
        if (!constantTimeEquals(expectedSig, parts[2])) {
            return new VerifyResult(false, "signature mismatch", null);
        }

        if (payload.has("exp")) {
            long exp = payload.get("exp").asLong();
            if (Instant.now().getEpochSecond() > exp) {
                return new VerifyResult(false, "token expired", null);
            }
        } else {
            return new VerifyResult(false, "missing exp claim", null);
        }

        return new VerifyResult(true, "ok", payload);
    }

    private static String hmacSha256(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
            byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }
}
