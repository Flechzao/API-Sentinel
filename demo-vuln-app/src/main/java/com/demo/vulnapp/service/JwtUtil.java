package com.demo.vulnapp.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Plain base64url helpers — no security logic, just encoding, shared by
 *  both JWT verifiers below. */
final class JwtUtil {
    private JwtUtil() {}

    static String encode(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    static String decode(String s) {
        return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
    }
}
