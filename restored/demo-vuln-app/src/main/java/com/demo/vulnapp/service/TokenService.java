package com.demo.vulnapp.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Random;

@Service
public class TokenService {

    private final Random rng = new Random();
    private final SecureRandom secureRng = new SecureRandom();

    public String generateToken(String username) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(String.format("%02x", rng.nextInt(256)));
        }
        return sb.toString();
    }

    public String generateSecureToken(String username) {
        byte[] bytes = new byte[32];
        secureRng.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
