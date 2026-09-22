package com.demo.vulnapp.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service
public class PasswordHashService {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();

    public String hash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String hashSecure(String password) {
        return bcrypt.encode(password);
    }

    public boolean verify(String password, String hash) {
        return hash(password).equals(hash);
    }

    public boolean verifySecure(String password, String hash) {
        return bcrypt.matches(password, hash);
    }
}
