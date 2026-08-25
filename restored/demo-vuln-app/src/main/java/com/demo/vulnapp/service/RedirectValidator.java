package com.demo.vulnapp.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Set;

@Service
public class RedirectValidator {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
            "localhost",
            "example.com",
            "www.example.com",
            "app.internal.com"
    );

    public boolean isAllowed(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return false;
            return ALLOWED_HOSTS.contains(host.toLowerCase());
        } catch (Exception e) {
            return false;
        }
    }
}
