package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory user directory shared by several endpoints. Fields deliberately
 * include sensitive data (passwordHash, ssn) so UserController's "get by id"
 * endpoint can demonstrate over-exposure (#17 in GROUND_TRUTH.md).
 */
@Component
public class UserStore {

    public record User(int id, String username, String email, String passwordHash, String ssn) {}

    private final Map<Integer, User> users = new LinkedHashMap<>();

    public UserStore() {
        users.put(1, new User(1, "alice", "alice@example.com", "5f4dcc3b5aa765d61d8327deb882cf99", "123-45-6789"));
        users.put(2, new User(2, "bob", "bob@example.com", "e10adc3949ba59abbe56e057f20f883e", "987-65-4321"));
        users.put(3, new User(3, "admin", "admin@example.com", "21232f297a57a5a743894a0e4a801fc3", "000-00-0000"));
    }

    public User findById(int id) {
        return users.get(id);
    }

    public User findByUsername(String username) {
        return users.values().stream()
                .filter(u -> u.username().equalsIgnoreCase(username))
                .findFirst()
                .orElse(null);
    }
}
