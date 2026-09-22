package com.demo.vulnapp.service;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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
        reset();
    }

    public void reset() {
        users.clear();
        users.put(1, new User(1, "alice", "alice@example.com", "5f4dcc3b5aa765d61d8327deb882cf99", "123-45-6789"));
        users.put(2, new User(2, "bob", "bob@example.com", "e10adc3949ba59abbe56e057f20f883e", "987-65-4321"));
        users.put(3, new User(3, "admin", "admin@example.com", "21232f297a57a5a743894a0e4a801fc3", "000-00-0000"));
        users.put(4, new User(4, "charlie", "charlie@example.com", "6ebe76c9fb411be97b3b0d48b79179c2", "234-56-7890"));
        users.put(5, new User(5, "diana", "diana@example.com", "098f6bcd4621d373cade4e832627b4f6", "345-67-8901"));
        users.put(6, new User(6, "eve", "eve@example.com", "5f4dcc3b5aa765d61d8327deb882cf99", "456-78-9012"));
        users.put(7, new User(7, "frank", "frank@example.com", "e99a18c428cb38d5f260853678922e03", "567-89-0123"));
        users.put(8, new User(8, "grace", "grace@example.com", "d8578edf8458ce06fbc5bb76a58c5ca4", "678-90-1234"));
        users.put(9, new User(9, "henry", "henry@example.com", "96e79218965eb72c92a549dd5a330112", "789-01-2345"));
        users.put(10, new User(10, "iris", "iris@example.com", "25d55ad283aa400af464c76d713c07ad", "890-12-3456"));
    }

    public List<UserStore.User> getAllUsers() {
        return new ArrayList<>(users.values());
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
