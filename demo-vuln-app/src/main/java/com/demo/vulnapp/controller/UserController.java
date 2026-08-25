package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.UserStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** #17 vulnerable (full entity incl. passwordHash/ssn) / #18 safe (filtered DTO). */
@RestController
public class UserController {

    private final UserStore userStore;

    public UserController(UserStore userStore) {
        this.userStore = userStore;
    }

    /** #17: VULNERABLE — returns the full User record, including passwordHash and ssn. */
    @GetMapping("/api/users/{id}")
    public ResponseEntity<?> getUser(@PathVariable int id) {
        UserStore.User user = userStore.findById(id);
        if (user == null) return ResponseEntity.status(404).body(Map.of("error", "not found"));
        return ResponseEntity.ok(user);
    }

    /** #18: SAFE — filtered DTO, no sensitive fields. */
    @GetMapping("/api/users/{id}/public")
    public ResponseEntity<?> getUserPublic(@PathVariable int id) {
        UserStore.User user = userStore.findById(id);
        if (user == null) return ResponseEntity.status(404).body(Map.of("error", "not found"));
        return ResponseEntity.ok(Map.of("id", user.id(), "username", user.username(), "email", user.email()));
    }
}
