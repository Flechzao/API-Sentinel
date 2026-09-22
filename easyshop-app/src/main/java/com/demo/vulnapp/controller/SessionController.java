package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.UserStore;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Login utility (not a scored item in GROUND_TRUTH.md) — deliberately has
 *  no password check, it only exists so Burp traffic can carry a realistic
 *  SESSION_USER cookie for the endpoints that ARE scored. */
@RestController
public class SessionController {

    private final UserStore userStore;

    public SessionController(UserStore userStore) {
        this.userStore = userStore;
    }

    @PostMapping("/api/login")
    public Object login(@RequestParam String username, HttpServletResponse response) {
        UserStore.User user = userStore.findByUsername(username);
        if (user == null) return Map.of("error", "unknown user");
        Cookie cookie = new Cookie("SESSION_USER", String.valueOf(user.id()));
        cookie.setPath("/");
        response.addCookie(cookie);
        return Map.of("userId", user.id(), "username", user.username());
    }
}
