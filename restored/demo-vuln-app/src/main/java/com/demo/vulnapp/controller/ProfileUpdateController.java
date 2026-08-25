package com.demo.vulnapp.controller;

import com.demo.vulnapp.model.ProfileUpdateDto;
import com.demo.vulnapp.model.UserProfile;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * #41 VULNERABLE: mass assignment — full UserProfile (including role/admin) bound from JSON.
 * #42 SAFE: only name/email fields accepted via restricted DTO.
 */
@RestController
public class ProfileUpdateController {

    @PostMapping("/api/profile/update")
    public Map<String, Object> updateProfile(@RequestBody UserProfile profile) {
        return Map.of("success", true,
                "updated", Map.of(
                        "name", profile.getName() != null ? profile.getName() : "",
                        "email", profile.getEmail() != null ? profile.getEmail() : "",
                        "role", profile.getRole() != null ? profile.getRole() : "user",
                        "admin", profile.isAdmin()
                ));
    }

    @PostMapping("/api/profile/update-safe")
    public Map<String, Object> updateProfileSafe(@RequestBody ProfileUpdateDto dto) {
        return Map.of("success", true,
                "updated", Map.of(
                        "name", dto.getName() != null ? dto.getName() : "",
                        "email", dto.getEmail() != null ? dto.getEmail() : "",
                        "role", "user",
                        "admin", false
                ));
    }
}
