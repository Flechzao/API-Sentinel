package com.demo.vulnapp.controller;

import com.demo.vulnapp.service.UrlFetchService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** #11 vulnerable (no allowlist) / #12 safe (host allowlist) — see UrlFetchService. */
@RestController
public class FetchController {

    private final UrlFetchService fetchService;

    public FetchController(UrlFetchService fetchService) {
        this.fetchService = fetchService;
    }

    @PostMapping("/api/fetch-url")
    public ResponseEntity<?> fetch(@RequestBody Map<String, String> body) {
        try {
            var result = fetchService.fetch(body.get("url"));
            return ResponseEntity.status(result.statusCode()).body(result.body());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/api/fetch-external")
    public ResponseEntity<?> fetchSafe(@RequestBody Map<String, String> body) {
        try {
            var result = fetchService.fetchSafe(body.get("url"));
            return ResponseEntity.status(result.statusCode()).body(result.body());
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        }
    }
}
