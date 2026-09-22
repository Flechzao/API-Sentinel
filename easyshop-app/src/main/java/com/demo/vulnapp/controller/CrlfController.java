package com.demo.vulnapp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * #49 VULNERABLE: CRLF injection — user input placed directly in a response
 * header without filtering \r\n characters. An attacker can inject arbitrary
 * headers or even perform HTTP response splitting.
 * #50 SAFE: strips CR/LF characters before setting the header.
 */
@RestController
public class CrlfController {

    /**
     * #49: VULNERABLE — the "filename" parameter is placed into the
     * Content-Disposition header as-is. Injecting "report.pdf\r\nX-Injected: evil"
     * adds an arbitrary header to the response.
     */
    @GetMapping("/api/download")
    public ResponseEntity<Map<String, String>> download(
            @RequestParam(defaultValue = "report.pdf") String filename) {
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                .body(Map.of("status", "ready", "file", filename));
    }

    /**
     * #50: SAFE — strips CR and LF characters before placing in the header.
     */
    @GetMapping("/api/fetch-file")
    public ResponseEntity<Map<String, String>> downloadSafe(
            @RequestParam(defaultValue = "report.pdf") String filename) {
        // Strip CR/LF to prevent header injection
        String safe = filename.replaceAll("[\\r\\n]", "");
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + safe + "\"")
                .body(Map.of("status", "ready", "file", safe));
    }
}
