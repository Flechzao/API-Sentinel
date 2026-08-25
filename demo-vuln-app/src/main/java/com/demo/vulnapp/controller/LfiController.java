package com.demo.vulnapp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * #25 VULNERABLE: Local File Inclusion / Path Traversal — no path sanitization.
 * #26 SAFE: validates the resolved path stays within the allowed directory.
 */
@RestController
public class LfiController {

    private static final String BASE_DIR = "/tmp/vuln-app-files";

    public LfiController() {
        try {
            Path base = Paths.get(BASE_DIR);
            Files.createDirectories(base);
            Files.writeString(base.resolve("readme.txt"), "This is a public file.");
        } catch (IOException ignored) {}
    }

    /** #25: VULNERABLE — path is concatenated directly, ../../etc/passwd works. */
    @GetMapping("/api/files")
    public Object readFile(@RequestParam String path) {
        try {
            String content = Files.readString(Paths.get(BASE_DIR, path));
            return Map.of("content", content);
        } catch (IOException e) {
            return Map.of("error", "File not found: " + e.getMessage());
        }
    }

    /** #26: SAFE — resolves the real path and checks it stays under BASE_DIR. */
    @GetMapping("/api/files-safe")
    public Object readFileSafe(@RequestParam String path) {
        try {
            Path resolved = Paths.get(BASE_DIR, path).toRealPath();
            if (!resolved.startsWith(Paths.get(BASE_DIR).toRealPath())) {
                return Map.of("error", "Access denied: path traversal detected");
            }
            String content = Files.readString(resolved);
            return Map.of("content", content);
        } catch (IOException e) {
            return Map.of("error", "File not found: " + e.getMessage());
        }
    }
}
