package com.demo.vulnapp.controller;

import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * #45 VULNERABLE: OS command injection — user input concatenated into shell command.
 * #46 SAFE: uses Java File API instead of shell, or validates against whitelist.
 */
@RestController
public class CommandController {

    private static final Path LOG_DIR = Path.of(System.getProperty("java.io.tmpdir"), "vulnapp-logs");

    public CommandController() {
        try {
            Files.createDirectories(LOG_DIR);
            Files.writeString(LOG_DIR.resolve("app.log"), "2026-09-07 INFO Application started\n");
            Files.writeString(LOG_DIR.resolve("access.log"), "2026-09-07 GET /api/users 200\n");
        } catch (Exception ignored) {}
    }

    /**
     * #45: VULNERABLE — filename is concatenated into a shell command.
     * An attacker can pass "app.log; cat /etc/passwd" to execute arbitrary commands.
     */
    @GetMapping("/api/logs")
    public Map<String, Object> readLog(@RequestParam(defaultValue = "app.log") String file) {
        try {
            String command = "cat " + LOG_DIR.toString() + "/" + file;
            Process proc = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            boolean finished = proc.waitFor(5, TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                return Map.of("error", "command timed out");
            }
            String output;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                output = reader.lines().collect(Collectors.joining("\n"));
            }
            if (proc.exitValue() != 0) {
                String errOutput;
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getErrorStream()))) {
                    errOutput = reader.lines().collect(Collectors.joining("\n"));
                }
                return Map.of("error", errOutput.isEmpty() ? "command failed" : errOutput);
            }
            return Map.of("file", file, "content", output);
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    /**
     * #46: SAFE — resolves path via Java NIO and validates it stays within LOG_DIR.
     * No shell command is ever executed.
     */
    @GetMapping("/api/system-logs")
    public Map<String, Object> readLogSafe(@RequestParam(defaultValue = "app.log") String file) {
        try {
            // Only allow known log files
            Set<String> allowed = Set.of("app.log", "access.log");
            if (!allowed.contains(file)) {
                return Map.of("error", "file not allowed: " + file);
            }
            Path resolved = LOG_DIR.resolve(file).toRealPath();
            if (!resolved.startsWith(LOG_DIR.toRealPath())) {
                return Map.of("error", "access denied: path traversal detected");
            }
            String content = Files.readString(resolved);
            return Map.of("file", file, "content", content);
        } catch (Exception e) {
            return Map.of("error", "file not found: " + e.getMessage());
        }
    }
}
