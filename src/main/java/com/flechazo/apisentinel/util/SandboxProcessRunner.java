package com.flechazo.apisentinel.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.TimeUnit;

/**
 * Runs a short script in a fresh subprocess + temp working directory, with a
 * hard timeout and output cap. This is a BEST-EFFORT sandbox, not a security
 * boundary on its own — see RunSandboxedCodeTool's description for the full
 * threat-model caveat. Concretely, this class guarantees:
 *   - a dedicated, disposable temp directory as the process's cwd
 *   - a minimal inherited environment (PATH only, so the interpreter itself
 *     can still be resolved)
 *   - a hard wall-clock timeout with forced kill
 *   - bounded stdout/stderr capture (no unbounded memory growth on runaway output)
 * It explicitly does NOT guarantee: no network access, no filesystem access
 * outside the temp dir (a script can still open an absolute path or make an
 * HTTP call — there is no OS-level namespace/firewall isolation here).
 */
public final class SandboxProcessRunner {

    public record SandboxResult(boolean success, String stdout, String stderr,
                                 int exitCode, boolean timedOut, boolean truncated, String error) {
        static SandboxResult failure(String error) {
            return new SandboxResult(false, "", "", -1, false, false, error);
        }
    }

    private SandboxProcessRunner() {}

    /** Interpreters this runner knows how to invoke, keyed by name → binary + script suffix. */
    public enum Interpreter {
        PYTHON3("python3", ".py"), PYTHON("python", ".py"), NODE("node", ".js");

        final String binary;
        final String suffix;
        Interpreter(String binary, String suffix) { this.binary = binary; this.suffix = suffix; }
    }

    /** Probes candidates in order (or just the requested one) and returns the
     *  first available interpreter's enum name, or null if none is usable. */
    public static Interpreter detectInterpreter(String requested) {
        if (requested != null && !requested.isBlank()) {
            Interpreter want = "python".equalsIgnoreCase(requested) ? Interpreter.PYTHON
                    : "node".equalsIgnoreCase(requested) || "javascript".equalsIgnoreCase(requested) ? Interpreter.NODE
                    : Interpreter.PYTHON3;
            if (isAvailable(want)) return want;
            // Requested binary missing — very common on macOS where "python"
            // doesn't exist but "python3" does. Fall back WITHIN the same
            // language family only (running JS under python would just produce
            // garbage errors, so node has no cross-family fallback).
            if (want == Interpreter.PYTHON && isAvailable(Interpreter.PYTHON3)) {
                return Interpreter.PYTHON3;
            }
            if (want == Interpreter.PYTHON3 && isAvailable(Interpreter.PYTHON)) {
                return Interpreter.PYTHON;
            }
            return null;
        }
        for (Interpreter candidate : new Interpreter[]{Interpreter.PYTHON3, Interpreter.PYTHON, Interpreter.NODE}) {
            if (isAvailable(candidate)) return candidate;
        }
        return null;
    }

    private static boolean isAvailable(Interpreter interpreter) {
        try {
            Process p = new ProcessBuilder(interpreter.binary, "--version")
                    .redirectErrorStream(true)
                    .start();
            boolean finished = p.waitFor(5, TimeUnit.SECONDS);
            if (!finished) { p.destroyForcibly(); return false; }
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    public static SandboxResult run(Interpreter interpreter, String code, int timeoutSeconds, int maxOutputChars) {
        Path tempDir;
        try {
            tempDir = Files.createTempDirectory("apisentinel-sandbox-");
        } catch (IOException e) {
            return SandboxResult.failure("无法创建临时目录: " + e.getMessage());
        }

        try {
            Path scriptFile = tempDir.resolve("script" + interpreter.suffix);
            Files.writeString(scriptFile, code, StandardCharsets.UTF_8);

            ProcessBuilder pb = new ProcessBuilder(interpreter.binary, scriptFile.toString());
            pb.directory(tempDir.toFile());
            // Best-effort environment minimization: keep only PATH (needed to
            // resolve the interpreter binary itself) — not a network/filesystem
            // isolation guarantee, just reduces incidental credential leakage
            // via inherited env vars (API keys, tokens, etc.).
            String path = System.getenv("PATH");
            pb.environment().clear();
            if (path != null) pb.environment().put("PATH", path);

            Process process = pb.start();

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            boolean[] truncated = {false};
            Thread outReader = readerThread(process.getInputStream(), stdout, maxOutputChars, truncated);
            Thread errReader = readerThread(process.getErrorStream(), stderr, maxOutputChars, truncated);
            outReader.start();
            errReader.start();

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            boolean timedOut = !finished;
            if (timedOut) {
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
            }
            outReader.join(5000);
            errReader.join(5000);

            int exitCode = finished ? process.exitValue() : -1;
            return new SandboxResult(finished && exitCode == 0, stdout.toString(), stderr.toString(),
                    exitCode, timedOut, truncated[0], null);
        } catch (Exception e) {
            return SandboxResult.failure("执行失败: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
        } finally {
            deleteRecursively(tempDir);
        }
    }

    private static Thread readerThread(InputStream in, StringBuilder sink, int maxChars, boolean[] truncatedFlag) {
        return new Thread(() -> {
            try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(in, StandardCharsets.UTF_8))) {
                char[] buf = new char[4096];
                int n;
                while ((n = reader.read(buf)) != -1) {
                    if (sink.length() < maxChars) {
                        int room = maxChars - sink.length();
                        sink.append(buf, 0, Math.min(n, room));
                        if (n > room) truncatedFlag[0] = true;
                    } else {
                        truncatedFlag[0] = true;
                    }
                }
            } catch (IOException ignored) {
                // stream closed on process kill — expected on timeout
            }
        });
    }

    private static void deleteRecursively(Path dir) {
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {
            // best-effort cleanup
        }
    }
}
