package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PathSandboxTest {

    @Test
    void legitimatePathInsideRepo_resolves(@TempDir Path tempDir) throws IOException {
        Path repoRoot = Files.createDirectory(tempDir.resolve("repo"));
        Path file = repoRoot.resolve("Foo.java");
        Files.writeString(file, "class Foo {}");

        List<CodeRepo> repos = List.of(new CodeRepo("repo", repoRoot.toString(), List.of()));

        Path resolved = PathSandbox.resolveWithinRepos(file.toString(), repos);

        assertNotNull(resolved);
        assertEquals(file.toRealPath(), resolved);
    }

    @Test
    void relativePathTraversal_isRejected(@TempDir Path tempDir) throws IOException {
        Path repoRoot = Files.createDirectory(tempDir.resolve("repo"));
        Path outsideFile = Files.writeString(tempDir.resolve("secret.txt"), "outside repo");

        List<CodeRepo> repos = List.of(new CodeRepo("repo", repoRoot.toString(), List.of()));

        // "../secret.txt" relative to the repo root escapes it.
        Path resolved = PathSandbox.resolveWithinRepos("../secret.txt", repos);

        assertNull(resolved, "path escaping the repo root must be rejected");
    }

    @Test
    void absolutePathOutsideRepo_isRejected(@TempDir Path tempDir) throws IOException {
        Path repoRoot = Files.createDirectory(tempDir.resolve("repo"));
        Path outsideFile = Files.writeString(tempDir.resolve("secret.txt"), "outside repo");

        List<CodeRepo> repos = List.of(new CodeRepo("repo", repoRoot.toString(), List.of()));

        Path resolved = PathSandbox.resolveWithinRepos(outsideFile.toString(), repos);

        assertNull(resolved, "absolute path outside any configured repo root must be rejected");
    }

    @Test
    void symlinkInsideRepoPointingOutside_isRejected(@TempDir Path tempDir) throws IOException {
        Path repoRoot = Files.createDirectory(tempDir.resolve("repo"));
        Path outsideFile = Files.writeString(tempDir.resolve("secret.txt"), "outside repo");
        Path link = repoRoot.resolve("Linked.java");
        try {
            Files.createSymbolicLink(link, outsideFile);
        } catch (UnsupportedOperationException | IOException e) {
            // Some CI/sandboxed environments disallow symlink creation —
            // skip rather than fail on an unrelated platform limitation.
            assumeTrue(false, "symlink creation not supported in this environment");
            return;
        }

        List<CodeRepo> repos = List.of(new CodeRepo("repo", repoRoot.toString(), List.of()));

        Path resolved = PathSandbox.resolveWithinRepos(link.toString(), repos);

        assertNull(resolved, "symlink resolving outside the repo root must be rejected");
    }

    @Test
    void nonExistentPath_returnsNull(@TempDir Path tempDir) throws IOException {
        Path repoRoot = Files.createDirectory(tempDir.resolve("repo"));
        List<CodeRepo> repos = List.of(new CodeRepo("repo", repoRoot.toString(), List.of()));

        Path resolved = PathSandbox.resolveWithinRepos(
                repoRoot.resolve("DoesNotExist.java").toString(), repos);

        assertNull(resolved);
    }
}
