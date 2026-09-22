package com.flechazo.apisentinel.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P1-5 — the {@code ~/.api-sentinel/} directory
 * and every file in it used to be created with umask-inherited perms
 * (typically 755/644), making captured cookies, API keys, and auth
 * sessions readable by any local user on a shared box. P1-5 forces
 * 700 on the directory and 600 on secret-bearing files at creation
 * time, so the secrets never have a readable-by-others window.
 *
 * <p>Tests run only on POSIX systems (Linux/macOS) where the chmod
 * semantics actually apply — Windows uses NTFS ACLs and is out of
 * scope for this hardening pass.
 */
@EnabledOnOs({OS.LINUX, OS.MAC})
class AppPathsP15Test {

    @Test
    void writePrivate_newFile_createdWith600(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("secret.json");
        AppPaths.writePrivate(file, "{\"apiKey\":\"sk-xxx\"}");

        assertThat(file).exists();
        assertThat(Files.readString(file)).isEqualTo("{\"apiKey\":\"sk-xxx\"}");

        Set<PosixFilePermission> perms = Files.getFileAttributeView(
                file, PosixFileAttributeView.class).readAttributes().permissions();
        assertThat(perms)
                .as("newly written secret must be owner-only readable/writable")
                .containsExactlyInAnyOrder(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE);
    }

    @Test
    void writePrivate_existingLooseFile_tightenedBeforeWrite(@TempDir Path tmp) throws Exception {
        // Simulate a pre-P1-5 install: a file created with 644 perms.
        Path file = tmp.resolve("legacy.json");
        Files.writeString(file, "old-content");
        Set<PosixFilePermission> loose = Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);
        Files.getFileAttributeView(file, PosixFileAttributeView.class).setPermissions(loose);

        // Now write through the helper.
        AppPaths.writePrivate(file, "new-content");

        Set<PosixFilePermission> perms = Files.getFileAttributeView(
                file, PosixFileAttributeView.class).readAttributes().permissions();
        assertThat(perms)
                .as("P1-5: an existing loose-perm file must be tightened "
                        + "before the new content lands, so the secret "
                        + "never has a world-readable window")
                .containsExactlyInAnyOrder(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE);
        assertThat(Files.readString(file)).isEqualTo("new-content");
    }

    @Test
    void writePrivate_alreadyTight_noChange(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("ok.json");
        Files.createFile(file, java.nio.file.attribute.PosixFilePermissions
                .asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
        AppPaths.writePrivate(file, "x");

        Set<PosixFilePermission> perms = Files.getFileAttributeView(
                file, PosixFileAttributeView.class).readAttributes().permissions();
        assertThat(perms).containsExactlyInAnyOrder(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE);
    }

    @Test
    void tightenDirectoryPermissions_removesGroupOtherBits(@TempDir Path tmp) throws Exception {
        // Create a dir with 755 (typical umask-inherited perms), then
        // ask the helper to tighten it.
        Path dir = Files.createDirectories(tmp.resolve("legacy-config"));
        Set<PosixFilePermission> loose = Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_EXECUTE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_EXECUTE);
        Files.getFileAttributeView(dir, PosixFileAttributeView.class).setPermissions(loose);

        AppPaths.tightenDirectoryPermissions(dir);

        Set<PosixFilePermission> perms = Files.getFileAttributeView(
                dir, PosixFileAttributeView.class).readAttributes().permissions();
        assertThat(perms)
                .as("P1-5: directory must be owner-only after tightening")
                .containsExactlyInAnyOrder(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE);
    }
}
