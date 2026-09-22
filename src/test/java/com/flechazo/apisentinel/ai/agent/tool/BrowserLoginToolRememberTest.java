package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.config.LoginProfile;
import com.flechazo.apisentinel.config.LoginProfile.LoginStrategy;
import com.flechazo.apisentinel.config.LoginProfileManager;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for the {@code remember} persistence path of {@link BrowserLoginTool}.
 *
 * <p>We exercise the persistence helper directly (bypassing the actual browser
 * launch) because we only care about "did the profile land in the JSON file
 * with the correct name?" — not whether Playwright could log in.
 */
class BrowserLoginToolRememberTest {

    @TempDir
    Path tempDir;

    private ToolContext ctx;
    private LoginProfileManager profileManager;
    private BrowserLoginTool tool;
    private Path profilesFile;

    @BeforeEach
    void setUp() {
        ctx = mock(ToolContext.class);
        org.mockito.Mockito.when(ctx.logger()).thenReturn(mock(LeveledLogger.class));

        profilesFile = tempDir.resolve("login-profiles.json");
        profileManager = new LoginProfileManager(mock(LeveledLogger.class), profilesFile);

        // browserManager, appConfig are unused by persistProfileForRemember
        tool = new BrowserLoginTool(ctx, null, null, profileManager);
    }

    @Test
    void rememberGeneratesNameFromDomainAndPersists() {
        LoginProfile inline = new LoginProfile(
                "inline",
                "https://app.example.com/login",
                "admin",
                "secret",
                LoginStrategy.AUTO,
                Map.of(),
                List.of("/dashboard"),
                true
        );

        String name = tool.persistProfileForRemember(inline);

        assertThat(name).isEqualTo("auto-app.example.com");

        // Re-load from disk to confirm the file was written
        LoginProfileManager reloaded = new LoginProfileManager(mock(LeveledLogger.class), profilesFile);
        assertThat(reloaded.findByName("auto-app.example.com")).isPresent();
        LoginProfile saved = reloaded.findByName("auto-app.example.com").get();
        assertThat(saved.username()).isEqualTo("admin");
        assertThat(saved.password()).isEqualTo("secret");
        assertThat(saved.loginUrl()).isEqualTo("https://app.example.com/login");
    }

    @Test
    void rememberUpsertsExistingAutoProfile() {
        LoginProfile first = new LoginProfile(
                "inline", "https://app.example.com/login", "alice", "pw1",
                LoginStrategy.AUTO, Map.of(), List.of(), true);
        LoginProfile second = new LoginProfile(
                "inline", "https://app.example.com/login", "bob", "pw2",
                LoginStrategy.AUTO, Map.of(), List.of(), true);

        tool.persistProfileForRemember(first);
        tool.persistProfileForRemember(second);

        LoginProfileManager reloaded = new LoginProfileManager(mock(LeveledLogger.class), profilesFile);
        // Only ONE auto-profile should exist, with the second user's credentials
        assertThat(reloaded.getAll()).hasSize(1);
        LoginProfile saved = reloaded.findByName("auto-app.example.com").get();
        assertThat(saved.username()).isEqualTo("bob");
        assertThat(saved.password()).isEqualTo("pw2");
    }

    @Test
    void rememberPreservesManuallyNamedProfiles() {
        // Seed a manually-named profile
        profileManager.add(new LoginProfile(
                "生产环境", "https://app.example.com/login", "root", "old",
                LoginStrategy.CUSTOM_FORM, Map.of(), List.of(), true));

        // remember=true for the same domain should create auto-<domain>, NOT touch 生产环境
        tool.persistProfileForRemember(new LoginProfile(
                "inline", "https://app.example.com/login", "guest", "new",
                LoginStrategy.AUTO, Map.of(), List.of(), true));

        LoginProfileManager reloaded = new LoginProfileManager(mock(LeveledLogger.class), profilesFile);
        assertThat(reloaded.getAll()).hasSize(2);
        assertThat(reloaded.findByName("生产环境")).isPresent();
        assertThat(reloaded.findByName("auto-app.example.com")).isPresent();
    }

    @Test
    void rememberReturnsNullForEmptyLoginUrl() {
        LoginProfile noUrl = new LoginProfile(
                "inline", "", "u", "p", LoginStrategy.AUTO, Map.of(), List.of(), true);
        assertThat(tool.persistProfileForRemember(noUrl)).isNull();
    }

    @Test
    void rememberReturnsNullForNullProfile() {
        assertThat(tool.persistProfileForRemember(null)).isNull();
    }

    @Test
    void rememberStripsPortFromDomain() {
        LoginProfile withPort = new LoginProfile(
                "inline", "https://app.example.com:8443/login", "u", "p",
                LoginStrategy.AUTO, Map.of(), List.of(), true);

        assertThat(tool.persistProfileForRemember(withPort)).isEqualTo("auto-app.example.com");
    }

    @Test
    void saveSetsPosix600OnSupportedFilesystems() throws Exception {
        profileManager.add(new LoginProfile(
                "test", "https://example.com/login", "u", "p",
                LoginStrategy.AUTO, Map.of(), List.of(), true));

        // On non-POSIX fs (Windows), this test verifies no exception is thrown;
        // on POSIX fs, it also verifies the permissions.
        if (Files.getFileStore(profilesFile).supportsFileAttributeView("posix")) {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(profilesFile);
            assertThat(perms).containsExactlyInAnyOrder(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            assertThat(perms).doesNotContain(
                    PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);
        }
        // File was written regardless of POSIX support
        assertThat(Files.exists(profilesFile)).isTrue();
    }
}
