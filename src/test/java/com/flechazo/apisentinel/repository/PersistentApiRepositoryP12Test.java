package com.flechazo.apisentinel.repository;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for P0-12 — {@link PersistentApiRepository#flushIfDirty}
 * used to clear the dirty flag BEFORE calling {@code save()}, so a save
 * failure (disk full, read-only mount, permission error) left the
 * repository in a "clean" state from its own point of view while the
 * on-disk copy silently drifted behind the in-memory one. A user who
 * made one edit, then exited Burp before any further mutation
 * triggered another save, lost the edit with zero signal.
 *
 * <p>P0-12 fix: on save failure, re-set {@code dirty=true} so the next
 * scheduled flush retries, and log a warning so the operator sees the
 * failure in the Burp extension console.
 */
class PersistentApiRepositoryP12Test {

    /**
     * Force a save failure and confirm the dirty flag bounces back to
     * true so the next scheduled flush retries. Without this, the
     * pre-P0-12 "clear-then-save" bug silently loses mutations.
     */
    @Test
    void flushIfDirty_saveFails_dirtyFlagIsReset(@TempDir Path tempDir) throws Exception {
        // Build a repository pointed at a path we control, then yank the
        // target directory out from under it so save() fails with an
        // IOException.
        Path dataFile = tempDir.resolve("data.json");
        PersistentApiRepository repo = new PersistentApiRepository(
                new com.flechazo.apisentinel.repository.InMemoryApiRepository(),
                dataFile, new com.flechazo.apisentinel.logging.LeveledLogger(null));

        // One mutation so the repo is dirty.
        repo.add(new ApiEntry("GET", "/api/x"));
        // Flush once to make sure save() works when the path is writable —
        // this also gives us a baseline on-disk state to compare against
        // after the forced failure.
        invokeFlush(repo);
        assertThat(readDirtyFlag(repo))
                .as("successful flush must clear the dirty flag")
                .isFalse();

        // Now make save() fail by pointing the repo at a path under a
        // non-existent parent directory — Files.writeString will throw
        // NoSuchFileException / IOException.
        swapDataFile(repo, Path.of("/nonexistent-" + System.nanoTime() + "/x/data.json"));

        // Re-dirty and flush again. The save must fail (bad path) and
        // the dirty flag must bounce back to true.
        repo.add(new ApiEntry("POST", "/api/y"));
        assertThat(readDirtyFlag(repo)).isTrue();
        invokeFlush(repo);
        assertThat(readDirtyFlag(repo))
                .as("P0-12: a failed save must re-set dirty=true so the next "
                        + "scheduled flush retries. Without this, the in-memory "
                        + "state silently drifts away from the on-disk copy.")
                .isTrue();
    }

    @Test
    void flushIfDirty_saveSucceeds_dirtyFlagIsCleared(@TempDir Path tempDir) throws Exception {
        // Happy path sanity — if the regression fix accidentally broke
        // the successful case, this would catch it.
        Path dataFile = tempDir.resolve("data.json");
        PersistentApiRepository repo = new PersistentApiRepository(
                new com.flechazo.apisentinel.repository.InMemoryApiRepository(),
                dataFile, new com.flechazo.apisentinel.logging.LeveledLogger(null));
        repo.add(new ApiEntry("GET", "/api/z"));

        invokeFlush(repo);

        assertThat(readDirtyFlag(repo)).isFalse();
    }

    // -- reflection helpers (flushIfDirty is private; we test its contract
    //    via the dirty flag it's meant to manage) --

    private static void invokeFlush(PersistentApiRepository repo) throws Exception {
        Method m = PersistentApiRepository.class.getDeclaredMethod("flushIfDirty");
        m.setAccessible(true);
        m.invoke(repo);
    }

    private static boolean readDirtyFlag(PersistentApiRepository repo) throws Exception {
        Field f = PersistentApiRepository.class.getDeclaredField("dirty");
        f.setAccessible(true);
        return ((AtomicBoolean) f.get(repo)).get();
    }

    private static void swapDataFile(PersistentApiRepository repo, Path newPath) throws Exception {
        // The delegate's save() resolves the path from a field set at
        // construction; overwrite it via reflection so this one repo
        // instance starts failing without affecting any other test.
        Field f = PersistentApiRepository.class.getDeclaredField("dataFilePath");
        f.setAccessible(true);
        f.set(repo, newPath);
    }
}
