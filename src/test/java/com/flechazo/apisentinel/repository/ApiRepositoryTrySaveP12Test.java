package com.flechazo.apisentinel.repository;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guard for P0-12 #6 — the {@link ApiRepository#save()}
 * contract used to be {@code void}, which made it impossible for a
 * caller to tell whether the disk write actually happened. The
 * {@link PersistentApiRepository} implementation swallowed every
 * IOException internally and only logged it, so a disk-full / read-only
 * / permission-denied failure was invisible to everyone except someone
 * tailing the Burp extension console.
 *
 * <p>P0-12 #6 added {@link ApiRepository#trySave()} which returns a
 * boolean; the legacy {@code save()} remains for backward compatibility
 * but now delegates to {@code trySave()} and discards the result.
 */
class ApiRepositoryTrySaveP12Test {

    @Test
    void inMemory_trySave_alwaysSucceeds() {
        // In-memory repo has nothing to persist — "save" is a no-op and
        // must report success. If anyone "optimises" this by throwing
        // when there's no disk target, this test catches it.
        InMemoryApiRepository repo = new InMemoryApiRepository();
        assertThat(repo.trySave()).isTrue();
    }

    @Test
    void persistent_trySave_writablePath_returnsTrue(@TempDir Path tempDir) throws Exception {
        Path dataFile = tempDir.resolve("data.json");
        PersistentApiRepository repo = new PersistentApiRepository(
                new InMemoryApiRepository(),
                dataFile, new com.flechazo.apisentinel.logging.LeveledLogger(null));
        repo.add(new ApiEntry("GET", "/api/x"));

        boolean ok = repo.trySave();

        assertThat(ok).isTrue();
        assertThat(dataFile).exists();
    }

    @Test
    void persistent_trySave_unwritablePath_returnsFalse() throws Exception {
        Path impossible = Path.of("/nonexistent-" + System.nanoTime() + "/x/data.json");
        PersistentApiRepository repo = new PersistentApiRepository(
                new InMemoryApiRepository(),
                impossible, new com.flechazo.apisentinel.logging.LeveledLogger(null));
        repo.add(new ApiEntry("GET", "/api/y"));

        boolean ok = repo.trySave();

        assertThat(ok)
                .as("P0-12 #6: a failed disk write must report false so the caller "
                        + "can decide to retry / surface the error / re-mark dirty. "
                        + "The pre-P0-12 void save() swallowed this silently.")
                .isFalse();
    }

    @Test
    void legacySave_doesNotThrow_onUnwritablePath() throws Exception {
        // The legacy void save() must keep its "never throws" contract —
        // any caller relying on the swallow-and-log behaviour must not
        // start seeing exceptions after the P0-12 refactor.
        Path impossible = Path.of("/nonexistent-" + System.nanoTime() + "/x/data.json");
        PersistentApiRepository repo = new PersistentApiRepository(
                new InMemoryApiRepository(),
                impossible, new com.flechazo.apisentinel.logging.LeveledLogger(null));
        repo.add(new ApiEntry("GET", "/api/z"));

        org.junit.jupiter.api.Assertions.assertDoesNotThrow(repo::save);
    }

    @Test
    void dirtyFlag_bouncesBack_afterTrySaveFailure(@TempDir Path tempDir) throws Exception {
        // End-to-end: mutate → save-fails → dirty must bounce back so
        // the next scheduled flush retries. Same behaviour as the
        // PersistentApiRepositoryP12Test but exercised through the
        // public trySave surface so the whole chain is covered.
        Path dataFile = tempDir.resolve("data.json");
        PersistentApiRepository repo = new PersistentApiRepository(
                new InMemoryApiRepository(),
                dataFile, new com.flechazo.apisentinel.logging.LeveledLogger(null));
        repo.add(new ApiEntry("GET", "/api/a"));
        // First flush works, establishing a baseline.
        invokeFlush(repo);
        assertThat(readDirty(repo)).isFalse();

        // Yank the path so the next flush fails.
        swapPath(repo, Path.of("/nonexistent-" + System.nanoTime() + "/x/data.json"));
        repo.add(new ApiEntry("POST", "/api/b"));
        invokeFlush(repo);

        assertThat(readDirty(repo))
                .as("failed save → dirty must bounce back so a retry is scheduled")
                .isTrue();
    }

    private static void invokeFlush(PersistentApiRepository repo) throws Exception {
        var m = PersistentApiRepository.class.getDeclaredMethod("flushIfDirty");
        m.setAccessible(true);
        m.invoke(repo);
    }

    private static boolean readDirty(PersistentApiRepository repo) throws Exception {
        Field f = PersistentApiRepository.class.getDeclaredField("dirty");
        f.setAccessible(true);
        return ((AtomicBoolean) f.get(repo)).get();
    }

    private static void swapPath(PersistentApiRepository repo, Path newPath) throws Exception {
        Field f = PersistentApiRepository.class.getDeclaredField("dataFilePath");
        f.setAccessible(true);
        f.set(repo, newPath);
    }
}
