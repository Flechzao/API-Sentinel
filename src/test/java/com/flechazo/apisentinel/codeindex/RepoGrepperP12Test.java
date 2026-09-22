package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression guards for P0-12 — {@link RepoGrepper} used to return the
 * same empty list for "no matches" and "every repo was unreadable", so
 * the tool layer ({@link com.flechazo.apisentinel.ai.agent.tool.GrepRepoTool},
 * {@link com.flechazo.apisentinel.mcp.McpTools}) silently reported
 * {@code match_count: 0} to the LLM when the real answer was "we had no
 * access to check". The LLM then concluded "this code has no such sink"
 * and moved on.
 *
 * <p>P0-12 added {@link RepoGrepper.GrepOutcome} with an explicit
 * {@code unavailableReason} field and a {@code searchEx()} overload.
 * These tests pin the contract so any regression that re-silent-ifies
 * the failure path is caught here.
 */
class RepoGrepperP12Test {

    @Test
    void searchEx_readableRepo_noMatches_isAvailable() throws Exception {
        Path root = Files.createTempDirectory("repo-ok");
        Files.writeString(root.resolve("Hello.java"),
                "public class Hello { public static void main(String[] a){} }");
        CodeRepo repo = new CodeRepo("ok", root.toString(), List.of());

        // Pattern that doesn't match anything in the file.
        RepoGrepper.GrepOutcome outcome = RepoGrepper.searchEx(
                List.of(repo), Pattern.compile("NONEXISTENT_TOKEN_XYZ"),
                "*.java", 10, 0, false);

        assertThat(outcome.isAvailable())
                .as("a readable repo that just happens to have no matches "
                        + "must NOT be reported as unavailable — that would "
                        + "turn every negative search into a permissions error")
                .isTrue();
        assertThat(outcome.matches()).isEmpty();
    }

    @Test
    void searchEx_readableRepo_withMatches_returnsMatches() throws Exception {
        Path root = Files.createTempDirectory("repo-match");
        // Put the file in a subdirectory so the "*.java" glob (which
        // RepoGrepper rewrites to "**\/*.java") reliably matches.
        Path src = root.resolve("src");
        Files.createDirectories(src);
        Files.writeString(src.resolve("Foo.java"),
                "class Foo { public void bar() { sink(); } }");
        CodeRepo repo = new CodeRepo("m", root.toString(), List.of());

        RepoGrepper.GrepOutcome outcome = RepoGrepper.searchEx(
                List.of(repo), Pattern.compile("sink"), "*.java", 10, 0, false);

        assertThat(outcome.isAvailable()).isTrue();
        assertThat(outcome.matches()).isNotEmpty();
        assertThat(outcome.matches().get(0).context()).contains("sink");
    }

    @Test
    void searchEx_nonexistentRepo_reportsUnavailable() {
        CodeRepo repo = new CodeRepo("ghost",
                "/this/path/does/not/exist/" + System.nanoTime(), List.of());

        RepoGrepper.GrepOutcome outcome = RepoGrepper.searchEx(
                List.of(repo), Pattern.compile("anything"), null, 10, 0, false);

        assertThat(outcome.isAvailable())
                .as("a repo whose path doesn't exist must be reported as "
                        + "unavailable so the tool layer can tell the LLM "
                        + "'I couldn't read the repo' instead of 'no matches'")
                .isFalse();
        assertThat(outcome.unavailableReason())
                .contains("all_repos_unreadable");
    }

    @Test
    void searchEx_allReposUnreadable_reasonAggregates() {
        CodeRepo a = new CodeRepo("a", "/nonexistent/" + System.nanoTime(), List.of());
        CodeRepo b = new CodeRepo("b", "/also-not-here/" + System.nanoTime(), List.of());

        RepoGrepper.GrepOutcome outcome = RepoGrepper.searchEx(
                List.of(a, b), Pattern.compile("anything"), null, 10, 0, false);

        assertThat(outcome.isAvailable()).isFalse();
        // Each repo's name should appear in the aggregated reason so
        // the operator can tell which repos need fixing.
        assertThat(outcome.unavailableReason()).contains("a").contains("b");
    }

    @Test
    void searchEx_mixedReadableAndUnreadable_isAvailable() throws Exception {
        // If at least one repo is readable, the search is "available"
        // even if others aren't — the user gets matches from the
        // readable ones and the unreadable ones are silently skipped.
        // This matches the pre-P0-12 behaviour (don't regress) while
        // still giving the tool layer an escape hatch when EVERY repo
        // is unreadable.
        Path root = Files.createTempDirectory("repo-mixed");
        Path src = root.resolve("src");
        Files.createDirectories(src);
        Files.writeString(src.resolve("X.java"), "class X { void z() { boom(); } }");
        CodeRepo ok = new CodeRepo("ok", root.toString(), List.of());
        CodeRepo bad = new CodeRepo("bad", "/nonexistent/" + System.nanoTime(), List.of());

        RepoGrepper.GrepOutcome outcome = RepoGrepper.searchEx(
                List.of(ok, bad), Pattern.compile("boom"), "*.java", 10, 0, false);

        assertThat(outcome.isAvailable())
                .as("one readable repo is enough to consider the search 'available'")
                .isTrue();
        assertThat(outcome.matches()).isNotEmpty();
    }

    @Test
    void legacySearchMethod_returnsList() throws Exception {
        // The pre-P0-12 search() overload must still exist and still
        // return a plain List, so all existing call sites
        // (AnalysisPipeline, TaintTracer, FindDefinitionTool) compile
        // without changes. P0-12 is additive, not breaking.
        Path root = Files.createTempDirectory("repo-legacy");
        Path src = root.resolve("src");
        Files.createDirectories(src);
        Files.writeString(src.resolve("Y.java"), "class Y { void z() { tick(); } }");
        CodeRepo repo = new CodeRepo("leg", root.toString(), List.of());

        List<RepoGrepper.GrepMatch> matches = RepoGrepper.search(
                List.of(repo), Pattern.compile("tick"), "*.java", 10, 0, false);

        assertThat(matches).isNotEmpty();
    }
}
