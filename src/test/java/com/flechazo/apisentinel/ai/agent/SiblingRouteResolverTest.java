package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.logging.LeveledLogger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises SiblingRouteResolver — the shared route-relationship core behind
 * map_sibling_endpoints AND AgentController's cascade — against a REAL
 * indexed Spring controller (same @TempDir style as MapSiblingEndpointsToolTest).
 * Focus: cascade targets must be REQUESTABLE (concrete paths with the source's
 * dynamic values substituted) and conservatively fall back to the raw pattern
 * when alignment is unsure.
 */
class SiblingRouteResolverTest {

    @TempDir
    Path tempDir;

    private CodeIndexService indexSampleController() throws IOException {
        Path javaFile = tempDir.resolve("UserController.java");
        Files.writeString(javaFile, """
                package com.demo.vulnapp.controller;

                import org.springframework.web.bind.annotation.*;

                @RestController
                @RequestMapping("/api/users")
                public class UserController {

                    @GetMapping("/{id}")
                    public String getUser(@PathVariable Long id) { return "user"; }

                    @PutMapping("/{id}")
                    public String updateUser(@PathVariable Long id) { return "updated"; }

                    @DeleteMapping("/{id}")
                    public String deleteUser(@PathVariable Long id) { return "deleted"; }

                    @GetMapping("/me")
                    public String me() { return "me"; }

                    @PostMapping
                    public String create() { return "created"; }
                }
                """);
        CodeIndexService svc = new CodeIndexService(new LeveledLogger(null));
        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        svc.indexRepo(repo, false);
        return svc;
    }

    @Test
    void concretePathSubstitutesDynamicValuesIntoParamSlots() {
        // The IDOR read→write escalation shape: PUT /api/users/{id} gets the
        // source GET's actual id.
        assertThat(SiblingRouteResolver.concretePath("/api/users/1001", "/api/users/{id}"))
                .isEqualTo("/api/users/1001");
        assertThat(SiblingRouteResolver.concretePath("/api/users/1001/audit", "/api/users/{id}/orders"))
                .isEqualTo("/api/users/1001/orders");
    }

    @Test
    void concretePathFallsBackToPatternWhenAlignmentIsUnsure() {
        // Different segment counts: no honest substitution possible.
        assertThat(SiblingRouteResolver.concretePath("/api/users/1001", "/api/users/{id}/files"))
                .isEqualTo("/api/users/{id}/files");
        // Literal mismatch: the source doesn't instantiate this pattern.
        assertThat(SiblingRouteResolver.concretePath("/api/users/1001/audit", "/api/users/{id}/orders/x"))
                .isEqualTo("/api/users/{id}/orders/x");
        // Non-dynamic literal must NOT be pushed into a :param slot —
        // GET /api/users/me never fabricates PUT /api/users/me.
        assertThat(SiblingRouteResolver.concretePath("/api/users/me", "/api/users/{id}"))
                .isEqualTo("/api/users/{id}");
        // Null/blank safety.
        assertThat(SiblingRouteResolver.concretePath(null, "/api/users/{id}"))
                .isEqualTo("/api/users/{id}");
    }

    @Test
    void resolveCascadeTargetsYieldsRequestableWriteFirstTargets() throws IOException {
        CodeIndexService svc = indexSampleController();

        List<SiblingRouteResolver.CascadeTarget> targets =
                SiblingRouteResolver.resolveCascadeTargets(svc, "GET", "/api/users/1001", 10);

        assertThat(targets).isNotEmpty();

        // Write methods first (IDOR read→write escalation targets), and their
        // paths must be concrete — requestable, not templates.
        SiblingRouteResolver.CascadeTarget first = targets.get(0);
        assertThat(first.write()).isTrue();
        assertThat(first.httpMethod()).isIn("PUT", "DELETE", "POST");
        assertThat(first.concretePath()).doesNotContain("{");

        // The PUT escalation target specifically: concrete with the source id.
        assertThat(targets).anySatisfy(t -> {
            assertThat(t.httpMethod()).isEqualTo("PUT");
            assertThat(t.concretePath()).isEqualTo("/api/users/1001");
            assertThat(t.relation()).isEqualTo("same_controller");
            assertThat(t.write()).isTrue();
        });

        // The literal GET /me sibling keeps its literal path (no {id} to fill).
        assertThat(targets).anySatisfy(t -> {
            assertThat(t.httpMethod()).isEqualTo("GET");
            assertThat(t.concretePath()).isEqualTo("/api/users/me");
            assertThat(t.write()).isFalse();
        });
    }

    @Test
    void resolveCascadeTargetsRespectsTheMaxCap() throws IOException {
        CodeIndexService svc = indexSampleController();

        List<SiblingRouteResolver.CascadeTarget> targets =
                SiblingRouteResolver.resolveCascadeTargets(svc, "GET", "/api/users/1001", 2);
        assertThat(targets).hasSize(2);
        // Cap keeps the priority order: both survivors are write methods.
        assertThat(targets).allMatch(SiblingRouteResolver.CascadeTarget::write);
    }

    @Test
    void resolveCascadeTargetsEmptyWhenSourceNotIndexed() throws IOException {
        CodeIndexService svc = indexSampleController();
        assertThat(SiblingRouteResolver.resolveCascadeTargets(svc, "GET", "/api/unknown/42", 10))
                .isEmpty();
    }
}
