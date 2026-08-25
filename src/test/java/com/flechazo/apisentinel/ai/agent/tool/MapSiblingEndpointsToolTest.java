package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.codeindex.CodeIndexService;
import com.flechazo.apisentinel.config.CodeRepo;
import com.flechazo.apisentinel.logging.LeveledLogger;
import com.flechazo.apisentinel.model.ApiEntry;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises MapSiblingEndpointsTool against a REAL indexed Spring controller
 * (same @TempDir style as SinkMapTest) — verifies the sibling matching rules
 * that the cluster hunt depends on: same_controller relations, write-method
 * priority flag, self-exclusion, and the same_prefix fallback relation.
 */
class MapSiblingEndpointsToolTest {

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

    private MapSiblingEndpointsTool toolFor(CodeIndexService svc, String method, String path) {
        ApiEntry entry = new ApiEntry(method, path);
        ToolContext ctx = new ToolContext(entry, null, null, svc, List.of(), null, null);
        return new MapSiblingEndpointsTool(ctx);
    }

    @Test
    void mapsSameControllerSiblingsWithWritePriority() throws IOException {
        CodeIndexService svc = indexSampleController();
        String json = toolFor(svc, "GET", "/api/users/1001").execute("{}");

        JsonObject out = JsonParser.parseString(json).getAsJsonObject();
        assertThat(out.get("success").getAsBoolean()).isTrue();

        // Self route resolved to the parameterized pattern
        JsonObject self = out.getAsJsonObject("self_route");
        assertThat(self.get("route_pattern").getAsString()).isEqualTo("/api/users/{id}");
        assertThat(self.get("http_method").getAsString()).isEqualTo("GET");

        var siblings = out.getAsJsonArray("siblings");
        assertThat(siblings.size()).isEqualTo(4); // PUT, DELETE, GET /me, POST

        // Write methods flagged priority=high — the IDOR read→write escalation targets
        assertThat(siblings).anySatisfy(s -> {
            JsonObject o = s.getAsJsonObject();
            assertThat(o.get("http_method").getAsString()).isEqualTo("PUT");
            assertThat(o.get("priority").getAsString()).isEqualTo("high");
            assertThat(o.get("relation").getAsString()).isEqualTo("same_controller");
        });

        // PUT/DELETE (high) sort before GET /me / POST create within their group;
        // same_controller entries all carry the relation
        assertThat(siblings).allSatisfy(s ->
                assertThat(s.getAsJsonObject().get("relation").getAsString()).isEqualTo("same_controller"));

        // Self (GET /api/users/{id}) must NOT appear as its own sibling
        assertThat(siblings).noneSatisfy(s -> {
            JsonObject o = s.getAsJsonObject();
            assertThat(o.get("http_method").getAsString()).isEqualTo("GET");
            assertThat(o.get("route_pattern").getAsString()).isEqualTo("/api/users/{id}");
        });
    }

    @Test
    void samePrefixSiblingFromAnotherController() throws IOException {
        // Two extra controllers: UserExtrasController holds a same_controller
        // sibling of the self route (audit), FilesController holds a route at
        // the same resource-prefix depth (/api/users/{id}/files vs
        // /api/users/{id}/audit — both children of /api/users/{id}) — that one
        // must surface as same_prefix (weak relation) despite a different
        // controller class.
        Files.writeString(tempDir.resolve("UserExtrasController.java"), """
                package com.demo.vulnapp.controller;

                import org.springframework.web.bind.annotation.*;

                @RestController
                public class UserExtrasController {
                    @GetMapping("/api/users/{id}/audit")
                    public String audit(@PathVariable Long id) { return "audit"; }

                    @GetMapping("/api/users/{id}/orders")
                    public String orders(@PathVariable Long id) { return "orders"; }
                }
                """);
        Files.writeString(tempDir.resolve("FilesController.java"), """
                package com.demo.vulnapp.controller;

                import org.springframework.web.bind.annotation.*;

                @RestController
                public class FilesController {
                    @GetMapping("/api/users/{id}/files")
                    public String files(@PathVariable Long id) { return "files"; }
                }
                """);
        CodeIndexService svc = indexSampleController();
        String json = toolFor(svc, "GET", "/api/users/1001/audit").execute("{}");

        JsonObject out = JsonParser.parseString(json).getAsJsonObject();
        assertThat(out.get("success").getAsBoolean()).isTrue();

        var siblings = out.getAsJsonArray("siblings");
        // Same controller → strong relation
        assertThat(siblings).anySatisfy(s -> {
            JsonObject o = s.getAsJsonObject();
            assertThat(o.get("route_pattern").getAsString()).isEqualTo("/api/users/{id}/orders");
            assertThat(o.get("relation").getAsString()).isEqualTo("same_controller");
        });
        // Same resource-prefix depth but different controller → weak relation
        assertThat(siblings).anySatisfy(s -> {
            JsonObject o = s.getAsJsonObject();
            assertThat(o.get("route_pattern").getAsString()).isEqualTo("/api/users/{id}/files");
            assertThat(o.get("relation").getAsString()).isEqualTo("same_prefix");
        });
    }

    @Test
    void failsGracefullyWhenRouteNotIndexed() throws IOException {
        CodeIndexService svc = indexSampleController();
        String json = toolFor(svc, "GET", "/api/unknown/42").execute("{}");

        JsonObject out = JsonParser.parseString(json).getAsJsonObject();
        assertThat(out.get("success").getAsBoolean()).isFalse();
        assertThat(out.get("error").getAsString()).contains("未在代码索引中找到");
    }

    @Test
    void failsGracefullyWithoutIndex() {
        ApiEntry entry = new ApiEntry("GET", "/api/users/1001");
        ToolContext ctx = new ToolContext(entry, null, null, null, List.of(), null, null);
        String json = new MapSiblingEndpointsTool(ctx).execute("{}");

        JsonObject out = JsonParser.parseString(json).getAsJsonObject();
        assertThat(out.get("success").getAsBoolean()).isFalse();
    }
}
