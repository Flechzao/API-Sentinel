package com.flechazo.apisentinel.ai.agent.tool;

import com.flechazo.apisentinel.config.CodeRepo;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class FindCallersToolTest {

    @TempDir
    Path tempDir;

    private FindCallersTool tool;

    @BeforeEach
    void setUp() throws IOException {
        Path serviceFile = tempDir.resolve("AuthService.java");
        Files.writeString(serviceFile, """
                package com.example;
                
                public class AuthService {
                    public boolean checkPermission(Long userId, String resource) {
                        return permDao.hasAccess(userId, resource);
                    }
                }
                """);

        Path controllerA = tempDir.resolve("UserController.java");
        Files.writeString(controllerA, """
                package com.example;
                
                public class UserController {
                    public User getUser(Long id) {
                        authService.checkPermission(id, "user:read");
                        return userService.getUser(id);
                    }
                }
                """);

        Path controllerB = tempDir.resolve("OrderController.java");
        Files.writeString(controllerB, """
                package com.example;
                
                public class OrderController {
                    public Order getOrder(Long orderId) {
                        authService.checkPermission(currentUserId(), "order:read");
                        return orderService.getOrder(orderId);
                    }
                }
                """);

        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        repo.setIndexed(true);

        ToolContext ctx = mock(ToolContext.class);
        when(ctx.codeRepos()).thenReturn(List.of(repo));
        when(ctx.entry()).thenReturn(null);

        tool = new FindCallersTool(ctx);
    }

    @Test
    void findsCallSitesExcludingDefinition() {
        String result = tool.execute("{\"method_name\": \"checkPermission\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("caller_count").getAsInt()).isEqualTo(2);
        String callers = json.getAsJsonArray("callers").toString();
        assertThat(callers).contains("UserController.java");
        assertThat(callers).contains("OrderController.java");
    }

    @Test
    void respectsMaxResults() {
        String result = tool.execute("{\"method_name\": \"checkPermission\", \"max_results\": 1}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.getAsJsonArray("callers").size()).isLessThanOrEqualTo(1);
    }

    @Test
    void nonExistentMethodReturnsEmpty() {
        String result = tool.execute("{\"method_name\": \"nonExistentMethod\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("caller_count").getAsInt()).isZero();
        assertThat(json.has("hint")).isTrue();
    }
}
