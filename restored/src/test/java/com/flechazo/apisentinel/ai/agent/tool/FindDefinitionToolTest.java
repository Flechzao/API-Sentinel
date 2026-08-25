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

class FindDefinitionToolTest {

    @TempDir
    Path tempDir;

    private FindDefinitionTool tool;

    @BeforeEach
    void setUp() throws IOException {
        Path serviceFile = tempDir.resolve("UserService.java");
        Files.writeString(serviceFile, """
                package com.example;
                
                public class UserService {
                    public User getUser(Long id) {
                        return userDao.findById(id);
                    }
                }
                """);

        Path daoFile = tempDir.resolve("UserDao.java");
        Files.writeString(daoFile, """
                package com.example;
                
                public interface UserDao {
                    User findById(Long id);
                }
                """);

        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        repo.setIndexed(true);

        ToolContext ctx = mock(ToolContext.class);
        when(ctx.codeRepos()).thenReturn(List.of(repo));
        when(ctx.entry()).thenReturn(null);

        tool = new FindDefinitionTool(ctx);
    }

    @Test
    void findClassDefinition() {
        String result = tool.execute("{\"name\": \"UserService\", \"type\": \"class\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("count").getAsInt()).isEqualTo(1);
        assertThat(json.get("type").getAsString()).isEqualTo("class");
        assertThat(json.getAsJsonArray("definitions").get(0).getAsJsonObject()
                .get("file").getAsString()).contains("UserService.java");
    }

    @Test
    void findInterfaceDefinition() {
        String result = tool.execute("{\"name\": \"UserDao\", \"type\": \"class\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("count").getAsInt()).isEqualTo(1);
        assertThat(json.getAsJsonArray("definitions").get(0).getAsJsonObject()
                .get("file").getAsString()).contains("UserDao.java");
    }

    @Test
    void findMethodDefinition() {
        String result = tool.execute("{\"name\": \"getUser\", \"type\": \"method\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("count").getAsInt()).isEqualTo(1);
        assertThat(json.get("type").getAsString()).isEqualTo("method");
    }

    @Test
    void autoDetectsType() {
        String result = tool.execute("{\"name\": \"UserService\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("type").getAsString()).isEqualTo("class");
        assertThat(json.get("count").getAsInt()).isEqualTo(1);
    }

    @Test
    void nonExistentReturnsEmpty() {
        String result = tool.execute("{\"name\": \"NonExistentClass\"}");
        JsonObject json = JsonParser.parseString(result).getAsJsonObject();

        assertThat(json.get("count").getAsInt()).isZero();
        assertThat(json.has("hint")).isTrue();
    }
}
