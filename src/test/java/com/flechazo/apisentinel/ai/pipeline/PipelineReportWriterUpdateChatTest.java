package com.flechazo.apisentinel.ai.pipeline;

import com.flechazo.apisentinel.logging.LeveledLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link PipelineReportWriter#updateChatHistory(Path, List)} —
 * the follow-up persistence fix. Initial analysis writes a snapshot report;
 * follow-ups in the chat panel must rewrite the stage6_chatHistory section
 * while preserving stages 1-5.
 */
class PipelineReportWriterUpdateChatTest {

    @TempDir
    Path tempDir;

    private PipelineReportWriter writer;
    private Path reportsDir;

    @BeforeEach
    void setUp() {
        // PipelineReportWriter uses AppPaths.reportsDir() internally, but
        // updateChatHistory takes a Path argument directly, so we can test
        // it against any directory without touching AppPaths.
        writer = new PipelineReportWriter(mock(LeveledLogger.class));
        reportsDir = tempDir;
    }

    private Path writeStubReport(String filename, String originalChat) throws Exception {
        JsonObject root = new JsonObject();
        root.addProperty("reportVersion", "1.0.0");
        root.addProperty("stage1", "findings data");
        root.addProperty("stage2", "code correlation");
        root.addProperty("stage5_finalVerdict", "verdict data");

        JsonArray chatArr = new JsonArray();
        JsonObject msg = new JsonObject();
        msg.addProperty("role", "assistant");
        msg.addProperty("content", originalChat);
        chatArr.add(msg);
        root.add("stage6_chatHistory", chatArr);

        Path file = reportsDir.resolve(filename);
        Files.writeString(file, root.toString());
        return file;
    }

    @Test
    void updateChatHistoryReplacesStage6AndPreservesOtherStages() throws Exception {
        Path file = writeStubReport("report.json", "initial analysis response");

        List<Object> newChat = List.of(
                Map.of("role", "assistant", "content", "initial analysis response"),
                Map.of("role", "user", "content", "追问：这个漏洞怎么利用？"),
                Map.of("role", "assistant", "content", "利用方式：...")
        );

        boolean ok = writer.updateChatHistory(file, newChat);

        assertThat(ok).isTrue();

        JsonObject updated = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
        // Other stages preserved
        assertThat(updated.get("stage1").getAsString()).isEqualTo("findings data");
        assertThat(updated.get("stage2").getAsString()).isEqualTo("code correlation");
        assertThat(updated.get("stage5_finalVerdict").getAsString()).isEqualTo("verdict data");

        // stage6_chatHistory replaced with new content
        JsonArray chat = updated.getAsJsonArray("stage6_chatHistory");
        assertThat(chat.size()).isEqualTo(3);
        assertThat(chat.get(1).getAsJsonObject().get("role").getAsString()).isEqualTo("user");
        assertThat(chat.get(1).getAsJsonObject().get("content").getAsString())
                .isEqualTo("追问：这个漏洞怎么利用？");
    }

    @Test
    void updateChatHistoryReturnsFalseWhenFileMissing() {
        Path missing = reportsDir.resolve("does-not-exist.json");
        boolean ok = writer.updateChatHistory(missing, List.of(Map.of("role", "user", "content", "q")));
        assertThat(ok).isFalse();
    }

    @Test
    void updateChatHistoryReturnsFalseWhenReportPathNull() {
        boolean ok = writer.updateChatHistory(null, List.of(Map.of("role", "user", "content", "q")));
        assertThat(ok).isFalse();
    }

    @Test
    void updateChatHistoryAcceptsEmptyListAsNoOp() throws Exception {
        Path file = writeStubReport("report.json", "initial");

        boolean ok = writer.updateChatHistory(file, List.of());

        assertThat(ok).isTrue();
        // Original content untouched
        JsonObject root = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
        JsonArray chat = root.getAsJsonArray("stage6_chatHistory");
        assertThat(chat.size()).isEqualTo(1);
        assertThat(chat.get(0).getAsJsonObject().get("content").getAsString()).isEqualTo("initial");
    }

    @Test
    void updateChatHistoryWorksWithMultipleSuccessiveFollowUps() throws Exception {
        Path file = writeStubReport("report.json", "initial");

        // First follow-up
        writer.updateChatHistory(file, List.of(
                Map.of("role", "assistant", "content", "initial"),
                Map.of("role", "user", "content", "Q1"),
                Map.of("role", "assistant", "content", "A1")
        ));

        // Second follow-up — should overwrite the whole stage6, not append
        writer.updateChatHistory(file, List.of(
                Map.of("role", "assistant", "content", "initial"),
                Map.of("role", "user", "content", "Q1"),
                Map.of("role", "assistant", "content", "A1"),
                Map.of("role", "user", "content", "Q2"),
                Map.of("role", "assistant", "content", "A2")
        ));

        JsonObject root = JsonParser.parseString(Files.readString(file)).getAsJsonObject();
        JsonArray chat = root.getAsJsonArray("stage6_chatHistory");
        assertThat(chat.size()).isEqualTo(5);
        assertThat(chat.get(4).getAsJsonObject().get("content").getAsString()).isEqualTo("A2");
    }
}
