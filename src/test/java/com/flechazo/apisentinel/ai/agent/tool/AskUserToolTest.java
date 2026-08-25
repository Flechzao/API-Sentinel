package com.flechazo.apisentinel.ai.agent.tool;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract tests for ask_user: an unanswered question (no bridge / timeout /
 * skip) must NEVER abort the analysis — it returns answered:false so the
 * Agent proceeds autonomously. The badge/UI rendering itself lives in the
 * (EDT-bound) ChatInteractionBridge and is covered manually.
 */
class AskUserToolTest {

    private ToolContext ctx;
    private UserInteractionBridge bridge;
    private AskUserTool tool;

    @BeforeEach
    void setUp() {
        ctx = mock(ToolContext.class);
        bridge = mock(UserInteractionBridge.class);
        when(ctx.userInteractionBridge()).thenReturn(bridge);
        tool = new AskUserTool(ctx);
    }

    @Test
    void noBridgeReturnsUnansweredWithoutThrowing() {
        when(ctx.userInteractionBridge()).thenReturn(null);

        JsonObject json = JsonParser.parseString(
                tool.execute("{\"question\": \"这个密钥是公开的吗?\"}")).getAsJsonObject();

        assertThat(json.get("answered").getAsBoolean()).isFalse();
        assertThat(json.get("reason").getAsString()).contains("无交互界面");
    }

    @Test
    void forwardsQuestionContextAndOptionsToBridge() {
        when(bridge.askChoice(anyString(), anyString(), anyList(), anyLong())).thenReturn(0);

        tool.execute("{\"question\": \"选哪个?\", \"context\": \"已排除A\", \"options\": [\"A\", \"B\"]}");

        verify(bridge).askChoice(eq("选哪个?"), eq("已排除A"),
                eq(List.of("A", "B")), eq(AskUserTool.TIMEOUT_SECONDS));
    }

    @Test
    void chosenOptionIsEchoedBack() {
        when(bridge.askChoice(anyString(), anyString(), anyList(), anyLong())).thenReturn(1);

        JsonObject json = JsonParser.parseString(
                tool.execute("{\"question\": \"选哪个?\", \"options\": [\"A\", \"B\"]}")).getAsJsonObject();

        assertThat(json.get("answered").getAsBoolean()).isTrue();
        assertThat(json.get("choice").getAsString()).isEqualTo("B");
        assertThat(json.get("index").getAsInt()).isEqualTo(1);
    }

    @Test
    void timeoutOrSkipIsUnanswered() {
        when(bridge.askChoice(anyString(), anyString(), anyList(), anyLong())).thenReturn(null);

        JsonObject json = JsonParser.parseString(
                tool.execute("{\"question\": \"选哪个?\", \"options\": [\"A\"]}")).getAsJsonObject();

        assertThat(json.get("answered").getAsBoolean()).isFalse();
        assertThat(json.get("reason").getAsString()).contains("未响应");
    }

    @Test
    void emptyQuestionIsRejected() {
        JsonObject json = JsonParser.parseString(tool.execute("{\"question\": \"\"}")).getAsJsonObject();

        assertThat(json.get("answered").getAsBoolean()).isFalse();
        assertThat(json.get("reason").getAsString()).contains("empty");
    }

    @Test
    void optionsAreCappedAtSix() {
        when(bridge.askChoice(anyString(), anyString(), anyList(), anyLong())).thenReturn(0);

        tool.execute("{\"question\": \"选哪个?\", \"options\": ["
                + "\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\"]}");

        verify(bridge).askChoice(anyString(), anyString(),
                argThat((List<String> opts) -> opts.size() == 6), anyLong());
    }

    @Test
    void invalidJsonIsRejected() {
        JsonObject json = JsonParser.parseString(tool.execute("not-json")).getAsJsonObject();

        assertThat(json.get("answered").getAsBoolean()).isFalse();
        assertThat(json.get("reason").getAsString()).contains("invalid arguments");
    }
}
