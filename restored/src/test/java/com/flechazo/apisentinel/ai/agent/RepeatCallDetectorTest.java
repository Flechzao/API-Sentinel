package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.provider.ToolCall;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for the generic stuck-loop guard used by AgentLoop. */
class RepeatCallDetectorTest {

    private static ToolCall call(String name, String args) {
        return new ToolCall("id-" + name, name, args);
    }

    @Test
    void countsConsecutiveIdenticalBatches() {
        RepeatCallDetector d = new RepeatCallDetector();
        assertThat(d.record(List.of(call("read_file", "{\"path\":\"a\"}")))).isEqualTo(1);
        assertThat(d.record(List.of(call("read_file", "{\"path\":\"a\"}")))).isEqualTo(2);
        assertThat(d.record(List.of(call("read_file", "{\"path\":\"a\"}")))).isEqualTo(3);
    }

    @Test
    void resetsWhenBatchChanges() {
        RepeatCallDetector d = new RepeatCallDetector();
        d.record(List.of(call("read_file", "{\"path\":\"a\"}")));
        d.record(List.of(call("read_file", "{\"path\":\"a\"}")));
        assertThat(d.record(List.of(call("read_file", "{\"path\":\"b\"}")))).isEqualTo(1);
        assertThat(d.record(List.of(call("read_file", "{\"path\":\"b\"}")))).isEqualTo(2);
    }

    @Test
    void differentCallOrderIsStillTheSameBatch() {
        // Mere reordering of the same calls is not progress.
        RepeatCallDetector d = new RepeatCallDetector();
        d.record(List.of(call("read_file", "{}"), call("grep_repo", "{}")));
        assertThat(d.record(List.of(call("grep_repo", "{}"), call("read_file", "{}")))).isEqualTo(2);
    }

    @Test
    void toolUseIdsDoNotAffectSignature() {
        // The model picks fresh tool_use ids every turn — detection must key
        // on tool name + arguments only.
        RepeatCallDetector d = new RepeatCallDetector();
        d.record(List.of(new ToolCall("id-1", "read_file", "{}")));
        assertThat(d.record(List.of(new ToolCall("id-2", "read_file", "{}")))).isEqualTo(2);
    }

    @Test
    void argumentsParticipateInSignature() {
        // Legitimate retry patterns (e.g. sending payloads one at a time)
        // differ by arguments and must NOT trip the breaker.
        RepeatCallDetector d = new RepeatCallDetector();
        d.record(List.of(call("send_request", "{\"path\":\"/a\"}")));
        assertThat(d.record(List.of(call("send_request", "{\"path\":\"/b\"}")))).isEqualTo(1);
    }

    @Test
    void emptyBatchHasItsOwnSignature() {
        RepeatCallDetector d = new RepeatCallDetector();
        assertThat(d.record(List.of())).isEqualTo(1);
        assertThat(d.record(List.of())).isEqualTo(2);
    }
}
