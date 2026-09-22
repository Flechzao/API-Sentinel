package com.flechazo.apisentinel.ai.agent;

import com.flechazo.apisentinel.ai.prompt.SafetyRules;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P2-2: cross-layer rule alignment. The Agent's condensed system prompt
 * ({@link SafetyRules#AGENT_CONDENSED_RULES}) compresses the 7-path
 * conditionally-valid upgrade table into one paragraph and drops the
 * structured table. D1 appends the full
 * {@link SafetyRules#CONDITIONALLY_VALID_PROMPT_TEXT} (the markdown table
 * form) to the Agent prompt too, so the Agent sees the same structured
 * escalation guidance the Pipeline mode gets — giving the LLM a clearer
 * framing for the {@code escalation_path} field that
 * {@link SafetyRules#hasChainEvidence} then reads back.
 */
class AgentLoopRulesAlignmentTest {

    @Test
    void condensedRules_dropTheStructuredTable_theGapD1Fixes() {
        // The condensed paragraph carries the 7 paths inline but does NOT
        // carry the markdown table form. This is the gap D1 closes.
        String condensed = SafetyRules.AGENT_CONDENSED_RULES;
        assertThat(condensed).doesNotContain("| 弱发现 | 需要的链 | 成立后等级 |");
    }

    @Test
    void fullUpgradeTable_carriesStructuredTable() {
        // The full table (now appended to the Agent prompt by D1) carries
        // the markdown table form with the chain-aligned vocabulary the
        // condensed paragraph lacks.
        String full = SafetyRules.CONDITIONALLY_VALID_PROMPT_TEXT;
        assertThat(full).contains("| 弱发现 | 需要的链 | 成立后等级 |");
        // Chain-aligned vocabulary the table makes explicit (matches
        // CHAIN_EVIDENCE_KEYWORDS entries the programmatic exemption reads).
        assertThat(full).contains("授权码");
        assertThat(full).contains("内网服务");
        assertThat(full).contains("PII");
    }

    @Test
    void agentSystemPrompt_nowIncludesStructuredUpgradeTable() throws Exception {
        // Wiring check: buildSystemPrompt() appends the full
        // conditionally-valid table after the condensed rules, so the Agent
        // sees the structured table the condensed paragraph omitted. The
        // condensed rules are still present (not replaced), and the table
        // header is now present too (the D1 fix). AgentLoop is constructed
        // with null deps — buildSystemPrompt uses none of them (only static
        // SafetyRules constants + the stateless cascadeInstruction() /
        // chainHuntingSection() helpers).
        AgentLoop loop = new AgentLoop(null, null, null, null, null, null, null);
        String prompt = loop.buildSystemPrompt();

        // Condensed rules still present (D1 appends, doesn't replace).
        assertThat(prompt).contains("误报抑制规则");
        // The structured upgrade table is now in the Agent prompt (the fix).
        assertThat(prompt).contains("| 弱发现 | 需要的链 | 成立后等级 |");
    }
}
