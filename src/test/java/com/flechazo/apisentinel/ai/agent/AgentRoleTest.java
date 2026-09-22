package com.flechazo.apisentinel.ai.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AgentRole 枚举单元测试
 *
 * @since 1.2.0
 */
class AgentRoleTest {

    @Test
    void allRoles_haveDescription() {
        for (AgentRole role : AgentRole.values()) {
            assertNotNull(role.description());
            assertFalse(role.description().isEmpty());
        }
    }

    @Test
    void planner_isReadOnly() {
        assertTrue(AgentRole.PLANNER.isReadOnly());
    }

    @Test
    void planner_cannotSendRequests() {
        assertFalse(AgentRole.PLANNER.canSendRequests());
    }

    @Test
    void explorer_isReadOnly() {
        assertTrue(AgentRole.EXPLORER.isReadOnly());
    }

    @Test
    void explorer_cannotSendRequests() {
        assertFalse(AgentRole.EXPLORER.canSendRequests());
    }

    @Test
    void executor_isNotReadOnly() {
        assertFalse(AgentRole.EXECUTOR.isReadOnly());
    }

    @Test
    void executor_canSendRequests() {
        assertTrue(AgentRole.EXECUTOR.canSendRequests());
    }

    @Test
    void verifier_isNotReadOnly() {
        assertFalse(AgentRole.VERIFIER.isReadOnly());
    }

    @Test
    void verifier_canSendRequests() {
        assertTrue(AgentRole.VERIFIER.canSendRequests());
    }

    @Test
    void exactlyFourRoles() {
        assertEquals(4, AgentRole.values().length);
    }

    @Test
    void valueOf_works() {
        assertEquals(AgentRole.PLANNER, AgentRole.valueOf("PLANNER"));
        assertEquals(AgentRole.EXPLORER, AgentRole.valueOf("EXPLORER"));
        assertEquals(AgentRole.EXECUTOR, AgentRole.valueOf("EXECUTOR"));
        assertEquals(AgentRole.VERIFIER, AgentRole.valueOf("VERIFIER"));
    }

    @Test
    void valueOf_invalidName_throws() {
        assertThrows(IllegalArgumentException.class, () -> {
            AgentRole.valueOf("INVALID_ROLE");
        });
    }

    @Test
    void readOnlyRoles_arePlannerAndExplorer() {
        int readOnlyCount = 0;
        for (AgentRole role : AgentRole.values()) {
            if (role.isReadOnly()) {
                readOnlyCount++;
                assertTrue(role == AgentRole.PLANNER || role == AgentRole.EXPLORER,
                        "只有 PLANNER 和 EXPLORER 应该是只读的");
            }
        }
        assertEquals(2, readOnlyCount, "应该有 2 个只读角色");
    }

    @Test
    void canSendRequestsRoles_areExecutorAndVerifier() {
        int canSendCount = 0;
        for (AgentRole role : AgentRole.values()) {
            if (role.canSendRequests()) {
                canSendCount++;
                assertTrue(role == AgentRole.EXECUTOR || role == AgentRole.VERIFIER,
                        "只有 EXECUTOR 和 VERIFIER 应该能发送请求");
            }
        }
        assertEquals(2, canSendCount, "应该有 2 个可发送请求的角色");
    }

    @Test
    void planner_descriptionMentionsPlanning() {
        assertTrue(AgentRole.PLANNER.description().contains("规划") ||
                AgentRole.PLANNER.description().toLowerCase().contains("plan"));
    }

    @Test
    void explorer_descriptionMentionsExploration() {
        assertTrue(AgentRole.EXPLORER.description().contains("探索") ||
                AgentRole.EXPLORER.description().toLowerCase().contains("explor"));
    }

    @Test
    void executor_descriptionMentionsExecution() {
        assertTrue(AgentRole.EXECUTOR.description().contains("执行") ||
                AgentRole.EXECUTOR.description().toLowerCase().contains("execut"));
    }

    @Test
    void verifier_descriptionMentionsVerification() {
        assertTrue(AgentRole.VERIFIER.description().contains("验证") ||
                AgentRole.VERIFIER.description().toLowerCase().contains("verif"));
    }

    @Test
    void ordinal_consistentOrder() {
        // 验证角色的顺序
        assertEquals(0, AgentRole.PLANNER.ordinal());
        assertEquals(1, AgentRole.EXPLORER.ordinal());
        assertEquals(2, AgentRole.EXECUTOR.ordinal());
        assertEquals(3, AgentRole.VERIFIER.ordinal());
    }

    @Test
    void readOnlyAndCanSendRequests_areMutuallyExclusive() {
        for (AgentRole role : AgentRole.values()) {
            // 一个角色不应该同时是只读且能发送请求
            assertFalse(role.isReadOnly() && role.canSendRequests(),
                    "角色 " + role + " 不应该同时是只读且能发送请求");
        }
    }
}
