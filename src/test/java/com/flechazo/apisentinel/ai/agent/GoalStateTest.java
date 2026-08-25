package com.flechazo.apisentinel.ai.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * GoalState guards the Controller-level cascade (P2): session budget and the
 * blocked breaker (consecutive fruitless cascades). Pure logic — no index,
 * no EventBus.
 */
class GoalStateTest {

    @Test
    void budgetCapsTotalQueuedEndpoints() {
        GoalState g = new GoalState();
        assertThat(g.shouldCascade()).isTrue();

        assertThat(g.grantQuota(30)).isEqualTo(30);
        assertThat(g.getTotalQueued()).isEqualTo(30);
        // Remaining budget shrinks the next batch, then dries up entirely.
        assertThat(g.grantQuota(30)).isEqualTo(20);
        assertThat(g.grantQuota(5)).isZero();
        assertThat(g.shouldCascade()).isFalse();
    }

    @Test
    void blockedBreakerTripsAfterThreeConsecutiveFruitlessCascades() {
        GoalState g = new GoalState();

        // First two fruitless outcomes: streak builds, breaker not yet tripped.
        assertThat(g.recordCascadeOutcome(false)).isFalse();
        assertThat(g.recordCascadeOutcome(false)).isFalse();
        assertThat(g.isBlocked()).isFalse();
        assertThat(g.shouldCascade()).isTrue();

        // Third fruitless outcome trips it — exactly once.
        assertThat(g.recordCascadeOutcome(false)).isTrue();
        assertThat(g.isBlocked()).isTrue();
        assertThat(g.shouldCascade()).isFalse();
        // Already blocked: further outcomes never re-trip.
        assertThat(g.recordCascadeOutcome(false)).isFalse();

        // Blocked store grants nothing even with budget left.
        assertThat(g.grantQuota(10)).isZero();
    }

    @Test
    void newFindingResetsTheBlockedStreak() {
        GoalState g = new GoalState();

        assertThat(g.recordCascadeOutcome(false)).isFalse();
        assertThat(g.recordCascadeOutcome(false)).isFalse();
        // A hit resets the streak — two more fruitless rounds stay under the
        // threshold, so the breaker must NOT trip.
        assertThat(g.recordCascadeOutcome(true)).isFalse();
        assertThat(g.recordCascadeOutcome(false)).isFalse();
        assertThat(g.recordCascadeOutcome(false)).isFalse();
        assertThat(g.isBlocked()).isFalse();
        assertThat(g.shouldCascade()).isTrue();
    }

    @Test
    void describeReflectsStateForUiAndLogs() {
        GoalState g = new GoalState();
        g.grantQuota(4);
        assertThat(g.describe()).contains("已入队 4/50").contains("0/3");

        g.recordCascadeOutcome(false);
        g.recordCascadeOutcome(false);
        g.recordCascadeOutcome(false);
        assertThat(g.describe()).contains("熔断");
    }
}
