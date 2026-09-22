package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.browser.BrowserService.*;
import com.flechazo.apisentinel.browser.PageLocator.CandidatePage;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for BrowserService record types and data structures.
 * These tests don't require a browser — they validate the record contracts.
 */
class BrowserServiceRecordsTest {

    // ========== BrowserAction ==========

    @Test
    void browserAction_clickAction() {
        var action = new BrowserAction("click", "button.submit", null, 5000, null, 0);

        assertThat(action.type()).isEqualTo("click");
        assertThat(action.selector()).isEqualTo("button.submit");
        assertThat(action.value()).isNull();
        assertThat(action.timeoutMs()).isEqualTo(5000);
    }

    @Test
    void browserAction_fillAction() {
        var action = new BrowserAction("fill", "input[name='email']", "test@example.com", 0, null, 0);

        assertThat(action.type()).isEqualTo("fill");
        assertThat(action.selector()).isEqualTo("input[name='email']");
        assertThat(action.value()).isEqualTo("test@example.com");
    }

    @Test
    void browserAction_waitForRequestAction() {
        var action = new BrowserAction("wait_for_request", null, null, 10000, "*/api/orders*", 0);

        assertThat(action.type()).isEqualTo("wait_for_request");
        assertThat(action.urlPattern()).isEqualTo("*/api/orders*");
        assertThat(action.selector()).isNull();
    }

    @Test
    void browserAction_typeActionWithDelay() {
        var action = new BrowserAction("type", "#search", "query text", 0, null, 50);

        assertThat(action.type()).isEqualTo("type");
        assertThat(action.delayMs()).isEqualTo(50);
    }

    // ========== ActionResult ==========

    @Test
    void actionResult_success() {
        var result = new ActionResult(1, "click", true, "Clicked: button", null);

        assertThat(result.step()).isEqualTo(1);
        assertThat(result.type()).isEqualTo("click");
        assertThat(result.success()).isTrue();
        assertThat(result.capturedRequest()).isNull();
    }

    @Test
    void actionResult_withCapturedRequest() {
        var captured = new CapturedRequest("POST", "/api/orders",
                Map.of("Authorization", "Bearer token123"), "{\"item\":\"test\"}",
                201, "{\"id\":42}");
        var result = new ActionResult(3, "wait_for_request", true,
                "Request captured", captured);

        assertThat(result.success()).isTrue();
        assertThat(result.capturedRequest()).isNotNull();
        assertThat(result.capturedRequest().method()).isEqualTo("POST");
        assertThat(result.capturedRequest().headers()).containsEntry("Authorization", "Bearer token123");
    }

    // ========== InteractionResult ==========

    @Test
    void interactionResult_successWithCapturedRequest() {
        var actions = List.of(
                new ActionResult(1, "wait_for", true, "Element found", null),
                new ActionResult(2, "fill", true, "Filled input", null),
                new ActionResult(3, "click", true, "Clicked submit", null));
        var captured = new CapturedRequest("POST", "/api/orders",
                Map.of("X-CSRF-Token", "abc123"), "{}", 200, "{}");
        var result = new InteractionResult(true, actions, captured,
                "http://localhost:3000/orders/42", "Executed 3/3 actions");

        assertThat(result.success()).isTrue();
        assertThat(result.actionResults()).hasSize(3);
        assertThat(result.capturedRequest()).isNotNull();
        assertThat(result.currentUrl()).isEqualTo("http://localhost:3000/orders/42");
    }

    @Test
    void interactionResult_partialFailure() {
        var actions = List.of(
                new ActionResult(1, "fill", true, "Filled", null),
                new ActionResult(2, "click", false, "Click failed: button not found", null));
        var result = new InteractionResult(true, actions, null,
                "http://localhost:3000/form", "Executed 2/3 actions");

        assertThat(result.actionResults()).hasSize(2);
        assertThat(result.actionResults().get(1).success()).isFalse();
        assertThat(result.capturedRequest()).isNull();
    }

    // ========== PageLocationResult ==========

    @Test
    void pageLocationResult_found() {
        var candidates = List.of(
                new CandidatePage("http://localhost:3000/orders/new", "high", "JS bundle match"),
                new CandidatePage("http://localhost:3000/orders", "medium", "Path inference"));
        var result = new PageLocationResult(true, "js_bundle", candidates, "Found 2 candidates");

        assertThat(result.found()).isTrue();
        assertThat(result.strategy()).isEqualTo("js_bundle");
        assertThat(result.candidates()).hasSize(2);
    }

    @Test
    void pageLocationResult_notFound() {
        var result = new PageLocationResult(false, "none", List.of(), "No candidates");

        assertThat(result.found()).isFalse();
        assertThat(result.candidates()).isEmpty();
    }

    // ========== CapturedRequest ==========

    @Test
    void capturedRequest_containsAuthHeaders() {
        var headers = Map.of(
                "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9...",
                "X-CSRF-Token", "csrf-abc-123",
                "Cookie", "session=sess-xyz-789");
        var request = new CapturedRequest("POST", "/api/v1/orders",
                headers, "{\"product\":\"widget\",\"qty\":2}",
                201, "{\"id\":42,\"status\":\"created\"}");

        assertThat(request.headers()).containsKey("Authorization");
        assertThat(request.headers()).containsKey("X-CSRF-Token");
        assertThat(request.headers()).containsKey("Cookie");
        assertThat(request.responseStatus()).isEqualTo(201);
    }
}
