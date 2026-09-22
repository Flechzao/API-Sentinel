package com.flechazo.apisentinel.browser;

import com.flechazo.apisentinel.model.ApiEntry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for DiscoveredApi record and conversion logic.
 */
class DiscoveredApiTest {

    @Test
    void toApiEntry_shouldCreateEntryWithCorrectMethodAndPath() {
        DiscoveredApi api = new DiscoveredApi("POST", "/api/users", "network", "", "", "http://target.com");

        ApiEntry entry = api.toApiEntry("example.com");

        assertThat(entry.getHttpMethod()).isEqualTo("POST");
        assertThat(entry.getApiPath()).isEqualTo("/api/users");
        assertThat(entry.getDomain()).isEqualTo("example.com");
    }

    @Test
    void toApiEntry_shouldIncludeSourceLabelInNote() {
        DiscoveredApi networkApi = DiscoveredApi.fromNetwork("GET", "/api/test", "", "", "http://page.com");
        DiscoveredApi jsApi = DiscoveredApi.fromJsBundle("GET", "/api/internal", "http://page.com");
        DiscoveredApi routerApi = DiscoveredApi.fromRouter("/admin", "http://page.com");

        assertThat(networkApi.toApiEntry("").getNote()).contains("network capture, untrusted");
        assertThat(jsApi.toApiEntry("").getNote()).contains("JS bundle, untrusted");
        assertThat(routerApi.toApiEntry("").getNote()).contains("frontend router, untrusted");
    }

    @Test
    void toApiEntry_shouldHandleNullMethod() {
        DiscoveredApi api = new DiscoveredApi(null, "/api/test", "network", "", "", "");

        ApiEntry entry = api.toApiEntry("");

        assertThat(entry.getHttpMethod()).isEqualTo("GET"); // Default to GET
    }

    @Test
    void fromNetwork_shouldSetSourceCorrectly() {
        DiscoveredApi api = DiscoveredApi.fromNetwork("PUT", "/api/update", "{\"id\":1}", "OK", "http://page.com");

        assertThat(api.source()).isEqualTo("network");
        assertThat(api.requestBody()).isEqualTo("{\"id\":1}");
        assertThat(api.responseSnippet()).isEqualTo("OK");
    }

    @Test
    void fromJsBundle_shouldHaveEmptyBodyAndResponse() {
        DiscoveredApi api = DiscoveredApi.fromJsBundle("DELETE", "/api/item/1", "http://page.com");

        assertThat(api.source()).isEqualTo("js_bundle");
        assertThat(api.requestBody()).isEmpty();
        assertThat(api.responseSnippet()).isEmpty();
    }

    @Test
    void fromRouter_shouldDefaultToGetMethod() {
        DiscoveredApi api = DiscoveredApi.fromRouter("/dashboard", "http://page.com");

        assertThat(api.method()).isEqualTo("GET");
        assertThat(api.source()).isEqualTo("router");
    }
}
