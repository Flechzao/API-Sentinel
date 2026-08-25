package com.flechazo.apisentinel.detection;

import com.flechazo.apisentinel.config.AppConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OobServiceTest {

    @Test
    void disabledByDefault_returnsNullPayload() {
        AppConfig cfg = new AppConfig(); // oobEnabled=false
        OobService svc = new OobService(null, cfg, null);
        assertFalse(svc.isEnabled());
        assertNull(svc.generatePayload());
    }

    @Test
    void internalRequiresBaseDomain() {
        AppConfig cfg = new AppConfig();
        cfg.setOobEnabled(true);
        cfg.setOobProvider("internal");
        // no base domain → not usable, no payload
        OobService svc = new OobService(null, cfg, null);
        assertFalse(svc.isEnabled());
        assertNull(svc.generatePayload());
    }

    @Test
    void internalGeneratesSubdomainWhenConfigured() {
        AppConfig cfg = new AppConfig();
        cfg.setOobEnabled(true);
        cfg.setOobProvider("internal");
        cfg.setOobInternalBaseDomain("xxx.dnslog.cn");
        OobService svc = new OobService(null, cfg, null);
        assertTrue(svc.isEnabled());
        String probe = svc.generatePayload();
        assertNotNull(probe);
        assertTrue(probe.endsWith(".xxx.dnslog.cn"), "probe should be a subdomain of the base, got " + probe);
        // Two probes differ (unique)
        assertNotEquals(probe, svc.generatePayload());
    }

    @Test
    void internalTestConnection_noUrl_reportsConfigured() throws Exception {
        AppConfig cfg = new AppConfig();
        cfg.setOobEnabled(true);
        cfg.setOobProvider("internal");
        cfg.setOobInternalBaseDomain("xxx.dnslog.cn");
        OobService svc = new OobService(null, cfg, null);
        var result = svc.testConnection().get();
        assertTrue(result.success, result.message);
        assertNotNull(result.samplePayload);
    }

    @Test
    void internalTestConnection_missingBase_fails() throws Exception {
        AppConfig cfg = new AppConfig();
        cfg.setOobEnabled(true);
        cfg.setOobProvider("internal");
        // base domain empty
        OobService svc = new OobService(null, cfg, null);
        var result = svc.testConnection().get();
        assertFalse(result.success);
        assertTrue(result.message.contains("基础域名") || result.message.toLowerCase().contains("base"));
    }

    @Test
    void providerNormalization() {
        AppConfig cfg = new AppConfig();
        cfg.setOobProvider("weird");
        assertEquals("collaborator", cfg.getOobProvider());
        cfg.setOobProvider("INTERNAL");
        assertEquals("internal", cfg.getOobProvider());
    }
}
