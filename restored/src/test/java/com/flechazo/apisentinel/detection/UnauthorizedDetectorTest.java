package com.flechazo.apisentinel.detection;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class UnauthorizedDetectorTest {

    // Access the private bodySimilarity via reflection to lock in the Jaccard
    // behavior (the old positional compare returned ~0 for reordered JSON).
    private static double similarity(String a, String b) throws Exception {
        var d = new UnauthorizedDetector(null, null, null, null, null);
        Method m = UnauthorizedDetector.class.getDeclaredMethod("bodySimilarity", String.class, String.class);
        m.setAccessible(true);
        return (double) m.invoke(d, a, b);
    }

    @Test
    void identicalBodies_scoreOne() throws Exception {
        assertEquals(1.0, similarity("{\"id\":1,\"name\":\"x\"}", "{\"id\":1,\"name\":\"x\"}"));
    }

    @Test
    void reorderedJson_staysHighSimilarity() throws Exception {
        // Positional char compare would tank here; Jaccard stays high.
        double s = similarity("{\"id\":1,\"name\":\"alice\"}", "{\"name\":\"alice\",\"id\":1}");
        assertTrue(s > 0.6, "reordered JSON should remain similar, got " + s);
    }

    @Test
    void differentBodies_lowSimilarity() throws Exception {
        double s = similarity("total success everything is fine", "error: unauthorized access denied");
        assertTrue(s < 0.4, "different bodies should be dissimilar, got " + s);
    }
}
