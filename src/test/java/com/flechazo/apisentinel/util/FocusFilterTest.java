package com.flechazo.apisentinel.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FocusFilterTest {

    @Test
    void excludedMethod_matchesCaseInsensitive() {
        assertTrue(FocusFilter.isExcludedMethod("OPTIONS", "OPTIONS,HEAD"));
        assertTrue(FocusFilter.isExcludedMethod("head", "OPTIONS,HEAD"));
        assertFalse(FocusFilter.isExcludedMethod("GET", "OPTIONS,HEAD"));
        assertFalse(FocusFilter.isExcludedMethod("GET", null));
        assertFalse(FocusFilter.isExcludedMethod("GET", ""));
    }
}
