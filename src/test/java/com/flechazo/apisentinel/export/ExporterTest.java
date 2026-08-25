package com.flechazo.apisentinel.export;

import com.flechazo.apisentinel.model.ApiEntry;
import com.flechazo.apisentinel.model.ApiStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExporterTest {

    @TempDir
    Path tempDir;

    @Test
    void csvContainsUtf8Bom() throws Exception {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.setDomain("example.com");
        Path out = tempDir.resolve("test.csv");

        new CsvExporter().export(List.of(entry), out);

        byte[] bytes = Files.readAllBytes(out);
        assertEquals((byte) 0xEF, bytes[0]);
        assertEquals((byte) 0xBB, bytes[1]);
        assertEquals((byte) 0xBF, bytes[2]);

        String content = Files.readString(out);
        assertTrue(content.contains("/api/test"));
    }

    @Test
    void csvEscapesCommasAndQuotes() throws Exception {
        ApiEntry entry = new ApiEntry("POST", "/api/data");
        entry.setNote("value with, comma and \"quotes\"");
        Path out = tempDir.resolve("test.csv");

        new CsvExporter().export(List.of(entry), out);

        String content = Files.readString(out);
        assertTrue(content.contains("\"value with, comma and \"\"quotes\"\"\""));
    }

    @Test
    void markdownEscapesPipeCharacter() throws Exception {
        ApiEntry entry = new ApiEntry("GET", "/api/a|b");
        entry.setNote("note with | pipe");
        entry.setDomain("example.com");
        Path out = tempDir.resolve("test.md");

        new MarkdownExporter().export(List.of(entry), out);

        String content = Files.readString(out);
        assertTrue(content.contains("\\|"));
        assertFalse(content.contains("| note with | pipe |"));
    }

    @Test
    void markdownEscapesNewlines() throws Exception {
        ApiEntry entry = new ApiEntry("GET", "/api/test");
        entry.setNote("line1\nline2");
        entry.setDomain("example.com");
        Path out = tempDir.resolve("test.md");

        new MarkdownExporter().export(List.of(entry), out);

        String content = Files.readString(out);
        assertFalse(content.contains("line1\nline2"));
        assertTrue(content.contains("line1 line2"));
    }
}
