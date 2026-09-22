package com.demo.vulnapp.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Map;

/** #15 in GROUND_TRUTH.md — VULNERABLE: deserializes arbitrary user-supplied
 *  bytes via ObjectInputStream, a classic Java insecure-deserialization gadget-
 *  chain entry point (e.g. ysoserial payloads). */
@RestController
public class ImportController {

    @PostMapping(value = "/api/import", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<?> importData(@RequestBody byte[] data) {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
            return ResponseEntity.ok(Map.of("type", obj.getClass().getName(), "value", String.valueOf(obj)));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }
}
