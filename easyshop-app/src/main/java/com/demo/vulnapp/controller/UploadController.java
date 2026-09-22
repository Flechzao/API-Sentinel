package com.demo.vulnapp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** #13 vulnerable (any extension) / #14 safe (whitelist + random name). */
@RestController
public class UploadController {

    private static final Path UPLOAD_DIR = Path.of(System.getProperty("java.io.tmpdir"), "vulnapp-uploads");
    private static final Set<String> SAFE_EXTENSIONS = Set.of("jpg", "jpeg", "png", "pdf", "txt");

    /** #13: VULNERABLE — no extension check, original filename kept as-is;
     *  uploading a .jsp/.php file succeeds. */
    @PostMapping("/api/upload")
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) throws IOException {
        Files.createDirectories(UPLOAD_DIR);
        String original = file.getOriginalFilename() != null ? file.getOriginalFilename() : "unnamed";
        Path dest = UPLOAD_DIR.resolve(original);
        file.transferTo(dest);
        return ResponseEntity.ok(Map.of("saved", dest.toString()));
    }

    /** #14: SAFE — extension whitelist + randomized stored filename. */
    @PostMapping("/api/upload-image")
    public ResponseEntity<?> uploadSafe(@RequestParam("file") MultipartFile file) throws IOException {
        String original = file.getOriginalFilename() != null ? file.getOriginalFilename() : "";
        String ext = original.contains(".") ? original.substring(original.lastIndexOf('.') + 1).toLowerCase() : "";
        if (!SAFE_EXTENSIONS.contains(ext)) {
            return ResponseEntity.status(400).body(Map.of("error", "extension not allowed: " + ext));
        }
        Files.createDirectories(UPLOAD_DIR);
        String randomName = UUID.randomUUID() + "." + ext;
        file.transferTo(UPLOAD_DIR.resolve(randomName));
        return ResponseEntity.ok(Map.of("saved", randomName));
    }
}
