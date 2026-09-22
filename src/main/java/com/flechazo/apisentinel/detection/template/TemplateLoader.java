package com.flechazo.apisentinel.detection.template;

import com.flechazo.apisentinel.logging.LeveledLogger;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 自定义检测模板加载器
 *
 * 从指定目录加载 YAML 模板，支持：
 * - 自动发现和加载 *.yaml / *.yml 文件
 * - 按 ID 索引模板
 * - 按标签过滤模板
 * - 热重载（开发模式）
 *
 * @since 1.2.0
 */
public class TemplateLoader {

    private final Path templateDir;
    private final LeveledLogger logger;
    private final Map<String, DetectionTemplate> templatesById = new HashMap<>();
    private final Map<String, List<DetectionTemplate>> templatesByTag = new HashMap<>();

    public TemplateLoader(Path templateDir, LeveledLogger logger) {
        this.templateDir = templateDir;
        this.logger = logger;
    }

    /**
     * 加载所有模板
     *
     * @return 加载的模板数量
     */
    public int loadAll() {
        if (templateDir == null || !Files.isDirectory(templateDir)) {
            logger.warn("[TemplateLoader] Template directory does not exist: %s", templateDir);
            return 0;
        }

        templatesById.clear();
        templatesByTag.clear();

        int loaded = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(templateDir, "*.{yaml,yml}")) {
            for (Path file : stream) {
                try {
                    DetectionTemplate template = TemplateParser.parse(file);
                    if (template.isValid()) {
                        templatesById.put(template.id(), template);
                        // Index by tags
                        if (template.tags() != null) {
                            for (String tag : template.tags()) {
                                templatesByTag.computeIfAbsent(tag, k -> new ArrayList<>())
                                        .add(template);
                            }
                        }
                        loaded++;
                        logger.debug("[TemplateLoader] Loaded: %s", template.summary());
                    } else {
                        logger.warn("[TemplateLoader] Invalid template: %s", file.getFileName());
                    }
                } catch (Exception e) {
                    logger.error("[TemplateLoader] Failed to parse %s: %s",
                            file.getFileName(), e.getMessage());
                }
            }
        } catch (IOException e) {
            logger.error("[TemplateLoader] Failed to scan directory: %s", e.getMessage());
        }

        logger.debug("[TemplateLoader] Loaded %d templates from %s", loaded, templateDir);
        return loaded;
    }

    /**
     * 根据 ID 获取模板
     */
    public DetectionTemplate getById(String id) {
        return templatesById.get(id);
    }

    /**
     * 根据标签获取模板
     */
    public List<DetectionTemplate> getByTag(String tag) {
        return templatesByTag.getOrDefault(tag, Collections.emptyList());
    }

    /**
     * 根据严重性过滤模板
     */
    public List<DetectionTemplate> getBySeverity(String severity) {
        List<DetectionTemplate> result = new ArrayList<>();
        for (DetectionTemplate t : templatesById.values()) {
            if (severity.equalsIgnoreCase(t.severity())) {
                result.add(t);
            }
        }
        return result;
    }

    /**
     * 获取所有模板
     */
    public List<DetectionTemplate> getAll() {
        return new ArrayList<>(templatesById.values());
    }

    /**
     * 获取所有标签
     */
    public List<String> getAllTags() {
        return new ArrayList<>(templatesByTag.keySet());
    }

    /**
     * 获取统计信息
     */
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total", templatesById.size());
        stats.put("tags", templatesByTag.size());

        Map<String, Integer> bySeverity = new HashMap<>();
        for (DetectionTemplate t : templatesById.values()) {
            bySeverity.merge(t.severity(), 1, Integer::sum);
        }
        stats.put("by_severity", bySeverity);

        return stats;
    }

    /**
     * 热重载（开发模式）
     */
    public void reload() {
        logger.debug("[TemplateLoader] Reloading templates...");
        loadAll();
    }
}
