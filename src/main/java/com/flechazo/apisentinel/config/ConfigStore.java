package com.flechazo.apisentinel.config;

import com.flechazo.apisentinel.logging.LeveledLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ConfigStore {

    // Derived from AppPaths so API_SENTINEL_HOME / -Dapi-sentinel.home overrides apply.
    private static final Path CONFIG_DIR = AppPaths.configDir();

    private final LeveledLogger logger;

    public ConfigStore(LeveledLogger logger) {
        this.logger = logger;
        ensureDir();
    }

    private void ensureDir() {
        try {
            Files.createDirectories(CONFIG_DIR);
        } catch (IOException e) {
            if (logger != null) logger.error("创建配置目录失败: %s", e.getMessage());
        }
    }

    public Path resolve(String filename) {
        return CONFIG_DIR.resolve(filename);
    }

    public String read(String filename) {
        Path file = resolve(filename);
        try {
            if (Files.exists(file)) {
                return Files.readString(file);
            }
        } catch (IOException e) {
            if (logger != null) logger.warn("读取配置失败 [%s]: %s", filename, e.getMessage());
        }
        return null;
    }

    public boolean write(String filename, String content) {
        Path file = resolve(filename);
        try {
            ensureDir();
            // P1-5: secrets (API keys, auth cookies in data.json) live in
            // the config dir; writing with 600 perms instead of the
            // umask-inherited 644 keeps them out of group/other read.
            AppPaths.writePrivate(file, content);
            if (logger != null) logger.debug("配置已保存: %s", filename);
            return true;
        } catch (IOException e) {
            if (logger != null) logger.error("保存配置失败 [%s]: %s", filename, e.getMessage());
            return false;
        }
    }

    public boolean exists(String filename) {
        return Files.exists(resolve(filename));
    }
}
