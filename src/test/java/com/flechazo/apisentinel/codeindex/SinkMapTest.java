package com.flechazo.apisentinel.codeindex;

import com.flechazo.apisentinel.config.CodeRepo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SinkMapTest {

    @TempDir
    Path tempDir;

    @Test
    void scanFindsSQL_sinks() throws IOException {
        Path javaFile = tempDir.resolve("UserDao.java");
        Files.writeString(javaFile, """
                public class UserDao {
                    public User findById(Long id) {
                        String sql = "SELECT * FROM user WHERE id=" + id;
                        return jdbcTemplate.query(sql, mapper);
                    }
                }
                """);

        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        SinkMap map = SinkMap.scan(List.of(repo), null);

        assertThat(map.totalSinkCount()).isGreaterThanOrEqualTo(2);
        assertThat(map.hasSinks("UserDao")).isTrue();
        List<SinkMap.SinkEntry> sinks = map.sinksInClass("UserDao");
        assertThat(sinks).anyMatch(s -> s.type() == SinkMap.SinkType.SQL);
    }

    @Test
    void scanFindsCommand_sinks() throws IOException {
        Path javaFile = tempDir.resolve("CmdService.java");
        Files.writeString(javaFile, """
                public class CmdService {
                    public void run(String cmd) {
                        Runtime.getRuntime().exec(cmd);
                    }
                }
                """);

        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        SinkMap map = SinkMap.scan(List.of(repo), null);

        assertThat(map.hasSinks("CmdService")).isTrue();
        assertThat(map.sinksInClass("CmdService"))
                .anyMatch(s -> s.type() == SinkMap.SinkType.COMMAND);
    }

    @Test
    void scanFindsSSRF_sinks() throws IOException {
        Path javaFile = tempDir.resolve("HttpClient.java");
        Files.writeString(javaFile, """
                public class HttpClient {
                    public String fetch(String url) {
                        URL u = new URL(url + "/api");
                        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                        return read(conn);
                    }
                }
                """);

        CodeRepo repo = new CodeRepo("test", tempDir.toString(), List.of());
        SinkMap map = SinkMap.scan(List.of(repo), null);

        assertThat(map.hasSinks("HttpClient")).isTrue();
        assertThat(map.sinksInClass("HttpClient"))
                .anyMatch(s -> s.type() == SinkMap.SinkType.SSRF);
    }

    @Test
    void emptyRepoReturnsEmptyMap() {
        SinkMap map = SinkMap.scan(List.of(), null);
        assertThat(map.totalSinkCount()).isZero();
    }

    @Test
    void hasSinksReturnsFalseForUnknownClass() {
        SinkMap map = SinkMap.empty();
        assertThat(map.hasSinks("NonExistent")).isFalse();
        assertThat(map.sinksInClass("NonExistent")).isEmpty();
    }
}
