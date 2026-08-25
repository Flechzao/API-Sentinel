package com.flechazo.apisentinel.codeindex.parser;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public interface RouteParser {

    Set<String> supportedFrameworks();

    Set<String> supportedExtensions();

    boolean canParse(Path filePath);

    List<RouteEntry> parseFile(Path filePath, String content);
}
