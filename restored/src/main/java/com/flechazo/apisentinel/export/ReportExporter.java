package com.flechazo.apisentinel.export;

import com.flechazo.apisentinel.model.ApiEntry;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public interface ReportExporter {

    void export(List<ApiEntry> entries, Path outputPath) throws IOException;

    String getFileExtension();

    String getDescription();
}
