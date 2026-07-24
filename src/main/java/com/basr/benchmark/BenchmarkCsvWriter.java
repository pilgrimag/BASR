package com.basr.benchmark;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Objects;

/**
 * Minimal UTF-8 CSV writer for benchmark raw data.
 */
final class BenchmarkCsvWriter implements AutoCloseable {

    private final BufferedWriter writer;
    private final int columnCount;

    BenchmarkCsvWriter(
            Path outputFile,
            List<String> header) throws IOException {

        Objects.requireNonNull(outputFile, "outputFile");
        Objects.requireNonNull(header, "header");

        if (header.isEmpty()) {
            throw new IllegalArgumentException(
                    "CSV header cannot be empty");
        }

        Path parent =
                outputFile.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        writer =
                Files.newBufferedWriter(
                        outputFile,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE);

        columnCount = header.size();
        writeValues(header.toArray());
    }

    void writeRow(
            Object... values) throws IOException {

        Objects.requireNonNull(values, "values");

        if (values.length != columnCount) {
            throw new IllegalArgumentException(
                    "Expected "
                            + columnCount
                            + " CSV columns, received "
                            + values.length);
        }

        writeValues(values);
    }

    private void writeValues(
            Object[] values) throws IOException {

        for (int index = 0;
             index < values.length;
             index++) {

            if (index > 0) {
                writer.write(',');
            }

            writer.write(
                    escape(values[index]));
        }

        writer.newLine();
    }

    private static String escape(
            Object value) {

        if (value == null) {
            return "";
        }

        String text = String.valueOf(value);

        boolean quote =
                text.indexOf(',') >= 0
                        || text.indexOf('"') >= 0
                        || text.indexOf('\n') >= 0
                        || text.indexOf('\r') >= 0;

        if (!quote) {
            return text;
        }

        return '"'
                + text.replace("\"", "\"\"")
                + '"';
    }

    @Override
    public void close() throws IOException {
        writer.close();
    }
}
