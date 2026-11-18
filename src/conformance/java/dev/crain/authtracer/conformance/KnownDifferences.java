package dev.crain.authtracer.conformance;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Disagreements between a graph and Spring that are understood, from {@code known-differences.tsv}: each line is a
 * fixture, an endpoint ({@code GET /path}, or {@code *} for all of the fixture's), a probe label prefix (or
 * {@code *}) and why the graph and Spring differ there. Blank lines and {@code #} comments are skipped.
 */
final class KnownDifferences {

    record Entry(String fixture, String endpoint, String probe, String reason) {

        boolean matches(Expectation expectation, Callers.Probe probe) {
            return fixture.equals(expectation.fixture())
                    && (endpoint.equals("*") || endpoint.equals(expectation.endpoint()))
                    && (this.probe.equals("*") || probe.label().startsWith(this.probe));
        }
    }

    private final List<Entry> entries;
    private final Set<Entry> used = new LinkedHashSet<>();

    private KnownDifferences(List<Entry> entries) {
        this.entries = entries;
    }

    static KnownDifferences load() throws IOException {
        List<Entry> entries = new ArrayList<>();
        try (InputStream in = KnownDifferences.class.getResourceAsStream("/known-differences.tsv")) {
            if (in == null) {
                return new KnownDifferences(entries);
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] cells = line.split("\t", 4);
                if (cells.length < 4) {
                    throw new IllegalStateException("known-differences.tsv: needs 4 tab-separated cells: " + line);
                }
                entries.add(new Entry(cells[0], cells[1], cells[2], cells[3]));
            }
        }
        return new KnownDifferences(entries);
    }

    /**
     * The entry that explains a disagreement on this probe, or {@code null}.
     */
    synchronized Entry find(Expectation expectation, Callers.Probe probe) {
        for (Entry entry : entries) {
            if (entry.matches(expectation, probe)) {
                used.add(entry);
                return entry;
            }
        }
        return null;
    }

    /**
     * Entries that explained nothing in this run: fixed, or their fixture didn't boot.
     */
    synchronized List<Entry> unused() {
        return entries.stream().filter(entry -> !used.contains(entry)).toList();
    }
}
