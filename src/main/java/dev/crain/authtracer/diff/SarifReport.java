package dev.crain.authtracer.diff;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.DiffReport.Change;
import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.DiffReport.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * A diff report as SARIF 2.1.0 (decision 0024), for GitHub code scanning's {@code upload-sarif} and other tools that
 * annotate pull requests: one result per change that fails the check or needs review, at the check that changed (or
 * the new endpoint's handler, or the finding), in the services whose source is at hand.
 */
@Supports(Feature.SARIF_ANNOTATIONS)
public final class SarifReport {

    private static final Logger log = LoggerFactory.getLogger(SarifReport.class);
    private static final JsonMapper JSON = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();
    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

    /**
     * What each kind means, and how GitHub ranks it ({@code security-severity}: 7 and up is high).
     */
    private static final Map<Kind, Rule> RULES = Map.of(
            Kind.WEAKENED, new Rule("Authorization weakened",
                    "A field or endpoint now keeps fewer callers out than before.", "8.1"),
            Kind.DIAGONAL_ESCALATION, new Rule("Diagonal escalation",
                    "A new route to data that asks less than every existing route to the same data.", "8.1"),
            Kind.POLICY_VIOLATION, new Rule("Data policy violated",
                    "A field with a governed label (e.g. PII), or an endpoint a policy names, is now exposed with less"
                            + " than its policy requires.", "8.1"),
            Kind.CHANGED, new Rule("Authorization changed",
                    "A requirement changed in a way that can't be ranked against the old one, e.g. one role for"
                            + " another.", "5.0"),
            Kind.NEW_FINDING, new Rule("New authorization finding",
                    "A new finding, e.g. a check that isn't enforced or a call path AuthTracer can't follow.", "5.0"));

    private record Rule(String name, String description, String securitySeverity) {
    }

    private SarifReport() {
    }

    /**
     * @param sources each service's project directory, for the services whose changes can be annotated
     */
    public static String write(DiffReport report, Map<String, Path> sources) {
        SourceFiles.ByService files = new SourceFiles.ByService(sources);
        List<Map<String, Object>> results = new ArrayList<>();
        int skipped = 0;
        for (Change change : report.changes()) {
            if (change.severity() == Severity.INFO) {
                continue;
            }
            Optional<SourceFiles.Location> location = files.locate(change.site());
            if (location.isEmpty()) {
                skipped++;
                continue;
            }
            results.add(result(change, location.get()));
        }
        if (skipped > 0) {
            log.info("{} changes are in code that isn't in the given sources; they are only in the diff report",
                    skipped);
        }
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "AuthTracer");
        driver.put("rules", RULES.keySet().stream().sorted().map(SarifReport::rule).toList());
        Map<String, Object> run = new LinkedHashMap<>();
        run.put("tool", Map.of("driver", driver));
        run.put("results", results);
        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("$schema", SCHEMA);
        sarif.put("version", "2.1.0");
        sarif.put("runs", List.of(run));
        return JSON.writeValueAsString(sarif);
    }

    private static Map<String, Object> rule(Kind kind) {
        Rule rule = RULES.get(kind);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", kind.name());
        out.put("name", rule.name().replace(" ", ""));
        out.put("shortDescription", Map.of("text", rule.name()));
        out.put("fullDescription", Map.of("text", rule.description()));
        out.put("defaultConfiguration", Map.of("level", level(kind.severity())));
        out.put("properties", Map.of("tags", List.of("security", "authorization"), "security-severity",
                rule.securitySeverity()));
        return out;
    }

    private static Map<String, Object> result(Change change, SourceFiles.Location location) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ruleId", change.kind().name());
        out.put("level", level(change.severity()));
        out.put("message", Map.of("text", message(change)));
        out.put("locations", List.of(Map.of("physicalLocation", Map.of(
                "artifactLocation", Map.of("uri", location.uri()),
                "region", Map.of("startLine", location.line())))));
        // Stable across commits, so code scanning tracks the same change as one alert.
        out.put("partialFingerprints", Map.of("authtracerChange/v1", fingerprint(change)));
        return out;
    }

    /**
     * E.g. "employee-service GET /employees/{id} ssn: ROLE_ADMIN → authenticated. Fewer callers are kept out than before."
     */
    static String message(Change change) {
        StringBuilder text = new StringBuilder(change.service()).append(' ').append(change.endpoint());
        if (!change.field().isEmpty()) {
            text.append(' ').append(change.field());
        }
        if (change.kind() != Kind.NEW_FINDING) {
            text.append(": ").append(change.before()).append(" → ").append(change.after());
        }
        if (change.message() != null && !change.message().isEmpty()) {
            text.append(change.kind() == Kind.NEW_FINDING ? ": " : ". ")
                    .append(Character.toUpperCase(change.message().charAt(0))).append(change.message().substring(1));
            if (!change.message().endsWith(".")) {
                text.append('.');
            }
        }
        return text.toString();
    }

    /**
     * Information is no result: what fails the check is an error, what needs review a warning.
     */
    private static String level(Severity severity) {
        return severity == Severity.FAIL ? "error" : "warning";
    }

    /**
     * The change's kind and exposure. Policy violations of one exposure differ by what the policy requires, and new
     * findings at one place by their kind and message; the other kinds keep the fingerprints they always had.
     */
    static String fingerprint(Change change) {
        String identity = change.kind() + "|" + change.service() + "|" + change.endpoint() + "|" + change.field()
                + switch (change.kind()) {
                    case POLICY_VIOLATION -> "|" + change.before();
                    case NEW_FINDING -> "|" + change.after() + "|" + change.message();
                    default -> "";
                };
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(identity.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 16);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
