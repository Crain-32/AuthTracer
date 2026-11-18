package dev.crain.authtracer.provided;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.ProvidedFact.Kind;
import dev.crain.authtracer.graph.ProvidedFact.Origin;
import org.springframework.web.util.pattern.PathPatternParser;
import org.springframework.web.util.pattern.PatternParseException;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Provided facts for one service, from its local {@code authtracer.yaml} and the organization's file, resolved by
 * precedence: an Org-controlled override scoped to the service, then Org-wide facts, then local facts.
 * A local fact that loses to an Org fact about the same thing is dropped and reported. Policies don't compete: each is
 * a floor, so all of them are kept and must all hold.
 */
@Supports(Feature.PROVIDED_FACTS)
public final class ProvidedFacts {

    public static final String LOCAL_FILE = "authtracer.yaml";
    public static final ProvidedFacts NONE = new ProvidedFacts(List.of(), List.of());

    private final List<ProvidedFact> facts;
    private final List<Finding> conflicts;

    private ProvidedFacts(List<ProvidedFact> facts, List<Finding> conflicts) {
        this.facts = List.copyOf(facts);
        this.conflicts = List.copyOf(conflicts);
    }

    public static ProvidedFacts load(Optional<Path> local, Optional<Path> org, String service) {
        List<ProvidedFact> candidates = new ArrayList<>();
        local.filter(Files::isRegularFile).ifPresent(file -> {
            Map<String, Object> document = read(file);
            candidates.addAll(facts(document.get("facts"), Origin.LOCAL, file));
            candidates.addAll(policies(document.get("policies"), Origin.LOCAL, file));
            candidates.addAll(rules(document.get("rules"), Origin.LOCAL, file));
        });
        org.filter(Files::isRegularFile).ifPresent(file -> {
            Map<String, Object> document = read(file);
            candidates.addAll(facts(document.get("facts"), Origin.ORG, file));
            candidates.addAll(policies(document.get("policies"), Origin.ORG, file));
            candidates.addAll(rules(document.get("rules"), Origin.ORG, file));
            if (document.get("services") instanceof Map<?, ?> services
                    && services.get(service) instanceof Map<?, ?> scoped) {
                candidates.addAll(facts(scoped.get("overrides"), Origin.ORG_OVERRIDE, file));
            }
        });
        return resolve(candidates);
    }

    /**
     * @param candidates lowest precedence first: local facts, then the Org's, then its overrides
     */
    @Supports(Feature.FINDING_PROVIDED_CONFLICT)
    private static ProvidedFacts resolve(List<ProvidedFact> candidates) {
        Map<String, ProvidedFact> winners = new LinkedHashMap<>();
        List<ProvidedFact> policies = new ArrayList<>();
        List<Finding> conflicts = new ArrayList<>();
        for (ProvidedFact fact : candidates) {
            if (fact.kind() == Kind.POLICY || fact.kind() == Kind.ENDPOINT_POLICY) {
                if (!policies.contains(fact)) {
                    policies.add(fact);
                }
                continue;
            }
            ProvidedFact current = winners.get(fact.conflictKey());
            if (current == null || fact.origin().compareTo(current.origin()) > 0) {
                if (current != null && current.origin() == Origin.LOCAL) {
                    conflicts.add(dropped(current, fact));
                }
                winners.put(fact.conflictKey(), fact);
            }
            else if (!fact.equals(current)) {
                // Two facts of one file (or of the Org's) about one thing: the first is kept, as before.
                conflicts.add(new Finding(Finding.Kind.PROVIDED_CONFLICT, fact.origin() + " " + fact.kind()
                        + " fact on " + fact.subject() + " is ignored: an earlier " + current.origin() + " fact ("
                        + current.kind() + ") covers the same " + fact.conflictKey().split(" ")[0],
                        fact.origin() == Origin.LOCAL ? CodeRef.ofClass(LOCAL_FILE) : null));
            }
        }
        List<ProvidedFact> facts = new ArrayList<>(winners.values());
        facts.addAll(policies);
        return new ProvidedFacts(facts, conflicts);
    }

    @Supports(Feature.FINDING_PROVIDED_CONFLICT)
    private static Finding dropped(ProvidedFact local, ProvidedFact winner) {
        return new Finding(Finding.Kind.PROVIDED_CONFLICT, "Local " + local.kind() + " fact on " + local.subject()
                + " is ignored: an " + winner.origin() + " fact (" + winner.kind() + ") covers the same "
                + local.conflictKey().split(" ")[0], CodeRef.ofClass(LOCAL_FILE));
    }

    public List<ProvidedFact> all() {
        return facts;
    }

    public List<ProvidedFact> of(Kind kind) {
        return facts.stream().filter(fact -> fact.kind() == kind).toList();
    }

    public Optional<ProvidedFact> about(Kind kind, String subject) {
        return facts.stream().filter(fact -> fact.kind() == kind && fact.subject().equals(subject)).findFirst();
    }

    public List<Finding> conflicts() {
        return conflicts;
    }

    private static List<ProvidedFact> facts(Object list, Origin origin, Path file) {
        List<ProvidedFact> facts = new ArrayList<>();
        if (!(list instanceof List<?> entries)) {
            return facts;
        }
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> map)) {
                throw new IllegalArgumentException(file + ": every fact must be a mapping, got " + entry);
            }
            String kindName = string(map, "kind").orElseThrow(() -> new IllegalArgumentException(
                    file + ": fact without a kind: " + map));
            Kind kind;
            try {
                kind = Kind.valueOf(kindName.toUpperCase(Locale.ROOT));
            }
            catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException(file + ": unknown fact kind '" + kindName + "'", ex);
            }
            String subjectKey = switch (kind) {
                case SENSITIVE, DECLASSIFY -> "field";
                case CHECK -> "method";
                case REQUIREMENT -> "ingress";
                case POLICY, ENDPOINT_POLICY -> throw new IllegalArgumentException(file
                        + ": policies go in 'policies', not 'facts'");
                case RULE -> throw new IllegalArgumentException(file + ": rules go in 'rules', not 'facts'");
            };
            String subject = string(map, subjectKey).orElseThrow(() -> new IllegalArgumentException(
                    file + ": " + kindName + " fact needs '" + subjectKey + "'"));
            if (kind == Kind.SENSITIVE || kind == Kind.DECLASSIFY) {
                subject = subject.startsWith("field:") ? subject : "field:" + subject;
            }
            // labels: [PII, PCI], or one label as a scalar.
            List<String> labels = map.get("labels") instanceof List<?> values
                    ? values.stream().map(String::valueOf).toList()
                    : string(map, "labels").map(List::of).orElse(List.of());
            facts.add(new ProvidedFact(kind, subject, labels, string(map, "requirement").orElse(null),
                    string(map, "reason").orElse(null), origin));
        }
        return facts;
    }

    /**
     * Decision 0120: {@code rules: [{annotation: com.acme.RequiresPermission, requires: "hasAuthority('{value}')"},
     * {call: "com.acme.Guard#require", requires: "hasRole('{arg0}')", combine: all}]}. One rule per annotation or
     * method: the organisation's beats the service's.
     */
    @Supports(Feature.STRUCTURE_RULES)
    private static List<ProvidedFact> rules(Object list, Origin origin, Path file) {
        List<ProvidedFact> rules = new ArrayList<>();
        if (!(list instanceof List<?> entries)) {
            return rules;
        }
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> map)) {
                throw new IllegalArgumentException(file + ": every rule must be a mapping, got " + entry);
            }
            Optional<String> annotation = string(map, "annotation");
            Optional<String> call = string(map, "call");
            if (annotation.isPresent() == call.isPresent()) {
                throw new IllegalArgumentException(file + ": a rule matches an 'annotation' or a 'call', one of them: "
                        + map);
            }
            if (call.isPresent() && !call.get().contains("#")) {
                throw new IllegalArgumentException(file + ": a rule's call is Class#method or"
                        + " Class#method(parameter types): " + call.get());
            }
            String requires = string(map, "requires").orElseThrow(() -> new IllegalArgumentException(
                    file + ": a rule needs what it 'requires': " + map));
            String combine = string(map, "combine").orElse("any");
            if (!combine.equals("any") && !combine.equals("all")) {
                throw new IllegalArgumentException(file + ": a rule's 'combine' is any or all, got " + combine);
            }
            rules.add(new ProvidedFact(Kind.RULE, annotation.map(name -> "annotation " + name)
                    .orElseGet(() -> "call " + call.get()), combine.equals("all") ? List.of("all") : List.of(),
                    requires, string(map, "reason").orElse(null), origin));
        }
        return rules;
    }

    /**
     * {@code policies: [{label: PII, requires: "hasRole('ADMIN')", reason: ..}]} (decision 0025), and
     * {@code {endpoint: "PUT /admin/**", requires: .., fresh: true}} (decision 0026).
     */
    @Supports(Feature.POLICIES)
    private static List<ProvidedFact> policies(Object list, Origin origin, Path file) {
        List<ProvidedFact> policies = new ArrayList<>();
        if (!(list instanceof List<?> entries)) {
            return policies;
        }
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> map)) {
                throw new IllegalArgumentException(file + ": every policy must be a mapping, got " + entry);
            }
            Optional<String> endpoint = string(map, "endpoint");
            String subject = endpoint.or(() -> string(map, "label")).orElseThrow(() -> new IllegalArgumentException(
                    file + ": policy without a label or an endpoint: " + map));
            String requires = string(map, "requires").orElseThrow(() -> new IllegalArgumentException(
                    file + ": policy for " + subject + " needs 'requires'"));
            String reason = string(map, "reason").orElse(null);
            endpoint.ifPresent(pattern -> validateEndpoint(pattern, file));
            policies.add(endpoint.isPresent()
                    ? new ProvidedFact(ProvidedFact.Kind.ENDPOINT_POLICY, subject, List.of(), requires, reason, origin,
                            Boolean.TRUE.equals(map.get("fresh")) ? Boolean.TRUE : null)
                    : new ProvidedFact(ProvidedFact.Kind.POLICY, subject, List.of(subject), requires, reason, origin));
        }
        return policies;
    }

    /**
     * {@code PUT /admin/**} or {@code /admin/**}: a path pattern as Spring MVC parses it, after an optional method.
     */
    private static void validateEndpoint(String endpoint, Object file) {
        String[] parts = endpoint.trim().split("\\s+", 2);
        try {
            PathPatternParser.defaultInstance.parse(parts[parts.length - 1]);
        }
        catch (PatternParseException ex) {
            throw new IllegalArgumentException(file + ": endpoint policy '" + endpoint + "' is not a path pattern: "
                    + ex.getMessage(), ex);
        }
    }

    /**
     * A fact as it was applied to a scan, e.g. in a graph posted to the server, by the rules the files are read
     * with: what a fact of its kind needs is there, and an endpoint policy's pattern is one.
     *
     * @throws IllegalArgumentException when it isn't
     */
    @Supports(Feature.GRAPH_SERVER)
    public static void validate(ProvidedFact fact) {
        if (fact == null || fact.kind() == null || fact.origin() == null || fact.subject() == null
                || fact.subject().isBlank()) {
            throw new IllegalArgumentException("A provided fact needs a kind, an origin and a subject: " + fact);
        }
        switch (fact.kind()) {
            case SENSITIVE, DECLASSIFY -> {
                if (!fact.subject().startsWith("field:") || fact.subject().lastIndexOf('.') <= "field:".length()) {
                    throw new IllegalArgumentException("A " + fact.kind() + " fact's subject must be a field id"
                            + " (field:<class>.<property>): " + fact.subject());
                }
            }
            case POLICY, ENDPOINT_POLICY -> {
                if (fact.requirement() == null) {
                    throw new IllegalArgumentException("Policy for " + fact.subject() + " needs a requirement");
                }
                if (fact.kind() == Kind.ENDPOINT_POLICY) {
                    validateEndpoint(fact.subject(), "provided fact");
                }
            }
            case RULE -> {
                if (fact.requirement() == null || !(fact.subject().startsWith("annotation ")
                        || fact.subject().startsWith("call ") && fact.subject().contains("#"))) {
                    throw new IllegalArgumentException("A rule matches an annotation or a call (Class#method) and"
                            + " needs a requirement: " + fact.subject());
                }
            }
            case CHECK, REQUIREMENT -> {
            }
        }
    }

    private static Optional<String> string(Map<?, ?> map, String key) {
        Object value = map.get(key);
        return value == null ? Optional.empty() : Optional.of(String.valueOf(value));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> read(Path file) {
        try {
            Object document = new Yaml(new SafeConstructor(new LoaderOptions())).load(Files.readString(file));
            if (document == null) {
                return Map.of();
            }
            if (!(document instanceof Map<?, ?> map) || !Integer.valueOf(1).equals(map.get("version"))) {
                throw new IllegalArgumentException(file + ": expected a mapping with 'version: 1'");
            }
            return (Map<String, Object>) map;
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
