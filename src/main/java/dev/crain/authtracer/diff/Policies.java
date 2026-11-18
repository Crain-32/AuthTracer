package dev.crain.authtracer.diff;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.Clauses.Clause;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.scan.spring.SpelRequirements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Policies the Provided facts files set, checked on every exposure.
 * <ul>
 * <li>Decision 0025, data governance: a field carrying a policy's label (directly, or inherited from its sources)
 * must require at least the policy's requirement wherever it is exposed: every clause of the policy must be implied
 * by the field's effective requirement.</li>
 * <li>Decision 0026, distributed policies: a matching endpoint must check the requirement on entry, in its own
 * service; with {@code fresh}, the checks on its request chain that evaluate against a live authority source
 * (introspection, a user lookup; decision 0007) must require it too, so a revocation during the request is honored.
 * The chain follows the calls that relay the caller's token (decision 0021).</li>
 * </ul>
 * A policy is a floor: every policy that applies must hold, whoever set it, so a service's own policy can add to the
 * Org's but never relax it.
 */
@Supports(Feature.POLICIES)
public final class Policies {

    private static final Logger log = LoggerFactory.getLogger(Policies.class);

    /**
     * An exposure that requires less than a policy.
     *
     * @param label the policy's label, or for an endpoint policy its endpoint pattern
     * @param requires what the policy asks for, as the diff describes requirements
     */
    public record Violation(String label, String requires, String reason) {
    }

    /**
     * @param service the service whose own facts set the policy, {@code null} for an Org-wide one
     */
    private record Policy(String service, String label, Set<Clause> clauses, String requires, String reason) {
    }

    /**
     * @param service the service whose own facts set the policy, {@code null} for an Org-wide one
     */
    private record EndpointPolicy(String service, String method, PathPattern pattern, String subject,
            Set<Clause> clauses, String requires, boolean fresh, String reason) {

        /**
         * A mapping that accepts any method ({@code *}) answers the policy's method too. A policy without a method is
         * about HTTP requests (a WebSocket's handshake is one), not a Kafka topic or a STOMP destination with the
         * same path.
         */
        boolean matches(Ingress ingress) {
            return (method == null ? HTTP.contains(ingress.httpMethod()) : "*".equals(ingress.httpMethod())
                    || method.equalsIgnoreCase(ingress.httpMethod()))
                    && pattern.matches(PathContainer.parsePath(ingress.route()));
        }
    }

    /**
     * A check on a request chain, the service it runs in, and whether that service reads authorities live.
     */
    private record ChainCheck(String service, Requirement requirement, boolean entry, boolean live) {
    }

    private static final int MAX_DEPTH = 6;
    private static final Set<String> HTTP = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE",
            "*", "WEBSOCKET");

    private final List<Policy> policies;
    private final List<EndpointPolicy> endpointPolicies;
    private final SystemGraph system;

    private Policies(List<Policy> policies, List<EndpointPolicy> endpointPolicies, SystemGraph system) {
        this.policies = policies;
        this.endpointPolicies = endpointPolicies;
        this.system = system;
    }

    /**
     * The policies the services were scanned with: the Org's, once each however many services carry them, and each
     * service's own.
     */
    static Policies of(SystemGraph system) {
        Set<ProvidedFact> org = new LinkedHashSet<>();
        Set<Map.Entry<String, ProvidedFact>> own = new LinkedHashSet<>();
        for (ApplicationGraph graph : system.services()) {
            for (ProvidedFact fact : graph.provided()) {
                if (fact.kind() != ProvidedFact.Kind.POLICY && fact.kind() != ProvidedFact.Kind.ENDPOINT_POLICY) {
                    continue;
                }
                if (fact.origin() == ProvidedFact.Origin.LOCAL) {
                    own.add(Map.entry(graph.service(), fact));
                }
                else {
                    org.add(fact);
                }
            }
        }
        List<Policy> policies = new ArrayList<>();
        List<EndpointPolicy> endpointPolicies = new ArrayList<>();
        org.forEach(fact -> add(null, fact, policies, endpointPolicies));
        own.forEach(entry -> add(entry.getKey(), entry.getValue(), policies, endpointPolicies));
        return new Policies(policies, endpointPolicies, system);
    }

    private static void add(String service, ProvidedFact fact, List<Policy> policies,
            List<EndpointPolicy> endpointPolicies) {
        Set<Clause> clauses = Clauses.of(List.of(SpelRequirements.standard(fact.requirement())));
        if (fact.kind() == ProvidedFact.Kind.POLICY) {
            policies.add(new Policy(service, fact.subject(), clauses, Clauses.describe(clauses), fact.reason()));
            return;
        }
        String[] parts = fact.subject().trim().split("\\s+", 2);
        String method = parts.length == 2 ? parts[0].toUpperCase(Locale.ROOT) : null;
        endpointPolicies.add(new EndpointPolicy(service, method,
                PathPatternParser.defaultInstance.parse(parts[parts.length - 1]), fact.subject(), clauses,
                Clauses.describe(clauses), Boolean.TRUE.equals(fact.fresh()), fact.reason()));
    }

    /**
     * An Org policy applies everywhere. A service's own label policy follows that service's data: it applies to the
     * service's exposures, and wherever another service exposes a field of it that carries the label.
     */
    private static boolean appliesTo(Policy policy, Exposure exposure) {
        return policy.service() == null || policy.service().equals(exposure.service())
                || exposure.labelledBy().getOrDefault(policy.label(), Set.of()).stream()
                        .anyMatch(field -> SystemGraph.serviceOf(field).equals(policy.service()));
    }

    List<Violation> violations(Exposure exposure) {
        Map<String, Set<Clause>> held = new LinkedHashMap<>();
        exposure.steps().forEach(step -> held.computeIfAbsent(SystemGraph.serviceOf(step.location()),
                service -> new LinkedHashSet<>()).addAll(Clauses.of(List.of(step.requirement()))));
        Set<Violation> violations = new LinkedHashSet<>();
        policies.stream()
                .filter(policy -> exposure.labels().contains(policy.label()))
                .filter(policy -> appliesTo(policy, exposure))
                .filter(policy -> !implied(held, policy.clauses()))
                .forEach(policy -> violations.add(new Violation(policy.label(), policy.requires(), policy.reason())));
        if (exposure.field().isEmpty()) {
            violations.addAll(endpointViolations(exposure));
        }
        return List.copyOf(violations);
    }

    private List<Violation> endpointViolations(Exposure exposure) {
        // The exposure's endpoint, in the system its exposures were read from.
        Ingress ingress = system.node(SystemGraph.qualify(exposure.service(), exposure.ingress()))
                .map(Ingress.class::cast).orElseThrow();
        // An endpoint policy names routes of the service that set it.
        List<EndpointPolicy> matching = endpointPolicies.stream()
                .filter(policy -> policy.service() == null || policy.service().equals(exposure.service()))
                .filter(policy -> policy.matches(ingress)).toList();
        if (matching.isEmpty()) {
            return List.of();
        }
        List<ChainCheck> chain = new ArrayList<>();
        chain(exposure.service(), ingress, true, 0, new HashSet<>(), chain);
        List<Violation> violations = new ArrayList<>();
        for (EndpointPolicy policy : matching) {
            if (!implied(held(chain, ChainCheck::entry), policy.clauses())) {
                violations.add(new Violation(policy.subject(), policy.requires() + " on entry", policy.reason()));
            }
            if (policy.fresh() && !implied(held(chain, ChainCheck::live), policy.clauses())) {
                violations.add(new Violation(policy.subject(), policy.requires() + " against a live authority source"
                        + " (no check on the chain both asks for it and reads authorities live)", policy.reason()));
            }
        }
        return violations;
    }

    /**
     * The checks on an endpoint's path, then on the endpoints it calls with the caller's token.
     */
    private void chain(String service, Ingress ingress, boolean entry, int depth, Set<String> seen,
            List<ChainCheck> chain) {
        if (depth > MAX_DEPTH) {
            log.warn("An endpoint policy follows {} relayed calls, no further: past {} {}, the checks aren't counted",
                    MAX_DEPTH, service, ingress.endpoint());
            return;
        }
        if (!seen.add(SystemGraph.qualify(service, ingress.id()))) {
            return;
        }
        // The exposure's service, or one a link leads to.
        ApplicationGraph graph = system.service(service).orElseThrow();
        boolean live = graph.authoritySource().freshness() == AuthoritySource.Freshness.LIVE;
        for (Edge edge : graph.path(ingress.id())) {
            Optional<Node> node = graph.node(edge.to());
            if (node.isPresent() && node.get() instanceof AuthorizationLocation location
                    && location.scope() != AuthorizationLocation.Scope.FIELD && !edge.conditional()) {
                chain.add(new ChainCheck(service, location.requirement(), entry, live));
            }
            else if (node.isPresent() && node.get() instanceof Egress egress
                    && Credentials.callerChecked(egress.credentials())) {
                for (Edge link : system.linksFrom(SystemGraph.qualify(service, egress.id()))) {
                    system.node(link.to()).filter(Ingress.class::isInstance).map(Ingress.class::cast)
                            .ifPresent(callee -> chain(SystemGraph.serviceOf(link.to()), callee, false, depth + 1,
                                    seen, chain));
                }
            }
        }
    }

    private static Map<String, Set<Clause>> held(List<ChainCheck> chain, Predicate<ChainCheck> filter) {
        Map<String, Set<Clause>> held = new LinkedHashMap<>();
        chain.stream().filter(filter).forEach(check -> held.computeIfAbsent(check.service(),
                service -> new LinkedHashSet<>()).addAll(Clauses.of(List.of(check.requirement()))));
        return held;
    }

    /**
     * Whether the clauses held in each service imply every clause of a policy. A service's role checks were widened
     * with its RoleHierarchy, so a policy's role clause is widened the same way before it is compared with them:
     * with {@code ROLE_ADMIN > ROLE_HR}, {@code hasRole('HR')} in that service meets {@code requires: hasRole('HR')}.
     */
    private boolean implied(Map<String, Set<Clause>> held, Set<Clause> required) {
        return required.stream().allMatch(clause -> held.entrySet().stream()
                .anyMatch(service -> Clauses.implies(service.getValue(), widened(clause, service.getKey()))));
    }

    private Clause widened(Clause clause, String service) {
        if (clause.kind() != Clause.Kind.ANY) {
            return clause;
        }
        return system.service(service).map(graph -> graph.authoritySource().roleHierarchy())
                .map(hierarchy -> Clause.any(SpelRequirements.widened(Requirement.anyAuthority(
                        List.copyOf(clause.authorities())), hierarchy).authorities()))
                .orElse(clause);
    }
}
