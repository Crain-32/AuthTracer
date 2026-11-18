package dev.crain.authtracer.api;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.Clauses;
import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.diff.Exposures.Step;
import dev.crain.authtracer.diff.Policies;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;

/**
 * An {@link Exposure} as the UI shows it: requirements already simplified, and each field-level check tied to the
 * field it guards.
 *
 * @param adds for a response field, what it asks beyond its endpoint ({@code ""}: nothing more); {@code null} for the
 *        endpoint itself, or when the field's requirement can't be written as an addition to the endpoint's
 * @param violations the data governance policies its labels carry that it requires less than (decision 0025)
 */
@Supports({Feature.EXPOSURES_VIEW, Feature.LINEAGE_VIEW, Feature.GRAPH_SERVER})
record ExposureView(String service, String ingress, String endpoint, String field, String fieldId,
        String requirement, String adds, List<StepView> steps, Set<String> sources, Set<String> labels,
        List<Flow> lineage, List<Policies.Violation> violations) {

    /**
     * @param guards for a field-level check, the qualified id of the field it guards
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record StepView(String location, String mechanism, AuthorizationLocation.Scope scope, String requirement,
            String guards) {
    }

    static List<ExposureView> of(SystemGraph system) {
        List<Exposure> all = Exposures.of(system);
        Map<String, Exposure> endpoints = new HashMap<>();
        all.stream().filter(exposure -> exposure.field().isEmpty())
                .forEach(exposure -> endpoints.putIfAbsent(exposure.service() + " " + exposure.ingress(), exposure));
        return all.stream().map(exposure -> of(exposure, endpoints.get(exposure.service() + " " + exposure.ingress()),
                system)).toList();
    }

    /**
     * @param endpoint the exposure of the endpoint itself, which Exposures has for every endpoint
     */
    private static ExposureView of(Exposure exposure, Exposure endpoint, SystemGraph system) {
        String adds = exposure.field().isEmpty() ? null
                : Clauses.added(endpoint.clauses(), exposure.clauses()).orElse(null);
        return new ExposureView(exposure.service(), exposure.ingress(), exposure.endpoint(), exposure.field(),
                exposure.fieldId(), exposure.requirement(), adds,
                exposure.steps().stream().map(step -> step(step, system)).toList(), exposure.sources(),
                exposure.labels(), exposure.lineage(), exposure.violations());
    }

    private static StepView step(Step step, SystemGraph system) {
        Optional<AuthorizationLocation> location = system.node(step.location())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast);
        String guards = location.filter(check -> check.scope() == AuthorizationLocation.Scope.FIELD)
                .map(check -> SystemGraph.qualify(SystemGraph.serviceOf(step.location()), check.guardedField()))
                .orElse(null);
        String requirement = step.requirement().kind() == Requirement.Kind.PERMIT_ALL ? "permitAll"
                : Clauses.describe(Clauses.of(List.of(step.requirement())));
        return new StepView(step.location(), step.mechanism(), location.map(AuthorizationLocation::scope)
                .orElse(null), requirement, guards);
    }
}
