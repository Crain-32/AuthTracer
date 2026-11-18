package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-19: an ObjectPostProcessor on the authorization configurer may replace or wrap its AuthorizationFilter or
 * AuthorizationManager, so it is an OPAQUE_CONFIG finding, unless it only sets the filter's dispatch flags.
 */
class PostProcessorsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("postprocessors");

    @Test
    void aPostProcessorThatMayReplaceTheManagerIsNamed() {
        assertThat(opaque()).anySatisfy(finding -> {
            assertThat(finding.message()).startsWith("withObjectPostProcessor(fixtures.postprocessors"
                    + ".AuditingPostProcessor) post-processes the authorization configurer's AuthorizationFilter or"
                    + " AuthorizationManager, which it may replace or wrap");
            assertThat(finding.location().method()).startsWith("admin(");
            assertThat(finding.location().line()).isNotNull();
        });
        // The rules are still what the chain configures.
        assertThat(rule(graph, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void aPostProcessorThatReplacesTheFilterIsNamed() {
        assertThat(opaque()).anySatisfy(finding -> {
            assertThat(finding.message()).startsWith("withObjectPostProcessor(fixtures.postprocessors"
                    + ".PostProcessorsApp$");
            assertThat(finding.location().method()).startsWith("tenants(");
        });
    }

    @Test
    void aPostProcessorAuthTracerCantSeeIsNamedByWhereItIsPassed() {
        assertThat(opaque()).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("withObjectPostProcessor(ObjectPostProcessor)"))
                .anySatisfy(message -> assertThat(message).startsWith("objectPostProcessor(ObjectPostProcessor)"));
    }

    @Test
    void aBeanThatPostProcessesEveryManagerIsNamed() {
        assertThat(opaque()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .startsWith("The ObjectPostProcessor bean fixtures.postprocessors.PostProcessorsApp#timing()"
                        + " post-processes every authorizeHttpRequests AuthorizationManager"));
    }

    @Test
    void aPostProcessorThatSetsDispatchFlagsIsRead() {
        assertThat(opaque()).filteredOn(finding -> finding.location().method().startsWith("app(")).isEmpty();
        assertThat(rule(graph, "GET /profile").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void withErrorDispatchesUncheckedTheErrorPageIsOpenOnAnError() {
        AuthorizationLocation error = rule(graph, "GET /error");
        assertThat(error.routePattern()).isEqualTo("anyRequest or, on an error, error dispatch");
        assertThat(error.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.AUTHENTICATED, Kind.PERMIT_ALL);
    }

    private java.util.List<Finding> opaque() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG).toList();
    }
}
