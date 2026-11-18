package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Method security on the shapes the other fixtures don't use: what a proxy can't intercept, a denied handler of the
 * application's own, a transaction ordered after method security, a query that doesn't read the caller, and a
 * reviewed check declared without a requirement.
 */
class MethodFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("methodforms");

    @TempDir
    Path dir;

    @Test
    void theProxyCantInterceptAFinalOrStaticMethod() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("Ledger#sealed", "final methods"))
                .anySatisfy(message -> assertThat(message).contains("Ledger#helper", "static methods"));
        assertThat(checks("GET /sealed")).isEmpty();
        assertThat(checks("GET /helper")).isEmpty();
    }

    @Test
    void anApplicationsDeniedHandlerOnTheMethodOrItsClassDecidesTheDenial() {
        for (String ingress : List.of("GET /masked", "GET /vault")) {
            assertThat(checks(ingress)).singleElement().satisfies(check -> {
                assertThat(check.denial().kind()).isEqualTo(Denial.Kind.HANDLER);
                assertThat(check.denial().handler()).isEqualTo("fixtures.methodforms.MaskingHandler");
                // Annotation templates on: an annotation written out is read as it is. Its interceptor published
                // again adds the same requirement, once.
                assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.ANY_AUTHORITY);
                assertThat(check.requirement().authorities()).containsExactly("ROLE_ADMIN");
            });
        }
    }

    @Test
    void anAnnotationTwoInterceptorsHandleNeedsBoth() {
        Requirement close = checks("GET /close").getFirst().requirement();
        assertThat(close.kind()).isEqualTo(Requirement.Kind.AND);
        assertThat(close.operands()).flatExtracting(Requirement::authorities)
                .containsExactly("ROLE_CLERK", "ROLE_SUPERVISOR");
    }

    @Test
    void aPostCheckOrderedBeforeTheTransactionDecidesAfterItsCommit() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.CHECK_AFTER_COMMIT)
                .extracting(Finding::message).singleElement().asString()
                .contains("@PostAuthorize", "Ledger#post", "interceptor order 500", "transactions 1000");
    }

    @Test
    void aQueryWhoseSpelDoesntReadTheCallerIsNoFilter() {
        assertThat(checks("GET /documents")).isEmpty();
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
    }

    @Test
    void aReviewedCheckWithoutARequirementIsShownAsOneWhoseRequirementIsntKnown() throws IOException {
        Path file = Files.writeString(dir.resolve("authtracer.yaml"), """
                version: 1
                facts:
                  - kind: check
                    method: "fixtures.methodforms.MethodFormsController#documents(java.lang.String)"
                    reason: the gateway checks the caller
                """);
        ApplicationGraph reviewed = FixtureScans.scan("methodforms",
                ProvidedFacts.load(Optional.of(file), Optional.empty(), "fixture"));
        assertThat(path(reviewed, "ingress:GET /documents")).singleElement().satisfies(id -> {
            AuthorizationLocation location = (AuthorizationLocation) reviewed.node(id).orElseThrow();
            assertThat(location.mechanism()).startsWith("Provided check");
            // Decision 0106: with the digest of the class whose hand-rolled check was reviewed, so a change to it
            // asks for review again.
            assertThat(location.requirement().code()).isNotBlank();
            assertThat(location.requirement().withCode(null)).isEqualTo(Requirement.expression(
                    "a reviewed check whose requirement wasn't given"));
        });
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
    }
}
