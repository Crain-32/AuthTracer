package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Argument;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0091 (EXPR-02, EXPR-04): the method parameters a pre/post expression names, tied to what the request binds
 * into them, and the token claims it reads.
 */
class SpelArgumentsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("spelarguments");

    @Test
    void aHandlersCheckReadsItsOwnPathVariable() {
        assertThat(check(graph, "ingress:GET /owners/{owner}").arguments())
                .containsExactly(new Argument("owner", 0, "path variable owner"));
    }

    @Test
    void aServiceCheckReadsWhatEveryHandlerCallingItPassesAlong() {
        // The handler names its path variable documentId.
        assertThat(check(graph, "ingress:GET /documents/{documentId}").arguments())
                .containsExactly(new Argument("id", 0, "path variable documentId"));
        assertThat(check(graph, "ingress:POST /documents").arguments())
                .containsExactly(new Argument("document", 0, "request body"));
        // #p0 is the first argument; an unannotated simple handler parameter is a request parameter.
        assertThat(check(graph, "ingress:GET /search").arguments())
                .containsExactly(new Argument("p0", 0, "request parameter q"));
    }

    /**
     * Decision 0106: an annotation's expression is its text, which a change to it changes; it carries no digest of
     * the code around it.
     */
    @Test
    void anAnnotationsExpressionIsItsTextAlone() {
        AuthorizationLocation owner = check(graph, "ingress:GET /owners/{owner}");
        assertThat(owner.mechanism()).startsWith("@");
        assertThat(owner.requirement().code()).isNull();
        assertThat(owner.requirement().operands()).allSatisfy(operand -> assertThat(operand.code()).isNull());
    }

    @Test
    void handlersThatPassDifferentThingsLeaveTheBindingOpen() {
        assertThat(check(graph, "ingress:GET /archive/{id}").arguments()).containsExactly(new Argument("id", 0, null));
    }

    @Test
    void aNameSpringDoesntGiveAParameterIsNullWhenTheCheckRuns() {
        // inTenant has @P("tenant") on its first parameter, so Spring takes no other names: #region is null.
        assertThat(check(graph, "ingress:GET /tenants").arguments())
                .containsExactly(new Argument("region", null, null));
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).contains("reads #region", "some of its parameters have @P names",
                    "#region is null when the check runs");
        });
    }

    @Test
    void theTokenClaimsAnExpressionReadsAreListed() {
        assertThat(check(graph, "ingress:GET /tenants").claims()).containsExactly("tenant", "region");
        assertThat(check(graph, "ingress:GET /archive").claims()).containsExactly("sub");
        assertThat(check(graph, "ingress:GET /search").claims()).isNull();
    }

    @Test
    void withoutParameterNamesInTheClassFileOnlyAtPNamesAParameter() {
        ApplicationGraph groovy = FixtureScans.scan("spelargumentsgroovy");
        assertThat(check(groovy, "ingress:GET /accounts/{owner}").arguments())
                .containsExactly(new Argument("owner", null, null));
        assertThat(check(groovy, "ingress:GET /named/{owner}").arguments())
                .containsExactly(new Argument("owner", 0, "path variable owner"));
        assertThat(groovy.findings()).anySatisfy(finding -> assertThat(finding.message())
                .contains("Accounts#owned", "the class file has no parameter names"));
    }

    @Test
    void withKotlinReflectSpringNamesAKotlinFunctionsParameters() {
        ApplicationGraph kotlin = FixtureScans.scan("spelargumentskotlin");
        assertThat(check(kotlin, "ingress:GET /reports/{owner}").arguments()).containsExactly(
                new Argument("owner", 0, "path variable owner"), new Argument("authentication", 1, "the caller"));
        assertThat(check(kotlin, "ingress:GET /reports").arguments()).containsExactly(
                new Argument("region", 0, "request parameter region"),
                new Argument("year", 1, "request parameter year"));
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() == AuthorizationLocation.Scope.METHOD).findFirst().orElseThrow();
    }
}
