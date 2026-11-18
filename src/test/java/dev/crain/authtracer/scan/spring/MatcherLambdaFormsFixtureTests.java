package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-06: RequestMatcher lambdas in more of the forms configurations write them, and under a context path and a
 * DispatcherServlet path, where what the request's servlet path and raw URI hold isn't the route's path.
 */
class MatcherLambdaFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("matcherlambdaforms");

    @Test
    void aLambdaThatLogsBeforeItDecidesIsReadForWhatItReturns() {
        AuthorizationLocation exact = rule(graph, "GET /forms/exact");
        assertThat(exact.routePattern()).isEqualTo("when path /forms/exact");
        assertThat(exact.requirement().authorities()).containsExactly("ROLE_EXACT");
    }

    @Test
    void aHelperThatTakesTheRequestFirstIsReadToo() {
        AuthorizationLocation users = rule(graph, "GET /forms/admin/users");
        assertThat(users.id()).doesNotStartWith("location:SPLIT:");
        assertThat(users.routePattern()).isEqualTo("when path under /forms/admin");
        assertThat(users.requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(opaque()).noneMatch(message -> message.contains("hasRole(ADMIN)"));
        // Not under the prefix: the helper's rule doesn't apply.
        assertThat(rule(graph, "POST /forms/items").requirement().operands()).extracting(Requirement::authorities)
                .noneMatch(authorities -> authorities.contains("ROLE_ADMIN"));
    }

    @Test
    void aConstantComparedWithTheRawUriIsTheCallersToAvoid() {
        AuthorizationLocation legacy = rule(graph, "GET /forms/legacy");
        assertThat(legacy.routePattern()).startsWith("when URI /forms/legacy or ");
        assertThat(bypassed()).contains("The rule when URI /forms/legacy (requires denyAll) depends on what the"
                + " caller sends (how it writes the URI, which it can percent-encode and still reach the same"
                + " handler): a caller picks whether its request gets it or the rules after it");
    }

    @Test
    void anyTestOfAHeaderOrParameterIsTheCallersToPick() {
        assertThat(bypassed())
                .anySatisfy(message -> assertThat(message).startsWith("The rule when header"
                        + " X-HTTP-Method-Override (requires hasRole(DELETER)) depends on what the caller sends"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule when parameter debug (requires"
                        + " hasRole(DEBUG)) depends on what the caller sends"));
    }

    @Test
    void lambdasThatTestAnythingElseStayUnread() {
        // A prefix of the method's name, the content length, a switch on the method, a prefix from the environment.
        for (String role : List.of("WRITER", "UPLOADER", "READER", "CONFIGURED")) {
            assertThat(opaque()).contains("The rule RequestMatcher (requires hasRole(" + role + ")) uses a"
                    + " RequestMatcher AuthTracer can't evaluate: the requests it matches get it instead of the"
                    + " rules after it");
        }
    }

    @Test
    void underAContextPathAndAServletPathThePathsALambdaTestsAreUnread() {
        ApplicationGraph paths = FixtureScans.scan("matcherlambdapaths");
        assertThat(paths.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactlyInAnyOrder(
                        "The rule RequestMatcher (requires hasRole(ADMIN)) uses a RequestMatcher AuthTracer can't"
                                + " evaluate: the requests it matches get it instead of the rules after it",
                        "The rule RequestMatcher (requires hasRole(REPORTS)) uses a RequestMatcher AuthTracer"
                                + " can't evaluate: the requests it matches get it instead of the rules after it");
        // The method is the same wherever the DispatcherServlet is.
        assertThat(rule(paths, "GET /admin/users").routePattern()).endsWith("when GET");
    }

    private List<String> opaque() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
    }

    private List<String> bypassed() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .map(Finding::message).toList();
    }
}
