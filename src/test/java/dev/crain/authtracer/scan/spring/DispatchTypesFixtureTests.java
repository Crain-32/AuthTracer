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
 * HTTP-05: dispatcherTypeMatchers(..) compare the request's dispatch, not its path (7.1.1
 * DispatcherTypeRequestMatcher): REQUEST is every request's own, the others never are; the error page is also reached
 * by the ERROR dispatch of a request that fails.
 */
class DispatchTypesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dispatchtypes");

    @Test
    void theRequestDispatchMatchesEveryRequestAheadOfLaterRules() {
        AuthorizationLocation users = rule(graph, "GET /legacy/admin/users");
        assertThat(users.requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(users.routePattern()).isEqualTo("dispatcherType REQUEST");
    }

    @Test
    void aRequestDispatchRuleCanAskForAnHttpMethod() {
        assertThat(rule(graph, "GET /reports").requirement().authorities()).containsExactly("ROLE_READER");
        assertThat(rule(graph, "GET /reports").routePattern()).isEqualTo("GET dispatcherType REQUEST");
        assertThat(rule(graph, "DELETE /reports/{id}").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(graph, "DELETE /reports/{id}").routePattern()).isEqualTo("DELETE dispatcherType REQUEST");
    }

    @Test
    void forwardsIncludesAsyncDispatchesAndErrorsNeverTakeARequestsOwnDispatch() {
        assertThat(rule(graph, "POST /reports").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(graph, "POST /reports").routePattern()).isEqualTo("anyRequest");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("dispatcherType"));
    }

    @Test
    void theErrorPageIsAlsoReachedByTheErrorDispatchOfAnyRequest() {
        AuthorizationLocation error = rule(graph, "GET /error");
        assertThat(error.id()).startsWith("location:SPLIT:").contains(":or-error:");
        assertThat(error.mechanism())
                .isEqualTo("authorizeHttpRequests (an error dispatch also reaches the error page)");
        assertThat(error.routePattern()).isEqualTo("GET dispatcherType REQUEST or, on an error, dispatcherType ERROR");
        assertThat(error.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
    }

    @Test
    void anErrorPageWhoseErrorDispatchGetsTheSameRuleIsOneCheck() {
        ApplicationGraph errorPage = FixtureScans.scan("errorpage");
        AuthorizationLocation problem = rule(errorPage, "GET /problem");
        assertThat(problem.id()).doesNotStartWith("location:SPLIT:");
        assertThat(problem.requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }
}
