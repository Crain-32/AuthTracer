package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Clauses;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class WebFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("web");

    @Test
    void firstMatchingRuleWins() {
        assertThat(requirement("GET /public/info").kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(requirement("GET /items/{id}").authorities()).containsExactly("ROLE_ADMIN", "ROLE_USER");
        assertThat(rule("GET /items/archive/{id}").routePattern()).isEqualTo("/items/**");
    }

    @Test
    void httpMethodSpecificMatchers() {
        Requirement delete = requirement("DELETE /items/{id}");
        assertThat(delete.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(delete.authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule("DELETE /items/{id}").routePattern()).isEqualTo("DELETE /items/**");
    }

    @Test
    void webExpressionManagersAreParsed() {
        Requirement reports = requirement("GET /reports/daily");
        assertThat(reports.kind()).isEqualTo(Kind.AND);
        assertThat(reports.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
    }

    @Test
    void securityMatcherSelectsTheChain() {
        assertThat(requirement("GET /partner/orders").authorities()).containsExactly("SCOPE_partner");
        assertThat(rule("GET /partner/orders").id()).contains("WebSecurityConfig#partnerApi");
    }

    @Test
    void unmatchedRequestsAreDeniedByDefault() {
        AuthorizationLocation stats = rule("GET /internal/stats");
        assertThat(stats.requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(stats.mechanism()).contains("denied by default");
    }

    @Test
    void ignoredRequestsSkipEveryChain() {
        AuthorizationLocation feed = rule("GET /items/feed");
        assertThat(feed.requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(feed.mechanism()).contains("ignoring()");
        assertThat(feed.routePattern()).isEqualTo("GET /items/feed");
        assertThat(rule("GET /assets/{name}").routePattern()).isEqualTo("/assets/**");
        assertThat(rule("DELETE /items/{id}").mechanism()).isEqualTo("authorizeHttpRequests");
    }

    @Test
    void ignoredRequestsAreBypassFindings() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /items/feed: ignoring()"))
                .anySatisfy(message -> assertThat(message).startsWith("On GET /assets/{name}: ignoring()"));
    }

    @Test
    void conditionalManagersAreAnOrOfTheirBranches() {
        Requirement beta = requirement("GET /beta/feature");
        assertThat(beta.kind()).isEqualTo(Kind.OR);
        assertThat(beta.operands()).extracting(Requirement::kind).containsExactly(Kind.ANY_AUTHORITY,
                Kind.PERMIT_ALL);
        assertThat(beta.expression()).contains("whenFalse permitAll");
        assertThat(Clauses.of(List.of(beta))).isEmpty();
        assertThat(Clauses.describe(Clauses.of(List.of(requirement("GET /audit/log"))))).isEqualTo("authenticated");
    }

    @Test
    void staticManagerFactoriesAreNormalized() {
        assertThat(Clauses.describe(Clauses.of(List.of(requirement("GET /ops/status")))))
                .isEqualTo("any of [ROLE_OPS, SCOPE_ops]");
    }

    @Test
    void ruleLinesPointAtTheDsl() {
        assertThat(rule("GET /items/{id}").target().line()).isNotNull();
    }

    @Test
    void basicAndFormLoginAreUserDetailsSources() {
        assertThat(graph.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.USER_DETAILS);
        assertThat(graph.authoritySource().detail()).contains("HTTP Basic").contains("Form login");
    }

    private Requirement requirement(String ingress) {
        return rule(ingress).requirement();
    }

    @Test
    void customDslsAddTheirRulesAfterTheChainsOwn() {
        ApplicationGraph dsl = FixtureScans.scan("customdsl");
        assertThat(FixtureScans.rule(dsl, "GET /public/info").requirement()).isEqualTo(Requirement.permitAll());
        assertThat(FixtureScans.rule(dsl, "GET /ops/health").requirement().authorities())
                .containsExactly("ROLE_OPS");
        assertThat(FixtureScans.rule(dsl, "GET /orders").requirement()).isEqualTo(Requirement.authenticated());
        // The spring.factories DSL's init runs before the one the chain applies.
        assertThat(FixtureScans.rule(dsl, "GET /internal/debug").requirement()).isEqualTo(Requirement.denyAll());
    }

    @Test
    void formLoginAndLogoutPermitAllLetEveryoneReachTheirPages() {
        ApplicationGraph login = FixtureScans.scan("loginpage");
        assertThat(FixtureScans.rule(login, "GET /signin").requirement()).isEqualTo(Requirement.permitAll());
        assertThat(FixtureScans.rule(login, "GET /bye").requirement()).isEqualTo(Requirement.permitAll());
        assertThat(FixtureScans.rule(login, "GET /home").requirement()).isEqualTo(Requirement.authenticated());
    }

    @Test
    void enableWebSecurityWithoutAChainGetsSpringSecuritysDefault() {
        ApplicationGraph defaults = FixtureScans.scan("defaultchain");
        AuthorizationLocation home = FixtureScans.rule(defaults, "GET /home");
        assertThat(home.mechanism()).isEqualTo("Spring Security default SecurityFilterChain");
        assertThat(home.requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        // Its form login and HTTP Basic look users up.
        assertThat(defaults.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.USER_DETAILS);
    }

    private AuthorizationLocation rule(String ingress) {
        return FixtureScans.rule(graph, ingress);
    }
}
