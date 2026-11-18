package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The request rules' DSL as real configurations write it: matchers by HTTP method or dispatcher type alone, Boot's
 * static resource locations narrowed, rules that need every authority, and managers composed or hand-written.
 */
class DslFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dslforms");

    @Test
    void aMethodOnlyMatcherTakesThatMethodOnEveryPath() {
        // The first rule after withObjectPostProcessor(..), which returns the registry.
        assertThat(rule(graph, "OPTIONS /items").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "OPTIONS /items").routePattern()).isEqualTo("OPTIONS /**");
        assertThat(rule(graph, "GET /items").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(graph, "PUT /items/{id}").requirement().kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(rule(graph, "PUT /items/{id}").routePattern()).isEqualTo("PUT regex .*");
    }

    @Test
    void aRegexRuleStopsMatchingOnceARequestHasAQueryString() {
        assertThat(rule(graph, "GET /legacy/report").requirement().kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(rule(graph, "GET /items/{id}").routePattern()).isEqualTo("regex /items/[0-9]+");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /legacy/report:")
                        .contains("(requires fullyAuthenticated)", "gets the default instead (denyAll)"))
                // The rule a request with a query string falls through to asks for the same.
                .noneSatisfy(message -> assertThat(message).contains("GET /items/{id}"));
    }

    @Test
    void aDispatcherTypeMatcherNeverTakesARequestsOwnDispatch() {
        assertThat(rule(graph, "GET /items").routePattern()).isEqualTo("anyRequest");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("dispatcherTypeMatchers"));
    }

    @Test
    void staticResourceLocationsCanBeNamedOrExcluded() {
        assertThat(rule(graph, "GET /css/site").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /css/site").routePattern()).isEqualTo("/css/**,/js/**");
        assertThat(rule(graph, "GET /fonts/brand").requirement().authorities()).containsExactly("ROLE_DESIGNER");
        assertThat(rule(graph, "GET /webjars/lib").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void rulesThatNeedEveryAuthority() {
        Requirement create = rule(graph, "POST /items").requirement();
        assertThat(create.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(create.authorities()).containsExactly("ROLE_EDITOR", "ROLE_PUBLISHER");
        Requirement delete = rule(graph, "DELETE /items/{id}").requirement();
        assertThat(delete.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(delete.authorities()).containsExactly("SCOPE_items.delete", "SCOPE_items.write");
        Requirement export = rule(graph, "GET /reports/export").requirement();
        assertThat(export.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(export.authorities()).containsExactly("SCOPE_reports.export", "SCOPE_reports.read");
    }

    @Test
    void rememberMeAndComposedManagers() {
        assertThat(rule(graph, "GET /session/refresh").requirement().kind()).isEqualTo(Kind.REMEMBER_ME);
        Requirement audit = rule(graph, "GET /audit/log").requirement();
        assertThat(audit.kind()).isEqualTo(Kind.AND);
        assertThat(audit.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.FULLY_AUTHENTICATED);
        Requirement signup = rule(graph, "GET /signup").requirement();
        assertThat(signup.kind()).isEqualTo(Kind.NOT);
        assertThat(signup.operands()).extracting(Requirement::kind).containsExactly(Kind.AUTHENTICATED);
    }

    @Test
    void aRolePrefixGivenToTheFactoryReplacesRole() {
        // AuthorityAuthorizationManager.hasAnyRole(rolePrefix, roles): the first argument is the prefix, not a role.
        Requirement partners = rule(graph, "GET /partners/deals").requirement();
        assertThat(partners.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(partners.authorities()).containsExactly("PARTNER_GOLD", "PARTNER_SILVER");
    }

    @Test
    void aHandWrittenManagerIsNamedByItsClass() {
        Requirement office = rule(graph, "GET /office/printers").requirement();
        assertThat(office.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(office.expression()).isEqualTo("access(OfficeNetwork)");
        assertThat(office.decidedBy().className()).isEqualTo("fixtures.dslforms.OfficeNetwork");
    }
}
