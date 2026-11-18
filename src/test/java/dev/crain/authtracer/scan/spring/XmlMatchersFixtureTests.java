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
 * Decision 0097: the beans the XML namespace's {@code request-matcher-ref} and {@code authorization-manager-ref}
 * name, and the legacy {@code FilterSecurityInterceptor} of {@code use-authorization-manager="false"}.
 */
class XmlMatchersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("xmlmatchers");

    @Test
    void aChainsMatcherBeanIsReadLikeAMatcherLambda() {
        assertThat(rule(graph, "GET /partners/admin/keys").requirement().authorities())
                .containsExactly("ROLE_PARTNER_ADMIN");
        assertThat(rule(graph, "GET /partners/orders").requirement().authorities()).containsExactly("ROLE_PARTNER");
        // Requests it doesn't pick go on to the chains after it.
        assertThat(rule(graph, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aRulesMatcherBeanIsSpringsRegexMatcherOrALambdaTheCallerDecides() {
        AuthorizationLocation export = rule(graph, "GET /reports/sales/export");
        assertThat(export.requirement().authorities()).containsExactly("ROLE_AUDITOR");
        assertThat(export.routePattern()).isEqualTo("GET regex /reports/[a-z]+/export");
        AuthorizationLocation sales = rule(graph, "GET /reports/sales");
        assertThat(sales.requirement().kind()).isEqualTo(Kind.OR);
        assertThat(sales.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.PERMIT_ALL, Kind.AUTHENTICATED);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("X-Internal"));
    }

    @Test
    void aRegexMatcherForAnyMethodAndAMatcherAuthTracerCantFind() {
        assertThat(rule(graph, "GET /audit/pages/{page}").requirement().authorities())
                .containsExactly("ROLE_AUDITOR");
        // The application's matcher, as an XML bean, doesn't match /audit; the next one may match anything.
        AuthorizationLocation log = rule(graph, "GET /audit/log");
        assertThat(log.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.PERMIT_ALL, Kind.DENY_ALL);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("RequestMatcher")
                        .contains("permitAll"));
    }

    @Test
    void aLambdaBeansCapturedPrefixAndMatchersAuthTracerCantRead() {
        assertThat(rule(graph, "GET /internal/tools/reindex").requirement().authorities())
                .containsExactly("ROLE_INTERNAL");
        assertThat(rule(graph, "GET /internal/any/status").requirement().authorities()).containsExactly("ROLE_STAFF");
        // Spring's path matcher from a @Bean method, and a regex given a bean, may match first.
        AuthorizationLocation beta = rule(graph, "GET /internal/flags/beta");
        assertThat(beta.routePattern()).isEqualTo("RequestMatcher or RequestMatcher or /internal/**");
        assertThat(beta.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.PERMIT_ALL, Kind.DENY_ALL);
    }

    @Test
    void aManagerBeanDecidesEveryRequestOfItsChain() {
        AuthorizationLocation tenants = rule(graph, "GET /tenants/settings");
        assertThat(tenants.mechanism()).isEqualTo("authorization-manager-ref");
        assertThat(tenants.requirement().authorities()).containsExactly("ROLE_TENANT");
        assertThat(tenants.requirement().decidedBy().className()).isEqualTo("fixtures.xmlmatchers.TenantManager");
    }

    @Test
    void aManagerBeanAuthTracerCantFindIsAnOpaqueRequirement() {
        assertThat(rule(graph, "GET /vendors/catalog").requirement())
                .isEqualTo(Requirement.expression("authorization-manager-ref(vendorManager)"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("vendorManager"));
    }

    @Test
    void theLegacyInterceptorsVotersAndWhatNoRuleMatches() {
        assertThat(rule(graph, "GET /legacy/admin/users").requirement().authorities())
                .containsExactly("ROLE_ADMIN", "ROLE_OPS");
        assertThat(rule(graph, "GET /legacy/secure/vault").requirement().kind())
                .isEqualTo(Kind.FULLY_AUTHENTICATED);
        AuthorizationLocation about = rule(graph, "GET /legacy/about");
        assertThat(about.requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(about.mechanism()).isEqualTo("intercept-url (FilterSecurityInterceptor) (no rule matched: let"
                + " through)");
    }
}
