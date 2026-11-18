package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0037: multi-factor authentication built from multiFactor(), AllRequiredFactorsAuthorizationManager and
 * RequiredFactor, as a factory bean for every rule and as managers for some.
 */
class MfaFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("mfaforms");

    @Test
    void aFactoryBeanAsksEveryRuleItBuildsForItsFactors() {
        Requirement home = rule(graph, "GET /home").requirement();
        assertThat(home.kind()).isEqualTo(Kind.AND);
        assertThat(home.operands()).extracting(Requirement::kind).containsExactly(Kind.AUTHENTICATED,
                Kind.ALL_AUTHORITIES);
        assertThat(home.operands().getLast().authorities()).containsExactly("FACTOR_PASSWORD", "FACTOR_SMS");
        assertThat(home.operands().getLast().expression()).isEqualTo("factors FACTOR_PASSWORD, FACTOR_SMS (recent)");
        assertThat(rule(graph, "GET /public").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aFactoryWithAConditionAsksOnlySomeCallers() {
        Requirement admin = rule(graph, "GET /admin/users").requirement();
        assertThat(admin.kind()).isEqualTo(Kind.AND);
        assertThat(admin.operands().getFirst().authorities()).containsExactly("ROLE_ADMIN");
        Requirement factors = admin.operands().getLast();
        assertThat(factors.kind()).isEqualTo(Kind.OR);
        assertThat(factors.expression()).isEqualTo("factors FACTOR_OTT when a condition");
    }

    @Test
    void requiredFactorsBuiltOneByOne() {
        Requirement keys = rule(graph, "GET /keys/rotate").requirement();
        assertThat(keys.kind()).isEqualTo(Kind.OR);
        assertThat(keys.operands()).flatExtracting(Requirement::authorities)
                .containsExactly("FACTOR_WEBAUTHN", "FACTOR_X509");
        Requirement payments = rule(graph, "GET /payments/send").requirement();
        assertThat(payments.authorities()).containsExactly("FACTOR_SMS");
        assertThat(payments.expression()).isEqualTo("factors FACTOR_SMS (recent)");
    }

    @Test
    void anAnnotationWithoutAuthoritiesRegistersNoFactory() {
        ApplicationGraph endpoints = FixtureScans.scan("mfaendpoints");
        assertThat(rule(endpoints, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        Requirement admin = rule(endpoints, "GET /admin/users").requirement();
        assertThat(admin.kind()).isEqualTo(Kind.AND);
        assertThat(admin.operands().getLast().authorities()).containsExactly("FACTOR_OTT", "FACTOR_PASSWORD");
    }

    @Test
    void aCustomizerOfTheAnnotationsFactoryAddsFactorsAndACondition() {
        Requirement home = rule(FixtureScans.scan("mfacustomizer"), "GET /home").requirement();
        assertThat(home.kind()).isEqualTo(Kind.AND);
        Requirement factors = home.operands().getLast();
        assertThat(factors.kind()).isEqualTo(Kind.OR);
        assertThat(factors.expression()).isEqualTo("factors FACTOR_OTT, FACTOR_PASSWORD, FACTOR_X509 when a condition");
    }
}
