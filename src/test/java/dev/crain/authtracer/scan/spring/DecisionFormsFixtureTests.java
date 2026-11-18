package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.TreeSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decisions 0064 and 0065: decision code in more of the forms applications write it.
 */
class DecisionFormsFixtureTests {

    private static final String CONFIG = "fixtures.decisionforms.DecisionFormsConfig";

    private final ApplicationGraph graph = FixtureScans.scan("decisionforms");

    @Test
    void aManagerThatCombinesBuiltInOnesIsWhatTheyCombineTo() {
        Requirement composite = rule(graph, "GET /composite/check").requirement();
        assertThat(composite.kind()).isEqualTo(Kind.OR);
        assertThat(composite.operands()).extracting(Requirement::authorities)
                .containsExactly(new TreeSet<>(List.of("ROLE_ADMIN")), new TreeSet<>(List.of("ROLE_OPS")));
        assertThat(composite.decidedBy().className()).isEqualTo("fixtures.decisionforms.Composite");
        assertThat(opaque()).noneMatch(message -> message.contains("Composite"));
        Requirement negated = rule(graph, "GET /negated/check").requirement();
        assertThat(negated.kind()).isEqualTo(Kind.NOT);
        assertThat(negated.operands().getFirst().authorities()).containsExactly("ROLE_BANNED");
    }

    @Test
    void aManagerBeanWrittenAsALambdaIsWhatTheLambdaDecides() {
        // Two manager beans: the one the chain method's parameter is named for.
        Requirement internal = rule(graph, "GET /internal/check").requirement();
        assertThat(internal.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(internal.authorities()).containsExactly("ROLE_INTERNAL");
        assertThat(internal.decidedBy().className()).isEqualTo(CONFIG);
        assertThat(internal.decidedBy().method()).startsWith("lambda$internalOnly$");
    }

    @Test
    void aPolicyInterfacesMethodIsDecidedThereUnread() {
        Requirement policy = rule(graph, "GET /policy/check").requirement();
        assertThat(policy.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(policy.decidedBy().className()).isEqualTo("fixtures.decisionforms.Policy");
        assertThat(opaque()).anySatisfy(message -> assertThat(message)
                .startsWith("fixtures.decisionforms.Policy#decide(").contains("decides authorizeHttpRequests on"
                        + " /policy/** in a way AuthTracer can't reduce"));
    }

    @Test
    void aManagerFactoryBeanCalledFromSpelIsItsPrefixsRole() {
        Requirement groups = preAuthorize("GET /groups").requirement();
        assertThat(groups.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(groups.authorities()).containsExactly("GROUP_ADMIN");
        assertThat(groups.decidedBy().method()).startsWith("groups(");
        Requirement all = preAuthorize("GET /groups/all").requirement();
        assertThat(all.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(all.authorities()).containsExactly("GROUP_ADMIN", "GROUP_AUDITOR");
        // A prefix from the environment: what it asks for is unknown.
        Requirement tenants = preAuthorize("GET /tenants").requirement();
        assertThat(tenants.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(tenants.decidedBy().method()).startsWith("tenants(");
    }

    @Test
    void aBeanWhoseMethodHasNoBodyIsDecidedByTheMethodThatMakesIt() {
        Requirement beta = preAuthorize("GET /beta").requirement();
        assertThat(beta.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(beta.decidedBy().className()).isEqualTo(CONFIG);
        assertThat(beta.decidedBy().method()).startsWith("featureFlags(");
    }

    @Test
    void aBeanDefinedOncePerProfileIsLeftAsTheExpression() {
        Requirement gate = preAuthorize("GET /gate").requirement();
        assertThat(gate).isEqualTo(Requirement.expression("@gate.allows(authentication)"));
        assertThat(opaque()).noneMatch(message -> message.contains("@gate"));
    }

    @Test
    void codeThatReadsATableOrAsksAnotherServiceIsLive() {
        AuthorizationLocation seats = preAuthorize("GET /seats");
        assertThat(seats.requirement().kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(seats.freshness()).isEqualTo(AuthoritySource.Freshness.LIVE);
        assertThat(opaque()).anySatisfy(message -> assertThat(message).startsWith("fixtures.decisionforms.Seats#")
                .contains("(it reads JdbcTemplate#queryForObject, so what it decides is Live)"));
        AuthorizationLocation quota = preAuthorize("GET /quota");
        assertThat(quota.freshness()).isEqualTo(AuthoritySource.Freshness.LIVE);
        assertThat(opaque()).anySatisfy(message -> assertThat(message).startsWith("fixtures.decisionforms.Quota#")
                .contains("(it calls another service (").contains("RestClient#get"));
        List<String> steps = path(graph, "ingress:GET /quota");
        assertThat(graph.node(steps.getLast()).orElseThrow()).isInstanceOfSatisfying(Egress.class,
                egress -> assertThat(egress.uriTemplate()).isEqualTo("/quotas/{user}"));
    }

    @Test
    void theRootsAuthenticationHasTheAuthoritiesTheCodeCompares() {
        assertThat(preAuthorize("GET /self").requirement().authorities()).containsExactly("ROLE_SELF");
    }

    @Test
    void aBeanNothingDefinesIsAFindingAlsoBesideACheckThatIsRead() {
        Requirement fallback = preAuthorize("GET /fallback").requirement();
        assertThat(fallback.operands()).extracting(Requirement::kind).containsExactly(Kind.ANY_AUTHORITY,
                Kind.EXPRESSION);
        assertThat(opaque()).contains("@PreAuthorize on fixtures.decisionforms.DecisionFormsController#fallback()"
                + " calls the bean @fallback, which AuthTracer finds no bean for: if there is none, the expression"
                + " fails and every caller is denied");
    }

    private AuthorizationLocation preAuthorize(String ingress) {
        return path(graph, "ingress:" + ingress).stream().filter(id -> id.endsWith(":@PreAuthorize"))
                .map(id -> (AuthorizationLocation) graph.node(id).orElseThrow()).findFirst().orElseThrow();
    }

    private List<String> opaque() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
    }
}
