package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0039: the message rule builder's matchers and requirements, the managers {@code access(..)} is given, and
 * the managers that never reach the inbound channel or can't be read.
 */
class StompRulesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("stomprules");

    @Test
    void eachMatcherAndRequirementOfTheBuilder() {
        AuthorizationLocation admin = messageRule(graph, "MESSAGE /app/admin/purge");
        assertThat(admin.routePattern()).isEqualTo("simpMessageDestMatchers(/app/admin/**)");
        assertThat(admin.requirement().authorities()).containsExactly("SCOPE_admin");
        assertThat(messageRule(graph, "SUBSCRIBE /topic/audit/events").requirement().kind())
                .isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(messageRule(graph, "MESSAGE /app/saved/drafts").requirement().kind()).isEqualTo(Kind.REMEMBER_ME);
        assertThat(messageRule(graph, "MESSAGE /app/guest/hello").requirement()).isEqualTo(Requirement.anonymous());
    }

    @Test
    void theManagerAccessIsGivenDecides() {
        assertThat(messageRule(graph, "MESSAGE /app/reports/run").requirement().authorities())
                .containsExactly("SCOPE_admin", "SCOPE_reports");
        assertThat(messageRule(graph, "MESSAGE /app/groups/sync").requirement().authorities())
                .containsExactly("GROUP_OPS", "GROUP_SRE");
        assertThat(messageRule(graph, "MESSAGE /app/members/list").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(messageRule(graph, "MESSAGE /app/ops/restart").requirement().kind())
                .isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(messageRule(graph, "MESSAGE /app/drafts/save").requirement().kind()).isEqualTo(Kind.REMEMBER_ME);
        assertThat(messageRule(graph, "MESSAGE /app/lobby/join").requirement()).isEqualTo(Requirement.anonymous());
        assertThat(messageRule(graph, "MESSAGE /app/open/ping").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(messageRule(graph, "MESSAGE /app/closed/legacy").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(messageRule(graph, "MESSAGE /app/vip/lounge").requirement().decidedBy().method())
                .startsWith("lambda$messageAuthorizationManager$");
    }

    @Test
    void aMessageMatcherAuthTracerCantEvaluateMayMatchFirst() {
        AuthorizationLocation chat = messageRule(graph, "MESSAGE /app/chat/send");
        assertThat(chat.mechanism()).isEqualTo(MessageSecurityRules.MECHANISM + " (a MessageMatcher may match first)");
        assertThat(chat.routePattern()).isEqualTo("matchers(MessageMatcher) or simpDestMatchers(/app/chat/**)");
        assertThat(chat.requirement().kind()).isEqualTo(Kind.OR);
        assertThat(chat.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).filteredOn(message -> message.contains("a MessageMatcher"))
                .singleElement().asString().contains("matchers(MessageMatcher)");
        // Rules before it match first.
        assertThat(messageRule(graph, "MESSAGE /app/admin/purge").mechanism())
                .isEqualTo(MessageSecurityRules.MECHANISM);
    }

    @Test
    void aMessageNoRuleMatchesIsDenied() {
        AuthorizationLocation echo = messageRule(graph, "MESSAGE /app/misc/echo");
        assertThat(echo.routePattern()).isEqualTo("matchers(MessageMatcher) or default");
        assertThat(echo.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.ANY_AUTHORITY, Kind.DENY_ALL);
    }

    @Test
    void withoutWebSocketSecurityTheManagerBeanNeverRuns() {
        ApplicationGraph unsecured = FixtureScans.scan("stompunsecured");
        assertThat(checks(unsecured, "MESSAGE /app/admin/reset")).extracting(AuthorizationLocation::mechanism)
                .doesNotContain(MessageSecurityRules.MECHANISM);
        assertThat(unsecured.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).singleElement().asString()
                .contains("messageAuthorizationManager", "@EnableWebSocketSecurity");
    }

    @Test
    void aManagerTheApplicationsInterceptorIsGivenIsOpaque() {
        ApplicationGraph injected = FixtureScans.scan("stompinjected");
        assertThat(messageRule(injected, "MESSAGE /app/ping").requirement().withCode(null))
                .isEqualTo(Requirement.expression("AuthorizationManager<Message<?>>"));
        assertThat(injected.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void aLambdaManagerDecidesEveryMessage() {
        ApplicationGraph lambda = FixtureScans.scan("stomplambda");
        AuthorizationLocation ticker = messageRule(lambda, "MESSAGE /app/ticker");
        assertThat(ticker.routePattern()).isEqualTo("anyMessage");
        assertThat(ticker.requirement().decidedBy().className()).isEqualTo("fixtures.stomplambda.StompLambdaConfig");
    }

    private static AuthorizationLocation messageRule(ApplicationGraph graph, String ingress) {
        return checks(graph, ingress).stream()
                .filter(location -> location.mechanism().startsWith(MessageSecurityRules.MECHANISM)).findFirst()
                .orElseThrow();
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
