package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0097 (MSG-06): the XML namespace's {@code <websocket-message-broker>} rules, with the WebSocket namespace's
 * broker as the way the messages arrive, and a security XML file AuthTracer can't parse.
 */
class XmlWebSocketFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("xmlwebsocket");

    @Test
    void theXmlBrokersDestinationsAreTheMessagesWaysIn() {
        assertThat(graph.nodes()).extracting(node -> node.id()).contains("ingress:MESSAGE /app/admin/purge",
                "ingress:SUBSCRIBE /app/rooms", "ingress:SUBSCRIBE /topic/audit/events");
        // The handshake's HTTP rule comes first.
        assertThat(checks(graph, "MESSAGE /app/chat/send").getFirst().mechanism()).isEqualTo("intercept-url");
    }

    @Test
    void theFirstInterceptMessageThatMatchesDecides() {
        AuthorizationLocation purge = messageRule(graph, "MESSAGE /app/admin/purge");
        assertThat(purge.requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(purge.routePattern()).isEqualTo("intercept-message pattern=/app/admin/**");
        assertThat(purge.target().className()).isEqualTo("WEB-INF/spring/security.xml");
        assertThat(purge.target().line()).isEqualTo(14);
        assertThat(messageRule(graph, "SUBSCRIBE /topic/audit/events").requirement().kind())
                .isEqualTo(Kind.DENY_ALL);
        assertThat(messageRule(graph, "MESSAGE /app/chat/send").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aMessageNoInterceptMessageMatchesIsLetThrough() {
        for (String ingress : List.of("MESSAGE /app/misc/echo", "SUBSCRIBE /app/rooms", "SUBSCRIBE /topic/misc/echo")) {
            AuthorizationLocation rule = messageRule(graph, ingress);
            assertThat(rule.requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
            assertThat(rule.mechanism()).endsWith("(no intercept-message matched: let through)");
        }
    }

    @Test
    void anExpressionHandlerAndAFileAuthTracerCantParseAreFindings() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("messageExpressions"))
                .anySatisfy(message -> assertThat(message).contains("legacy-security.xml"));
    }

    @Test
    void aManagerBeanTheXmlNamesDecidesAndAnUnwiredBrokerNeverRuns() {
        ApplicationGraph managed = FixtureScans.scan("xmlwebsocketmanager");
        assertThat(messageRule(managed, "MESSAGE /app/orders/place").requirement().authorities())
                .containsExactly("ROLE_BUYER");
        assertThat(messageRule(managed, "MESSAGE /app/status").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        // Both application destination prefixes.
        assertThat(messageRule(managed, "MESSAGE /api/status").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(managed.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("messageManager"))
                .anySatisfy(message -> assertThat(message).contains("draftSecurity").contains("never runs"));
        assertThat(checks(managed, "MESSAGE /app/status")).filteredOn(location -> location.mechanism()
                .startsWith(MessageSecurityRules.MECHANISM)).hasSize(1);
    }

    @Test
    void eachBrokersInterceptorChecksAndOneTheJavaConfigurationMayWireIsAFinding() {
        ApplicationGraph beans = FixtureScans.scan("xmlwebsocketbeans");
        List<AuthorizationLocation> rules = checks(beans, "MESSAGE /app/restart").stream()
                .filter(location -> location.mechanism().startsWith(MessageSecurityRules.MECHANISM)).toList();
        assertThat(rules).hasSize(2);
        assertThat(rules.getFirst().requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(rules.getFirst().requirement().decidedBy().className())
                .isEqualTo("fixtures.xmlwebsocketbeans.OpsMessageManager");
        assertThat(rules.getLast().requirement().expression())
                .isEqualTo("authorization-manager-ref(missingManager)");
        assertThat(beans.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("missingManager"))
                .anySatisfy(message -> assertThat(message).contains("manualSecurity")
                        .contains("XmlWebSocketBeansConfig#configureClientInboundChannel"));
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
