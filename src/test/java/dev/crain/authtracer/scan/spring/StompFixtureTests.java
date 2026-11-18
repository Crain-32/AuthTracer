package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0039: STOMP messages and subscriptions.
 */
class StompFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("stomp");

    @Test
    void messagesPassTheHandshakeThenTheFirstMatchingMessageRule() {
        List<AuthorizationLocation> chat = checks("ingress:MESSAGE /app/chat");
        assertThat(chat).extracting(AuthorizationLocation::mechanism)
                .containsExactly("authorizeHttpRequests", MessageSecurityRules.MECHANISM);
        assertThat(chat.getFirst().routePattern()).isEqualTo("/ws");
        // AuthorityAuthorizationManager: no role hierarchy, so ROLE_ADMIN doesn't count.
        assertThat(chat.getLast().requirement().authorities()).containsExactly("ROLE_USER");
        assertThat(checks("ingress:MESSAGE /app/admin/announce").getLast().requirement().authorities())
                .containsExactly("ROLE_ADMIN");
        assertThat(checks("ingress:SUBSCRIBE /app/rooms").getLast().routePattern())
                .isEqualTo("simpDestMatchers(/app/**)");
    }

    @Test
    void aBroadcastReachesTheTopicsSubscribers() {
        // The sender gets nothing back; the topic's subscribers get the reply.
        assertThat(ingress("ingress:MESSAGE /app/chat").response()).isNull();
        Ingress messages = ingress("ingress:SUBSCRIBE /topic/messages");
        assertThat(messages.response().type()).isEqualTo("fixtures.stomp.ChatMessage");
        assertThat(checks("ingress:SUBSCRIBE /topic/messages").getLast().requirement().authorities())
                .containsExactly("ROLE_USER");
        // Only admins announce, but anyone may subscribe.
        assertThat(checks("ingress:SUBSCRIBE /topic/announcements").getLast().requirement().kind())
                .isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals(
                "ingress:SUBSCRIBE /topic/announcements")).extracting(Exposures.Exposure::field)
                .contains("text", "author");
        assertThat(ingress("ingress:MESSAGE /app/private").response().type()).isEqualTo("fixtures.stomp.ChatMessage");
        assertThat(ingress("ingress:SUBSCRIBE /app/rooms").response()).isNotNull();
    }

    @Test
    void whatTheCodeSendsToATopicReachesItsSubscribers() {
        Ingress orders = ingress("ingress:SUBSCRIBE /topic/orders");
        assertThat(orders.response().type()).isEqualTo("fixtures.stomp.Order");
        assertThat(orders.handler().method()).startsWith("place(");
        assertThat(checks("ingress:SUBSCRIBE /topic/orders").getLast().requirement().authorities())
                .containsExactly("ROLE_USER");
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals(
                "ingress:SUBSCRIBE /topic/orders")).extracting(Exposures.Exposure::field)
                .contains("customerEmail", "total");
    }

    @Test
    void withoutAManagerBeanEveryMessageMustBeAuthenticated() {
        ApplicationGraph defaults = FixtureScans.scan("stompdefault");
        assertThat(path(defaults, "ingress:MESSAGE /app/ping").stream().map(id -> defaults.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals(MessageSecurityRules.MECHANISM)))
                .singleElement().satisfies(location -> assertThat(location.requirement().kind())
                        .isEqualTo(Requirement.Kind.AUTHENTICATED));
    }

    @Test
    void aChannelInterceptorTheApplicationAddsAndASingleManager() {
        ApplicationGraph manual = FixtureScans.scan("stompmanual");
        assertThat(messageRule(manual, "ingress:MESSAGE /app/admin/reset").requirement().authorities())
                .containsExactly("ROLE_ADMIN");
        assertThat(messageRule(manual, "ingress:MESSAGE /app/ping").requirement().authorities())
                .containsExactly("ROLE_USER");
        ApplicationGraph single = FixtureScans.scan("stompsingle");
        assertThat(messageRule(single, "ingress:MESSAGE /app/ping").requirement().authorities())
                .containsExactly("ROLE_USER");
    }

    @Test
    void classLevelMappingsDefaultDestinationsAndPushesToAUsersQueue() {
        ApplicationGraph controllers = FixtureScans.scan("stompcontrollers");
        // No application destination prefix: the class's @MessageMapping prefixes its methods', a bare one is the
        // class's. @SendTo without a destination is /topic and the message's; the class's named @SendTo wins over
        // the method's unnamed one. convertAndSendToUser is the user's /user queue, once however often it's sent;
        // a computed destination and send(..) aren't read.
        assertThat(controllers.nodes(Ingress.class)).extracting(Ingress::id)
                .filteredOn(id -> id.startsWith("ingress:MESSAGE") || id.startsWith("ingress:SUBSCRIBE"))
                .containsExactlyInAnyOrder("ingress:MESSAGE /rooms/{room}/send", "ingress:MESSAGE /rooms",
                        "ingress:MESSAGE /audit/login", "ingress:SUBSCRIBE /topic/rooms/{room}/send",
                        "ingress:SUBSCRIBE /topic/audit", "ingress:SUBSCRIBE /user/queue/notifications");
        // @SendToUser answers the sender.
        assertThat(((Ingress) controllers.node("ingress:MESSAGE /rooms").orElseThrow()).response().type())
                .isEqualTo("java.lang.String");
        assertThat(((Ingress) controllers.node("ingress:SUBSCRIBE /user/queue/notifications").orElseThrow())
                .response().type()).isEqualTo("fixtures.stompcontrollers.Notification");
    }

    private static AuthorizationLocation messageRule(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals(MessageSecurityRules.MECHANISM)).findFirst()
                .orElseThrow();
    }

    private Ingress ingress(String id) {
        return (Ingress) graph.node(id).orElseThrow();
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
