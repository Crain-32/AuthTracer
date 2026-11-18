package dev.crain.authtracer.link;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import org.junit.jupiter.api.Test;

/**
 * Decision 0075: what a token carried over a link can be rejected for.
 */
class TokenLinkTests {

    private static final Ingress ORDERS = Ingress.of("GET", "/orders", CodeRef.ofMethod("front.Orders", "list()"));
    private static final Egress RELAYED = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001", null,
            CodeRef.ofMethod("front.ItemClient", "get(long)"), null).withCredentials(Credentials.RELAY, "relay");
    private static final Ingress ITEM = Ingress.of("GET", "/items/{itemId}", CodeRef.ofMethod("back.Items", "get(long)"));

    @Test
    void aRelayedTokenNeedNotNameTheAudienceTheCalledServiceAccepts() {
        List<Finding> findings = link(front(Set.of("front-api"), RELAYED), back(Set.of("back-api"), Set.of()));
        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.TOKEN_REJECTED);
            assertThat(finding.message()).isEqualTo("front relays its caller's token to back GET /items/{itemId},"
                    + " which accepts only tokens for back-api, and front's need only name one of front-api: the call"
                    + " is rejected unless the token also names one of back-api");
            assertThat(finding.location()).isEqualTo(RELAYED.callSite());
        });
        // A caller that checks no audience guarantees none.
        assertThat(link(front(Set.of(), RELAYED), back(Set.of("back-api"), Set.of()))).singleElement()
                .extracting(Finding::message).asString().contains("front accepts tokens for any audience");
    }

    @Test
    void aTokenEveryAudienceOfWhichTheCalledServiceAcceptsPasses() {
        assertThat(link(front(Set.of("shop"), RELAYED), back(Set.of("shop", "back-api"), Set.of()))).isEmpty();
        // The called service checks no audience.
        assertThat(link(front(Set.of("shop"), RELAYED), back(Set.of(), Set.of()))).isEmpty();
        // A validator the scan can't read might accept it.
        assertThat(link(front(Set.of("shop"), RELAYED), back(Set.of("back-api"), Set.of("TenantValidator"))))
                .isEmpty();
        // The service's own token is checked as the service.
        assertThat(link(front(Set.of("shop"), RELAYED.withCredentials(Credentials.OAUTH2_CLIENT, "client")),
                back(Set.of("back-api"), Set.of()))).noneMatch(finding -> finding.kind()
                        == Finding.Kind.TOKEN_REJECTED);
    }

    private static List<Finding> link(ApplicationGraph caller, ApplicationGraph callee) {
        return new Linker().link(List.of(caller, callee), ZipkinTraces.of(List.of())).findings();
    }

    private static ApplicationGraph front(Set<String> audiences, Egress call) {
        return graph("front", 9000, audiences, Set.of(), List.of(ORDERS, call),
                List.of(Edge.local(ORDERS.id(), ORDERS.id(), call.id(), 1, List.of())));
    }

    private static ApplicationGraph back(Set<String> audiences, Set<String> unread) {
        return graph("back", 9001, audiences, unread, List.of(ITEM), List.of());
    }

    private static ApplicationGraph graph(String service, int port, Set<String> audiences, Set<String> unread,
            List<Node> nodes, List<Edge> edges) {
        AuthoritySource source = new AuthoritySource(AuthoritySource.Kind.JWT_CLAIMS,
                AuthoritySource.Freshness.SNAPSHOT, "jwt", null, null, new AuthoritySource.Jwt(List.of(),
                        new TreeSet<>(audiences), null, new TreeSet<>(unread), null));
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "test", port, source,
                new ArrayList<>(nodes), edges, List.of(), List.of(), List.of());
    }
}
