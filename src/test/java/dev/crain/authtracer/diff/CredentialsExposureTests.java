package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;

/**
 * Decision 0021: the called service's checks count for the original caller only when the call relays its token.
 */
class CredentialsExposureTests {

    private static final Egress GET_ITEM = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001",
            null, CodeRef.ofMethod("front.ItemClient", "get(long)"), new Payload("front.ItemDto", false));
    private static final Ingress ORDERS = Ingress.of("GET", "/orders", CodeRef.ofMethod("front.Orders", "get()"))
            .withResponse(new Payload("front.View", false));
    private static final Ingress ITEM = Ingress.of("GET", "/items/{itemId}", CodeRef.ofMethod("back.Items", "get(long)"))
            .withResponse(new Payload("back.Item", false));
    private static final AuthorizationLocation AUTHENTICATED = new AuthorizationLocation(
            "location:HTTP_REQUEST:back.Config:0:anyRequest", "authorizeHttpRequests",
            AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE, Requirement.authenticated(),
            CodeRef.ofClass("back.Config"), null, "anyRequest", AuthorizationLocation.Denial.THROW, false);
    private static final AuthorizationLocation PRICE_CHECK = new AuthorizationLocation(
            "location:FIELD:back.Item#getPrice():@PreAuthorize", "@PreAuthorize", AuthorizationLocation.Scope.FIELD,
            AuthorizationLocation.Phase.PRE, Requirement.anyAuthority(List.of("ROLE_ADMIN")),
            CodeRef.ofMethod("back.Item", "getPrice()"), "price", null, AuthorizationLocation.Denial.THROW, true);

    @Test
    void aRelayedCallCarriesTheDownstreamChecks() {
        SystemGraph system = link(Credentials.RELAY);
        assertThat(price(system).requirement()).isEqualTo("ROLE_ADMIN");
        assertThat(system.findings()).isEmpty();
    }

    @Test
    void anOAuth2ClientTokenIsCheckedDownstreamNotTheCaller() {
        SystemGraph system = link(Credentials.OAUTH2_CLIENT);
        assertThat(price(system).requirement()).isEqualTo("none");
        assertThat(price(system).sources()).containsExactly("back/field:back.Item.price");
        assertThat(system.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.BYPASSED);
            assertThat(finding.message()).contains("front calls back GET /items/{itemId} with its own OAuth2 client token",
                    "field check on price", "don't count");
        });
    }

    @Test
    void unknownCredentialsAreNotCountedEither() {
        SystemGraph system = link(Credentials.UNKNOWN);
        assertThat(price(system).requirement()).isEqualTo("none");
        assertThat(system.findings()).singleElement().extracting(Finding::kind).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
    }

    @Test
    void graphsFromBeforeCredentialsWereRecordedKeepCountingThem() {
        assertThat(price(link(null)).requirement()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    void switchingFromRelayToTheServicesOwnTokenFailsTheDiff() {
        DiffReport report = GraphDiff.compare(link(Credentials.RELAY), link(Credentials.OAUTH2_CLIENT));
        assertThat(report.changes()).anySatisfy(change -> {
            assertThat(change.kind()).isEqualTo(DiffReport.Kind.WEAKENED);
            assertThat(change.endpoint()).isEqualTo("GET /orders");
            assertThat(change.field()).isEqualTo("price");
        });
        assertThat(report.failed(false)).isTrue();
    }

    private static Exposures.Exposure price(SystemGraph system) {
        return Exposures.of(system).stream()
                .filter(exposure -> exposure.endpoint().equals("GET /orders") && exposure.field().equals("price"))
                .findFirst().orElseThrow();
    }

    private static SystemGraph link(Credentials credentials) {
        Egress egress = GET_ITEM.withCredentials(credentials, credentials == null ? null : "test");
        ApplicationGraph front = graph("front", 9000, List.of(ORDERS, egress,
                Field.of("front.View", "price", "price", "java.math.BigDecimal"),
                Field.of("front.ItemDto", "price", "price", "java.math.BigDecimal")),
                List.of(Edge.local(ORDERS.id(), ORDERS.id(), egress.id(), 1, List.of())),
                List.of(Flow.local(ORDERS.id(), Field.id("front.ItemDto", "price"), Field.id("front.View", "price"),
                        FieldSource.DIRECT)));
        ApplicationGraph back = graph("back", 9001, List.of(ITEM, AUTHENTICATED, PRICE_CHECK,
                Field.of("back.Item", "price", "price", "java.math.BigDecimal")),
                List.of(Edge.local(ITEM.id(), ITEM.id(), AUTHENTICATED.id(), 1, List.of()),
                        Edge.local(ITEM.id(), AUTHENTICATED.id(), PRICE_CHECK.id(), 2, List.of())), List.of());
        return new Linker().link(List.of(front, back), ZipkinTraces.of(List.of()));
    }

    private static ApplicationGraph graph(String service, int port, List<Node> nodes, List<Edge> edges,
            List<Flow> flows) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, "test", port, AuthoritySource.UNKNOWN,
                new ArrayList<>(nodes), edges, flows, List.of(), List.of());
    }
}
