package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class OrdersFixtureTests {

    private static final String SERVICE = "location:METHOD:fixtures.orders.OrderService#";

    private final ApplicationGraph graph = FixtureScans.scan("orders");

    @Test
    void controllerMappingsBecomeIngress() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /orders/{id}",
                "ingress:POST /orders",
                "ingress:DELETE /orders/{id}",
                "ingress:GET /orders/{id}/stock",
                "ingress:GET /orders/{id}/summary",
                "ingress:GET /orders/{id}/note",
                "ingress:GET /orders/legacy",
                "ingress:HEAD /orders/legacy");
    }

    @Test
    void preAuthorizeIsNormalizedToAuthorities() {
        assertThat(path(graph, "ingress:GET /orders/{id}")).containsExactly(SERVICE + "find(long):@PreAuthorize");
        AuthorizationLocation find = location(SERVICE + "find(long):@PreAuthorize");
        assertThat(find.requirement().kind()).isEqualTo(Requirement.Kind.ANY_AUTHORITY);
        assertThat(find.requirement().authorities()).containsExactly("SCOPE_orders.read");
        assertThat(find.phase()).isEqualTo(AuthorizationLocation.Phase.PRE);
        assertThat(find.denial().kind()).isEqualTo(AuthorizationLocation.Denial.Kind.THROW);
    }

    @Test
    void securedThenEgressInCallOrder() {
        assertThat(path(graph, "ingress:POST /orders")).containsExactly(
                SERVICE + "create(fixtures.orders.Order):@Secured",
                "egress:fixtures.orders.RemoteInventory#reserve(java.lang.String) POST /reservations/{sku}");
        Egress reserve = (Egress) graph.node(
                "egress:fixtures.orders.RemoteInventory#reserve(java.lang.String) POST /reservations/{sku}").get();
        assertThat(reserve.baseUrl()).isEqualTo("http://inventory:8080");
        assertThat(reserve.callSite().line()).isNotNull();
    }

    @Test
    void metaAnnotationsResolveToTheirPreAuthorize() {
        assertThat(path(graph, "ingress:DELETE /orders/{id}")).containsExactly(SERVICE + "delete(long):@PreAuthorize");
        assertThat(location(SERVICE + "delete(long):@PreAuthorize").requirement().authorities())
                .containsExactly("ROLE_ADMIN");
    }

    @Test
    void checksBeforeEgressOnTheSamePath() {
        assertThat(path(graph, "ingress:GET /orders/{id}/stock")).containsExactly(
                SERVICE + "find(long):@PreAuthorize",
                "egress:fixtures.orders.RemoteInventory#stock(java.lang.String) GET /stock/{sku}");
    }

    @Test
    void selfInvocationSkipsTheProxy() {
        assertThat(path(graph, "ingress:GET /orders/{id}/summary")).isEmpty();
        assertThat(findings(Finding.Kind.BYPASSED)).anySatisfy(message -> assertThat(message)
                .contains("OrderService#audited(long)").contains("calls it on this"));
    }

    @Test
    void annotationsThatNeverRunAreFindingsNotLocations() {
        assertThat(path(graph, "ingress:GET /orders/{id}/note")).isEmpty();
        assertThat(findings(Finding.Kind.NOT_ENFORCED)).satisfiesExactlyInAnyOrder(
                message -> assertThat(message).contains("OrderNote#getText").contains("not a Spring bean"),
                message -> assertThat(message).contains("@RolesAllowed").contains("jsr250Enabled = true"),
                message -> assertThat(message).contains("OrderService#purge").contains("private"));
    }

    @Test
    void noHttpSecurityMeansUnknownAuthoritySource() {
        assertThat(graph.authoritySource()).isEqualTo(AuthoritySource.UNKNOWN);
    }

    private AuthorizationLocation location(String id) {
        return (AuthorizationLocation) graph.node(id).orElseThrow(() -> new AssertionError("No node " + id));
    }

    private java.util.List<String> findings(Finding.Kind kind) {
        return graph.findings().stream().filter(finding -> finding.kind() == kind).map(Finding::message).toList();
    }
}
