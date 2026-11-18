package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0041: Actuator's web endpoints.
 */
class ActuatorFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("actuator");

    @Test
    void theExposedEndpointsOperations() {
        List<String> ingress = graph.nodes().stream().filter(Ingress.class::isInstance)
                .map(node -> ((Ingress) node).id()).toList();
        assertThat(ingress).contains("ingress:GET /actuator/health", "ingress:GET /actuator/health/{*path}",
                "ingress:GET /actuator/info", "ingress:GET /actuator/env", "ingress:GET /actuator/env/{toMatch}",
                "ingress:GET /actuator/loggers", "ingress:GET /actuator/loggers/{name}",
                "ingress:GET /actuator/heapdump", "ingress:GET /actuator/audit", "ingress:GET /actuator/audit/{id}",
                "ingress:DELETE /actuator/audit");
        // Read-only loggers can't be changed, nor can ops, read-only by its own default; beans isn't exposed.
        assertThat(ingress).doesNotContain("ingress:POST /actuator/loggers/{name}", "ingress:GET /actuator/beans",
                "ingress:POST /actuator/ops").contains("ingress:GET /actuator/ops");
        assertThat(((Ingress) graph.node("ingress:GET /actuator/audit/{id}").orElseThrow()).response().type())
                .isEqualTo("fixtures.actuator.AuditRecord");
    }

    @Test
    void endpointRequestMatchers() {
        assertThat(rule("ingress:GET /actuator/health/{*path}").kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule("ingress:GET /actuator/env").authorities()).containsExactly("ROLE_OPS");
        assertThat(rule("ingress:DELETE /actuator/audit").authorities()).containsExactly("ROLE_OPS");
        // excluding("heapdump") falls through to anyRequest().
        assertThat(rule("ingress:GET /actuator/heapdump").kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void springBootsOwnChainLetsEveryoneSeeHealth() {
        ApplicationGraph defaults = FixtureScans.scan("actuatordefault");
        assertThat(defaults.nodes()).filteredOn(Ingress.class::isInstance).map(node -> ((Ingress) node).id())
                .filteredOn(id -> id.contains("/actuator")).containsOnly("ingress:GET /actuator/health",
                        "ingress:GET /actuator/health/{*path}");
        assertThat(checks(defaults, "ingress:GET /actuator/health")).singleElement()
                .satisfies(location -> assertThat(location.requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL));
        assertThat(checks(defaults, "ingress:GET /hello")).singleElement().satisfies(location ->
                assertThat(location.requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED));
    }

    /**
     * Boot 4.1.1 configures its resource server, OAuth2 Login and authorization server chains before
     * ManagementWebSecurityAutoConfiguration, so when one of them takes the default chain's place, Actuator's own
     * chain isn't made, and health needs what every other request does. Found by conformanceTest: Spring answers 401.
     */
    @Test
    void anOAuth2DefaultChainKeepsHealthBehindAuthentication() {
        for (String fixture : List.of("bootjwt", "bootopaque", "oauthclient", "authserverproperties")) {
            ApplicationGraph graph = FixtureScans.scan(fixture);
            assertThat(checks(graph, "ingress:GET /actuator/health")).as(fixture).isNotEmpty()
                    .allSatisfy(location -> assertThat(location.requirement().kind()).as(fixture)
                            .isEqualTo(Requirement.Kind.AUTHENTICATED));
        }
    }

    @Test
    void aYamlListExposesAndTheEndpointsDefaultBeatsAnEndpointsOwn() {
        // Boot 4.1.1's PropertiesEndpointAccessResolver: management.endpoints.access.default before shutdown's NONE.
        assertThat(FixtureScans.scan("actuatoryaml").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /actuator/env", "ingress:POST /actuator/shutdown");
    }

    @Test
    void aNegativeManagementPortTurnsTheEndpointsOff() {
        assertThat(FixtureScans.scan("actuatoroff").nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.contains("/actuator"));
    }

    @Test
    void onItsOwnPortActuatorIsUnderTheManagementBasePath() {
        assertThat(FixtureScans.scan("actuatorport").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /manage/actuator/health").doesNotContain("ingress:GET /actuator/health");
    }

    @Test
    void theStartupEndpointIsThereWhenMainBuffersTheStartup() {
        assertThat(FixtureScans.scan("actuatorport").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /manage/actuator/startup");
        // Every endpoint exposed, but the startup isn't buffered.
        assertThat(FixtureScans.scan("actuatorcloud").nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.endsWith("/actuator/startup"));
    }

    @Test
    void accessIsCappedByTheMostPermitted() {
        assertThat(FixtureScans.scan("actuatorcapped").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /actuator/loggers").doesNotContain("ingress:POST /actuator/loggers/{name}");
    }

    @Test
    void aRestControllerEndpointsOperationsAreItsMappingsReadOnlyHasOnlyItsReads() {
        ApplicationGraph gateway = FixtureScans.scan("actuatorgateway");
        // On a port of its own with management.server.base-path=/: still under /actuator.
        assertThat(gateway.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /actuator/logfile",
                "ingress:GET /actuator/gateway",
                "ingress:GET /actuator/gateway/routes", "ingress:GET /actuator/gateway/routes/{id}",
                "ingress:GET /actuator/gateway/routes/{id}/combinedfilters",
                "ingress:GET /actuator/gateway/globalfilters")
                .doesNotContain("ingress:POST /actuator/gateway/refresh", "ingress:POST /actuator/gateway/routes/{id}",
                        "ingress:DELETE /actuator/gateway/routes/{id}");
        // The application's own: a @RequestMapping of any method is a read, and a mapping the class overrides is
        // the override's.
        assertThat(gateway.nodes(Ingress.class)).extracting(Ingress::id).contains(
                "ingress:POST /actuator/toggles/{name}", "ingress:GET /actuator/toggles/export",
                "ingress:GET /actuator/toggles/count");
        assertThat(((Ingress) gateway.node("ingress:GET /actuator/toggles/{name}").orElseThrow()).handler()
                .className()).isEqualTo("fixtures.actuatorgateway.TogglesEndpoint");
        assertThat(FixtureScans.rule(gateway, "GET /actuator/toggles/export").requirement().authorities())
                .containsExactly("ROLE_OPS");
    }

    @Test
    void theBoot2EnabledFlagsAndTheEndpointsTheirBeansMakeAvailable() {
        ApplicationGraph legacy = FixtureScans.scan("actuatorlegacy");
        // At the root, on the application's own port (whose management base path doesn't apply); only what is
        // enabled, exposed and not excluded.
        assertThat(legacy.nodes(Ingress.class)).extracting(Ingress::id)
                .filteredOn(id -> !id.contains("api-docs") && !id.contains("swagger-ui")).containsExactlyInAnyOrder(
                        "ingress:GET /health", "ingress:GET /health/{*path}", "ingress:GET /logfile",
                        "ingress:GET /auditevents", "ingress:GET /httpexchanges", "ingress:GET /startup",
                        "ingress:POST /startup", "ingress:POST /shutdown");
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }

    private Requirement rule(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals("authorizeHttpRequests")).findFirst().orElseThrow()
                .requirement();
    }

    @Test
    void springCloudsEndpointsAndTheWritableEnvironment() {
        ApplicationGraph cloud = FixtureScans.scan("actuatorcloud");
        assertThat(cloud.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:POST /actuator/refresh",
                "ingress:POST /actuator/env", "ingress:DELETE /actuator/env", "ingress:GET /actuator/features")
                // restart (like Boot 4.1's heapdump and shutdown) is off unless given access; the Gateway's endpoint
                // needs a reactive Gateway.
                .doesNotContain("ingress:POST /actuator/restart", "ingress:GET /actuator/heapdump",
                        "ingress:POST /actuator/shutdown")
                .noneMatch(id -> id.contains("/actuator/gateway"));
        assertThat(FixtureScans.rule(cloud, "POST /actuator/env").requirement().kind())
                .isEqualTo(dev.crain.authtracer.graph.Requirement.Kind.PERMIT_ALL);
    }
}
