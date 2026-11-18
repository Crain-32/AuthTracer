package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0080: servlet registrations AuthTracer reads in part, and Spring Web Services without Spring Boot.
 */
class ServletHelpersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("servlethelpers");

    @Test
    void aRegistrationAHelperBuildsIsReadWithTheArgumentsItIsGiven() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /legacy/**",
                "ingress:GET /old/**");
        assertThat(((Ingress) graph.node("ingress:GET /legacy/**").orElseThrow()).handler().className())
                .isEqualTo("fixtures.servlethelpers.LegacyServlet");
    }

    @Test
    void theConstantMappingsAreKeptAndTheOthersReported() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /exports/**");
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#exports(",
                "maps its servlet to /exports/* and to URL patterns that aren't constants"));
    }

    @Test
    void aLibraryServletAtAPathOfTheApplicationsIsAWayInCheckedByTheRules() {
        Ingress console = (Ingress) graph.node("ingress:* /db/**").orElseThrow();
        assertThat(console.handler().className()).isEqualTo("org.h2.server.web.JakartaWebServlet");
        assertThat(rule(graph, "* /db/**").requirement().authorities()).containsExactly("ROLE_DBA");
    }

    @Test
    void registrationsItCantReadAreReported() {
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#plugin(",
                "registers a servlet in a way AuthTracer can't read"));
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#any(",
                "registers a servlet AuthTracer can't tell"));
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::route).doesNotContain("/any/**");
    }

    @Test
    void springWebServicesWithoutBootAtTheInitializersMappings() {
        ApplicationGraph overridden = FixtureScans.scan("soapnoboot");
        assertThat(rule(overridden, "SOAP orderRequest?namespace:http://example.com/orders").requirement()
                .authorities()).containsExactly("ROLE_PARTNER");
        assertThat(overridden.findings()).isEmpty();
        // Spring WS's defaults, /services and *.wsdl: the operations are posted to /services.
        ApplicationGraph defaults = FixtureScans.scan("soapnobootdefault");
        assertThat(rule(defaults, "SOAP pingRequest?namespace:http://example.com/ping").requirement().authorities())
                .containsExactly("ROLE_CLIENT");
        assertThat(defaults.findings()).isEmpty();
    }

    @Test
    void springWebServicesWithNothingThatRegistersItsServletIsReported() {
        ApplicationGraph unregistered = FixtureScans.scan("soapunregistered");
        assertThat(unregistered.nodes(Ingress.class)).isEmpty();
        assertThat(unregistered.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).contains("fixtures.soapunregistered.PingEndpoint",
                    "no MessageDispatcherServlet AuthTracer can find");
        });
    }

    private List<String> opaque() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
    }
}
