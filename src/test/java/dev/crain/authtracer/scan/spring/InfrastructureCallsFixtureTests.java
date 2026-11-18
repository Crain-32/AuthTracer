package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0058: calls to the config server and the Eureka server a service is configured with.
 */
class InfrastructureCallsFixtureTests {

    @Test
    void aServiceLinksToItsConfigServerAndEurekaServer() {
        ApplicationGraph client = FixtureScans.scan("cloudclient");
        assertThat(client.nodes(Egress.class)).extracting(Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("GET", "/config/{name}/{profiles}"),
                        tuple("POST", "/eureka/apps/{app}"), tuple("PUT", "/eureka/apps/{app}/{id}"),
                        tuple("GET", "/eureka/apps/"));
        SystemGraph system = new Linker().link(List.of(client, FixtureScans.scan("configserver"),
                FixtureScans.scan("eurekaserver")), ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).contains(
                "configserver/ingress:GET /config/{name}/{profiles}?produces:application/json",
                "eurekaserver/ingress:POST /eureka/**", "eurekaserver/ingress:PUT /eureka/**",
                "eurekaserver/ingress:GET /eureka/**");
        // The Eureka server doesn't register with itself.
        assertThat(FixtureScans.scan("eurekaserver").nodes(Egress.class)).isEmpty();
    }

    @Test
    void aConfigServerUriOfItsOwnWithAUsernameAndARegistryReadWithoutRegistering() {
        // The username comes from the environment: set all the same.
        assertThat(FixtureScans.scan("cloudclientforms").nodes(Egress.class))
                .extracting(Egress::client, Egress::httpMethod, Egress::baseUrl, Egress::uriTemplate, Egress::credentials)
                .containsExactlyInAnyOrder(
                        tuple("Config client", "GET", "http://config:8888", "/{name}/{profiles}", Credentials.STATIC),
                        tuple("Eureka client", "GET", "http://eureka:8761", "/eureka/apps/", Credentials.NONE));
    }

    @Test
    void theConfigServersDefaultUriAndAEurekaClientSwitchedOff() {
        assertThat(FixtureScans.scan("cloudclientoff").nodes(Egress.class))
                .extracting(Egress::client, Egress::baseUrl, Egress::uriTemplate)
                .containsExactly(tuple("Config client", "http://localhost:8888", "/{name}/{profiles}"));
    }

    @Test
    void withoutTheClientLibrariesTheirPropertiesCallNothing() {
        assertThat(FixtureScans.scanWithout("cloudclient", "spring-cloud-config-client",
                "spring-cloud-netflix-eureka-client").nodes(Egress.class)).isEmpty();
    }

    @Test
    void yamlListsAndFlagsAreReadAsSpringReadsThem() {
        assertThat(FixtureScans.scan("cloudclientyaml").nodes(Egress.class))
                .extracting(Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("GET", "/config/{name}/{profiles}"),
                        tuple("POST", "/eureka/apps/{app}"), tuple("PUT", "/eureka/apps/{app}/{id}"));
    }
}
