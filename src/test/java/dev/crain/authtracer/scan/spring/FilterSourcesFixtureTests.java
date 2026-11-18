package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070 amended): the filters and interceptors the first pass didn't read, and where code after
 * {@code chain.doFilter(..)} runs; decision 0071 amended: Spring's authenticating filters added by hand.
 */
class FilterSourcesFixtureTests {

    @Test
    void aCustomizerBeansFilterIsInEveryChain() {
        ApplicationGraph graph = FixtureScans.scan("filtercustomizer");
        assertThat(steps(graph, "ingress:GET /orders")).containsExactly("egress GET /keys/{key}",
                "check authorizeHttpRequests");
        assertThat(graph.authoritySource().detail()).contains("Custom filter ApiKeyFilter");
    }

    @Test
    void aCustomizerBeansWebFilterIsInTheChain() {
        assertThat(steps(FixtureScans.scan("webfiltercustomizer"), "ingress:GET /items")).containsExactly(
                "egress GET /tenants/current", "check authorizeExchange");
    }

    @Test
    void aCustomizerBeansFilterIsInBootsDefaultChain() {
        ApplicationGraph graph = FixtureScans.scan("filtercustomizerboot");
        assertThat(steps(graph, "ingress:GET /reports")).containsExactly("egress POST /spans",
                "check Spring Boot default SecurityFilterChain", "egress POST /events");
    }

    @Test
    void mappedInterceptorBeansRunBeforeTheRegistrysWhateverItsOrder() {
        ApplicationGraph graph = FixtureScans.scan("mappedinterceptors");
        assertThat(steps(graph, "ingress:GET /api/orders")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress POST /audit", "egress POST /trace",
                "egress POST /posts?", "egress POST /first");
        assertThat(steps(graph, "ingress:GET /api/public/info")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress POST /audit", "egress POST /posts?",
                "egress POST /first");
        assertThat(steps(graph, "ingress:GET /home")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress POST /trace", "egress POST /views",
                "egress POST /first");
        // springdoc's endpoints are the DispatcherServlet's too.
        assertThat(steps(graph, "ingress:GET /v3/api-docs")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress POST /trace", "egress POST /first");
    }

    @Test
    void anInitializerAfterSpringSecuritysRegistrationAddsFiltersAfterTheChain() {
        ApplicationGraph graph = FixtureScans.scan("servletinitializer");
        // The WebApplicationInitializer's filter, mapped to a servlet by name, is read as ahead of the chain.
        assertThat(steps(graph, "ingress:GET /api/orders")).containsExactly("egress GET /war?",
                "check Spring Boot default SecurityFilterChain", "egress GET /tenants", "egress GET /late");
        assertThat(steps(graph, "ingress:GET /home")).containsExactly("egress GET /war?",
                "check Spring Boot default SecurityFilterChain", "egress GET /late");
    }

    @Test
    void anInitializerBeforeSpringSecuritysRegistrationPutsEveryPlainInitializerFirst() {
        assertThat(steps(FixtureScans.scan("servletinitializerearly"), "ingress:GET /home")).containsExactly(
                "egress GET /early", "egress GET /later", "check Spring Boot default SecurityFilterChain");
    }

    @Test
    void webXmlFiltersRunWhereTheFileMapsThemAgainstSpringSecuritys() {
        ApplicationGraph graph = FixtureScans.scan("webxmlfilters");
        assertThat(steps(graph, "ingress:GET /api/orders")).containsExactly("egress GET /early",
                "check authorizeHttpRequests", "egress POST /audit", "egress POST /stamps", "egress GET /xml",
                "opaque Filter AuthTracer can't resolve (the bean missing, which a DelegatingFilterProxy in web.xml"
                        + " runs)");
        assertThat(steps(graph, "ingress:GET /home")).doesNotContain("egress GET /xml");
    }

    @Test
    void aWebXmlAuthTracerCantReadIsAFinding() {
        assertThat(FixtureScans.scan("webxmlbroken").findings())
                .filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("AuthTracer couldn't read WEB-INF/web.xml"));
    }

    @Test
    void aHandshakePassesTheFiltersWithItsCallerAndOnlyTheMappedInterceptors() {
        ApplicationGraph graph = FixtureScans.scan("filterhandshake");
        assertThat(steps(graph, "ingress:WEBSOCKET /chat")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "check @PreAuthorize", "egress POST /handshakes",
                "check @PreAuthorize (no caller)");
    }

    @Test
    void servletGrpcCallsPassTheFiltersBootsHealthServicesToo() {
        ApplicationGraph graph = FixtureScans.scan("grpcservletfilter");
        for (String ingress : new String[] {"ingress:GRPC fixtures.grpc.Greeter/SayHello",
                "ingress:GRPC grpc.health.v1.Health/Check"}) {
            assertThat(steps(graph, ingress)).as(ingress).containsExactly("check authorizeHttpRequests",
                    "egress POST /audit");
        }
    }

    @Test
    void codeAfterTheChainRunsAfterTheHandlerAsTheRequestUnwinds() {
        ApplicationGraph graph = FixtureScans.scan("filterunwinding");
        assertThat(steps(graph, "ingress:GET /orders")).containsExactly("egress POST /start",
                "egress POST /turned-away?", "check Spring Boot default SecurityFilterChain", "egress GET /orders",
                "egress POST /after?", "egress POST /served?", "egress POST /stop");
    }

    @Test
    void springsAuthenticatingFiltersAddedByHandAreWaysIn() {
        ApplicationGraph graph = FixtureScans.scan("libraryauthfilters");
        // Boot runs the Basic registration and the lambda initializer's Digest after Spring Security's filter.
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.AUTHORITIES_IN_CODE)
                .extracting(Finding::message).hasSize(2).allMatch(message -> message.contains(
                        "authenticates after the AuthorizationFilter"));
        AuthoritySource source = graph.authoritySource();
        assertThat(source.kind()).isEqualTo(AuthoritySource.Kind.CUSTOM_FILTER);
        assertThat(source.detail()).contains(
                "RequestHeaderAuthenticationFilter added by hand (kept in the session)",
                "BasicAuthenticationFilter added by hand (after the AuthorizationFilter; authenticates with the"
                        + " AuthenticationManager it is given)",
                "RememberMeAuthenticationFilter added by hand (authenticates with the AuthenticationManager it is"
                        + " given)",
                "DigestAuthenticationFilter added by hand (after the AuthorizationFilter; looks the caller up on every"
                        + " request: its UserDetailsService)");
    }
}
