package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0053: servlets and the H2 console.
 */
class ServletFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("servlets");

    @Test
    void registeredServletsAreIngressAtTheirPatterns() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /legacy/**",
                "ingress:POST /reports/**", "ingress:GET /h2-console/**", "ingress:POST /h2-console/**",
                // A registration without URL mappings is /*; its doGet is inherited.
                "ingress:GET /**");
        assertThat(((Ingress) graph.node("ingress:GET /legacy/**").orElseThrow()).handler().className())
                .isEqualTo("fixtures.servlets.LegacyServlet");
        assertThat(rule(graph, "GET /legacy/**").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void mappingsSetAsACollectionAreReadAndOnesThatArentConstantsAreReported() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:DELETE /feeds/**")
                .doesNotContain("ingress:DELETE /**", "ingress:PUT /**");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("ServletsApp#archive(java.lang.String)"));
    }

    @Test
    void theOtherWaysToRegisterAServlet() {
        ApplicationGraph registrations = FixtureScans.scan("servletregistrations");
        // setServlet and addUrlMappings after the no-argument constructor, the nearest doGet (not its one-argument
        // namesake); an injected servlet bean with alwaysMapUrl; a @WebServlet's service(..) answering any method.
        // A second DispatcherServlet and mappings from configuration aren't read; Decision 0080: the constant one
        // among them is. Decision 0112: an extension mapping is every path ending in it, the default servlet all.
        assertThat(registrations.nodes(Ingress.class)).extracting(Ingress::id)
                .filteredOn(id -> !id.contains("/actuator/") && !id.contains("api-docs") && !id.contains("swagger-ui"))
                .containsExactlyInAnyOrder("ingress:GET /status", "ingress:GET /health/servlet",
                        "ingress:POST /uploads/**", "ingress:* /metrics/**", "ingress:GET /print",
                        "ingress:POST /**/*.do", "ingress:POST /**", "ingress:* /**/*.metrics");
        assertThat(((Ingress) registrations.node("ingress:GET /status").orElseThrow()).handler())
                .isEqualTo(CodeRef.ofMethod("fixtures.servletregistrations.StatusServlet",
                        "doGet(jakarta.servlet.http.HttpServletRequest,jakarta.servlet.http.HttpServletResponse)"));
        assertThat(rule(registrations, "GET /status").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(registrations.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("#reports("))
                .anySatisfy(message -> assertThat(message).contains("#printedReports("));
    }

    @Test
    void extensionAndDefaultMappingsAreWaysIn() {
        ApplicationGraph mappings = FixtureScans.scan("servletmappings");
        // Every path ending in .csv: /public/users.csv gets the permitAll rule.
        assertThat(((Ingress) mappings.node("ingress:GET /**/*.csv").orElseThrow()).handler().className())
                .isEqualTo("fixtures.servletmappings.ExportServlet");
        assertThat(rule(mappings, "GET /**/*.csv").requirement().permitsAnyone()).isTrue();
        assertThat(rule(mappings, "GET /**/*.csv").requirement().operands()).extracting(Requirement::kind)
                .contains(Requirement.Kind.ANY_AUTHORITY, Requirement.Kind.PERMIT_ALL, Requirement.Kind.AUTHENTICATED);
        assertThat(((Ingress) mappings.node("ingress:GET /**").orElseThrow()).handler().className())
                .isEqualTo("fixtures.servletmappings.FallbackServlet");
        assertThat(mappings.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("The @WebServlet"
                        + " fixtures.servletmappings.FallbackServlet maps its servlet to /, where Spring Boot maps the"
                        + " DispatcherServlet"))
                .noneSatisfy(message -> assertThat(message).contains("#exports("));
        assertThat(registrations().findings()).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("The servlet registration"
                        + " fixtures.servletregistrations.ServletRegistrationsApp#actions() maps its servlet to /"));
    }

    @Test
    void servletPatternsAsRoutes() {
        assertThat(ServletEndpoints.route("*.do")).contains("/**/*.do");
        assertThat(ServletEndpoints.route("/")).contains("/**");
        assertThat(ServletEndpoints.route("")).contains("/");
        assertThat(ServletEndpoints.route("/x/*")).contains("/x/**");
        assertThat(ServletEndpoints.route("/x")).contains("/x");
        assertThat(ServletEndpoints.route("x")).isEmpty();
    }

    private static ApplicationGraph registrations() {
        return FixtureScans.scan("servletregistrations");
    }

    @Test
    void theH2ConsoleIsOnlyAsSafeAsItsRule() {
        assertThat(rule(graph, "GET /h2-console/**").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }
}
