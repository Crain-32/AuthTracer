package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class MatchersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("matchers");

    @Test
    void regexRulesMatchRoutes() {
        assertThat(rule(graph, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(graph, "GET /admin/users").routePattern()).isEqualTo("regex /admin/[a-z]+");
        assertThat(rule(graph, "GET /reports/{id}").requirement().authorities()).containsExactly("ROLE_AUDITOR");
        assertThat(rule(graph, "GET /docs").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aRegexWithoutTheQueryStringIsBypassedByAddingOne() {
        // Decision 0110: HEAD /reports/{id} has a BYPASSED finding of its own, as the regex rule asks GET only.
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED
                && !finding.message().startsWith("HEAD "))
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("GET /admin/users", "regex /admin/[a-z]+",
                        "query string", "rule anyRequest", "authenticated"))
                .noneSatisfy(message -> assertThat(message).contains("/reports"))
                .noneSatisfy(message -> assertThat(message).contains("/docs"));
    }

    @Test
    void bootStaticResourceLocationsMatchTheirPaths() {
        assertThat(rule(graph, "GET /css/theme").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /css/theme").routePattern()).startsWith("/css/**,/js/**");
    }

    @Test
    void builtMatchersAndExpressionBuilders() {
        assertThat(rule(graph, "GET /legacy/items").requirement().authorities()).containsExactly("ROLE_LEGACY");
        assertThat(rule(graph, "GET /expr").requirement().authorities()).containsExactly("ROLE_EXPR");
        assertThat(rule(graph, "GET /expr/bean").requirement().authorities()).containsExactly("ROLE_BEAN");
    }

    @Test
    void topLevelRegistryCustomizerRulesComeFirst() {
        AuthorizationLocation ops = rule(graph, "GET /ops/status");
        assertThat(ops.requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(ops.target().method()).isEqualTo("ops()");
    }

    @Test
    void securityMatchersCollectEveryMatcher() {
        assertThat(rule(graph, "GET /partner/data").requirement().authorities()).containsExactly("SCOPE_partner");
        assertThat(rule(graph, "POST /hooks/in").requirement().authorities()).containsExactly("SCOPE_partner");
        assertThat(rule(graph, "GET /hooks/in").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aLaterSecurityMatcherReplacesTheEarlierOne() {
        assertThat(rule(graph, "GET /new/thing").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(rule(graph, "GET /old/thing").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void theBuilderBeansBasePathAndTheServletPathLineUp() {
        ApplicationGraph basePath = FixtureScans.scan("basepath");
        assertThat(rule(basePath, "GET /admin/settings").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(basePath, "GET /admin/settings").routePattern()).isEqualTo("/mvc/admin/**");
        assertThat(rule(basePath, "GET /public/info").mechanism()).startsWith("WebSecurityCustomizer ignoring()");
        assertThat(rule(basePath, "GET /images/logo").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(basePath, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void theLoginPageACustomizerBeanPermitsIsOpenOnEveryChain() {
        ApplicationGraph login = FixtureScans.scan("customizerlogin");
        assertThat(rule(login, "GET /signin").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(login, "GET /account").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aChainBeanOfTheConcreteChainTypeIsTheChain() {
        ApplicationGraph concrete = FixtureScans.scan("concretechain");
        assertThat(rule(concrete, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(concrete, "GET /open").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void bootsOwnBuilderAddsTheServletPathWhenTheApplicationDeclaresNone() {
        // Boot 4.1.1's PathPatternRequestMatcherBuilderConfiguration: basePath(DispatcherServletPath#getPath).
        ApplicationGraph servletPath = FixtureScans.scan("servletpath");
        assertThat(rule(servletPath, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(servletPath, "GET /admin/users").routePattern()).isEqualTo("/api/admin/**");
        assertThat(rule(servletPath, "GET /public/info").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(servletPath, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }
}
