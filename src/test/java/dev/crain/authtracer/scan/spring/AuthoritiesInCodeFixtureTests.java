package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * SRC-10 (decision 0071): code outside a filter that sets the Authentication, or its authorities, itself.
 */
class AuthoritiesInCodeFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("authoritiesincode");

    @Test
    void codeThatSetsTheAuthenticationBeforeACheckIsAFinding() {
        assertThat(finding("SupportController#refund")).contains("SecurityContext#setAuthentication",
                "UsernamePasswordAuthenticationToken", "authorities ROLE_BILLING", "a caller may need less");
    }

    @Test
    void authoritiesAddedWithToBuilderAndATaskThatRunsAsTheSystemAreFindingsToo() {
        assertThat(finding("SupportController#stepUp")).contains("Authentication$Builder#authorities");
        assertThat(finding("NightlyClose#close")).contains("SecurityContextHolder#setContext",
                "authorities ROLE_BILLING");
    }

    @Test
    void aFilterThatAuthenticatesIsAWayInNotAFinding() {
        assertThat(FixtureScans.scan("filterauth").findings())
                .noneMatch(finding -> finding.kind() == Finding.Kind.AUTHORITIES_IN_CODE);
    }

    private String finding(String method) {
        return findings().stream().filter(message -> message.contains(method + "(")).findFirst().orElseThrow();
    }

    private List<String> findings() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.AUTHORITIES_IN_CODE)
                .map(Finding::message).toList();
    }
}
