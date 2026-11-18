package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The ways of denying a hand-rolled check is recognized by, beyond the {@code handrolled} fixture's.
 */
class HandRolledFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("handrolledforms");

    @Test
    void aStatusExceptionDeniesOnlyWithADenialStatus() {
        assertThat(check("AccountsController#account")).contains("Principal.getName()",
                "throw ResponseStatusException");
        assertThat(checks()).noneMatch(message -> message.contains("AccountsController#statement"));
    }

    @Test
    void theServletResponsesStatusDeniesWhateverNamesIt() {
        assertThat(check("AccountsController#reports")).contains("HttpServletRequest.getRemoteUser()",
                "HttpServletRequest.isUserInRole()", "HttpServletResponse.sendError(401)",
                "HttpServletResponse.sendError(FORBIDDEN)");
        assertThat(check("AccountsController#exports")).contains("Authentication.getAuthorities()",
                "HttpServletResponse.setStatus(403)");
    }

    @Test
    void aStatusCodeOrAnExceptionNamedForADenialDenies() {
        assertThat(check("AccountsController#tokens")).contains("Jwt.getClaimAsString()",
                "ResponseEntity.status(401)");
        assertThat(check("AccountsController#team")).contains("throw TeamAccessDeniedException");
    }

    private String check(String method) {
        return checks().stream().filter(message -> message.contains(method + "(")).findFirst().orElseThrow();
    }

    private List<String> checks() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .map(Finding::message).toList();
    }
}
