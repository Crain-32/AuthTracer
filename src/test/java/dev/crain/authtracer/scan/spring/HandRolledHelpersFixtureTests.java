package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Hand-rolled checks (AUTHZ-13, AUTHZ-15) split across a helper, and the deny forms beyond a thrown denial.
 */
class HandRolledHelpersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("handrolledhelpers");

    @Test
    void aConditionInOneMethodAndADenialInItsHelperAreOneCheck() {
        assertThat(check("HelpersController#document")).contains("Authentication.getName()",
                "throw AccessDeniedException", "its helper fixtures.handrolledhelpers.HelpersController#forbidden()");
        assertThat(check("HelpersController#report")).contains("Authentication.getAuthorities()",
                "GrantedAuthority.getAuthority()", "throw AccessDeniedException",
                "its helper fixtures.handrolledhelpers.HelpersController#isAdmin(");
        // A static helper of another class.
        assertThat(check("HelpersController#guarded")).contains("Principal.getName()",
                "throw ResponseStatusException", "fixtures.handrolledhelpers.Guards#require(boolean)");
    }

    @Test
    void aHelperThatIsACheckByItselfIsReportedOnce() {
        // requireAdmin reads the caller through its own helper, isAdmin, and throws.
        assertThat(check("HelpersController#requireAdmin")).contains("Authentication.getAuthorities()",
                "throw AccessDeniedException", "its helper fixtures.handrolledhelpers.HelpersController#isAdmin(");
        assertThat(checks()).noneMatch(message -> message.contains("#settings("));
        // The handler reads the caller too, but the check is the helper's.
        assertThat(check("HelpersController#requireOwner")).contains("Authentication.getName()",
                "throw AccessDeniedException");
        assertThat(checks()).noneMatch(message -> message.contains("#notes("));
    }

    @Test
    void anotherBeansDenialIsItsOwnNotTheCallers() {
        assertThat(checks()).noneMatch(message -> message.contains("#archived") || message.contains("Archive#open"));
    }

    @Test
    void hidingIsNotDenyingEvenWithAHelperThatReadsTheCaller() {
        assertThat(checks()).noneMatch(message -> message.contains("#hidden"));
    }

    @Test
    void aResponseMadeWithADenialStatusDenies() {
        assertThat(check("HelpersController#entity")).contains("new ResponseEntity(FORBIDDEN)");
        assertThat(check("HelpersController#account")).contains("@AuthenticationPrincipal Account",
                "ResponseEntity.status(403)");
    }

    @Test
    void anExceptionThatAnswersWithADenialDenies() {
        assertThat(check("HelpersController#vault")).contains("throw NotPermitted");
        assertThat(check("HelpersController#lock")).contains("throw LockedOut");
    }

    private String check(String method) {
        return checks().stream().filter(message -> message.contains(method + "(")).findFirst().orElseThrow();
    }

    private List<String> checks() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .map(Finding::message).toList();
    }
}
