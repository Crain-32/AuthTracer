package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Hand-rolled checks (decision 0072): a read and a denial in two helpers, and what is not a check.
 */
class HandRolledCornersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("handrolledcorners");

    @Test
    void aReadInOneHelperAndADenialInAnotherAreTheCallersCheck() {
        assertThat(checks()).singleElement().asString().contains("CornersController#ledger(",
                "its helpers fixtures.handrolledcorners.CornersController#caller(),"
                        + " fixtures.handrolledcorners.CornersController#refuse()",
                "Authentication.getName()", "throw AccessDeniedException");
    }

    @Test
    void notFoundOtherErrorsHeadersWithoutCredentialsAndAnUnusedPrincipalAreNoCheck() {
        assertThat(checks()).noneMatch(message -> message.contains("#missing(") || message.contains("#gone(")
                || message.contains("#hiddenThing(") || message.contains("#broken(")
                || message.contains("#stream(") || message.contains("#traced(") || message.contains("#unused("));
    }

    private List<String> checks() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .map(Finding::message).toList();
    }
}
