package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0035: FreeMarker views, read like JSPs.
 */
class FreeMarkerViewFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("freemarkerviews");

    @Test
    void theFieldsTheTemplateReads() {
        Map<String, String> account = Exposures.of(graph).stream()
                .filter(exposure -> exposure.ingress().equals("ingress:GET /account"))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        // The comment's ${account.iban} doesn't count; the include's account.id does.
        assertThat(account).containsOnlyKeys("", "account.id", "account.holder", "account.cards",
                "account.cards[].expiry", "account.iban", "account.cards[].number");
        // <@sec.authorize access=".."> guards what it wraps.
        assertThat(account.get("account.iban")).contains("ROLE_TELLER");
        assertThat(account.get("account.cards[].number")).contains("ROLE_TELLER");
        assertThat(account.get("account.holder")).doesNotContain("ROLE_TELLER");
        assertThat(graph.flows("ingress:GET /account")).contains(Flow.local("ingress:GET /account",
                "field:fixtures.freemarkerviews.Account.iban", "field:view:account.account:iban", FieldSource.DIRECT));
    }

    @Test
    void aLayoutMacroCapturedAssignmentsAndSpringsMacrosUnderTheApplicationsLoaderPath() {
        Map<String, String> show = Exposures.of(FixtureScans.scan("freemarkerlayout")).stream()
                .filter(exposure -> exposure.ingress().equals("ingress:GET /owners/{id}"))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        assertThat(show).containsOnlyKeys("", "owner.lastName", "owner.telephone", "owner.notes", "owner.visits",
                "owner.visits[].date", "owner.visits[].diagnosis");
        // <@sec.authorize url=".."> names no expression: what it wraps is shown unguarded.
        assertThat(show.get("owner.notes")).isEqualTo("none");
        assertThat(show.get("owner.visits[].diagnosis")).isEqualTo("ROLE_VET");
    }
}
