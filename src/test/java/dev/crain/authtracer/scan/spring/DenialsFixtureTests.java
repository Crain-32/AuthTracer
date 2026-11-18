package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * What a caller gets when a field check denies: an error, or what the check's denial handler returns, which may be
 * derived from the very value it denied (DENY-02).
 */
class DenialsFixtureTests {

    private static final String ACCOUNT = "location:FIELD:fixtures.denials.Account#";
    private static final String OWNER = ACCOUNT + "getOwner():@PostAuthorize";
    private static final String IBAN = ACCOUNT + "getIban():@PostAuthorize";
    private static final String EMAIL = ACCOUNT + "getEmail():@PostAuthorize";

    private final ApplicationGraph graph = FixtureScans.scan("denials");

    @Test
    void springsThrowingHandlerNamedExplicitlyStillDenies() {
        assertThat(path(graph, "ingress:GET /accounts/{id}")).contains(OWNER);
        assertThat(location(OWNER).denial()).isEqualTo(Denial.THROW);
    }

    @Test
    void aHandlerThatMasksTheDeniedResultHandsDeniedCallersAValueDerivedFromIt() {
        Exposure iban = exposure("GET /accounts/{id}", "iban");
        Exposure masked = exposure("GET /accounts/{id}", "iban(denied)");
        assertThat(iban.steps()).extracting(Exposures.Step::location).contains("denials/" + IBAN);
        // The masked value is what the check answers with: it doesn't stand in front of it.
        assertThat(masked.steps()).extracting(Exposures.Step::location).doesNotContain("denials/" + IBAN);
        assertThat(masked.sources()).containsExactly("denials/field:fixtures.denials.Account.iban");
        assertThat(masked.lineage()).extracting(Flow::source).containsExactly(FieldSource.MASKED);
    }

    @Test
    void aParameterDrivenHandlerMasksFromTheResultItHandsABean() {
        assertThat(exposure("GET /accounts/{id}", "email(denied)").sources())
                .containsExactly("denials/field:fixtures.denials.Account.email");
        assertThat(location(EMAIL).denial()).isEqualTo(new Denial(Denial.Kind.HANDLER,
                "fixtures.denials.ObscuringHandler"));
    }

    @Test
    void handlersThatAnswerWithoutTheResultHandOutNothingOfIt() {
        // A pre check's handler has no result; one that only answers a constant, or the annotation's value, neither.
        assertThat(fields("GET /accounts/{id}")).containsExactlyInAnyOrder("owner", "iban", "iban(denied)", "pin",
                "phone", "note", "email", "email(denied)");
    }

    @Test
    void noHandlerAnswersWhereNoCheckRuns() {
        assertThat(fields("GET /accounts/{id}/raw")).containsExactlyInAnyOrder("owner", "iban", "pin", "phone",
                "note", "email");
    }

    @Test
    void codeThatReadsAMaskedGetterGetsTheMaskedValueInWhatItBuilds() {
        assertThat(path(graph, "ingress:GET /accounts/{id}/summary")).containsExactly(IBAN);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .extracting(Finding::message).singleElement().asString()
                .startsWith("On GET /accounts/{id}/summary: when @PostAuthorize on fixtures.denials.Account#getIban()"
                        + " denies, LastFour returns a value it derives from Account.iban");
    }

    @Test
    void onlyPreAndPostAuthorizeAnswerThroughAHandler() {
        // 7.1.1: only their attribute registries read @HandleAuthorizationDenied; @Secured's manager throws.
        AuthorizationLocation manager = location("location:FIELD:fixtures.denials.Branch#getManager():@Secured");
        assertThat(manager.denial()).isEqualTo(Denial.THROW);
        assertThat(fields("GET /branches/{id}")).containsExactlyInAnyOrder("manager", "name");
    }

    @Test
    void aHandlerNoBeanIsFailsEveryCallAndSaysSo() {
        // The reading stays the weaker one (the handler answers), with a finding: the bean may be registered in a
        // way AuthTracer doesn't read.
        AuthorizationLocation number = location("location:FIELD:fixtures.denials.Card#getNumber():@PostAuthorize");
        assertThat(number.denial()).isEqualTo(new Denial(Denial.Kind.HANDLER, "fixtures.denials.Unregistered"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString()
                .startsWith("@HandleAuthorizationDenied on fixtures.denials.Card#getNumber() names "
                        + "fixtures.denials.Unregistered, which AuthTracer finds no bean of");
    }

    private List<String> fields(String endpoint) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.endpoint().equals(endpoint))
                .map(Exposure::field).filter(field -> !field.isEmpty()).toList();
    }

    private Exposure exposure(String endpoint, String field) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.endpoint().equals(endpoint)
                && exposure.field().equals(field)).findFirst().orElseThrow();
    }

    private AuthorizationLocation location(String id) {
        return (AuthorizationLocation) graph.node(id).orElseThrow();
    }
}
