package dev.crain.authtracer.provided;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.tuple;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.ProvidedFact.Kind;
import dev.crain.authtracer.graph.ProvidedFact.Origin;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProvidedFactsTests {

    @TempDir
    Path dir;

    @Test
    void readsEveryKind() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: app.Account.iban
                    labels: [PII, PCI]
                  - kind: declassify
                    field: app.View.band
                    reason: bands are public
                  - kind: check
                    method: "app.Legacy#secret(long)"
                    requirement: "hasRole('ADMIN')"
                  - kind: requirement
                    ingress: "GET /internal/**"
                    requirement: "VPN only"
                """);

        ProvidedFacts facts = ProvidedFacts.load(Optional.of(local), Optional.empty(), "app");

        assertThat(facts.about(Kind.SENSITIVE, "field:app.Account.iban")).hasValueSatisfying(fact ->
                assertThat(fact.labels()).containsExactly("PII", "PCI"));
        assertThat(facts.about(Kind.DECLASSIFY, "field:app.View.band")).hasValueSatisfying(fact ->
                assertThat(fact.reason()).isEqualTo("bands are public"));
        assertThat(facts.about(Kind.CHECK, "app.Legacy#secret(long)")).hasValueSatisfying(fact ->
                assertThat(fact.requirement()).isEqualTo("hasRole('ADMIN')"));
        assertThat(facts.of(Kind.REQUIREMENT)).singleElement().extracting(ProvidedFact::subject)
                .isEqualTo("GET /internal/**");
        assertThat(facts.all()).allMatch(fact -> fact.origin() == Origin.LOCAL);
        assertThat(facts.conflicts()).isEmpty();
    }

    @Test
    void policiesFromBothFilesAreAllKeptForTheyAreFloors() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                policies:
                  - label: PII
                    requires: "hasRole('ADMIN') and hasAuthority('SCOPE_pii')"
                  - label: INTERNAL
                    requires: "hasAuthority('SCOPE_internal')"
                """);
        Path org = write("org.yaml", """
                version: 1
                policies:
                  - label: PII
                    requires: "hasRole('ADMIN')"
                    reason: PII is for HR admins
                  - endpoint: "PUT /admin/**"
                    requires: "hasRole('ADMIN')"
                    fresh: true
                """);

        ProvidedFacts facts = ProvidedFacts.load(Optional.of(local), Optional.of(org), "app");

        // The service's stricter PII policy adds a clause to the Org's; neither replaces the other.
        assertThat(facts.of(Kind.POLICY)).filteredOn(policy -> policy.subject().equals("PII"))
                .extracting(ProvidedFact::origin, ProvidedFact::requirement)
                .containsExactlyInAnyOrder(tuple(Origin.LOCAL, "hasRole('ADMIN') and hasAuthority('SCOPE_pii')"),
                        tuple(Origin.ORG, "hasRole('ADMIN')"));
        assertThat(facts.about(Kind.POLICY, "INTERNAL")).hasValueSatisfying(policy ->
                assertThat(policy.origin()).isEqualTo(Origin.LOCAL));
        assertThat(facts.about(Kind.ENDPOINT_POLICY, "PUT /admin/**")).hasValueSatisfying(policy -> {
            assertThat(policy.requirement()).isEqualTo("hasRole('ADMIN')");
            assertThat(policy.fresh()).isTrue();
        });
        assertThat(facts.conflicts()).isEmpty();
    }

    @Test
    void aSecondFactOnTheSameThingInOneFileIsReported() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: app.Account.iban
                    labels: [PCI]
                  - kind: declassify
                    field: app.Account.iban
                """);

        ProvidedFacts facts = ProvidedFacts.load(Optional.of(local), Optional.empty(), "app");

        assertThat(facts.about(Kind.SENSITIVE, "field:app.Account.iban")).isPresent();
        assertThat(facts.about(Kind.DECLASSIFY, "field:app.Account.iban")).isEmpty();
        assertThat(facts.conflicts()).singleElement().extracting(Finding::message).asString()
                .contains("LOCAL DECLASSIFY fact on field:app.Account.iban is ignored");
    }

    @Test
    void orgFactsWinOverLocalOnesAndTheLossIsReported() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                facts:
                  - kind: declassify
                    field: app.Account.iban
                  - kind: declassify
                    field: app.View.band
                """);
        Path org = write("org.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: app.Account.iban
                    labels: [PCI]
                """);

        ProvidedFacts facts = ProvidedFacts.load(Optional.of(local), Optional.of(org), "app");

        assertThat(facts.about(Kind.DECLASSIFY, "field:app.Account.iban")).isEmpty();
        assertThat(facts.about(Kind.SENSITIVE, "field:app.Account.iban")).isPresent();
        assertThat(facts.about(Kind.DECLASSIFY, "field:app.View.band")).isPresent();
        assertThat(facts.conflicts()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.PROVIDED_CONFLICT);
            assertThat(finding.message()).contains("Local DECLASSIFY").contains("app.Account.iban").contains("ORG");
        });
    }

    @Test
    void anOrgOverrideScopedToTheServiceBeatsOrgWideFactsAndOnlyAppliesThere() throws IOException {
        Path org = write("org.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: app.View.band
                    labels: [CONFIDENTIAL]
                services:
                  app:
                    overrides:
                      - kind: declassify
                        field: app.View.band
                        reason: approved for app only
                """);

        ProvidedFacts app = ProvidedFacts.load(Optional.empty(), Optional.of(org), "app");
        ProvidedFacts other = ProvidedFacts.load(Optional.empty(), Optional.of(org), "other");

        assertThat(app.about(Kind.DECLASSIFY, "field:app.View.band")).hasValueSatisfying(fact ->
                assertThat(fact.origin()).isEqualTo(Origin.ORG_OVERRIDE));
        assertThat(app.about(Kind.SENSITIVE, "field:app.View.band")).isEmpty();
        assertThat(other.about(Kind.SENSITIVE, "field:app.View.band")).isPresent();
        assertThat(other.about(Kind.DECLASSIFY, "field:app.View.band")).isEmpty();
    }

    @Test
    void rejectsMalformedFiles() throws IOException {
        Path noVersion = write("a.yaml", "facts: []\n");
        Path unknownKind = write("b.yaml", "version: 1\nfacts:\n  - kind: magic\n    field: x.Y.z\n");
        Path missingSubject = write("c.yaml", "version: 1\nfacts:\n  - kind: check\n");

        assertThatIllegalArgumentException().isThrownBy(() -> load(noVersion)).withMessageContaining("version: 1");
        assertThatIllegalArgumentException().isThrownBy(() -> load(unknownKind)).withMessageContaining("magic");
        assertThatIllegalArgumentException().isThrownBy(() -> load(missingSubject)).withMessageContaining("method");
    }

    @Test
    void oneLabelMayBeWrittenAsAScalar() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: app.Account.iban
                    labels: PII
                """);

        assertThat(load(local).about(Kind.SENSITIVE, "field:app.Account.iban")).hasValueSatisfying(fact ->
                assertThat(fact.labels()).containsExactly("PII"));
    }

    @Test
    void aMalformedEndpointPatternFailsWhenTheFactsLoad() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                policies:
                  - endpoint: "PUT /admin/{id"
                    requires: "hasRole('ADMIN')"
                """);

        assertThatIllegalArgumentException().isThrownBy(() -> load(local))
                .withMessageContaining("PUT /admin/{id").withMessageContaining("authtracer.yaml");
    }

    @Test
    void aFactOrPolicyWrittenTwiceIsOneAndTwoOrgFactsOnOneFieldConflict() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: field:app.Account.iban
                    labels: [PCI]
                  - kind: sensitive
                    field: app.Account.iban
                    labels: [PCI]
                policies:
                  - label: PCI
                    requires: "hasRole('ADMIN')"
                  - label: PCI
                    requires: "hasRole('ADMIN')"
                """);
        Path org = write("org.yaml", """
                version: 1
                facts:
                  - kind: sensitive
                    field: app.View.band
                    labels: [CONFIDENTIAL]
                  - kind: declassify
                    field: app.View.band
                """);

        ProvidedFacts facts = ProvidedFacts.load(Optional.of(local), Optional.of(org), "app");

        // The field: prefix is optional.
        assertThat(facts.of(Kind.SENSITIVE)).extracting(ProvidedFact::subject)
                .containsExactly("field:app.Account.iban", "field:app.View.band");
        assertThat(facts.of(Kind.POLICY)).singleElement().extracting(ProvidedFact::subject).isEqualTo("PCI");
        // The Org's file isn't the project's, so the conflict has no place in it.
        assertThat(facts.conflicts()).singleElement().satisfies(finding -> {
            assertThat(finding.message()).isEqualTo("ORG DECLASSIFY fact on field:app.View.band is ignored: an"
                    + " earlier ORG fact (SENSITIVE) covers the same field");
            assertThat(finding.location()).isNull();
        });
    }

    @Test
    void anEndpointPolicyThatIsNotFreshNeedsNoLiveCheck() throws IOException {
        Path local = write("authtracer.yaml", """
                version: 1
                policies:
                  - endpoint: "/admin/**"
                    requires: "hasRole('ADMIN')"
                    reason: admins only
                """);

        assertThat(load(local).about(Kind.ENDPOINT_POLICY, "/admin/**")).hasValueSatisfying(policy -> {
            assertThat(policy.fresh()).isNull();
            assertThat(policy.reason()).isEqualTo("admins only");
        });
    }

    @Test
    void anEmptyFileHasNoFacts() throws IOException {
        assertThat(load(write("authtracer.yaml", "")).all()).isEmpty();
        assertThat(load(write("comments.yaml", "# nothing yet\n")).conflicts()).isEmpty();
    }

    @Test
    void rejectsFactsAndPoliciesThatAreNotWhatTheirKindNeeds() throws IOException {
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("a.yaml", "- version: 1\n")))
                .withMessageContaining("expected a mapping with 'version: 1'");
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("b.yaml", """
                version: 1
                facts:
                  - app.Account.iban
                """))).withMessageContaining("every fact must be a mapping, got app.Account.iban");
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("c.yaml", """
                version: 1
                facts:
                  - field: app.Account.iban
                """))).withMessageContaining("fact without a kind");
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("d.yaml", """
                version: 1
                facts:
                  - kind: policy
                    label: PII
                """))).withMessageContaining("policies go in 'policies', not 'facts'");
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("e.yaml", """
                version: 1
                policies:
                  - PII
                """))).withMessageContaining("every policy must be a mapping, got PII");
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("f.yaml", """
                version: 1
                policies:
                  - requires: "hasRole('ADMIN')"
                """))).withMessageContaining("policy without a label or an endpoint");
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("g.yaml", """
                version: 1
                policies:
                  - label: PII
                """))).withMessageContaining("policy for PII needs 'requires'");
    }

    @Test
    void readsRulesAndRejectsOnesThatDontSayWhatTheyMatchOrRequire() throws IOException {
        ProvidedFacts facts = load(write("rules.yaml", """
                version: 1
                rules:
                  - annotation: com.acme.RequiresPermission
                    requires: "hasAuthority('{value}')"
                    reason: the permission aspect
                  - call: "com.acme.Guard#require(java.lang.String[])"
                    requires: "hasRole('{arg0}')"
                    combine: all
                """));

        assertThat(facts.of(Kind.RULE)).extracting(ProvidedFact::subject, ProvidedFact::labels,
                ProvidedFact::requirement).containsExactly(
                        tuple("annotation com.acme.RequiresPermission", List.of(), "hasAuthority('{value}')"),
                        tuple("call com.acme.Guard#require(java.lang.String[])", List.of("all"), "hasRole('{arg0}')"));
        ProvidedFacts.validate(facts.of(Kind.RULE).getFirst());
        for (String rule : List.of("- requires: x", "- {annotation: a.B, call: a.B#c, requires: x}",
                "- {call: a.B.c, requires: x}", "- {annotation: a.B}", "- {annotation: a.B, requires: x, combine: some}",
                "- a.B")) {
            assertThatIllegalArgumentException().isThrownBy(() -> load(write("bad.yaml", "version: 1\nrules:\n  "
                    + rule + "\n")));
        }
        assertThatIllegalArgumentException().isThrownBy(() -> load(write("kind.yaml", """
                version: 1
                facts:
                  - kind: rule
                    method: a.B#c
                """))).withMessageContaining("rules go in 'rules', not 'facts'");
        assertThatIllegalArgumentException().isThrownBy(() -> ProvidedFacts.validate(new ProvidedFact(Kind.RULE,
                "call a.B.c", List.of(), "x", null, Origin.LOCAL))).withMessageContaining("a call (Class#method)");
    }

    @Test
    void aFactInAPostedGraphIsCheckedByTheRulesItsFileIsReadWith() {
        ProvidedFacts.validate(new ProvidedFact(Kind.SENSITIVE, "field:app.Account.iban", List.of("PCI"), null, null,
                Origin.LOCAL));
        ProvidedFacts.validate(new ProvidedFact(Kind.CHECK, "app.Legacy#secret(long)", List.of(), "hasRole('ADMIN')",
                null, Origin.LOCAL));
        ProvidedFacts.validate(new ProvidedFact(Kind.ENDPOINT_POLICY, "PUT /admin/**", List.of(), "hasRole('ADMIN')",
                null, Origin.ORG, true));
        ProvidedFacts.validate(new ProvidedFact(Kind.POLICY, "PII", List.of("PII"), "hasRole('ADMIN')", null,
                Origin.ORG));

        assertThatIllegalArgumentException().isThrownBy(() -> ProvidedFacts.validate(new ProvidedFact(Kind.POLICY,
                "PII", List.of("PII"), null, null, Origin.ORG))).withMessage("Policy for PII needs a requirement");

        assertThatIllegalArgumentException().isThrownBy(() -> ProvidedFacts.validate(null))
                .withMessageContaining("needs a kind, an origin and a subject");
        for (ProvidedFact incomplete : List.of(
                new ProvidedFact(null, "field:app.Account.iban", List.of(), null, null, Origin.LOCAL),
                new ProvidedFact(Kind.SENSITIVE, "field:app.Account.iban", List.of(), null, null, null),
                new ProvidedFact(Kind.SENSITIVE, null, List.of(), null, null, Origin.LOCAL),
                new ProvidedFact(Kind.SENSITIVE, " ", List.of(), null, null, Origin.LOCAL))) {
            assertThatIllegalArgumentException().isThrownBy(() -> ProvidedFacts.validate(incomplete))
                    .withMessageContaining("needs a kind, an origin and a subject");
        }
        for (String notAField : List.of("app.Account.iban", "field:iban")) {
            assertThatIllegalArgumentException().isThrownBy(() -> ProvidedFacts.validate(new ProvidedFact(
                    Kind.DECLASSIFY, notAField, List.of(), null, null, Origin.LOCAL)))
                    .withMessage("A DECLASSIFY fact's subject must be a field id (field:<class>.<property>): "
                            + notAField);
        }
        assertThatIllegalArgumentException().isThrownBy(() -> ProvidedFacts.validate(new ProvidedFact(
                Kind.ENDPOINT_POLICY, "PUT /admin/{id", List.of(), "hasRole('ADMIN')", null, Origin.ORG)))
                .withMessageStartingWith("provided fact: endpoint policy 'PUT /admin/{id' is not a path pattern");
    }

    private static ProvidedFacts load(Path file) {
        return ProvidedFacts.load(Optional.of(file), Optional.empty(), "app");
    }

    private Path write(String name, String content) throws IOException {
        return Files.writeString(dir.resolve(name), content);
    }
}
