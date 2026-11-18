package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class FieldsFixtureTests {

    private static final String IBAN = "location:FIELD:fixtures.fields.Account#getIban():@PreAuthorize";

    private final ApplicationGraph graph = FixtureScans.scan("fields");

    @Test
    void getterOfAnAuthorizeReturnObjectElementIsAFieldCheck() {
        AuthorizationLocation iban = (AuthorizationLocation) graph.node(IBAN).orElseThrow();
        assertThat(iban.scope()).isEqualTo(AuthorizationLocation.Scope.FIELD);
        assertThat(iban.field()).isEqualTo("iban");
        assertThat(iban.denial().kind()).isEqualTo(AuthorizationLocation.Denial.Kind.NULL);
    }

    @Test
    void methodReferenceReachesTheFieldCheck() {
        assertThat(path(graph, "ingress:GET /accounts")).containsExactly(IBAN);
    }

    @Test
    void rawObjectsSkipFieldChecks() {
        assertThat(path(graph, "ingress:GET /accounts/raw/{id}")).isEmpty();
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.BYPASSED);
            assertThat(finding.message()).contains("Account#getIban()").contains("@AuthorizeReturnObject");
        });
    }

    @Test
    void aReturnedObjectsMethodCheckRunsOnlyOnTheProxy() {
        assertThat(path(graph, "ingress:GET /accounts/withdraw/{id}"))
                .containsExactly("location:METHOD:fixtures.fields.Account#withdraw(long):@PreAuthorize");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /accounts/withdraw/{id}:")
                        .contains("Account#withdraw(long)", "calls it"));
    }

    @Test
    void onlyReadsOfTheProxiedObjectAreChecked() {
        // Before decision 0014's per-object tracking, the raw read counted too, once any proxy had been returned.
        assertThat(path(graph, "ingress:GET /accounts/mixed/{id}")).containsExactly(IBAN);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /accounts/mixed/{id}:")
                        .contains("Account#getIban()"));
    }

    @Test
    void proxiesComeBackThroughHelpersAndIntoLambdas() {
        assertThat(path(graph, "ingress:GET /accounts/first")).containsExactly(IBAN);
        assertThat(path(graph, "ingress:GET /accounts/each")).containsExactly(IBAN);
        assertThat(graph.findings()).extracting(Finding::message)
                .noneMatch(message -> message.startsWith("On GET /accounts/first:")
                        || message.startsWith("On GET /accounts/each:"));
    }

    @Test
    void returnedProxiesAreCheckedWhenSerialized() {
        assertThat(path(graph, "ingress:GET /accounts/all")).containsExactly(IBAN);
        // A Spring Data repository with @AuthorizeReturnObject, through a method it inherits.
        assertThat(path(graph, "ingress:GET /accounts/stored/{id}")).containsExactly(IBAN);
        assertThat(path(graph, "ingress:GET /accounts/plain/{id}")).isEmpty();
    }

    @Test
    void serializingAProxyRunsItsGettersChecksInNameOrder() {
        assertThat(path(graph, "ingress:GET /statements/current")).containsExactly(
                "location:FIELD:fixtures.fields.Statement#getBalance():@PreAuthorize",
                "location:FIELD:fixtures.fields.Statement#getTotal():@PreAuthorize");
    }

    @Test
    void proxyFactoryObjectsGetFieldChecks() {
        String number = "location:FIELD:fixtures.fields.Card#getNumber():@PreAuthorize";
        assertThat(path(graph, "ingress:GET /cards/proxied")).containsExactly(number);
        assertThat(path(graph, "ingress:GET /cards/raw")).isEmpty();
    }
}
