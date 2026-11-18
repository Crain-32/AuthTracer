package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import dev.crain.authtracer.diff.DiffReport.Change;
import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.DiffReport.Site;
import dev.crain.authtracer.graph.CodeRef;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentReportTests {

    @TempDir
    Path project;

    @Test
    void whatFailsGroupedByPlaceWithWhatToDo() throws IOException {
        Path controller = project.resolve("src/main/java/app/Directory.java");
        Files.createDirectories(controller.getParent());
        Files.writeString(controller, """
                package app;

                class Directory {

                    View get(long id) {
                        return View.of(repository.find(id));
                    }
                }
                """);
        Site handler = Site.of("bank", CodeRef.ofMethod("app.Directory", "get(long)"));
        List<Change> changes = List.of(
                Change.of(Kind.DIAGONAL_ESCALATION, "bank", "GET /directory/{id}", "iban", "ROLE_ADMIN",
                        "authenticated", "a new route to bank Account.iban").at(handler),
                Change.of(Kind.DIAGONAL_ESCALATION, "bank", "GET /directory/{id}", "owner", "ROLE_ADMIN",
                        "authenticated", "a new route to bank Account.owner").at(handler),
                Change.of(Kind.STRENGTHENED, "bank", "GET /accounts", "", "authenticated", "ROLE_ADMIN", null));

        String text = AgentReport.write(new DiffReport("base", "head", changes), Map.of("bank", project), false);

        assertThat(text).startsWith("AuthTracer: this change weakens authorization")
                .contains("1. Fields iban, owner of bank GET /directory/{id} can be read with authenticated: a new"
                        + " route to their data that asks less than every existing route to it.")
                .contains("   At src/main/java/app/Directory.java:5.")
                .contains("Org security review")
                .doesNotContain("GET /accounts");
    }

    @Test
    void eachFailureSaysWhatItRequiresNowAndWhereTheCheckIs() throws IOException {
        Path account = project.resolve("src/main/java/app/Account.java");
        Files.createDirectories(account.getParent());
        Files.writeString(account, """
                package app;

                class Account {

                    @PreAuthorize("hasRole('ADMIN')")
                    String getIban() {
                        return iban;
                    }
                }
                """);
        Site check = new Site("bank", CodeRef.ofMethod("app.Account", "getIban()"), "@PreAuthorize");
        Site handler = Site.of("bank", CodeRef.ofMethod("app.Accounts", "list()"));
        List<Change> changes = List.of(
                Change.of(Kind.WEAKENED, "bank", "GET /accounts/{id}", "iban", "ROLE_ADMIN", "authenticated",
                        "fewer callers are kept out than before").at(check),
                Change.of(Kind.WEAKENED, "bank", "GET /accounts", "iban", "ROLE_ADMIN", "authenticated",
                        "the iban check is gone").at(handler),
                Change.of(Kind.WEAKENED, "bank", "GET /accounts", "owner", "ROLE_ADMIN", "authenticated",
                        "the owner check is gone").at(handler),
                Change.of(Kind.POLICY_VIOLATION, "bank", "GET /reports", "total", "ROLE_CFO", "ROLE_ADMIN",
                        "the FIN policy requires ROLE_CFO"),
                Change.of(Kind.POLICY_VIOLATION, "bank", "GET /reports", "tax", "ROLE_CFO", "ROLE_ADMIN",
                        "the FIN policy requires ROLE_CFO"),
                Change.of(Kind.NEW_FINDING, "bank", "app.Account", "", null, "NOT_ENFORCED",
                        "method security is not enabled"));

        String text = AgentReport.write(new DiffReport("base", "head", changes), Map.of("bank", project), true);

        assertThat(text).contains("""
                1. Fields iban, owner of bank GET /accounts now requires authenticated (before: ROLE_ADMIN): fewer\
                 callers are kept out than before.
                2. Field iban of bank GET /accounts/{id} now requires authenticated (before: ROLE_ADMIN): fewer callers\
                 are kept out than before.
                   At src/main/java/app/Account.java:5 (@PreAuthorize).
                3. Fields tax, total of bank GET /reports requires ROLE_ADMIN: the FIN policy requires ROLE_CFO.
                4. New finding in bank: method security is not enabled.
                """);
    }

    @Test
    void nothingToDoWhenNothingFails() {
        Change sideways = Change.of(Kind.CHANGED, "bank", "GET /x", "", "ROLE_A", "ROLE_B", null);
        DiffReport report = new DiffReport("base", "head", List.of(sideways));
        assertThat(AgentReport.write(report, Map.of(), false)).isEqualTo("AuthTracer: no authorization got weaker.\n");
        assertThat(AgentReport.write(report, Map.of(), true)).contains("1. bank GET /x: ROLE_A → ROLE_B.");
    }
}
