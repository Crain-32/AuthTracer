package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import dev.crain.authtracer.diff.DiffReport.Change;
import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.DiffReport.Site;
import dev.crain.authtracer.graph.CodeRef;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class SarifReportTests {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @TempDir
    Path project;

    @BeforeEach
    void sources() throws IOException {
        write("src/main/java/app/Account.java", """
                package app;

                public class Account {

                    private String iban;

                    @PreAuthorize("hasRole('AUDITOR')")
                    @JsonProperty("iban")
                    public String getIban() {
                        return iban;
                    }
                }
                """);
        write("src/main/kotlin/app/Orders.kt", """
                package app

                data class Order(val id: Long)

                @Service
                class OrderService {

                    fun refund(id: Long): String = "refunded"
                }
                """);
    }

    @Test
    void failingAndReviewChangesAreResultsAtTheirCheck() {
        Change weakened = Change.of(Kind.WEAKENED, "bank", "GET /accounts/{id}", "iban", "ROLE_ADMIN",
                "authenticated", "fewer callers are kept out than before")
                .at(new Site("bank", CodeRef.ofMethod("app.Account", "getIban()"), "@PreAuthorize"));
        Change kotlin = Change.of(Kind.CHANGED, "bank", "POST /orders/{id}/refund", "", "ROLE_ADMIN", "ROLE_OPS",
                null).at(Site.of("bank", CodeRef.ofMethod("app.OrderService", "refund(long)")));
        Change info = Change.of(Kind.STRENGTHENED, "bank", "GET /accounts", "", "authenticated", "ROLE_ADMIN", null)
                .at(Site.of("bank", CodeRef.ofMethod("app.Account", "getIban()")));
        Change elsewhere = Change.of(Kind.WEAKENED, "other", "GET /x", "", "ROLE_ADMIN", "authenticated", null)
                .at(Site.of("other", CodeRef.ofMethod("app.Account", "getIban()")));

        JsonNode run = runOf(new DiffReport("base", "head", List.of(weakened, kotlin, info, elsewhere)));

        assertThat(run.at("/tool/driver/name").asString()).isEqualTo("AuthTracer");
        assertThat(run.at("/tool/driver/rules").valueStream().map(rule -> rule.get("id").asString()).toList())
                .containsExactly("WEAKENED", "DIAGONAL_ESCALATION", "POLICY_VIOLATION", "CHANGED", "NEW_FINDING");
        // STRENGTHENED is information, and "other" has no source here: only in the diff report.
        assertThat(run.get("results")).hasSize(2);
        JsonNode first = run.get("results").get(0);
        assertThat(first.get("ruleId").asString()).isEqualTo("WEAKENED");
        assertThat(first.get("level").asString()).isEqualTo("error");
        assertThat(first.at("/message/text").asString()).isEqualTo("bank GET /accounts/{id} iban: ROLE_ADMIN →"
                + " authenticated. Fewer callers are kept out than before.");
        // The annotation's line, which is the one a change to the check touches.
        assertThat(first.at("/locations/0/physicalLocation/artifactLocation/uri").asString())
                .isEqualTo("src/main/java/app/Account.java");
        assertThat(first.at("/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(7);
        JsonNode second = run.get("results").get(1);
        assertThat(second.get("level").asString()).isEqualTo("warning");
        assertThat(second.at("/locations/0/physicalLocation/artifactLocation/uri").asString())
                .isEqualTo("src/main/kotlin/app/Orders.kt");
        assertThat(second.at("/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(8);
    }

    @Test
    void fingerprintsStayTheSameAcrossCommits() {
        Change change = Change.of(Kind.WEAKENED, "bank", "GET /accounts/{id}", "iban", "ROLE_ADMIN", "authenticated",
                null).at(Site.of("bank", CodeRef.ofMethod("app.Account", "getIban()")));
        String once = runOf(new DiffReport("a", "b", List.of(change))).at("/results/0/partialFingerprints").toString();
        String again = runOf(new DiffReport("b", "c", List.of(change))).at("/results/0/partialFingerprints").toString();
        assertThat(once).isEqualTo(again).contains("authtracerChange/v1");
    }

    @Test
    void changesThatShareAnExposureOrAPlaceHaveTheirOwnFingerprints() {
        Change admin = Change.of(Kind.POLICY_VIOLATION, "bank", "GET /accounts/{id}", "iban", "ROLE_ADMIN",
                "authenticated", "the PCI policy requires ROLE_ADMIN");
        Change mfa = Change.of(Kind.POLICY_VIOLATION, "bank", "GET /accounts/{id}", "iban", "FACTOR_OTT",
                "authenticated", "the MFA policy requires FACTOR_OTT");
        Change notEnforced = Change.of(Kind.NEW_FINDING, "bank", "app.Account", "", null, "NOT_ENFORCED",
                "method security is not enabled");
        Change opaque = Change.of(Kind.NEW_FINDING, "bank", "app.Account", "", null, "OPAQUE_CALLPATH",
                "reflection");

        assertThat(SarifReport.fingerprint(admin)).isNotEqualTo(SarifReport.fingerprint(mfa));
        assertThat(SarifReport.fingerprint(notEnforced)).isNotEqualTo(SarifReport.fingerprint(opaque));
    }

    @Test
    void otherKindsKeepTheirFirstFingerprints() throws Exception {
        Change weakened = Change.of(Kind.WEAKENED, "bank", "GET /accounts/{id}", "iban", "ROLE_ADMIN",
                "authenticated", null);
        byte[] v1 = MessageDigest.getInstance("SHA-256")
                .digest("WEAKENED|bank|GET /accounts/{id}|iban".getBytes(StandardCharsets.UTF_8));

        assertThat(SarifReport.fingerprint(weakened)).isEqualTo(HexFormat.of().formatHex(v1, 0, 16));
    }

    @Test
    void aMethodNamedWithoutItsParametersIsFound() {
        // Data REST's repository methods are named so: findAll.
        Change change = Change.of(Kind.WEAKENED, "bank", "GET /accounts", "", "ROLE_ADMIN", "authenticated", null)
                .at(Site.of("bank", CodeRef.ofMethod("app.Account", "getIban")));

        JsonNode run = runOf(new DiffReport("base", "head", List.of(change)));

        assertThat(run.at("/results/0/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(9);
    }

    @Test
    void anOverloadIsFoundByItsParameters() throws IOException {
        write("src/main/java/app/Exports.java", """
                package app;

                public class Exports {

                    public String export(long id) {
                        return "by id";
                    }

                    @PreAuthorize("hasRole('ADMIN')")
                    public String export(final String name,
                            @RequestParam(defaultValue = "csv") String format) {
                        return "by name";
                    }

                    public String export(String name) {
                        return "by name only";
                    }
                }
                """);
        Change change = Change.of(Kind.WEAKENED, "bank", "GET /exports", "", "ROLE_ADMIN", "authenticated", null)
                .at(new Site("bank", CodeRef.ofMethod("app.Exports", "export(java.lang.String,java.lang.String)"),
                        "@PreAuthorize"));
        Change byName = Change.of(Kind.WEAKENED, "bank", "GET /exports/{name}", "", "ROLE_ADMIN", "authenticated",
                null).at(Site.of("bank", CodeRef.ofMethod("app.Exports", "export(java.lang.String)")));

        JsonNode run = runOf(new DiffReport("base", "head", List.of(change, byName)));

        assertThat(run.at("/results/0/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(9);
        assertThat(run.at("/results/1/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(15);
    }

    @Test
    void aFindingIsAtItsClassInItsOwnWords() {
        Change finding = Change.of(Kind.NEW_FINDING, "bank", "app.Account", "", null, "OPAQUE_CALLPATH",
                "the call path goes through reflection.").at(Site.of("bank", CodeRef.ofClass("app.Account")));

        JsonNode result = runOf(new DiffReport("base", "head", List.of(finding))).get("results").get(0);

        assertThat(result.at("/message/text").asString())
                .isEqualTo("bank app.Account: The call path goes through reflection.");
        assertThat(result.at("/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(3);
    }

    @Test
    void aProvidedFactIsInTheProjectsFactsFile() throws IOException {
        write("authtracer.yaml", "version: 1\n");
        Change conflict = Change.of(Kind.NEW_FINDING, "bank", "authtracer.yaml", "", null, "PROVIDED_CONFLICT",
                "Local DECLASSIFY fact on field:app.Account.iban is ignored")
                .at(Site.of("bank", CodeRef.ofClass("authtracer.yaml")));

        JsonNode run = runOf(new DiffReport("base", "head", List.of(conflict)));

        assertThat(run.at("/results/0/locations/0/physicalLocation/artifactLocation/uri").asString())
                .isEqualTo("authtracer.yaml");
        assertThat(run.at("/results/0/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(1);
    }

    @Test
    void pathsAreRelativeToTheRepositoryAProjectIsIn() throws IOException {
        // A service in a monorepo: code scanning matches paths from the repository's root.
        Path service = project.resolve("services/bank");
        Files.createDirectories(project.resolve(".git"));
        Files.createDirectories(service.resolve("src/main/java/app"));
        Files.move(project.resolve("src/main/java/app/Account.java"), service.resolve("src/main/java/app/Account.java"));
        Change change = Change.of(Kind.WEAKENED, "bank", "GET /accounts/{id}", "iban", "ROLE_ADMIN", "authenticated",
                null).at(Site.of("bank", CodeRef.ofMethod("app.Account", "getIban()")));

        JsonNode sarif = JSON.readTree(SarifReport.write(new DiffReport("base", "head", List.of(change)),
                Map.of("bank", service)));

        assertThat(sarif.at("/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri").asString())
                .isEqualTo("services/bank/src/main/java/app/Account.java");
    }

    private JsonNode runOf(DiffReport report) {
        JsonNode sarif = JSON.readTree(SarifReport.write(report, Map.of("bank", project)));
        assertThat(sarif.get("version").asString()).isEqualTo("2.1.0");
        return sarif.get("runs").get(0);
    }

    private void write(String relative, String content) throws IOException {
        Path file = project.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
