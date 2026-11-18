package dev.crain.authtracer.mutation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import dev.crain.authtracer.mutation.Mutation.Operator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mutations mutationTest makes, on the roles fixture's sources.
 */
class MutatorsTests {

    private static final Path ROLES = Path.of("src/fixtures/java/fixtures/roles");

    private final List<Mutation> mutations = mutations();

    private static List<Mutation> mutations() {
        try {
            return Mutators.of(ROLES);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private String mutated(Operator operator, String description) throws IOException {
        Mutation mutation = mutations.stream().filter(candidate -> candidate.operator() == operator
                && candidate.description().contains(description)).findFirst().orElseThrow();
        return mutation.apply(Files.readString(ROLES.resolve(mutation.file())));
    }

    @Test
    void aMethodCheckIsDroppedOrLoosened() throws IOException {
        assertThat(mutated(Operator.DROP_METHOD_CHECK, "@Secured(\"ROLE_ADMIN\")"))
                .doesNotContain("@Secured").contains("String admin()");
        assertThat(mutated(Operator.LOOSEN_METHOD_CHECK, "profile()"))
                .contains("@PreAuthorize(\"isAuthenticated()\")");
        assertThat(mutated(Operator.WIDEN_ROLES, "admin(): @Secured"))
                .contains("@Secured({\"ROLE_ADMIN\", \"ROLE_USER\"})");
    }

    @Test
    void aRequestRuleIsLoosenedDroppedOrMovedBehindAPermitAll() throws IOException {
        assertThat(mutated(Operator.LOOSEN_RULE, "\"/staff/**\""))
                .contains(".requestMatchers(\"/staff/**\").permitAll()");
        assertThat(mutated(Operator.RULE_TO_AUTHENTICATED, "\"/both/**\""))
                .contains(".requestMatchers(\"/both/**\").authenticated()");
        assertThat(mutated(Operator.DROP_RULE, "\"/legacy/**\"")).doesNotContain("/legacy/**");
        assertThat(mutated(Operator.EARLY_PERMIT_ALL, "for .requestMatchers(\"/both/**\")"))
                .contains(".requestMatchers(\"/both/**\").permitAll().requestMatchers(\"/staff/**\")");
        assertThat(mutated(Operator.REORDER_RULES, "swap .requestMatchers(\"/staff/**\")"))
                .containsSubsequence("/legacy/**", "/staff/**", "/both/**");
    }

    @Test
    void aMatcherMatchesLessOrMore() throws IOException {
        assertThat(mutated(Operator.NARROW_MATCHER, "narrowed to \"/staff\""))
                .contains(".requestMatchers(\"/staff\").hasRole(\"STAFF\")");
        assertThat(mutated(Operator.NARROW_MATCHER, "\"/staff/**\").hasRole(\"STAFF\") for GET only"))
                .contains(".requestMatchers(org.springframework.http.HttpMethod.GET, \"/staff/**\")");
        assertThat(Mutators.parent("/a/b/**")).isEqualTo("/a/**");
        assertThat(Mutators.parent("/a/b")).isEqualTo("/a/**");
        assertThat(Mutators.parent("/a/**")).isEqualTo("/**");
    }

    @Test
    void aCustomManagersDecisionGrantsEveryone() throws IOException {
        Path programmatic = Path.of("src/fixtures/java/fixtures/programmaticchecks");
        Mutation grant = Mutators.of(programmatic).stream()
                .filter(mutation -> mutation.operator() == Operator.GRANT_IN_CODE
                        && mutation.description().startsWith("DraftsManager.authorize()"))
                .findFirst().orElseThrow();
        assertThat(grant.apply(Files.readString(programmatic.resolve(grant.file())))).contains(
                "{ return new org.springframework.security.authorization.AuthorizationDecision(true); }");
    }

    /**
     * Decision 0120: what a rule in the fixture's authtracer.yaml describes is a check like Spring's own; the
     * library's own calls are what the rule stands for, not the application's checks.
     */
    @Test
    void aRulesAnnotationAndCallAreChecks() throws IOException {
        Path library = Path.of("src/fixtures/java/fixtures/customlibrary");
        List<Mutation> found = Mutators.of(library, List.of("annotation fixtures.customlibrary.RequiresPermission",
                "call fixtures.customlibrary.Guard#require"));
        assertThat(found).filteredOn(mutation -> mutation.operator() == Operator.DROP_METHOD_CHECK)
                .extracting(Mutation::description).contains(
                        "Orders.list(): drop @RequiresPermission(\"orders.read\")",
                        "OrdersController.export(): drop guard.require(\"orders.export\");")
                .noneMatch(description -> description.startsWith("Guard."));
        assertThat(found).filteredOn(mutation -> mutation.operator() == Operator.WIDEN_ROLES)
                .extracting(Mutation::description)
                .contains("Orders.list(): @RequiresPermission(\"orders.read\") also lets in USER");
    }

    @Test
    void aSecurityConfigurationLosesItsConfigurationAsAnUpgradeLeavesIt() throws IOException {
        assertThat(mutated(Operator.DROP_CONFIGURATION, "RolesSecurityConfig: drop @Configuration"))
                .doesNotContain("@Configuration\n@EnableMethodSecurity")
                .contains("@EnableMethodSecurity(securedEnabled = true)\nclass RolesSecurityConfig");
        assertThat(mutations).filteredOn(mutation -> mutation.operator() == Operator.DROP_CONFIGURATION).hasSize(1);
    }

    @Test
    void twoChainsSwapTheirOrder() throws IOException {
        Path web = Path.of("src/fixtures/java/fixtures/web");
        Mutation mutation = Mutators.of(web).stream()
                .filter(candidate -> candidate.operator() == Operator.REORDER_CHAINS).findFirst().orElseThrow();
        assertThat(mutation.description()).contains("swap @Order(1) of partnerApi() with @Order(2) of app()");
        assertThat(mutation.apply(Files.readString(web.resolve(mutation.file()))))
                .containsSubsequence("@Order(2)", "partnerApi(", "@Order(1)", "app(");
    }

    @Test
    void methodSecurityIsTurnedOffAndTheHierarchyUpsideDown() throws IOException {
        assertThat(mutated(Operator.DISABLE_METHOD_SECURITY, "with prePostEnabled = false"))
                .contains("@EnableMethodSecurity(prePostEnabled = false, securedEnabled = true)");
        assertThat(mutated(Operator.INVERT_ROLE_HIERARCHY, "role hierarchy"))
                .contains("ROLE_STAFF > ROLE_ADMIN\\nROLE_GUEST > ROLE_USER > ROLE_STAFF");
    }
}
