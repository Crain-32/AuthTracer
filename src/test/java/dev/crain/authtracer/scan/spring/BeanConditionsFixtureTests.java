package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0111: a bean behind a profile, a condition or outside the component scan is a bean when the code and the
 * configuration make it one; otherwise it may be one, and the graph keeps its weaker reading with a finding.
 */
class BeanConditionsFixtureTests {

    private final ApplicationGraph profiles = FixtureScans.scan("profilechains");
    private final ApplicationGraph scanned = FixtureScans.scan("scannedbeans");

    @Test
    void aChainForAProfileTheConfigurationDoesntActivateMayTakeItsRequests() {
        AuthorizationLocation admin = rule(profiles, "GET /admin/users");
        assertThat(admin.id()).startsWith("location:SPLIT:");
        assertThat(admin.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
        assertThat(opaque(profiles)).anySatisfy(message -> assertThat(message)
                .startsWith("The bean fixtures.profilechains.ProfileChainsConfig#prod(")
                .contains("only made when profile prod is active", "the configuration activates [dev]",
                        "its rules or the chains after it"));
    }

    @Test
    void aProfileTheConfigurationActivatesMakesItsBeans() {
        assertThat(rule(profiles, "GET /ping").requirement().kind())
                .isEqualTo(Kind.PERMIT_ALL);
        assertThat(opaque(profiles)).noneSatisfy(message -> assertThat(message)
                .containsAnyOf("#dev(", "#rest(", "PingController"));
    }

    @Test
    void methodSecurityEnabledOnlyUnderAProfileMayNotBeOn() {
        assertThat(profiles.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("@PreAuthorize", "may never run: method security is enabled only by"
                                + " @EnableMethodSecurity on fixtures.profilechains.SecureMethodsConfig, which is"
                                + " only a bean when profile secure is active"));
        assertThat(opaque(profiles)).anySatisfy(message -> assertThat(message)
                .startsWith("fixtures.profilechains.SecureMethodsConfig is only a bean when profile secure is active")
                .contains("its @EnableMethodSecurity may not be on"));
    }

    @Test
    void anEndpointBehindAPropertyTheConfigurationDoesntSetIsShownWithAFinding() {
        assertThat(profiles.node("ingress:GET /debug/state")).isPresent();
        assertThat(opaque(profiles)).anySatisfy(message -> assertThat(message)
                .startsWith("fixtures.profilechains.DebugController is only a bean when app.debug.enabled is true"
                        + " (the configuration doesn't set it)")
                .contains("its endpoints are shown, though they may not exist"));
    }

    @Test
    void aComponentOutsideTheComponentScanMayNotBeABean() {
        assertThat(scanned.node("ingress:GET /legacy/items")).isPresent();
        assertThat(opaque(scanned)).anySatisfy(message -> assertThat(message)
                .startsWith("fixtures.scannedbeans.extra.LegacyController is only a bean when something registers"
                        + " it: it is outside the component scan (packages [fixtures.scannedbeans.app])")
                .contains("its endpoints are shown"));
        assertThat(opaque(scanned)).anySatisfy(message -> assertThat(message)
                .startsWith("fixtures.scannedbeans.extra.StrayRoles is only a bean when")
                .contains("its bean roleHierarchy (the graph shows it as made)"));
    }

    @Test
    void anEnableAnnotationOnAClassNothingRegistersEnablesNothing() {
        // Spring Security 6's @Enable annotations don't carry @Configuration: these classes are no beans.
        ApplicationGraph upgraded = FixtureScans.scan("enablenoconfiguration");
        assertThat(FixtureScans.path(upgraded, "ingress:GET /vault"))
                .noneMatch(id -> id.contains("Vault#open"));
        assertThat(upgraded.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("@PreAuthorize on fixtures.enablenoconfiguration.Vault#open may never run:"
                                + " method security is enabled only by @EnableMethodSecurity on"
                                + " fixtures.enablenoconfiguration.MethodSecurityConfig, which is only a bean when"
                                + " something registers it"));
        // Its chain is never made: Boot's default chain, which asks less, may take the requests.
        AuthorizationLocation vault = rule(upgraded, "GET /vault");
        assertThat(vault.requirement().kind()).isNotEqualTo(Kind.DENY_ALL);
        assertThat(opaque(upgraded)).anySatisfy(message -> assertThat(message)
                .startsWith("fixtures.enablenoconfiguration.WebSecurityConfig is only a bean when something"
                        + " registers it: it has no @Configuration"));
    }

    @Test
    void aClassHandedToSpringApplicationRunIsABean() {
        ApplicationGraph handed = FixtureScans.scan("enablehanded");
        assertThat(FixtureScans.path(handed, "ingress:GET /vault"))
                .contains("location:METHOD:fixtures.enablehanded.Vault#open():@PreAuthorize");
        assertThat(handed.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void anImportedConfigurationIsABeanWherever() {
        assertThat(rule(scanned, "GET /items").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(scanned, "GET /items").id()).doesNotStartWith("location:SPLIT:");
        assertThat(opaque(scanned)).noneSatisfy(message -> assertThat(message).contains("ImportedSecurity"));
    }

    @Test
    void autoConfigurationFilesRegisterTheClassesTheyName() {
        assertThat(scanned.node("ingress:GET /factory/items")).isPresent();
        assertThat(scanned.node("ingress:GET /imports/items")).isPresent();
        assertThat(opaque(scanned)).noneSatisfy(message -> assertThat(message)
                .containsAnyOf("FactoryController", "ImportsController", "ItemsController"));
    }

    @Test
    void whereTheScanRootsCantBeToldEveryComponentIsABean() {
        assertThat(opaque(FixtureScans.scan("scanannotation")))
                .noneSatisfy(message -> assertThat(message).contains("OtherController"));
        assertThat(opaque(FixtureScans.scan("xmlscan")))
                .noneSatisfy(message -> assertThat(message).contains("XmlScannedController"));
    }

    @Test
    void conditionsTheClasspathTheStackAndTheConfigurationDecide() {
        List<String> findings = opaque(FixtureScans.scan("conditionforms"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.MissingClassController is only a bean when com.example.NotThere is on the"
                        + " classpath (it isn't on the one AuthTracer read), which AuthTracer can't decide: its"
                        + " endpoints are shown"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.NoDispatcherController is only a bean when"
                        + " org.springframework.web.servlet.DispatcherServlet is not on the classpath"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.ReactiveOnlyController is only a bean when the application is a reactive"
                        + " web application (AuthTracer reads it as a servlet one)"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.NotWebController is only a bean when the application is not a web"
                        + " application"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.OnBeanController is only a bean when @ConditionalOnBean(name=auditTrail)"
                        + " holds"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.NoFlagController is only a bean when app.flag is false (the configuration"
                        + " sets true)"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.StrictController is only a bean when app.mode is strict (the configuration"
                        + " sets lenient)"));
        assertThat(findings).anySatisfy(message -> assertThat(message).startsWith(
                "fixtures.conditionforms.OffController is only a bean when app.off is set and not false (the"
                        + " configuration sets false)"));
        assertThat(findings).noneSatisfy(message -> assertThat(message).containsAnyOf("PresentClassController",
                "NoMissingController", "AnyWebController", "conditionforms.FlagController", "UnsetController",
                "CloudController"));
    }

    @Test
    void profileExpressionsReadAsSpringReadsThem() {
        List<String> active = List.of("prod", "cloud");
        assertThat(new BeanConditions.ProfileExpression("prod").matches(active)).isTrue();
        assertThat(new BeanConditions.ProfileExpression("!test").matches(active)).isTrue();
        assertThat(new BeanConditions.ProfileExpression("!prod").matches(active)).isFalse();
        assertThat(new BeanConditions.ProfileExpression("prod & cloud").matches(active)).isTrue();
        assertThat(new BeanConditions.ProfileExpression("prod & dev").matches(active)).isFalse();
        assertThat(new BeanConditions.ProfileExpression("dev | cloud").matches(active)).isTrue();
        assertThat(new BeanConditions.ProfileExpression("(dev | prod) & !test").matches(active)).isTrue();
        assertThat(new BeanConditions.ProfileExpression("").matches(active)).isFalse();
    }

    private static List<String> opaque(ApplicationGraph graph) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
    }
}
