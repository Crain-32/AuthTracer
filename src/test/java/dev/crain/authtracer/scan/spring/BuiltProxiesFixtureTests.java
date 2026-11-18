package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0088: a proxy factory the application builds applies only its own interceptors, as Spring's defaults
 * build them, never the advisor beans Spring Security's factory bean has.
 */
class BuiltProxiesFixtureTests {

    private static final String STATEMENT = "fixtures.builtproxies.Statement#";
    private static final String BALANCE = "location:FIELD:" + STATEMENT + "getBalance():@PreAuthorize";
    private static final String NUMBER = "location:FIELD:" + STATEMENT + "getNumber():@Secured";
    private static final String OWNER = "location:FIELD:" + STATEMENT + "getOwner():@RolesAllowed";
    private static final String AMOUNT = "location:FIELD:fixtures.builtproxies.Entry#getAmount():@PreAuthorize";
    private static final String AUDIT = ":advisor:fixtures.builtproxies.BuiltProxiesConfig#auditStatements()";
    private static final String BUILT = ":built-factory";

    private final ApplicationGraph graph = FixtureScans.scan("builtproxies");

    @Test
    void springSecuritysFactoryBeanAppliesEveryAdvisor() {
        assertThat(path(graph, "ingress:GET /spring/balance")).containsExactlyInAnyOrder(BALANCE,
                "location:FIELD:" + STATEMENT + "getBalance()" + AUDIT);
        assertThat(location(BALANCE).requirement().authorities()).containsExactly("GROUP_ACCOUNTANT");
        assertThat(path(graph, "ingress:GET /spring/number")).contains(NUMBER);
    }

    @Test
    void aFactoryBuiltWithDefaultsRunsPrePostWithSpringsDefaultsAndNoAdvisorBean() {
        assertThat(path(graph, "ingress:GET /own/balance")).containsExactly(BALANCE + BUILT);
        AuthorizationLocation balance = location(BALANCE + BUILT);
        assertThat(balance.mechanism()).isEqualTo("@PreAuthorize");
        assertThat(balance.field()).isEqualTo("balance");
        assertThat(balance.requirement().authorities()).containsExactly("ROLE_ACCOUNTANT");
        assertThat(bypassed("/own/balance")).containsExactly("On GET /own/balance: Advisor auditStatements() on "
                + STATEMENT + "getBalance() is skipped when " + "fixtures.builtproxies.StatementController"
                + "#ownBalance() reads it: the object it reads comes from a proxy factory the application builds,"
                + " which applies only @PreFilter, @PreAuthorize, @PostAuthorize, @PostFilter,"
                + " @AuthorizeReturnObject");
    }

    @Test
    void aFactoryBuiltWithDefaultsSkipsSecuredAndJsr250() {
        assertThat(path(graph, "ingress:GET /own/number")).isEmpty();
        assertThat(bypassed("/own/number")).anySatisfy(message -> assertThat(message)
                .startsWith("On GET /own/number: @Secured on " + STATEMENT + "getNumber() is skipped"));
        // A static field the class initializer fills, and a local.
        assertThat(path(graph, "ingress:GET /own/owner")).isEmpty();
        assertThat(bypassed("/own/owner")).anySatisfy(message -> assertThat(message).startsWith(
                "On GET /own/owner: @RolesAllowed on " + STATEMENT + "getOwner() is skipped"));
        assertThat(path(graph, "ingress:GET /local/number")).isEmpty();
        assertThat(location(OWNER).requirement().authorities()).containsExactly("GROUP_TELLER");
    }

    @Test
    void whatAProxyFromABuiltFactoryReturnsIsThatFactorysProxy() {
        assertThat(path(graph, "ingress:GET /own/latest")).containsExactly(AMOUNT + BUILT);
        assertThat(location(AMOUNT + BUILT).requirement().authorities()).containsExactly("ROLE_ACCOUNTANT");
    }

    @Test
    void aFactoryBuiltFromAListAppliesTheInterceptorsListed() {
        assertThat(path(graph, "ingress:GET /listed/number")).containsExactly(NUMBER + BUILT);
        assertThat(location(NUMBER + BUILT).requirement().authorities()).containsExactly("ROLE_CLERK");
        assertThat(path(graph, "ingress:GET /listed/balance")).isEmpty();
        assertThat(bypassed("/listed/balance")).anySatisfy(message -> assertThat(message)
                .contains("@PreAuthorize on " + STATEMENT + "getBalance() is skipped")
                .endsWith("which applies only @Secured"));
    }

    @Test
    void aSerializedProxyRunsTheGettersChecksItsFactoryApplies() {
        assertThat(path(graph, "ingress:GET /own/statement")).containsExactlyInAnyOrder(BALANCE + BUILT,
                AMOUNT + BUILT);
        assertThat(path(graph, "ingress:GET /spring/statement")).contains(BALANCE, NUMBER, OWNER, AMOUNT);
    }

    @Test
    void aFactoryWhoseInterceptorsArentReadIsAFindingAndCreditsOnlyThoseRead() {
        ApplicationGraph unread = FixtureScans.scan("builtproxiesunread");
        assertThat(unread.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("builds an AuthorizationAdvisorProxyFactory with advisors AuthTracer doesn't read")
                .endsWith(", only @PreAuthorize"));
        assertThat(path(unread, "ingress:GET /listed")).containsExactly(
                "location:FIELD:fixtures.builtproxiesunread.Card#getNumber():@PreAuthorize" + BUILT);
        assertThat(path(unread, "ingress:GET /holder")).isEmpty();
        // A factory handed in by a caller AuthTracer doesn't trace: only what every factory the application builds
        // applies.
        assertThat(unread.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("proxies objects with a proxy factory AuthTracer can't trace")
                .endsWith(", only @PreAuthorize"));
        assertThat(path(unread, "ingress:GET /handed")).containsExactly(
                "location:FIELD:fixtures.builtproxiesunread.Card#getNumber():@PreAuthorize" + BUILT);
    }

    @Test
    void aFactoryBeanOfTheApplicationsOwnMayBeTheOneInjected() {
        ApplicationGraph forms = FixtureScans.scan("builtproxyforms");
        assertThat(path(forms, "ingress:GET /injected/title")).isEmpty();
        assertThat(forms.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("@Secured on fixtures.builtproxyforms.Report#getTitle() is skipped"));
    }

    @Test
    void listsFilledWithAddOrMadeByAsListAreRead() {
        ApplicationGraph forms = FixtureScans.scan("builtproxyforms");
        String report = "location:FIELD:fixtures.builtproxyforms.Report#";
        assertThat(path(forms, "ingress:GET /added/body")).containsExactly(report + "getBody():@RolesAllowed"
                + BUILT);
        assertThat(path(forms, "ingress:GET /asList/previous/notes")).containsExactly(report
                + "getNotes():@PostAuthorize" + BUILT);
    }

    @Test
    void oneOfTwoFactoriesRunsWhatBothApply() {
        ApplicationGraph forms = FixtureScans.scan("builtproxyforms");
        assertThat(path(forms, "ingress:GET /either/body")).isEmpty();
        assertThat(forms.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("@RolesAllowed on fixtures.builtproxyforms.Report#getBody() is skipped")
                .endsWith("which applies none of Spring's interceptors"));
    }

    @Test
    void aBuiltFactoryRunsItsInterceptorsWithoutMethodSecurity() {
        ApplicationGraph only = FixtureScans.scan("builtproxiesonly");
        String invoice = "location:FIELD:fixtures.builtproxiesonly.Invoice#";
        String boot = "location:HTTP_REQUEST:spring-boot-default:anyRequest";
        assertThat(path(only, "ingress:GET /invoice/total")).containsExactly(boot, invoice
                + "getTotal():@PreAuthorize" + BUILT);
        assertThat(((AuthorizationLocation) only.node(invoice + "getTotal():@PreAuthorize" + BUILT).orElseThrow())
                .requirement().authorities()).containsExactly("ROLE_ACCOUNTANT");
        assertThat(path(only, "ingress:GET /invoice/line")).containsExactly(boot,
                "location:FIELD:fixtures.builtproxiesonly.Line#getAmount():@PreAuthorize" + BUILT);
        // It has no interceptor for @Secured, and nothing else runs it.
        assertThat(path(only, "ingress:GET /invoice/number")).containsExactly(boot);
        assertThat(only.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).singleElement().asString()
                .contains("@Secured on fixtures.builtproxiesonly.Invoice#getNumber never runs");
    }

    private List<String> bypassed(String route) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .map(Finding::message).filter(message -> message.startsWith("On GET " + route + ":")).toList();
    }

    private AuthorizationLocation location(String id) {
        return (AuthorizationLocation) graph.node(id).orElseThrow();
    }
}
