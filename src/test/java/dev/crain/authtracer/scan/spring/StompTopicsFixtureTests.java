package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0039: message rules on message types, a destination that isn't a constant, and one topic two handlers
 * send to.
 */
class StompTopicsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("stomptopics");

    @Test
    void simpTypeMatchersMatchTheirMessageTypes() {
        AuthorizationLocation rule = messageRule("ingress:SUBSCRIBE /topic/public");
        assertThat(rule.routePattern()).isEqualTo("simpTypeMatchers(SUBSCRIBE)");
        assertThat(rule.requirement().authorities()).containsExactly("ROLE_SUBSCRIBER");
    }

    @Test
    void aDestinationThatIsntAConstantMayMatchFirst() {
        AuthorizationLocation rule = messageRule("ingress:MESSAGE /app/news");
        assertThat(rule.id()).startsWith("location:SPLIT:");
        assertThat(rule.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Requirement.Kind.PERMIT_ALL, Requirement.Kind.ANY_AUTHORITY);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString().startsWith("The message rule"
                        + " simpDestMatchers(?)");
    }

    @Test
    void aTopicTwoHandlersSendToIsCheckedOnceAndEachSendsItsOwnType() {
        String subscribe = "ingress:SUBSCRIBE /topic/public";
        assertThat(path(graph, subscribe)).isNotEmpty().doesNotHaveDuplicates();
        // The subscription keeps the first sender's type; each sender's payload is read as its own type.
        assertThat(graph.node(Field.id("fixtures.stomptopics.News", "headline"))).isPresent();
        assertThat(graph.node(Field.id("fixtures.stomptopics.Alert", "level"))).isPresent();
        // So is what a template pushes there.
        assertThat(graph.node(Field.id("fixtures.stomptopics.Bulletin", "secretDetail"))).isPresent();
        // A subscriber gets every sender's type, so each is exposed to it (found by checking GraphBuilder's
        // duplicate ids: the subscription kept the first sender's type only).
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.endpoint().equals("SUBSCRIBE /topic/public"))
                .extracting(Exposures.Exposure::fieldId).contains("stomptopics/field:fixtures.stomptopics.News.headline",
                        "stomptopics/field:fixtures.stomptopics.Alert.level",
                        "stomptopics/field:fixtures.stomptopics.Bulletin.secretDetail");
    }

    @Test
    void aClassLevelSendToUserRepliesToTheSenderOnly() {
        assertThat(graph.node("ingress:SUBSCRIBE /topic/balance")).isEmpty();
        assertThat(((Ingress) graph.node("ingress:MESSAGE /app/balance").orElseThrow()).response().type())
                .isEqualTo("fixtures.stomptopics.Balance");
    }

    private AuthorizationLocation messageRule(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().startsWith(MessageSecurityRules.MECHANISM)).findFirst()
                .orElseThrow();
    }
}
