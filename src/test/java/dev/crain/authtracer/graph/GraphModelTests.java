package dev.crain.authtracer.graph;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * What the graph's nodes and edges make of the values a scan gives them.
 */
class GraphModelTests {

    private static final CodeRef HANDLER = CodeRef.ofMethod("app.Users", "get(long)");

    @Test
    void aFieldCheckGuardsAFieldOfItsTargetUnlessItNamesAnotherOwner() {
        AuthorizationLocation getter = check(CodeRef.ofMethod("app.User", "getSsn()"), "ssn", null);
        // A GraphQL resolver on UserController guards a field of the User it resolves.
        AuthorizationLocation resolver = check(CodeRef.ofMethod("app.UserController", "ssn(app.User)"), "ssn",
                "app.User");

        assertThat(getter.guardedField()).isEqualTo("field:app.User.ssn");
        assertThat(resolver.guardedField()).isEqualTo("field:app.User.ssn");
        assertThat(check(HANDLER, null, null).guardedField()).isNull();
    }

    @Test
    void aLineIsKeptOnlyWhenTheClassFileHasOne() {
        assertThat(HANDLER.atLine(12).line()).isEqualTo(12);
        // A statement the class file gives no line for.
        assertThat(HANDLER.atLine(-1).line()).isNull();
        assertThat(HANDLER.atLine(0).line()).isNull();
        assertThat(HANDLER.atLine(null).line()).isNull();
    }

    @Test
    void anEdgeWithoutViaGoesThroughNothing() {
        assertThat(new Edge("ingress:GET /users", "location:METHOD:app.Users#get", Edge.Kind.LOCAL,
                "ingress:GET /users", 1, null, false).via()).isEmpty();
    }

    @Test
    void anEmptyQueryIsNoQuery() {
        Egress call = Egress.of("RestClient", "GET", "/users", "http://users", null, HANDLER, null);

        assertThat(call.withQuery("view=full").query()).isEqualTo("view=full");
        assertThat(call.withQuery("").query()).isNull();
        assertThat(call.withQuery(null).query()).isNull();
    }

    @Test
    void aCallMovedToAnotherSiteKeepsWhatItSends() {
        CodeRef lambda = CodeRef.ofMethod("app.Users", "lambda$get$0(long)").atLine(14);
        Payload message = new Payload("app.UserViewed", false);
        Egress send = Egress.of("KafkaTemplate", "KAFKA", "users.viewed", null, null, lambda, null)
                .withRequest(message).withQuery("view=full");

        Egress moved = send.withCallSite(HANDLER.atLine(14));

        assertThat(moved.id()).isEqualTo("egress:" + HANDLER.atLine(14).key() + " KAFKA users.viewed");
        assertThat(moved.request()).isEqualTo(message);
        assertThat(moved.query()).isEqualTo("view=full");
    }

    @Test
    void aFieldHoldsTheElementsOfAnArray() {
        assertThat(Field.held("app.Pet[]")).isEqualTo("app.Pet");
        assertThat(Field.held("app.Pet")).isEqualTo("app.Pet");
        assertThat(Field.held(null)).isNull();
        assertThat(Field.isMap(null)).isFalse();
    }

    @Test
    void moreParamsAreAddedToTheOnesAnEndpointHas() {
        Ingress ingress = Ingress.of("GET", "/users", HANDLER);

        Ingress versioned = ingress.andParams("version:2");
        assertThat(versioned.params()).isEqualTo("version:2");
        Ingress both = versioned.andParams("handler=app.Users#get(long)");
        assertThat(both.params()).isEqualTo("version:2&handler=app.Users#get(long)");
        assertThat(both.id()).isEqualTo("ingress:GET /users?version:2&handler=app.Users#get(long)");
    }

    @Test
    void aTopicAnswersWithEachSendersTypeOnce() {
        Payload notice = new Payload("app.Notice", false);
        Payload alert = new Payload("app.Alert", false);
        Ingress topic = Ingress.of("SUBSCRIBE", "/topic/news", HANDLER).withOtherResponse(alert);
        // Without a response of its own, the first other one is what it answers with first.
        assertThat(topic.responses()).containsExactly(alert);

        Ingress answering = topic.withResponse(notice);
        assertThat(answering.withOtherResponse(null)).isSameAs(answering);
        assertThat(answering.withOtherResponse(notice)).isSameAs(answering);
        assertThat(answering.withOtherResponse(alert)).isSameAs(answering);
        assertThat(answering.responses()).containsExactly(notice, alert);
    }

    @Test
    void findingsWithoutALocationComeFirstAmongTheirKind() {
        Finding located = new Finding(Finding.Kind.OPAQUE_CONFIG, "a RoleHierarchy built at runtime", HANDLER);
        Finding anywhere = new Finding(Finding.Kind.OPAQUE_CONFIG, "the security chain can't be read", null);

        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "users", "r1", 8080,
                AuthoritySource.UNKNOWN, List.of(), List.of(), List.of(), List.of(), List.of(located, anywhere));

        assertThat(graph.findings()).containsExactly(anywhere, located);
    }

    private static AuthorizationLocation check(CodeRef target, String field, String fieldOwner) {
        return new AuthorizationLocation("location:FIELD:" + target.key(), "@PreAuthorize",
                AuthorizationLocation.Scope.FIELD, AuthorizationLocation.Phase.PRE,
                Requirement.anyAuthority(List.of("ROLE_ADMIN")), target, field, null,
                AuthorizationLocation.Denial.THROW, true, fieldOwner);
    }
}
