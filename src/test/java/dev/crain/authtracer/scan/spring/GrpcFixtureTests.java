package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Registration;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0032: gRPC services on Spring gRPC, with stubs generated from src/fixtures/proto/greeter.proto.
 */
class GrpcFixtureTests {

    private static final String SAY_HELLO = "ingress:GRPC fixtures.grpc.Greeter/SayHello";
    private static final String LIST = "ingress:GRPC fixtures.grpc.Greeter/list_greetings";
    private static final String PING = "ingress:GRPC fixtures.grpc.Greeter/Ping";

    private final ApplicationGraph graph = FixtureScans.scan("grpc");

    @Test
    void everyRpcTheServiceImplementsIsIngress() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(SAY_HELLO, LIST,
                PING);
        Ingress list = (Ingress) graph.node(LIST).orElseThrow();
        assertThat(list.handler().method()).startsWith("listGreetings(");
        assertThat(list.response().type()).isEqualTo("fixtures.grpc.HelloReply");
        assertThat(list.response().many()).isTrue();
    }

    @Test
    void grpcSecurityRulesMatchTheFullMethodName() {
        assertThat(rule(SAY_HELLO).requirement().authorities()).containsExactly("SCOPE_greet");
        assertThat(rule(SAY_HELLO).mechanism()).isEqualTo("authorizeRequests (gRPC)");
        assertThat(rule(LIST).requirement().authorities()).containsExactly("SCOPE_greet", "SCOPE_list");
        assertThat(rule(LIST).routePattern()).isEqualTo("fixtures.grpc.Greeter/list_*");
        assertThat(rule(PING).requirement()).isEqualTo(Requirement.authenticated());
        assertThat(rule(PING).routePattern()).isEqualTo("allRequests");
    }

    @Test
    void methodSecurityOnTheHandlersAndWhatTheyCall() {
        assertThat(path(graph, LIST)).contains(
                "location:METHOD:fixtures.grpc.GreeterService#listGreetings(fixtures.grpc.HelloRequest,"
                        + "io.grpc.stub.StreamObserver):@PreAuthorize");
        assertThat(path(graph, SAY_HELLO)).endsWith("location:METHOD:fixtures.grpc.Notes#secret():@PreAuthorize");
    }

    @Test
    void theResourceServerIsTheAuthoritySource() {
        assertThat(graph.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.JWT_CLAIMS);
    }

    @Test
    void protobufMessagesExposeTheirFields() {
        assertThat(graph.node("field:fixtures.grpc.HelloReply.message")).isPresent();
        assertThat(graph.node("field:fixtures.grpc.HelloReply.secretNote")).isPresent();
        assertThat(graph.node("field:fixtures.grpc.HelloReply.serializedSize")).isEmpty();
        // A repeated field, read through getHistoryList(), and one written in camel case.
        assertThat(((Field) graph.node("field:fixtures.grpc.HelloReply.history").orElseThrow()).javaType())
                .isEqualTo("fixtures.grpc.Greeting[]");
        assertThat(graph.node("field:fixtures.grpc.HelloReply.replyToken")).isPresent();
        assertThat(graph.node("field:fixtures.grpc.HelloReply.historyCount")).isEmpty();
    }

    @Test
    void whatABuilderAddsToARepeatedFieldHasLineage() {
        assertThat(graph.flows(SAY_HELLO)).contains(Flow.local(SAY_HELLO, "field:fixtures.grpc.HelloRequest.name",
                "field:fixtures.grpc.Greeting.text", FieldSource.DIRECT));
    }

    @Test
    void responsesPassedToTheObserverHaveLineage() {
        // HelloReply.newBuilder().setMessage("Hello " + request.getName()).. passed to responseObserver.onNext(..).
        assertThat(graph.flows(SAY_HELLO)).contains(Flow.local(SAY_HELLO, "field:fixtures.grpc.HelloRequest.name",
                "field:fixtures.grpc.HelloReply.message", FieldSource.COMPUTED));
    }

    @Test
    void anInterceptorThatIsNeverAppliedIsNotEnforced() {
        ApplicationGraph unenforced = FixtureScans.scan("grpcunenforced");
        assertThat(path(unenforced, SAY_HELLO)).isEmpty();
        assertThat(unenforced.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).singleElement().asString()
                .contains("not a @GlobalServerInterceptor");
    }

    @Test
    void stubCallsAreEgressLinkedToTheRpc() {
        ApplicationGraph client = FixtureScans.scan("grpcclient");
        Egress call = client.nodes(Egress.class).getFirst();
        assertThat(call.httpMethod()).isEqualTo("GRPC");
        assertThat(call.uriTemplate()).isEqualTo("fixtures.grpc.Greeter/SayHello");
        assertThat(call.baseUrlExpression()).isEqualTo("static://localhost:9090");
        assertThat(call.response().type()).isEqualTo("fixtures.grpc.HelloReply");
        assertThat(call.credentials()).isEqualTo(Credentials.RELAY);
        SystemGraph system = new Linker().link(List.of(client, graph), ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).containsExactly("grpc/" + SAY_HELLO);
    }

    @Test
    void theBearerInterceptorSendsTheTokenItIsGiven() {
        ApplicationGraph relay = FixtureScans.scan("grpcrelay");
        assertThat(relay.nodes(Egress.class)).extracting(call -> call.callSite().className()
                .replace("fixtures.grpcrelay.", ""), call -> call.credentials() + " " + call.credentialsVia())
                .containsExactlyInAnyOrder(
                        // The caller's token, read from the Reactor context, as a reactive client must.
                        org.assertj.core.groups.Tuple.tuple("RelayingGreeter",
                                "RELAY BearerTokenAuthenticationInterceptor: the caller's token, from"
                                        + " RelayingGreeter#greet"),
                        org.assertj.core.groups.Tuple.tuple("FixedGreeter",
                                "STATIC BearerTokenAuthenticationInterceptor"),
                        org.assertj.core.groups.Tuple.tuple("ListenerGreeter",
                                "STATIC BearerTokenAuthenticationInterceptor"),
                        // An application TokenSupplier that asks an authorized-client manager.
                        org.assertj.core.groups.Tuple.tuple("ServiceGreeter", "OAUTH2_CLIENT ServiceTokens"),
                        // A key from a bean AuthTracer doesn't see the implementation of.
                        org.assertj.core.groups.Tuple.tuple("KeyedGreeter",
                                "UNKNOWN BearerTokenAuthenticationInterceptor: the Authorization value comes from"
                                        + " KeyStore#current, which AuthTracer can't follow"));
    }

    @Test
    void eachCallOnAStubHasTheTokenItsOwnInterceptorIsGiven() {
        ApplicationGraph tokens = FixtureScans.scan("grpctokens");
        assertThat(tokens.nodes(Egress.class)).filteredOn(call -> call.httpMethod().equals("GRPC"))
                .extracting(call -> call.callSite().method(), call -> call.credentials() + " " + call.credentialsVia())
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("greet(java.lang.String)",
                                "RELAY BearerTokenAuthenticationInterceptor: the caller's token, from"
                                        + " TwoWayGreeter#greet"),
                        // The service's own, from a reactive authorized-client manager: what a listener calls with.
                        org.assertj.core.groups.Tuple.tuple("greetAsService(java.lang.String)",
                                "OAUTH2_CLIENT BearerTokenAuthenticationInterceptor: an authorized client's token,"
                                        + " from TwoWayGreeter#greetAsService"),
                        // A registration for the signed-in user (authorization_code): their token, as on a relay.
                        org.assertj.core.groups.Tuple.tuple("greetForPortal(java.lang.String)",
                                "RELAY BearerTokenAuthenticationInterceptor: the caller's token, from"
                                        + " TwoWayGreeter#greetForPortal (the signed-in user's authorization_code"
                                        + " token of registration portal)"));
        assertThat(path(tokens, "ingress:KAFKA greetings")).containsExactly("egress:fixtures.grpctokens.TwoWayGreeter"
                + "#greetAsService(java.lang.String) GRPC fixtures.grpcrelay.Relay/Greet");
    }

    @Test
    void theServicesOwnTokenNamesTheRegistrationItIsIssuedTo() {
        ApplicationGraph tokens = FixtureScans.scan("grpctokens");
        Egress service = (Egress) tokens.node("egress:fixtures.grpctokens.TwoWayGreeter#greetAsService(java.lang.String)"
                + " GRPC fixtures.grpcrelay.Relay/Greet").orElseThrow();
        // As the properties declare it: the client, its grant and scopes, and its provider's token endpoint.
        assertThat(service.registration()).isEqualTo(new Registration("greeter", "greeter-service",
                "client_credentials", new java.util.TreeSet<>(List.of("greetings.audit", "greetings.read")),
                "http://localhost:9000/oauth2/token", null));
        // A relayed token, the signed-in user's among them, is no registration's own.
        assertThat(tokens.nodes(Egress.class)).filteredOn(call -> call.credentials() == Credentials.RELAY)
                .hasSize(2).allSatisfy(call -> assertThat(call.registration()).isNull());
    }

    @Test
    void aListenerKeepsTheReplyItWaitsForNotTheRequestItSends() {
        ApplicationGraph relay = FixtureScans.scan("grpcrelay");
        // block() waits for the pipeline's value: the reply's message, as the call's response has it.
        assertThat(relay.flows("ingress:KAFKA names")).extracting(Flow::from, Flow::to, Flow::source)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("field:fixtures.grpcrelay.NameChanged.name",
                                "field:fixtures.grpcrelay.Reply.name", FieldSource.DIRECT),
                        org.assertj.core.groups.Tuple.tuple("field:fixtures.grpcrelay.GreetReply.message",
                                "field:fixtures.grpcrelay.Reply.text", FieldSource.DIRECT));
        // A protobuf builder makes the request the call sends; its getters are not fields.
        assertThat(relay.nodes(Field.class)).noneMatch(field -> field.owner().endsWith("$Builder"));
    }

    @Test
    void aReplyMappedIntoARecordStillComesFromTheReply() {
        ApplicationGraph relay = FixtureScans.scan("grpcrelay");
        assertThat(relay.flows("ingress:GET /greetings/{name}")).extracting(Flow::from, Flow::to, Flow::source)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("field:fixtures.grpcrelay.GreetReply.message",
                                "field:fixtures.grpcrelay.GreetingView.text", FieldSource.COMPUTED),
                        org.assertj.core.groups.Tuple.tuple("field:fixtures.grpcrelay.GreetReply.secretNote",
                                "field:fixtures.grpcrelay.GreetingView.note", FieldSource.DIRECT));
    }

    @Test
    void anImportedStubBeanCallsItsTarget() {
        Egress ping = FixtureScans.scan("grpcimport").nodes(Egress.class).getFirst();
        assertThat(ping.uriTemplate()).isEqualTo("fixtures.grpc.Greeter/Ping");
        assertThat(ping.baseUrlExpression()).isEqualTo("static://greeter:9090");
    }

    @Test
    void springBootsServerAddsHealthAndReflection() {
        ApplicationGraph boot = FixtureScans.scan("grpcboot");
        assertThat(boot.nodes(Ingress.class)).extracting(Ingress::id).contains(
                "ingress:GRPC grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
                "ingress:GRPC grpc.health.v1.Health/Check", "ingress:GRPC grpc.health.v1.Health/Watch");
        // Its global rules permit grpc.*: reflection lists every service to anyone.
        assertThat(FixtureScans.rule(boot, "GRPC grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
                .requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        // Not without Spring Boot.
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).noneMatch(id -> id.contains("grpc.health"));
    }

    @Test
    void reflectionRegisteredByHandIsServedWhateverBootsPropertySays() {
        ApplicationGraph byHand = FixtureScans.scan("grpcreflection");
        assertThat(byHand.nodes(Ingress.class)).extracting(Ingress::id).contains(
                "ingress:GRPC grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
                "ingress:GRPC grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo");
        assertThat(((Ingress) byHand.node("ingress:GRPC grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
                .orElseThrow()).handler().method()).startsWith("legacyReflection(");
        assertThat(FixtureScans.rule(byHand, "GRPC grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
                .requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    @Test
    void throughTheServletContainerHealthIsAPostAndReflectionCanBeOff() {
        ApplicationGraph servlet = FixtureScans.scan("grpcservletboot");
        // spring.grpc.server.reflection.enabled=false; the greeter implements only SayHello.
        assertThat(servlet.nodes(Ingress.class)).extracting(Ingress::id).filteredOn(id -> id.startsWith("ingress:GRPC"))
                .containsExactlyInAnyOrder("ingress:GRPC fixtures.grpc.Greeter/SayHello",
                        "ingress:GRPC grpc.health.v1.Health/Check", "ingress:GRPC grpc.health.v1.Health/Watch");
        // Health arrives as POST /grpc.health.v1.Health/Check, which the HTTP rules authorize.
        AuthorizationLocation health = FixtureScans.rule(servlet, "GRPC grpc.health.v1.Health/Check");
        assertThat(health.mechanism()).isEqualTo("authorizeHttpRequests");
        assertThat(health.requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(FixtureScans.rule(servlet, "GRPC fixtures.grpc.Greeter/SayHello").requirement().kind())
                .isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void repeatedImportsAndScannedPackagesGiveTheStubsChannel() {
        ApplicationGraph repeated = FixtureScans.scan("grpcimports");
        assertThat(repeated.nodes(Egress.class)).extracting(Egress::baseUrlExpression)
                .containsExactlyInAnyOrder("static://greeter:9090", "static://backup:9091");
        assertThat(FixtureScans.scan("grpcscan").nodes(Egress.class)).singleElement()
                .satisfies(call -> assertThat(call.baseUrlExpression()).isEqualTo("static://scanned:9093"));
    }

    @Test
    void channelsNamedInOtherWays() {
        ApplicationGraph forms = FixtureScans.scan("grpcclientforms");
        // An import by value on the default channel, whose address is the standalone starter's property; a channel
        // the client creates from a configured name; and a stub a @Bean elsewhere builds, whose channel the caller's
        // class doesn't name.
        assertThat(forms.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrlExpression)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("fixtures.grpc.Greeter/SayHello", "static://greeter:9094"),
                        org.assertj.core.groups.Tuple.tuple("fixtures.grpc.Greeter/list_greetings",
                                "static://backup:9095"),
                        org.assertj.core.groups.Tuple.tuple("fixtures.grpc.Greeter/Ping", null));
        assertThat(forms.nodes(Egress.class)).filteredOn(call -> call.uriTemplate().endsWith("list_greetings"))
                .singleElement().satisfies(call -> assertThat(call.response().many()).isTrue());
        // basePackages by name: a package without the stub, then a parent package of its.
        assertThat(FixtureScans.scan("grpcpackages").nodes(Egress.class)).singleElement()
                .satisfies(call -> assertThat(call.baseUrlExpression()).isEqualTo("static://everything:9096"));
    }

    @Test
    void grpcKotlinCoroutineServicesAndStubs() {
        ApplicationGraph kotlin = FixtureScans.scan("grpckotlin");
        assertThat(kotlin.nodes(Ingress.class)).extracting(Ingress::id).contains(SAY_HELLO, PING);
        assertThat(path(kotlin, SAY_HELLO)).contains("location:METHOD:fixtures.grpckotlin.KotlinNotes#secret():"
                + "@PreAuthorize");
        assertThat(path(kotlin, PING)).anySatisfy(step -> assertThat(step).startsWith(
                "location:METHOD:fixtures.grpckotlin.KotlinGreeter#ping("));
        Egress call = kotlin.nodes(Egress.class).getFirst();
        assertThat(call.uriTemplate()).isEqualTo("fixtures.grpc.Greeter/SayHello");
        assertThat(call.baseUrlExpression()).isEqualTo("static://localhost:9090");
    }

    @Test
    void servedThroughTheServletContainerTheHttpRulesApply() {
        ApplicationGraph servlet = FixtureScans.scan("grpcservlet");
        AuthorizationLocation grpcRule = (AuthorizationLocation) servlet.node(path(servlet, SAY_HELLO).getFirst())
                .orElseThrow();
        // GrpcRequest.toAnyService(): the services the application serves, as /<service>/** request patterns.
        assertThat(grpcRule.mechanism()).isEqualTo("authorizeHttpRequests");
        assertThat(grpcRule.routePattern()).isEqualTo("/fixtures.grpc.Greeter/**");
        assertThat(grpcRule.requirement().authorities()).containsExactly("SCOPE_grpc");
        assertThat(FixtureScans.rule(servlet, "GET /status/now").requirement().authorities())
                .containsExactly("SCOPE_rest");
    }

    @Test
    void anInterceptorBeanTypedAsServerInterceptor() {
        ApplicationGraph basic = FixtureScans.scan("grpcbasic");
        AuthorizationLocation hello = (AuthorizationLocation) basic.node(path(basic, SAY_HELLO).getFirst())
                .orElseThrow();
        assertThat(hello.requirement().authorities()).containsExactly("ROLE_USER");
        AuthorizationLocation ping = (AuthorizationLocation) basic.node(path(basic, PING).getFirst()).orElseThrow();
        assertThat(ping.requirement()).isEqualTo(Requirement.denyAll());
        assertThat(basic.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.USER_DETAILS);
        assertThat(basic.authoritySource().detail()).contains("HTTP Basic").contains("client certificate");
    }

    @Test
    void aRuleOverMethodsAuthTracerCantReadMayMatchFirst() {
        ApplicationGraph dynamic = FixtureScans.scan("grpcdynamic");
        AuthorizationLocation hello = (AuthorizationLocation) dynamic.node(path(dynamic, SAY_HELLO).getFirst())
                .orElseThrow();
        // The open rule may take the call before allRequests() does: the weakest of the two.
        assertThat(hello.requirement().permitsAnyone()).isTrue();
        assertThat(hello.mechanism()).contains("may match first");
        assertThat(dynamic.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).contains("methods AuthTracer can't read");
        });
    }

    @Test
    void aServiceThatNamesTheInterceptorGetsItsRules() {
        ApplicationGraph named = FixtureScans.scan("grpcnamed");
        // The configured methods may match first, with the same requirement as the rule that does.
        AuthorizationLocation hello = FixtureScans.rule(named, "GRPC fixtures.grpc.Greeter/SayHello");
        assertThat(hello.mechanism()).contains("may match first");
        assertThat(hello.requirement().authorities()).containsExactly("SCOPE_greet");
        // No rule matches Ping, which is denied unless the configured methods take it.
        AuthorizationLocation ping = FixtureScans.rule(named, "GRPC fixtures.grpc.Greeter/Ping");
        assertThat(ping.routePattern()).endsWith(" or unmatched");
        assertThat(ping.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Requirement.Kind.ANY_AUTHORITY, Requirement.Kind.DENY_ALL);
        assertThat(named.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .hasSize(1);
        // Health is a library service: the named rules don't reach it, and the global interceptor only authenticates.
        assertThat(path(named, "ingress:GRPC grpc.health.v1.Health/Check")).isEmpty();
        assertThat(named.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void aServiceThatListsTheInterceptorsClassGetsItsRules() {
        ApplicationGraph listed = FixtureScans.scan("grpclisted");
        assertThat(FixtureScans.rule(listed, "GRPC fixtures.grpc.Greeter/SayHello").requirement().kind())
                .isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(listed.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    private AuthorizationLocation rule(String ingress) {
        return (AuthorizationLocation) graph.node(path(graph, ingress).getFirst()).orElseThrow();
    }
}
