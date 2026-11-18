package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Opaque;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.FrameworkModule;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.GenericTypes;
import dev.crain.authtracer.scan.flow.Payloads;
import dev.crain.authtracer.scan.flow.ResponseFields;
import dev.crain.authtracer.scan.flow.TypeProperties;
import dev.crain.authtracer.scan.flow.ValueFlow;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Spring Security, as documented in the Spring Security 7.x reference (see {@code docs/catalog/spring-security-7.md}).
 */
@Supports({Feature.CALL_PATHS, Feature.APPLICATION_GRAPH})
public final class SpringSecurityModule implements FrameworkModule {

    private static final String AUTHENTICATION = "org.springframework.security.core.Authentication";
    private static final List<String> WEB_STACKS = List.of("org.springframework.web.servlet.DispatcherServlet",
            "org.springframework.web.reactive.DispatcherHandler", "io.grpc.BindableService");
    private static final Set<String> PRE_POST = Set.of("@PreAuthorize", "@PostAuthorize", "@PreFilter", "@PostFilter");
    private static final String JSON_VIEW = "com.fasterxml.jackson.annotation.JsonView";

    /**
     * A Spring web (or gRPC) application, with or without Spring Security: without it, every endpoint is reachable by
     * anyone, which is what the graph then shows.
     */
    @Override
    public boolean applies(ScanContext context) {
        return context.findClass(AUTHENTICATION).isPresent() || WEB_STACKS.stream()
                .anyMatch(stack -> context.findClass(stack).isPresent());
    }

    @Override
    public void scan(ScanContext context, GraphBuilder graph) {
        new Scan(context, graph).run();
    }

    /**
     * One application's scan: the configuration read first, then the phases in {@link #run()}, in order.
     */
    private static final class Scan {

        private final ScanContext context;
        private final GraphBuilder graph;
        private final SecurityXml.Config xml;
        private final SpringBeans beans;
        private final RoleHierarchies hierarchy;
        private final AuthoritySource authorities;
        private final AuthorizationManagerFactories.Factory http;
        private final boolean reactive;
        private final AuthorizationManagerFactories.Factory prePost;
        private final MethodSecurity methodSecurity;
        private final Proxies proxies;
        private final GrpcServices grpc;
        private final List<RequestMappings.Mapping> rpcs;
        private final HttpSecurityRules httpRules;
        private final GrpcSecurityRules grpcRules;
        private final HttpClientEgress egress;
        private final CallTraversal traversal;
        private final ValueFlow valueFlow;
        private final ResponseFields responseFields;
        private final GenericTypes genericTypes;
        private final ViewModels viewModels;
        private final ViewFields viewFields;
        private final Set<JavaSootMethod> reachable = new LinkedHashSet<>();
        private final AsyncCalls async;
        private final EnclosingMethods enclosing;
        private final MessagePayloads payloads;
        /**
         * Decision 0066: the checks the code makes itself with an AuthorizationManager.
         */
        private final ProgrammaticChecks programmatic;
        /**
         * Decision 0064: the code that decides checks, held for the whole scan.
         */
        private final DecisionCode decisionCode;
        /**
         * Where each path ends, for the GraphQL field resolvers that run after it.
         */
        private final Map<String, PathTail> tails = new HashMap<>();
        private final RequestFilters filters;
        /**
         * The handlers the DispatcherServlet's handler mappings serve, which its interceptors run before.
         */
        private final Set<MethodSignature> dispatched = new HashSet<>();
        /**
         * Decision 0110: the handlers whose GET mapping a HEAD request runs too.
         */
        private final Set<JavaSootMethod> headServed = new HashSet<>();

        // What the entry points phase finds, for the phases after it.
        private SoapEndpoints soap;
        private ServletEndpoints servlets;
        /**
         * The GrantedAuthorityDefaults prefix, which the request wrapper's isUserInRole adds (Jersey's roles).
         */
        private final String rolePrefix;
        private JaxRsResources jaxRs;
        private final Map<String, StreamFunctions.Binding> streamBindings = new HashMap<>();
        private DataRestRepositories dataRest;
        private SensitiveEndpoints sensitive;
        private GraphQlMappings graphQl;
        private List<RequestMappings.Mapping> operations;
        private StompMappings stomp;
        /**
         * Decision 0113: the handshakes a WebSocket transport stands for, by its id, where there are several.
         */
        private final Map<String, List<Ingress>> handshakes = new HashMap<>();

        @Supports({Feature.AUTHORITY_SOURCE, Feature.SYSTEM_GRAPH, Feature.FINDING_OPAQUE_CONFIG})
        Scan(ScanContext context, GraphBuilder graph) {
            this.context = context;
            this.graph = graph;
            decisionCode = DecisionCode.of(context);
            // Decision 0036: the XML namespace configuration, alongside the Java one, and the beans the XML defines.
            xml = SecurityXml.load(context.input().resourceDirs());
            // Decision 0097: shown, never guessed.
            xml.unread().forEach(file -> graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "AuthTracer can't"
                    + " parse " + file + ", which uses Spring Security's XML namespace (it is malformed, or declares a"
                    + " DOCTYPE, which AuthTracer refuses): the chains, rules and checks it configures are not in the"
                    + " graph", CodeRef.ofClass(file))));
            beans = new SpringBeans(context, xml.beans());
            // Decision 0111: the beans that may not be made, each in its weaker reading, with a finding.
            BeanConditions.of(context, xml.beans()).report(graph);
            hierarchy = RoleHierarchies.detect(context, graph);
            reactive = WebStack.reactive(context);
            // Decision 0070: the filters and interceptors requests pass before their handler; decision 0071: those
            // that authenticate are ways in.
            filters = new RequestFilters(context, beans, reactive);
            filters.findings().forEach(graph::finding);
            authorities = AuthenticationMechanisms.detect(context, xml, graph, FilterAuthentication.detect(context,
                    filters)).withRoleHierarchy(hierarchy.implies());
            graph.authoritySource(authorities);
            context.properties().get("server.port").map(String::trim).filter(port -> port.matches("\\d+"))
                    .map(Integer::valueOf).ifPresent(graph::port);
            additionalPorts(context, graph);
            rolePrefix = RoleHierarchies.rolePrefix(context, graph);
            // An AuthorizationManagerFactory bean replaces the prefix and hierarchy beans where it applies.
            AuthorizationManagerFactories factories = AuthorizationManagerFactories.detect(context, graph, hierarchy);
            http = factories.http().orElse(new AuthorizationManagerFactories.Factory(rolePrefix, hierarchy));
            WebStack.report(context, graph, reactive);
            // Decision 0091 (EXPR-05): a MethodSecurityExpressionHandler bean replaces pre/post's own.
            Optional<ExpressionHandlers.Handler> handler = ExpressionHandlers.detect(context, graph, hierarchy,
                    factories.prePost(), context.anyClassAnnotated(SpringNames.ENABLE_GLOBAL_METHOD_SECURITY));
            prePost = prePost(factories, rolePrefix, handler);
            ProxyFactories proxyFactories = new ProxyFactories(context, graph);
            methodSecurity = new MethodSecurity(context, beans, graph, prePost.rolePrefix(), rolePrefix,
                    xml, handler, proxyFactories);
            proxies = new Proxies(context, methodSecurity, proxyFactories);
            grpc = new GrpcServices(context);
            rpcs = grpc.detect(beans);
            // gRPC served through the servlet container passes the HTTP rules: GrpcRequest.toAnyService() names them.
            httpRules = new HttpSecurityRules(context, graph, new SpelRequirements(http.rolePrefix()), reactive,
                    GrpcServices.serviceNames(rpcs), xml);
            grpcRules = new GrpcSecurityRules(context, graph, new SpelRequirements(http.rolePrefix()));
            egress = new HttpClientEgress(context, grpc);
            // A call that more than one bean answers runs one of them.
            traversal = new CallTraversal(context, beans::isBean);
            TypeProperties properties = new TypeProperties(context);
            valueFlow = new ValueFlow(context, properties, traversal);
            responseFields = new ResponseFields(graph, properties);
            payloads = new MessagePayloads(valueFlow, responseFields, properties);
            genericTypes = new GenericTypes(context);
            viewModels = new ViewModels(context, genericTypes);
            // Decision 0081: a view's guard by URL asks what the request rules ask of that request.
            viewFields = new ViewFields(context, graph, properties, genericTypes, responseFields, xml,
                    (method, path) -> httpRules.locationFor(Ingress.of(method, path, null))
                            .map(AuthorizationLocation::requirement));
            // Decision 0048: @Async calls leave the caller's SecurityContext behind.
            async = new AsyncCalls(context);
            enclosing = new EnclosingMethods(context);
            programmatic = new ProgrammaticChecks(context, graph);
        }

        @Supports(Feature.INFRASTRUCTURE_CALLS)
        void run() {
            List<RequestMappings.Mapping> mappings = entryPoints();
            MessageSecurityRules messageRules = new MessageSecurityRules(context, graph, xml);
            EntryRules entryRules = new EntryRules(context, graph, httpRules, grpcRules, messageRules,
                    new RSocketSecurityRules(context, graph), graphQl.webSocketAuthentication(graph),
                    soap.transports(), handshakes);
            // A path a more specific mapping takes doesn't reach a route with variables that also matches it.
            httpRules.handled(mappings.stream().map(RequestMappings.Mapping::ingress).toList());
            List<RequestMappings.Mapping> walked = withHead(RequestMappings.unique(MessageListeners.distinct(
                    new RequestMappings(context).distinct(mappings))));
            // Decision 0081: handlers rendering one view with different models each show their own.
            viewModels.prepare(walked.stream().filter(mapping -> !mapping.functional() && mapping.transport() == null)
                    .toList());
            for (RequestMappings.Mapping mapping : walked) {
                try {
                    walk(mapping, entryRules);
                }
                catch (RuntimeException ex) {
                    // Which of the scan's endpoints it broke on, and where its handler is: what a report needs.
                    throw new IllegalStateException("Scanning " + mapping.ingress().endpoint() + " (handler "
                            + MethodNames.key(mapping.handler().getSignature()) + ") failed: " + ex, ex);
                }
            }
            gatewayRoutes();
            libraryEndpoints();
            // Decision 0049: what a resource server calls on its authorization server, and that server's endpoints.
            new IdentityProviderCalls(context).detect().forEach(graph::node);
            // Decision 0058: what it calls on its config server and Eureka server.
            new InfrastructureCalls(context).detect().forEach(graph::node);
            authorizationServers();
            stompBroadcasts(messageRules);
            Map<GraphQlMappings.Resolver, List<CallTraversal.Step>> resolvers = graphQlResolvers();
            // Decision 0091: what the requests bind into the parameters the checks' expressions name.
            Set<JavaSootMethod> handlers = new HashSet<>();
            walked.forEach(mapping -> handlers.add(mapping.handler()));
            resolvers.keySet().forEach(resolver -> handlers.add(resolver.method()));
            methodSecurity.bindArguments(handlers);
            hierarchiesAndFactories();
            hasPermission();
            // Decision 0063: what callers who haven't signed in hold, once the hierarchy has widened the role checks.
            AnonymousAuthentication.detect(context, graph, reactive).apply(graph);
            // Decision 0064: the custom code that decides checks, as they now show it.
            decisionCode.report(graph);
            AuthenticationMechanisms.ungranted(graph, authorities);
            rebuildSplits(graph);
            sensitive.report(graph);
            GraphQlFieldPaths.append(graph, operations, resolvers, tails, responseFields, valueFlow);
            GraphQlFieldPaths.markSchemaFields(graph, GraphQlSchema.load(context), operations);
            handRolledChecks();
            // Decision 0082: the calls on the paths whose target AuthTracer can't read.
            egress.findings().forEach(graph::finding);
        }

        /**
         * What pre/post builds its checks with: an expression handler bean's prefix, hierarchy and factory; else on
         * Servlet the factory bean, or the GrantedAuthorityDefaults and RoleHierarchy beans; reactive pre/post
         * ignores the factory and the hierarchy bean (RX-08).
         */
        @Supports(Feature.REQUIREMENTS)
        private AuthorizationManagerFactories.Factory prePost(AuthorizationManagerFactories factories,
                String rolePrefix, Optional<ExpressionHandlers.Handler> handler) {
            if (handler.isPresent()) {
                return handler.get().factory();
            }
            boolean reactiveMethods = context.anyClassAnnotated(SpringNames.ENABLE_REACTIVE_METHOD_SECURITY)
                    && !context.anyClassAnnotated(SpringNames.ENABLE_METHOD_SECURITY);
            if (reactiveMethods) {
                return new AuthorizationManagerFactories.Factory(rolePrefix, RoleHierarchies.NONE);
            }
            // 7.1.1's DefaultMethodSecurityExpressionHandler hands each root the factory bean and then, when the
            // GrantedAuthorityDefaults prefix isn't ROLE_, calls root.setDefaultRolePrefix(..), which sets that
            // prefix on the factory: pre/post builds with the bean's hierarchy and factors, and that prefix.
            return factories.prePost().map(factory -> rolePrefix.equals("ROLE_") ? factory
                    : new AuthorizationManagerFactories.Factory(rolePrefix, factory.hierarchy(), factory.additional()))
                    .orElse(new AuthorizationManagerFactories.Factory(rolePrefix, hierarchy));
        }

        /**
         * Every way a request, message, call or schedule enters the application, with its handler.
         */
        @Supports({Feature.HTTP_ENDPOINTS, Feature.GRAPHQL_OPERATIONS, Feature.GRPC_METHODS, Feature.MESSAGE_LISTENERS,
                Feature.WEBSOCKET_MESSAGES, Feature.RSOCKET_ROUTES, Feature.SCHEDULED_TASKS, Feature.LIBRARY_ENDPOINTS})
        private List<RequestMappings.Mapping> entryPoints() {
            List<RequestMappings.Mapping> mappings = new ArrayList<>(new RequestMappings(context).detect(beans));
            // Decision 0110: Spring MVC and WebFlux answer HEAD with a GET mapping.
            mappings.forEach(mapping -> headServed.add(mapping.handler()));
            // Decision 0080: functional endpoints, with findings for what can't be read of them.
            FunctionalEndpoints functional = new FunctionalEndpoints(context, beans);
            mappings.addAll(functional.detect());
            functional.findings().forEach(graph::finding);
            mappings.forEach(mapping -> dispatched.add(mapping.handler().getSignature()));
            // Decision 0056: Spring Web Services' SOAP operations, behind the dispatcher servlet's path.
            soap = new SoapEndpoints(context);
            mappings.addAll(soap.detect());
            soap.findings().forEach(graph::finding);
            // Decision 0055: Spring Cloud Config Server's endpoints.
            mappings.addAll(headServed(new ConfigServerEndpoints(context).detect()));
            // Decision 0053: servlets the application registers.
            servlets = new ServletEndpoints(context);
            // HttpServlet#doHead runs doGet, unless the servlet overrides it (a HEAD mapping of its own).
            mappings.addAll(headServed(servlets.detect()));
            servlets.findings().forEach(graph::finding);
            // Decision 0052: JAX-RS resources on Jersey, and the @RolesAllowed checks Jersey makes itself.
            jaxRs = new JaxRsResources(context, rolePrefix);
            // Jersey answers HEAD with a GET resource method (AbstractMethodSelectingRouter#createHeadEnrichedRouter).
            mappings.addAll(headServed(jaxRs.detect()));
            // Decision 0044: message listeners.
            MessageListeners listeners = new MessageListeners(context);
            mappings.addAll(listeners.detect());
            listeners.findings().forEach(graph::finding);
            // Decision 0050: plain WebSocket handlers (and WebFlux's), behind their handshake.
            WebSocketHandlers webSockets = new WebSocketHandlers(context);
            mappings.addAll(webSockets.detect());
            webSockets.findings().forEach(graph::finding);
            handshakes.putAll(webSockets.ways());
            // Decision 0046: scheduled tasks.
            mappings.addAll(new ScheduledTasks(context).detect());
            // Decision 0047: Spring Cloud Stream functions, and where their results go.
            for (StreamFunctions.Binding binding : new StreamFunctions(context).detect()) {
                mappings.add(binding.mapping());
                streamBindings.put(StreamFunctions.Binding.key(binding.mapping()), binding);
            }
            // Decision 0040: repositories Spring Data REST exports, and the event handlers their requests run.
            dataRest = new DataRestRepositories(context);
            mappings.addAll(dataRest.detect());
            dataRest.findings().forEach(graph::finding);
            // Decision 0041: Actuator's exposed endpoints.
            ActuatorEndpoints actuator = new ActuatorEndpoints(context);
            mappings.addAll(headServed(actuator.detect()));
            // Decision 0061: the library endpoints that must not answer anyone.
            sensitive = new SensitiveEndpoints(context, actuator);
            graphQl = new GraphQlMappings(context);
            operations = graphQl.detect(beans);
            // Over HTTP, GraphQL is a router function of the DispatcherServlet's.
            operations.forEach(operation -> dispatched.add(operation.handler().getSignature()));
            mappings.addAll(operations);
            mappings.addAll(rpcs);
            // Decision 0039: STOMP messages and subscriptions, after their WebSocket handshake.
            stomp = new StompMappings(context, genericTypes, xml.stomp());
            mappings.addAll(stomp.detect(beans));
            if (stomp.handshakes().size() > 1) {
                handshakes.put(stomp.handshakes().getFirst().id(), stomp.handshakes());
            }
            // Decision 0045: RSocket routes, after their connection's setup.
            mappings.addAll(new RSocketMappings(context).detect(beans));
            return mappings;
        }

        private List<RequestMappings.Mapping> headServed(List<RequestMappings.Mapping> mappings) {
            mappings.forEach(mapping -> headServed.add(mapping.handler()));
            return mappings;
        }

        /**
         * Decision 0110: a GET mapping's handler also answers HEAD (7.0.9 {@code RequestMethodsRequestCondition}, a
         * servlet's {@code doHead}, Jersey), without the body, while a rule for GET doesn't match HEAD (7.1.1
         * {@code PathPatternRequestMatcher} compares the method exactly). Where the rules ask HEAD for something other
         * than GET, GET doesn't let everyone in already and HEAD isn't denied, HEAD is a way to the handler of its own: an Ingress, and
         * a BYPASSED finding. A mapping of its own for HEAD takes HEAD's requests instead.
         */
        @Supports({Feature.HTTP_ENDPOINTS, Feature.REQUEST_RULES, Feature.FINDING_BYPASSED})
        private List<RequestMappings.Mapping> withHead(List<RequestMappings.Mapping> mappings) {
            Set<String> ownHead = new HashSet<>();
            mappings.stream().filter(mapping -> mapping.ingress().httpMethod().equals("HEAD"))
                    .forEach(mapping -> ownHead.add(mapping.ingress().route() + "?" + mapping.ingress().params()));
            List<RequestMappings.Mapping> result = new ArrayList<>();
            for (RequestMappings.Mapping mapping : mappings) {
                result.add(mapping);
                Ingress get = mapping.ingress();
                if (!get.httpMethod().equals("GET") || !headServed.contains(mapping.handler())
                        || ownHead.contains(get.route() + "?" + get.params())) {
                    continue;
                }
                Ingress head = new Ingress("ingress:HEAD " + get.id().substring("ingress:GET ".length()), "HEAD",
                        get.route(), get.handler(), null, get.params(), null);
                Requirement onGet = httpRules.quietly(() -> combined(requestChecks(context, graph, httpRules, get)));
                Requirement onHead = httpRules.quietly(() -> combined(requestChecks(context, graph, httpRules,
                        head)));
                if (onGet.permitsAnyone() || onHead.kind() == Requirement.Kind.DENY_ALL || onHead.equals(onGet)) {
                    continue;
                }
                result.add(mapping.withIngress(head));
                graph.finding(new Finding(Finding.Kind.BYPASSED, "HEAD " + get.route() + " runs the handler of "
                        + get.endpoint() + " (Spring answers HEAD with a GET mapping, without the body), and the"
                        + " request rules ask it for " + describe(onHead) + " where GET needs " + describe(onGet)
                        + ": a rule for GET doesn't match HEAD", get.handler()));
            }
            return result;
        }

        private static String describe(Requirement requirement) {
            return switch (requirement.kind()) {
                case AND, OR -> "(" + String.join(requirement.kind() == Requirement.Kind.AND ? " and " : " or ",
                        requirement.operands().stream().map(Scan::describe).toList()) + ")";
                case NOT -> "not " + describe(requirement.operands().getFirst());
                default -> HttpSecurityRules.describe(requirement);
            };
        }

        /**
         * One entry point's path: the rules it passes, then what its handler (and what runs with it) reaches, then
         * the checks serializing its response runs.
         */
        @Supports({Feature.RESPONSE_FIELDS, Feature.FIELD_CHECKS, Feature.VIEW_FIELDS, Feature.FIELD_LINEAGE,
                Feature.MESSAGE_SENDS})
        private void walk(RequestMappings.Mapping mapping, EntryRules entryRules) {
            // Decision 0035: a handler that renders a view responds with what the view shows.
            // Decision 0110: a HEAD response has no body.
            boolean head = mapping.ingress().httpMethod().equals("HEAD");
            Optional<ViewModels.View> view = mapping.functional() || mapping.transport() != null || head
                    ? Optional.empty() : viewModels.of(mapping.handler(), mapping.receiver());
            Optional<Payload> response = view.isPresent() ? Optional.of(new Payload(view.get().owner(), false))
                    : mapping.functional() || head ? Optional.ofNullable(mapping.ingress().response())
                            : Payloads.returnedBy(context, mapping.handler().getSignature())
                                    .map(payload -> payload.withViews(jsonViews(context, mapping.handler())));
            Ingress ingress = graph.node(mapping.ingress().withResponse(response.orElse(null)));
            sensitive.note(ingress, mapping.handler());
            payloads.received(ingress);
            List<String> viewChecks = view.map(found -> viewFields.expose(ingress.id(), found)).orElse(List.of());
            if (view.isEmpty()) {
                response.ifPresent(payload -> responseFields.expose(ingress.id(), payload.type(),
                        valueFlow.returnShape(mapping.handler())));
            }
            if (view.isEmpty() && !mapping.functional()) {
                Payloads.unread(context, mapping.handler().getSignature()).ifPresent(type -> graph.finding(
                        new Finding(Finding.Kind.OPAQUE_CONFIG, "On " + ingress.endpoint() + ": the response is a "
                                + type + ", a library type AuthTracer doesn't know how Jackson writes: the fields of"
                                + " the application's types in it aren't in the graph",
                                MethodNames.codeRef(mapping.handler().getSignature()))));
            }
            List<CallTraversal.Step> steps = new ArrayList<>(entryRules.checks(mapping, ingress));
            // A listener's or task's path is walked on its own, to see whether it sets the SecurityContext its checks
            // need.
            boolean listener = NoCaller.applies(ingress);
            Set<JavaSootMethod> walked = listener ? new LinkedHashSet<>() : reachable;
            // Decision 0070: the request's filters run around its filter chain's rule, its interceptors around the
            // handler. A WebSocket handshake's run for the handshake, which has its caller.
            RequestFilters.Around around = filters(mapping, ingress);
            List<CallTraversal.Step> unwinding = aroundRule(steps, around, ingress, reachable);
            Optional.ofNullable(jaxRs.jerseyChecks().get(mapping.handler())).ifPresent(check -> steps.add(
                    CallTraversal.Step.unconditional(graph.node(check).id())));
            DataRestRepositories.EventHandlers events = dataRest.eventHandlers().get(mapping.ingress().id());
            for (JavaSootMethod before : events == null ? List.<JavaSootMethod>of() : events.before()) {
                steps.addAll(walkFrom(before, ingress, walked));
            }
            List<CallTraversal.Step> preHandle = passed(around.beforeHandler(), "Interceptor", ingress, reachable)
                    .steps();
            List<CallTraversal.Step> postHandle = passed(around.afterHandler(), "Interceptor", ingress, reachable)
                    .steps();
            // What the handshake's request reaches has its caller.
            Set<String> handshake = new HashSet<>();
            Stream.of(steps, preHandle, postHandle, unwinding).flatMap(List::stream)
                    .forEach(step -> handshake.add(step.nodeId()));
            steps.addAll(preHandle);
            // A functional route's filters run inside the handler adapter, after the interceptors.
            for (JavaSootMethod filter : mapping.filters()) {
                steps.addAll(walkFrom(filter, ingress, walked));
            }
            steps.addAll(walkFrom(mapping.handler(), mapping.receiver(), ingress, walked));
            steps.addAll(postHandle);
            for (JavaSootMethod after : events == null ? List.<JavaSootMethod>of() : events.after()) {
                steps.addAll(walkFrom(after, ingress, walked));
            }
            Optional.ofNullable(streamBindings.get(StreamFunctions.Binding.key(mapping))).ifPresent(binding -> {
                // A composition's other functions run after the first, then the result goes out.
                for (JavaSootMethod next : binding.composed()) {
                    steps.addAll(walkFrom(next, ingress, walked));
                }
                JavaSootMethod last = binding.composed().isEmpty() ? mapping.handler()
                        : binding.composed().getLast();
                for (Egress output : binding.outputs()) {
                    Egress node = graph.node(output);
                    // Decision 0098: what the last function returns is what goes out.
                    payloads.returned(node, last);
                    steps.add(CallTraversal.Step.unconditional(node.id()));
                }
            });
            if (listener) {
                reachable.addAll(walked);
                NoCaller.mark(graph, ingress, steps, walked, handshake);
            }
            // Decision 0048: what fails on an @Async thread doesn't deny the caller.
            steps.replaceAll(step -> NoCaller.isOffThread(step.nodeId()) && !step.conditional()
                    ? new CallTraversal.Step(step.nodeId(), step.via(), true) : step);
            // Decision 0014: proxies the handler returns are serialized, which calls their checked getters.
            Set<String> onPath = new HashSet<>(steps.stream().map(CallTraversal.Step::nodeId).toList());
            ProxyFactories.Factory returned = response.isPresent()
                    ? proxies.frame(mapping.handler(), Map.of()).returned() : null;
            List<String> serialized = returned != null ? serialized(context, methodSecurity, response.get().type(),
                    returned, new HashSet<>()) : List.of();
            deniedValues(ingress, onPath, serialized);
            serialized.stream().filter(onPath::add).forEach(id -> steps.add(CallTraversal.Step.unconditional(id)));
            // The view renders after the handler returns.
            viewChecks.forEach(id -> steps.add(CallTraversal.Step.unconditional(id)));
            // Then the filters' code after chain.doFilter(..), as the request unwinds through them.
            unwinding.forEach(step -> steps.add(NoCaller.isOffThread(step.nodeId()) ? maybe(step) : step));
            tail(ingress, distinct(decisionCalls(steps)));
        }

        /**
         * Decision 0065: what the code that decides a check calls on another service (a remote authorization manager,
         * OPA) is an Egress on the path, right after the check.
         */
        @Supports({Feature.CUSTOM_DECISIONS, Feature.SERVICE_CALLS})
        private List<CallTraversal.Step> decisionCalls(List<CallTraversal.Step> steps) {
            List<CallTraversal.Step> withCalls = new ArrayList<>();
            for (CallTraversal.Step step : steps) {
                withCalls.add(step);
                if (!(graph.find(step.nodeId()).orElse(null) instanceof AuthorizationLocation location)) {
                    continue;
                }
                for (JavaSootMethod decider : decisionCode.deciders(location.requirement())) {
                    for (Stmt stmt : decider.getBody().getStmts()) {
                        Locals.invoke(stmt).flatMap(invoke -> egress.detect(decider, stmt, invoke))
                                .map(found -> graph.node(found.withCallSite(enclosing.site(decider, found.callSite()))))
                                .ifPresent(found -> withCalls.add(new CallTraversal.Step(found.id(), step.via(),
                                        step.conditional())));
                    }
                }
            }
            return withCalls;
        }

        /**
         * DENY-02 (decision 0076): a field check whose denial handler derives what it returns from the value it
         * denied hands the denied callers part of it. Where the response is serialized, that value is written in the
         * field's place; where the code reads the getter, it flows on into what the code builds, which the graph
         * doesn't follow.
         *
         * @param read the checks the walk reached, the getters the code called
         * @param serialized the checks serializing the response runs
         */
        @Supports({Feature.FIELD_CHECKS, Feature.FINDING_OPAQUE_CALLPATH})
        private void deniedValues(Ingress ingress, Set<String> read, List<String> serialized) {
            for (String id : serialized) {
                derivingCheck(id).ifPresent(check -> responseFields.denied(ingress.id(), check.guardedField()));
            }
            read.stream().filter(id -> !serialized.contains(id)).sorted().map(this::derivingCheck)
                    .flatMap(Optional::stream).forEach(check -> graph.finding(new Finding(
                            Finding.Kind.OPAQUE_CALLPATH, "On " + ingress.endpoint() + ": when " + check.mechanism()
                                    + " on " + check.target().key() + " denies, "
                                    + MethodNames.simpleName(check.denial().handler()) + " returns a value it derives"
                                    + " from " + Field.shortName(check.guardedField()) + "; the fields the code builds"
                                    + " from it show " + Field.shortName(check.guardedField()) + "'s checks, though a"
                                    + " denied caller gets that value in them", check.target())));
        }

        @Supports(Feature.FIELD_CHECKS)
        private Optional<AuthorizationLocation> derivingCheck(String id) {
            return graph.find(id).filter(AuthorizationLocation.class::isInstance)
                    .map(AuthorizationLocation.class::cast)
                    .filter(location -> location.scope() == AuthorizationLocation.Scope.FIELD)
                    .filter(location -> methodSecurity.denialHandler(location)
                            .filter(handler -> valueFlow.derivesFrom(handler, 0)).isPresent());
        }

        /**
         * The filters and interceptors of an entry point that comes in as an HTTP request (or over one's connection):
         * none for a message, a task or a gRPC call on its own server.
         */
        private RequestFilters.Around filters(RequestMappings.Mapping mapping, Ingress ingress) {
            Ingress request = mapping.transport() != null ? mapping.transport() : ingress;
            // A WebSocket handshake is a request with a caller, whatever its messages have.
            boolean http = (mapping.transport() != null || !NoCaller.applies(ingress)) && !GrpcServices.isGrpc(request)
                    && (mapping.transport() != null || !StompMappings.isMessage(ingress)
                            && !RSocketMappings.isRSocket(ingress));
            // Only the MappedInterceptor beans run for a servlet WebSocket handshake, whose handler mapping
            // WebSocketConfigurationSupport makes; gRPC's servlet is mapped on the whole path.
            return http ? filters.around(request, httpRules.chainsFor(request),
                    dispatched.contains(mapping.handler().getSignature()),
                    WebSocketHandlers.isWebSocket(ingress) && !reactive, GrpcServices.isGrpc(ingress))
                    : RequestFilters.Around.NONE;
        }

        /**
         * The filters before the filter chain's rule (after the Provided requirements) and those after it; returns what
         * they do after {@code chain.doFilter(..)}, last filter first, which runs once the handler has returned.
         */
        private List<CallTraversal.Step> aroundRule(List<CallTraversal.Step> steps, RequestFilters.Around around,
                Ingress ingress, Set<JavaSootMethod> walked) {
            int rule = 0;
            while (rule < steps.size() && !(graph.find(steps.get(rule).nodeId()).orElse(null)
                    instanceof AuthorizationLocation location && location.scope()
                            == AuthorizationLocation.Scope.HTTP_REQUEST && !location.mechanism().startsWith("Provided"))) {
                rule++;
            }
            Passed before = passed(around.beforeRule(), "Filter", ingress, walked);
            Passed after = passed(around.afterRule(), "Filter", ingress, walked);
            steps.addAll(rule < steps.size() ? rule + 1 : rule, after.steps());
            steps.addAll(rule, before.steps());
            List<CallTraversal.Step> unwound = new ArrayList<>(after.unwinding());
            unwound.addAll(before.unwinding());
            return unwound;
        }

        /**
         * What a request's filters or interceptors reach: in order, and what the filters do after
         * {@code chain.doFilter(..)}, last filter first.
         */
        private record Passed(List<CallTraversal.Step> steps, List<CallTraversal.Step> unwinding) {
        }

        /**
         * What the filters or interceptors reach, in order; one AuthTracer can't resolve is an Opaque step.
         *
         * @param what {@code Filter} or {@code Interceptor}
         */
        @Supports(Feature.FINDING_OPAQUE_CALLPATH)
        private Passed passed(List<RequestFilters.Pass> passes, String what, Ingress ingress,
                Set<JavaSootMethod> walked) {
            List<CallTraversal.Step> steps = new ArrayList<>();
            List<CallTraversal.Step> unwinding = new ArrayList<>();
            for (RequestFilters.Pass pass : passes) {
                if (pass.code() == null) {
                    Opaque opaque = graph.node(Opaque.of(what + " AuthTracer can't resolve (" + pass.unresolved()
                            + ")", pass.site()));
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CALLPATH, "On " + ingress.endpoint() + ": the"
                            + " request passes " + pass.unresolved() + ", registered in " + pass.site().key()
                            + "; what it does is not in the graph", pass.site()));
                    steps.add(new CallTraversal.Step(opaque.id(), List.of(), pass.conditional()));
                    continue;
                }
                List<CallTraversal.Step> later = new ArrayList<>();
                for (JavaSootMethod method : pass.code().methods()) {
                    FilterChainCalls.Split split = FilterChainCalls.walk(traversal, method, pass.code().receiver(),
                            new RequestPath(ingress, methodSecurity, proxies, egress, graph, walked, async, enclosing,
                                    payloads, programmatic));
                    split.before().forEach(step -> steps.add(pass.conditional() ? maybe(step) : step));
                    split.after().forEach(step -> later.add(pass.conditional() ? maybe(step) : step));
                }
                unwinding.addAll(0, later);
            }
            return new Passed(steps, unwinding);
        }

        private static CallTraversal.Step maybe(CallTraversal.Step step) {
            return new CallTraversal.Step(step.nodeId(), step.via(), true);
        }

        private List<CallTraversal.Step> walkFrom(JavaSootMethod method, Ingress ingress, Set<JavaSootMethod> walked) {
            return walkFrom(method, null, ingress, walked);
        }

        /**
         * @param receiver the controller that inherits the handler, {@code null} for the handler's own class
         */
        private List<CallTraversal.Step> walkFrom(JavaSootMethod method, ClassType receiver, Ingress ingress,
                Set<JavaSootMethod> walked) {
            return traversal.walk(method.getSignature(), receiver,
                    new RequestPath(ingress, methodSecurity, proxies, egress, graph, walked, async, enclosing,
                            payloads, programmatic));
        }

        /**
         * The Ingress's path, from it through the steps.
         */
        private void tail(Ingress ingress, List<CallTraversal.Step> steps) {
            tails.put(ingress.id(), PathTail.start(ingress.id()).append(graph, ingress.id(), steps));
        }

        /**
         * Decision 0043: a gateway route's Ingress forwards to its uri, after the gateway's own rules.
         */
        @Supports(Feature.GATEWAY_ROUTES)
        private void gatewayRoutes() {
            for (GatewayRoutes.Forward forward : new GatewayRoutes(context).detect()) {
                Ingress route = graph.node(forward.ingress());
                Egress forwarded = graph.node(forward.egress());
                List<CallTraversal.Step> steps = new ArrayList<>(steps(requestChecks(context, graph, httpRules,
                        route)));
                steps.add(CallTraversal.Step.unconditional(forwarded.id()));
                tail(route, steps);
            }
        }

        /**
         * Decisions 0053, 0054, 0057, 0060: endpoints libraries serve (the H2 console, springdoc's API docs, a Eureka
         * server, GraphiQL), checked by the filter chain alone; decision 0059: the gRPC services Spring Boot adds,
         * checked by the gRPC rules, or, through the servlet container, the HTTP ones.
         */
        @Supports(Feature.LIBRARY_ENDPOINTS)
        private void libraryEndpoints() {
            List<Ingress> library = new ArrayList<>(servlets.library());
            library.addAll(new EurekaServerEndpoints(context).library());
            // Served by the DispatcherServlet's handler mappings, so its interceptors run too.
            List<Ingress> dispatchedLibrary = new ArrayList<>(new ApiDocsEndpoints(context).library(reactive));
            dispatchedLibrary.addAll(new GraphQlTools(context).library(!operations.isEmpty()));
            library.addAll(dispatchedLibrary);
            for (Map.Entry<Ingress, Ingress> service : grpc.library(!rpcs.isEmpty())) {
                Ingress served = graph.node(service.getKey());
                if (GrpcServices.isGrpc(service.getValue())) {
                    tail(served, steps(grpcRules.locationsFor(served, null)));
                    continue;
                }
                // Through the servlet container: the HTTP request's filters, on gRPC's own servlet.
                tail(served, withFilters(requestChecks(context, graph, httpRules, service.getValue()), served,
                        filters.around(service.getValue(), httpRules.chainsFor(service.getValue()), false, false,
                                true)));
            }
            for (Ingress served : library) {
                Ingress console = graph.node(served);
                sensitive.note(console, null);
                tail(console, withFilters(requestChecks(context, graph, httpRules, console), console, filters.around(
                        console, httpRules.chainsFor(console), dispatchedLibrary.contains(served), false, false)));
            }
        }

        /**
         * A library endpoint's checks with the request's filters around its rule, and its interceptors after.
         */
        @Supports(Feature.LIBRARY_ENDPOINTS)
        private List<CallTraversal.Step> withFilters(List<AuthorizationLocation> checks, Ingress ingress,
                RequestFilters.Around around) {
            List<CallTraversal.Step> steps = new ArrayList<>(steps(checks));
            List<CallTraversal.Step> unwinding = aroundRule(steps, around, ingress, reachable);
            steps.addAll(passed(around.beforeHandler(), "Interceptor", ingress, reachable).steps());
            steps.addAll(passed(around.afterHandler(), "Interceptor", ingress, reachable).steps());
            steps.addAll(unwinding);
            return steps;
        }

        /**
         * Decision 0049: the endpoints of an authorization server the application is, each behind its check, and a
         * resource server's metadata.
         */
        @Supports({Feature.LIBRARY_ENDPOINTS, Feature.FINDING_TOKEN_REJECTED})
        private void authorizationServers() {
            List<AuthorizationServerEndpoints.Endpoint> endpoints = new AuthorizationServerEndpoints(context).detect();
            for (AuthorizationServerEndpoints.Endpoint endpoint : endpoints) {
                Ingress served = graph.node(endpoint.ingress());
                tail(served, List.of(CallTraversal.Step.unconditional(graph.node(endpoint.check()).id())));
            }
            // Decision 0075 (SRC-19): the clients it issues tokens to, and the scopes each can be granted.
            if (!endpoints.isEmpty()) {
                graph.issuer(RegisteredClients.read(context));
            }
            // OAUTH-07: a resource server's metadata, which answers before authorization.
            boolean bootAuthorizationServer = !endpoints.isEmpty() && SpringBeans.beanMethodsOf(context,
                    Set.of(WebStack.SECURITY_FILTER_CHAIN)).isEmpty();
            new ResourceServerMetadata(context).detect(httpRules, bootAuthorizationServer).ifPresent(metadata ->
                    tail(graph.node(metadata.ingress()), List.of(CallTraversal.Step.unconditional(
                            graph.node(metadata.check()).id()))));
        }

        /**
         * Decision 0039: what a message handler sends to a topic, everyone subscribed to it receives. Each sender
         * exposes what it sends; the subscription is checked once, by its @SubscribeMapping's path if it has one.
         */
        @Supports({Feature.WEBSOCKET_MESSAGES, Feature.RESPONSE_FIELDS})
        private void stompBroadcasts(MessageSecurityRules messageRules) {
            for (StompMappings.Broadcast broadcast : stomp.broadcasts()) {
                Ingress subscribe = graph.node(broadcast.subscribe());
                if (!subscribe.responses().contains(broadcast.subscribe().response())) {
                    // Another handler sends its own type to the topic: its subscribers get that too.
                    subscribe = graph.replace(subscribe.withOtherResponse(broadcast.subscribe().response()));
                }
                responseFields.expose(subscribe.id(), broadcast.subscribe().response().type(),
                        broadcast.payload() == null ? valueFlow.returnShape(broadcast.handler())
                                : valueFlow.argumentShape(broadcast.handler(), broadcast.payload()));
                if (!tails.containsKey(subscribe.id())) {
                    tail(subscribe, messageChecks(context, graph, httpRules, messageRules, subscribe,
                            ways(handshakes, broadcast.transport())));
                }
            }
        }

        /**
         * Decision 0030: the field resolvers of non-root GraphQL types, each walked once.
         */
        @Supports(Feature.GRAPHQL_OPERATIONS)
        private Map<GraphQlMappings.Resolver, List<CallTraversal.Step>> graphQlResolvers() {
            Map<GraphQlMappings.Resolver, List<CallTraversal.Step>> resolvers = new LinkedHashMap<>();
            for (GraphQlMappings.Resolver resolver : graphQl.resolvers(beans)) {
                Ingress field = Ingress.of("FIELD", resolver.graphQlType() + "." + resolver.field(),
                        MethodNames.codeRef(resolver.method().getSignature()));
                resolvers.put(resolver, walkFrom(resolver.method(), field, reachable));
            }
            return resolvers;
        }

        /**
         * Each check's requirement as the RoleHierarchy and AuthorizationManagerFactory of its kind expand it.
         * Provided requirements and checks are enforced outside Spring Security, so the hierarchy doesn't widen them;
         * a Split takes its parts' policies: it is rebuilt from them once they are expanded.
         */
        @Supports(Feature.REQUIREMENTS)
        private void hierarchiesAndFactories() {
            for (AuthorizationLocation location : List.copyOf(graph.nodes()).stream()
                    .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                    .filter(location -> !graph.splits().containsKey(location.id())).toList()) {
                // Message rules are AuthorityAuthorizationManager's: no hierarchy (decision 0039); RSocket rules are
                // AuthorityReactiveAuthorizationManager's (decision 0045).
                // Jersey asks the request wrapper's isUserInRole, which compares the role as written: no hierarchy
                // (7.1.1 SecurityContextHolderAwareRequestWrapper#isGranted).
                if (!location.mechanism().startsWith("Provided") && httpRules.hierarchyAware(location)
                        && methodSecurity.hierarchyAware(location) && programmatic.hierarchyAware(location)
                        && !location.mechanism().equals(JaxRsResources.MECHANISM)
                        && !location.mechanism().startsWith(MessageSecurityRules.MECHANISM)
                        && !location.mechanism().startsWith(RSocketSecurityRules.MECHANISM)) {
                    boolean request = location.scope() == AuthorizationLocation.Scope.HTTP_REQUEST;
                    RoleHierarchies applies = request ? http.hierarchy() : PRE_POST.contains(location.mechanism())
                            ? prePost.hierarchy() : hierarchy;
                    Requirement expanded = applies.expand(location.requirement());
                    // Decision 0037: the factory's additional factors, on the rules it builds: the
                    // authorizeHttpRequests DSL's (also the default chains') and the pre/post built-ins, Servlet only
                    // in 7.1.1.
                    boolean dsl = location.mechanism().equals("authorizeHttpRequests")
                            || location.mechanism().endsWith("default SecurityFilterChain");
                    AuthorizationManagerFactories.Factory builtBy = reactive ? null : request ? dsl ? http : null
                            : PRE_POST.contains(location.mechanism()) ? prePost : null;
                    graph.replace(location.withRequirement(builtBy == null ? expanded : builtBy.build(expanded)));
                }
            }
        }

        /**
         * Decision 0038: without a PermissionEvaluator, pre/post hasPermission(..) denies everyone.
         */
        @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_ALWAYS_GRANTED, Feature.CUSTOM_DECISIONS})
        private void hasPermission() {
            if (!methodSecurity.permissionsDenied()) {
                // Decision 0065: each hasPermission(..) as the evaluator's method decides it.
                methodSecurity.permissionEvaluator().ifPresent(evaluator -> graph.nodes().stream()
                        .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                        .filter(location -> PRE_POST.contains(location.mechanism())
                                && PermissionEvaluators.mentionsHasPermission(location.requirement()))
                        .toList().forEach(location -> graph.replace(location.withRequirement(PermissionEvaluators
                                .decided(location.requirement(), evaluator, decisionCode)))));
                return;
            }
            for (AuthorizationLocation location : List.copyOf(graph.nodes()).stream()
                    .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                    .filter(location -> PRE_POST.contains(location.mechanism())
                            && PermissionEvaluators.mentionsHasPermission(location.requirement()))
                    .toList()) {
                Requirement denied = PermissionEvaluators.denied(location.requirement());
                graph.replace(location.withRequirement(denied));
                // Decision 0092: a negated hasPermission(..) is true for everyone.
                graph.finding(new Finding(denied.permitsAnyone() ? Finding.Kind.ALWAYS_GRANTED
                        : Finding.Kind.ALWAYS_DENIED, location.mechanism() + " on " + location.target().className()
                        + "#" + location.target().method() + " uses hasPermission(..), but no PermissionEvaluator"
                        + " reaches method security, so Spring's DenyAllPermissionEvaluator denies it"
                        + (denied.permitsAnyone() ? ", and the check, which asks for its negation, admits everyone"
                                : "") + ": @EnableMethodSecurity doesn't use a PermissionEvaluator bean, a"
                        + " MethodSecurityExpressionHandler bean that is given one does", location.target()));
            }
        }

        /**
         * Hand-rolled checks matter where requests can reach them; a reviewed one is declared as a Provided check.
         */
        @Supports({Feature.FINDING_UNRECOGNIZED_CHECK, Feature.FINDING_AUTHORITIES_IN_CODE})
        private void handRolledChecks() {
            // Decision 0066: what a method reads of the caller to check with a manager is that check.
            new HandRolledChecks(context).detect(reachable.stream()
                    .filter(method -> context.input().facts().about(ProvidedFact.Kind.CHECK,
                            MethodNames.key(method.getSignature())).isEmpty())
                    .filter(method -> !programmatic.checks(method)).toList())
                    .forEach(graph::finding);
            // SRC-10: authorities set in code outside the filters that are ways in.
            FilterAuthentication.inCode(context, reachable).forEach(graph::finding);
        }
    }

    /**
     * Other ports the service listens on: Actuator's {@code management.server.port}, the RSocket server's
     * {@code spring.rsocket.server.port} (decision 0045), and {@code connector.setPort(8090)} on a Tomcat
     * {@code Connector} the code adds (as the Spring Authorization Server messages-resource sample does, next to its TLS
     * port).
     */
    @Supports(Feature.SYSTEM_GRAPH)
    private static void additionalPorts(ScanContext context, GraphBuilder graph) {
        RSocketMappings rsocket = new RSocketMappings(context);
        if (rsocket.server()) {
            rsocket.port().ifPresent(graph::additionalPort);
        }
        // Actuator on its own port.
        context.properties().get("management.server.port").map(String::trim).filter(port -> port.matches("\\d+"))
                .filter(port -> !port.equals(context.properties().get("server.port").map(String::trim).orElse("8080")))
                .ifPresent(port -> graph.additionalPort(Integer.parseInt(port)));
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature().getName().equals("setPort")
                            && invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                    .equals("org.apache.catalina.connector.Connector")
                            && invoke.getArgCount() == 1 && invoke.getArg(0) instanceof IntConstant)
                            .ifPresent(invoke -> graph.additionalPort(((IntConstant) invoke.getArg(0)).getValue()));
                }
            }
        }
    }

    /**
     * A handler's {@code @JsonView}, with the views it extends: Jackson writes only the fields in one of them.
     */
    @Supports(Feature.RESPONSE_FIELDS)
    private static List<String> jsonViews(ScanContext context, JavaSootMethod handler) {
        List<String> views = new ArrayList<>();
        context.findAnnotation(handler, JSON_VIEW).ifPresent(annotation -> Annotations.strings(annotation, "value")
                .forEach(view -> {
                    views.add(view);
                    ClassType type = context.type(view);
                    context.superClassesOf(type).forEach(superclass -> views.add(superclass.getFullyQualifiedName()));
                    context.interfacesOf(type).forEach(extended -> views.add(extended.getFullyQualifiedName()));
                }));
        return views;
    }

    /**
     * The rules an entry point passes before its handler runs, by its kind.
     */
    @Supports(Feature.REQUEST_RULES)
    private record EntryRules(ScanContext context, GraphBuilder graph, HttpSecurityRules http,
            GrpcSecurityRules grpc, MessageSecurityRules messages, RSocketSecurityRules rsocket,
            Optional<AuthorizationLocation> webSocketAuthentication, List<Ingress> soapTransports,
            Map<String, List<Ingress>> handshakes) {

        List<CallTraversal.Step> checks(RequestMappings.Mapping mapping, Ingress ingress) {
            // Requirements enforced outside the code (Provided facts) come first, then the filter chain; a gRPC call
            // passes Spring gRPC's interceptors instead.
            Ingress request = mapping.transport() != null ? mapping.transport() : ingress;
            if (GrpcServices.isGrpc(request)) {
                return steps(context.findClass(mapping.handler().getDeclaringClassType())
                        .map(service -> grpc.locationsFor(request, service)).orElse(List.of()));
            }
            if (mapping.webSocket() != null) {
                List<AuthorizationLocation> overWebSocket = new ArrayList<>(requestChecks(context, graph, http,
                        mapping.webSocket()));
                webSocketAuthentication.ifPresent(overWebSocket::add);
                return alternatives(graph, ingress, "graphql-transports", "Transports", "HTTP or WebSocket",
                        List.of(requestChecks(context, graph, http, request), overWebSocket));
            }
            if (SoapEndpoints.isSoap(ingress) && soapTransports.size() > 1) {
                return alternatives(graph, ingress, "soap-paths", "Paths", "any dispatcher servlet path",
                        soapTransports.stream().map(path -> requestChecks(context, graph, http, path)).toList());
            }
            if (StompMappings.isMessage(ingress)) {
                return messageChecks(context, graph, http, messages, ingress, ways(handshakes,
                        mapping.transport()));
            }
            if (RSocketMappings.isRSocket(ingress)) {
                // Decision 0045: the WebSocket handshake's rules, if over one, then the setup's and the route's.
                List<AuthorizationLocation> checks = new ArrayList<>(mapping.transport() == null ? List.of()
                        : requestChecks(context, graph, http, mapping.transport()));
                checks.addAll(rsocket.locationsFor(ingress));
                return steps(checks);
            }
            if (WebSocketHandlers.isWebSocket(ingress)) {
                return handshakeChecks(context, graph, http, ingress, ways(handshakes, mapping.transport()));
            }
            // A broker delivers it, or a scheduler runs it: no caller, no request rule.
            return NoCaller.applies(ingress) ? List.of() : steps(requestChecks(context, graph, http, request));
        }
    }

    /**
     * As {@link CallTraversal} records a walk's: a node reached twice (a filter Boot registers and a chain adds) keeps
     * its first place, and is unconditional when any way to it is.
     */
    private static List<CallTraversal.Step> distinct(List<CallTraversal.Step> steps) {
        Map<String, CallTraversal.Step> kept = new LinkedHashMap<>();
        for (CallTraversal.Step step : steps) {
            kept.merge(step.nodeId(), step, (first, again) -> first.conditional() && !again.conditional()
                    ? new CallTraversal.Step(first.nodeId(), first.via(), false) : first);
        }
        return List.copyOf(kept.values());
    }

    private static List<CallTraversal.Step> steps(List<AuthorizationLocation> locations) {
        return locations.stream().map(location -> CallTraversal.Step.unconditional(location.id())).toList();
    }

    /**
     * A STOMP message's checks: its WebSocket handshake's HTTP rule, then the message rule.
     */
    @Supports({Feature.WEBSOCKET_MESSAGES, Feature.REQUEST_RULES})
    private static List<CallTraversal.Step> messageChecks(ScanContext context, GraphBuilder graph,
            HttpSecurityRules httpRules, MessageSecurityRules messageRules, Ingress message, List<Ingress> handshakes) {
        List<CallTraversal.Step> checks = new ArrayList<>(handshakeChecks(context, graph, httpRules, message,
                handshakes));
        checks.addAll(steps(messageRules.locationsFor(message)));
        return checks;
    }

    /**
     * The handshakes a transport stands for: those recorded for it, else itself (none without one).
     */
    private static List<Ingress> ways(Map<String, List<Ingress>> handshakes, Ingress transport) {
        return transport == null ? List.of() : handshakes.getOrDefault(transport.id(), List.of(transport));
    }

    /**
     * Decision 0113: the HTTP rules of a WebSocket session's way in: its handshake's, or, where it may arrive in
     * several (each STOMP endpoint, SockJS's transports), a Split asking for any one's (decision 0034).
     */
    @Supports({Feature.WEBSOCKET_MESSAGES, Feature.REQUEST_RULES})
    private static List<CallTraversal.Step> handshakeChecks(ScanContext context, GraphBuilder graph,
            HttpSecurityRules httpRules, Ingress operation, List<Ingress> handshakes) {
        if (handshakes.size() < 2) {
            return handshakes.isEmpty() ? List.of()
                    : steps(requestChecks(context, graph, httpRules, handshakes.getFirst()));
        }
        return alternatives(graph, operation, "handshakes", "Handshakes", "any of its WebSocket handshakes",
                handshakes.stream().map(handshake -> requestChecks(context, graph, httpRules, handshake)).toList());
    }

    /**
     * The request-level checks on an HTTP request: Provided requirements, then the filter chain's rule.
     */
    @Supports({Feature.REQUEST_RULES, Feature.PROVIDED_FACTS})
    private static List<AuthorizationLocation> requestChecks(ScanContext context, GraphBuilder graph,
            HttpSecurityRules httpRules, Ingress request) {
        List<AuthorizationLocation> checks = new ArrayList<>();
        providedRequirements(context, graph, request).forEach(id -> graph.find(id)
                .map(AuthorizationLocation.class::cast).ifPresent(checks::add));
        httpRules.locationFor(request).ifPresent(checks::add);
        return checks;
    }

    /**
     * Decision 0034: an operation that arrives in more than one way (over HTTP or over WebSocket; Decision 0056: at
     * each of the SOAP dispatcher's paths) is as open as the weakest way in. When they all ask for the same, the
     * first way's checks stand as they are; otherwise each way's checks run on that way only (conditional), and a
     * Split location asks for any way's.
     */
    @Supports({Feature.GRAPHQL_OPERATIONS, Feature.HTTP_ENDPOINTS, Feature.REQUEST_RULES})
    private static List<CallTraversal.Step> alternatives(GraphBuilder graph, Ingress operation, String kind,
            String name, String ways, List<List<AuthorizationLocation>> checks) {
        List<Requirement> required = checks.stream().map(SpringSecurityModule::combined).distinct().toList();
        List<CallTraversal.Step> steps = new ArrayList<>();
        if (required.size() == 1) {
            checks.getFirst().forEach(location -> steps.add(CallTraversal.Step.unconditional(location.id())));
            return steps;
        }
        Set<String> added = new LinkedHashSet<>();
        checks.stream().flatMap(List::stream).filter(location -> added.add(location.id()))
                .forEach(location -> steps.add(new CallTraversal.Step(location.id(), List.of(), true)));
        // By the endpoint: a SOAP operation's namespace tells two of one name apart.
        AuthorizationLocation either = graph.split(new AuthorizationLocation("location:SPLIT:" + kind + ":"
                + operation.endpoint(), name + " of " + operation.endpoint() + " (" + ways + ")",
                AuthorizationLocation.Scope.HTTP_REQUEST,
                AuthorizationLocation.Phase.PRE, Requirement.or(required), operation.handler(), null,
                null, AuthorizationLocation.Denial.THROW, false), new GraphBuilder.Split(checks.stream()
                        .map(way -> way.stream().map(AuthorizationLocation::id).toList()).toList(), true));
        steps.add(CallTraversal.Step.unconditional(either.id()));
        return steps;
    }

    /**
     * Each Split location again from its parts, whose requirements the hierarchy, the factories and
     * {@code hasPermission} have changed since it was made: innermost first, as they were made.
     */
    @Supports(Feature.REQUIREMENTS)
    private static void rebuildSplits(GraphBuilder graph) {
        graph.splits().forEach((id, split) -> graph.find(id).map(AuthorizationLocation.class::cast)
                .ifPresent(location -> {
                    List<Requirement> alternatives = split.alternatives().stream().map(ids -> {
                        List<AuthorizationLocation> parts = ids.stream().flatMap(part -> graph.find(part).stream())
                                .map(AuthorizationLocation.class::cast).toList();
                        List<Requirement> required = parts.stream().map(AuthorizationLocation::requirement).toList();
                        return split.combined() ? combined(parts) : required.size() == 1 ? required.getFirst()
                                : Requirement.and(required);
                    }).distinct().toList();
                    graph.replace(location.withRequirement(alternatives.size() == 1 ? alternatives.getFirst()
                            : Requirement.or(alternatives)));
                }));
    }

    /**
     * What a list of checks asks for together: {@code permitAll} for none.
     */
    private static Requirement combined(List<AuthorizationLocation> checks) {
        List<Requirement> required = checks.stream().map(AuthorizationLocation::requirement)
                .filter(requirement -> requirement.kind() != Requirement.Kind.PERMIT_ALL).distinct().toList();
        return required.isEmpty() ? Requirement.permitAll() : required.size() == 1 ? required.getFirst()
                : Requirement.and(required);
    }

    /**
     * The field checks that run when a proxy of this type is serialized: those on its getters, and on the getters of
     * the proxies its {@code @AuthorizeReturnObject} getters return, as the factory that made it applies them.
     */
    @Supports(Feature.FIELD_CHECKS)
    private static List<String> serialized(ScanContext context, MethodSecurity methodSecurity, String type,
            ProxyFactories.Factory factory, Set<String> seen) {
        Optional<JavaSootClass> cls = context.findClass(type).filter(found -> context.isApplication(found.getType()));
        if (cls.isEmpty() || !seen.add(type)) {
            return List.of();
        }
        List<String> checks = new ArrayList<>();
        // In name order: a class's methods come in no fixed order, and the path should be the same every scan.
        for (JavaSootMethod getter : cls.get().getMethods().stream()
                .sorted(Comparator.comparing(JavaSootMethod::getName)).toList()) {
            if (getter.isStatic() || getter.getParameterCount() != 0
                    || !(getter.getName().startsWith("get") || getter.getName().startsWith("is"))) {
                continue;
            }
            methodSecurity.checks(getter).ifPresent(found -> {
                List<AuthorizationLocation> all = new ArrayList<>(found.pre());
                all.addAll(found.post());
                all.stream().filter(location -> location.scope() == AuthorizationLocation.Scope.FIELD)
                        .flatMap(location -> (factory.spring() ? Optional.of(location)
                                : methodSecurity.onBuiltProxy(location, factory)).stream())
                        .forEach(location -> checks.add(location.id()));
            });
            if (methodSecurity.authorizesReturnObject(getter, factory)) {
                List<String> returned = new ArrayList<>(context.classFiles()
                        .returnTypeArguments(getter.getSignature()));
                if (getter.getReturnType() instanceof ClassType direct) {
                    returned.add(direct.getFullyQualifiedName());
                }
                returned.forEach(nested -> checks.addAll(serialized(context, methodSecurity, nested, factory, seen)));
            }
        }
        return checks;
    }

    /**
     * Provided {@code requirement} facts whose ingress pattern ({@code GET /path/**} or {@code /path/**}) matches.
     */
    @Supports(Feature.PROVIDED_FACTS)
    private static List<String> providedRequirements(ScanContext context, GraphBuilder graph, Ingress ingress) {
        List<String> ids = new ArrayList<>();
        for (ProvidedFact fact : context.input().facts().of(ProvidedFact.Kind.REQUIREMENT)) {
            String[] parts = fact.subject().trim().split("\\s+", 2);
            HttpSecurityRules.Matcher matcher = parts.length == 2
                    ? HttpSecurityRules.Matcher.paths(parts[0].toUpperCase(Locale.ROOT), List.of(parts[1]))
                    : HttpSecurityRules.Matcher.paths(null, List.of(parts[0]));
            if (matcher.matches(ingress.httpMethod(), ingress.route())) {
                AuthorizationLocation location = graph.node(new AuthorizationLocation(
                        "location:HTTP_REQUEST:provided:" + fact.subject(), "Provided requirement (" + fact.origin()
                                + ")", AuthorizationLocation.Scope.HTTP_REQUEST, AuthorizationLocation.Phase.PRE,
                        // SpEL reads as Spring would (a policy on it can hold); any other text stays as written.
                        fact.requirement() == null ? Requirement.expression(fact.subject())
                                : SpelRequirements.standard(fact.requirement()),
                        CodeRef.ofClass("authtracer.yaml"), null, fact.subject(), AuthorizationLocation.Denial.THROW,
                        false));
                ids.add(location.id());
            }
        }
        return ids;
    }

    /**
     * Collects the checks and egress along one request path.
     */
    @Supports({Feature.METHOD_SECURITY, Feature.CALL_PATHS})
    private static final class RequestPath implements CallTraversal.Listener {

        private static final String ASYNC = "@Async";
        private static final AsyncCalls.HandOff NO_HOP = new AsyncCalls.HandOff("", null);
        private static final AsyncCalls.Site UNKNOWN_SITE = new AsyncCalls.Site(null, null);

        private final Ingress ingress;
        private final MethodSecurity methodSecurity;
        private final Proxies proxies;
        private final HttpClientEgress egress;
        private final GraphBuilder graph;
        private final Set<JavaSootMethod> reachable;
        private final AsyncCalls async;
        private final MessagePayloads payloads;
        /**
         * Names a call site in a lambda or closure by the method it is written in, so its id doesn't shift with the
         * compiler's numbering.
         */
        private final EnclosingMethods enclosing;
        private final ProgrammaticChecks programmatic;
        /**
         * The methods being walked, innermost first, with which of their values are authorization proxies.
         */
        private final Deque<Proxies.Frame> frames = new ArrayDeque<>();
        /**
         * Per method being walked, the thread calling it moved to (decisions 0048, 0062, 0084), or {@link #NO_HOP}.
         */
        private final Deque<AsyncCalls.HandOff> hops = new ArrayDeque<>();
        /**
         * The threads the walk is on, innermost first.
         */
        private final Deque<AsyncCalls.HandOff> threads = new ArrayDeque<>();
        /**
         * The lambdas and method references created on the walk that go to another thread, with the call that takes
         * them there.
         */
        private final Map<AbstractInvokeExpr, AsyncCalls.HandOff> handedOff = new IdentityHashMap<>();
        /**
         * Where each call on the walk is made, for the callers that wait for another thread (decision 0084).
         */
        private final Map<AbstractInvokeExpr, AsyncCalls.Site> sites = new IdentityHashMap<>();
        /**
         * Per method being walked, innermost first, where it was called from: {@link AsyncCalls#ENTRY} for the walk's
         * entry.
         */
        private final Deque<AsyncCalls.Site> calledFrom = new ArrayDeque<>();

        RequestPath(Ingress ingress, MethodSecurity methodSecurity, Proxies proxies, HttpClientEgress egress,
                GraphBuilder graph, Set<JavaSootMethod> reachable, AsyncCalls async, EnclosingMethods enclosing,
                MessagePayloads payloads, ProgrammaticChecks programmatic) {
            this.ingress = ingress;
            this.methodSecurity = methodSecurity;
            this.proxies = proxies;
            this.egress = egress;
            this.graph = graph;
            this.reachable = reachable;
            this.async = async;
            this.enclosing = enclosing;
            this.payloads = payloads;
            this.programmatic = programmatic;
        }

        @Override
        public List<String> onEnter(JavaSootMethod method, AbstractInvokeExpr call, boolean viaThis,
                List<String> stack) {
            AsyncCalls.Site site = call == null ? AsyncCalls.ENTRY : sites.getOrDefault(call, UNKNOWN_SITE);
            AsyncCalls.HandOff hop = NO_HOP;
            if (async.hops(method, viaThis)) {
                // Decision 0084: the caller may wait for the @Async method's future.
                hop = new AsyncCalls.HandOff(ASYNC, site.method() == null ? null
                        : async.waiter(site, calledFrom.iterator()).orElse(null));
            }
            else if (call != null && handedOff.containsKey(call)) {
                hop = handedOff.get(call);
            }
            else {
                hop = async.pooledAsync(method, viaThis).map(annotation -> new AsyncCalls.HandOff(annotation, null,
                        true)).orElse(NO_HOP);
            }
            hops.push(hop);
            calledFrom.push(site);
            if (hop != NO_HOP) {
                threads.push(hop);
            }
            return offThread(method, enter(method, call, viaThis, stack));
        }

        @Override
        public List<String> onExit(JavaSootMethod method, boolean viaThis) {
            List<String> post = offThread(method, exit(method, viaThis));
            calledFrom.pop();
            if (hops.pop() != NO_HOP) {
                threads.pop();
            }
            return post;
        }

        /**
         * Decisions 0048, 0062: on another thread without the caller's SecurityContext, a check that asks for the
         * caller denies.
         */
        @Supports(Feature.FINDING_ALWAYS_DENIED)
        private List<String> offThread(JavaSootMethod method, List<String> ids) {
            if (threads.isEmpty() || ids.isEmpty()) {
                return ids;
            }
            AsyncCalls.HandOff hop = threads.peek();
            if (hop.pooled()) {
                return pooled(method, ids, hop);
            }
            boolean async = hop.thread().equals(ASYNC);
            boolean reactor = hop.thread().startsWith("Mono.") || hop.thread().startsWith("Flux.");
            List<String> result = new ArrayList<>();
            for (String id : ids) {
                if (graph.find(id).orElse(null) instanceof AuthorizationLocation location
                        && NoCaller.asksForCaller(location)) {
                    // Decision 0084: a caller that waits for the work sees it fail.
                    result.add((hop.waiter() != null ? NoCaller.waitedOffThread(graph, location, async)
                            : NoCaller.offThread(graph, location, async)).id());
                    // Decision 0093: a task or a delivery has no caller whose context is left behind.
                    boolean noCaller = NoCaller.applies(ingress);
                    String who = noCaller ? ingress.endpoint() : "the request";
                    String carried = reactor ? "context propagation carries it there"
                            + " (spring.reactor.context-propagation=auto)" : "the executor carries "
                                    + (noCaller ? "it" : "the context") + " over"
                                    + " (DelegatingSecurityContextAsyncTaskExecutor, a TaskDecorator)";
                    graph.finding(new Finding(Finding.Kind.ALWAYS_DENIED, "On " + ingress.endpoint() + ": "
                            + location.mechanism() + " on " + location.target().className() + "#"
                            + location.target().method() + (async ? " runs on an @Async thread" : " runs on the"
                                    + " thread " + hop.thread() + " hands it to") + (noCaller ? ", and " + who
                                            + " has no caller, so the thread has no SecurityContext: "
                                            : ", which doesn't have the caller's SecurityContext: ")
                            + (location.mechanism().startsWith(ProgrammaticChecks.MECHANISM)
                                    ? "the manager finds no Authentication and denies"
                                    : "it throws AuthenticationCredentialsNotFoundException")
                            + (noCaller ? " unless the code sets a SecurityContext there, or sets one before handing"
                                    + " the work over and " + carried : " unless " + carried)
                            + (hop.waiter() == null ? "" : "; " + hop.waiter() + " waits for it, so " + who
                                    + " fails with it"), enclosing.codeRef(method)));
                }
                else {
                    result.add(id);
                }
            }
            return result;
        }

        /**
         * Decision 0084, amended: on a pool's thread, which only a strategy that isn't thread-local gives a
         * SecurityContext, a check that asks for the caller decides for the one whose request created the thread (the
         * inheritable strategy), or whose context was set last (the global one), not this caller: the check stays, and
         * a finding says so.
         */
        @Supports(Feature.FINDING_AUTHORITIES_IN_CODE)
        private List<String> pooled(JavaSootMethod method, List<String> ids, AsyncCalls.HandOff hop) {
            for (String id : ids) {
                if (graph.find(id).orElse(null) instanceof AuthorizationLocation location
                        && NoCaller.asksForCaller(location)) {
                    graph.finding(new Finding(Finding.Kind.AUTHORITIES_IN_CODE, "On " + ingress.endpoint() + ": "
                            + location.mechanism() + " on " + location.target().className() + "#"
                            + location.target().method() + " runs on a pooled thread ("
                            + (hop.thread().startsWith(ASYNC) ? hop.thread() + "'s executor" : hop.thread())
                            + "), which keeps the SecurityContext the SecurityContextHolder strategy gave it when it was"
                            + " created, not this caller's: the check decides for whichever request that was, unless"
                            + " the executor carries the context over (DelegatingSecurityContextAsyncTaskExecutor, a"
                            + " TaskDecorator)", MethodNames.codeRef(method.getSignature())));
                }
            }
            return ids;
        }

        private List<String> enter(JavaSootMethod method, AbstractInvokeExpr call, boolean viaThis,
                List<String> stack) {
            reachable.add(method);
            Map<Integer, ProxyFactories.Factory> proxied = call == null || frames.isEmpty() ? Map.of()
                    : frames.peek().proxiedArguments(call);
            frames.push(proxies.frame(method, proxied));
            Optional<MethodSecurity.MethodChecks> checks = methodSecurity.checks(method);
            if (checks.isEmpty()) {
                return List.of();
            }
            String caller = stack.size() > 1 ? stack.get(stack.size() - 2) : "?";
            if (viaThis) {
                for (AuthorizationLocation location : all(checks.get())) {
                    if (location.proxied()) {
                        bypassed(method, location.mechanism() + " on " + MethodNames.key(method.getSignature())
                                + " is skipped when " + caller
                                + " calls it on this (the call does not go through Spring's proxy)");
                    }
                }
                // A check woven into the method (AspectJ) runs on any call.
                return checks.get().pre().stream().filter(location -> !location.proxied())
                        .map(AuthorizationLocation::id).toList();
            }
            return fieldChecks(method, checks.get().pre(), caller, proxied.get(Proxies.RECEIVER));
        }

        /**
         * Decision 0014: a field check runs only when its getter is called on an authorization proxy; decision 0088:
         * as the factory that made the proxy applies it.
         *
         * @param onProxy the factory that made the proxy the method is called on, {@code null} for none
         */
        @Supports(Feature.FIELD_CHECKS)
        private List<String> fieldChecks(JavaSootMethod method, List<AuthorizationLocation> locations, String caller,
                ProxyFactories.Factory onProxy) {
            List<String> reached = new ArrayList<>();
            // Any check of a returned object's class, not only its getters', runs only on the proxy.
            boolean proxyOnly = methodSecurity.onlyOnReturnedProxy(method);
            for (AuthorizationLocation location : locations) {
                boolean field = location.scope() == AuthorizationLocation.Scope.FIELD;
                if (!field && !proxyOnly || onProxy != null && onProxy.spring()) {
                    reached.add(location.id());
                    continue;
                }
                Optional<AuthorizationLocation> runs = onProxy == null ? Optional.empty()
                        : methodSecurity.onBuiltProxy(location, onProxy);
                runs.ifPresentOrElse(check -> reached.add(check.id()), () -> bypassed(method, location.mechanism()
                        + " on " + MethodNames.key(method.getSignature()) + " is skipped when " + caller
                        + (field ? " reads it: the object it reads" : " calls it: the object it is called on")
                        + (onProxy == null ? " does not come from an @AuthorizeReturnObject method or"
                                + " AuthorizationProxyFactory, so it is not an authorization proxy"
                                : " comes from " + onProxy.madeBy() + " " + onProxy.describe())));
            }
            return reached;
        }

        /**
         * Decision 0027: when every way the method returns passes some of its conditional checks, a Split location
         * asks for the weakest branch's checks; when a way returns without any, those checks are BYPASSED there.
         */
        @Override
        public List<String> onBranches(JavaSootMethod method, List<List<String>> branches, List<String> conditional) {
            // Decision 0089 (amended): a lambda's by the method it is written in, and its line there.
            String key = enclosing.key(method);
            String where = enclosing.written(method) ? "a lambda in " + key : key;
            return weakest(method, branches, conditional, "location:SPLIT:" + key + lambdaLine(method), "Branches of "
                    + (enclosing.written(method) ? where : method.getDeclaringClassType().getClassName() + "#"
                            + method.getName()), (check, without) -> check.mechanism() + " on "
                                    + check.target().key() + " runs on some of " + where
                                    + "'s branches only: it also returns without it");
        }

        /**
         * A lambda's first line in the method it is written in, which tells it from the method's other lambdas.
         */
        private String lambdaLine(JavaSootMethod method) {
            return enclosing.written(method) ? ":lambda@" + enclosing.codeRef(method).line() : "";
        }

        /**
         * Decision 0027 for virtual calls: a call more than one bean answers runs one of them, so it is as open as
         * the most open: a Split location asks for the weakest one's checks; when one runs none, the others' are
         * BYPASSED there.
         */
        @Override
        public List<String> onDispatch(JavaSootMethod caller, AbstractInvokeExpr call, List<JavaSootMethod> targets,
                List<List<String>> reached) {
            String called = call.getMethodSignature().getDeclClassType().getClassName() + "#"
                    + call.getMethodSignature().getName();
            return weakest(caller, reached, reached.stream().flatMap(List::stream).distinct().toList(),
                    "location:SPLIT:" + enclosing.key(caller) + lambdaLine(caller) + ":calls:"
                            + MethodNames.key(call.getMethodSignature()), "Implementations of " + called,
                    (check, without) -> check.mechanism() + " on " + check.target().key() + " runs in some of the"
                            + " beans " + enclosing.key(caller) + " calls " + called + " on only: "
                            + MethodNames.key(targets.get(without).getSignature()) + " runs without it");
        }

        /**
         * Decision 0027: a Split location asking for the weakest alternative's checks, when every alternative passes
         * some; when one passes none, the checks are BYPASSED there and no Split is made.
         *
         * @param bypassed the finding for a check, given the index of an alternative without any
         */
        private List<String> weakest(JavaSootMethod method, List<List<String>> ways, List<String> conditional,
                String id, String mechanism, BiFunction<AuthorizationLocation, Integer, String> bypassed) {
            List<AuthorizationLocation> checks = requestChecks(conditional);
            if (checks.isEmpty()) {
                return List.of();
            }
            List<Requirement> alternatives = new ArrayList<>();
            List<List<String>> parts = new ArrayList<>();
            for (int i = 0; i < ways.size(); i++) {
                List<AuthorizationLocation> wayChecks = requestChecks(ways.get(i));
                parts.add(wayChecks.stream().map(AuthorizationLocation::id).toList());
                List<Requirement> required = wayChecks.stream().map(AuthorizationLocation::requirement).toList();
                if (required.isEmpty()) {
                    for (AuthorizationLocation check : checks) {
                        bypassed(method, bypassed.apply(check, i));
                    }
                    return List.of();
                }
                alternatives.add(required.size() == 1 ? required.getFirst() : Requirement.and(required));
            }
            Requirement weakest = alternatives.stream().distinct().count() == 1 ? alternatives.getFirst()
                    : Requirement.or(alternatives.stream().distinct().toList());
            return List.of(graph.split(new AuthorizationLocation(id, mechanism, AuthorizationLocation.Scope.METHOD,
                    AuthorizationLocation.Phase.PRE, weakest, enclosing.codeRef(method), null, null,
                    AuthorizationLocation.Denial.THROW, false), new GraphBuilder.Split(parts, false)).id());
        }

        /**
         * The request- and method-level checks among the nodes; field checks guard their own values on any branch.
         */
        private List<AuthorizationLocation> requestChecks(List<String> nodeIds) {
            // Decision 0048: what fails on an @Async thread doesn't constrain the caller, on any branch.
            return nodeIds.stream().distinct().filter(id -> !NoCaller.isOffThread(id))
                    .map(id -> graph.find(id).orElse(null))
                    .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                    .filter(location -> location.scope() != AuthorizationLocation.Scope.FIELD).toList();
        }

        @Supports(Feature.FINDING_BYPASSED)
        private void bypassed(JavaSootMethod method, String message) {
            graph.finding(new Finding(Finding.Kind.BYPASSED, "On " + ingress.endpoint()
                    + ": " + message, enclosing.codeRef(method)));
        }

        private static List<AuthorizationLocation> all(MethodSecurity.MethodChecks checks) {
            List<AuthorizationLocation> all = new ArrayList<>(checks.pre());
            all.addAll(checks.post());
            return all;
        }

        /**
         * Decision 0080: the walk stopped this deep, so what the method does is shown as unread rather than left out.
         */
        @Supports(Feature.FINDING_OPAQUE_CALLPATH)
        @Override
        public List<String> onTooDeep(JavaSootMethod method, AbstractInvokeExpr call, int limit) {
            CodeRef site = MethodNames.codeRef(method.getSignature());
            Opaque opaque = graph.node(Opaque.of("A call more than " + limit + " calls deep, past what AuthTracer"
                    + " follows", site));
            graph.finding(new Finding(Finding.Kind.OPAQUE_CALLPATH, "On " + ingress.httpMethod() + " "
                    + ingress.route() + ": the call path is more than " + limit + " calls deep at " + site.key()
                    + "; the checks, calls and field reads past it are not in the graph", site));
            return List.of(opaque.id());
        }

        @Supports({Feature.SERVICE_CALLS, Feature.MESSAGE_SENDS, Feature.CALL_CREDENTIALS, Feature.CUSTOM_DECISIONS,
                Feature.FIELD_LINEAGE, Feature.FINDING_OPAQUE_CALLPATH})
        @Override
        public List<String> onCallSite(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
            if (MethodSecurity.isProxyCall(invoke)) {
                return List.of();
            }
            async.handsOff(caller, stmt, calledFrom.iterator()).ifPresentOrElse(started -> handedOff.put(invoke,
                    new AsyncCalls.HandOff(started.thread(), async.waiter(new AsyncCalls.Site(caller, started.at()),
                            calledFrom.iterator()).orElse(null))),
                    () -> async.handsOffToPool(caller, stmt).ifPresent(started -> handedOff.put(invoke,
                            new AsyncCalls.HandOff(started.thread(), null, true))));
            sites.put(invoke, new AsyncCalls.Site(caller, stmt));
            if (MessageListeners.isListener(ingress)) {
                // Decision 0098: what a listener writes of what it received.
                payloads.written(ingress, caller, invoke, calledFrom.iterator());
            }
            // Decision 0066: a check the code makes itself, at the call, before what follows.
            Optional<AuthorizationLocation> check = programmatic.detect(caller, stmt, invoke,
                    enclosing.site(caller, MethodNames.codeRef(caller.getSignature(), stmt)));
            if (check.isPresent()) {
                return offThread(caller, List.of(check.get().id()));
            }
            Optional<String> reflection = reflection(invoke)
                    .or(() -> GroovyCalls.of(invoke).flatMap(HttpClientEgress::dynamicClient)
                            .map(call -> "Dynamic Groovy HTTP client call (" + call + ")"));
            if (reflection.isPresent()) {
                Opaque opaque = graph.node(Opaque.of(reflection.get(),
                        enclosing.site(caller, MethodNames.codeRef(caller.getSignature(), stmt))));
                graph.finding(new Finding(Finding.Kind.OPAQUE_CALLPATH, "On " + ingress.httpMethod() + " "
                        + ingress.route() + ": " + reflection.get() + " in " + opaque.site().key()
                        + "; what it calls is not in the graph", opaque.site()));
                return List.of(opaque.id());
            }
            return egress.detect(caller, stmt, invoke)
                    // Decisions 0048, 0062: on another thread, there is no caller's token to relay.
                    .map(found -> !threads.isEmpty() && found.credentials() == Credentials.RELAY
                            ? found.withCredentials(Credentials.NONE, threads.peek().thread()
                                    + ": the caller's token stays on its thread")
                            : found)
                    .map(found -> {
                        Egress node = graph.node(found.withCallSite(enclosing.site(caller, found.callSite())));
                        // Decision 0090: what a message carries, from what it is built of on this walk.
                        payloads.sent(node, caller, invoke, calledFrom.iterator());
                        return node;
                    })
                    .map(Egress::id).map(List::of).orElse(List.of());
        }

        private static Optional<String> reflection(AbstractInvokeExpr invoke) {
            String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.getMethodSignature().getName();
            return switch (owner) {
                case "java.lang.reflect.Method" -> name.equals("invoke") ? Optional.of("Reflection (Method.invoke)")
                        : Optional.empty();
                case "java.lang.reflect.Constructor" -> name.equals("newInstance")
                        ? Optional.of("Reflection (Constructor.newInstance)") : Optional.empty();
                case "java.lang.invoke.MethodHandle" -> name.startsWith("invoke")
                        ? Optional.of("Method handle (MethodHandle." + name + ")") : Optional.empty();
                default -> Optional.empty();
            };
        }

        private List<String> exit(JavaSootMethod method, boolean viaThis) {
            Proxies.Frame frame = frames.pop();
            if (viaThis) {
                return methodSecurity.checks(method).map(checks -> checks.post().stream()
                        .filter(location -> !location.proxied()).map(AuthorizationLocation::id).toList())
                        .orElse(List.of());
            }
            return methodSecurity.checks(method)
                    .map(checks -> fieldChecks(method, checks.post(), "its caller", frame.onProxy()))
                    .orElse(List.of());
        }
    }
}
