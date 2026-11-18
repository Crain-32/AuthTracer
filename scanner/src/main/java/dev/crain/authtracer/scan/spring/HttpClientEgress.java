package dev.crain.authtracer.scan.spring;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.Payloads;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.FieldSignature;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Where a request leaves the service through a client it calls:
 * <ul>
 * <li>{@code RestClient} and {@code WebClient}: {@code client.get().uri("/employees/{id}", id)...}</li>
 * <li>{@code RestTemplate}: {@code restTemplate.getForObject(baseUrl + "/employees/{id}", Employee.class, id)}</li>
 * <li>the JDK's {@code HttpClient}: {@code client.send(HttpRequest.newBuilder(URI.create(..)).GET().build(), ..)}</li>
 * <li>HTTP interfaces: a call to an {@code @GetExchange("/employees/{id}")} interface method</li>
 * <li>Spring Cloud OpenFeign clients (decision 0042): a call to a {@code @FeignClient} interface method</li>
 * <li>Spring for GraphQL's clients (decision 0031): {@code client.document("{ person(id: 1) { name } }")
 * .retrieveSync("person")}, the Egress {@code QUERY person}</li>
 * <li>gRPC stubs (decision 0032), the Egress {@code GRPC package.Service/Method}</li>
 * <li>{@code RSocketRequester} routes (decision 0045)</li>
 * <li>messages sent to a destination (decisions 0044, 0047: {@link MessageSends}) and SOAP calls (decision 0056:
 * {@link SoapCalls})</li>
 * </ul>
 */
@Supports(Feature.SERVICE_CALLS)
final class HttpClientEgress {

    private static final Set<String> HTTP_METHODS = Set.of("get", "post", "put", "patch", "delete", "head",
            "options");
    private static final String WEB_CLIENT = "org.springframework.web.reactive.function.client.WebClient";
    /**
     * The calls that send a fluent client's request.
     */
    private static final Set<String> SENDS = Set.of("retrieve", "exchange", "exchangeToMono", "exchangeToFlux");
    private static final int MAX_CHAIN = 12;
    private static final String REST_TEMPLATE = "org.springframework.web.client.RestTemplate";
    private static final String REST_OPERATIONS = "org.springframework.web.client.RestOperations";
    private static final String REST_TEMPLATE_BUILDER = "org.springframework.boot.restclient.RestTemplateBuilder";
    private static final String REQUEST_ENTITY = "org.springframework.http.RequestEntity";
    private static final String HTTP_METHOD = "org.springframework.http.HttpMethod";
    private static final String EXCHANGE = "org.springframework.web.service.annotation.";
    private static final String HTTP_EXCHANGE = EXCHANGE + "HttpExchange";
    /**
     * {@code @HttpExchange} last: the others carry it as a meta-annotation.
     */
    private static final List<Map.Entry<String, String>> EXCHANGES = List.of(Map.entry(EXCHANGE + "GetExchange",
            "GET"), Map.entry(EXCHANGE + "PostExchange", "POST"), Map.entry(EXCHANGE + "PutExchange", "PUT"),
            Map.entry(EXCHANGE + "PatchExchange", "PATCH"), Map.entry(EXCHANGE + "DeleteExchange", "DELETE"),
            Map.entry(HTTP_EXCHANGE, "*"));
    private static final String IMPORT_HTTP_SERVICES = "org.springframework.web.service.registry.ImportHttpServices";
    private static final String FEIGN_CLIENT = "org.springframework.cloud.openfeign.FeignClient";
    private static final String RSOCKET_REQUESTER = "org.springframework.messaging.rsocket.RSocketRequester";
    private static final String JDK_HTTP_CLIENT = "java.net.http.HttpClient";
    private static final Set<String> JDK_METHODS = Set.of("GET", "POST", "PUT", "DELETE", "HEAD");
    private static final String RSOCKET_SECURITY_METADATA = "org.springframework.security.rsocket.metadata.";
    private static final String PROXY_FACTORY = "org.springframework.web.service.invoker.HttpServiceProxyFactory";
    private static final String URI = "java.net.URI";
    private static final String URI_BUILDER_FACTORY = "org.springframework.web.util.DefaultUriBuilderFactory";
    private static final Set<String> URI_BUILDERS = Set.of("org.springframework.web.util.UriComponentsBuilder",
            "org.springframework.web.util.UriComponents", "org.springframework.web.util.UriBuilder");
    /**
     * {@code UriComponentsBuilder}/{@code UriBuilder} calls that keep the path as it is.
     */
    private static final Set<String> URI_PASS_THROUGH = Set.of("build", "buildAndExpand", "expand", "encode", "toUri",
            "toUriString", "queryParam", "queryParams", "query", "replaceQuery", "replaceQueryParam", "fragment",
            "uriVariables", "normalize", "cloneBuilder");
    /**
     * {@code UriBuilder} calls that send the request elsewhere than the client's base URL.
     */
    private static final Set<String> URI_HOST_PARTS = Set.of("scheme", "host", "port", "userInfo", "uri",
            "uriComponents", "schemeSpecificPart");
    private static final String STRING = "java.lang.String";
    private static final Set<String> STRING_BUILDERS = Set.of("java.lang.StringBuilder", "java.lang.StringBuffer");
    /**
     * A {@code java.util.Formatter} specifier: its argument index, if it names one, and its conversion.
     */
    private static final Pattern FORMAT_SPECIFIER = Pattern.compile(
            "%(?:(\\d+)\\$)?[-#+ 0,(<]*\\d*(?:\\.\\d+)?([a-zA-Z%])");
    /**
     * A URI template variable, as Spring's {@code UriComponents} finds them: {@code {name}} or {@code {name:regex}}.
     */
    private static final Pattern URI_VARIABLE = Pattern.compile("\\{([^/]+?)}");
    private static final Map<String, String> REST_TEMPLATE_METHODS = Map.ofEntries(Map.entry("getForObject", "GET"),
            Map.entry("getForEntity", "GET"), Map.entry("headForHeaders", "HEAD"),
            Map.entry("postForObject", "POST"), Map.entry("postForEntity", "POST"),
            Map.entry("postForLocation", "POST"), Map.entry("put", "PUT"), Map.entry("patchForObject", "PATCH"),
            Map.entry("delete", "DELETE"), Map.entry("optionsForAllow", "OPTIONS"), Map.entry("exchange", ""),
            Map.entry("execute", ""));

    /**
     * A fluent client: requests start with {@code get()}/{@code post()}/... (or {@code method(HttpMethod.PATCH)}) on
     * {@code type}, the path is the {@code uri(..)} argument, and the base URL comes from {@code type.create(url)} or
     * {@code builder.baseUrl(url)}. The response is read into a type by its response spec's {@code bodies}.
     */
    private record Fluent(String client, String type, Set<String> bodies, Set<String> manyBodies) {

        String builder() {
            return type + "$Builder";
        }

        /**
         * Not its request spec, whose {@code body(order)} is the request's.
         */
        String responseSpec() {
            return type + "$ResponseSpec";
        }

        boolean owns(String declaring) {
            return declaring.startsWith(type + "$");
        }
    }

    private static final List<Fluent> FLUENT = List.of(
            new Fluent("RestClient", SpringNames.REST_CLIENT, Set.of("body", "toEntity"), Set.of()),
            new Fluent("WebClient", WEB_CLIENT, Set.of("bodyToMono", "toEntity"), Set.of("bodyToFlux",
                    "toEntityList", "toEntityFlux")));

    private static final String GRAPHQL_CLIENT = "org.springframework.graphql.client.";
    private static final String IMPORT_GRPC_CLIENTS = "org.springframework.grpc.client.ImportGrpcClients";
    private static final String GRAPHQL_REQUEST = GRAPHQL_CLIENT + "GraphQlClient$RequestSpec";
    private static final Set<String> GRAPHQL_SENDS = Set.of("retrieve", "retrieveSync", "retrieveSubscription",
            "execute", "executeSync", "executeSubscription");
    private static final List<String> GRAPHQL_BUILDERS = List.of(GRAPHQL_CLIENT + "HttpSyncGraphQlClient$Builder",
            GRAPHQL_CLIENT + "HttpGraphQlClient$Builder", GRAPHQL_CLIENT + "WebGraphQlClient$Builder");
    private static final List<String> GRAPHQL_DOCUMENTS = List.of("graphql-documents/%s.graphql",
            "graphql-documents/%s.gql");

    private record BaseUrl(String value, String expression) {
        static final BaseUrl UNKNOWN = new BaseUrl(null, null);
    }

    /**
     * A request a {@code RequestEntity} describes.
     */
    private record Request(String httpMethod, Url url) {
    }

    /**
     * A request URL split into the service's base URL and the path template the linker matches.
     *
     * @param query the query string, without its {@code ?}, when the URL has a constant one
     */
    private record Url(BaseUrl baseUrl, String path, String query) {

        Url(BaseUrl baseUrl, String path) {
            this(baseUrl, path, null);
        }
    }

    private final ScanContext context;
    private final GrpcServices grpc;
    private final MessageSends messages;
    private final SoapCalls soap;
    private final Map<String, BaseUrl> baseUrls = new ConcurrentHashMap<>();
    /**
     * Per HTTP interface, the method that wires it by hand and the base URL of its service group: each a scan of
     * the application, done once.
     */
    private final Map<String, Optional<Wiring>> proxyFactoryMethods = new ConcurrentHashMap<>();
    private final Map<String, Optional<AnnotationUsage>> serviceGroups = new ConcurrentHashMap<>();
    private final EgressCredentials credentials;
    private final UnreadCalls unread = new UnreadCalls();
    private final ConfiguredValues configured;

    HttpClientEgress(ScanContext context, GrpcServices grpc) {
        this.context = context;
        this.grpc = grpc;
        this.configured = new ConfiguredValues(context);
        this.messages = new MessageSends(context, unread, configured);
        this.soap = new SoapCalls(context, unread, configured);
        this.credentials = new EgressCredentials(context);
    }

    /**
     * Decision 0082: the calls on the paths walked so far whose target AuthTracer can't read.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    List<Finding> findings() {
        return unread.findings();
    }

    /**
     * What the call authenticates with, from where its client is built.
     */
    @Supports(Feature.CALL_CREDENTIALS)
    private Egress withCredentials(Egress egress, JavaSootMethod caller) {
        return withCredentials(egress, caller, Optional.empty());
    }

    /**
     * What the call authenticates with: the client it is made on's, where that is built (decision 0083), else the
     * calling class's.
     */
    @Supports(Feature.CALL_CREDENTIALS)
    private Egress withCredentials(Egress egress, JavaSootMethod caller, Optional<Local> client) {
        EgressCredentials.Found found = client.map(local -> credentials.forClient(caller, local))
                .orElseGet(() -> context.findClass(caller.getDeclaringClassType()).map(credentials::forClass)
                        .orElse(EgressCredentials.Found.NONE));
        // An OAuth2 client picks the registration per request: .attributes(clientRegistrationId("x")), or the
        // authorized client itself. Spring Security's interceptor and filter functions add no token to a request
        // that names neither (7.1.1).
        if (found.credentials() == Credentials.OAUTH2_CLIENT) {
            EgressCredentials.Found perRequest = found;
            found = credentials.registrationIn(caller).map(registration -> credentials.forRegistration(registration,
                    "clientRegistrationId(\"" + registration + "\")"))
                    .or(() -> credentials.authorizedClientIn(caller))
                    .orElseGet(() -> perRequest.unnamed("the request names no client registration"));
        }
        return credentialed(egress, found);
    }

    /**
     * The call with what it authenticates with, and the OAuth2 client registration whose own token it sends when
     * AuthTracer reads it (decision 0075 amended).
     */
    @Supports(Feature.CALL_CREDENTIALS)
    private Egress credentialed(Egress egress, EgressCredentials.Found found) {
        return egress.withCredentials(found.credentials(), found.via())
                .withRegistration(credentials.registration(found).orElse(null));
    }

    /**
     * The client a fluent request is made on: the receiver of its {@code get()}, {@code post()}, ...
     */
    @Supports(Feature.CALL_CREDENTIALS)
    private static Optional<Local> clientOf(Fluent fluent, JavaSootMethod caller, Local request) {
        Local receiver = request;
        for (int depth = 0; depth < MAX_CHAIN; depth++) {
            if (!(Locals.definition(caller.getBody(), receiver).orElse(null) instanceof AbstractInstanceInvokeExpr call)) {
                return Optional.empty();
            }
            String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            if (owner.equals(fluent.type())) {
                return Optional.of(call.getBase());
            }
            if (!fluent.owns(owner)) {
                return Optional.empty();
            }
            receiver = call.getBase();
        }
        return Optional.empty();
    }

    @Supports({Feature.SERVICE_CALLS, Feature.MESSAGE_SENDS})
    Optional<Egress> detect(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        Optional<GroovyCalls.Call> groovy = GroovyCalls.of(invoke);
        if (groovy.isPresent()) {
            // Dynamic Groovy: an HTTP interface method on a typed receiver (fluent clients: dynamicClient).
            return GroovyCalls.target(context, groovy.get()).filter(method -> !method.isStatic())
                    .flatMap(method -> httpInterface(caller, stmt, method.getSignature()));
        }
        if (invoke instanceof JDynamicInvokeExpr dynamic) {
            // A method reference to an HTTP interface or Feign method (ids.stream().map(orders::order)) makes the
            // call where it is used, as a lambda does where it is created.
            return referenced(dynamic).filter(called -> context.isApplication(called.getDeclClassType()))
                    .flatMap(called -> httpInterface(caller, stmt, called).or(() -> feign(caller, stmt, called)));
        }
        String declaring = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        for (Fluent fluent : FLUENT) {
            if (fluent.owns(declaring)) {
                return fluent(fluent, caller, stmt, invoke).or(() -> withoutUri(fluent, caller, stmt, invoke));
            }
        }
        if (declaring.equals(REST_TEMPLATE) || declaring.equals(REST_OPERATIONS)) {
            return restTemplate(caller, stmt, invoke);
        }
        if (declaring.equals(JDK_HTTP_CLIENT)) {
            return jdkHttpClient(caller, stmt, invoke);
        }
        if (declaring.equals(GRAPHQL_REQUEST) && GRAPHQL_SENDS.contains(invoke.getMethodSignature().getName())) {
            return graphQl(caller, stmt, invoke);
        }
        if (declaring.equals(RSOCKET_REQUESTER) && invoke.getMethodSignature().getName().equals("route")) {
            return rsocket(caller, stmt, invoke);
        }
        Optional<GrpcServices.GrpcMethod> rpc = grpc.stubCall(invoke.getMethodSignature());
        if (rpc.isPresent()) {
            return Optional.of(grpcCall(caller, stmt, invoke, rpc.get(),
                    invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()));
        }
        if (context.isApplication(invoke.getMethodSignature().getDeclClassType())) {
            return httpInterface(caller, stmt, invoke.getMethodSignature())
                    .or(() -> feign(caller, stmt, invoke.getMethodSignature()));
        }
        return messages.detect(caller, stmt, invoke).or(() -> soap.detect(caller, stmt, invoke));
    }

    /**
     * The method a method reference names.
     */
    private static Optional<MethodSignature> referenced(JDynamicInvokeExpr dynamic) {
        return dynamic.getBootstrapArgs().stream().filter(MethodHandle.class::isInstance).map(MethodHandle.class::cast)
                .filter(MethodHandle::isMethodRef).map(MethodHandle::getReferenceSignature)
                .filter(MethodSignature.class::isInstance).map(MethodSignature.class::cast).findFirst();
    }

    /**
     * Decision 0042: a call to a Spring Cloud OpenFeign client: an interface annotated {@code @FeignClient} whose
     * methods carry Spring MVC's mapping annotations, under the client's {@code path}; the base URL is its
     * {@code url}, else the service its {@code name} looks up ({@code http://<name>}).
     */
    private Optional<Egress> feign(JavaSootMethod caller, Stmt stmt, MethodSignature called) {
        Optional<JavaSootMethod> target = context.findMethod(called);
        Optional<JavaSootClass> owner = context.findClass(called.getDeclClassType());
        Optional<AnnotationUsage> client = owner.filter(JavaSootClass::isInterface)
                .flatMap(found -> context.findAnnotation(found, FEIGN_CLIENT));
        if (target.isEmpty() || client.isEmpty()) {
            return Optional.empty();
        }
        Optional<RequestMappings.MappingInfo> mapping = new RequestMappings(context).mappingInfo(target.get());
        if (mapping.isEmpty()) {
            return Optional.empty();
        }
        String name = Annotations.string(client.get(), "name").filter(value -> !value.isEmpty())
                .or(() -> Annotations.string(client.get(), "value").filter(value -> !value.isEmpty()))
                .orElse("?");
        // The name's placeholders resolved, as FeignClientsRegistrar.getName resolves them (5.0).
        BaseUrl baseUrl = Annotations.string(client.get(), "url").filter(url -> !url.isEmpty())
                .map(url -> url.contains("${") ? fromExpression(url) : new BaseUrl(url, null))
                .orElse(new BaseUrl("http://" + context.properties().resolveKnown(name),
                        "@FeignClient(name = \"" + name + "\")"));
        String path = RequestMappings.join(Annotations.string(client.get(), "path").orElse(""),
                mapping.get().paths().getFirst());
        EgressCredentials.Found found = credentials.forFeign(owner.get(), client.get());
        Url url = rebased(baseUrl, path, null);
        return Optional.of(credentialed(Egress.of("Feign", mapping.get().methods().getFirst(), url.path(),
                url.baseUrl().value(), url.baseUrl().expression(), MethodNames.codeRef(caller.getSignature(), stmt),
                Payloads.returnedBy(context, called).orElse(null)), found));
    }

    /**
     * Decision 0032: a call on a generated gRPC stub is Egress to the rpc's full method name. The service is the
     * channel's target: {@code createChannel("greeter")} (or a {@code @Value} name) in the calling class, else the
     * (single)
     * {@code @ImportGrpcClients(target = "greeter")} that registers the stub's type as a bean; its address comes from
     * {@code spring.grpc.client.channel.greeter.target}. gRPC calls link by method name, not by port.
     */
    private Egress grpcCall(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke, GrpcServices.GrpcMethod rpc,
            String stubType) {
        // A channel the class creates is its stub's, its name a constant or a @Value (else not known).
        Optional<Optional<String>> created = context.findClass(caller.getDeclaringClassType()).stream()
                .flatMap(cls -> cls.getMethods().stream()).filter(JavaSootMethod::hasBody)
                .flatMap(method -> method.getBody().getStmts().stream().map(Locals::invoke).flatMap(Optional::stream)
                        .filter(call -> call.getMethodSignature().getName().equals("createChannel")
                                && call.getArgCount() >= 1)
                        .map(call -> Optional.ofNullable(baseUrlValue(method, call.getArg(0)).value())))
                .findFirst();
        Optional<String> target = created.orElseGet(() -> context.applicationClasses().stream()
                .flatMap(cls -> repeatable(cls, IMPORT_GRPC_CLIENTS).stream())
                .filter(imports -> imports(imports, stubType,
                        stubType.substring(0, Math.max(stubType.lastIndexOf('.'), 0))))
                .map(imports -> Annotations.string(imports, "target").orElse("default"))
                .findFirst());
        // Spring Boot 4.1's property, then the standalone spring-grpc starter's.
        String address = target.map(name -> context.properties().get("spring.grpc.client.channel." + name + ".target")
                .or(() -> context.properties().get("spring.grpc.client.channels." + name + ".address")).orElse(name))
                .orElse(null);
        Egress call = Egress.of("gRPC", GrpcServices.GRPC, rpc.fullName(), null, address,
                MethodNames.codeRef(caller.getSignature(), stmt), rpc.responseType() == null ? null
                        : new Payload(rpc.responseType(), rpc.streaming()));
        // What the interceptors on the stub it is made on send (decision 0032 amended).
        if (invoke instanceof AbstractInstanceInvokeExpr instance && instance.getBase() instanceof Local stub) {
            return credentialed(call, credentials.forStub(caller, stub));
        }
        return withCredentials(call, caller);
    }

    /**
     * A class's {@code @ImportGrpcClients} or {@code @ImportHttpServices}, repeated ones from their container too.
     */
    private List<AnnotationUsage> repeatable(JavaSootClass cls, String annotation) {
        List<AnnotationUsage> imports = new ArrayList<>();
        context.findAnnotation(cls, annotation).ifPresent(imports::add);
        context.findAnnotation(cls, annotation + "$Container")
                .ifPresent(container -> imports.addAll(Annotations.nested(container, "value")));
        return imports;
    }

    /**
     * Whether an import registers the type: by its {@code types}/{@code value}, or by scanning {@code basePackages}
     * or {@code basePackageClasses}' packages, and their subpackages.
     */
    private static boolean imports(AnnotationUsage imports, String type, String pkg) {
        if (Annotations.strings(imports, "types").contains(type) || Annotations.strings(imports, "value").contains(type)) {
            return true;
        }
        List<String> bases = new ArrayList<>(Annotations.strings(imports, "basePackages"));
        Annotations.strings(imports, "basePackageClasses")
                .forEach(marker -> bases.add(marker.substring(0, Math.max(marker.lastIndexOf('.'), 0))));
        return bases.stream().anyMatch(base -> pkg.equals(base) || pkg.startsWith(base + "."));
    }

    /**
     * A dynamic Groovy call on a RestClient, WebClient or RestTemplate (outside {@code @CompileStatic}): the rest of
     * the chain is untyped, so the request it makes is not read. Returns the call, e.g. {@code RestClient.post()}.
     */
    @Supports(Feature.FINDING_OPAQUE_CALLPATH)
    static Optional<String> dynamicClient(GroovyCalls.Call call) {
        Optional<String> type = call.typedReceiver().map(ClassType::getFullyQualifiedName);
        if (type.isEmpty() || !call.type().equals("invoke")) {
            return Optional.empty();
        }
        String client = FLUENT.stream().filter(fluent -> type.get().equals(fluent.type()) || fluent.owns(type.get()))
                .map(Fluent::client).findFirst()
                .orElse(type.get().equals(REST_TEMPLATE) || type.get().equals(REST_OPERATIONS) ? "RestTemplate" : null);
        return Optional.ofNullable(client).map(name -> name + "." + call.name() + "()");
    }

    private Optional<Egress> fluent(Fluent fluent, JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        if (!invoke.getMethodSignature().getName().equals("uri")) {
            return Optional.empty();
        }
        // Each uri(..) takes the URI first, on the spec of the request it builds: an interface's (so an instance's).
        Local spec = ((AbstractInstanceInvokeExpr) invoke).getBase();
        String httpMethod = httpMethod(fluent, caller, spec).orElse("*");
        // uri(function), or uri(template, function), whose function builds on the template.
        Optional<UriFunction> function = uriFunction(caller, invoke.getArg(invoke.getArgCount() - 1));
        String why = function.map(UriFunction::unread).orElse(null);
        boolean otherHost = function.map(UriFunction::otherHost).orElse(false);
        Optional<Url> url = Optional.empty();
        if (invoke.getArgCount() > 1 || function.isEmpty()) {
            url = templateUrl(caller, invoke);
            if (url.isEmpty()) {
                // A whole URL AuthTracer can't read may name its own host.
                why = UnreadCalls.origin(caller, invoke.getArg(0));
                otherHost = true;
            }
        }
        if (why != null) {
            // Decision 0082.
            BaseUrl base = otherHost ? BaseUrl.UNKNOWN : url.map(Url::baseUrl).filter(found -> found != BaseUrl.UNKNOWN)
                    .orElseGet(() -> fluentBaseUrl(fluent, caller, spec));
            return Optional.of(withCredentials(unread.egress(fluent.client(), httpMethod, "path", base.value(),
                    base.expression(), caller, stmt, why, response(fluent, caller, stmt).orElse(null)), caller,
                    clientOf(fluent, caller, spec)));
        }
        Optional<Url> template = url;
        Url read = function.map(found -> template.map(given -> new Url(given.baseUrl(), found.path().equals("/")
                ? given.path() : joinPath(given.path(), found.path()), given.query()))
                .orElse(new Url(BaseUrl.UNKNOWN, found.path()))).orElseGet(template::get);
        Url target = otherHost ? new Url(BaseUrl.UNKNOWN, read.path(), read.query())
                : read.baseUrl() != BaseUrl.UNKNOWN ? read
                        : rebased(fluentBaseUrl(fluent, caller, spec), read.path(), read.query());
        return Optional.of(withCredentials(Egress.of(fluent.client(), httpMethod, target.path(),
                target.baseUrl().value(), target.baseUrl().expression(), MethodNames.codeRef(caller.getSignature(),
                        stmt), response(fluent, caller, stmt).orElse(null)).withQuery(target.query()), caller,
                clientOf(fluent, caller, spec)));
    }

    /**
     * The type the response is read into: the response spec's next body call (e.g. {@code body(...)},
     * {@code bodyToMono(...)}) after the {@code uri} call, with a class literal or a
     * {@code ParameterizedTypeReference} subclass. Each takes the type, and only it.
     */
    @Supports(Feature.FIELD_LINEAGE)
    private Optional<Payload> response(Fluent fluent, JavaSootMethod caller, Stmt uriStmt) {
        List<Stmt> stmts = caller.getBody().getStmts();
        for (int i = stmts.indexOf(uriStmt) + 1; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            String declaring = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.get().getMethodSignature().getName();
            if (!fluent.owns(declaring)) {
                continue;
            }
            if (name.equals("uri")) {
                return Optional.empty();
            }
            boolean many = fluent.manyBodies().contains(name);
            if (declaring.equals(fluent.responseSpec()) && (many || fluent.bodies().contains(name))) {
                return payload(caller, invoke.get().getArg(0), many);
            }
        }
        return Optional.empty();
    }

    /**
     * {@code webClient.get().retrieve()}: a request that never calls {@code uri(..)} goes to the client's base URL.
     * Read at {@code retrieve()}/{@code exchange..()}, following the chain back to the {@code get()}/{@code post()}/...
     * call.
     */
    private Optional<Egress> withoutUri(Fluent fluent, JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        if (!SENDS.contains(invoke.getMethodSignature().getName())) {
            return Optional.empty();
        }
        // The specs' retrieve() and exchange..(..) are an interface's.
        Local receiver = ((AbstractInstanceInvokeExpr) invoke).getBase();
        for (int depth = 0; depth < MAX_CHAIN; depth++) {
            Optional<AbstractInvokeExpr> definition = Locals.definition(caller.getBody(), receiver)
                    .filter(AbstractInvokeExpr.class::isInstance).map(AbstractInvokeExpr.class::cast);
            if (definition.isEmpty() || definition.get().getMethodSignature().getName().equals("uri")) {
                return Optional.empty();
            }
            String owner = definition.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            Optional<String> httpMethod = requestMethod(fluent, caller, definition.get());
            if (httpMethod.isPresent()) {
                Url target = rebased(fluentBaseUrl(fluent, caller, receiver), "/", null);
                // get(), post(), ... are the client's instance methods.
                return Optional.of(withCredentials(Egress.of(fluent.client(), httpMethod.get(), target.path(),
                        target.baseUrl().value(), target.baseUrl().expression(),
                        MethodNames.codeRef(caller.getSignature(), stmt), response(fluent, caller, stmt).orElse(null)),
                        caller, Optional.of(((AbstractInstanceInvokeExpr) definition.get()).getBase())));
            }
            if (!(definition.get() instanceof AbstractInstanceInvokeExpr previous) || !fluent.owns(owner)) {
                return Optional.empty();
            }
            receiver = previous.getBase();
        }
        return Optional.empty();
    }

    /**
     * Decision 0031: a GraphQL request, read where it is sent ({@code retrieve..(path)}, {@code execute..()}) and
     * followed back to its {@code document(..)} (a constant) or {@code documentName(..)} (a
     * {@code graphql-documents/} resource). The Egress is the operation and the root field it reads, e.g.
     * {@code QUERY person}, so it links to the called service's GraphQL Ingress; with no document to read, any
     * operation on the field the response path names.
     */
    private Optional<Egress> graphQl(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        String path = invoke.getArgCount() == 1 ? constant(caller, invoke.getArg(0)).orElse(null) : null;
        Optional<String> document = Optional.empty();
        Value documentArgument = null;
        // The request spec's, an interface's.
        Local receiver = ((AbstractInstanceInvokeExpr) invoke).getBase();
        for (int depth = 0; depth < MAX_CHAIN && document.isEmpty(); depth++) {
            Optional<AbstractInvokeExpr> definition = Locals.definition(caller.getBody(), receiver)
                    .filter(AbstractInvokeExpr.class::isInstance).map(AbstractInvokeExpr.class::cast);
            if (definition.isEmpty() || !(definition.get() instanceof AbstractInstanceInvokeExpr previous)) {
                break;
            }
            String name = definition.get().getMethodSignature().getName();
            if ((name.equals("document") || name.equals("documentName")) && definition.get().getArgCount() == 1) {
                documentArgument = definition.get().getArg(0);
                Optional<String> argument = constant(caller, documentArgument);
                document = name.equals("document") ? argument : argument.flatMap(this::namedDocument);
                break;
            }
            receiver = previous.getBase();
        }
        Optional<GraphQlDocuments.Operation> operation = document.flatMap(GraphQlDocuments::firstOperation);
        Optional<String> field = operation.flatMap(found -> found.field(path))
                .or(() -> Optional.ofNullable(path).map(key -> key.split("[.\\[]", 2)[0]));
        // url(..) on the client's builder, here or in the @Bean method that builds the client (the client type has
        // no factory method that takes a URL), else the RestClient's or WebClient's base URL.
        BaseUrl baseUrl = GRAPHQL_BUILDERS.stream()
                .map(builder -> classBaseUrl(caller, "GraphQlClient " + builder, builder, "url",
                        builder.substring(0, builder.length() - "$Builder".length()), "url"))
                .filter(found -> found != BaseUrl.UNKNOWN).findFirst()
                .orElseGet(() -> FLUENT.stream().map(fluent -> classBaseUrl(caller, fluent.client(),
                        fluent.builder(), "baseUrl", fluent.type(), "create"))
                        .filter(found -> found != BaseUrl.UNKNOWN).findFirst().orElse(BaseUrl.UNKNOWN));
        if (baseUrl.value() != null) {
            // The client's URL is the GraphQL endpoint; the service is its scheme, host and port.
            baseUrl = new BaseUrl(split(baseUrl.value()).baseUrl().value(), baseUrl.expression());
        }
        String type = operation.map(GraphQlDocuments.Operation::type).orElse("*");
        if (field.isEmpty()) {
            // Decision 0082.
            String why = (documentArgument == null ? "no document" : "a document from "
                    + UnreadCalls.origin(caller, documentArgument)) + " and " + (invoke.getArgCount() == 1
                            ? "a response path from " + UnreadCalls.origin(caller, invoke.getArg(0))
                            : "no response path");
            return Optional.of(withCredentials(unread.egress("GraphQlClient", type, "field", baseUrl.value(),
                    baseUrl.expression(), caller, stmt, why, graphQlResponse(caller, stmt).orElse(null)), caller));
        }
        return Optional.of(withCredentials(Egress.of("GraphQlClient", type, field.get(), baseUrl.value(),
                baseUrl.expression(), MethodNames.codeRef(caller.getSignature(), stmt),
                graphQlResponse(caller, stmt).orElse(null)), caller));
    }

    /**
     * Decision 0045: {@code requester.route("profile.{name}", name)...retrieveMono(Profile.class)}, an RSocket request
     * to the route, at the {@code tcp(host, port)} (constants or {@code @Value}s) or {@code websocket(uri)} the
     * requester is built with (in the
     * calling class or a {@code @Bean} method), authenticated with the {@code UsernamePasswordMetadata} built there
     * (fixed credentials), a {@code BearerTokenMetadata} (a token AuthTracer can't follow), or nothing.
     */
    private Optional<Egress> rsocket(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        List<JavaSootMethod> builders = new ArrayList<>();
        context.findClass(caller.getDeclaringClassType()).ifPresent(cls -> builders.addAll(cls.getMethods()));
        builders.addAll(SpringBeans.beanMethods(context, RSOCKET_REQUESTER));
        String baseUrl = null;
        Credentials credentials = Credentials.NONE;
        String via = null;
        for (JavaSootMethod method : builders) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt candidate : method.getBody().getStmts()) {
                if (candidate instanceof AbstractDefinitionStmt definition
                        && definition.getRightOp() instanceof JNewExpr created
                        && created.getType().getFullyQualifiedName().startsWith(RSOCKET_SECURITY_METADATA)) {
                    String type = created.getType().getClassName();
                    if (type.equals("UsernamePasswordMetadata")) {
                        credentials = Credentials.STATIC;
                        via = type;
                    }
                    else if (type.equals("BearerTokenMetadata") && credentials == Credentials.NONE) {
                        credentials = Credentials.UNKNOWN;
                        via = type;
                    }
                }
                Optional<AbstractInvokeExpr> call = Locals.invoke(candidate);
                if (baseUrl != null || call.isEmpty() || !call.get().getMethodSignature().getDeclClassType()
                        .getFullyQualifiedName().equals(RSOCKET_REQUESTER + "$Builder")) {
                    continue;
                }
                // The builder's only tcp(host, port) and websocket(uri).
                String name = call.get().getMethodSignature().getName();
                if (name.equals("tcp")) {
                    String host = baseUrlValue(method, call.get().getArg(0)).value();
                    String port = call.get().getArg(1) instanceof IntConstant constant
                            ? String.valueOf(constant.getValue()) : baseUrlValue(method, call.get().getArg(1)).value();
                    if (host != null && port != null) {
                        baseUrl = "tcp://" + host + ":" + port;
                    }
                }
                else if (name.equals("websocket")) {
                    baseUrl = url(method, call.get().getArg(0)).map(Url::baseUrl).map(BaseUrl::value).orElse(null);
                }
            }
        }
        // route(String route, Object... vars), its only form.
        Optional<String> route = constant(caller, invoke.getArg(0));
        Payload response = rsocketResponse(caller, stmt).orElse(null);
        if (route.isEmpty()) {
            // Decision 0082.
            return Optional.of(unread.egress("RSocketRequester", RSocketMappings.RSOCKET, "route", baseUrl, null,
                    caller, stmt, UnreadCalls.origin(caller, invoke.getArg(0)), response)
                    .withCredentials(credentials, via));
        }
        return Optional.of(Egress.of("RSocketRequester", RSocketMappings.RSOCKET, route.get(), baseUrl, null,
                MethodNames.codeRef(caller.getSignature(), stmt), response).withCredentials(credentials, via));
    }

    /**
     * The JDK's {@code httpClient.send(request, ..)} (or {@code sendAsync}): the request's builder chain, followed back
     * from {@code build()}, gives the URI ({@code HttpRequest.newBuilder(uri)} or {@code uri(..)}) and the method
     * (the last of {@code GET()}, {@code POST(..)}, ..., {@code method("PATCH", ..)}, {@code *} when that method
     * isn't a constant; by default {@code GET}).
     */
    private Optional<Egress> jdkHttpClient(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        String name = invoke.getMethodSignature().getName();
        // send(request, handler) and sendAsync(request, handler[, pushPromiseHandler]).
        if (!(name.equals("send") || name.equals("sendAsync")) || !(invoke.getArg(0) instanceof Local request)) {
            return Optional.empty();
        }
        String method = null;
        Optional<Url> url = Optional.empty();
        Value unreadUrl = null;
        // Where the chain goes back to code AuthTracer doesn't see: a request or builder from elsewhere.
        Local unfollowed = null;
        Local current = request;
        for (int depth = 0; depth < MAX_CHAIN * 2 && current != null; depth++) {
            Optional<Value> definition = Locals.definition(caller.getBody(), current);
            if (definition.isEmpty() || !(definition.get() instanceof AbstractInvokeExpr call)) {
                unfollowed = current;
                break;
            }
            String step = call.getMethodSignature().getName();
            if (method == null && JDK_METHODS.contains(step)) {
                method = step;
            }
            else if (method == null && step.equals("method") && call.getArgCount() >= 1) {
                // Not GET when it isn't a constant: any method.
                method = constant(caller, call.getArg(0)).orElse("*");
            }
            if (url.isEmpty() && unreadUrl == null && (step.equals("uri") || step.equals("newBuilder"))
                    && call.getArgCount() == 1) {
                url = url(caller, call.getArg(0));
                unreadUrl = url.isEmpty() ? call.getArg(0) : null;
            }
            current = call instanceof AbstractInstanceInvokeExpr instance ? instance.getBase() : null;
        }
        // Built elsewhere, it may have any method.
        method = method != null ? method : unfollowed == null ? "GET" : "*";
        if (url.isEmpty()) {
            // Decision 0082.
            String why = unreadUrl != null ? UnreadCalls.origin(caller, unreadUrl)
                    : "a request" + (unfollowed == request ? "" : " builder") + " from "
                            + UnreadCalls.origin(caller, unfollowed);
            return Optional.of(withCredentials(unread.egress("HttpClient", method, "URL", null, null, caller, stmt,
                    why, null), caller));
        }
        return Optional.of(withCredentials(Egress.of("HttpClient", method,
                url.get().path(), url.get().baseUrl().value(), url.get().baseUrl().expression(),
                MethodNames.codeRef(caller.getSignature(), stmt), null).withQuery(url.get().query()), caller));
    }

    /**
     * The next {@code retrieveMono(..)}/{@code retrieveFlux(..)} after the route, before the next request's route or a
     * {@code send()}.
     */
    @Supports(Feature.FIELD_LINEAGE)
    private Optional<Payload> rsocketResponse(JavaSootMethod caller, Stmt routeStmt) {
        List<Stmt> stmts = caller.getBody().getStmts();
        for (int i = stmts.indexOf(routeStmt) + 1; i < stmts.size(); i++) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmts.get(i));
            if (invoke.isEmpty()) {
                continue;
            }
            String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.get().getMethodSignature().getName();
            // route(..) is the requester's own; the rest, its request and retrieve specs'.
            if (owner.equals(RSOCKET_REQUESTER) && name.equals("route") || owner.startsWith(RSOCKET_REQUESTER + "$")
                    && name.equals("send")) {
                return Optional.empty();
            }
            // Each takes the type, and only it.
            if (owner.startsWith(RSOCKET_REQUESTER + "$")
                    && (name.equals("retrieveMono") || name.equals("retrieveFlux"))) {
                return payload(caller, invoke.get().getArg(0), name.equals("retrieveFlux"));
            }
        }
        return Optional.empty();
    }

    /**
     * The type the response path is read into: the next {@code toEntity(..)}/{@code toEntityList(..)}.
     */
    @Supports(Feature.FIELD_LINEAGE)
    private Optional<Payload> graphQlResponse(JavaSootMethod caller, Stmt sendStmt) {
        List<Stmt> stmts = caller.getBody().getStmts();
        for (int i = stmts.indexOf(sendStmt) + 1; i < stmts.size(); i++) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmts.get(i));
            if (invoke.isEmpty() || !invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                    .startsWith(GRAPHQL_CLIENT + "GraphQlClient$Retrieve")) {
                continue;
            }
            // The retrieve specs' only methods, toEntity(..) and toEntityList(..), each take the type, and only it.
            return payload(caller, invoke.get().getArg(0),
                    invoke.get().getMethodSignature().getName().equals("toEntityList"));
        }
        return Optional.empty();
    }

    private Optional<String> namedDocument(String name) {
        for (Path dir : context.input().resourceDirs()) {
            for (String pattern : GRAPHQL_DOCUMENTS) {
                Path file = dir.resolve(pattern.formatted(name));
                if (Files.isRegularFile(file)) {
                    try {
                        return Optional.of(Files.readString(file));
                    }
                    catch (IOException ex) {
                        return Optional.empty();
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * A string constant, directly or through a local it was assigned to.
     */
    @Supports({Feature.SERVICE_CALLS, Feature.CALL_PATHS})
    static Optional<String> constant(JavaSootMethod caller, Value value) {
        if (value instanceof StringConstant constant) {
            return Optional.of(constant.getValue());
        }
        return value instanceof Local local ? Locals.definition(caller.getBody(), local)
                .filter(StringConstant.class::isInstance).map(found -> ((StringConstant) found).getValue())
                : Optional.empty();
    }

    /**
     * Follows {@code uri(...)}'s receiver back to the {@code get()}/{@code post()}/... call that created it.
     */
    private static Optional<String> httpMethod(Fluent fluent, JavaSootMethod caller, Local receiver) {
        return Locals.definition(caller.getBody(), receiver)
                .filter(AbstractInvokeExpr.class::isInstance)
                .map(AbstractInvokeExpr.class::cast)
                .flatMap(definition -> requestMethod(fluent, caller, definition));
    }

    /**
     * The method of the request a call on the client starts: {@code get()}, {@code post()}, ... or
     * {@code method(HttpMethod.PATCH)}, {@code *} when its method isn't a constant.
     */
    private static Optional<String> requestMethod(Fluent fluent, JavaSootMethod caller, AbstractInvokeExpr call) {
        if (!call.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(fluent.type())) {
            return Optional.empty();
        }
        String name = call.getMethodSignature().getName();
        if (name.equals("method")) {
            return Optional.of(httpMethodConstant(caller, call.getArg(0)).orElse("*"));
        }
        return HTTP_METHODS.contains(name) ? Optional.of(name.toUpperCase(Locale.ROOT)) : Optional.empty();
    }

    /**
     * {@code getForObject(url, Type.class, ..)}, {@code exchange(url, HttpMethod.GET, entity, Type.class)} and the
     * other methods, with a {@code String} or {@code URI} URL; and {@code exchange(requestEntity, Type.class)}.
     */
    private Optional<Egress> restTemplate(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke) {
        String name = invoke.getMethodSignature().getName();
        String httpMethod = REST_TEMPLATE_METHODS.get(name);
        if (httpMethod == null) {
            return Optional.empty();
        }
        // Each of them takes the URL first (a String or a URI), or a RequestEntity.
        if (invoke.getMethodSignature().getParameterTypes().getFirst().toString().equals(REQUEST_ENTITY)) {
            Payload response = payload(caller, invoke.getArg(1), false).orElse(null);
            return Optional.of(requestEntity(caller, invoke.getArg(0)).map(request -> restTemplateCall(caller, stmt,
                    invoke, request.httpMethod(), request.url(), response))
                    // Decision 0082: an entity's URL is a whole URI, so its host isn't known either.
                    .orElseGet(() -> withCredentials(unread.egress("RestTemplate", "*", "URL", null, null, caller,
                            stmt, "a RequestEntity from " + UnreadCalls.origin(caller, invoke.getArg(0)), response),
                            caller, template(invoke))));
        }
        if (httpMethod.isEmpty()) {
            // exchange(url, method, ..) and execute(url, method, ..).
            httpMethod = httpMethodConstant(caller, invoke.getArg(1)).orElse("*");
        }
        Optional<Url> url = templateUrl(caller, invoke);
        Payload response = null;
        if (!Set.of("headForHeaders", "postForLocation", "put", "delete", "optionsForAllow", "execute")
                .contains(name)) {
            for (int i = 1; i < invoke.getArgCount() && response == null; i++) {
                Value argument = invoke.getArg(i);
                boolean responseType = argument instanceof ClassConstant
                        || name.equals("exchange") && i == 3 && argument instanceof Local;
                if (responseType) {
                    response = payload(caller, argument, false).orElse(null);
                }
            }
        }
        if (url.isEmpty()) {
            // Decision 0082: a whole URL, which may name its own host.
            return Optional.of(withCredentials(unread.egress("RestTemplate", httpMethod, "URL", null, null, caller,
                    stmt, UnreadCalls.origin(caller, invoke.getArg(0)), response), caller, template(invoke)));
        }
        return Optional.of(restTemplateCall(caller, stmt, invoke, httpMethod, url.get(), response));
    }

    private Egress restTemplateCall(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke, String httpMethod,
            Url url, Payload response) {
        Url target = url.baseUrl() != BaseUrl.UNKNOWN ? url : rebased(restTemplateBaseUrl(caller, invoke), url.path(),
                url.query());
        return withCredentials(Egress.of("RestTemplate", httpMethod, target.path(), target.baseUrl().value(),
                target.baseUrl().expression(), MethodNames.codeRef(caller.getSignature(), stmt), response)
                .withQuery(target.query()), caller, template(invoke));
    }

    /**
     * The template a call is made on: RestTemplate's and RestOperations' request methods are all instance methods.
     */
    private static Optional<Local> template(AbstractInvokeExpr invoke) {
        return Optional.of(((AbstractInstanceInvokeExpr) invoke).getBase());
    }

    /**
     * The root URI of the template the call is made on: the one its field was built with
     * ({@code this.europe = builder.rootUri(url).build()}), else the class's.
     */
    private BaseUrl restTemplateBaseUrl(JavaSootMethod caller, AbstractInvokeExpr invoke) {
        // RestTemplate's and RestOperations' request methods are all instance methods.
        Local template = ((AbstractInstanceInvokeExpr) invoke).getBase();
        if (Locals.definition(caller.getBody(), template).orElse(null) instanceof JFieldRef field) {
            Optional<BaseUrl> built = fieldBaseUrl(field.getFieldSignature(), REST_TEMPLATE_BUILDER, "rootUri", null,
                    null);
            if (built.isPresent()) {
                return built.get();
            }
        }
        return classBaseUrl(caller, "RestTemplate", REST_TEMPLATE_BUILDER, "rootUri", null, null);
    }

    /**
     * A {@code RequestEntity} built where it is sent: {@code RequestEntity.post(uri)} or
     * {@code RequestEntity.method(HttpMethod.PATCH, uri)}, then its headers and body.
     */
    private Optional<Request> requestEntity(JavaSootMethod caller, Value entity) {
        Value current = entity;
        for (int depth = 0; depth < MAX_CHAIN && current instanceof Local local; depth++) {
            Optional<Value> definition = Locals.definition(caller.getBody(), local);
            if (definition.orElse(null) instanceof JCastExpr cast) {
                // header(..) returns the builder's type variable, which javac casts back.
                current = cast.getOp();
                continue;
            }
            if (definition.orElse(null) instanceof JNewExpr created
                    && created.getType().getFullyQualifiedName().equals(REQUEST_ENTITY)) {
                return constructedEntity(caller, local);
            }
            Optional<AbstractInvokeExpr> call = definition
                    .filter(AbstractInvokeExpr.class::isInstance).map(AbstractInvokeExpr.class::cast)
                    .filter(found -> found.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                            .startsWith(REQUEST_ENTITY));
            if (call.isEmpty()) {
                return Optional.empty();
            }
            if (call.get() instanceof AbstractInstanceInvokeExpr builder) {
                current = builder.getBase();
                continue;
            }
            // RequestEntity's static methods are its builders: get(uri), post(uri), ..., method(method, uri).
            String name = call.get().getMethodSignature().getName();
            boolean byMethod = name.equals("method");
            String httpMethod = byMethod ? httpMethodConstant(caller, call.get().getArg(0)).orElse("*")
                    : name.toUpperCase(Locale.ROOT);
            return url(caller, call.get().getArg(byMethod ? 1 : 0)).map(url -> new Request(httpMethod, url));
        }
        return Optional.empty();
    }

    /**
     * {@code new RequestEntity<>([body,] [headers,] HttpMethod.POST, uri[, type])}: each constructor takes the method
     * and then the URI.
     */
    private Optional<Request> constructedEntity(JavaSootMethod caller, Local entity) {
        for (Stmt stmt : caller.getBody().getStmts()) {
            if (Locals.invoke(stmt).orElse(null) instanceof AbstractInstanceInvokeExpr init
                    && init.getBase().equals(entity) && init.getMethodSignature().getName().equals("<init>")) {
                int method = init.getMethodSignature().getParameterTypes().stream().map(Object::toString).toList()
                        .indexOf(HTTP_METHOD);
                if (method < 0 || method + 1 >= init.getArgCount()) {
                    return Optional.empty();
                }
                String httpMethod = httpMethodConstant(caller, init.getArg(method)).orElse("*");
                return url(caller, init.getArg(method + 1)).map(url -> new Request(httpMethod, url));
            }
        }
        return Optional.empty();
    }

    private static Optional<String> httpMethodConstant(JavaSootMethod caller, Value argument) {
        Optional<Value> value = argument instanceof Local local ? Locals.definition(caller.getBody(), local)
                : Optional.of(argument);
        Optional<GroovyCalls.Call> groovy = value.filter(AbstractInvokeExpr.class::isInstance)
                .flatMap(call -> GroovyCalls.of((AbstractInvokeExpr) call));
        if (groovy.isPresent()) {
            // Dynamic Groovy's HttpMethod.GET: the class's static property.
            return groovy.filter(call -> call.type().equals("getProperty")
                    && call.staticOwner().filter(HTTP_METHOD::equals).isPresent()).map(GroovyCalls.Call::name);
        }
        return value.filter(JStaticFieldRef.class::isInstance).map(JStaticFieldRef.class::cast)
                .filter(field -> field.getFieldSignature().getDeclClassType().getFullyQualifiedName()
                        .equals(HTTP_METHOD))
                .map(field -> field.getFieldSignature().getName());
    }

    /**
     * A call to an HTTP interface method: the path from {@code @GetExchange}/{@code @HttpExchange} on the method
     * and its interface, the base URL from an absolute {@code url}, or from Spring Boot's
     * {@code spring.http.serviceclient.<group>.base-url} for the {@code @ImportHttpServices} group.
     */
    private Optional<Egress> httpInterface(JavaSootMethod caller, Stmt stmt, MethodSignature called) {
        Optional<JavaSootMethod> target = context.findMethod(called);
        Optional<JavaSootClass> owner = context.findClass(called.getDeclClassType());
        if (target.isEmpty() || owner.isEmpty() || !owner.get().isInterface()) {
            return Optional.empty();
        }
        for (Map.Entry<String, String> exchange : EXCHANGES) {
            var annotation = context.findAnnotation(target.get(), exchange.getKey());
            if (annotation.isEmpty()) {
                continue;
            }
            String httpMethod = exchange.getValue().equals("*")
                    ? Annotations.string(annotation.get(), "method").filter(method -> !method.isEmpty())
                            .map(method -> method.toUpperCase(Locale.ROOT)).orElse("*")
                    : exchange.getValue();
            String prefix = context.findAnnotation(owner.get(), HTTP_EXCHANGE).map(this::exchangeUrl).orElse("");
            Url url = split(exchangeUrl(prefix, exchangeUrl(annotation.get())));
            Optional<Wiring> wiring = proxyFactoryMethod(owner.get());
            BaseUrl baseUrl = url.baseUrl() != BaseUrl.UNKNOWN ? url.baseUrl() : serviceGroupBaseUrl(owner.get());
            if (baseUrl == BaseUrl.UNKNOWN) {
                baseUrl = wiring.map(this::proxyFactoryBaseUrl).orElse(BaseUrl.UNKNOWN);
            }
            EgressCredentials.Found found = credentials.forHttpInterface(owner.get(), target.get(),
                    wiring.map(Wiring::method),
                    serviceGroup(owner.get()).map(imported -> Annotations.string(imported, "clientType")
                            .orElse("REST_CLIENT")));
            Url rebased = rebased(baseUrl, url.path().isEmpty() ? "/" : url.path(), null);
            return Optional.of(credentialed(Egress.of("HTTP interface", httpMethod, rebased.path(),
                    rebased.baseUrl().value(), rebased.baseUrl().expression(),
                    MethodNames.codeRef(caller.getSignature(), stmt), Payloads.returnedBy(context, called).orElse(null)),
                    found));
        }
        return Optional.empty();
    }

    /**
     * An {@code @HttpExchange} URL, its placeholders resolved as the proxy factory's embedded value resolver does.
     */
    private String exchangeUrl(AnnotationUsage annotation) {
        return context.properties().resolveKnown(Annotations.string(annotation, "value")
                .filter(value -> !value.isEmpty()).or(() -> Annotations.string(annotation, "url")).orElse(""));
    }

    /**
     * The interface's URL and the method's, as Spring 7's {@code HttpServiceMethod} joins them: with a {@code /}
     * between them when neither has one ({@code /api} and {@code users} are {@code /api/users}).
     */
    private static String exchangeUrl(String type, String method) {
        if (type.isEmpty() || method.isEmpty()) {
            return type + method;
        }
        return !type.endsWith("/") && !method.startsWith("/") ? type + "/" + method : type + method;
    }

    /**
     * The base URL of the group an {@code @ImportHttpServices} annotation puts the interface in ({@code default} when
     * unnamed).
     */
    private BaseUrl serviceGroupBaseUrl(JavaSootClass service) {
        return serviceGroup(service).map(imported -> {
            String group = Annotations.string(imported, "group").filter(g -> !g.isEmpty()).orElse("default");
            String key = "spring.http.serviceclient." + group + ".base-url";
            return new BaseUrl(context.properties().get(key).orElse(null), "${" + key + "}");
        }).orElse(BaseUrl.UNKNOWN);
    }

    /**
     * The {@code @ImportHttpServices} that puts the interface in a group, if one does.
     */
    private Optional<AnnotationUsage> serviceGroup(JavaSootClass service) {
        return serviceGroups.computeIfAbsent(service.getType().getFullyQualifiedName(),
                name -> serviceGroup(name, service.getType().getPackageName().getName()));
    }

    private Optional<AnnotationUsage> serviceGroup(String name, String pkg) {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (AnnotationUsage imported : repeatable(cls, IMPORT_HTTP_SERVICES)) {
                if (imports(imported, name, pkg)) {
                    return Optional.of(imported);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * An HTTP interface wired by hand: {@code HttpServiceProxyFactory...createClient(Service.class)}, with the base
     * URL of the client built in the same method ({@code baseUrl(..)}, {@code RestClient.create(..)},
     * {@code new DefaultUriBuilderFactory(..)}); in a helper given the type, from what its caller passes it.
     */
    private BaseUrl proxyFactoryBaseUrl(Wiring wiring) {
        for (Stmt stmt : wiring.method().getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get().getArgCount() == 1 && configuresBaseUrl(invoke.get())) {
                Value argument = invoke.get().getArg(0);
                OptionalInt parameter = wiring.call() != null && argument instanceof Local local
                        ? Locals.parameterIndex(wiring.method().getBody(), local) : OptionalInt.empty();
                return parameter.isPresent()
                        ? resolve(wiring.caller(), wiring.call().getArg(parameter.getAsInt()))
                        : resolve(wiring.method(), argument);
            }
        }
        return BaseUrl.UNKNOWN;
    }

    /**
     * Where an HTTP interface is wired by hand: the method that calls {@code createClient(Service.class)}, or a
     * generic helper that calls {@code createClient(type)} with the type its caller passes it
     * ({@code create(OrdersApi.class, url)}).
     *
     * @param caller the method that calls the helper with the interface's type, when the wiring is a helper
     * @param call that call
     */
    private record Wiring(JavaSootMethod method, JavaSootMethod caller, AbstractInvokeExpr call) {
    }

    /**
     * Where the HTTP interface is wired by hand, if it is.
     */
    private Optional<Wiring> proxyFactoryMethod(JavaSootClass service) {
        return proxyFactoryMethods.computeIfAbsent(service.getType().getFullyQualifiedName(),
                this::proxyFactoryMethod);
    }

    private Optional<Wiring> proxyFactoryMethod(String service) {
        String descriptor = "L" + service.replace('.', '/') + ";";
        Map<JavaSootMethod, Integer> helpers = new LinkedHashMap<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt).filter(call -> call.getArgCount() == 1
                            && call.getMethodSignature().getName().equals("createClient")
                            && call.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                    .equals(PROXY_FACTORY));
                    if (invoke.isEmpty()) {
                        continue;
                    }
                    if (invoke.get().getArg(0) instanceof ClassConstant type && type.getValue().equals(descriptor)) {
                        return Optional.of(new Wiring(method, null, null));
                    }
                    OptionalInt parameter = invoke.get().getArg(0) instanceof Local local
                            ? Locals.parameterIndex(method.getBody(), local) : OptionalInt.empty();
                    parameter.ifPresent(index -> helpers.put(method, index));
                }
            }
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                for (Stmt stmt : method.hasBody() ? method.getBody().getStmts() : List.<Stmt>of()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    Optional<JavaSootMethod> helper = invoke.flatMap(call -> helpers.keySet().stream()
                            .filter(found -> found.getSignature().equals(call.getMethodSignature())).findFirst());
                    if (helper.isPresent() && invoke.get().getArg(helpers.get(helper.get())) instanceof ClassConstant
                            type && type.getValue().equals(descriptor)) {
                        return Optional.of(new Wiring(helper.get(), method, invoke.get()));
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static boolean configuresBaseUrl(AbstractInvokeExpr invoke) {
        String declaring = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        return FLUENT.stream().anyMatch(fluent -> declaring.equals(fluent.builder()) && name.equals("baseUrl")
                || declaring.equals(fluent.type()) && name.equals("create"))
                || declaring.equals(REST_TEMPLATE_BUILDER) && name.equals("rootUri")
                || declaring.equals(URI_BUILDER_FACTORY) && name.equals("<init>");
    }

    @Supports(Feature.FIELD_LINEAGE)
    private Optional<Payload> payload(JavaSootMethod caller, Value argument, boolean many) {
        if (argument instanceof ClassConstant type) {
            String descriptor = type.getValue();
            return Optional.of(new Payload(descriptor.substring(1, descriptor.length() - 1).replace('/', '.'), many));
        }
        if (argument instanceof Local local) {
            return Locals.created(caller.getBody(), local)
                    .flatMap(created -> context.classFiles().genericSuperclass(created.getFullyQualifiedName()))
                    .flatMap(generic -> Payloads.unwrap(context, generic, many));
        }
        return Optional.empty();
    }

    /**
     * A URL argument: a constant; text built from parts, such as {@code baseUrl + "/employees/" + id}
     * ({@link #textParts}), whose first part is the base URL and whose other variable parts are the values they hold
     * when AuthTracer knows them ({@code "http://" + host}, from a property), else path variables; a value from the
     * configuration ({@link ConfiguredValues}); or a {@code URI} from {@code URI.create}, {@code new URI} or a
     * {@code UriComponentsBuilder} chain. A {@code uri(builder -> builder.path(..)...)} function is read where it is
     * given ({@link #uriFunction}): every URL argument is a {@code String} or a {@code URI}.
     */
    private Optional<Url> url(JavaSootMethod caller, Value argument) {
        return url(caller, argument, 6);
    }

    private Optional<Url> url(JavaSootMethod caller, Value argument, int depth) {
        if (argument instanceof StringConstant constant) {
            return Optional.of(split(constant.getValue()));
        }
        if (!(argument instanceof Local local) || depth == 0) {
            return Optional.empty();
        }
        Value definition = Locals.definition(caller.getBody(), local).orElse(null);
        if (definition instanceof AbstractInvokeExpr call && !(definition instanceof JDynamicInvokeExpr)) {
            Optional<Url> uri = uriCall(caller, call, depth);
            if (uri.isPresent()) {
                return uri;
            }
        }
        if (definition instanceof JNewExpr created && created.getType().getFullyQualifiedName().equals(URI)) {
            // new URI(text): the constructor call follows the new.
            return caller.getBody().getStmts().stream()
                    .flatMap(stmt -> Locals.invoke(stmt).stream())
                    .filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                            && instance.getBase().equals(local) && invoke.getMethodSignature().getName().equals("<init>")
                            && invoke.getArgCount() == 1)
                    .findFirst().flatMap(init -> url(caller, init.getArg(0), depth - 1));
        }
        Optional<List<Object>> parts = definition == null ? Optional.empty() : textParts(caller, definition);
        if (parts.isPresent()) {
            return Optional.of(joined(caller, parts.get()));
        }
        BaseUrl base = baseUrlValue(caller, local);
        if (base == BaseUrl.UNKNOWN) {
            return Optional.empty();
        }
        if (base.value() != null && base.value().contains("://")) {
            // A whole URL in a property: https://host:8443/messages is the base and /messages, and one with no
            // path is the root.
            Url whole = split(base.value());
            return Optional.of(new Url(new BaseUrl(whole.baseUrl().value(), base.expression()), whole.path()));
        }
        return Optional.of(new Url(base, ""));
    }

    /**
     * A call's URL template, taken first, with what its URI variables give the scheme, host and port: Spring's
     * {@code UriComponents} expands {@code "http://{host}:8080/orders/{id}"} and {@code "{gateway}/orders"} (a leading
     * variable, which holds the base URL) from the call's variables, in order or by name from a {@code Map}. A host
     * AuthTracer doesn't know the value of is no base URL ({@link #split}).
     */
    private Optional<Url> templateUrl(JavaSootMethod caller, AbstractInvokeExpr invoke) {
        Value argument = invoke.getArg(0);
        Optional<String> template = constant(caller, argument);
        if (template.isEmpty() || !template.get().contains("{")) {
            return url(caller, argument);
        }
        int hostEnd = template.get().contains("://") ? template.get().indexOf('/', template.get().indexOf("://") + 3)
                : template.get().startsWith("{") ? template.get().indexOf('}') + 1 : 0;
        String host = hostEnd < 0 ? template.get() : template.get().substring(0, hostEnd);
        List<String> parameters = invoke.getMethodSignature().getParameterTypes().stream().map(Object::toString)
                .toList();
        String variables = parameters.isEmpty() ? "" : parameters.getLast();
        if (!host.contains("{") || !(variables.equals("java.lang.Object[]") || variables.equals("java.util.Map"))) {
            return url(caller, argument);
        }
        Map<Integer, Value> byPosition = variables.equals("java.util.Map") ? Map.of()
                : arrayElements(caller, invoke.getArg(invoke.getArgCount() - 1));
        Map<String, Value> byName = variables.equals("java.util.Map")
                ? mapEntries(caller, invoke.getArg(invoke.getArgCount() - 1)) : Map.of();
        StringBuilder expanded = new StringBuilder();
        // Where the host comes from, when a property gives it: http://${orders.host}:8080.
        StringBuilder expression = new StringBuilder();
        boolean configured = false;
        Matcher variable = URI_VARIABLE.matcher(host);
        int position = 0;
        while (variable.find()) {
            String name = variable.group(1).split(":", 2)[0];
            Value value = byName.isEmpty() ? byPosition.get(position++) : byName.get(name);
            BaseUrl known = value == null ? BaseUrl.UNKNOWN : baseUrlValue(caller, value);
            if (known.value() == null) {
                return url(caller, argument);
            }
            configured |= known.expression() != null;
            int start = expanded.length();
            variable.appendReplacement(expanded, Matcher.quoteReplacement(known.value()));
            expression.append(expanded, start, expanded.length() - known.value().length())
                    .append(known.expression() != null ? known.expression() : known.value());
        }
        variable.appendTail(expanded);
        expression.append(host.substring(Math.max(host.lastIndexOf('}') + 1, 0)));
        Url url = split(expanded + (hostEnd < 0 ? "" : template.get().substring(hostEnd)));
        return Optional.of(configured && url.baseUrl().value() != null ? new Url(new BaseUrl(url.baseUrl().value(),
                expression.toString()), url.path(), url.query()) : url);
    }

    /**
     * {@code Map.of("host", host, "id", id)}'s entries, by key.
     */
    private static Map<String, Value> mapEntries(JavaSootMethod caller, Value map) {
        Map<String, Value> entries = new HashMap<>();
        if (map instanceof Local local && Locals.definition(caller.getBody(), local).orElse(null)
                instanceof AbstractInvokeExpr call && call.getMethodSignature().getName().equals("of")
                && call.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals("java.util.Map")) {
            for (int i = 0; i + 1 < call.getArgCount(); i += 2) {
                int value = i + 1;
                constant(caller, call.getArg(i)).ifPresent(key -> entries.put(key, call.getArg(value)));
            }
        }
        return entries;
    }

    /**
     * A URL built from parts, constant text and values, in order: the first part, when it is a value, is the base
     * URL; the other values are the text they hold when AuthTracer knows it, else path variables.
     */
    private Url joined(JavaSootMethod caller, List<Object> parts) {
        StringBuilder path = new StringBuilder();
        BaseUrl baseUrl = BaseUrl.UNKNOWN;
        int values = 0;
        for (int i = 0; i < parts.size(); i++) {
            if (parts.get(i) instanceof String text) {
                path.append(text);
                continue;
            }
            Value part = (Value) parts.get(i);
            values++;
            if (i == 0) {
                baseUrl = baseUrlValue(caller, part);
            }
            else {
                String known = baseUrlValue(caller, part).value();
                path.append(known != null ? known : "{p" + values + "}");
            }
        }
        Url rest = split(path.toString());
        if (rest.baseUrl() == BaseUrl.UNKNOWN && baseUrl.value() != null) {
            // The base's own path joins the rest: "http://visits-service/" + "pets/visits".
            Url whole = split(baseUrl.value() + path);
            return new Url(new BaseUrl(whole.baseUrl().value(), baseUrl.expression()), whole.path(), whole.query());
        }
        return rest.baseUrl() != BaseUrl.UNKNOWN ? rest : new Url(baseUrl, rest.path(), rest.query());
    }

    /**
     * The parts of text the code builds: a concatenation ({@code base + "/orders/" + id}), a {@code StringBuilder}'s
     * {@code toString()} after its appends (chained or one by one), or {@code String.format(..)} and
     * {@code formatted(..)} with a constant format. Each part is a {@code String} or the {@link Value} it holds.
     */
    @Supports({Feature.SERVICE_CALLS, Feature.GATEWAY_ROUTES})
    static Optional<List<Object>> textParts(JavaSootMethod caller, Value definition) {
        if (definition instanceof JDynamicInvokeExpr concat
                && concat.getBootstrapMethodSignature().getName().equals("makeConcatWithConstants")
                && concat.getBootstrapArgs().getFirst() instanceof StringConstant recipe) {
            List<Object> parts = new ArrayList<>();
            StringBuilder literal = new StringBuilder();
            int dynamic = 0;
            int constants = 1;
            for (char c : recipe.getValue().toCharArray()) {
                if (c == '\u0001') {
                    flush(literal, parts);
                    parts.add(concat.getArg(dynamic++));
                }
                else if (c == '\u0002') {
                    literal.append(concat.getBootstrapArgs().get(constants++) instanceof StringConstant constant
                            ? constant.getValue() : "");
                }
                else {
                    literal.append(c);
                }
            }
            flush(literal, parts);
            return Optional.of(parts);
        }
        if (!(definition instanceof AbstractInvokeExpr call)) {
            return Optional.empty();
        }
        String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = call.getMethodSignature().getName();
        if (STRING_BUILDERS.contains(owner) && name.equals("toString") && call instanceof AbstractInstanceInvokeExpr
                instance) {
            return builderParts(caller, instance);
        }
        if (owner.equals(STRING) && (name.equals("format") || name.equals("formatted"))) {
            // format(String, Object...), format(Locale, String, Object...) and "..".formatted(Object...).
            Value format = call instanceof AbstractInstanceInvokeExpr instance ? instance.getBase()
                    : call.getArg(call.getArgCount() - 2);
            return constant(caller, format).flatMap(text -> formatParts(caller, text,
                    call.getArg(call.getArgCount() - 1)));
        }
        return Optional.empty();
    }

    private static void flush(StringBuilder literal, List<Object> parts) {
        if (!literal.isEmpty()) {
            parts.add(literal.toString());
            literal.setLength(0);
        }
    }

    /**
     * What a {@code StringBuilder} (or {@code StringBuffer}) holds at its {@code toString()}: what it is created with,
     * then each {@code append(..)} on it, in order. Anything else done to it ({@code insert}, {@code reverse}, ...) is
     * text AuthTracer doesn't follow.
     */
    private static Optional<List<Object>> builderParts(JavaSootMethod caller, AbstractInstanceInvokeExpr toString) {
        Local root = toString.getBase() instanceof Local local ? local : null;
        for (int depth = 0; depth < MAX_CHAIN * 4 && root != null; depth++) {
            Value definition = Locals.definition(caller.getBody(), root).orElse(null);
            if (definition instanceof JNewExpr) {
                break;
            }
            root = definition instanceof AbstractInstanceInvokeExpr append
                    && STRING_BUILDERS.contains(append.getMethodSignature().getDeclClassType().getFullyQualifiedName())
                    && append.getBase() instanceof Local base ? base : null;
        }
        if (root == null || Locals.created(caller.getBody(), root).isEmpty()) {
            return Optional.empty();
        }
        Set<Local> builder = new LinkedHashSet<>(Set.of(root));
        List<Object> parts = new ArrayList<>();
        for (Stmt stmt : caller.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty() || !(invoke.get() instanceof AbstractInstanceInvokeExpr call)
                    || !builder.contains(call.getBase())) {
                continue;
            }
            if (call == toString) {
                return Optional.of(parts);
            }
            String name = call.getMethodSignature().getName();
            if (name.equals("<init>") || name.equals("append")) {
                if (call.getArgCount() == 1 && !(name.equals("<init>")
                        && call.getMethodSignature().getParameterTypes().getFirst().toString().equals("int"))) {
                    parts.add(appended(call));
                }
                if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local result) {
                    builder.add(result);
                }
            }
            else {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
     * What an {@code append(..)} adds: a constant's text (a {@code char} as its character), else the value.
     */
    private static Object appended(AbstractInvokeExpr append) {
        Value argument = append.getArg(0);
        String type = append.getMethodSignature().getParameterTypes().getFirst().toString();
        if (argument instanceof StringConstant constant) {
            return constant.getValue();
        }
        if (argument instanceof IntConstant constant) {
            return type.equals("char") ? String.valueOf((char) constant.getValue()) : String.valueOf(constant.getValue());
        }
        return argument;
    }

    /**
     * {@code String.format}'s text: each specifier ({@code %s}, {@code %d}, {@code %2$s}, ...) the argument it
     * formats, {@code %%} a {@code %}.
     */
    private static Optional<List<Object>> formatParts(JavaSootMethod caller, String format, Value arguments) {
        Map<Integer, Value> values = arrayElements(caller, arguments);
        List<Object> parts = new ArrayList<>();
        StringBuilder literal = new StringBuilder();
        Matcher specifier = FORMAT_SPECIFIER.matcher(format);
        int next = 0;
        int end = 0;
        while (specifier.find()) {
            literal.append(format, end, specifier.start());
            end = specifier.end();
            String conversion = specifier.group(2);
            if (conversion.equals("%")) {
                literal.append('%');
                continue;
            }
            int index = specifier.group(1) != null ? Integer.parseInt(specifier.group(1)) - 1 : next++;
            Value value = values.get(index);
            if (value == null) {
                return Optional.empty();
            }
            flush(literal, parts);
            parts.add(value);
        }
        literal.append(format.substring(end));
        flush(literal, parts);
        return Optional.of(parts);
    }

    /**
     * The values a varargs call stores into its array, by index, as they are stored (locals not followed).
     */
    private static Map<Integer, Value> arrayElements(JavaSootMethod caller, Value array) {
        Map<Integer, Value> elements = new TreeMap<>();
        if (!(array instanceof Local local)) {
            return elements;
        }
        for (Stmt stmt : caller.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JArrayRef element
                    && element.getBase().equals(local) && element.getIndex() instanceof IntConstant index) {
                elements.put(index.getValue(), definition.getRightOp());
            }
        }
        return elements;
    }

    /**
     * {@code URI.create(..)}, {@code UriComponentsBuilder.fromUriString(base).path("/x/{id}")...toUri()} and the
     * other builder calls that only add a query, expand variables or build.
     */
    private Optional<Url> uriCall(JavaSootMethod caller, AbstractInvokeExpr call, int depth) {
        String declaring = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = call.getMethodSignature().getName();
        if (!(call instanceof AbstractInstanceInvokeExpr instance)) {
            boolean factory = declaring.equals(URI) && name.equals("create") || URI_BUILDERS.contains(declaring)
                    && Set.of("fromUriString", "fromHttpUrl", "fromPath", "fromUri").contains(name);
            if (declaring.equals("org.springframework.web.util.UriComponentsBuilder") && name.equals("newInstance")) {
                return Optional.of(new Url(BaseUrl.UNKNOWN, ""));
            }
            // Each takes the URL, and only it.
            return factory ? url(caller, call.getArg(0), depth - 1) : Optional.empty();
        }
        if (!URI_BUILDERS.contains(declaring) && !declaring.equals(URI)) {
            return Optional.empty();
        }
        Optional<Url> receiver = url(caller, instance.getBase(), depth - 1);
        if (URI_PASS_THROUGH.contains(name)) {
            return receiver;
        }
        if (name.equals("path") && call.getArg(0) instanceof StringConstant piece) {
            return receiver.map(url -> new Url(url.baseUrl(), joinPath(url.path(), piece.getValue())));
        }
        if (name.equals("pathSegment")) {
            return receiver.flatMap(url -> segments(caller, call.getArg(0))
                    .map(segments -> new Url(url.baseUrl(), joinPath(url.path(), segments))));
        }
        return Optional.empty();
    }

    /**
     * {@code pathSegment("orders", id)}'s segments, joined: a constant as it is, a value as a variable. Each value is
     * one segment, as Spring encodes the {@code /} in it.
     */
    private static Optional<String> segments(JavaSootMethod caller, Value array) {
        if (!(array instanceof Local local) || !(Locals.definition(caller.getBody(), local).orElse(null)
                instanceof JNewArrayExpr)) {
            return Optional.empty();
        }
        Map<Integer, Value> elements = arrayElements(caller, array);
        List<String> segments = new ArrayList<>();
        elements.forEach((index, value) -> segments.add(constant(caller, value).orElse("{p" + (index + 1) + "}")));
        return Optional.of(String.join("/", segments));
    }

    /**
     * What a {@code uri(..)} function does to the URI builder it is given.
     *
     * @param path the path it adds, {@code /} for none (it only adds a query); {@code null} when {@code unread} says
     *        what of it AuthTracer can't read
     * @param otherHost whether it sets the scheme, host or port: the request goes elsewhere than the base URL
     */
    private record UriFunction(String path, String unread, boolean otherHost) {
    }

    /**
     * {@code uri(builder -> builder.path("/accounts/{id}").build(id))}, a lambda or a method reference: the paths the
     * function adds, in order. A path that isn't a constant, a segment, or the builder handed to other code is a path
     * AuthTracer can't read.
     */
    private Optional<UriFunction> uriFunction(JavaSootMethod caller, Value argument) {
        Optional<ClassType> closure = argument instanceof Local local ? Locals.created(caller.getBody(), local)
                .filter(this::isClosure) : Optional.empty();
        if (closure.isPresent()) {
            // A Groovy closure Groovy coerces to the function: its doCall with the builder is its body.
            return Optional.of(context.findClass(closure.get()).stream().flatMap(cls -> cls.getMethods().stream())
                    .filter(method -> method.getName().equals("doCall") && method.hasBody())
                    .max(Comparator.comparing(JavaSootMethod::getParameterCount))
                    .map(doCall -> readUriFunction(doCall, MAX_CHAIN))
                    .map(read -> read.unread() != null || !read.path().isEmpty() ? read
                            : new UriFunction("/", null, read.otherHost()))
                    .orElseGet(() -> new UriFunction(null, "the closure " + MethodNames.simpleName(
                            closure.get().getFullyQualifiedName()), false)));
        }
        if (!(argument instanceof Local local) || !(Locals.definition(caller.getBody(), local).orElse(null)
                instanceof JDynamicInvokeExpr lambda)
                || lambda.getBootstrapMethodSignature().getName().equals("makeConcatWithConstants")) {
            return Optional.empty();
        }
        for (Value bootstrap : lambda.getBootstrapArgs()) {
            if (!(bootstrap instanceof MethodHandle handle)
                    || !(handle.getReferenceSignature() instanceof MethodSignature target)) {
                continue;
            }
            Optional<JavaSootMethod> body = context.isApplication(target.getDeclClassType())
                    ? context.findMethod(target).filter(JavaSootMethod::hasBody) : Optional.empty();
            if (body.isEmpty()) {
                return Optional.of(new UriFunction(null, "the function " + MethodNames.simpleName(
                        target.getDeclClassType().getFullyQualifiedName()) + "::" + target.getName(), false));
            }
            UriFunction read = readUriFunction(body.get(), MAX_CHAIN);
            return Optional.of(read.unread() != null || !read.path().isEmpty() ? read
                    : new UriFunction("/", null, read.otherHost()));
        }
        return Optional.empty();
    }

    /**
     * The function's builder calls in order, and those of the application methods it hands the builder to.
     */
    private UriFunction readUriFunction(JavaSootMethod function, int depth) {
        UriReading reading = new UriReading();
        // A Groovy closure's dynamic calls name no type: those on its parameter, and on what they return, are the
        // builder's.
        Set<Value> groovyBuilders = new LinkedHashSet<>();
        for (Stmt stmt : function.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt identity && identity.getRightOp() instanceof JParameterRef) {
                groovyBuilders.add(identity.getLeftOp());
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            Optional<GroovyCalls.Call> groovy = GroovyCalls.of(invoke.get());
            if (groovy.isPresent()) {
                if (groovy.get().type().equals("invoke") && groovyBuilders.contains(groovy.get().receiver())) {
                    List<String> segments = new ArrayList<>();
                    for (int i = 0; i < groovy.get().args().size(); i++) {
                        segments.add(constant(function, groovy.get().args().get(i)).orElse("{p" + (i + 1) + "}"));
                    }
                    reading.call(groovy.get().name(), groovy.get().args().isEmpty() ? null
                            : groovy.get().args().getFirst(), Optional.of(String.join("/", segments)));
                    if (stmt instanceof AbstractDefinitionStmt definition) {
                        groovyBuilders.add(definition.getLeftOp());
                    }
                }
                continue;
            }
            String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.get().getMethodSignature().getName();
            if (!URI_BUILDERS.contains(owner)) {
                boolean handsOn = invoke.get().getArgs().stream().anyMatch(arg -> arg.getType() instanceof ClassType
                        type && URI_BUILDERS.contains(type.getFullyQualifiedName()));
                Optional<JavaSootMethod> helper = handsOn && depth > 0
                        && context.isApplication(invoke.get().getMethodSignature().getDeclClassType())
                        ? context.findMethod(invoke.get().getMethodSignature()).filter(JavaSootMethod::hasBody)
                        : Optional.empty();
                if (helper.isPresent()) {
                    UriFunction more = readUriFunction(helper.get(), depth - 1);
                    reading.path = more.path() == null || more.path().isEmpty() ? reading.path
                            : joinPath(reading.path, more.path());
                    reading.unread = reading.unread != null ? reading.unread : more.unread();
                    reading.otherHost |= more.otherHost();
                }
                else if (handsOn && reading.unread == null) {
                    reading.unread = "the URI builder handed to " + MethodNames.simpleName(owner).replace('$', '.')
                            + "." + name + "(..)";
                }
                continue;
            }
            reading.call(name, invoke.get().getArgCount() == 0 ? null : invoke.get().getArg(0),
                    name.equals("pathSegment") ? segments(function, invoke.get().getArg(0)) : Optional.empty());
        }
        return new UriFunction(reading.unread != null ? null : reading.path, reading.unread, reading.otherHost);
    }

    /**
     * What a {@code uri(..)} function's builder calls have done so far.
     */
    private static final class UriReading {

        String path = "";
        String unread;
        boolean otherHost;

        /**
         * @param first the call's first argument, {@code null} for none
         * @param segments a {@code pathSegment(..)} call's segments, when they are read
         */
        void call(String name, Value first, Optional<String> segments) {
            if (URI_PASS_THROUGH.contains(name)) {
                return;
            }
            if (URI_HOST_PARTS.contains(name)) {
                otherHost = true;
            }
            else if (name.equals("path") && first instanceof StringConstant piece) {
                path = joinPath(path, piece.getValue());
            }
            else if (name.equals("replacePath") && first instanceof StringConstant piece) {
                path = pathOnly(piece.getValue());
            }
            else if (name.equals("pathSegment") && segments.isPresent()) {
                path = joinPath(path, segments.get());
            }
            else if (unread == null) {
                unread = "UriBuilder." + name + "(..)" + (name.equals("path") || name.equals("replacePath")
                        ? " with a value that isn't a constant" : "");
            }
        }
    }

    private boolean isClosure(ClassType type) {
        return context.superClassesOf(type).stream()
                .anyMatch(superclass -> superclass.getFullyQualifiedName().equals("groovy.lang.Closure"));
    }

    private static String joinPath(String path, String piece) {
        return ("/" + path + "/" + piece).replaceAll("/+", "/");
    }

    /**
     * The request path under the base URL's own path, and the base URL without it, as Spring's
     * {@code DefaultUriBuilderFactory} and Boot's {@code RootUriTemplateHandler} join them: {@code http://orders/api}
     * and {@code /orders/{id}} are {@code http://orders} and {@code /api/orders/{id}}.
     */
    private static Url rebased(BaseUrl base, String path, String query) {
        Url split = base.value() == null ? null : split(base.value());
        if (split == null || split.baseUrl() == BaseUrl.UNKNOWN || split.path().equals("/")) {
            return new Url(base, path, query);
        }
        return new Url(new BaseUrl(split.baseUrl().value(), base.expression()), RequestMappings.join(split.path(),
                path), query);
    }

    /**
     * {@code http://host:8080/employees/{id}} → base {@code http://host:8080}, path {@code /employees/{id}}. A base
     * with a URI variable in it ({@code http://{host}:8080}) names no host AuthTracer knows: its value is unknown,
     * and the template is where it comes from.
     */
    private static Url split(String url) {
        int scheme = url.indexOf("://");
        if (scheme < 0) {
            return new Url(BaseUrl.UNKNOWN, pathOnly(url), query(url));
        }
        int slash = url.indexOf('/', scheme + 3);
        String base = slash < 0 ? url : url.substring(0, slash);
        BaseUrl baseUrl = base.contains("{") ? new BaseUrl(null, base) : new BaseUrl(base, null);
        return slash < 0 ? new Url(baseUrl, "/")
                : new Url(baseUrl, pathOnly(url.substring(slash)), query(url.substring(slash)));
    }

    private static String query(String path) {
        int start = path.indexOf('?');
        if (start < 0) {
            return null;
        }
        int fragment = path.indexOf('#', start);
        return fragment < 0 ? path.substring(start + 1) : path.substring(start + 1, fragment);
    }

    /**
     * The path the linker matches: without the query string or fragment ({@code pets/visits?petId={petId}} is
     * {@code /pets/visits}), from the root.
     */
    private static String pathOnly(String path) {
        int query = path.indexOf('?');
        String trimmed = query < 0 ? path : path.substring(0, query);
        int fragment = trimmed.indexOf('#');
        trimmed = fragment < 0 ? trimmed : trimmed.substring(0, fragment);
        return trimmed.isEmpty() || trimmed.startsWith("/") || trimmed.startsWith("{") ? trimmed : "/" + trimmed;
    }

    /**
     * The base URL of the client a fluent request is made on: the one it is built with right there
     * ({@code RestClient.create(url).get()...}), the one its field was built with, when the request's chain starts at
     * a field the class builds; else the class's.
     */
    private BaseUrl fluentBaseUrl(Fluent fluent, JavaSootMethod caller, Local request) {
        Local receiver = request;
        for (int depth = 0; depth < MAX_CHAIN; depth++) {
            Optional<Value> definition = Locals.definition(caller.getBody(), receiver);
            if (definition.orElse(null) instanceof JFieldRef field) {
                Optional<BaseUrl> built = fieldBaseUrl(field.getFieldSignature(), fluent.builder(), "baseUrl",
                        fluent.type(), "create");
                if (built.isPresent()) {
                    return built.get();
                }
                break;
            }
            if (definition.orElse(null) instanceof AbstractInvokeExpr call && call.getArgCount() == 1
                    && configuresBaseUrl(call)) {
                BaseUrl built = resolve(caller, call.getArg(0));
                if (built != BaseUrl.UNKNOWN) {
                    return built;
                }
                break;
            }
            if (!(definition.orElse(null) instanceof AbstractInstanceInvokeExpr call)) {
                break;
            }
            String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            if (!owner.equals(fluent.type()) && !fluent.owns(owner)) {
                break;
            }
            receiver = call.getBase();
        }
        return classBaseUrl(caller, fluent.client(), fluent.builder(), "baseUrl", fluent.type(), "create");
    }

    /**
     * The base URL set on the builder chain a field of the application is assigned from:
     * {@code this.orders = builder.clone().baseUrl(ordersUrl).build()}.
     */
    private Optional<BaseUrl> fieldBaseUrl(FieldSignature field, String builder, String builderMethod, String factory,
            String factoryMethod) {
        Optional<JavaSootClass> cls = context.isApplication(field.getDeclClassType())
                ? context.findClass(field.getDeclClassType()) : Optional.empty();
        Set<BaseUrl> found = new LinkedHashSet<>();
        for (JavaSootMethod method : cls.map(JavaSootClass::getMethods).orElse(Set.of())) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                if (!(stmt instanceof JAssignStmt assign) || !(assign.getLeftOp() instanceof JFieldRef target)
                        || !target.getFieldSignature().equals(field) || !(assign.getRightOp() instanceof Local value)) {
                    continue;
                }
                Local current = value;
                for (int depth = 0; depth < MAX_CHAIN; depth++) {
                    Optional<AbstractInvokeExpr> call = Locals.definition(method.getBody(), current)
                            .filter(AbstractInvokeExpr.class::isInstance).map(AbstractInvokeExpr.class::cast);
                    if (call.isEmpty()) {
                        break;
                    }
                    String declaring = call.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = call.get().getMethodSignature().getName();
                    if (call.get().getArgCount() == 1 && (declaring.equals(builder) && name.equals(builderMethod)
                            || declaring.equals(factory) && name.equals(factoryMethod))) {
                        found.add(resolve(method, call.get().getArg(0)));
                        break;
                    }
                    if (!(call.get() instanceof AbstractInstanceInvokeExpr instance)) {
                        break;
                    }
                    current = instance.getBase();
                }
            }
        }
        return found.size() == 1 ? Optional.of(found.iterator().next()) : Optional.empty();
    }

    /**
     * A base URL the class configures once: {@code builder.<builderMethod>(url)} or
     * {@code <factory>.<factoryMethod>(url)}, from a constant or a {@code @Value} parameter or field. A class that
     * configures several has none the walk can pick.
     */
    private BaseUrl classBaseUrl(JavaSootMethod caller, String client, String builder, String builderMethod,
            String factory, String factoryMethod) {
        String className = caller.getDeclaringClassType().getFullyQualifiedName();
        return baseUrls.computeIfAbsent(client + " " + className, key -> {
            List<BaseUrl> configured = context.findClass(className)
                    .map(cls -> classBaseUrls(cls, builder, builderMethod, factory, factoryMethod)).orElse(List.of());
            if (configured.size() > 1) {
                return BaseUrl.UNKNOWN;
            }
            return configured.size() == 1 ? configured.getFirst() : beanBaseUrl(factory != null ? factory
                    : REST_TEMPLATE, builder, builderMethod, factory, factoryMethod);
        });
    }

    /**
     * A client injected from the application's only {@code @Bean} method that builds one: the base URL set there.
     */
    private BaseUrl beanBaseUrl(String clientType, String builder, String builderMethod, String factory,
            String factoryMethod) {
        List<JavaSootClass> declaring = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            cls.getMethods().stream()
                    .filter(method -> method.hasBody() && context.hasAnnotation(method, SpringNames.BEAN)
                            && method.getReturnType() instanceof ClassType returned
                            && returned.getFullyQualifiedName().equals(clientType))
                    .forEach(method -> declaring.add(cls));
        }
        List<BaseUrl> configured = declaring.size() == 1
                ? classBaseUrls(declaring.getFirst(), builder, builderMethod, factory, factoryMethod) : List.of();
        return configured.size() == 1 ? configured.getFirst() : BaseUrl.UNKNOWN;
    }

    /**
     * The distinct base URLs the class configures.
     */
    private List<BaseUrl> classBaseUrls(JavaSootClass cls, String builder, String builderMethod, String factory,
            String factoryMethod) {
        Set<BaseUrl> found = new LinkedHashSet<>();
        for (JavaSootMethod method : cls.getMethods()) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                if (!stmt.isInvokableStmt()) {
                    continue;
                }
                Optional<AbstractInvokeExpr> invoke = stmt.asInvokableStmt().getInvokeExpr();
                if (invoke.isEmpty() || invoke.get().getArgCount() != 1) {
                    continue;
                }
                String declaring = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                String name = invoke.get().getMethodSignature().getName();
                if (declaring.equals(builder) && name.equals(builderMethod)
                        || declaring.equals(factory) && name.equals(factoryMethod)
                        || declaring.equals(URI_BUILDER_FACTORY) && name.equals("<init>")) {
                    found.add(resolve(method, invoke.get().getArg(0)));
                }
            }
        }
        return List.copyOf(found);
    }

    private BaseUrl resolve(JavaSootMethod method, Value argument) {
        if (argument instanceof StringConstant constant) {
            return new BaseUrl(constant.getValue(), null);
        }
        if (argument instanceof Local local
                && Locals.definition(method.getBody(), local).orElse(null) instanceof JDynamicInvokeExpr) {
            // A base and a path joined, url(baseUrl + "/graphql"): the whole URL, from the base's expression.
            return url(method, local).filter(joined -> joined.baseUrl() != BaseUrl.UNKNOWN)
                    .map(joined -> new BaseUrl(joined.baseUrl().value() == null ? null
                            : joined.baseUrl().value() + joined.path(), joined.baseUrl().expression() == null ? null
                                    : joined.baseUrl().expression() + joined.path()))
                    .orElse(BaseUrl.UNKNOWN);
        }
        return argument instanceof Local local ? baseUrlValue(method, local) : BaseUrl.UNKNOWN;
    }

    /**
     * A base URL the configuration gives ({@link ConfiguredValues}): a constant, a {@code @Value} parameter or field,
     * a field set from one, or a {@code @ConfigurationProperties} getter.
     */
    private BaseUrl baseUrlValue(JavaSootMethod method, Value value) {
        ConfiguredValues.Configured found = configured.of(method, value);
        return found.known() ? new BaseUrl(found.value(), found.expression()) : BaseUrl.UNKNOWN;
    }

    private BaseUrl fromExpression(String expression) {
        return new BaseUrl(context.properties().resolve(expression).orElse(null), expression);
    }
}
